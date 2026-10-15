/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <gnutls/gnutls.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <type_traits>

namespace {

enum class SendApi { kNone, kRecordSend, kEarlyData };

struct SessionState {
  gnutls_session_t session = nullptr;
  const char *fatal_api = nullptr;
  int fatal_result = 0;
  const char *retry_api = nullptr;
  SendApi retry_id = SendApi::kNone;
  const void *retry_data = nullptr;
  std::size_t retry_size = 0;
  bool send_closed = false;
  bool receive_closed = false;
};

constexpr std::size_t kMaximumTrackedSessions = 256;
std::array<SessionState, kMaximumTrackedSessions> session_states{};
std::mutex session_states_mutex;
std::atomic<std::size_t> session_state_count{0};

// Static GnuTLS calls some of its public entrypoints internally. Bypass the
// monitor while a real library call is active so only application calls drive
// the contract state machine.
thread_local unsigned real_call_depth = 0;

class RealCallScope {
public:
  RealCallScope() { ++real_call_depth; }
  ~RealCallScope() { --real_call_depth; }

  RealCallScope(const RealCallScope &) = delete;
  RealCallScope &operator=(const RealCallScope &) = delete;
};

bool IsRealCallActive() { return real_call_depth != 0; }

SessionState *FindSession(gnutls_session_t session) {
  for (SessionState &state : session_states) {
    if (state.session == session) {
      return &state;
    }
  }
  return nullptr;
}

SessionState *FindEmptySession() {
  for (SessionState &state : session_states) {
    if (state.session == nullptr) {
      return &state;
    }
  }
  return nullptr;
}

[[noreturn]] void AbortFatalUse(const char *attempted_api,
                                const SessionState &state) {
  std::fprintf(stderr,
               "GnuTLS contract assertion failed: %s called on session %p "
               "after %s returned fatal error %d; further handshake, record "
               "I/O, and bye calls are disallowed\n",
               attempted_api, static_cast<void *>(state.session),
               state.fatal_api, state.fatal_result);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortRetryMismatch(const char *attempted_api,
                                     gnutls_session_t session,
                                     const SessionState &state,
                                     const char *difference) {
  std::fprintf(stderr,
               "GnuTLS contract assertion failed: %s called on session %p "
               "while %s has a queued retry of %zu bytes; %s\n",
               attempted_api, static_cast<void *>(session), state.retry_api,
               state.retry_size, difference);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortClosedUse(const char *attempted_api,
                                 const SessionState &state,
                                 const char *operation) {
  const char *how =
      state.receive_closed ? "GNUTLS_SHUT_RDWR" : "GNUTLS_SHUT_WR";
  std::fprintf(stderr,
               "GnuTLS contract assertion failed: %s called on session %p "
               "after successful gnutls_bye(%s); further %s are disallowed\n",
               attempted_api, static_cast<void *>(state.session), how,
               operation);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortTrackingOverflow(gnutls_session_t session) {
  std::fprintf(stderr,
               "GnuTLS contract assertion failed: cannot track session %p; "
               "fixed session table is full\n",
               static_cast<void *>(session));
  std::fflush(stderr);
  std::abort();
}

void CheckUsable(gnutls_session_t session, const char *attempted_api) {
  if (session == nullptr ||
      session_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  SessionState state;
  {
    std::lock_guard<std::mutex> lock(session_states_mutex);
    const SessionState *tracked = FindSession(session);
    if (tracked != nullptr && tracked->fatal_api != nullptr) {
      state = *tracked;
    }
  }
  if (state.fatal_api != nullptr) {
    AbortFatalUse(attempted_api, state);
  }
}

void CheckSendRetry(gnutls_session_t session, const char *api, SendApi send_api,
                    const void *data, std::size_t size) {
  if (session == nullptr ||
      session_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  SessionState state;
  {
    std::lock_guard<std::mutex> lock(session_states_mutex);
    const SessionState *tracked = FindSession(session);
    if (tracked != nullptr && tracked->retry_api != nullptr) {
      state = *tracked;
    }
  }
  if (state.retry_api == nullptr) {
    return;
  }
  if (state.retry_id != send_api) {
    AbortRetryMismatch(api, session, state,
                       "the queued data must be retried with the same API");
  }
  // GnuTLS explicitly permits NULL,0 to flush the previously queued record.
  if (data == nullptr && size == 0) {
    return;
  }
  if (data != state.retry_data) {
    AbortRetryMismatch(api, session, state, "the retry data pointer changed");
  }
  if (size != state.retry_size) {
    AbortRetryMismatch(api, session, state, "the retry size changed");
  }
}

void CheckSendAllowed(gnutls_session_t session, const char *api) {
  if (session == nullptr ||
      session_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  SessionState state;
  {
    std::lock_guard<std::mutex> lock(session_states_mutex);
    const SessionState *tracked = FindSession(session);
    if (tracked != nullptr && tracked->send_closed) {
      state = *tracked;
    }
  }
  if (state.send_closed) {
    AbortClosedUse(api, state, "sends");
  }
}

void CheckReceiveAllowed(gnutls_session_t session, const char *api) {
  if (session == nullptr ||
      session_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  SessionState state;
  {
    std::lock_guard<std::mutex> lock(session_states_mutex);
    const SessionState *tracked = FindSession(session);
    if (tracked != nullptr && tracked->receive_closed) {
      state = *tracked;
    }
  }
  if (state.receive_closed) {
    AbortClosedUse(api, state, "receives");
  }
}

bool IsFatalResult(int result) {
  if (result >= 0) {
    return false;
  }
  RealCallScope real_call;
  return gnutls_error_is_fatal(result) != 0;
}

void RecordResult(gnutls_session_t session, const char *api, int result,
                  SendApi send_api = SendApi::kNone, const void *data = nullptr,
                  std::size_t size = 0) {
  if (session == nullptr) {
    return;
  }
  const bool fatal = IsFatalResult(result);
  const bool is_send = send_api != SendApi::kNone;
  const bool retry =
      is_send && (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED);

  bool table_full = false;
  {
    std::lock_guard<std::mutex> lock(session_states_mutex);
    SessionState *state = FindSession(session);
    if (state == nullptr && (fatal || retry)) {
      state = FindEmptySession();
      if (state != nullptr) {
        state->session = session;
        session_state_count.fetch_add(1, std::memory_order_release);
      } else {
        table_full = true;
      }
    }
    if (state != nullptr) {
      if (fatal) {
        state->fatal_api = api;
        state->fatal_result = result;
        state->retry_api = nullptr;
        state->retry_id = SendApi::kNone;
      } else if (is_send) {
        if (retry) {
          // NULL,0 asks GnuTLS to retry the record already stored internally,
          // so preserve the original pointer and length in that case.
          if (!(data == nullptr && size == 0 && state->retry_api != nullptr)) {
            state->retry_api = api;
            state->retry_id = send_api;
            state->retry_data = data;
            state->retry_size = size;
          }
        } else {
          state->retry_api = nullptr;
          state->retry_id = SendApi::kNone;
          state->retry_data = nullptr;
          state->retry_size = 0;
        }
      }
      if (state->fatal_api == nullptr && state->retry_api == nullptr &&
          !state->send_closed && !state->receive_closed) {
        *state = SessionState{};
        session_state_count.fetch_sub(1, std::memory_order_release);
      }
    }
  }
  if (table_full) {
    AbortTrackingOverflow(session);
  }
}

void RecordByeResult(gnutls_session_t session, gnutls_close_request_t how,
                     int result) {
  if (session == nullptr) {
    return;
  }
  const bool fatal = IsFatalResult(result);
  const bool success = result == GNUTLS_E_SUCCESS;
  // GNUTLS_E_AGAIN and GNUTLS_E_INTERRUPTED leave the session retryable and
  // do not complete either shutdown direction.
  if (!fatal && !success) {
    return;
  }

  bool table_full = false;
  {
    std::lock_guard<std::mutex> lock(session_states_mutex);
    SessionState *state = FindSession(session);
    if (state == nullptr) {
      state = FindEmptySession();
      if (state != nullptr) {
        state->session = session;
        session_state_count.fetch_add(1, std::memory_order_release);
      } else {
        table_full = true;
      }
    }
    if (state != nullptr) {
      if (fatal) {
        state->fatal_api = "gnutls_bye";
        state->fatal_result = result;
        state->retry_api = nullptr;
        state->retry_id = SendApi::kNone;
        state->retry_data = nullptr;
        state->retry_size = 0;
      } else {
        state->send_closed = true;
        if (how == GNUTLS_SHUT_RDWR) {
          state->receive_closed = true;
        }
        state->retry_api = nullptr;
        state->retry_id = SendApi::kNone;
        state->retry_data = nullptr;
        state->retry_size = 0;
      }
    }
  }
  if (table_full) {
    AbortTrackingOverflow(session);
  }
}

void ForgetSession(gnutls_session_t session) {
  if (session == nullptr ||
      session_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  std::lock_guard<std::mutex> lock(session_states_mutex);
  SessionState *state = FindSession(session);
  if (state != nullptr) {
    *state = SessionState{};
    session_state_count.fetch_sub(1, std::memory_order_release);
  }
}

} // namespace

extern "C" decltype(gnutls_init) __real_gnutls_init;
extern "C" decltype(gnutls_deinit) __real_gnutls_deinit;
extern "C" decltype(gnutls_handshake) __real_gnutls_handshake;
extern "C" decltype(gnutls_record_send) __real_gnutls_record_send;
extern "C" decltype(gnutls_record_send_early_data)
    __real_gnutls_record_send_early_data;
extern "C" decltype(gnutls_record_recv) __real_gnutls_record_recv;
extern "C" decltype(gnutls_bye) __real_gnutls_bye;

extern "C" int __wrap_gnutls_init(gnutls_session_t *session,
                                  unsigned int flags) {
  if (IsRealCallActive()) {
    return __real_gnutls_init(session, flags);
  }
  int result;
  {
    RealCallScope real_call;
    result = __real_gnutls_init(session, flags);
  }
  if (result == GNUTLS_E_SUCCESS && session != nullptr) {
    ForgetSession(*session);
  }
  return result;
}
static_assert(
    std::is_same<decltype(gnutls_init), decltype(__wrap_gnutls_init)>::value,
    "gnutls_init signature changed");

extern "C" void __wrap_gnutls_deinit(gnutls_session_t session) {
  if (IsRealCallActive()) {
    __real_gnutls_deinit(session);
    return;
  }
  ForgetSession(session);
  RealCallScope real_call;
  __real_gnutls_deinit(session);
}
static_assert(std::is_same<decltype(gnutls_deinit),
                           decltype(__wrap_gnutls_deinit)>::value,
              "gnutls_deinit signature changed");

#define DEFINE_GNUTLS_IO_WRAPPER(name, result_type, parameters, arguments)     \
  extern "C" result_type __wrap_##name parameters {                            \
    if (IsRealCallActive()) {                                                  \
      return __real_##name arguments;                                          \
    }                                                                          \
    CheckUsable(session, #name);                                               \
    result_type result;                                                        \
    {                                                                          \
      RealCallScope real_call;                                                 \
      result = __real_##name arguments;                                        \
    }                                                                          \
    RecordResult(session, #name, static_cast<int>(result));                    \
    return result;                                                             \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

#define DEFINE_GNUTLS_SEND_WRAPPER(name, send_api)                             \
  extern "C" ssize_t __wrap_##name(gnutls_session_t session, const void *data, \
                                   size_t size) {                              \
    if (IsRealCallActive()) {                                                  \
      return __real_##name(session, data, size);                               \
    }                                                                          \
    CheckUsable(session, #name);                                               \
    CheckSendAllowed(session, #name);                                          \
    CheckSendRetry(session, #name, send_api, data, size);                      \
    ssize_t result;                                                            \
    {                                                                          \
      RealCallScope real_call;                                                 \
      result = __real_##name(session, data, size);                             \
    }                                                                          \
    RecordResult(session, #name, static_cast<int>(result), send_api, data,     \
                 size);                                                        \
    return result;                                                             \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

DEFINE_GNUTLS_IO_WRAPPER(gnutls_handshake, int, (gnutls_session_t session),
                         (session))
DEFINE_GNUTLS_SEND_WRAPPER(gnutls_record_send, SendApi::kRecordSend)
DEFINE_GNUTLS_SEND_WRAPPER(gnutls_record_send_early_data, SendApi::kEarlyData)
extern "C" ssize_t __wrap_gnutls_record_recv(gnutls_session_t session,
                                             void *data, size_t size) {
  if (IsRealCallActive()) {
    return __real_gnutls_record_recv(session, data, size);
  }
  CheckUsable(session, "gnutls_record_recv");
  CheckReceiveAllowed(session, "gnutls_record_recv");
  ssize_t result;
  {
    RealCallScope real_call;
    result = __real_gnutls_record_recv(session, data, size);
  }
  RecordResult(session, "gnutls_record_recv", static_cast<int>(result));
  return result;
}
static_assert(std::is_same<decltype(gnutls_record_recv),
                           decltype(__wrap_gnutls_record_recv)>::value,
              "gnutls_record_recv signature changed");

extern "C" int __wrap_gnutls_bye(gnutls_session_t session,
                                 gnutls_close_request_t how) {
  if (IsRealCallActive()) {
    return __real_gnutls_bye(session, how);
  }
  CheckUsable(session, "gnutls_bye");
  int result;
  {
    RealCallScope real_call;
    result = __real_gnutls_bye(session, how);
  }
  RecordByeResult(session, how, result);
  return result;
}
static_assert(
    std::is_same<decltype(gnutls_bye), decltype(__wrap_gnutls_bye)>::value,
    "gnutls_bye signature changed");

#undef DEFINE_GNUTLS_SEND_WRAPPER
#undef DEFINE_GNUTLS_IO_WRAPPER
