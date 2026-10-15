/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <mbedtls/ssl.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <type_traits>

namespace {

enum class Operation { kHandshake, kRead, kWrite, kCloseNotify };

struct ContextState {
  mbedtls_ssl_context *ssl = nullptr;
  const char *fatal_api = nullptr;
  int fatal_result = 0;
  const char *peer_close_api = nullptr;
  const unsigned char *retry_buffer = nullptr;
  std::size_t retry_length = 0;
  bool write_retry = false;
};

constexpr std::size_t kMaximumTrackedContexts = 256;
std::array<ContextState, kMaximumTrackedContexts> context_states{};
std::mutex context_states_mutex;
std::atomic<std::size_t> context_state_count{0};

// Static Mbed TLS may call public SSL entrypoints internally. Keep those calls
// outside the application-level contract state machine.
thread_local unsigned real_call_depth = 0;

class RealCallScope {
public:
  RealCallScope() { ++real_call_depth; }
  ~RealCallScope() { --real_call_depth; }

  RealCallScope(const RealCallScope &) = delete;
  RealCallScope &operator=(const RealCallScope &) = delete;
};

bool IsRealCallActive() { return real_call_depth != 0; }

ContextState *FindContext(mbedtls_ssl_context *ssl) {
  for (ContextState &state : context_states) {
    if (state.ssl == ssl) {
      return &state;
    }
  }
  return nullptr;
}

ContextState *FindEmptyContext() {
  for (ContextState &state : context_states) {
    if (state.ssl == nullptr) {
      return &state;
    }
  }
  return nullptr;
}

[[noreturn]] void AbortFatalUse(const char *attempted_api,
                                const ContextState &state) {
  std::fprintf(stderr,
               "Mbed TLS contract assertion failed: %s called on context %p "
               "after %s returned fatal result -0x%04X; call "
               "mbedtls_ssl_session_reset or mbedtls_ssl_free before further "
               "connection I/O\n",
               attempted_api, static_cast<void *>(state.ssl), state.fatal_api,
               static_cast<unsigned int>(-state.fatal_result));
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortRetryMismatch(const char *difference,
                                     mbedtls_ssl_context *ssl,
                                     const ContextState &state) {
  std::fprintf(stderr,
               "Mbed TLS contract assertion failed: mbedtls_ssl_write called "
               "on context %p while a %zu-byte write retry is pending; %s\n",
               static_cast<void *>(ssl), state.retry_length, difference);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortPeerCloseUse(const char *attempted_api,
                                    const ContextState &state) {
  std::fprintf(stderr,
               "Mbed TLS contract assertion failed: %s called on context %p "
               "after %s returned MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY; the "
               "context cannot be used for further reading or writing; "
               "mbedtls_ssl_close_notify remains permitted, and "
               "mbedtls_ssl_session_reset or mbedtls_ssl_free can prepare "
               "the context for reuse\n",
               attempted_api, static_cast<void *>(state.ssl),
               state.peer_close_api);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortTrackingOverflow(mbedtls_ssl_context *ssl) {
  std::fprintf(stderr,
               "Mbed TLS contract assertion failed: cannot track context %p; "
               "fixed context table is full\n",
               static_cast<void *>(ssl));
  std::fflush(stderr);
  std::abort();
}

void CheckUsable(mbedtls_ssl_context *ssl, const char *attempted_api,
                 Operation operation) {
  if (ssl == nullptr ||
      context_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  ContextState state;
  {
    std::lock_guard<std::mutex> lock(context_states_mutex);
    const ContextState *tracked = FindContext(ssl);
    if (tracked != nullptr &&
        (tracked->fatal_api != nullptr ||
         (tracked->peer_close_api != nullptr &&
          (operation == Operation::kRead || operation == Operation::kWrite)))) {
      state = *tracked;
    }
  }
  if (state.fatal_api != nullptr) {
    AbortFatalUse(attempted_api, state);
  }
  if (state.peer_close_api != nullptr) {
    AbortPeerCloseUse(attempted_api, state);
  }
}

void CheckWriteRetry(mbedtls_ssl_context *ssl, const unsigned char *buffer,
                     std::size_t length) {
  if (ssl == nullptr ||
      context_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  ContextState state;
  {
    std::lock_guard<std::mutex> lock(context_states_mutex);
    const ContextState *tracked = FindContext(ssl);
    if (tracked != nullptr && tracked->write_retry) {
      state = *tracked;
    }
  }
  if (!state.write_retry) {
    return;
  }
  if (buffer != state.retry_buffer) {
    AbortRetryMismatch("the retry buffer pointer changed", ssl, state);
  }
  if (length != state.retry_length) {
    AbortRetryMismatch("the retry length changed", ssl, state);
  }
}

bool IsRetryResult(int result) {
  return result == MBEDTLS_ERR_SSL_WANT_READ ||
         result == MBEDTLS_ERR_SSL_WANT_WRITE ||
         result == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
         result == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS;
}

bool IsFatalResult(Operation operation, int result) {
  switch (operation) {
  case Operation::kHandshake:
    return result != 0 && !IsRetryResult(result) &&
           result != MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA;
  case Operation::kRead:
    return result <= 0 && !IsRetryResult(result) &&
           result != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY &&
           result != MBEDTLS_ERR_SSL_CLIENT_RECONNECT &&
           result != MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA &&
           result != MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
  case Operation::kWrite:
    return result < 0 && !IsRetryResult(result) &&
           result != MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA &&
           result != MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
  case Operation::kCloseNotify:
    return result != 0 && result != MBEDTLS_ERR_SSL_WANT_READ &&
           result != MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  return true;
}

void RecordResult(mbedtls_ssl_context *ssl, const char *api,
                  Operation operation, int result,
                  const unsigned char *buffer = nullptr,
                  std::size_t length = 0) {
  if (ssl == nullptr) {
    return;
  }
  const bool fatal = IsFatalResult(operation, result);
  const bool peer_close = operation == Operation::kRead &&
                          result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  const bool write_retry =
      operation == Operation::kWrite && (result == MBEDTLS_ERR_SSL_WANT_READ ||
                                         result == MBEDTLS_ERR_SSL_WANT_WRITE);

  bool table_full = false;
  {
    std::lock_guard<std::mutex> lock(context_states_mutex);
    ContextState *state = FindContext(ssl);
    if (state == nullptr && (fatal || peer_close || write_retry)) {
      state = FindEmptyContext();
      if (state != nullptr) {
        state->ssl = ssl;
        context_state_count.fetch_add(1, std::memory_order_release);
      } else {
        table_full = true;
      }
    }
    if (state != nullptr) {
      if (fatal) {
        state->fatal_api = api;
        state->fatal_result = result;
        state->peer_close_api = nullptr;
        state->write_retry = false;
      } else if (peer_close) {
        state->peer_close_api = api;
        state->write_retry = false;
      } else if (operation == Operation::kWrite) {
        state->write_retry = write_retry;
        state->retry_buffer = write_retry ? buffer : nullptr;
        state->retry_length = write_retry ? length : 0;
      }
      if (state->fatal_api == nullptr && state->peer_close_api == nullptr &&
          !state->write_retry) {
        *state = ContextState{};
        context_state_count.fetch_sub(1, std::memory_order_release);
      }
    }
  }
  if (table_full) {
    AbortTrackingOverflow(ssl);
  }
}

void ForgetContext(mbedtls_ssl_context *ssl) {
  if (ssl == nullptr ||
      context_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  std::lock_guard<std::mutex> lock(context_states_mutex);
  ContextState *state = FindContext(ssl);
  if (state != nullptr) {
    *state = ContextState{};
    context_state_count.fetch_sub(1, std::memory_order_release);
  }
}

} // namespace

extern "C" decltype(mbedtls_ssl_init) __real_mbedtls_ssl_init;
extern "C" decltype(mbedtls_ssl_free) __real_mbedtls_ssl_free;
extern "C" decltype(mbedtls_ssl_session_reset) __real_mbedtls_ssl_session_reset;
extern "C" decltype(mbedtls_ssl_handshake) __real_mbedtls_ssl_handshake;
extern "C" decltype(mbedtls_ssl_read) __real_mbedtls_ssl_read;
extern "C" decltype(mbedtls_ssl_write) __real_mbedtls_ssl_write;
extern "C" decltype(mbedtls_ssl_close_notify) __real_mbedtls_ssl_close_notify;

extern "C" void __wrap_mbedtls_ssl_init(mbedtls_ssl_context *ssl) {
  if (IsRealCallActive()) {
    __real_mbedtls_ssl_init(ssl);
    return;
  }
  ForgetContext(ssl);
  RealCallScope real_call;
  __real_mbedtls_ssl_init(ssl);
}
static_assert(std::is_same<decltype(mbedtls_ssl_init),
                           decltype(__wrap_mbedtls_ssl_init)>::value,
              "mbedtls_ssl_init signature changed");

extern "C" void __wrap_mbedtls_ssl_free(mbedtls_ssl_context *ssl) {
  if (IsRealCallActive()) {
    __real_mbedtls_ssl_free(ssl);
    return;
  }
  ForgetContext(ssl);
  RealCallScope real_call;
  __real_mbedtls_ssl_free(ssl);
}
static_assert(std::is_same<decltype(mbedtls_ssl_free),
                           decltype(__wrap_mbedtls_ssl_free)>::value,
              "mbedtls_ssl_free signature changed");

extern "C" int __wrap_mbedtls_ssl_session_reset(mbedtls_ssl_context *ssl) {
  if (IsRealCallActive()) {
    return __real_mbedtls_ssl_session_reset(ssl);
  }
  int result;
  {
    RealCallScope real_call;
    result = __real_mbedtls_ssl_session_reset(ssl);
  }
  if (result == 0) {
    ForgetContext(ssl);
  }
  return result;
}
static_assert(std::is_same<decltype(mbedtls_ssl_session_reset),
                           decltype(__wrap_mbedtls_ssl_session_reset)>::value,
              "mbedtls_ssl_session_reset signature changed");

#define DEFINE_MBEDTLS_IO_WRAPPER(name, operation, parameters, arguments)      \
  extern "C" int __wrap_##name parameters {                                    \
    if (IsRealCallActive()) {                                                  \
      return __real_##name arguments;                                          \
    }                                                                          \
    CheckUsable(ssl, #name, operation);                                        \
    int result;                                                                \
    {                                                                          \
      RealCallScope real_call;                                                 \
      result = __real_##name arguments;                                        \
    }                                                                          \
    RecordResult(ssl, #name, operation, result);                               \
    return result;                                                             \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

DEFINE_MBEDTLS_IO_WRAPPER(mbedtls_ssl_handshake, Operation::kHandshake,
                          (mbedtls_ssl_context * ssl), (ssl))
DEFINE_MBEDTLS_IO_WRAPPER(mbedtls_ssl_read, Operation::kRead,
                          (mbedtls_ssl_context * ssl, unsigned char *buffer,
                           size_t length),
                          (ssl, buffer, length))
DEFINE_MBEDTLS_IO_WRAPPER(mbedtls_ssl_close_notify, Operation::kCloseNotify,
                          (mbedtls_ssl_context * ssl), (ssl))

extern "C" int __wrap_mbedtls_ssl_write(mbedtls_ssl_context *ssl,
                                        const unsigned char *buffer,
                                        size_t length) {
  if (IsRealCallActive()) {
    return __real_mbedtls_ssl_write(ssl, buffer, length);
  }
  CheckUsable(ssl, "mbedtls_ssl_write", Operation::kWrite);
  CheckWriteRetry(ssl, buffer, length);
  int result;
  {
    RealCallScope real_call;
    result = __real_mbedtls_ssl_write(ssl, buffer, length);
  }
  RecordResult(ssl, "mbedtls_ssl_write", Operation::kWrite, result, buffer,
               length);
  return result;
}
static_assert(std::is_same<decltype(mbedtls_ssl_write),
                           decltype(__wrap_mbedtls_ssl_write)>::value,
              "mbedtls_ssl_write signature changed");

#undef DEFINE_MBEDTLS_IO_WRAPPER
