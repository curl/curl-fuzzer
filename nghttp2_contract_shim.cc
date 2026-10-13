/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <nghttp2/nghttp2.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <type_traits>

namespace {

// Fatal nghttp2 errors invalidate a session. Keep this assertion state out of
// the heap so allocation-failure fuzzing cannot disable or perturb the check.
struct PoisonedSession {
  nghttp2_session *session = nullptr;
  const char *fatal_api = nullptr;
  long long fatal_result = 0;
};

constexpr std::size_t kMaximumPoisonedSessions = 256;
std::array<PoisonedSession, kMaximumPoisonedSessions> poisoned_sessions{};
std::mutex poisoned_sessions_mutex;
std::atomic<std::size_t> poisoned_session_count{0};

[[noreturn]] void AbortContractViolation(const char *attempted_api,
                                         const PoisonedSession &poisoned) {
  std::fprintf(
      stderr,
      "nghttp2 contract assertion failed: %s called on session %p after "
      "%s returned %lld (< NGHTTP2_ERR_FATAL); only "
      "nghttp2_session_del is allowed\n",
      attempted_api, static_cast<void *>(poisoned.session), poisoned.fatal_api,
      poisoned.fatal_result);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortTrackingOverflow(nghttp2_session *session,
                                        const char *fatal_api,
                                        long long fatal_result) {
  std::fprintf(stderr,
               "nghttp2 contract assertion failed: cannot track session %p "
               "after %s returned %lld; poisoned-session table is full\n",
               static_cast<void *>(session), fatal_api, fatal_result);
  std::fflush(stderr);
  std::abort();
}

void CheckUsable(nghttp2_session *session, const char *attempted_api) {
  if (session == nullptr ||
      poisoned_session_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  PoisonedSession poisoned;
  {
    std::lock_guard<std::mutex> lock(poisoned_sessions_mutex);
    for (const PoisonedSession &entry : poisoned_sessions) {
      if (entry.session == session) {
        poisoned = entry;
        break;
      }
    }
  }
  if (poisoned.session != nullptr) {
    AbortContractViolation(attempted_api, poisoned);
  }
}

void ForgetSession(nghttp2_session *session) {
  if (session == nullptr ||
      poisoned_session_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  std::lock_guard<std::mutex> lock(poisoned_sessions_mutex);
  for (PoisonedSession &entry : poisoned_sessions) {
    if (entry.session == session) {
      entry = PoisonedSession{};
      poisoned_session_count.fetch_sub(1, std::memory_order_release);
      return;
    }
  }
}

void RecordResult(nghttp2_session *session, const char *api, long long result) {
  if (session == nullptr || result >= NGHTTP2_ERR_FATAL) {
    return;
  }

  bool table_full = false;
  {
    std::lock_guard<std::mutex> lock(poisoned_sessions_mutex);
    PoisonedSession *empty_entry = nullptr;
    for (PoisonedSession &entry : poisoned_sessions) {
      if (entry.session == session) {
        // Preserve the first fatal result; it is the point at which the
        // application was required to stop using this session.
        return;
      }
      if (entry.session == nullptr && empty_entry == nullptr) {
        empty_entry = &entry;
      }
    }
    if (empty_entry != nullptr) {
      empty_entry->session = session;
      empty_entry->fatal_api = api;
      empty_entry->fatal_result = result;
      poisoned_session_count.fetch_add(1, std::memory_order_release);
    } else {
      table_full = true;
    }
  }
  if (table_full) {
    AbortTrackingOverflow(session, api, result);
  }
}

} // namespace

// GNU ld and lld provide each __real_* symbol when the final link uses the
// matching --wrap option. decltype keeps these declarations tied to the
// installed nghttp2 headers and makes signature drift a compile-time failure.
extern "C" decltype(nghttp2_session_client_new3)
    __real_nghttp2_session_client_new3;
extern "C" decltype(nghttp2_session_del) __real_nghttp2_session_del;
extern "C" decltype(nghttp2_session_check_request_allowed)
    __real_nghttp2_session_check_request_allowed;
extern "C" decltype(nghttp2_session_consume) __real_nghttp2_session_consume;
extern "C" decltype(nghttp2_session_get_local_window_size)
    __real_nghttp2_session_get_local_window_size;
extern "C" decltype(nghttp2_session_get_remote_settings)
    __real_nghttp2_session_get_remote_settings;
extern "C" decltype(nghttp2_session_get_remote_window_size)
    __real_nghttp2_session_get_remote_window_size;
extern "C" decltype(nghttp2_session_get_stream_effective_local_window_size)
    __real_nghttp2_session_get_stream_effective_local_window_size;
extern "C" decltype(nghttp2_session_get_stream_effective_recv_data_length)
    __real_nghttp2_session_get_stream_effective_recv_data_length;
extern "C" decltype(nghttp2_session_get_stream_remote_window_size)
    __real_nghttp2_session_get_stream_remote_window_size;
extern "C" decltype(nghttp2_session_get_stream_user_data)
    __real_nghttp2_session_get_stream_user_data;
extern "C" decltype(nghttp2_session_mem_recv) __real_nghttp2_session_mem_recv;
extern "C" decltype(nghttp2_session_resume_data)
    __real_nghttp2_session_resume_data;
extern "C" decltype(nghttp2_session_send) __real_nghttp2_session_send;
extern "C" decltype(nghttp2_session_set_local_window_size)
    __real_nghttp2_session_set_local_window_size;
extern "C" decltype(nghttp2_session_set_stream_user_data)
    __real_nghttp2_session_set_stream_user_data;
extern "C" decltype(nghttp2_session_upgrade2) __real_nghttp2_session_upgrade2;
extern "C" decltype(nghttp2_session_want_read) __real_nghttp2_session_want_read;
extern "C" decltype(nghttp2_session_want_write)
    __real_nghttp2_session_want_write;
extern "C" decltype(nghttp2_submit_goaway) __real_nghttp2_submit_goaway;
extern "C" decltype(nghttp2_submit_ping) __real_nghttp2_submit_ping;
extern "C" decltype(nghttp2_submit_priority) __real_nghttp2_submit_priority;
extern "C" decltype(nghttp2_submit_request) __real_nghttp2_submit_request;
extern "C" decltype(nghttp2_submit_rst_stream) __real_nghttp2_submit_rst_stream;
extern "C" decltype(nghttp2_submit_settings) __real_nghttp2_submit_settings;
extern "C" decltype(nghttp2_submit_window_update)
    __real_nghttp2_submit_window_update;

extern "C" int __wrap_nghttp2_session_client_new3(
    nghttp2_session **session_ptr, const nghttp2_session_callbacks *callbacks,
    void *user_data, const nghttp2_option *option, nghttp2_mem *mem) {
  const int result = __real_nghttp2_session_client_new3(session_ptr, callbacks,
                                                        user_data, option, mem);
  if (result == 0 && session_ptr != nullptr) {
    // A custom allocator may deliberately reuse a recently deleted address.
    ForgetSession(*session_ptr);
  }
  return result;
}
static_assert(std::is_same<decltype(nghttp2_session_client_new3),
                           decltype(__wrap_nghttp2_session_client_new3)>::value,
              "nghttp2_session_client_new3 signature changed");

extern "C" void __wrap_nghttp2_session_del(nghttp2_session *session) {
  // Deallocation is the sole operation permitted after a fatal return.
  ForgetSession(session);
  __real_nghttp2_session_del(session);
}
static_assert(std::is_same<decltype(nghttp2_session_del),
                           decltype(__wrap_nghttp2_session_del)>::value,
              "nghttp2_session_del signature changed");

#define DEFINE_CHECKED_WRAPPER(name, parameters, arguments)                    \
  extern "C" auto __wrap_##name parameters                                     \
      ->decltype(__real_##name arguments) {                                    \
    CheckUsable(session, #name);                                               \
    return __real_##name arguments;                                            \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

#define DEFINE_RESULT_WRAPPER(name, parameters, arguments)                     \
  extern "C" auto __wrap_##name parameters                                     \
      ->decltype(__real_##name arguments) {                                    \
    CheckUsable(session, #name);                                               \
    const auto result = __real_##name arguments;                               \
    RecordResult(session, #name, static_cast<long long>(result));              \
    return result;                                                             \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

DEFINE_CHECKED_WRAPPER(nghttp2_session_check_request_allowed,
                       (nghttp2_session * session), (session))
DEFINE_RESULT_WRAPPER(nghttp2_session_consume,
                      (nghttp2_session * session, int32_t stream_id,
                       size_t size),
                      (session, stream_id, size))
DEFINE_CHECKED_WRAPPER(nghttp2_session_get_local_window_size,
                       (nghttp2_session * session), (session))
DEFINE_CHECKED_WRAPPER(nghttp2_session_get_remote_settings,
                       (nghttp2_session * session, nghttp2_settings_id id),
                       (session, id))
DEFINE_CHECKED_WRAPPER(nghttp2_session_get_remote_window_size,
                       (nghttp2_session * session), (session))
DEFINE_CHECKED_WRAPPER(nghttp2_session_get_stream_effective_local_window_size,
                       (nghttp2_session * session, int32_t stream_id),
                       (session, stream_id))
DEFINE_CHECKED_WRAPPER(nghttp2_session_get_stream_effective_recv_data_length,
                       (nghttp2_session * session, int32_t stream_id),
                       (session, stream_id))
DEFINE_CHECKED_WRAPPER(nghttp2_session_get_stream_remote_window_size,
                       (nghttp2_session * session, int32_t stream_id),
                       (session, stream_id))
DEFINE_CHECKED_WRAPPER(nghttp2_session_get_stream_user_data,
                       (nghttp2_session * session, int32_t stream_id),
                       (session, stream_id))
DEFINE_RESULT_WRAPPER(nghttp2_session_mem_recv,
                      (nghttp2_session * session, const uint8_t *input,
                       size_t input_length),
                      (session, input, input_length))
DEFINE_RESULT_WRAPPER(nghttp2_session_resume_data,
                      (nghttp2_session * session, int32_t stream_id),
                      (session, stream_id))
DEFINE_RESULT_WRAPPER(nghttp2_session_send, (nghttp2_session * session),
                      (session))
DEFINE_RESULT_WRAPPER(nghttp2_session_set_local_window_size,
                      (nghttp2_session * session, uint8_t flags,
                       int32_t stream_id, int32_t window_size),
                      (session, flags, stream_id, window_size))
DEFINE_RESULT_WRAPPER(nghttp2_session_set_stream_user_data,
                      (nghttp2_session * session, int32_t stream_id,
                       void *stream_user_data),
                      (session, stream_id, stream_user_data))
DEFINE_RESULT_WRAPPER(nghttp2_session_upgrade2,
                      (nghttp2_session * session,
                       const uint8_t *settings_payload,
                       size_t settings_payload_length, int head_request,
                       void *stream_user_data),
                      (session, settings_payload, settings_payload_length,
                       head_request, stream_user_data))
DEFINE_CHECKED_WRAPPER(nghttp2_session_want_read, (nghttp2_session * session),
                       (session))
DEFINE_CHECKED_WRAPPER(nghttp2_session_want_write, (nghttp2_session * session),
                       (session))
DEFINE_RESULT_WRAPPER(nghttp2_submit_goaway,
                      (nghttp2_session * session, uint8_t flags,
                       int32_t last_stream_id, uint32_t error_code,
                       const uint8_t *opaque_data, size_t opaque_data_length),
                      (session, flags, last_stream_id, error_code, opaque_data,
                       opaque_data_length))
DEFINE_RESULT_WRAPPER(nghttp2_submit_ping,
                      (nghttp2_session * session, uint8_t flags,
                       const uint8_t *opaque_data),
                      (session, flags, opaque_data))
DEFINE_RESULT_WRAPPER(nghttp2_submit_priority,
                      (nghttp2_session * session, uint8_t flags,
                       int32_t stream_id,
                       const nghttp2_priority_spec *priority_spec),
                      (session, flags, stream_id, priority_spec))
DEFINE_RESULT_WRAPPER(nghttp2_submit_request,
                      (nghttp2_session * session,
                       const nghttp2_priority_spec *priority_spec,
                       const nghttp2_nv *headers, size_t header_count,
                       const nghttp2_data_provider *data_provider,
                       void *stream_user_data),
                      (session, priority_spec, headers, header_count,
                       data_provider, stream_user_data))
DEFINE_RESULT_WRAPPER(nghttp2_submit_rst_stream,
                      (nghttp2_session * session, uint8_t flags,
                       int32_t stream_id, uint32_t error_code),
                      (session, flags, stream_id, error_code))
DEFINE_RESULT_WRAPPER(nghttp2_submit_settings,
                      (nghttp2_session * session, uint8_t flags,
                       const nghttp2_settings_entry *settings,
                       size_t settings_count),
                      (session, flags, settings, settings_count))
DEFINE_RESULT_WRAPPER(nghttp2_submit_window_update,
                      (nghttp2_session * session, uint8_t flags,
                       int32_t stream_id, int32_t window_size_increment),
                      (session, flags, stream_id, window_size_increment))

#undef DEFINE_RESULT_WRAPPER
#undef DEFINE_CHECKED_WRAPPER
