/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <nghttp3/nghttp3.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <type_traits>

namespace {

// A negative read_stream/read_stream2/writev_stream result invalidates an
// nghttp3 connection. Keep the state outside the heap so allocation-failure
// fuzzing cannot disable or perturb the assertion.
struct ConnectionState {
  nghttp3_conn *connection = nullptr;
  const char *fatal_api = nullptr;
  long long fatal_result = 0;
  nghttp3_tstamp last_read_timestamp = 0;
  bool has_read_timestamp = false;
};

constexpr std::size_t kMaximumTrackedConnections = 256;
std::array<ConnectionState, kMaximumTrackedConnections> connection_states{};
std::mutex connection_states_mutex;
std::atomic<std::size_t> connection_state_count{0};

// Static libnghttp3 contains calls to public nghttp3_conn_* APIs. --wrap
// redirects those calls too, so calls made while a real nghttp3 function is
// running bypass application-level state checks.
thread_local unsigned real_call_depth = 0;

class RealCallScope {
public:
  RealCallScope() { ++real_call_depth; }
  ~RealCallScope() { --real_call_depth; }

  RealCallScope(const RealCallScope &) = delete;
  RealCallScope &operator=(const RealCallScope &) = delete;
};

bool IsRealCallActive() { return real_call_depth != 0; }

[[noreturn]] void AbortContractViolation(const char *attempted_api,
                                         const ConnectionState &state) {
  std::fprintf(stderr,
               "nghttp3 contract assertion failed: %s called on connection "
               "%p after %s returned %lld; only nghttp3_conn_del is "
               "allowed\n",
               attempted_api, static_cast<void *>(state.connection),
               state.fatal_api, state.fatal_result);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortTimestampRegression(nghttp3_conn *connection,
                                           nghttp3_tstamp previous,
                                           nghttp3_tstamp current) {
  std::fprintf(stderr,
               "nghttp3 contract assertion failed: "
               "nghttp3_conn_read_stream2 called on connection %p with "
               "decreasing timestamp %llu after %llu\n",
               static_cast<void *>(connection),
               static_cast<unsigned long long>(current),
               static_cast<unsigned long long>(previous));
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortInvalidReadTimestamp(nghttp3_conn *connection) {
  std::fprintf(stderr,
               "nghttp3 contract assertion failed: "
               "nghttp3_conn_read_stream2 called on connection %p with "
               "invalid timestamp UINT64_MAX\n",
               static_cast<void *>(connection));
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortTrackingOverflow(nghttp3_conn *connection,
                                        const char *api, long long result) {
  std::fprintf(stderr,
               "nghttp3 contract assertion failed: cannot track connection "
               "%p after %s returned %lld; connection-state table is full\n",
               static_cast<void *>(connection), api, result);
  std::fflush(stderr);
  std::abort();
}

ConnectionState *FindConnection(nghttp3_conn *connection) {
  for (ConnectionState &state : connection_states) {
    if (state.connection == connection) {
      return &state;
    }
  }
  return nullptr;
}

void CheckUsable(nghttp3_conn *connection, const char *attempted_api) {
  if (connection == nullptr ||
      connection_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  ConnectionState state;
  {
    std::lock_guard<std::mutex> lock(connection_states_mutex);
    const ConnectionState *tracked = FindConnection(connection);
    if (tracked != nullptr && tracked->fatal_api != nullptr) {
      state = *tracked;
    }
  }
  if (state.fatal_api != nullptr) {
    AbortContractViolation(attempted_api, state);
  }
}

void ForgetConnection(nghttp3_conn *connection) {
  if (connection == nullptr ||
      connection_state_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  std::lock_guard<std::mutex> lock(connection_states_mutex);
  ConnectionState *state = FindConnection(connection);
  if (state != nullptr) {
    *state = ConnectionState{};
    connection_state_count.fetch_sub(1, std::memory_order_release);
  }
}

void RegisterConnection(nghttp3_conn *connection) {
  if (connection == nullptr) {
    return;
  }

  bool table_full = false;
  {
    std::lock_guard<std::mutex> lock(connection_states_mutex);
    ConnectionState *state = FindConnection(connection);
    bool added = false;
    if (state == nullptr) {
      for (ConnectionState &entry : connection_states) {
        if (entry.connection == nullptr) {
          state = &entry;
          added = true;
          break;
        }
      }
    }
    if (state != nullptr) {
      *state = ConnectionState{};
      state->connection = connection;
      if (added) {
        connection_state_count.fetch_add(1, std::memory_order_release);
      }
    } else {
      table_full = true;
    }
  }
  if (table_full) {
    AbortTrackingOverflow(connection, "connection constructor", 0);
  }
}

void RecordFatalResult(nghttp3_conn *connection, const char *api,
                       long long result) {
  if (connection == nullptr || result >= 0) {
    return;
  }

  bool table_full = false;
  {
    std::lock_guard<std::mutex> lock(connection_states_mutex);
    ConnectionState *state = FindConnection(connection);
    bool added = false;
    if (state == nullptr) {
      for (ConnectionState &entry : connection_states) {
        if (entry.connection == nullptr) {
          state = &entry;
          added = true;
          break;
        }
      }
    }
    if (state != nullptr) {
      if (added) {
        state->connection = connection;
        connection_state_count.fetch_add(1, std::memory_order_release);
      }
      // Preserve the operation that first invalidated the connection.
      if (state->fatal_api == nullptr) {
        state->fatal_api = api;
        state->fatal_result = result;
      }
    } else {
      table_full = true;
    }
  }
  if (table_full) {
    AbortTrackingOverflow(connection, api, result);
  }
}

void RecordReadTimestamp(nghttp3_conn *connection, nghttp3_tstamp timestamp) {
  if (timestamp == UINT64_MAX) {
    AbortInvalidReadTimestamp(connection);
  }
  if (connection == nullptr) {
    return;
  }

  bool table_full = false;
  bool regressed = false;
  nghttp3_tstamp previous = 0;
  {
    std::lock_guard<std::mutex> lock(connection_states_mutex);
    ConnectionState *state = FindConnection(connection);
    bool added = false;
    if (state == nullptr) {
      for (ConnectionState &entry : connection_states) {
        if (entry.connection == nullptr) {
          state = &entry;
          added = true;
          break;
        }
      }
    }
    if (state == nullptr) {
      table_full = true;
    } else {
      if (added) {
        state->connection = connection;
        connection_state_count.fetch_add(1, std::memory_order_release);
      }
      if (state->has_read_timestamp && timestamp < state->last_read_timestamp) {
        regressed = true;
        previous = state->last_read_timestamp;
      } else {
        state->last_read_timestamp = timestamp;
        state->has_read_timestamp = true;
      }
    }
  }
  if (table_full) {
    AbortTrackingOverflow(connection, "nghttp3_conn_read_stream2", 0);
  }
  if (regressed) {
    AbortTimestampRegression(connection, previous, timestamp);
  }
}

} // namespace

// GNU ld and lld provide each __real_* symbol when the final link uses the
// matching --wrap option. decltype ties these declarations to the installed
// nghttp3 headers and makes signature drift a compile-time failure.
extern "C" decltype(nghttp3_conn_client_new_versioned)
    __real_nghttp3_conn_client_new_versioned;
extern "C" decltype(nghttp3_conn_server_new_versioned)
    __real_nghttp3_conn_server_new_versioned;
extern "C" decltype(nghttp3_conn_del) __real_nghttp3_conn_del;
extern "C" decltype(nghttp3_conn_add_ack_offset)
    __real_nghttp3_conn_add_ack_offset;
extern "C" decltype(nghttp3_conn_add_write_offset)
    __real_nghttp3_conn_add_write_offset;
extern "C" decltype(nghttp3_conn_bind_control_stream)
    __real_nghttp3_conn_bind_control_stream;
extern "C" decltype(nghttp3_conn_bind_qpack_streams)
    __real_nghttp3_conn_bind_qpack_streams;
extern "C" decltype(nghttp3_conn_block_stream) __real_nghttp3_conn_block_stream;
extern "C" decltype(nghttp3_conn_close_stream) __real_nghttp3_conn_close_stream;
extern "C" decltype(nghttp3_conn_close_stream2)
    __real_nghttp3_conn_close_stream2;
extern "C" decltype(nghttp3_conn_read_stream) __real_nghttp3_conn_read_stream;
extern "C" decltype(nghttp3_conn_read_stream2) __real_nghttp3_conn_read_stream2;
extern "C" decltype(nghttp3_conn_resume_stream)
    __real_nghttp3_conn_resume_stream;
extern "C" decltype(nghttp3_conn_set_max_concurrent_streams)
    __real_nghttp3_conn_set_max_concurrent_streams;
extern "C" decltype(nghttp3_conn_set_stream_user_data)
    __real_nghttp3_conn_set_stream_user_data;
extern "C" decltype(nghttp3_conn_shutdown_stream_read)
    __real_nghttp3_conn_shutdown_stream_read;
extern "C" decltype(nghttp3_conn_shutdown_stream_write)
    __real_nghttp3_conn_shutdown_stream_write;
extern "C" decltype(nghttp3_conn_submit_info) __real_nghttp3_conn_submit_info;
extern "C" decltype(nghttp3_conn_submit_request)
    __real_nghttp3_conn_submit_request;
extern "C" decltype(nghttp3_conn_submit_response)
    __real_nghttp3_conn_submit_response;
extern "C" decltype(nghttp3_conn_submit_trailers)
    __real_nghttp3_conn_submit_trailers;
extern "C" decltype(nghttp3_conn_unblock_stream)
    __real_nghttp3_conn_unblock_stream;
extern "C" decltype(nghttp3_conn_writev_stream)
    __real_nghttp3_conn_writev_stream;

#define DEFINE_NEW_WRAPPER(name)                                               \
  extern "C" int __wrap_##name(                                                \
      nghttp3_conn **connection_ptr, int callbacks_version,                    \
      const nghttp3_callbacks *callbacks, int settings_version,                \
      const nghttp3_settings *settings, const nghttp3_mem *memory,             \
      void *connection_user_data) {                                            \
    if (IsRealCallActive()) {                                                  \
      return __real_##name(connection_ptr, callbacks_version, callbacks,       \
                           settings_version, settings, memory,                 \
                           connection_user_data);                              \
    }                                                                          \
    int result;                                                                \
    {                                                                          \
      RealCallScope real_call;                                                 \
      result = __real_##name(connection_ptr, callbacks_version, callbacks,     \
                             settings_version, settings, memory,               \
                             connection_user_data);                            \
    }                                                                          \
    if (result == 0 && connection_ptr != nullptr) {                            \
      RegisterConnection(*connection_ptr);                                     \
    }                                                                          \
    return result;                                                             \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

DEFINE_NEW_WRAPPER(nghttp3_conn_client_new_versioned)
DEFINE_NEW_WRAPPER(nghttp3_conn_server_new_versioned)

#undef DEFINE_NEW_WRAPPER

extern "C" void __wrap_nghttp3_conn_del(nghttp3_conn *connection) {
  if (IsRealCallActive()) {
    __real_nghttp3_conn_del(connection);
    return;
  }
  // Deallocation is the sole operation permitted after a fatal return.
  ForgetConnection(connection);
  RealCallScope real_call;
  __real_nghttp3_conn_del(connection);
}
static_assert(std::is_same<decltype(nghttp3_conn_del),
                           decltype(__wrap_nghttp3_conn_del)>::value,
              "nghttp3_conn_del signature changed");

#define DEFINE_CHECKED_WRAPPER(name, parameters, arguments)                    \
  extern "C" auto __wrap_##name parameters                                     \
      ->decltype(__real_##name arguments) {                                    \
    if (IsRealCallActive()) {                                                  \
      return __real_##name arguments;                                          \
    }                                                                          \
    CheckUsable(connection, #name);                                            \
    RealCallScope real_call;                                                   \
    return __real_##name arguments;                                            \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

DEFINE_CHECKED_WRAPPER(nghttp3_conn_add_ack_offset,
                       (nghttp3_conn * connection, int64_t stream_id,
                        uint64_t length),
                       (connection, stream_id, length))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_add_write_offset,
                       (nghttp3_conn * connection, int64_t stream_id,
                        size_t length),
                       (connection, stream_id, length))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_bind_control_stream,
                       (nghttp3_conn * connection, int64_t stream_id),
                       (connection, stream_id))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_bind_qpack_streams,
                       (nghttp3_conn * connection, int64_t encoder_stream_id,
                        int64_t decoder_stream_id),
                       (connection, encoder_stream_id, decoder_stream_id))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_block_stream,
                       (nghttp3_conn * connection, int64_t stream_id),
                       (connection, stream_id))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_close_stream,
                       (nghttp3_conn * connection, int64_t stream_id,
                        uint64_t application_error),
                       (connection, stream_id, application_error))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_close_stream2,
                       (nghttp3_conn * connection, uint32_t flags,
                        int64_t stream_id, uint64_t receive_error,
                        uint64_t transmit_error),
                       (connection, flags, stream_id, receive_error,
                        transmit_error))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_resume_stream,
                       (nghttp3_conn * connection, int64_t stream_id),
                       (connection, stream_id))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_set_max_concurrent_streams,
                       (nghttp3_conn * connection, size_t maximum),
                       (connection, maximum))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_set_stream_user_data,
                       (nghttp3_conn * connection, int64_t stream_id,
                        void *stream_user_data),
                       (connection, stream_id, stream_user_data))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_shutdown_stream_read,
                       (nghttp3_conn * connection, int64_t stream_id),
                       (connection, stream_id))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_shutdown_stream_write,
                       (nghttp3_conn * connection, int64_t stream_id),
                       (connection, stream_id))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_submit_info,
                       (nghttp3_conn * connection, int64_t stream_id,
                        const nghttp3_nv *name_values, size_t count),
                       (connection, stream_id, name_values, count))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_submit_request,
                       (nghttp3_conn * connection, int64_t stream_id,
                        const nghttp3_nv *name_values, size_t count,
                        const nghttp3_data_reader *reader,
                        void *stream_user_data),
                       (connection, stream_id, name_values, count, reader,
                        stream_user_data))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_submit_response,
                       (nghttp3_conn * connection, int64_t stream_id,
                        const nghttp3_nv *name_values, size_t count,
                        const nghttp3_data_reader *reader),
                       (connection, stream_id, name_values, count, reader))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_submit_trailers,
                       (nghttp3_conn * connection, int64_t stream_id,
                        const nghttp3_nv *name_values, size_t count),
                       (connection, stream_id, name_values, count))
DEFINE_CHECKED_WRAPPER(nghttp3_conn_unblock_stream,
                       (nghttp3_conn * connection, int64_t stream_id),
                       (connection, stream_id))

#undef DEFINE_CHECKED_WRAPPER

extern "C" nghttp3_ssize
__wrap_nghttp3_conn_read_stream(nghttp3_conn *connection, int64_t stream_id,
                                const uint8_t *source, size_t source_length,
                                int fin) {
  if (IsRealCallActive()) {
    return __real_nghttp3_conn_read_stream(connection, stream_id, source,
                                           source_length, fin);
  }
  CheckUsable(connection, "nghttp3_conn_read_stream");
  nghttp3_ssize result;
  {
    RealCallScope real_call;
    result = __real_nghttp3_conn_read_stream(connection, stream_id, source,
                                             source_length, fin);
  }
  RecordFatalResult(connection, "nghttp3_conn_read_stream",
                    static_cast<long long>(result));
  return result;
}
static_assert(std::is_same<decltype(nghttp3_conn_read_stream),
                           decltype(__wrap_nghttp3_conn_read_stream)>::value,
              "nghttp3_conn_read_stream signature changed");

extern "C" nghttp3_ssize
__wrap_nghttp3_conn_read_stream2(nghttp3_conn *connection, int64_t stream_id,
                                 const uint8_t *source, size_t source_length,
                                 int fin, nghttp3_tstamp timestamp) {
  if (IsRealCallActive()) {
    return __real_nghttp3_conn_read_stream2(connection, stream_id, source,
                                            source_length, fin, timestamp);
  }
  CheckUsable(connection, "nghttp3_conn_read_stream2");
  RecordReadTimestamp(connection, timestamp);
  nghttp3_ssize result;
  {
    RealCallScope real_call;
    result = __real_nghttp3_conn_read_stream2(connection, stream_id, source,
                                              source_length, fin, timestamp);
  }
  RecordFatalResult(connection, "nghttp3_conn_read_stream2",
                    static_cast<long long>(result));
  return result;
}
static_assert(std::is_same<decltype(nghttp3_conn_read_stream2),
                           decltype(__wrap_nghttp3_conn_read_stream2)>::value,
              "nghttp3_conn_read_stream2 signature changed");

extern "C" nghttp3_ssize
__wrap_nghttp3_conn_writev_stream(nghttp3_conn *connection, int64_t *stream_id,
                                  int *fin, nghttp3_vec *vectors,
                                  size_t vector_count) {
  if (IsRealCallActive()) {
    return __real_nghttp3_conn_writev_stream(connection, stream_id, fin,
                                             vectors, vector_count);
  }
  CheckUsable(connection, "nghttp3_conn_writev_stream");
  nghttp3_ssize result;
  {
    RealCallScope real_call;
    result = __real_nghttp3_conn_writev_stream(connection, stream_id, fin,
                                               vectors, vector_count);
  }
  RecordFatalResult(connection, "nghttp3_conn_writev_stream",
                    static_cast<long long>(result));
  return result;
}
static_assert(std::is_same<decltype(nghttp3_conn_writev_stream),
                           decltype(__wrap_nghttp3_conn_writev_stream)>::value,
              "nghttp3_conn_writev_stream signature changed");
