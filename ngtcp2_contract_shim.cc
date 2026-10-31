/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <ngtcp2/ngtcp2.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <type_traits>

namespace {

enum class TransactionOrigin {
  Stream,
  Datagram,
};

enum class ContractState {
  Coalescing,
  CloseOnly,
};

struct ConnectionContract {
  const ngtcp2_conn *conn = nullptr;
  const char *write_api = nullptr;
  ngtcp2_ssize error_result = 0;
  const ngtcp2_path *path = nullptr;
  const ngtcp2_pkt_info *pi = nullptr;
  const uint8_t *dest = nullptr;
  size_t destlen = 0;
  ngtcp2_tstamp timestamp = 0;
  TransactionOrigin origin = TransactionOrigin::Stream;
  ContractState state = ContractState::Coalescing;
};

struct ContinuationState {
  bool active = false;
  TransactionOrigin origin = TransactionOrigin::Stream;
};

// Fault injection must not disable or perturb the monitor itself.
constexpr std::size_t kMaximumTrackedConnections = 256;
std::array<ConnectionContract, kMaximumTrackedConnections> contracts{};
std::mutex contracts_mutex;
std::atomic<std::size_t> contract_count{0};

#if defined(NGTCP2_CONTRACT_TESTING)
struct ForcedWriteResult {
  bool active = false;
  ngtcp2_ssize result = 0;
  ngtcp2_ssize data_length = -1;
  int accepted = 0;
};

thread_local ForcedWriteResult forced_stream_result;
thread_local ForcedWriteResult forced_datagram_result;

bool TakeForcedStreamResult(ngtcp2_ssize *result, ngtcp2_ssize *data_length) {
  if (!forced_stream_result.active)
    return false;
  *result = forced_stream_result.result;
  if (data_length != nullptr)
    *data_length = forced_stream_result.data_length;
  forced_stream_result.active = false;
  return true;
}

bool TakeForcedDatagramResult(ngtcp2_ssize *result, int *accepted) {
  if (!forced_datagram_result.active)
    return false;
  *result = forced_datagram_result.result;
  if (accepted != nullptr)
    *accepted = forced_datagram_result.accepted;
  forced_datagram_result.active = false;
  return true;
}
#endif

// Static libngtcp2 contains calls to its public APIs. --wrap redirects those
// calls too, so nested calls made by a real ngtcp2 function bypass the monitor
// and cannot be mistaken for application calls while a restriction is active.
thread_local unsigned real_call_depth = 0;

class RealCallScope {
public:
  RealCallScope() { ++real_call_depth; }
  ~RealCallScope() { --real_call_depth; }

  RealCallScope(const RealCallScope &) = delete;
  RealCallScope &operator=(const RealCallScope &) = delete;
};

bool IsRealCallActive() { return real_call_depth != 0; }

ConnectionContract *FindContract(const ngtcp2_conn *conn) {
  for (ConnectionContract &contract : contracts) {
    if (contract.conn == conn)
      return &contract;
  }
  return nullptr;
}

[[noreturn]] void AbortForbiddenCall(const char *attempted_api,
                                     const ConnectionContract &transaction) {
  if (transaction.state == ContractState::CloseOnly) {
    std::fprintf(stderr,
                 "ngtcp2 contract assertion failed: %s called on connection "
                 "%p after %s returned %td; the connection is close-only, "
                 "and only connection close, terminal status inspection, or "
                 "connection teardown is allowed\n",
                 attempted_api, static_cast<const void *>(transaction.conn),
                 transaction.write_api, transaction.error_result);
    std::fflush(stderr);
    std::abort();
  }
  std::fprintf(stderr,
               "ngtcp2 contract assertion failed: %s called on connection "
               "%p while a packet started by %s is being coalesced; only "
               "writev_stream/writev_datagram continuation, connection "
               "close, stream shutdown, or connection teardown is allowed\n",
               attempted_api, static_cast<const void *>(transaction.conn),
               transaction.write_api);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortTupleMismatch(const char *attempted_api,
                                     const char *field,
                                     const ConnectionContract &transaction) {
  std::fprintf(stderr,
               "ngtcp2 contract assertion failed: %s changed %s on "
               "connection %p while continuing a packet started by %s; "
               "conn, path, pi, dest, destlen, and timestamp must remain "
               "identical\n",
               attempted_api, field,
               static_cast<const void *>(transaction.conn),
               transaction.write_api);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortPostcondition(const char *api, ngtcp2_ssize result,
                                     const char *postcondition) {
  std::fprintf(stderr,
               "ngtcp2 contract assertion failed: %s returned %td but %s\n",
               api, result, postcondition);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortTrackingOverflow(const ConnectionContract &value) {
  std::fprintf(stderr,
               "ngtcp2 contract assertion failed: cannot track connection "
               "%p after %s established a restricted state; contract table "
               "is full\n",
               static_cast<const void *>(value.conn), value.write_api);
  std::fflush(stderr);
  std::abort();
}

void CheckNoTransaction(const ngtcp2_conn *conn, const char *attempted_api,
                        bool allow_coalescing = false,
                        bool allow_close_only = false) {
  if (conn == nullptr || contract_count.load(std::memory_order_acquire) == 0)
    return;

  ConnectionContract value;
  {
    std::lock_guard<std::mutex> lock(contracts_mutex);
    const ConnectionContract *contract = FindContract(conn);
    if (contract != nullptr)
      value = *contract;
  }
  if (value.conn == nullptr)
    return;
  if ((allow_coalescing && value.state == ContractState::Coalescing) ||
      (allow_close_only && value.state == ContractState::CloseOnly))
    return;
  AbortForbiddenCall(attempted_api, value);
}

ContinuationState CheckContinuation(const ngtcp2_conn *conn,
                                    const ngtcp2_path *path,
                                    const ngtcp2_pkt_info *pi,
                                    const uint8_t *dest, size_t destlen,
                                    ngtcp2_tstamp timestamp,
                                    const char *attempted_api) {
  if (conn == nullptr || contract_count.load(std::memory_order_acquire) == 0)
    return ContinuationState{};

  ConnectionContract value;
  {
    std::lock_guard<std::mutex> lock(contracts_mutex);
    const ConnectionContract *contract = FindContract(conn);
    if (contract == nullptr)
      return ContinuationState{};
    value = *contract;
  }

  if (value.state == ContractState::CloseOnly)
    AbortForbiddenCall(attempted_api, value);

  if (value.path != path)
    AbortTupleMismatch(attempted_api, "path", value);
  if (value.pi != pi)
    AbortTupleMismatch(attempted_api, "packet info", value);
  if (value.dest != dest)
    AbortTupleMismatch(attempted_api, "destination buffer", value);
  if (value.destlen != destlen)
    AbortTupleMismatch(attempted_api, "destination length", value);
  if (value.timestamp != timestamp)
    AbortTupleMismatch(attempted_api, "timestamp", value);
  ContinuationState state;
  state.active = true;
  state.origin = value.origin;
  return state;
}

void ForgetContract(const ngtcp2_conn *conn) {
  if (conn == nullptr || contract_count.load(std::memory_order_acquire) == 0)
    return;

  std::lock_guard<std::mutex> lock(contracts_mutex);
  ConnectionContract *contract = FindContract(conn);
  if (contract != nullptr) {
    *contract = ConnectionContract{};
    contract_count.fetch_sub(1, std::memory_order_release);
  }
}

void StoreContract(ConnectionContract value, bool preserve_origin) {
  bool added = false;
  bool table_full = false;
  {
    std::lock_guard<std::mutex> lock(contracts_mutex);
    ConnectionContract *contract = FindContract(value.conn);
    if (contract == nullptr) {
      for (ConnectionContract &entry : contracts) {
        if (entry.conn == nullptr) {
          contract = &entry;
          added = true;
          break;
        }
      }
    }
    if (contract != nullptr) {
      if (!added && preserve_origin &&
          contract->state == ContractState::Coalescing) {
        value.write_api = contract->write_api;
        value.origin = contract->origin;
      }
      *contract = value;
      if (added)
        contract_count.fetch_add(1, std::memory_order_release);
    } else
      table_full = true;
  }
  if (table_full)
    AbortTrackingOverflow(value);
}

void RecordTransaction(const ngtcp2_conn *conn, const char *write_api,
                       const ngtcp2_path *path, const ngtcp2_pkt_info *pi,
                       const uint8_t *dest, size_t destlen,
                       ngtcp2_tstamp timestamp, TransactionOrigin origin,
                       bool keep_open) {
  if (conn == nullptr)
    return;
  if (!keep_open) {
    ForgetContract(conn);
    return;
  }

  ConnectionContract value;
  value.conn = conn;
  value.write_api = write_api;
  value.path = path;
  value.pi = pi;
  value.dest = dest;
  value.destlen = destlen;
  value.timestamp = timestamp;
  value.origin = origin;
  StoreContract(value, true);
}

void RecordCloseOnly(const ngtcp2_conn *conn, const char *write_api,
                     ngtcp2_ssize error_result) {
  if (conn == nullptr)
    return;

  ConnectionContract value;
  value.conn = conn;
  value.write_api = write_api;
  value.error_result = error_result;
  value.state = ContractState::CloseOnly;
  StoreContract(value, false);
}

bool IsStreamContinuationResult(ngtcp2_ssize result) {
  return result == NGTCP2_ERR_WRITE_MORE ||
         result == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
         result == NGTCP2_ERR_STREAM_NOT_FOUND ||
         result == NGTCP2_ERR_STREAM_SHUT_WR;
}

bool IsFatalResult(ngtcp2_ssize result) { return result < NGTCP2_ERR_FATAL; }

void ValidateStreamPostcondition(const char *api, ngtcp2_ssize result,
                                 const ngtcp2_ssize *pdatalen) {
  if (pdatalen == nullptr)
    return;
  if (result == NGTCP2_ERR_WRITE_MORE && *pdatalen < 0)
    AbortPostcondition(api, result,
                       "pdatalen is negative instead of nonnegative");
  if ((result == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
       result == NGTCP2_ERR_STREAM_NOT_FOUND ||
       result == NGTCP2_ERR_STREAM_SHUT_WR) &&
      *pdatalen != -1)
    AbortPostcondition(api, result, "pdatalen is not -1");
}

void ValidateDatagramPostcondition(const char *api, ngtcp2_ssize result,
                                   const int *paccepted) {
  if (result == 0 && paccepted != nullptr && *paccepted != 0)
    AbortPostcondition(api, result, "paccepted is nonzero instead of zero");
  if (result == NGTCP2_ERR_WRITE_MORE && paccepted != nullptr &&
      *paccepted == 0)
    AbortPostcondition(api, result, "paccepted is zero");
}

} // namespace

#if defined(NGTCP2_CONTRACT_TESTING)
extern "C" void
curl_fuzzer_ngtcp2_contract_test_force_stream_result(ngtcp2_ssize result,
                                                     ngtcp2_ssize data_length) {
  forced_stream_result.active = true;
  forced_stream_result.result = result;
  forced_stream_result.data_length = data_length;
}

extern "C" void
curl_fuzzer_ngtcp2_contract_test_force_datagram_result(ngtcp2_ssize result,
                                                       int accepted) {
  forced_datagram_result.active = true;
  forced_datagram_result.result = result;
  forced_datagram_result.accepted = accepted;
}
#endif

// GNU ld and lld provide each __real_* symbol when the final link uses the
// matching --wrap option. decltype ties these declarations to the installed
// ngtcp2 headers and makes signature drift a compile-time failure.
#define DECLARE_REAL(name) extern "C" decltype(name) __real_##name

DECLARE_REAL(ngtcp2_conn_client_new_versioned);
DECLARE_REAL(ngtcp2_conn_server_new_versioned);
DECLARE_REAL(ngtcp2_conn_del);
DECLARE_REAL(ngtcp2_conn_decode_and_set_0rtt_transport_params);
DECLARE_REAL(ngtcp2_conn_encode_0rtt_transport_params);
DECLARE_REAL(ngtcp2_conn_extend_max_offset);
DECLARE_REAL(ngtcp2_conn_extend_max_stream_offset);
DECLARE_REAL(ngtcp2_conn_get_ccerr);
DECLARE_REAL(ngtcp2_conn_get_cwnd_left);
DECLARE_REAL(ngtcp2_conn_get_expiry);
DECLARE_REAL(ngtcp2_conn_get_expiry2);
DECLARE_REAL(ngtcp2_conn_get_handshake_completed);
DECLARE_REAL(ngtcp2_conn_get_max_data_left);
DECLARE_REAL(ngtcp2_conn_get_max_tx_udp_payload_size);
DECLARE_REAL(ngtcp2_conn_get_path_max_tx_udp_payload_size);
DECLARE_REAL(ngtcp2_conn_get_remote_transport_params);
DECLARE_REAL(ngtcp2_conn_get_send_quantum);
DECLARE_REAL(ngtcp2_conn_get_stream_user_data);
DECLARE_REAL(ngtcp2_conn_get_streams_uni_left);
DECLARE_REAL(ngtcp2_conn_get_timestamp);
DECLARE_REAL(ngtcp2_conn_get_tls_alert);
DECLARE_REAL(ngtcp2_conn_get_tls_early_data_rejected2);
DECLARE_REAL(ngtcp2_conn_handle_expiry);
DECLARE_REAL(ngtcp2_conn_in_draining_period);
DECLARE_REAL(ngtcp2_conn_open_bidi_stream);
DECLARE_REAL(ngtcp2_conn_open_uni_stream);
DECLARE_REAL(ngtcp2_conn_read_pkt_versioned);
DECLARE_REAL(ngtcp2_conn_set_keep_alive_timeout);
DECLARE_REAL(ngtcp2_conn_set_stream_user_data);
DECLARE_REAL(ngtcp2_conn_set_tls_native_handle);
DECLARE_REAL(ngtcp2_conn_shutdown_stream);
DECLARE_REAL(ngtcp2_conn_shutdown_stream_read);
DECLARE_REAL(ngtcp2_conn_shutdown_stream_write);
DECLARE_REAL(ngtcp2_conn_update_pkt_tx_time);
DECLARE_REAL(ngtcp2_conn_write_connection_close_versioned);
DECLARE_REAL(ngtcp2_conn_write_datagram_versioned);
DECLARE_REAL(ngtcp2_conn_write_pkt_versioned);
DECLARE_REAL(ngtcp2_conn_write_stream_versioned);
DECLARE_REAL(ngtcp2_conn_writev_datagram_versioned);
DECLARE_REAL(ngtcp2_conn_writev_stream_versioned);

#undef DECLARE_REAL

#define ASSERT_SIGNATURE(name)                                                 \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed")

extern "C" int __wrap_ngtcp2_conn_client_new_versioned(
    ngtcp2_conn **pconn, const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
    const ngtcp2_path *path, uint32_t version, int callbacks_version,
    const ngtcp2_callbacks *callbacks, int settings_version,
    const ngtcp2_settings *settings, int transport_params_version,
    const ngtcp2_transport_params *params, const ngtcp2_mem *mem,
    void *user_data) {
  if (IsRealCallActive())
    return __real_ngtcp2_conn_client_new_versioned(
        pconn, dcid, scid, path, version, callbacks_version, callbacks,
        settings_version, settings, transport_params_version, params, mem,
        user_data);
  int result;
  {
    RealCallScope real_call;
    result = __real_ngtcp2_conn_client_new_versioned(
        pconn, dcid, scid, path, version, callbacks_version, callbacks,
        settings_version, settings, transport_params_version, params, mem,
        user_data);
  }
  if (result == 0 && pconn != nullptr)
    ForgetContract(*pconn);
  return result;
}
ASSERT_SIGNATURE(ngtcp2_conn_client_new_versioned);

extern "C" int __wrap_ngtcp2_conn_server_new_versioned(
    ngtcp2_conn **pconn, const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
    const ngtcp2_path *path, uint32_t version, int callbacks_version,
    const ngtcp2_callbacks *callbacks, int settings_version,
    const ngtcp2_settings *settings, int transport_params_version,
    const ngtcp2_transport_params *params, const ngtcp2_mem *mem,
    void *user_data) {
  if (IsRealCallActive())
    return __real_ngtcp2_conn_server_new_versioned(
        pconn, dcid, scid, path, version, callbacks_version, callbacks,
        settings_version, settings, transport_params_version, params, mem,
        user_data);
  int result;
  {
    RealCallScope real_call;
    result = __real_ngtcp2_conn_server_new_versioned(
        pconn, dcid, scid, path, version, callbacks_version, callbacks,
        settings_version, settings, transport_params_version, params, mem,
        user_data);
  }
  if (result == 0 && pconn != nullptr)
    ForgetContract(*pconn);
  return result;
}
ASSERT_SIGNATURE(ngtcp2_conn_server_new_versioned);

extern "C" void __wrap_ngtcp2_conn_del(ngtcp2_conn *conn) {
  if (IsRealCallActive()) {
    __real_ngtcp2_conn_del(conn);
    return;
  }
  ForgetContract(conn);
  RealCallScope real_call;
  __real_ngtcp2_conn_del(conn);
}
ASSERT_SIGNATURE(ngtcp2_conn_del);

#define DEFINE_CHECKED_WRAPPER(name, parameters, arguments, conn_argument)     \
  extern "C" auto __wrap_##name parameters                                     \
      ->decltype(__real_##name arguments) {                                    \
    if (IsRealCallActive())                                                    \
      return __real_##name arguments;                                          \
    CheckNoTransaction(conn_argument, #name);                                  \
    RealCallScope real_call;                                                   \
    return __real_##name arguments;                                            \
  }                                                                            \
  ASSERT_SIGNATURE(name)

#define DEFINE_CHECKED_VOID_WRAPPER(name, parameters, arguments,               \
                                    conn_argument)                             \
  extern "C" void __wrap_##name parameters {                                   \
    if (IsRealCallActive()) {                                                  \
      __real_##name arguments;                                                 \
      return;                                                                  \
    }                                                                          \
    CheckNoTransaction(conn_argument, #name);                                  \
    RealCallScope real_call;                                                   \
    __real_##name arguments;                                                   \
  }                                                                            \
  ASSERT_SIGNATURE(name)

#define DEFINE_TERMINAL_INSPECTION_WRAPPER(name, parameters, arguments,        \
                                           conn_argument)                      \
  extern "C" auto __wrap_##name parameters                                     \
      ->decltype(__real_##name arguments) {                                    \
    if (IsRealCallActive())                                                    \
      return __real_##name arguments;                                          \
    CheckNoTransaction(conn_argument, #name, false, true);                     \
    RealCallScope real_call;                                                   \
    return __real_##name arguments;                                            \
  }                                                                            \
  ASSERT_SIGNATURE(name)

DEFINE_CHECKED_WRAPPER(ngtcp2_conn_decode_and_set_0rtt_transport_params,
                       (ngtcp2_conn * conn, const uint8_t *data,
                        size_t datalen),
                       (conn, data, datalen), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_encode_0rtt_transport_params,
                       (ngtcp2_conn * conn, uint8_t *dest, size_t destlen),
                       (conn, dest, destlen), conn);
DEFINE_CHECKED_VOID_WRAPPER(ngtcp2_conn_extend_max_offset,
                            (ngtcp2_conn * conn, uint64_t datalen),
                            (conn, datalen), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_extend_max_stream_offset,
                       (ngtcp2_conn * conn, int64_t stream_id,
                        uint64_t datalen),
                       (conn, stream_id, datalen), conn);
DEFINE_TERMINAL_INSPECTION_WRAPPER(ngtcp2_conn_get_ccerr, (ngtcp2_conn * conn),
                                   (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_cwnd_left, (ngtcp2_conn * conn), (conn),
                       conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_expiry, (ngtcp2_conn * conn), (conn),
                       conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_expiry2, (const ngtcp2_conn *conn),
                       (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_handshake_completed,
                       (ngtcp2_conn * conn), (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_max_data_left, (ngtcp2_conn * conn),
                       (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_max_tx_udp_payload_size,
                       (ngtcp2_conn * conn), (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_path_max_tx_udp_payload_size,
                       (ngtcp2_conn * conn), (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_remote_transport_params,
                       (ngtcp2_conn * conn), (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_send_quantum, (ngtcp2_conn * conn),
                       (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_stream_user_data,
                       (ngtcp2_conn * conn, int64_t stream_id),
                       (conn, stream_id), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_streams_uni_left, (ngtcp2_conn * conn),
                       (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_timestamp, (const ngtcp2_conn *conn),
                       (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_get_tls_early_data_rejected2,
                       (const ngtcp2_conn *conn), (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_handle_expiry,
                       (ngtcp2_conn * conn, ngtcp2_tstamp timestamp),
                       (conn, timestamp), conn);
DEFINE_TERMINAL_INSPECTION_WRAPPER(ngtcp2_conn_in_draining_period,
                                   (ngtcp2_conn * conn), (conn), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_open_bidi_stream,
                       (ngtcp2_conn * conn, int64_t *stream_id,
                        void *stream_user_data),
                       (conn, stream_id, stream_user_data), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_open_uni_stream,
                       (ngtcp2_conn * conn, int64_t *stream_id,
                        void *stream_user_data),
                       (conn, stream_id, stream_user_data), conn);
DEFINE_CHECKED_WRAPPER(
    ngtcp2_conn_read_pkt_versioned,
    (ngtcp2_conn * conn, const ngtcp2_path *path, int pkt_info_version,
     const ngtcp2_pkt_info *pi, const uint8_t *packet, size_t packet_length,
     ngtcp2_tstamp timestamp),
    (conn, path, pkt_info_version, pi, packet, packet_length, timestamp), conn);
DEFINE_CHECKED_VOID_WRAPPER(ngtcp2_conn_set_keep_alive_timeout,
                            (ngtcp2_conn * conn, ngtcp2_duration timeout),
                            (conn, timeout), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_set_stream_user_data,
                       (ngtcp2_conn * conn, int64_t stream_id,
                        void *stream_user_data),
                       (conn, stream_id, stream_user_data), conn);
DEFINE_CHECKED_VOID_WRAPPER(ngtcp2_conn_set_tls_native_handle,
                            (ngtcp2_conn * conn, void *tls_native_handle),
                            (conn, tls_native_handle), conn);
DEFINE_CHECKED_VOID_WRAPPER(ngtcp2_conn_update_pkt_tx_time,
                            (ngtcp2_conn * conn, ngtcp2_tstamp timestamp),
                            (conn, timestamp), conn);
DEFINE_CHECKED_WRAPPER(ngtcp2_conn_write_pkt_versioned,
                       (ngtcp2_conn * conn, ngtcp2_path *path,
                        int pkt_info_version, ngtcp2_pkt_info *pi,
                        uint8_t *dest, size_t destlen, ngtcp2_tstamp timestamp),
                       (conn, path, pkt_info_version, pi, dest, destlen,
                        timestamp),
                       conn);

DEFINE_TERMINAL_INSPECTION_WRAPPER(ngtcp2_conn_get_tls_alert,
                                   (ngtcp2_conn * conn), (conn), conn);

#undef DEFINE_TERMINAL_INSPECTION_WRAPPER
#undef DEFINE_CHECKED_VOID_WRAPPER
#undef DEFINE_CHECKED_WRAPPER

#define DEFINE_ALLOWED_SHUTDOWN_WRAPPER(name)                                  \
  extern "C" int __wrap_##name(ngtcp2_conn *conn, uint32_t flags,              \
                               int64_t stream_id, uint64_t app_error_code) {   \
    if (IsRealCallActive())                                                    \
      return __real_##name(conn, flags, stream_id, app_error_code);            \
    CheckNoTransaction(conn, #name, true, false);                              \
    RealCallScope real_call;                                                   \
    return __real_##name(conn, flags, stream_id, app_error_code);              \
  }                                                                            \
  ASSERT_SIGNATURE(name)

DEFINE_ALLOWED_SHUTDOWN_WRAPPER(ngtcp2_conn_shutdown_stream);
DEFINE_ALLOWED_SHUTDOWN_WRAPPER(ngtcp2_conn_shutdown_stream_read);
DEFINE_ALLOWED_SHUTDOWN_WRAPPER(ngtcp2_conn_shutdown_stream_write);

#undef DEFINE_ALLOWED_SHUTDOWN_WRAPPER

extern "C" ngtcp2_ssize __wrap_ngtcp2_conn_write_connection_close_versioned(
    ngtcp2_conn *conn, ngtcp2_path *path, int pkt_info_version,
    ngtcp2_pkt_info *pi, uint8_t *dest, size_t destlen,
    const ngtcp2_ccerr *ccerr, ngtcp2_tstamp timestamp) {
  if (IsRealCallActive())
    return __real_ngtcp2_conn_write_connection_close_versioned(
        conn, path, pkt_info_version, pi, dest, destlen, ccerr, timestamp);
  ngtcp2_ssize result;
  {
    RealCallScope real_call;
    result = __real_ngtcp2_conn_write_connection_close_versioned(
        conn, path, pkt_info_version, pi, dest, destlen, ccerr, timestamp);
  }
  return result;
}
ASSERT_SIGNATURE(ngtcp2_conn_write_connection_close_versioned);

#if defined(NGTCP2_CONTRACT_TESTING)
#define NGTCP2_CONTRACT_TAKE_FORCED_STREAM(result, data_length, forced)        \
  forced = TakeForcedStreamResult(&(result), (data_length))
#define NGTCP2_CONTRACT_TAKE_FORCED_DATAGRAM(result, accepted, forced)         \
  forced = TakeForcedDatagramResult(&(result), (accepted))
#else
#define NGTCP2_CONTRACT_TAKE_FORCED_STREAM(result, data_length, forced)        \
  do {                                                                         \
  } while (false)
#define NGTCP2_CONTRACT_TAKE_FORCED_DATAGRAM(result, accepted, forced)         \
  do {                                                                         \
  } while (false)
#endif

#define DEFINE_STREAM_WRITE_WRAPPER(name, data_type, data_name, count_name)    \
  extern "C" ngtcp2_ssize __wrap_##name(                                       \
      ngtcp2_conn *conn, ngtcp2_path *path, int pkt_info_version,              \
      ngtcp2_pkt_info *pi, uint8_t *dest, size_t destlen,                      \
      ngtcp2_ssize *pdatalen, uint32_t flags, int64_t stream_id,               \
      data_type *data_name, size_t count_name, ngtcp2_tstamp timestamp) {      \
    if (IsRealCallActive())                                                    \
      return __real_##name(conn, path, pkt_info_version, pi, dest, destlen,    \
                           pdatalen, flags, stream_id, data_name, count_name,  \
                           timestamp);                                         \
    const ContinuationState continuation =                                     \
        CheckContinuation(conn, path, pi, dest, destlen, timestamp, #name);    \
    ngtcp2_ssize result;                                                       \
    bool forced = false;                                                       \
    (void)forced;                                                              \
    /* Test builds can inject documented outcomes without constructing a */    \
    /* complete encrypted QUIC session. */                                     \
    /* NOLINTNEXTLINE(bugprone-macro-parentheses) */                           \
    NGTCP2_CONTRACT_TAKE_FORCED_STREAM(result, pdatalen, forced);              \
    if (!forced) {                                                             \
      RealCallScope real_call;                                                 \
      result = __real_##name(conn, path, pkt_info_version, pi, dest, destlen,  \
                             pdatalen, flags, stream_id, data_name,            \
                             count_name, timestamp);                           \
    }                                                                          \
    ValidateStreamPostcondition(#name, result, pdatalen);                      \
    const TransactionOrigin origin =                                           \
        continuation.active ? continuation.origin : TransactionOrigin::Stream; \
    const bool stream_coalescing =                                             \
        origin == TransactionOrigin::Stream &&                                 \
        (continuation.active || (flags & NGTCP2_WRITE_STREAM_FLAG_MORE) != 0); \
    const bool connection_error =                                              \
        IsFatalResult(result) || (stream_coalescing && result < 0 &&           \
                                  !IsStreamContinuationResult(result));        \
    if (connection_error) {                                                    \
      RecordCloseOnly(conn, #name, result);                                    \
      return result;                                                           \
    }                                                                          \
    const bool keep_open =                                                     \
        (IsStreamContinuationResult(result) &&                                 \
         (continuation.active ||                                               \
          (flags & NGTCP2_WRITE_STREAM_FLAG_MORE) != 0)) ||                    \
        (continuation.active &&                                                \
         continuation.origin == TransactionOrigin::Datagram && result <= 0);   \
    RecordTransaction(conn, #name, path, pi, dest, destlen, timestamp, origin, \
                      keep_open);                                              \
    return result;                                                             \
  }                                                                            \
  ASSERT_SIGNATURE(name)

DEFINE_STREAM_WRITE_WRAPPER(ngtcp2_conn_write_stream_versioned, const uint8_t,
                            data, datalen);
DEFINE_STREAM_WRITE_WRAPPER(ngtcp2_conn_writev_stream_versioned,
                            const ngtcp2_vec, data, datacnt);

#undef DEFINE_STREAM_WRITE_WRAPPER

#define DEFINE_DATAGRAM_WRITE_WRAPPER(name, data_type, data_name, count_name)  \
  extern "C" ngtcp2_ssize __wrap_##name(                                       \
      ngtcp2_conn *conn, ngtcp2_path *path, int pkt_info_version,              \
      ngtcp2_pkt_info *pi, uint8_t *dest, size_t destlen, int *paccepted,      \
      uint32_t flags, uint64_t datagram_id, data_type *data_name,              \
      size_t count_name, ngtcp2_tstamp timestamp) {                            \
    if (IsRealCallActive())                                                    \
      return __real_##name(conn, path, pkt_info_version, pi, dest, destlen,    \
                           paccepted, flags, datagram_id, data_name,           \
                           count_name, timestamp);                             \
    const ContinuationState continuation =                                     \
        CheckContinuation(conn, path, pi, dest, destlen, timestamp, #name);    \
    ngtcp2_ssize result;                                                       \
    bool forced = false;                                                       \
    (void)forced;                                                              \
    NGTCP2_CONTRACT_TAKE_FORCED_DATAGRAM(result, paccepted, forced);           \
    if (!forced) {                                                             \
      RealCallScope real_call;                                                 \
      result = __real_##name(conn, path, pkt_info_version, pi, dest, destlen,  \
                             paccepted, flags, datagram_id, data_name,         \
                             count_name, timestamp);                           \
    }                                                                          \
    ValidateDatagramPostcondition(#name, result, paccepted);                   \
    if (IsFatalResult(result)) {                                               \
      RecordCloseOnly(conn, #name, result);                                    \
      return result;                                                           \
    }                                                                          \
    const bool keep_open =                                                     \
        result == NGTCP2_ERR_WRITE_MORE ||                                     \
        (continuation.active &&                                                \
         continuation.origin == TransactionOrigin::Datagram && result <= 0);   \
    RecordTransaction(conn, #name, path, pi, dest, destlen, timestamp,         \
                      continuation.active ? continuation.origin                \
                                          : TransactionOrigin::Datagram,       \
                      keep_open);                                              \
    return result;                                                             \
  }                                                                            \
  ASSERT_SIGNATURE(name)

DEFINE_DATAGRAM_WRITE_WRAPPER(ngtcp2_conn_write_datagram_versioned,
                              const uint8_t, data, datalen);
DEFINE_DATAGRAM_WRITE_WRAPPER(ngtcp2_conn_writev_datagram_versioned,
                              const ngtcp2_vec, data, datacnt);

#undef DEFINE_DATAGRAM_WRITE_WRAPPER
#undef NGTCP2_CONTRACT_TAKE_FORCED_DATAGRAM
#undef NGTCP2_CONTRACT_TAKE_FORCED_STREAM
#undef ASSERT_SIGNATURE
