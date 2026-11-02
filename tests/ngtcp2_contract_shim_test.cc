/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <ngtcp2/ngtcp2.h>

#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "test_assertions.h"

namespace {

using test_support::Expect;

extern "C" void
curl_fuzzer_ngtcp2_contract_test_force_stream_result(ngtcp2_ssize result,
                                                     ngtcp2_ssize data_length);
extern "C" void
curl_fuzzer_ngtcp2_contract_test_force_datagram_result(ngtcp2_ssize result,
                                                       int accepted);

extern "C" int UnusedCallback() { return 0; }

template <typename Callback> Callback CallbackStub() {
  return reinterpret_cast<Callback>(&UnusedCallback);
}

class TestConnection {
public:
  explicit TestConnection(const ngtcp2_mem *memory = nullptr) {
    local_address_.sin_family = AF_INET;
    remote_address_.sin_family = AF_INET;
    ngtcp2_path_storage_init(
        &path_storage_,
        reinterpret_cast<const ngtcp2_sockaddr *>(&local_address_),
        sizeof(local_address_),
        reinterpret_cast<const ngtcp2_sockaddr *>(&remote_address_),
        sizeof(remote_address_), nullptr);

    std::array<uint8_t, 18> destination_id{};
    std::array<uint8_t, 8> source_id{};
    ngtcp2_cid dcid{};
    ngtcp2_cid scid{};
    ngtcp2_cid_init(&dcid, destination_id.data(), destination_id.size());
    ngtcp2_cid_init(&scid, source_id.data(), source_id.size());

    ngtcp2_callbacks callbacks{};
    callbacks.recv_client_initial =
        CallbackStub<decltype(callbacks.recv_client_initial)>();
    callbacks.recv_crypto_data =
        CallbackStub<decltype(callbacks.recv_crypto_data)>();
    callbacks.encrypt = CallbackStub<decltype(callbacks.encrypt)>();
    callbacks.decrypt = CallbackStub<decltype(callbacks.decrypt)>();
    callbacks.hp_mask = CallbackStub<decltype(callbacks.hp_mask)>();
    callbacks.rand = CallbackStub<decltype(callbacks.rand)>();
    callbacks.get_new_connection_id2 =
        CallbackStub<decltype(callbacks.get_new_connection_id2)>();
    callbacks.update_key = CallbackStub<decltype(callbacks.update_key)>();
    callbacks.delete_crypto_aead_ctx =
        CallbackStub<decltype(callbacks.delete_crypto_aead_ctx)>();
    callbacks.delete_crypto_cipher_ctx =
        CallbackStub<decltype(callbacks.delete_crypto_cipher_ctx)>();
    callbacks.get_path_challenge_data2 =
        CallbackStub<decltype(callbacks.get_path_challenge_data2)>();

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = kTimestamp;

    ngtcp2_transport_params parameters;
    ngtcp2_transport_params_default(&parameters);
    parameters.original_dcid = dcid;
    parameters.original_dcid_present = 1;
    parameters.initial_max_data = 4096;
    parameters.initial_max_stream_data_bidi_local = 1024;
    parameters.initial_max_stream_data_bidi_remote = 1024;
    parameters.initial_max_streams_bidi = 4;

    const int result = ngtcp2_conn_server_new(
        &connection_, &dcid, &scid, &path_storage_.path, NGTCP2_PROTO_VER_V1,
        &callbacks, &settings, &parameters, memory, nullptr);
    Expect(result == 0 && connection_ != nullptr,
           "could not create ngtcp2 test connection");
  }

  ~TestConnection() { Free(); }

  void Free() {
    if (connection_ != nullptr) {
      ngtcp2_conn_del(connection_);
      connection_ = nullptr;
    }
  }

  ngtcp2_conn *connection() const { return connection_; }
  ngtcp2_path *path() { return &path_storage_.path; }
  uint8_t *destination() { return destination_.data(); }
  size_t destination_size() const { return destination_.size(); }

  static constexpr ngtcp2_tstamp kTimestamp = 1;

  TestConnection(const TestConnection &) = delete;
  TestConnection &operator=(const TestConnection &) = delete;

private:
  ngtcp2_conn *connection_ = nullptr;
  sockaddr_in local_address_{};
  sockaddr_in remote_address_{};
  ngtcp2_path_storage path_storage_{};
  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> destination_{};
};

constexpr ngtcp2_tstamp TestConnection::kTimestamp;

void BeginCoalescing(TestConnection &connection) {
  ngtcp2_ssize data_length = 123;
  const ngtcp2_ssize result = ngtcp2_conn_writev_stream(
      connection.connection(), connection.path(), nullptr,
      connection.destination(), connection.destination_size(), &data_length,
      NGTCP2_WRITE_STREAM_FLAG_MORE, 100, nullptr, 0,
      TestConnection::kTimestamp);
  Expect(result == NGTCP2_ERR_STREAM_NOT_FOUND,
         "unknown stream did not start the deterministic MORE transaction");
  Expect(data_length == -1,
         "STREAM_NOT_FOUND did not set the documented pdatalen value");
}

void FinishCoalescing(TestConnection &connection) {
  ngtcp2_ssize data_length = 123;
  const ngtcp2_ssize result = ngtcp2_conn_writev_stream(
      connection.connection(), connection.path(), nullptr,
      connection.destination(), connection.destination_size(), &data_length,
      NGTCP2_WRITE_STREAM_FLAG_MORE, -1, nullptr, 0,
      TestConnection::kTimestamp);
  Expect(result == 0, "empty continuation did not finish packet coalescing");
  Expect(data_length == -1,
         "empty continuation did not preserve the no-stream-data sentinel");
}

void TestCompletedTransactionAllowsOtherCalls() {
  TestConnection connection;
  BeginCoalescing(connection);
  FinishCoalescing(connection);
  (void)ngtcp2_conn_get_max_data_left(connection.connection());
}

void TestOtherConnectionsRemainUsable() {
  TestConnection coalescing;
  TestConnection unrelated;
  BeginCoalescing(coalescing);
  (void)ngtcp2_conn_get_max_data_left(unrelated.connection());
  FinishCoalescing(coalescing);
}

void TestStreamShutdownIsAllowedAndKeepsTransaction() {
  TestConnection connection;
  BeginCoalescing(connection);
  Expect(ngtcp2_conn_shutdown_stream_write(connection.connection(), 0, 100,
                                           0) == 0,
         "stream shutdown was not accepted during packet coalescing");
  FinishCoalescing(connection);
}

void TestConnectionCloseIsAllowed() {
  TestConnection connection;
  BeginCoalescing(connection);

  ngtcp2_ccerr error;
  ngtcp2_ccerr_default(&error);
  ngtcp2_ccerr_set_application_error(&error, 1, nullptr, 0);
  (void)ngtcp2_conn_write_connection_close(
      connection.connection(), connection.path(), nullptr,
      connection.destination(), connection.destination_size(), &error,
      TestConnection::kTimestamp);
  connection.Free();
}

void BeginForcedDatagramCoalescing(TestConnection &connection) {
  curl_fuzzer_ngtcp2_contract_test_force_datagram_result(NGTCP2_ERR_WRITE_MORE,
                                                         1);
  int accepted = 0;
  const ngtcp2_ssize result = ngtcp2_conn_writev_datagram(
      connection.connection(), connection.path(), nullptr,
      connection.destination(), connection.destination_size(), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 7, nullptr, 0,
      TestConnection::kTimestamp);
  Expect(result == NGTCP2_ERR_WRITE_MORE && accepted != 0,
         "forced DATAGRAM write did not begin packet coalescing");
}

void ContinueForcedDatagram(TestConnection &connection, ngtcp2_ssize result) {
  curl_fuzzer_ngtcp2_contract_test_force_datagram_result(result, 0);
  int accepted = 1;
  const ngtcp2_ssize actual = ngtcp2_conn_writev_datagram(
      connection.connection(), connection.path(), nullptr,
      connection.destination(), connection.destination_size(), &accepted,
      NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 8, nullptr, 0,
      TestConnection::kTimestamp);
  Expect(actual == result, "forced DATAGRAM continuation result changed");
}

void TestPositiveDatagramResultEndsTransaction() {
  TestConnection connection;
  BeginForcedDatagramCoalescing(connection);
  ContinueForcedDatagram(connection, 12);
  (void)ngtcp2_conn_get_max_data_left(connection.connection());
}

void TestFatalDatagramResultAllowsConnectionClose() {
  TestConnection connection;
  BeginForcedDatagramCoalescing(connection);
  ContinueForcedDatagram(connection, NGTCP2_ERR_INVALID_STATE);

  ngtcp2_ccerr error;
  ngtcp2_ccerr_default(&error);
  ngtcp2_ccerr_set_application_error(&error, 1, nullptr, 0);
  (void)ngtcp2_conn_write_connection_close(
      connection.connection(), connection.path(), nullptr,
      connection.destination(), connection.destination_size(), &error,
      TestConnection::kTimestamp);
  connection.Free();
}

class ReusingArena {
public:
  ReusingArena() {
    memory_.user_data = this;
    memory_.malloc = &Allocate;
    memory_.free = &Free;
    memory_.calloc = &Callocate;
    memory_.realloc = &Reallocate;
  }

  const ngtcp2_mem *memory() const { return &memory_; }
  void Reset() { offset_ = 0; }

private:
  struct alignas(std::max_align_t) Header {
    size_t size;
  };

  static void *Allocate(size_t size, void *user_data) {
    ReusingArena &arena = *static_cast<ReusingArena *>(user_data);
    const size_t alignment = alignof(std::max_align_t);
    const size_t aligned = (arena.offset_ + alignment - 1) & ~(alignment - 1);
    if (size > arena.storage_.size() - aligned - sizeof(Header))
      return nullptr;
    Header *header =
        reinterpret_cast<Header *>(arena.storage_.data() + aligned);
    header->size = size;
    arena.offset_ = aligned + sizeof(Header) + size;
    return header + 1;
  }

  static void Free(void *, void *) {}

  static void *Callocate(size_t count, size_t size, void *user_data) {
    if (size != 0 && count > static_cast<size_t>(-1) / size)
      return nullptr;
    const size_t total = count * size;
    void *result = Allocate(total, user_data);
    if (result != nullptr)
      std::memset(result, 0, total);
    return result;
  }

  static void *Reallocate(void *pointer, size_t size, void *user_data) {
    if (pointer == nullptr)
      return Allocate(size, user_data);
    void *result = Allocate(size, user_data);
    if (result != nullptr) {
      const Header *old_header = static_cast<const Header *>(pointer) - 1;
      std::memcpy(result, pointer, std::min(old_header->size, size));
    }
    return result;
  }

  ngtcp2_mem memory_{};
  size_t offset_ = 0;
  alignas(std::max_align_t) std::array<uint8_t, 4 * 1024 * 1024> storage_{};
};

void TestTeardownForgetsReusedAddress() {
  static ReusingArena arena;
  ngtcp2_conn *old_address = nullptr;
  {
    TestConnection connection(arena.memory());
    old_address = connection.connection();
    BeginCoalescing(connection);
    connection.Free();
  }

  arena.Reset();
  TestConnection replacement(arena.memory());
  Expect(replacement.connection() == old_address,
         "test arena did not reuse the ngtcp2 connection address");
  (void)ngtcp2_conn_get_max_data_left(replacement.connection());
}

using Violation = void (*)();

void ViolateLikeCurrentCurlNextLoop() {
  TestConnection connection;
  BeginCoalescing(connection);
  (void)ngtcp2_conn_get_max_data_left(connection.connection());
}

void ViolateWithChangedDestination() {
  TestConnection connection;
  BeginCoalescing(connection);
  ngtcp2_ssize data_length = 123;
  (void)ngtcp2_conn_writev_stream(connection.connection(), connection.path(),
                                  nullptr, connection.destination() + 1,
                                  connection.destination_size() - 1,
                                  &data_length, NGTCP2_WRITE_STREAM_FLAG_MORE,
                                  -1, nullptr, 0, TestConnection::kTimestamp);
}

void ViolateAfterZeroDatagramResult() {
  TestConnection connection;
  BeginForcedDatagramCoalescing(connection);
  ContinueForcedDatagram(connection, 0);
  // Unlike stream-origin coalescing, a DATAGRAM-origin transaction remains
  // active after zero and must continue until a positive packet is produced.
  (void)ngtcp2_conn_get_max_data_left(connection.connection());
}

void ViolateAfterFatalDatagramResult() {
  TestConnection connection;
  BeginForcedDatagramCoalescing(connection);
  ContinueForcedDatagram(connection, NGTCP2_ERR_INVALID_STATE);
  // The DATAGRAM-origin rule requires a positive result. A later error can be
  // handled with connection close, stream shutdown, or connection teardown,
  // but it does not authorize arbitrary ngtcp2 calls.
  (void)ngtcp2_conn_get_max_data_left(connection.connection());
}

void ViolateStreamPostcondition() {
  TestConnection connection;
  curl_fuzzer_ngtcp2_contract_test_force_stream_result(NGTCP2_ERR_WRITE_MORE,
                                                       -1);
  ngtcp2_ssize data_length = 0;
  (void)ngtcp2_conn_writev_stream(connection.connection(), connection.path(),
                                  nullptr, connection.destination(),
                                  connection.destination_size(), &data_length,
                                  NGTCP2_WRITE_STREAM_FLAG_MORE, 100, nullptr,
                                  0, TestConnection::kTimestamp);
}

void ViolateZeroDatagramPostcondition() {
  TestConnection connection;
  curl_fuzzer_ngtcp2_contract_test_force_datagram_result(0, 1);
  int accepted = 0;
  (void)ngtcp2_conn_writev_datagram(connection.connection(), connection.path(),
                                    nullptr, connection.destination(),
                                    connection.destination_size(), &accepted,
                                    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 7, nullptr,
                                    0, TestConnection::kTimestamp);
}

void ExpectViolation(Violation violation,
                     const std::array<const char *, 3> &fragments) {
  int diagnostic_pipe[2];
  Expect(pipe(diagnostic_pipe) == 0, "could not create ngtcp2 diagnostic pipe");

  const pid_t child = fork();
  Expect(child >= 0, "could not fork ngtcp2 contract child");
  if (child == 0) {
    close(diagnostic_pipe[0]);
    if (dup2(diagnostic_pipe[1], STDERR_FILENO) < 0)
      _exit(90);
    close(diagnostic_pipe[1]);
    violation();
    _exit(91);
  }

  close(diagnostic_pipe[1]);
  std::string diagnostic;
  std::array<char, 512> buffer{};
  for (;;) {
    const ssize_t length =
        read(diagnostic_pipe[0], buffer.data(), buffer.size());
    if (length > 0) {
      diagnostic.append(buffer.data(), static_cast<size_t>(length));
      continue;
    }
    if (length < 0 && errno == EINTR)
      continue;
    break;
  }
  close(diagnostic_pipe[0]);

  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  Expect(waited == child, "could not wait for ngtcp2 contract child");
  Expect(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
         "ngtcp2 contract violation did not abort");
  for (const char *fragment : fragments) {
    Expect(diagnostic.find(fragment) != std::string::npos,
           "ngtcp2 diagnostic omitted expected context");
  }
}

void TestCurrentCurlNextLoopAbortsWithDiagnostic() {
  // read_pkt_to_send() currently reaches this getter at the top of the next
  // loop iteration after the same MORE/STREAM_NOT_FOUND outcome.
  ExpectViolation(ViolateLikeCurrentCurlNextLoop,
                  {{"ngtcp2 contract assertion failed",
                    "ngtcp2_conn_get_max_data_left called",
                    "ngtcp2_conn_writev_stream_versioned"}});
}

void TestChangedTupleAbortsWithDiagnostic() {
  ExpectViolation(
      ViolateWithChangedDestination,
      {{"ngtcp2 contract assertion failed",
        "ngtcp2_conn_writev_stream_versioned changed", "destination buffer"}});
}

void TestZeroDatagramResultKeepsTransaction() {
  ExpectViolation(ViolateAfterZeroDatagramResult,
                  {{"ngtcp2 contract assertion failed",
                    "ngtcp2_conn_get_max_data_left called",
                    "ngtcp2_conn_writev_datagram_versioned"}});
}

void TestFatalDatagramResultKeepsTransaction() {
  ExpectViolation(ViolateAfterFatalDatagramResult,
                  {{"ngtcp2 contract assertion failed",
                    "ngtcp2_conn_get_max_data_left called",
                    "ngtcp2_conn_writev_datagram_versioned"}});
}

void TestStreamPostconditionAbortsWithDiagnostic() {
  ExpectViolation(ViolateStreamPostcondition,
                  {{"ngtcp2 contract assertion failed",
                    "ngtcp2_conn_writev_stream_versioned returned",
                    "pdatalen is negative"}});
}

void TestZeroDatagramPostconditionAbortsWithDiagnostic() {
  ExpectViolation(ViolateZeroDatagramPostcondition,
                  {{"ngtcp2 contract assertion failed",
                    "ngtcp2_conn_writev_datagram_versioned returned 0",
                    "paccepted is nonzero"}});
}

} // namespace

int main() {
  TestCompletedTransactionAllowsOtherCalls();
  TestOtherConnectionsRemainUsable();
  TestStreamShutdownIsAllowedAndKeepsTransaction();
  TestConnectionCloseIsAllowed();
  TestPositiveDatagramResultEndsTransaction();
  TestFatalDatagramResultAllowsConnectionClose();
  TestTeardownForgetsReusedAddress();
  TestCurrentCurlNextLoopAbortsWithDiagnostic();
  TestChangedTupleAbortsWithDiagnostic();
  TestZeroDatagramResultKeepsTransaction();
  TestFatalDatagramResultKeepsTransaction();
  TestStreamPostconditionAbortsWithDiagnostic();
  TestZeroDatagramPostconditionAbortsWithDiagnostic();
  return 0;
}
