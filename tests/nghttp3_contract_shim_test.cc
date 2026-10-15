/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <nghttp3/nghttp3.h>

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>

#include "test_assertions.h"

namespace {

using test_support::Expect;

nghttp3_conn *NewClient(const nghttp3_mem *memory = nullptr) {
  nghttp3_callbacks callbacks{};
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);

  nghttp3_conn *connection = nullptr;
  Expect(nghttp3_conn_client_new(&connection, &callbacks, &settings, memory,
                                 nullptr) == 0,
         "could not allocate nghttp3 connection");
  return connection;
}

nghttp3_ssize PoisonWithReadStream(nghttp3_conn *connection) {
  // HTTP/3 unidirectional stream type 0x1 denotes a push stream, which
  // nghttp3 rejects for this client configuration.
  const uint8_t push_stream_type = 0x1;
  const nghttp3_ssize result = nghttp3_conn_read_stream(
      connection, 3, &push_stream_type, sizeof(push_stream_type), 0);
  Expect(result == NGHTTP3_ERR_H3_STREAM_CREATION_ERROR,
         "push stream did not fail nghttp3_conn_read_stream");
  return result;
}

nghttp3_ssize PoisonWithReadStream2(nghttp3_conn *connection) {
  const uint8_t push_stream_type = 0x1;
  const nghttp3_ssize result = nghttp3_conn_read_stream2(
      connection, 3, &push_stream_type, sizeof(push_stream_type), 0, 1);
  Expect(result == NGHTTP3_ERR_H3_STREAM_CREATION_ERROR,
         "push stream did not fail nghttp3_conn_read_stream2");
  return result;
}

nghttp3_ssize FailingReadData(nghttp3_conn *, int64_t, nghttp3_vec *, size_t,
                              uint32_t *, void *, void *) {
  return NGHTTP3_ERR_CALLBACK_FAILURE;
}

nghttp3_nv NameValue(const char *name, const char *value) {
  return {reinterpret_cast<const uint8_t *>(name),
          reinterpret_cast<const uint8_t *>(value), std::strlen(name),
          std::strlen(value), NGHTTP3_NV_FLAG_NONE};
}

nghttp3_ssize PoisonWithWritevStream(nghttp3_conn *connection) {
  Expect(nghttp3_conn_bind_control_stream(connection, 2) == 0,
         "could not bind nghttp3 control stream");
  Expect(nghttp3_conn_bind_qpack_streams(connection, 6, 10) == 0,
         "could not bind nghttp3 QPACK streams");

  const std::array<nghttp3_nv, 4> request_headers{
      NameValue(":scheme", "https"), NameValue(":method", "GET"),
      NameValue(":authority", "example.com"), NameValue(":path", "/")};
  nghttp3_data_reader reader{};
  reader.read_data = FailingReadData;
  Expect(nghttp3_conn_submit_request(connection, 0, request_headers.data(),
                                     request_headers.size(), &reader,
                                     nullptr) == 0,
         "could not submit nghttp3 request");

  std::array<nghttp3_vec, 16> vectors{};
  for (std::size_t attempt = 0; attempt < 16; ++attempt) {
    int64_t stream_id = -1;
    int fin = 0;
    const nghttp3_ssize result = nghttp3_conn_writev_stream(
        connection, &stream_id, &fin, vectors.data(), vectors.size());
    if (result < 0) {
      Expect(result == NGHTTP3_ERR_CALLBACK_FAILURE,
             "write callback returned an unexpected nghttp3 error");
      return result;
    }
    Expect(stream_id != -1,
           "nghttp3 stopped writing before invoking the failing reader");

    std::size_t written = 0;
    for (nghttp3_ssize index = 0; index < result; ++index) {
      Expect(vectors[static_cast<std::size_t>(index)].len <=
                 std::numeric_limits<std::size_t>::max() - written,
             "nghttp3 vector length overflowed");
      written += vectors[static_cast<std::size_t>(index)].len;
    }
    Expect(nghttp3_conn_add_write_offset(connection, stream_id, written) == 0,
           "could not consume nghttp3 output");
  }

  Expect(false, "nghttp3 did not invoke the failing data reader");
  return 0;
}

// A resettable arena makes connection-address reuse deterministic. Its no-op
// free is valid because the test resets the whole arena after conn_del.
class FixedArena {
public:
  nghttp3_mem Memory() { return {this, Malloc, Free, Calloc, Realloc}; }

  void Reset() {
    storage_.fill(0);
    used_ = 0;
  }

private:
  static constexpr std::size_t kCapacity = 256 * 1024;
  static constexpr std::size_t kAlignment = alignof(std::max_align_t);

  static std::size_t Align(std::size_t value) {
    return (value + kAlignment - 1) & ~(kAlignment - 1);
  }

  void *Allocate(std::size_t size, bool clear) {
    if (used_ > kCapacity - sizeof(std::size_t)) {
      return nullptr;
    }
    const std::size_t data_offset = Align(used_ + sizeof(std::size_t));
    if (data_offset > kCapacity || size > kCapacity - data_offset) {
      return nullptr;
    }

    std::memcpy(storage_.data() + data_offset - sizeof(size), &size,
                sizeof(size));
    void *result = storage_.data() + data_offset;
    if (clear) {
      std::memset(result, 0, size);
    }
    used_ = data_offset + size;
    return result;
  }

  static void *Malloc(std::size_t size, void *user_data) {
    return static_cast<FixedArena *>(user_data)->Allocate(size, false);
  }

  static void Free(void *, void *) {}

  static void *Calloc(std::size_t count, std::size_t size, void *user_data) {
    if (count != 0 && size > std::numeric_limits<std::size_t>::max() / count) {
      return nullptr;
    }
    return static_cast<FixedArena *>(user_data)->Allocate(count * size, true);
  }

  static void *Realloc(void *pointer, std::size_t size, void *user_data) {
    auto *arena = static_cast<FixedArena *>(user_data);
    if (pointer == nullptr) {
      return arena->Allocate(size, false);
    }
    if (size == 0) {
      return nullptr;
    }

    std::size_t old_size = 0;
    const auto *bytes = static_cast<const unsigned char *>(pointer);
    std::memcpy(&old_size, bytes - sizeof(old_size), sizeof(old_size));
    void *replacement = arena->Allocate(size, false);
    if (replacement != nullptr) {
      std::memcpy(replacement, pointer, std::min(old_size, size));
    }
    return replacement;
  }

  alignas(std::max_align_t) std::array<unsigned char, kCapacity> storage_{};
  std::size_t used_ = 0;
};

void TestNonfatalResultDoesNotPoison() {
  nghttp3_conn *connection = NewClient();
  Expect(nghttp3_conn_bind_control_stream(connection, 2) == 0,
         "could not bind nghttp3 control stream");
  Expect(nghttp3_conn_bind_control_stream(connection, 6) ==
             NGHTTP3_ERR_INVALID_STATE,
         "duplicate control stream returned an unexpected error");
  nghttp3_conn_set_max_concurrent_streams(connection, 8);
  nghttp3_conn_del(connection);
}

void TestNondecreasingTimestampsRemainUsable() {
  nghttp3_conn *connection = NewClient();
  Expect(nghttp3_conn_read_stream2(connection, 3, nullptr, 0, 0, 10) == 0,
         "empty nghttp3 stream read failed");
  Expect(nghttp3_conn_read_stream2(connection, 3, nullptr, 0, 0, 10) == 0,
         "equal nghttp3 timestamp was rejected");
  Expect(nghttp3_conn_read_stream2(connection, 3, nullptr, 0, 0, 11) == 0,
         "increasing nghttp3 timestamp was rejected");
  nghttp3_conn_del(connection);
}

void TestDeprecatedReadStreamAllowsItsInternalTimestampSentinel() {
  nghttp3_conn *connection = NewClient();
  Expect(nghttp3_conn_read_stream(connection, 3, nullptr, 0, 0) == 0,
         "deprecated nghttp3 stream read rejected its internal timestamp");
  nghttp3_conn_set_max_concurrent_streams(connection, 8);
  nghttp3_conn_del(connection);
}

void TestFatalConnectionCanBeDeletedAndAddressReused() {
  FixedArena arena;
  nghttp3_mem memory = arena.Memory();

  nghttp3_conn *first = NewClient(&memory);
  PoisonWithReadStream2(first);
  nghttp3_conn_del(first);

  arena.Reset();
  nghttp3_conn *reused = NewClient(&memory);
  Expect(reused == first, "fixed arena did not reuse the connection address");
  nghttp3_conn_set_max_concurrent_streams(reused, 8);
  nghttp3_conn_del(reused);
}

void ViolateAfterReadStream() {
  nghttp3_conn *connection = NewClient();
  PoisonWithReadStream(connection);
  nghttp3_conn_set_max_concurrent_streams(connection, 8);
}

void ViolateAfterReadStream2() {
  nghttp3_conn *connection = NewClient();
  PoisonWithReadStream2(connection);
  nghttp3_conn_set_max_concurrent_streams(connection, 8);
}

void ViolateAfterWritevStream() {
  nghttp3_conn *connection = NewClient();
  PoisonWithWritevStream(connection);
  nghttp3_conn_set_max_concurrent_streams(connection, 8);
}

void ViolateTimestampOrder() {
  nghttp3_conn *connection = NewClient();
  Expect(nghttp3_conn_read_stream2(connection, 3, nullptr, 0, 0, 10) == 0,
         "initial timestamp read failed");
  (void)nghttp3_conn_read_stream2(connection, 3, nullptr, 0, 0, 9);
}

void ViolateInvalidTimestamp() {
  nghttp3_conn *connection = NewClient();
  (void)nghttp3_conn_read_stream2(connection, 3, nullptr, 0, 0, UINT64_MAX);
}

using Violation = void (*)();

void ExpectViolationAbortsWithDiagnostic(Violation violate,
                                         const char *expected_detail) {
  int diagnostic_pipe[2];
  Expect(pipe(diagnostic_pipe) == 0, "could not create diagnostic pipe");
  std::fflush(nullptr);

  const pid_t child = fork();
  Expect(child >= 0, "could not fork nghttp3 contract test");
  if (child == 0) {
    close(diagnostic_pipe[0]);
    if (dup2(diagnostic_pipe[1], STDERR_FILENO) < 0) {
      _exit(90);
    }
    close(diagnostic_pipe[1]);
    violate();
    _exit(91);
  }

  close(diagnostic_pipe[1]);
  std::string diagnostic;
  std::array<char, 512> buffer{};
  for (;;) {
    const ssize_t length =
        read(diagnostic_pipe[0], buffer.data(), buffer.size());
    if (length > 0) {
      diagnostic.append(buffer.data(), static_cast<std::size_t>(length));
      continue;
    }
    if (length < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  close(diagnostic_pipe[0]);

  int status = 0;
  pid_t waited = 0;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  Expect(waited == child, "could not wait for nghttp3 contract child");
  Expect(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
         "nghttp3 contract violation did not abort");
  Expect(diagnostic.find("nghttp3 contract assertion failed") !=
             std::string::npos,
         "contract diagnostic omitted the assertion context");
  Expect(diagnostic.find(expected_detail) != std::string::npos,
         "contract diagnostic omitted the violation detail");
}

void TestUseAfterEachFatalResultAborts() {
  const std::string read_fatal =
      "nghttp3_conn_read_stream returned " +
      std::to_string(NGHTTP3_ERR_H3_STREAM_CREATION_ERROR);
  ExpectViolationAbortsWithDiagnostic(ViolateAfterReadStream,
                                      read_fatal.c_str());

  const std::string read2_fatal =
      "nghttp3_conn_read_stream2 returned " +
      std::to_string(NGHTTP3_ERR_H3_STREAM_CREATION_ERROR);
  ExpectViolationAbortsWithDiagnostic(ViolateAfterReadStream2,
                                      read2_fatal.c_str());

  const std::string write_fatal = "nghttp3_conn_writev_stream returned " +
                                  std::to_string(NGHTTP3_ERR_CALLBACK_FAILURE);
  ExpectViolationAbortsWithDiagnostic(ViolateAfterWritevStream,
                                      write_fatal.c_str());
}

void TestTimestampRegressionAborts() {
  ExpectViolationAbortsWithDiagnostic(ViolateTimestampOrder,
                                      "decreasing timestamp 9 after 10");
}

void TestInvalidTimestampAborts() {
  ExpectViolationAbortsWithDiagnostic(ViolateInvalidTimestamp,
                                      "invalid timestamp UINT64_MAX");
}

} // namespace

int main() {
  TestNonfatalResultDoesNotPoison();
  TestNondecreasingTimestampsRemainUsable();
  TestDeprecatedReadStreamAllowsItsInternalTimestampSentinel();
  TestFatalConnectionCanBeDeletedAndAddressReused();
  TestUseAfterEachFatalResultAborts();
  TestTimestampRegressionAborts();
  TestInvalidTimestampAborts();
  return 0;
}
