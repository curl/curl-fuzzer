/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <string>

#include "test_assertions.h"

namespace {

using test_support::Expect;

struct Stream {
  ZSTD_DStream *stream = ZSTD_createDStream();

  Stream() { Expect(stream != nullptr, "could not allocate zstd DStream"); }

  ~Stream() { ZSTD_freeDStream(stream); }

  Stream(const Stream &) = delete;
  Stream &operator=(const Stream &) = delete;
};

size_t DecompressInvalidFrame(ZSTD_DStream *stream) {
  constexpr std::array<unsigned char, 8> invalid_frame{0x00, 0x11, 0x22, 0x33,
                                                       0x44, 0x55, 0x66, 0x77};
  std::array<unsigned char, 64> output_storage{};
  ZSTD_inBuffer input{invalid_frame.data(), invalid_frame.size(), 0};
  ZSTD_outBuffer output{output_storage.data(), output_storage.size(), 0};
  const size_t result = ZSTD_decompressStream(stream, &output, &input);
  Expect(ZSTD_isError(result) != 0,
         "invalid zstd frame did not produce a decompression error");
  return result;
}

size_t DecompressWithInvalidInputPosition(ZSTD_DStream *stream) {
  unsigned char input_storage = 0;
  std::array<unsigned char, 64> output_storage{};
  ZSTD_inBuffer input{&input_storage, 0, 1};
  ZSTD_outBuffer output{output_storage.data(), output_storage.size(), 0};
  const size_t result = ZSTD_decompressStream(stream, &output, &input);
  Expect(ZSTD_isError(result) != 0,
         "invalid zstd input position did not produce an error");
  return result;
}

void DecompressEmptyInput(ZSTD_DStream *stream) {
  std::array<unsigned char, 64> output_storage{};
  ZSTD_inBuffer input{nullptr, 0, 0};
  ZSTD_outBuffer output{output_storage.data(), output_storage.size(), 0};
  const size_t result = ZSTD_decompressStream(stream, &output, &input);
  Expect(ZSTD_isError(result) == 0,
         "empty input unexpectedly produced a zstd error");
}

void TestNonErrorDoesNotPoison() {
  Stream stream;
  DecompressEmptyInput(stream.stream);
  DecompressEmptyInput(stream.stream);
}

void TestInitRecoversPoisonedStream() {
  Stream stream;
  DecompressInvalidFrame(stream.stream);
  Expect(ZSTD_isError(ZSTD_initDStream(stream.stream)) == 0,
         "ZSTD_initDStream failed to recover poisoned stream");
  DecompressEmptyInput(stream.stream);
}

void TestResetRecoversPoisonedContext() {
  Stream stream;
  DecompressInvalidFrame(stream.stream);
  Expect(ZSTD_isError(
             ZSTD_DCtx_reset(stream.stream, ZSTD_reset_session_only)) == 0,
         "ZSTD_DCtx_reset failed to recover poisoned stream");
  DecompressEmptyInput(stream.stream);
}

void TestSessionAndParametersResetRecoversPoisonedContext() {
  Stream stream;
  DecompressInvalidFrame(stream.stream);
  Expect(ZSTD_isError(ZSTD_DCtx_reset(stream.stream,
                                      ZSTD_reset_session_and_parameters)) == 0,
         "combined ZSTD_DCtx_reset failed to recover poisoned stream");
  DecompressEmptyInput(stream.stream);
}

void TestPoisonedStreamCanBeFreed() {
  ZSTD_DStream *stream = ZSTD_createDStream();
  Expect(stream != nullptr, "could not allocate zstd DStream for free test");
  DecompressInvalidFrame(stream);
  Expect(ZSTD_isError(ZSTD_freeDStream(stream)) == 0,
         "could not free poisoned zstd DStream");
}

struct ReusingAllocator {
  static constexpr std::size_t kCapacity = 1024 * 1024;
  alignas(std::max_align_t) std::array<unsigned char, kCapacity> storage{};
  std::size_t used = 0;

  void Reset() { used = 0; }
};

void *AllocateFromArena(void *opaque, size_t size) {
  auto *allocator = static_cast<ReusingAllocator *>(opaque);
  constexpr std::size_t alignment = alignof(std::max_align_t);
  const std::size_t offset =
      (allocator->used + alignment - 1) & ~(alignment - 1);
  if (offset > allocator->storage.size() ||
      size > allocator->storage.size() - offset) {
    return nullptr;
  }
  allocator->used = offset + size;
  return allocator->storage.data() + offset;
}

void FreeFromArena(void *, void *) {}

void TestFreedAddressCanBeReused() {
  ReusingAllocator allocator;
  const ZSTD_customMem memory{AllocateFromArena, FreeFromArena, &allocator};

  ZSTD_DStream *first = ZSTD_createDStream_advanced(memory);
  Expect(first != nullptr, "could not allocate first arena-backed DStream");
  DecompressInvalidFrame(first);
  Expect(ZSTD_isError(ZSTD_freeDStream(first)) == 0,
         "could not free first arena-backed DStream");

  allocator.Reset();
  ZSTD_DStream *second = ZSTD_createDStream_advanced(memory);
  Expect(second != nullptr, "could not allocate reused arena-backed DStream");
  Expect(second == first,
         "custom zstd allocator did not reuse DStream address");
  DecompressEmptyInput(second);
  Expect(ZSTD_isError(ZSTD_freeDStream(second)) == 0,
         "could not free reused arena-backed DStream");
}

void ViolateWithRepeatedDecompress() {
  Stream stream;
  DecompressInvalidFrame(stream.stream);
  DecompressEmptyInput(stream.stream);
}

void ViolateAfterParametersOnlyReset() {
  Stream stream;
  // This validation error occurs before zstd advances the session state, so
  // resetting parameters succeeds. It still does not satisfy the documented
  // requirement to reset the session after ZSTD_decompressStream fails.
  DecompressWithInvalidInputPosition(stream.stream);
  Expect(ZSTD_isError(ZSTD_DCtx_reset(stream.stream, ZSTD_reset_parameters)) ==
             0,
         "parameters-only reset unexpectedly failed");
  DecompressEmptyInput(stream.stream);
}

using Violation = void (*)();

void ExpectViolationAbortsWithDiagnostic(Violation violate) {
  int diagnostic_pipe[2];
  Expect(pipe(diagnostic_pipe) == 0, "could not create diagnostic pipe");
  std::fflush(nullptr);

  const pid_t child = fork();
  Expect(child >= 0, "could not fork zstd contract test");
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
  Expect(waited == child, "could not wait for zstd contract child");
  Expect(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
         "decompression after a zstd error did not abort");
  Expect(diagnostic.find("zstd contract assertion failed") != std::string::npos,
         "contract diagnostic omitted the assertion context");
  Expect(diagnostic.find("ZSTD_decompressStream called") != std::string::npos,
         "contract diagnostic omitted the attempted API");
  Expect(diagnostic.find("after ZSTD_decompressStream returned error code") !=
             std::string::npos,
         "contract diagnostic omitted the original error");
}

void TestRepeatedDecompressAbortsWithDiagnostic() {
  ExpectViolationAbortsWithDiagnostic(ViolateWithRepeatedDecompress);
}

void TestParametersOnlyResetDoesNotRecoverPoisonedContext() {
  ExpectViolationAbortsWithDiagnostic(ViolateAfterParametersOnlyReset);
}

} // namespace

int main() {
  TestNonErrorDoesNotPoison();
  TestInitRecoversPoisonedStream();
  TestResetRecoversPoisonedContext();
  TestSessionAndParametersResetRecoversPoisonedContext();
  TestPoisonedStreamCanBeFreed();
  TestFreedAddressCanBeReused();
  TestRepeatedDecompressAbortsWithDiagnostic();
  TestParametersOnlyResetDoesNotRecoverPoisonedContext();
  return 0;
}
