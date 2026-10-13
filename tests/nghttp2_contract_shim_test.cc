/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <nghttp2/nghttp2.h>

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>

namespace {

void Expect(bool condition, const char *message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

nghttp2_ssize FailingSend(nghttp2_session *, const uint8_t *, size_t, int,
                          void *) {
  return NGHTTP2_ERR_CALLBACK_FAILURE;
}

nghttp2_session_callbacks *NewCallbacks() {
  nghttp2_session_callbacks *callbacks = nullptr;
  Expect(nghttp2_session_callbacks_new(&callbacks) == 0,
         "could not allocate nghttp2 callbacks");
  nghttp2_session_callbacks_set_send_callback2(callbacks, FailingSend);
  return callbacks;
}

nghttp2_session *NewSession(nghttp2_session_callbacks *callbacks,
                            nghttp2_mem *memory = nullptr) {
  nghttp2_session *session = nullptr;
  Expect(nghttp2_session_client_new3(&session, callbacks, nullptr, nullptr,
                                     memory) == 0,
         "could not allocate nghttp2 session");
  return session;
}

void PoisonWithCallbackFailure(nghttp2_session *session) {
  Expect(nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0) == 0,
         "could not queue nghttp2 settings");
  Expect(nghttp2_session_send(session) == NGHTTP2_ERR_CALLBACK_FAILURE,
         "send callback did not produce a fatal nghttp2 result");
}

// A resettable arena makes session-address reuse deterministic. Its no-op free
// is valid because the test resets the entire arena only after session_del.
class FixedArena {
public:
  nghttp2_mem Memory() { return {this, Malloc, Free, Calloc, Realloc}; }

  void Reset() {
    storage_.fill(0);
    used_ = 0;
  }

private:
  static constexpr std::size_t kCapacity = 128 * 1024;
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
      std::memcpy(replacement, pointer, old_size < size ? old_size : size);
    }
    return replacement;
  }

  alignas(std::max_align_t) std::array<unsigned char, kCapacity> storage_{};
  std::size_t used_ = 0;
};

void TestRecoverableErrorDoesNotPoison() {
  nghttp2_session_callbacks *callbacks = NewCallbacks();
  nghttp2_session *session = NewSession(callbacks);

  Expect(nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 0,
                                   NGHTTP2_NO_ERROR) ==
             NGHTTP2_ERR_INVALID_ARGUMENT,
         "recoverable nghttp2 probe returned an unexpected result");
  Expect(nghttp2_session_want_read(session) != 0,
         "recoverable nghttp2 error poisoned the session");

  nghttp2_session_del(session);
  nghttp2_session_callbacks_del(callbacks);
}

void TestFatalSessionCanBeDeletedAndAddressReused() {
  nghttp2_session_callbacks *callbacks = NewCallbacks();
  FixedArena arena;
  nghttp2_mem memory = arena.Memory();

  nghttp2_session *first = NewSession(callbacks, &memory);
  PoisonWithCallbackFailure(first);
  nghttp2_session_del(first);

  arena.Reset();
  nghttp2_session *reused = NewSession(callbacks, &memory);
  Expect(reused == first, "fixed arena did not reuse the session address");
  Expect(nghttp2_session_want_read(reused) != 0,
         "deleted session left stale poison state at its reused address");

  nghttp2_session_del(reused);
  nghttp2_session_callbacks_del(callbacks);
}

void ViolateContract() {
  nghttp2_session_callbacks *callbacks = NewCallbacks();
  nghttp2_session *session = NewSession(callbacks);
  PoisonWithCallbackFailure(session);
  (void)nghttp2_session_want_read(session);
}

void TestUseAfterFatalAbortsWithDiagnostic() {
  int diagnostic_pipe[2];
  Expect(pipe(diagnostic_pipe) == 0, "could not create diagnostic pipe");
  std::fflush(nullptr);

  const pid_t child = fork();
  Expect(child >= 0, "could not fork nghttp2 contract test");
  if (child == 0) {
    close(diagnostic_pipe[0]);
    if (dup2(diagnostic_pipe[1], STDERR_FILENO) < 0) {
      _exit(90);
    }
    close(diagnostic_pipe[1]);
    ViolateContract();
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
  Expect(waited == child, "could not wait for nghttp2 contract child");
  Expect(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
         "use after fatal nghttp2 result did not abort");
  const std::string expected_fatal =
      "nghttp2_session_send returned " +
      std::to_string(NGHTTP2_ERR_CALLBACK_FAILURE);
  Expect(diagnostic.find(expected_fatal) != std::string::npos,
         "contract diagnostic omitted the fatal API and result");
  Expect(diagnostic.find("nghttp2_session_want_read called") !=
             std::string::npos,
         "contract diagnostic omitted the attempted API");
}

} // namespace

int main() {
  TestRecoverableErrorDoesNotPoison();
  TestFatalSessionCanBeDeletedAndAddressReused();
  TestUseAfterFatalAbortsWithDiagnostic();
  return 0;
}
