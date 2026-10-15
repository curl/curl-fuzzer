/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <openssl/ssl.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <type_traits>

namespace {

// OpenSSL 4.0.3 defines its same-arguments retry contract for these two
// functions. SSL_write_ex2 and SSL_write_early_data remain monitored I/O, but
// their documentation does not establish a new retry obligation.
enum class WriteApi { kNone, kSslWrite, kSslWriteEx };

struct BufferFingerprint {
  std::uint64_t first = 0;
  std::uint64_t second = 0;
};

// SSL_get_error classifies a preceding I/O result for one SSL object. Keep
// pending results keyed by that object so interleaved connections cannot
// replace one another's classification state.
struct PendingIoCall {
  const SSL *ssl = nullptr;
  const char *api = nullptr;
  long long result = 0;
  bool zero_is_non_error = false;
  WriteApi write_api = WriteApi::kNone;
  const void *write_buffer = nullptr;
  std::size_t write_length = 0;
  BufferFingerprint write_fingerprint;
  bool moving_write_buffer = false;
};

struct PendingWriteRetry {
  const SSL *ssl = nullptr;
  const char *api = nullptr;
  WriteApi write_api = WriteApi::kNone;
  const void *buffer = nullptr;
  std::size_t length = 0;
  BufferFingerprint fingerprint;
  bool moving_buffer = false;
  int ssl_error = SSL_ERROR_NONE;
};

struct FatalConnection {
  const SSL *ssl = nullptr;
  const char *io_api = nullptr;
  long long io_result = 0;
  int ssl_error = SSL_ERROR_NONE;
};

// Fixed tables keep allocation-failure fuzzing from disabling or perturbing
// the monitor.
constexpr std::size_t kMaximumTrackedConnections = 256;
std::array<PendingIoCall, kMaximumTrackedConnections> pending_io_calls{};
std::mutex pending_io_calls_mutex;
std::atomic<std::size_t> pending_io_call_count{0};

std::array<PendingWriteRetry, kMaximumTrackedConnections>
    pending_write_retries{};
std::mutex pending_write_retries_mutex;
std::atomic<std::size_t> pending_write_retry_count{0};

constexpr std::size_t kMaximumFatalConnections = kMaximumTrackedConnections;
std::array<FatalConnection, kMaximumFatalConnections> fatal_connections{};
std::mutex fatal_connections_mutex;
std::atomic<std::size_t> fatal_connection_count{0};

// Static libssl contains calls to public SSL APIs. --wrap redirects those
// calls too, so calls made while a real OpenSSL function is running bypass the
// monitor and cannot replace the application call being classified.
thread_local unsigned real_call_depth = 0;

class RealCallScope {
public:
  RealCallScope() { ++real_call_depth; }
  ~RealCallScope() { --real_call_depth; }

  RealCallScope(const RealCallScope &) = delete;
  RealCallScope &operator=(const RealCallScope &) = delete;
};

bool IsRealCallActive() { return real_call_depth != 0; }

BufferFingerprint FingerprintBuffer(const void *buffer, std::size_t length) {
  // A moving write buffer means the original storage may no longer be valid
  // when OpenSSL asks for a retry. Retaining an exact, unbounded copy would
  // violate the allocation-free design, so hash every byte into two fixed-size
  // fingerprints while the storage is live.
  BufferFingerprint fingerprint;
  fingerprint.first = 1469598103934665603ULL;
  fingerprint.second = 1099511628211ULL ^ length;
  if (buffer == nullptr) {
    return fingerprint;
  }
  const auto *bytes = static_cast<const unsigned char *>(buffer);
  for (std::size_t index = 0; index < length; ++index) {
    fingerprint.first ^= bytes[index];
    fingerprint.first *= 1099511628211ULL;
    fingerprint.second ^= static_cast<std::uint64_t>(bytes[index]) +
                          0x9e3779b97f4a7c15ULL + (fingerprint.second << 6) +
                          (fingerprint.second >> 2);
  }
  fingerprint.first ^= length;
  fingerprint.second ^= length * 0xbf58476d1ce4e5b9ULL;
  return fingerprint;
}

bool FingerprintsEqual(const BufferFingerprint &left,
                       const BufferFingerprint &right) {
  return left.first == right.first && left.second == right.second;
}

const char *ErrorName(int ssl_error) {
  switch (ssl_error) {
  case SSL_ERROR_SSL:
    return "SSL_ERROR_SSL";
  case SSL_ERROR_SYSCALL:
    return "SSL_ERROR_SYSCALL";
  default:
    return "unknown fatal error";
  }
}

[[noreturn]] void AbortContractViolation(const char *attempted_api,
                                         const FatalConnection &fatal) {
  std::fprintf(stderr,
               "OpenSSL contract assertion failed: %s called on SSL %p "
               "after %s returned %lld and SSL_get_error classified it as "
               "%s; no further I/O or SSL_shutdown is allowed\n",
               attempted_api, static_cast<const void *>(fatal.ssl),
               fatal.io_api, fatal.io_result, ErrorName(fatal.ssl_error));
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortPendingOverflow(const PendingIoCall &call) {
  std::fprintf(stderr,
               "OpenSSL contract assertion failed: cannot track SSL %p "
               "after %s returned %lld; pending-I/O table is full\n",
               static_cast<const void *>(call.ssl), call.api, call.result);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortGetErrorMismatch(const SSL *ssl, int io_result,
                                        const PendingIoCall *latest) {
  if (latest == nullptr) {
    std::fprintf(stderr,
                 "OpenSSL contract assertion failed: SSL_get_error called on "
                 "SSL %p with result %d, but that SSL has no saved monitored "
                 "I/O result\n",
                 static_cast<const void *>(ssl), io_result);
  } else {
    std::fprintf(stderr,
                 "OpenSSL contract assertion failed: SSL_get_error called on "
                 "SSL %p with result %d, but its latest monitored I/O was %s "
                 "returning %lld\n",
                 static_cast<const void *>(ssl), io_result, latest->api,
                 latest->result);
  }
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortWriteRetryMismatch(const SSL *ssl,
                                          const char *attempted_api,
                                          const PendingWriteRetry &retry,
                                          const char *difference) {
  std::fprintf(stderr,
               "OpenSSL contract assertion failed: %s called on SSL %p "
               "while %s has a pending %zu-byte write retry; %s\n",
               attempted_api, static_cast<const void *>(ssl), retry.api,
               retry.length, difference);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortWriteRetryOverflow(const PendingIoCall &call) {
  std::fprintf(stderr,
               "OpenSSL contract assertion failed: cannot track SSL %p "
               "after %s returned %lld and needs a write retry; "
               "write-retry table is full\n",
               static_cast<const void *>(call.ssl), call.api, call.result);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortFatalOverflow(const PendingIoCall &call, int ssl_error) {
  std::fprintf(stderr,
               "OpenSSL contract assertion failed: cannot track SSL %p "
               "after %s returned %lld and SSL_get_error classified it as "
               "%s; fatal-connection table is full\n",
               static_cast<const void *>(call.ssl), call.api, call.result,
               ErrorName(ssl_error));
  std::fflush(stderr);
  std::abort();
}

PendingIoCall *FindPendingIoCall(const SSL *ssl) {
  for (PendingIoCall &call : pending_io_calls) {
    if (call.ssl == ssl) {
      return &call;
    }
  }
  return nullptr;
}

FatalConnection *FindFatalConnection(const SSL *ssl) {
  for (FatalConnection &fatal : fatal_connections) {
    if (fatal.ssl == ssl) {
      return &fatal;
    }
  }
  return nullptr;
}

PendingWriteRetry *FindPendingWriteRetry(const SSL *ssl) {
  for (PendingWriteRetry &retry : pending_write_retries) {
    if (retry.ssl == ssl) {
      return &retry;
    }
  }
  return nullptr;
}

void CheckUsable(const SSL *ssl, const char *attempted_api) {
  if (ssl == nullptr ||
      fatal_connection_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  FatalConnection fatal;
  {
    std::lock_guard<std::mutex> lock(fatal_connections_mutex);
    const FatalConnection *tracked = FindFatalConnection(ssl);
    if (tracked != nullptr) {
      fatal = *tracked;
    }
  }
  if (fatal.ssl != nullptr) {
    AbortContractViolation(attempted_api, fatal);
  }
}

void ForgetPendingIoCall(const SSL *ssl) {
  if (ssl == nullptr ||
      pending_io_call_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  std::lock_guard<std::mutex> lock(pending_io_calls_mutex);
  PendingIoCall *call = FindPendingIoCall(ssl);
  if (call != nullptr) {
    *call = PendingIoCall{};
    pending_io_call_count.fetch_sub(1, std::memory_order_release);
  }
}

void ForgetPendingWriteRetry(const SSL *ssl) {
  if (ssl == nullptr ||
      pending_write_retry_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  std::lock_guard<std::mutex> lock(pending_write_retries_mutex);
  PendingWriteRetry *retry = FindPendingWriteRetry(ssl);
  if (retry != nullptr) {
    *retry = PendingWriteRetry{};
    pending_write_retry_count.fetch_sub(1, std::memory_order_release);
  }
}

void CheckWriteRetry(const SSL *ssl, const char *api, WriteApi write_api,
                     const void *buffer, std::size_t length) {
  if (ssl == nullptr ||
      pending_write_retry_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  PendingWriteRetry retry;
  {
    std::lock_guard<std::mutex> lock(pending_write_retries_mutex);
    const PendingWriteRetry *tracked = FindPendingWriteRetry(ssl);
    if (tracked != nullptr) {
      retry = *tracked;
    }
  }
  if (retry.ssl == nullptr) {
    return;
  }
  if (retry.write_api != write_api) {
    AbortWriteRetryMismatch(
        ssl, api, retry, "the retry must use the same OpenSSL write function");
  }
  if (retry.length != length) {
    AbortWriteRetryMismatch(ssl, api, retry, "the retry length changed");
  }
  if (!retry.moving_buffer && retry.buffer != buffer) {
    AbortWriteRetryMismatch(ssl, api, retry,
                            "the retry buffer pointer changed without "
                            "SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER");
  }
  if (!FingerprintsEqual(retry.fingerprint,
                         FingerprintBuffer(buffer, length))) {
    AbortWriteRetryMismatch(ssl, api, retry,
                            "the retry buffer contents changed");
  }
}

void CheckDifferentWriteApi(const SSL *ssl, const char *api) {
  if (ssl == nullptr ||
      pending_write_retry_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  PendingWriteRetry retry;
  {
    std::lock_guard<std::mutex> lock(pending_write_retries_mutex);
    const PendingWriteRetry *tracked = FindPendingWriteRetry(ssl);
    if (tracked != nullptr) {
      retry = *tracked;
    }
  }
  if (retry.ssl != nullptr) {
    AbortWriteRetryMismatch(
        ssl, api, retry, "the retry must use the same OpenSSL write function");
  }
}

void CheckWantWriteRetry(const SSL *ssl, const char *api) {
  if (ssl == nullptr ||
      pending_write_retry_count.load(std::memory_order_acquire) == 0) {
    return;
  }
  PendingWriteRetry retry;
  {
    std::lock_guard<std::mutex> lock(pending_write_retries_mutex);
    const PendingWriteRetry *tracked = FindPendingWriteRetry(ssl);
    if (tracked != nullptr) {
      retry = *tracked;
    }
  }
  if (retry.ssl != nullptr && retry.ssl_error == SSL_ERROR_WANT_WRITE) {
    AbortWriteRetryMismatch(
        ssl, api, retry,
        "SSL_ERROR_WANT_WRITE requires repeating the pending write before "
        "another operation that can trigger I/O");
  }
}

void RememberPendingWriteRetry(const PendingIoCall &call, int ssl_error) {
  bool table_full = false;
  bool added = false;
  {
    std::lock_guard<std::mutex> lock(pending_write_retries_mutex);
    PendingWriteRetry *retry = FindPendingWriteRetry(call.ssl);
    if (retry == nullptr) {
      for (PendingWriteRetry &entry : pending_write_retries) {
        if (entry.ssl == nullptr) {
          retry = &entry;
          added = true;
          break;
        }
      }
    }
    if (retry != nullptr) {
      retry->ssl = call.ssl;
      retry->api = call.api;
      retry->write_api = call.write_api;
      retry->buffer = call.write_buffer;
      retry->length = call.write_length;
      retry->fingerprint = call.write_fingerprint;
      retry->moving_buffer = call.moving_write_buffer;
      retry->ssl_error = ssl_error;
      if (added) {
        pending_write_retry_count.fetch_add(1, std::memory_order_release);
      }
    } else {
      table_full = true;
    }
  }
  if (table_full) {
    AbortWriteRetryOverflow(call);
  }
}

void RecordIoResult(const SSL *ssl, const char *api, long long result,
                    bool zero_is_non_error = false,
                    WriteApi write_api = WriteApi::kNone,
                    const void *write_buffer = nullptr,
                    std::size_t write_length = 0,
                    bool moving_write_buffer = false) {
  if (ssl == nullptr) {
    return;
  }
  if (write_api != WriteApi::kNone && result > 0) {
    ForgetPendingWriteRetry(ssl);
  }

  PendingIoCall recorded;
  recorded.ssl = ssl;
  recorded.api = api;
  recorded.result = result;
  recorded.zero_is_non_error = zero_is_non_error;
  recorded.write_api = write_api;
  recorded.write_buffer = write_buffer;
  recorded.write_length = write_length;
  recorded.write_fingerprint = FingerprintBuffer(write_buffer, write_length);
  recorded.moving_write_buffer = moving_write_buffer;
  bool table_full = false;
  bool added = false;
  {
    std::lock_guard<std::mutex> lock(pending_io_calls_mutex);
    PendingIoCall *call = FindPendingIoCall(ssl);
    if (call == nullptr) {
      for (PendingIoCall &entry : pending_io_calls) {
        if (entry.ssl == nullptr) {
          call = &entry;
          added = true;
          break;
        }
      }
    }
    if (call != nullptr) {
      *call = recorded;
      if (added) {
        pending_io_call_count.fetch_add(1, std::memory_order_release);
      }
    } else {
      table_full = true;
    }
  }
  if (table_full) {
    AbortPendingOverflow(recorded);
  }
}

void RecordSslError(const SSL *ssl, int io_result, int ssl_error) {
  PendingIoCall classified_call;
  bool found = false;
  {
    std::lock_guard<std::mutex> lock(pending_io_calls_mutex);
    PendingIoCall *pending = FindPendingIoCall(ssl);
    if (pending != nullptr) {
      classified_call = *pending;
      found = true;
    }
  }
  if (!found || classified_call.result != io_result) {
    AbortGetErrorMismatch(ssl, io_result, found ? &classified_call : nullptr);
  }

  // SSL_get_error accepts any exact saved I/O result. Positive results
  // classify as SSL_ERROR_NONE, while successful zero-valued shutdown results
  // are not fatal even if OpenSSL assigns them a fatal-looking category.
  if (classified_call.result > 0 ||
      (classified_call.zero_is_non_error && classified_call.result == 0)) {
    return;
  }
  if (classified_call.write_api != WriteApi::kNone) {
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
      RememberPendingWriteRetry(classified_call, ssl_error);
    } else {
      ForgetPendingWriteRetry(ssl);
    }
  }
  if (ssl_error != SSL_ERROR_SSL && ssl_error != SSL_ERROR_SYSCALL) {
    return;
  }

  ForgetPendingWriteRetry(ssl);

  bool table_full = false;
  bool added = false;
  {
    std::lock_guard<std::mutex> lock(fatal_connections_mutex);
    FatalConnection *fatal = FindFatalConnection(ssl);
    if (fatal == nullptr) {
      for (FatalConnection &entry : fatal_connections) {
        if (entry.ssl == nullptr) {
          fatal = &entry;
          added = true;
          break;
        }
      }
    }
    if (fatal != nullptr) {
      fatal->ssl = ssl;
      fatal->io_api = classified_call.api;
      fatal->io_result = classified_call.result;
      fatal->ssl_error = ssl_error;
      if (added) {
        fatal_connection_count.fetch_add(1, std::memory_order_release);
      }
    } else {
      table_full = true;
    }
  }
  if (table_full) {
    AbortFatalOverflow(classified_call, ssl_error);
  }
}

void ForgetConnection(const SSL *ssl) {
  ForgetPendingIoCall(ssl);
  ForgetPendingWriteRetry(ssl);
  if (ssl == nullptr ||
      fatal_connection_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  std::lock_guard<std::mutex> lock(fatal_connections_mutex);
  FatalConnection *fatal = FindFatalConnection(ssl);
  if (fatal != nullptr) {
    *fatal = FatalConnection{};
    fatal_connection_count.fetch_sub(1, std::memory_order_release);
  }
}

} // namespace

// GNU ld and lld provide each __real_* symbol when the final link uses the
// matching --wrap option. decltype ties these declarations to the installed
// OpenSSL headers and makes signature drift a compile-time failure.
extern "C" decltype(SSL_new) __real_SSL_new;
extern "C" decltype(SSL_free) __real_SSL_free;
extern "C" decltype(SSL_clear) __real_SSL_clear;
extern "C" decltype(SSL_get_error) __real_SSL_get_error;
extern "C" decltype(SSL_accept) __real_SSL_accept;
extern "C" decltype(SSL_connect) __real_SSL_connect;
extern "C" decltype(SSL_do_handshake) __real_SSL_do_handshake;
extern "C" decltype(SSL_read) __real_SSL_read;
extern "C" decltype(SSL_read_ex) __real_SSL_read_ex;
extern "C" decltype(SSL_read_early_data) __real_SSL_read_early_data;
extern "C" decltype(SSL_peek) __real_SSL_peek;
extern "C" decltype(SSL_peek_ex) __real_SSL_peek_ex;
extern "C" decltype(SSL_sendfile) __real_SSL_sendfile;
extern "C" decltype(SSL_write) __real_SSL_write;
extern "C" decltype(SSL_write_ex) __real_SSL_write_ex;
extern "C" decltype(SSL_write_ex2) __real_SSL_write_ex2;
extern "C" decltype(SSL_write_early_data) __real_SSL_write_early_data;
extern "C" decltype(SSL_shutdown) __real_SSL_shutdown;
extern "C" decltype(SSL_shutdown_ex) __real_SSL_shutdown_ex;

extern "C" SSL *__wrap_SSL_new(SSL_CTX *ctx) {
  if (IsRealCallActive()) {
    return __real_SSL_new(ctx);
  }
  SSL *ssl;
  {
    RealCallScope real_call;
    ssl = __real_SSL_new(ctx);
  }
  // OpenSSL's allocator may reuse a recently freed address.
  ForgetConnection(ssl);
  return ssl;
}
static_assert(std::is_same<decltype(SSL_new), decltype(__wrap_SSL_new)>::value,
              "SSL_new signature changed");

extern "C" void __wrap_SSL_free(SSL *ssl) {
  if (IsRealCallActive()) {
    __real_SSL_free(ssl);
    return;
  }
  ForgetConnection(ssl);
  RealCallScope real_call;
  __real_SSL_free(ssl);
}
static_assert(
    std::is_same<decltype(SSL_free), decltype(__wrap_SSL_free)>::value,
    "SSL_free signature changed");

extern "C" int __wrap_SSL_clear(SSL *ssl) {
  if (IsRealCallActive()) {
    return __real_SSL_clear(ssl);
  }
  // SSL_clear supersedes any earlier result on this SSL even if the clear
  // itself fails.
  ForgetPendingIoCall(ssl);
  int result;
  {
    RealCallScope real_call;
    result = __real_SSL_clear(ssl);
  }
  if (result == 1) {
    // A successful clear starts a new connection on the same SSL object.
    ForgetConnection(ssl);
  }
  return result;
}
static_assert(
    std::is_same<decltype(SSL_clear), decltype(__wrap_SSL_clear)>::value,
    "SSL_clear signature changed");

extern "C" int __wrap_SSL_get_error(const SSL *ssl, int io_result) {
  if (IsRealCallActive()) {
    return __real_SSL_get_error(ssl, io_result);
  }
  int ssl_error;
  {
    RealCallScope real_call;
    ssl_error = __real_SSL_get_error(ssl, io_result);
  }
  RecordSslError(ssl, io_result, ssl_error);
  return ssl_error;
}
static_assert(std::is_same<decltype(SSL_get_error),
                           decltype(__wrap_SSL_get_error)>::value,
              "SSL_get_error signature changed");

#define DEFINE_IO_WRAPPER_WITH_POLICY(                                         \
    name, parameters, arguments, zero_is_non_error, allow_during_want_write)   \
  extern "C" auto __wrap_##name parameters                                     \
      ->decltype(__real_##name arguments) {                                    \
    if (IsRealCallActive()) {                                                  \
      return __real_##name arguments;                                          \
    }                                                                          \
    CheckUsable(ssl, #name);                                                   \
    if (!(allow_during_want_write)) {                                          \
      CheckWantWriteRetry(ssl, #name);                                         \
    }                                                                          \
    ForgetPendingIoCall(ssl);                                                  \
    decltype(__real_##name arguments) result;                                  \
    {                                                                          \
      RealCallScope real_call;                                                 \
      result = __real_##name arguments;                                        \
    }                                                                          \
    RecordIoResult(ssl, #name, static_cast<long long>(result),                 \
                   zero_is_non_error);                                         \
    return result;                                                             \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

#define DEFINE_IO_WRAPPER(name, parameters, arguments)                         \
  DEFINE_IO_WRAPPER_WITH_POLICY(name, parameters, arguments, false, false)

#define DEFINE_READ_WRAPPER(name, parameters, arguments)                       \
  DEFINE_IO_WRAPPER_WITH_POLICY(name, parameters, arguments, false, true)

#define DEFINE_ZERO_NONERROR_WRAPPER(name, parameters, arguments)              \
  DEFINE_IO_WRAPPER_WITH_POLICY(name, parameters, arguments, true, false)

DEFINE_IO_WRAPPER(SSL_accept, (SSL * ssl), (ssl))
DEFINE_IO_WRAPPER(SSL_connect, (SSL * ssl), (ssl))
DEFINE_IO_WRAPPER(SSL_do_handshake, (SSL * ssl), (ssl))
DEFINE_READ_WRAPPER(SSL_read, (SSL * ssl, void *buffer, int length),
                    (ssl, buffer, length))
DEFINE_READ_WRAPPER(SSL_read_ex,
                    (SSL * ssl, void *buffer, size_t length, size_t *readbytes),
                    (ssl, buffer, length, readbytes))
DEFINE_IO_WRAPPER(SSL_read_early_data,
                  (SSL * ssl, void *buffer, size_t length, size_t *readbytes),
                  (ssl, buffer, length, readbytes))
DEFINE_IO_WRAPPER(SSL_peek, (SSL * ssl, void *buffer, int length),
                  (ssl, buffer, length))
DEFINE_IO_WRAPPER(SSL_peek_ex,
                  (SSL * ssl, void *buffer, size_t length, size_t *readbytes),
                  (ssl, buffer, length, readbytes))
DEFINE_ZERO_NONERROR_WRAPPER(SSL_shutdown, (SSL * ssl), (ssl))
DEFINE_ZERO_NONERROR_WRAPPER(SSL_shutdown_ex,
                             (SSL * ssl, uint64_t flags,
                              const SSL_SHUTDOWN_EX_ARGS *args,
                              size_t args_length),
                             (ssl, flags, args, args_length))

extern "C" int __wrap_SSL_write(SSL *ssl, const void *buffer, int length) {
  if (IsRealCallActive()) {
    return __real_SSL_write(ssl, buffer, length);
  }
  CheckUsable(ssl, "SSL_write");
  const std::size_t checked_length =
      length > 0 ? static_cast<std::size_t>(length) : 0;
  CheckWriteRetry(ssl, "SSL_write", WriteApi::kSslWrite, buffer,
                  checked_length);
  ForgetPendingIoCall(ssl);
  int result;
  bool moving_write_buffer;
  {
    RealCallScope real_call;
    moving_write_buffer =
        (SSL_get_mode(ssl) & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) != 0;
    result = __real_SSL_write(ssl, buffer, length);
  }
  RecordIoResult(ssl, "SSL_write", result, false, WriteApi::kSslWrite, buffer,
                 checked_length, moving_write_buffer);
  return result;
}
static_assert(
    std::is_same<decltype(SSL_write), decltype(__wrap_SSL_write)>::value,
    "SSL_write signature changed");

extern "C" int __wrap_SSL_write_ex(SSL *ssl, const void *buffer, size_t length,
                                   size_t *written) {
  if (IsRealCallActive()) {
    return __real_SSL_write_ex(ssl, buffer, length, written);
  }
  CheckUsable(ssl, "SSL_write_ex");
  CheckWriteRetry(ssl, "SSL_write_ex", WriteApi::kSslWriteEx, buffer, length);
  ForgetPendingIoCall(ssl);
  int result;
  bool moving_write_buffer;
  {
    RealCallScope real_call;
    moving_write_buffer =
        (SSL_get_mode(ssl) & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) != 0;
    result = __real_SSL_write_ex(ssl, buffer, length, written);
  }
  RecordIoResult(ssl, "SSL_write_ex", result, false, WriteApi::kSslWriteEx,
                 buffer, length, moving_write_buffer);
  return result;
}
static_assert(
    std::is_same<decltype(SSL_write_ex), decltype(__wrap_SSL_write_ex)>::value,
    "SSL_write_ex signature changed");

// These calls do not create a retry obligation under the pinned documentation,
// but none can substitute for SSL_write or SSL_write_ex while one is pending.
#define DEFINE_UNTRACKED_WRITE_WRAPPER_WITH_POLICY(                            \
    name, parameters, arguments, zero_is_non_error)                            \
  extern "C" auto __wrap_##name parameters                                     \
      ->decltype(__real_##name arguments) {                                    \
    if (IsRealCallActive()) {                                                  \
      return __real_##name arguments;                                          \
    }                                                                          \
    CheckUsable(ssl, #name);                                                   \
    CheckDifferentWriteApi(ssl, #name);                                        \
    ForgetPendingIoCall(ssl);                                                  \
    decltype(__real_##name arguments) result;                                  \
    {                                                                          \
      RealCallScope real_call;                                                 \
      result = __real_##name arguments;                                        \
    }                                                                          \
    RecordIoResult(ssl, #name, static_cast<long long>(result),                 \
                   zero_is_non_error);                                         \
    return result;                                                             \
  }                                                                            \
  static_assert(std::is_same<decltype(name), decltype(__wrap_##name)>::value,  \
                #name " signature changed");

DEFINE_UNTRACKED_WRITE_WRAPPER_WITH_POLICY(SSL_sendfile,
                                           (SSL * ssl, int fd, off_t offset,
                                            size_t size, int flags),
                                           (ssl, fd, offset, size, flags), true)
DEFINE_UNTRACKED_WRITE_WRAPPER_WITH_POLICY(
    SSL_write_ex2,
    (SSL * ssl, const void *buffer, size_t length, uint64_t flags,
     size_t *written),
    (ssl, buffer, length, flags, written), false)
DEFINE_UNTRACKED_WRITE_WRAPPER_WITH_POLICY(SSL_write_early_data,
                                           (SSL * ssl, const void *buffer,
                                            size_t length, size_t *written),
                                           (ssl, buffer, length, written),
                                           false)

#undef DEFINE_UNTRACKED_WRITE_WRAPPER_WITH_POLICY
#undef DEFINE_ZERO_NONERROR_WRAPPER
#undef DEFINE_READ_WRAPPER
#undef DEFINE_IO_WRAPPER
#undef DEFINE_IO_WRAPPER_WITH_POLICY
