/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <openssl/ssl.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <type_traits>

namespace {

// SSL_get_error classifies a preceding I/O result for one SSL object. Keep
// pending results keyed by that object so interleaved connections cannot
// replace one another's classification state.
struct PendingIoCall {
  const SSL *ssl = nullptr;
  const char *api = nullptr;
  long long result = 0;
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

void RecordIoResult(const SSL *ssl, const char *api, long long result,
                    bool zero_is_non_error = false) {
  if (ssl == nullptr) {
    return;
  }
  if (result > 0 || (zero_is_non_error && result == 0)) {
    ForgetPendingIoCall(ssl);
    return;
  }

  PendingIoCall recorded;
  recorded.ssl = ssl;
  recorded.api = api;
  recorded.result = result;
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
  if (ssl == nullptr ||
      pending_io_call_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  PendingIoCall classified_call;
  {
    std::lock_guard<std::mutex> lock(pending_io_calls_mutex);
    PendingIoCall *pending = FindPendingIoCall(ssl);
    if (pending == nullptr || pending->result != io_result) {
      return;
    }
    classified_call = *pending;
    *pending = PendingIoCall{};
    pending_io_call_count.fetch_sub(1, std::memory_order_release);
  }
  if (ssl_error != SSL_ERROR_SSL && ssl_error != SSL_ERROR_SYSCALL) {
    return;
  }

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

#define DEFINE_IO_WRAPPER_WITH_POLICY(name, parameters, arguments,             \
                                      zero_is_non_error)                       \
  extern "C" auto __wrap_##name parameters                                     \
      ->decltype(__real_##name arguments) {                                    \
    if (IsRealCallActive()) {                                                  \
      return __real_##name arguments;                                          \
    }                                                                          \
    CheckUsable(ssl, #name);                                                   \
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
  DEFINE_IO_WRAPPER_WITH_POLICY(name, parameters, arguments, false)

#define DEFINE_ZERO_NONERROR_WRAPPER(name, parameters, arguments)              \
  DEFINE_IO_WRAPPER_WITH_POLICY(name, parameters, arguments, true)

DEFINE_IO_WRAPPER(SSL_accept, (SSL * ssl), (ssl))
DEFINE_IO_WRAPPER(SSL_connect, (SSL * ssl), (ssl))
DEFINE_IO_WRAPPER(SSL_do_handshake, (SSL * ssl), (ssl))
DEFINE_IO_WRAPPER(SSL_read, (SSL * ssl, void *buffer, int length),
                  (ssl, buffer, length))
DEFINE_IO_WRAPPER(SSL_read_ex,
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
DEFINE_ZERO_NONERROR_WRAPPER(SSL_sendfile,
                             (SSL * ssl, int fd, off_t offset, size_t size,
                              int flags),
                             (ssl, fd, offset, size, flags))
DEFINE_IO_WRAPPER(SSL_write, (SSL * ssl, const void *buffer, int length),
                  (ssl, buffer, length))
DEFINE_IO_WRAPPER(SSL_write_ex,
                  (SSL * ssl, const void *buffer, size_t length,
                   size_t *written),
                  (ssl, buffer, length, written))
DEFINE_IO_WRAPPER(SSL_write_ex2,
                  (SSL * ssl, const void *buffer, size_t length, uint64_t flags,
                   size_t *written),
                  (ssl, buffer, length, flags, written))
DEFINE_IO_WRAPPER(SSL_write_early_data,
                  (SSL * ssl, const void *buffer, size_t length,
                   size_t *written),
                  (ssl, buffer, length, written))
DEFINE_ZERO_NONERROR_WRAPPER(SSL_shutdown, (SSL * ssl), (ssl))
DEFINE_ZERO_NONERROR_WRAPPER(SSL_shutdown_ex,
                             (SSL * ssl, uint64_t flags,
                              const SSL_SHUTDOWN_EX_ARGS *args,
                              size_t args_length),
                             (ssl, flags, args, args_length))

#undef DEFINE_ZERO_NONERROR_WRAPPER
#undef DEFINE_IO_WRAPPER
#undef DEFINE_IO_WRAPPER_WITH_POLICY
