/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <type_traits>

namespace {

struct PoisonedContext {
  const ZSTD_DCtx *context = nullptr;
  size_t error_result = 0;
};

// The checker must keep working when the fuzzer injects allocation failures,
// so its state is bounded and never allocates.
constexpr std::size_t kMaximumPoisonedContexts = 256;
std::array<PoisonedContext, kMaximumPoisonedContexts> poisoned_contexts{};
std::mutex poisoned_contexts_mutex;
std::atomic<std::size_t> poisoned_context_count{0};

// Static libzstd calls some of its public entry points internally. --wrap
// redirects those calls too; bypass checking while a real zstd call is active
// so only application-visible operations alter the tracked state.
thread_local unsigned real_call_depth = 0;

class RealCallScope {
public:
  RealCallScope() { ++real_call_depth; }
  ~RealCallScope() { --real_call_depth; }

  RealCallScope(const RealCallScope &) = delete;
  RealCallScope &operator=(const RealCallScope &) = delete;
};

bool IsRealCallActive() { return real_call_depth != 0; }

bool ResetsDecompressionSession(ZSTD_ResetDirective reset) {
  return reset == ZSTD_reset_session_only ||
         reset == ZSTD_reset_session_and_parameters;
}

PoisonedContext *FindPoisonedContext(const ZSTD_DCtx *context) {
  for (PoisonedContext &entry : poisoned_contexts) {
    if (entry.context == context) {
      return &entry;
    }
  }
  return nullptr;
}

[[noreturn]] void AbortContractViolation(const char *attempted_api,
                                         const PoisonedContext &poisoned) {
  std::fprintf(stderr,
               "zstd contract assertion failed: %s called on DStream/DCtx "
               "%p after ZSTD_decompressStream returned error code %zu; "
               "successfully reset, initialize, or free the context before "
               "using it again\n",
               attempted_api, static_cast<const void *>(poisoned.context),
               poisoned.error_result);
  std::fflush(stderr);
  std::abort();
}

[[noreturn]] void AbortTableOverflow(const ZSTD_DCtx *context,
                                     size_t error_result) {
  std::fprintf(stderr,
               "zstd contract assertion failed: cannot track DStream/DCtx "
               "%p after ZSTD_decompressStream returned error code %zu; "
               "poisoned-context table is full\n",
               static_cast<const void *>(context), error_result);
  std::fflush(stderr);
  std::abort();
}

void CheckUsable(const ZSTD_DCtx *context, const char *attempted_api) {
  if (context == nullptr ||
      poisoned_context_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  PoisonedContext poisoned;
  {
    std::lock_guard<std::mutex> lock(poisoned_contexts_mutex);
    const PoisonedContext *tracked = FindPoisonedContext(context);
    if (tracked != nullptr) {
      poisoned = *tracked;
    }
  }
  if (poisoned.context != nullptr) {
    AbortContractViolation(attempted_api, poisoned);
  }
}

void ForgetContext(const ZSTD_DCtx *context) {
  if (context == nullptr ||
      poisoned_context_count.load(std::memory_order_acquire) == 0) {
    return;
  }

  std::lock_guard<std::mutex> lock(poisoned_contexts_mutex);
  PoisonedContext *poisoned = FindPoisonedContext(context);
  if (poisoned != nullptr) {
    *poisoned = PoisonedContext{};
    poisoned_context_count.fetch_sub(1, std::memory_order_release);
  }
}

void PoisonContext(const ZSTD_DCtx *context, size_t error_result) {
  if (context == nullptr) {
    return;
  }

  bool table_full = false;
  bool added = false;
  {
    std::lock_guard<std::mutex> lock(poisoned_contexts_mutex);
    PoisonedContext *poisoned = FindPoisonedContext(context);
    if (poisoned == nullptr) {
      for (PoisonedContext &entry : poisoned_contexts) {
        if (entry.context == nullptr) {
          poisoned = &entry;
          added = true;
          break;
        }
      }
    }
    if (poisoned != nullptr) {
      poisoned->context = context;
      poisoned->error_result = error_result;
      if (added) {
        poisoned_context_count.fetch_add(1, std::memory_order_release);
      }
    } else {
      table_full = true;
    }
  }
  if (table_full) {
    AbortTableOverflow(context, error_result);
  }
}

} // namespace

// GNU ld and lld provide each __real_* symbol when the final link uses the
// matching --wrap option. decltype ties these declarations to the installed
// zstd headers and makes signature drift a compile-time failure.
extern "C" decltype(ZSTD_createDCtx) __real_ZSTD_createDCtx;
extern "C" decltype(ZSTD_createDCtx_advanced) __real_ZSTD_createDCtx_advanced;
extern "C" decltype(ZSTD_createDStream) __real_ZSTD_createDStream;
extern "C" decltype(ZSTD_createDStream_advanced)
    __real_ZSTD_createDStream_advanced;
extern "C" decltype(ZSTD_freeDCtx) __real_ZSTD_freeDCtx;
extern "C" decltype(ZSTD_freeDStream) __real_ZSTD_freeDStream;
extern "C" decltype(ZSTD_initDStream) __real_ZSTD_initDStream;
extern "C" decltype(ZSTD_DCtx_reset) __real_ZSTD_DCtx_reset;
extern "C" decltype(ZSTD_decompressStream) __real_ZSTD_decompressStream;

extern "C" ZSTD_DCtx *__wrap_ZSTD_createDCtx(void) {
  if (IsRealCallActive()) {
    return __real_ZSTD_createDCtx();
  }
  ZSTD_DCtx *context;
  {
    RealCallScope real_call;
    context = __real_ZSTD_createDCtx();
  }
  // A zstd allocator may reuse the address of a recently freed context.
  ForgetContext(context);
  return context;
}
static_assert(std::is_same<decltype(ZSTD_createDCtx),
                           decltype(__wrap_ZSTD_createDCtx)>::value,
              "ZSTD_createDCtx signature changed");

extern "C" ZSTD_DCtx *
__wrap_ZSTD_createDCtx_advanced(ZSTD_customMem custom_memory) {
  if (IsRealCallActive()) {
    return __real_ZSTD_createDCtx_advanced(custom_memory);
  }
  ZSTD_DCtx *context;
  {
    RealCallScope real_call;
    context = __real_ZSTD_createDCtx_advanced(custom_memory);
  }
  ForgetContext(context);
  return context;
}
static_assert(std::is_same<decltype(ZSTD_createDCtx_advanced),
                           decltype(__wrap_ZSTD_createDCtx_advanced)>::value,
              "ZSTD_createDCtx_advanced signature changed");

extern "C" ZSTD_DStream *__wrap_ZSTD_createDStream(void) {
  if (IsRealCallActive()) {
    return __real_ZSTD_createDStream();
  }
  ZSTD_DStream *stream;
  {
    RealCallScope real_call;
    stream = __real_ZSTD_createDStream();
  }
  ForgetContext(stream);
  return stream;
}
static_assert(std::is_same<decltype(ZSTD_createDStream),
                           decltype(__wrap_ZSTD_createDStream)>::value,
              "ZSTD_createDStream signature changed");

extern "C" ZSTD_DStream *
__wrap_ZSTD_createDStream_advanced(ZSTD_customMem custom_memory) {
  if (IsRealCallActive()) {
    return __real_ZSTD_createDStream_advanced(custom_memory);
  }
  ZSTD_DStream *stream;
  {
    RealCallScope real_call;
    stream = __real_ZSTD_createDStream_advanced(custom_memory);
  }
  ForgetContext(stream);
  return stream;
}
static_assert(std::is_same<decltype(ZSTD_createDStream_advanced),
                           decltype(__wrap_ZSTD_createDStream_advanced)>::value,
              "ZSTD_createDStream_advanced signature changed");

extern "C" size_t __wrap_ZSTD_freeDCtx(ZSTD_DCtx *context) {
  if (IsRealCallActive()) {
    return __real_ZSTD_freeDCtx(context);
  }
  size_t result;
  {
    RealCallScope real_call;
    result = __real_ZSTD_freeDCtx(context);
  }
  if (!ZSTD_isError(result)) {
    ForgetContext(context);
  }
  return result;
}
static_assert(std::is_same<decltype(ZSTD_freeDCtx),
                           decltype(__wrap_ZSTD_freeDCtx)>::value,
              "ZSTD_freeDCtx signature changed");

extern "C" size_t __wrap_ZSTD_freeDStream(ZSTD_DStream *stream) {
  if (IsRealCallActive()) {
    return __real_ZSTD_freeDStream(stream);
  }
  size_t result;
  {
    RealCallScope real_call;
    result = __real_ZSTD_freeDStream(stream);
  }
  if (!ZSTD_isError(result)) {
    ForgetContext(stream);
  }
  return result;
}
static_assert(std::is_same<decltype(ZSTD_freeDStream),
                           decltype(__wrap_ZSTD_freeDStream)>::value,
              "ZSTD_freeDStream signature changed");

extern "C" size_t __wrap_ZSTD_initDStream(ZSTD_DStream *stream) {
  if (IsRealCallActive()) {
    return __real_ZSTD_initDStream(stream);
  }
  size_t result;
  {
    RealCallScope real_call;
    result = __real_ZSTD_initDStream(stream);
  }
  if (!ZSTD_isError(result)) {
    ForgetContext(stream);
  }
  return result;
}
static_assert(std::is_same<decltype(ZSTD_initDStream),
                           decltype(__wrap_ZSTD_initDStream)>::value,
              "ZSTD_initDStream signature changed");

extern "C" size_t __wrap_ZSTD_DCtx_reset(ZSTD_DCtx *context,
                                         ZSTD_ResetDirective reset) {
  if (IsRealCallActive()) {
    return __real_ZSTD_DCtx_reset(context, reset);
  }
  size_t result;
  {
    RealCallScope real_call;
    result = __real_ZSTD_DCtx_reset(context, reset);
  }
  if (!ZSTD_isError(result) && ResetsDecompressionSession(reset)) {
    ForgetContext(context);
  }
  return result;
}
static_assert(std::is_same<decltype(ZSTD_DCtx_reset),
                           decltype(__wrap_ZSTD_DCtx_reset)>::value,
              "ZSTD_DCtx_reset signature changed");

extern "C" size_t __wrap_ZSTD_decompressStream(ZSTD_DStream *stream,
                                               ZSTD_outBuffer *output,
                                               ZSTD_inBuffer *input) {
  if (IsRealCallActive()) {
    return __real_ZSTD_decompressStream(stream, output, input);
  }
  CheckUsable(stream, "ZSTD_decompressStream");
  size_t result;
  {
    RealCallScope real_call;
    result = __real_ZSTD_decompressStream(stream, output, input);
  }
  if (ZSTD_isError(result)) {
    PoisonContext(stream, result);
  }
  return result;
}
static_assert(std::is_same<decltype(ZSTD_decompressStream),
                           decltype(__wrap_ZSTD_decompressStream)>::value,
              "ZSTD_decompressStream signature changed");
