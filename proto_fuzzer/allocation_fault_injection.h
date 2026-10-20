/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef PROTO_FUZZER_ALLOCATION_FAULT_INJECTION_H_
#define PROTO_FUZZER_ALLOCATION_FAULT_INJECTION_H_

#include <cstddef>
#include <cstdint>

namespace proto_fuzzer::allocation_fault_injection {

namespace internal {

/// Nesting depth for harness-only allocations excluded from fault injection.
inline thread_local std::size_t failure_suppression_depth = 0;
/// Invalidates live guards when Reset() repairs state after a non-local exit.
inline thread_local std::uint64_t failure_suppression_generation = 0;

/// Enter one nestable suppression scope on the calling thread.
/// @return Generation captured by the matching scope guard.
inline std::uint64_t BeginFailureSuppression() noexcept {
  ++failure_suppression_depth;
  return failure_suppression_generation;
}

/// Leave a suppression scope unless Reset() already invalidated its guard.
/// @param generation Generation captured when the guard was constructed.
inline void EndFailureSuppression(std::uint64_t generation) noexcept {
  if (generation == failure_suppression_generation && failure_suppression_depth != 0) {
    --failure_suppression_depth;
  }
}

/// @return Whether injected failures are suppressed on the calling thread.
inline bool FailuresSuppressed() noexcept { return failure_suppression_depth != 0; }

/// Clear leaked suppression after a standalone-runner non-local exit.
inline void ResetFailureSuppression() noexcept {
  failure_suppression_depth = 0;
  ++failure_suppression_generation;
}

}  // namespace internal

/**
 * Exclude a narrow harness-only operation from the allocation-failure plan.
 *
 * Scopes nest on the calling thread. Positive-size libcurl allocations made
 * inside them bypass injected failures without advancing the active ordinal
 * sequence, so failures remain pending for subsequent injectable allocations.
 * Construct and destroy each guard on the same thread. Reset() invalidates any
 * live guards after a non-local exit and makes their later destruction a no-op.
 */
class ScopedFailureSuppression final {
 public:
  ScopedFailureSuppression() noexcept : generation_(internal::BeginFailureSuppression()) {}
  ~ScopedFailureSuppression() { internal::EndFailureSuppression(generation_); }

  ScopedFailureSuppression(const ScopedFailureSuppression&) = delete;
  ScopedFailureSuppression& operator=(const ScopedFailureSuppression&) = delete;
  ScopedFailureSuppression(ScopedFailureSuppression&&) = delete;
  ScopedFailureSuppression& operator=(ScopedFailureSuppression&&) = delete;

 private:
  /// Suppression generation used to make destruction safe across Reset().
  std::uint64_t generation_;
};

/** Snapshot of the calling thread's current allocation-failure plan. */
struct Statistics {
  /// Positive-size allocation calls observed since the last Arm().
  std::uint64_t allocation_attempts = 0;
  /// Selected calls rejected since the last Arm().
  std::uint64_t injected_failures = 0;
  /// Distinct ordinals retained in the bounded plan.
  std::size_t configured_failures = 0;
  /// Whether allocation calls on this thread are currently observed.
  bool armed = false;
};

bool InitializeCurl() noexcept;
void Configure(const std::uint32_t* ordinals, std::size_t count) noexcept;
void Arm() noexcept;
void Disarm() noexcept;
void Reset() noexcept;
Statistics GetStatistics() noexcept;

// These are the process-wide callbacks passed to curl_global_init_mem. They
// remain visible so the focused unit test can verify the allocator contracts
// without depending on a particular libcurl call's private allocation trace.
namespace internal {

void* Malloc(std::size_t size) noexcept;
void Free(void* pointer) noexcept;
void* Realloc(void* pointer, std::size_t size) noexcept;
char* Strdup(const char* string) noexcept;
void* Calloc(std::size_t count, std::size_t size) noexcept;

}  // namespace internal
}  // namespace proto_fuzzer::allocation_fault_injection

#endif  // PROTO_FUZZER_ALLOCATION_FAULT_INJECTION_H_
