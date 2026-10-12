/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/allocation_fault_injection.h"

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer::allocation_fault_injection {
namespace {

struct ThreadState {
  std::array<std::uint32_t, scenario_limits::kMaxAllocationFailures> ordinals{};
  std::size_t ordinal_count = 0;
  std::size_t next_ordinal = 0;
  std::uint64_t allocation_attempts = 0;
  std::uint64_t injected_failures = 0;
  bool armed = false;
};

thread_local ThreadState state;
std::once_flag initialize_once;
bool callbacks_active = false;

std::uint32_t CanonicalOrdinal(std::uint32_t ordinal) noexcept {
  if (ordinal == 0) {
    return 0;
  }
  const std::uint32_t maximum = static_cast<std::uint32_t>(scenario_limits::kMaxAllocationOrdinal);
  return 1U + ((ordinal - 1U) % maximum);
}

void InsertOrdinal(std::uint32_t ordinal) noexcept {
  if (ordinal == 0) {
    return;
  }
  const auto begin = state.ordinals.begin();
  const auto end = begin + static_cast<std::ptrdiff_t>(state.ordinal_count);
  const auto position = std::lower_bound(begin, end, ordinal);
  if (position != end && *position == ordinal) {
    return;
  }
  const std::size_t index = static_cast<std::size_t>(position - begin);
  if (index >= state.ordinals.size()) {
    return;
  }
  if (state.ordinal_count < state.ordinals.size()) {
    ++state.ordinal_count;
  }
  for (std::size_t destination = state.ordinal_count - 1; destination > index; --destination) {
    state.ordinals[destination] = state.ordinals[destination - 1];
  }
  state.ordinals[index] = ordinal;
}

bool ShouldFail(bool positive_size) noexcept {
  if (!positive_size || !state.armed) {
    return false;
  }
  ++state.allocation_attempts;
  if (state.next_ordinal < state.ordinal_count && state.allocation_attempts == state.ordinals[state.next_ordinal]) {
    ++state.next_ordinal;
    ++state.injected_failures;
    errno = ENOMEM;
    return true;
  }
  return false;
}

}  // namespace

/// Install the allocator callbacks before any other libcurl global
/// initialization. The callbacks remain installed for the process lifetime;
/// individual inputs only change thread-local state. A small allocation
/// verifies that a pre-existing global initialization did not silently keep
/// the default callbacks.
/// @return true when libcurl invoked the installed callbacks.
bool InitializeCurl() noexcept {
  std::call_once(initialize_once, [] {
    if (curl_global_init_mem(CURL_GLOBAL_ALL, internal::Malloc, internal::Free, internal::Realloc, internal::Strdup,
                             internal::Calloc) != CURLE_OK) {
      return;
    }

    state.armed = true;
    char* probe = curl_escape("allocator callback probe", 0);
    callbacks_active = state.allocation_attempts != 0;
    state.armed = false;
    curl_free(probe);
    state = ThreadState{};
  });
  return callbacks_active;
}

/// Store a bounded, sorted, unique allocation plan for the calling thread.
/// Values outside the useful range are folded into it. Retaining the smallest
/// ordinals makes oversized compatibility inputs deterministic without heap
/// allocation in the controller itself.
/// @param ordinals One-based positive allocation attempt numbers.
/// @param count Number of values available at ordinals.
void Configure(const std::uint32_t* ordinals, std::size_t count) noexcept {
  state = ThreadState{};
  if (ordinals == nullptr) {
    return;
  }
  for (std::size_t index = 0; index < count; ++index) {
    InsertOrdinal(CanonicalOrdinal(ordinals[index]));
  }
}

/// Begin counting positive-size allocation attempts on the calling thread.
/// Each configured ordinal can fail once. A later ordinal is evaluated on the
/// execution path already changed by every earlier injected failure.
void Arm() noexcept {
  state.next_ordinal = 0;
  state.allocation_attempts = 0;
  state.injected_failures = 0;
  state.armed = state.ordinal_count != 0;
}

/// Stop fault injection while retaining counters for diagnostics and tests.
void Disarm() noexcept { state.armed = false; }

/// Clear all thread-local controller state. Fuzzer entrypoints call this
/// before parsing so a standalone-runner siglongjmp cannot leak an armed plan
/// into the next input.
void Reset() noexcept { state = ThreadState{}; }

/// Read the calling thread's current plan and counters.
/// @return A value snapshot that remains valid after later controller calls.
Statistics GetStatistics() noexcept {
  return {state.allocation_attempts, state.injected_failures, state.ordinal_count, state.armed};
}

namespace internal {

/// Allocate with libc unless this positive-size attempt is selected to fail.
void* Malloc(std::size_t size) noexcept { return ShouldFail(size != 0) ? nullptr : std::malloc(size); }

/// Release an allocation. Frees are never counted or rejected.
void Free(void* pointer) noexcept { std::free(pointer); }

/// Resize with libc unless this positive-size attempt is selected to fail.
/// Rejecting the call before libc preserves ownership of the original block.
void* Realloc(void* pointer, std::size_t size) noexcept {
  return ShouldFail(size != 0) ? nullptr : std::realloc(pointer, size);
}

/// Duplicate one string while counting the operation as one allocation.
char* Strdup(const char* string) noexcept {
  if (string == nullptr) {
    return nullptr;
  }
  const std::size_t length = std::strlen(string) + 1;
  if (ShouldFail(length != 0)) {
    return nullptr;
  }
  char* copy = static_cast<char*>(std::malloc(length));
  if (copy != nullptr) {
    std::memcpy(copy, string, length);
  }
  return copy;
}

/// Allocate zero-filled storage unless this positive-size request is selected
/// to fail. The request counts once rather than once per element.
void* Calloc(std::size_t count, std::size_t size) noexcept {
  return ShouldFail(count != 0 && size != 0) ? nullptr : std::calloc(count, size);
}

}  // namespace internal
}  // namespace proto_fuzzer::allocation_fault_injection
