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
