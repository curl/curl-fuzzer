/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/allocation_fault_injection.h"
#include "test_assertions.h"

#include <curl/curl.h>

#include <array>
#include <cstring>
#include <iterator>
#include <thread>

namespace {

namespace faults = proto_fuzzer::allocation_fault_injection;
using test_support::Expect;

void TestBoundedOrdinalPlan() {
  const std::uint32_t ordinals[] = {9, 0, 3, 9, 1, 7, 2};
  faults::Configure(ordinals, std::size(ordinals));
  faults::Arm();

  std::array<void *, 9> allocations{};
  for (std::size_t index = 0; index < allocations.size(); ++index) {
    allocations[index] = faults::internal::Malloc(8);
    const bool should_fail =
        index == 0 || index == 1 || index == 2 || index == 6;
    Expect((allocations[index] == nullptr) == should_fail,
           "bounded allocation plan failed the wrong ordinal");
  }
  const faults::Statistics stats = faults::GetStatistics();
  Expect(stats.armed && stats.configured_failures == 4 &&
             stats.allocation_attempts == allocations.size() &&
             stats.injected_failures == 4,
         "bounded allocation plan reported incorrect statistics");
  faults::Disarm();
  for (void *allocation : allocations) {
    faults::internal::Free(allocation);
  }
}

void TestAllocatorContracts() {
  const std::uint32_t first[] = {1};
  faults::Configure(first, std::size(first));
  faults::Arm();
  void *empty_malloc = faults::internal::Malloc(0);
  void *empty_calloc = faults::internal::Calloc(0, 8);
  Expect(faults::GetStatistics().allocation_attempts == 0,
         "zero-size calls consumed an allocation ordinal");
  Expect(faults::internal::Malloc(8) == nullptr,
         "positive malloc failure was not injected");
  void *allocated = faults::internal::Malloc(8);
  Expect(allocated != nullptr && faults::GetStatistics().injected_failures == 1,
         "malloc did not recover after its selected failure");
  faults::Disarm();
  faults::internal::Free(empty_malloc);
  faults::internal::Free(empty_calloc);
  faults::internal::Free(allocated);

  char *original = static_cast<char *>(faults::internal::Malloc(16));
  Expect(original != nullptr, "realloc setup failed");
  std::memcpy(original, "original", 9);
  faults::Configure(first, std::size(first));
  faults::Arm();
  Expect(faults::internal::Realloc(original, 32) == nullptr,
         "realloc failure was not injected");
  Expect(std::strcmp(original, "original") == 0,
         "failed realloc changed or released the original allocation");
  faults::Disarm();
  char *grown = static_cast<char *>(faults::internal::Realloc(original, 32));
  Expect(grown != nullptr && std::strcmp(grown, "original") == 0,
         "realloc did not recover after disarming");
  faults::internal::Free(grown);

  faults::Configure(first, std::size(first));
  faults::Arm();
  Expect(faults::internal::Strdup("copy") == nullptr,
         "strdup failure was not injected");
  char *copy = faults::internal::Strdup("copy");
  Expect(copy != nullptr && std::strcmp(copy, "copy") == 0,
         "strdup did not recover after its selected failure");
  faults::Disarm();
  faults::internal::Free(copy);

  faults::Configure(first, std::size(first));
  faults::Arm();
  Expect(faults::internal::Calloc(8, 1) == nullptr,
         "calloc failure was not injected");
  auto *zeroed = static_cast<unsigned char *>(faults::internal::Calloc(8, 1));
  Expect(zeroed != nullptr,
         "calloc did not recover after its selected failure");
  for (std::size_t index = 0; index < 8; ++index) {
    Expect(zeroed[index] == 0, "calloc lost its zero-fill contract");
  }
  faults::Disarm();
  faults::internal::Free(zeroed);
}

void TestDisarmAndReset() {
  const std::uint32_t first[] = {1};
  faults::Configure(first, std::size(first));
  faults::Arm();
  faults::Disarm();
  void *allocation = faults::internal::Malloc(8);
  Expect(allocation != nullptr && !faults::GetStatistics().armed &&
             faults::GetStatistics().allocation_attempts == 0,
         "disarmed controller still consumed a failure ordinal");
  faults::internal::Free(allocation);

  faults::Arm();
  faults::Reset();
  allocation = faults::internal::Malloc(8);
  const faults::Statistics reset = faults::GetStatistics();
  Expect(allocation != nullptr && !reset.armed &&
             reset.configured_failures == 0 && reset.allocation_attempts == 0,
         "entry reset did not clear stale armed state");
  faults::internal::Free(allocation);
}

void TestThreadLocalPlan() {
  const std::uint32_t first[] = {1};
  faults::Configure(first, std::size(first));
  faults::Arm();
  bool worker_succeeded = false;
  std::thread worker([&worker_succeeded] {
    void *allocation = faults::internal::Malloc(8);
    worker_succeeded = allocation != nullptr &&
                       faults::GetStatistics().allocation_attempts == 0;
    faults::internal::Free(allocation);
  });
  worker.join();
  Expect(worker_succeeded, "worker thread inherited the caller's failure plan");
  Expect(faults::internal::Malloc(8) == nullptr &&
             faults::GetStatistics().injected_failures == 1,
         "worker allocation consumed the caller's failure ordinal");
  faults::Disarm();
}

void TestInstalledCurlCallbacks() {
  const std::uint32_t first[] = {1};
  faults::Configure(first, std::size(first));
  faults::Arm();
  char *escaped = curl_escape("callback value", 0);
  const faults::Statistics failed = faults::GetStatistics();
  Expect(escaped == nullptr && failed.allocation_attempts >= 1 &&
             failed.injected_failures == 1,
         "libcurl did not use the installed failure callbacks");
  faults::Disarm();
  curl_free(escaped);

  escaped = curl_escape("callback value", 0);
  Expect(escaped != nullptr && std::strcmp(escaped, "callback%20value") == 0,
         "libcurl did not recover after fault injection was disarmed");
  curl_free(escaped);
}

} // namespace

int main() {
  Expect(faults::InitializeCurl(), "allocator callbacks were not installed");
  TestBoundedOrdinalPlan();
  TestAllocatorContracts();
  TestDisarmAndReset();
  TestThreadLocalPlan();
  TestInstalledCurlCallbacks();
  faults::Reset();
  return 0;
}
