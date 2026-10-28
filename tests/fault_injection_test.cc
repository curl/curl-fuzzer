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
#include <optional>
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

void TestArmNextAllocationFailure() {
  const std::uint32_t later[] = {7};
  faults::Configure(later, std::size(later));
  faults::Arm();
  faults::ArmNextAllocationFailure();

  Expect(faults::internal::Malloc(8) == nullptr,
         "semantic arm did not fail the next allocation");
  void *recovered = faults::internal::Malloc(8);
  const faults::Statistics statistics = faults::GetStatistics();
  Expect(recovered != nullptr && statistics.armed &&
             statistics.configured_failures == 1 &&
             statistics.allocation_attempts == 2 &&
             statistics.injected_failures == 1,
         "semantic arm retained an earlier plan or reported bad statistics");
  faults::Reset();
  faults::internal::Free(recovered);
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

void TestScopedFailureSuppression() {
  const std::uint32_t first[] = {1};
  faults::Configure(first, std::size(first));
  faults::Arm();

  void *outer_allocation = nullptr;
  void *nested_allocation = nullptr;
  void *resumed_allocation = nullptr;
  bool worker_failure_observed = false;
  {
    faults::ScopedFailureSuppression outer;
    outer_allocation = faults::internal::Malloc(8);
    {
      faults::ScopedFailureSuppression nested;
      nested_allocation = faults::internal::Malloc(8);
      std::thread worker([&worker_failure_observed] {
        const std::uint32_t worker_first[] = {1};
        faults::Configure(worker_first, std::size(worker_first));
        faults::Arm();
        void *allocation = faults::internal::Malloc(8);
        const faults::Statistics statistics = faults::GetStatistics();
        worker_failure_observed = allocation == nullptr && statistics.armed &&
                                  statistics.allocation_attempts == 1 &&
                                  statistics.injected_failures == 1;
        faults::internal::Free(allocation);
        faults::Reset();
      });
      worker.join();
    }
    resumed_allocation = faults::internal::Malloc(8);
    const faults::Statistics suppressed = faults::GetStatistics();
    Expect(outer_allocation != nullptr && nested_allocation != nullptr &&
               resumed_allocation != nullptr && worker_failure_observed &&
               !suppressed.armed && suppressed.allocation_attempts == 0 &&
               suppressed.injected_failures == 0,
           "scoped suppression consumed an ordinal or crossed threads");
  }

  Expect(faults::internal::Malloc(8) == nullptr,
         "suppression did not preserve the pending allocation failure");
  void *recovered = faults::internal::Malloc(8);
  const faults::Statistics resumed = faults::GetStatistics();
  Expect(recovered != nullptr && resumed.allocation_attempts == 2 &&
             resumed.injected_failures == 1,
         "allocation plan did not resume after suppression");
  faults::Disarm();
  faults::internal::Free(outer_allocation);
  faults::internal::Free(nested_allocation);
  faults::internal::Free(resumed_allocation);
  faults::internal::Free(recovered);
}

void TestResetInvalidatesLiveSuppression() {
  std::optional<faults::ScopedFailureSuppression> stale_guard;
  stale_guard.emplace();
  faults::Reset();

  const std::uint32_t first[] = {1};
  faults::Configure(first, std::size(first));
  faults::Arm();
  void *suppressed = nullptr;
  {
    faults::ScopedFailureSuppression current_guard;
    stale_guard.reset();
    suppressed = faults::internal::Malloc(8);
    Expect(suppressed != nullptr &&
               faults::GetStatistics().allocation_attempts == 0,
           "stale suppression guard changed the current generation");
  }
  Expect(faults::internal::Malloc(8) == nullptr,
         "reset suppression generation lost the pending failure");
  faults::Reset();
  faults::internal::Free(suppressed);
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

void TestCurlCallbackReinitialization() {
  faults::Reset();
  curl_global_cleanup();
  Expect(faults::ReinitializeCurl(),
         "allocator callbacks were not reinstalled after global cleanup");
  TestInstalledCurlCallbacks();
}

} // namespace

int main() {
  Expect(faults::InitializeCurl(), "allocator callbacks were not installed");
  Expect(faults::CurlInitializationSucceeded(),
         "allocator setup did not retain its global initialization");
  Expect(faults::ClaimCurlInitializationReference(),
         "allocator global reference could not be claimed");
  Expect(!faults::ClaimCurlInitializationReference(),
         "allocator global reference was claimed more than once");
  TestBoundedOrdinalPlan();
  TestAllocatorContracts();
  TestArmNextAllocationFailure();
  TestDisarmAndReset();
  TestScopedFailureSuppression();
  TestResetInvalidatesLiveSuppression();
  TestThreadLocalPlan();
  TestInstalledCurlCallbacks();
  TestCurlCallbackReinitialization();
  faults::Reset();
  return 0;
}
