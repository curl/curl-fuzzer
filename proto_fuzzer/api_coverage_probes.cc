/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/api_coverage_probes.h"

#include <curl/curl.h>

#include "full_coverage/dynamic_formatting.h"
#include "full_coverage/public_api.h"
#include "full_coverage/utility_api.h"
#include "proto_fuzzer/allocation_fault_injection.h"
#include "proto_fuzzer/curl_global_lifecycle.h"

namespace proto_fuzzer {
namespace {

/** Balance the API probe's public global reference only at process exit. */
class DeferredCurlGlobalReference final {
 public:
  DeferredCurlGlobalReference() : initialized_(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK) {}

  ~DeferredCurlGlobalReference() {
    if (initialized_) {
      // Drop this probe's public reference, then ask the registered owner to
      // release its own base reference. This destructor was registered from
      // LLVMFuzzerInitialize, so final resolver/TLS cleanup runs before LLVM's
      // profile writer. The owner's later destructor is then a no-op.
      curl_global_cleanup();
      FinalizeRegisteredCurlGlobalLifecyclesForExit();
    }
  }

  DeferredCurlGlobalReference(const DeferredCurlGlobalReference&) = delete;
  DeferredCurlGlobalReference& operator=(const DeferredCurlGlobalReference&) = delete;

 private:
  bool initialized_;
};

}  // namespace

/**
 * Run bounded curl API probes once without tearing down global state.
 *
 * The caller normally owns an initialized curl runtime. This function retains
 * one public global reference until process exit, so repeated calls are safe
 * and perform no additional work. Both LLVMFuzzerInitialize and the first
 * input callback can therefore provide reachability without per-input cost.
 */
void RunApiCoverageProbesOnce() {
  // This function-local lifetime begins after the proto runtime's static
  // bootstrap, so its destructor can finalize curl before the bootstrap's
  // idempotent destructor and LLVM's profile write.
  static const DeferredCurlGlobalReference global_reference;
  static const bool completed = [] {
    // These are harness-owned deterministic allocations, not part of a
    // Scenario's fault plan. The initialization hook normally runs before a
    // plan can be armed; suppression also makes the callback fallback safe.
    allocation_fault_injection::ScopedFailureSuppression suppress_failures;
    full_coverage::ExercisePublicApiCoverageWithInitializedCurl();
    full_coverage::ExerciseUtilityApiCoverageWithInitializedCurl();
    full_coverage::ExerciseDynamicFormattingCoverage();
    return true;
  }();
  (void)global_reference;
  (void)completed;
}

}  // namespace proto_fuzzer
