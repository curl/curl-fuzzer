/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#ifdef CURL_FUZZER_COVERAGE_ONLY
#include "full_coverage/dynamic_formatting.h"
#include "full_coverage/legacy_mutator.h"
#include "full_coverage/public_api.h"
#include "full_coverage/utility_api.h"

namespace {

// OSS-Fuzz's coverage job invokes targets with -merge=1. When the saved corpus
// is empty, libFuzzer still calls LLVMFuzzerInitialize but never calls
// LLVMFuzzerTestOneInput. Keep the initialization-safe probes reachable from
// both hooks so the coverage-only target does useful work even before
// ClusterFuzz has retained a corpus unit for it.
void RunInitializationSafeProbesOnce() {
  static bool completed = false;
  if (completed)
    return;

  completed = true;
  full_coverage::ExercisePublicApiCoverage();
  full_coverage::ExerciseUtilityApiCoverage();
  full_coverage::ExerciseDynamicFormattingCoverage();
}

void RunCallbackOnlyProbesOnce() {
  static bool completed = false;
  if (completed)
    return;

  completed = true;
  // This probe deliberately exercises LLVMFuzzerMutate when the engine
  // provides it. That API is not ready during LLVMFuzzerInitialize, so keep
  // the probe behind the first ordinary input callback.
  full_coverage::ExerciseLegacyMutatorCoverage();
}

} // namespace
#endif

// libFuzzer calls this hook even when -merge=1 is paired with an empty corpus.
// Ordinary sanitizer builds leave it as a no-op; their first input callback
// still terminates the profiling-only target below.
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
#ifdef CURL_FUZZER_COVERAGE_ONLY
  RunInitializationSafeProbesOnce();
#endif
  return 0;
}

// Keep a literal, same-named entrypoint for Fuzz Introspector attribution.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) {
#ifdef CURL_FUZZER_COVERAGE_ONLY
  // Retain the calls from the canonical fuzz entrypoint for Fuzz
  // Introspector attribution and standalone runners that do not implement
  // libFuzzer's optional initialization hook.
  RunInitializationSafeProbesOnce();
  RunCallbackOnlyProbesOnce();
  return 0;
#else
  // Returning zero would leave libFuzzer mutating a target with no work.
  // Skip its atexit handler, which classifies exit() inside a callback as a
  // target failure and writes a spurious crash artifact.
  std::_Exit(EXIT_SUCCESS);
#endif
}
