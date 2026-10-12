/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#ifdef CURL_FUZZER_COVERAGE_ONLY
#include "full_coverage/public_api.h"
#endif

// Keep a literal, same-named entrypoint for Fuzz Introspector attribution.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t)
{
#ifdef CURL_FUZZER_COVERAGE_ONLY
  // These deterministic probes supplement corpus replay. Run them once even
  // when the profiling engine invokes the entrypoint for many corpus entries.
  static bool completed = false;
  if(!completed) {
    completed = true;
    full_coverage::ExercisePublicApiCoverage();
  }
  return 0;
#else
  // Returning zero would leave libFuzzer mutating a target with no work.
  // Skip its atexit handler, which classifies exit() inside a callback as a
  // target failure and writes a spurious crash artifact.
  std::_Exit(EXIT_SUCCESS);
#endif
}
