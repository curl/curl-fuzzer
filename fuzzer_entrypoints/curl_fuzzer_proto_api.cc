/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "generated/api/api_traits.h"
#include "proto_fuzzer/fuzzer_main.h"

#if defined(PROTO_FUZZER_API_COVERAGE_PROBES)
#include "proto_fuzzer/api_coverage_probes.h"
#endif

namespace {

// Bind this source's visible target identity once so mutation, crossover, and
// execution cannot drift onto different policies as the shared runner evolves.
using Traits = proto_fuzzer::generated::ApiTraits;

} // namespace

#if defined(PROTO_FUZZER_API_COVERAGE_PROBES)
// OSS-Fuzz can execute a coverage merge with an empty corpus. The optional
// initialization hook keeps the API probes reachable in that case.
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  proto_fuzzer::RunApiCoverageProbesOnce();
  return 0;
}
#endif

// Keep all three libFuzzer ABI hooks in the same-named source. Besides making
// the selected profile explicit, this lets Fuzz Introspector attribute the
// API lifecycle lane independently while the implementation remains shared.
extern "C" std::size_t LLVMFuzzerCustomMutator(std::uint8_t *data,
                                               std::size_t size,
                                               std::size_t max_size,
                                               unsigned int seed) {
  return proto_fuzzer::ProtoFuzzerCustomMutator<Traits>(data, size, max_size,
                                                        seed);
}

extern "C" std::size_t
LLVMFuzzerCustomCrossOver(const std::uint8_t *data1, std::size_t size1,
                          const std::uint8_t *data2, std::size_t size2,
                          std::uint8_t *out, std::size_t max_out_size,
                          unsigned int seed) {
  return proto_fuzzer::ProtoFuzzerCustomCrossOver<Traits>(
      data1, size1, data2, size2, out, max_out_size, seed);
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
#if defined(PROTO_FUZZER_API_COVERAGE_PROBES)
  // Standalone replay engines do not always call LLVMFuzzerInitialize.
  proto_fuzzer::RunApiCoverageProbesOnce();
#endif
  return proto_fuzzer::ProtoFuzzerTestOneInput<Traits>(data, size);
}
