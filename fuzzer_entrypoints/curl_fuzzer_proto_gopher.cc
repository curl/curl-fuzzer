/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/fuzzer_main.h"

namespace {

// Keep mutation, crossover, and execution on the Gopher policy.
constexpr auto kProfile = proto_fuzzer::TargetProfile::kFastGopher;

} // namespace

extern "C" std::size_t LLVMFuzzerCustomMutator(std::uint8_t *data,
                                               std::size_t size,
                                               std::size_t max_size,
                                               unsigned int seed) {
  return proto_fuzzer::ProtoFuzzerCustomMutator(kProfile, data, size, max_size,
                                                seed);
}

extern "C" std::size_t
LLVMFuzzerCustomCrossOver(const std::uint8_t *data1, std::size_t size1,
                          const std::uint8_t *data2, std::size_t size2,
                          std::uint8_t *out, std::size_t max_out_size,
                          unsigned int seed) {
  return proto_fuzzer::ProtoFuzzerCustomCrossOver(
      kProfile, data1, size1, data2, size2, out, max_out_size, seed);
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  return proto_fuzzer::ProtoFuzzerTestOneInput(kProfile, data, size);
}
