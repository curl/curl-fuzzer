/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/fuzzer_main.h"

namespace {

using Fuzzer =
    proto_fuzzer::ProtoFuzzerEntrypoint<proto_fuzzer::TargetProfile::kMulti>;

} // namespace

extern "C" std::size_t LLVMFuzzerCustomMutator(std::uint8_t *data,
                                               std::size_t size,
                                               std::size_t max_size,
                                               unsigned int seed) {
  return Fuzzer::CustomMutator(data, size, max_size, seed);
}

extern "C" std::size_t
LLVMFuzzerCustomCrossOver(const std::uint8_t *data1, std::size_t size1,
                          const std::uint8_t *data2, std::size_t size2,
                          std::uint8_t *out, std::size_t max_out_size,
                          unsigned int seed) {
  return Fuzzer::CustomCrossOver(data1, size1, data2, size2, out, max_out_size,
                                 seed);
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  return Fuzzer::TestOneInput(data, size);
}
