/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared byte-to-protobuf dispatch for the policy-split fuzzers.

#ifndef PROTO_FUZZER_FUZZER_MAIN_H_
#define PROTO_FUZZER_FUZZER_MAIN_H_

#include <cstddef>
#include <cstdint>

#include "proto_fuzzer/target_profile.h"

namespace proto_fuzzer {

int ProtoFuzzerTestOneInput(TargetProfile profile, const std::uint8_t* data, std::size_t size);

std::size_t ProtoFuzzerCustomMutator(TargetProfile profile, std::uint8_t* data, std::size_t size, std::size_t max_size,
                                     unsigned int seed);

std::size_t ProtoFuzzerCustomCrossOver(TargetProfile profile, const std::uint8_t* data1, std::size_t size1,
                                       const std::uint8_t* data2, std::size_t size2, std::uint8_t* out,
                                       std::size_t max_out_size, unsigned int seed);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_FUZZER_MAIN_H_
