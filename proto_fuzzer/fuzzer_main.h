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

namespace proto_fuzzer {

/// Decode and run one serialized Scenario. Keeping this behind an ordinary
/// function allows each binary to expose a discoverable, same-named libFuzzer
/// entrypoint while retaining one mutation and execution implementation.
/// @param data Serialized binary Scenario bytes.
/// @param size Number of bytes available at data.
/// @return Always zero, as required by libFuzzer.
int ProtoFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_FUZZER_MAIN_H_
