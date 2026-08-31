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

/// Decode and run one serialized Scenario. Keeping this behind an ordinary
/// function allows each binary to expose a discoverable, same-named libFuzzer
/// entrypoint while retaining one mutation and execution implementation. The
/// profile is explicit so target identity remains visible at the entrypoint
/// instead of being hidden in per-translation-unit compiler definitions.
/// @param profile Mutation and execution policy selected by the entrypoint.
/// @param data Serialized binary Scenario bytes.
/// @param size Number of bytes available at data.
/// @return Always zero, as required by libFuzzer.
int ProtoFuzzerTestOneInput(TargetProfile profile, const std::uint8_t* data, std::size_t size);

/// Mutate a serialized Scenario while preserving the selected lane's policy.
/// @param profile Mutation and execution policy selected by the entrypoint.
/// @param data Mutable serialized Scenario storage.
/// @param size Current serialized size.
/// @param max_size Capacity of data.
/// @param seed Mutation random seed supplied by libFuzzer.
/// @return Serialized size after mutation.
std::size_t ProtoFuzzerCustomMutator(TargetProfile profile, std::uint8_t* data, std::size_t size, std::size_t max_size,
                                     unsigned int seed);

/// Cross two serialized Scenarios while preserving the selected lane's policy.
/// @param profile Mutation and execution policy selected by the entrypoint.
/// @param data1 First serialized parent.
/// @param size1 Size of data1.
/// @param data2 Second serialized parent.
/// @param size2 Size of data2.
/// @param out Destination storage.
/// @param max_out_size Capacity of out.
/// @param seed Crossover random seed supplied by libFuzzer.
/// @return Serialized child size.
std::size_t ProtoFuzzerCustomCrossOver(TargetProfile profile, const std::uint8_t* data1, std::size_t size1,
                                       const std::uint8_t* data2, std::size_t size2, std::uint8_t* out,
                                       std::size_t max_out_size, unsigned int seed);

/// Binds a concrete profile once in each thin entrypoint source. This adapter
/// keeps libFuzzer's C ABI boilerplate uniform without making target selection
/// an invisible compile-time side effect in the shared implementation.
/// @tparam Profile Fixed identity of the binary exposing these callbacks.
template <TargetProfile Profile>
struct ProtoFuzzerEntrypoint {
  /// Forward a corpus input with the profile fixed by this binary. Keeping the
  /// profile out of the C ABI prevents libFuzzer from choosing it while still
  /// making the binding explicit in the entrypoint source.
  /// @param data Serialized binary Scenario bytes.
  /// @param size Number of bytes available at data.
  /// @return Always zero, as required by libFuzzer.
  static int TestOneInput(const std::uint8_t* data, std::size_t size) {
    return ProtoFuzzerTestOneInput(Profile, data, size);
  }

  /// Forward mutation through the same fixed profile used for execution so a
  /// lane cannot accumulate inputs that its runner will immediately discard.
  /// @param data Mutable serialized Scenario storage.
  /// @param size Current serialized size.
  /// @param max_size Capacity of data.
  /// @param seed Mutation random seed supplied by libFuzzer.
  /// @return Serialized size after mutation.
  static std::size_t CustomMutator(std::uint8_t* data, std::size_t size, std::size_t max_size, unsigned int seed) {
    return ProtoFuzzerCustomMutator(Profile, data, size, max_size, seed);
  }

  /// Forward crossover through the fixed profile so children are normalized
  /// for the same lane as both ordinary mutations and execution.
  /// @param data1 First serialized parent.
  /// @param size1 Size of data1.
  /// @param data2 Second serialized parent.
  /// @param size2 Size of data2.
  /// @param out Destination storage.
  /// @param max_out_size Capacity of out.
  /// @param seed Crossover random seed supplied by libFuzzer.
  /// @return Serialized child size.
  static std::size_t CustomCrossOver(const std::uint8_t* data1, std::size_t size1, const std::uint8_t* data2,
                                     std::size_t size2, std::uint8_t* out, std::size_t max_out_size,
                                     unsigned int seed) {
    return ProtoFuzzerCustomCrossOver(Profile, data1, size1, data2, size2, out, max_out_size, seed);
  }
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_FUZZER_MAIN_H_
