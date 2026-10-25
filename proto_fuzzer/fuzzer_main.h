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

#if defined(PROTO_FUZZER_OBSERVE_STATE)
#include <array>
#endif

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/allocation_fault_injection.h"
#include "proto_fuzzer/profile_fuzzer.h"
#include "proto_fuzzer/target_policy.h"
#include "proto_fuzzer/target_profile.h"

namespace proto_fuzzer {

/// Execute one already-lowered runtime scenario under its fixed target lane.
void ExecuteProfileScenario(TargetProfile profile, curl::fuzzer::proto::Scenario* scenario);

#if defined(PROTO_FUZZER_OBSERVE_STATE)
/// Exercise the typed mutation ABI once for the profiling timing target.
template <typename Traits>
void ProbeTimingMutationHelpers() {
  constexpr std::size_t kBufferSize = 1024;
  constexpr unsigned int kMutationSeed = 0x4355524cU;

  curl::fuzzer::proto::Scenario runtime;
  runtime.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  runtime.set_host_path("timing.test/profile");
  runtime.mutable_connection();
  runtime.add_subsequent_connections()->mutable_backpressure()->set_drain_limit(1);
  NormalizeScenarioForTarget(&runtime, Traits::kProfile, &Traits::PruneConditionalEligibility);

  typename Traits::Message message;
  Traits::Lift(&runtime, &message);
  std::array<std::uint8_t, kBufferSize> first = {};
  const std::size_t original_size = message.ByteSizeLong();
  if (original_size > first.size()) {
    return;
  }
  (void)message.SerializeWithCachedSizesToArray(first.data());

  using Hooks = ProfileFuzzerHooks<Traits>;
  std::array<std::uint8_t, kBufferSize> second = first;
  std::array<std::uint8_t, kBufferSize> child = {};
  const std::size_t mutated_size = Hooks::CustomMutator(first.data(), original_size, first.size(), kMutationSeed);
  const std::size_t crossed_size = Hooks::CustomCrossOver(first.data(), mutated_size, second.data(), original_size,
                                                          child.data(), child.size(), kMutationSeed);
  const volatile std::size_t result_sizes[] = {mutated_size, crossed_size};
  (void)result_sizes;
}
#endif

/// Mutate one serialized generated profile message.
template <typename Traits>
std::size_t ProtoFuzzerCustomMutator(std::uint8_t* data, std::size_t size, std::size_t max_size, unsigned int seed) {
  allocation_fault_injection::Reset();
  return ProfileFuzzerHooks<Traits>::CustomMutator(data, size, max_size, seed);
}

/// Cross two serialized generated profile messages of the same concrete type.
template <typename Traits>
std::size_t ProtoFuzzerCustomCrossOver(const std::uint8_t* data1, std::size_t size1, const std::uint8_t* data2,
                                       std::size_t size2, std::uint8_t* out, std::size_t max_out_size,
                                       unsigned int seed) {
  allocation_fault_injection::Reset();
  return ProfileFuzzerHooks<Traits>::CustomCrossOver(data1, size1, data2, size2, out, max_out_size, seed);
}

/// Load one generated profile message, lower it, and execute runtime state.
template <typename Traits>
int ProtoFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  allocation_fault_injection::Reset();
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  if constexpr (Traits::kProfile == TargetProfile::kTiming) {
    static const bool mutation_helpers_probed = [] {
      ProbeTimingMutationHelpers<Traits>();
      return true;
    }();
    (void)mutation_helpers_probed;
  }
#endif
  curl::fuzzer::proto::Scenario runtime;
  if (ProfileFuzzerHooks<Traits>::LoadAndLower(data, size, &runtime)) {
    ExecuteProfileScenario(Traits::kProfile, &runtime);
  }
  return 0;
}

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_FUZZER_MAIN_H_
