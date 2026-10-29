/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared execution for profile-split protobuf targets.

#include "proto_fuzzer/fuzzer_main.h"

#include <curl/curl.h>

#include <array>
#include <cstdio>

#include "proto_fuzzer/allocation_fault_injection.h"
#include "proto_fuzzer/curl_global_lifecycle.h"
#include "proto_fuzzer/scenario_runner.h"
#include "proto_fuzzer/target_policy.h"

#if defined(PROTO_FUZZER_OBSERVE_STATE)
/// Invoke this target's libFuzzer mutator from coverage-only corpus replay.
/// @param data Serialized profile message buffer to mutate in place.
/// @param size Number of input bytes currently stored in `data`.
/// @param max_size Capacity of `data` available for the mutated message.
/// @param seed Deterministic mutation seed.
/// @return Number of serialized bytes in the mutated message.
extern "C" std::size_t LLVMFuzzerCustomMutator(std::uint8_t* data, std::size_t size, std::size_t max_size,
                                               unsigned int seed);

/// Invoke this target's libFuzzer crossover from coverage-only corpus replay.
/// @param data1 Serialized first parent message.
/// @param size1 Number of bytes in `data1`.
/// @param data2 Serialized second parent message.
/// @param size2 Number of bytes in `data2`.
/// @param out Destination buffer for the child message.
/// @param max_out_size Capacity of `out`.
/// @param seed Deterministic crossover seed.
/// @return Number of serialized bytes written to `out`.
extern "C" std::size_t LLVMFuzzerCustomCrossOver(const std::uint8_t* data1, std::size_t size1,
                                                 const std::uint8_t* data2, std::size_t size2, std::uint8_t* out,
                                                 std::size_t max_out_size, unsigned int seed);
#endif

namespace {

// libFuzzer reuses one process, so the static object initializes curl once and
// releases its global resolver/TLS state only after the engine has stopped.
proto_fuzzer::CurlGlobalLifecycle kGlobalBootstrap;

#if defined(PROTO_FUZZER_OBSERVE_STATE)
/// Exercise this executable's public mutation ABI once. Corpus replay calls
/// only LLVMFuzzerTestOneInput, so otherwise the same-named entrypoint wrappers
/// and shared dispatchers remain uncovered even though libFuzzer uses them in
/// mutation runs. Empty protobuf inputs are valid messages; fixed seeds and
/// bounded buffers keep this coverage-only probe deterministic.
void ProbeMutationEntrypoints() {
  static const bool mutation_entrypoints_probed = [] {
    constexpr std::size_t kBufferSize = 1024;
    constexpr unsigned int kFirstSeed = 0x4355524cU;
    constexpr unsigned int kSecondSeed = 0x46555a5aU;

    std::array<std::uint8_t, kBufferSize> first = {};
    std::array<std::uint8_t, kBufferSize> second = {};
    std::array<std::uint8_t, kBufferSize> child = {};
    const std::size_t first_size = LLVMFuzzerCustomMutator(first.data(), 0, first.size(), kFirstSeed);
    const std::size_t second_size = LLVMFuzzerCustomMutator(second.data(), 0, second.size(), kSecondSeed);
    const std::size_t child_size = LLVMFuzzerCustomCrossOver(first.data(), first_size, second.data(), second_size,
                                                             child.data(), child.size(), kFirstSeed);
    const volatile std::size_t result_sizes[] = {first_size, second_size, child_size};
    (void)result_sizes;
    return true;
  }();
  (void)mutation_entrypoints_probed;
}
#endif

}  // namespace

namespace proto_fuzzer {

/// Mutate one serialized generated profile message.
/// @param data Serialized profile message buffer to mutate in place.
/// @param size Number of input bytes currently stored in `data`.
/// @param max_size Capacity of `data` available for the mutated message.
/// @param seed Deterministic mutation seed supplied by libFuzzer.
/// @param traits Generated profile binding for this executable.
/// @return Number of serialized bytes in the mutated message.
std::size_t ProtoFuzzerCustomMutator(std::uint8_t* data, std::size_t size, std::size_t max_size, unsigned int seed,
                                     const ProfileFuzzerTraits& traits) {
  allocation_fault_injection::Reset();
  if (traits.custom_mutator == nullptr) {
    return 0;
  }
  return traits.custom_mutator(data, size, max_size, seed);
}

/// Cross two serialized generated profile messages of the same concrete type.
/// @param data1 Serialized first parent message.
/// @param size1 Number of bytes in `data1`.
/// @param data2 Serialized second parent message.
/// @param size2 Number of bytes in `data2`.
/// @param out Destination buffer for the crossed message.
/// @param max_out_size Capacity of `out`.
/// @param seed Deterministic crossover seed supplied by libFuzzer.
/// @param traits Generated profile binding for this executable.
/// @return Number of serialized bytes written to `out`.
std::size_t ProtoFuzzerCustomCrossOver(const std::uint8_t* data1, std::size_t size1, const std::uint8_t* data2,
                                       std::size_t size2, std::uint8_t* out, std::size_t max_out_size,
                                       unsigned int seed, const ProfileFuzzerTraits& traits) {
  allocation_fault_injection::Reset();
  if (traits.custom_crossover == nullptr) {
    return 0;
  }
  return traits.custom_crossover(data1, size1, data2, size2, out, max_out_size, seed);
}

/// Load and execute one generated-profile input under its fixed target lane.
/// @param data Serialized generated-profile input bytes.
/// @param size Number of bytes available at `data`.
/// @param traits Generated profile binding selected by the entrypoint.
/// @return Always zero, as required by the libFuzzer entrypoint contract.
int ProtoFuzzerTestOneInput(const std::uint8_t* data, std::size_t size, const ProfileFuzzerTraits& traits) {
  allocation_fault_injection::Reset();
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  ProbeMutationEntrypoints();
  if (traits.probe_mutation_helpers != nullptr) {
    traits.probe_mutation_helpers();
  }
#endif
  curl::fuzzer::proto::Scenario scenario;
  if (traits.load_input == nullptr || !traits.load_input(data, size, &scenario)) {
    return 0;
  }

  NormalizeScenarioForExecution(&scenario);
  allocation_fault_injection::Configure(scenario.fail_allocations().data(),
                                        static_cast<std::size_t>(scenario.fail_allocations_size()));
  allocation_fault_injection::Arm();
  proto_fuzzer::RunScenario(scenario, RunModeFor(traits.profile));
  allocation_fault_injection::Reset();
  if (traits.profile == TargetProfile::kResolver &&
      scenario.resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_GLOBAL_LIFECYCLE) {
    curl_global_cleanup();
    if (!allocation_fault_injection::ReinitializeCurl()) {
      std::fputs("warning: libcurl reinitialization failed\n", stderr);
      (void)curl_global_init(CURL_GLOBAL_ALL);
    }
  }
  return 0;
}

}  // namespace proto_fuzzer
