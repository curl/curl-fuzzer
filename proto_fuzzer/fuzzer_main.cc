/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared LPM mutation and execution for profile-split protobuf targets.

#include "proto_fuzzer/fuzzer_main.h"

#include <curl/curl.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include <array>
#include <cassert>
#include <cstdio>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/allocation_fault_injection.h"
#include "proto_fuzzer/curl_global_lifecycle.h"
#include "proto_fuzzer/scenario_runner.h"
#include "proto_fuzzer/target_policy.h"

namespace {

constexpr bool kUseBinaryFormat = true;

/// Register the fixed lane's normalizer before asking LPM to parse or mutate
/// its first input. LoadProtoInput runs LPM's Fix() only for direct corpus
/// loads; a just-mutated input is recovered from LPM's cache and has already
/// passed the same postprocessor. Ordering the registration here therefore
/// covers both paths without normalizing cached mutations twice.
///
/// One libFuzzer process exposes exactly one entrypoint and therefore one
/// profile. Capturing the first profile lets the shared runtime use LPM's
/// process-wide postprocessor registry without hiding target selection in a
/// compiler definition. The compatibility target deliberately registers
/// nothing, preserving its historical mixed-corpus mutation semantics.
void EnsureTargetPostProcessor(proto_fuzzer::TargetProfile profile) {
  if (profile == proto_fuzzer::TargetProfile::kCompatibility) {
    return;
  }

  static const proto_fuzzer::TargetProfile registered_profile = profile;
  static const protobuf_mutator::libfuzzer::PostProcessorRegistration<curl::fuzzer::proto::Scenario>
      policy_registration([](curl::fuzzer::proto::Scenario* scenario, unsigned int /*seed*/) {
        proto_fuzzer::NormalizeScenarioForTarget(scenario, registered_profile);
      });

  // A second profile in one process would cause LPM's global registry to
  // enforce the wrong lane. Real fuzz binaries cannot do this; keep the
  // assertion to make misuse by future in-process callers immediately clear.
  assert(profile == registered_profile);
  (void)policy_registration;
}

// libFuzzer reuses one process, so the static object initializes curl once and
// releases its global resolver/TLS state only after the engine has stopped.
proto_fuzzer::CurlGlobalLifecycle kGlobalBootstrap;

#if defined(PROTO_FUZZER_OBSERVE_STATE)
/// Exercise the mutation ABI once in the profiling-only timing lane. Corpus
/// replay invokes test inputs but does not ask libFuzzer to mutate or cross
/// them, leaving the two target hooks invisible to coverage and introspection.
/// A fixed, bounded Scenario keeps the probe deterministic and also checks the
/// timing policy's follow-on backpressure normalization without executing the
/// generated children.
void ProbeTimingMutationHelpers() {
  constexpr std::size_t kBufferSize = 1024;
  constexpr unsigned int kMutationSeed = 0x4355524cU;

  curl::fuzzer::proto::Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("timing.test/profile");
  scenario.mutable_connection();
  scenario.add_subsequent_connections()->mutable_backpressure()->set_drain_limit(1);
  proto_fuzzer::NormalizeScenarioForTarget(&scenario, proto_fuzzer::TargetProfile::kTiming);

  std::array<std::uint8_t, kBufferSize> first = {};
  const std::size_t original_size = scenario.ByteSizeLong();
  (void)scenario.SerializeWithCachedSizesToArray(first.data());

  std::array<std::uint8_t, kBufferSize> second = first;
  std::array<std::uint8_t, kBufferSize> child = {};
  const std::size_t mutated_size = proto_fuzzer::ProtoFuzzerCustomMutator(
      proto_fuzzer::TargetProfile::kTiming, first.data(), original_size, first.size(), kMutationSeed);
  const std::size_t crossed_size =
      proto_fuzzer::ProtoFuzzerCustomCrossOver(proto_fuzzer::TargetProfile::kTiming, first.data(), mutated_size,
                                               second.data(), original_size, child.data(), child.size(), kMutationSeed);
  const volatile std::size_t result_sizes[] = {mutated_size, crossed_size};
  (void)result_sizes;
}
#endif

}  // namespace

namespace proto_fuzzer {

/// Mutate a serialized Scenario while preserving the selected lane's policy.
/// @param profile Mutation and execution policy selected by the entrypoint.
/// @param data Mutable serialized Scenario storage.
/// @param size Current serialized size.
/// @param max_size Capacity of data.
/// @param seed Mutation random seed supplied by libFuzzer.
/// @return Serialized size after mutation.
std::size_t ProtoFuzzerCustomMutator(TargetProfile profile, std::uint8_t* data, std::size_t size, std::size_t max_size,
                                     unsigned int seed) {
  allocation_fault_injection::Reset();
  EnsureTargetPostProcessor(profile);
  curl::fuzzer::proto::Scenario scenario;
  return protobuf_mutator::libfuzzer::CustomProtoMutator(kUseBinaryFormat, data, size, max_size, seed, &scenario);
}

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
                                       std::size_t max_out_size, unsigned int seed) {
  allocation_fault_injection::Reset();
  EnsureTargetPostProcessor(profile);
  curl::fuzzer::proto::Scenario scenario1;
  curl::fuzzer::proto::Scenario scenario2;
  return protobuf_mutator::libfuzzer::CustomProtoCrossOver(kUseBinaryFormat, data1, size1, data2, size2, out,
                                                           max_out_size, seed, &scenario1, &scenario2);
}

/// Decode and run one serialized Scenario. Keeping this behind an ordinary
/// function allows each binary to expose a discoverable, same-named libFuzzer
/// entrypoint while retaining one mutation and execution implementation. The
/// profile is explicit so target identity remains visible at the entrypoint
/// instead of being hidden in per-translation-unit compiler definitions.
/// @param profile Mutation and execution policy selected by the entrypoint.
/// @param data Serialized binary Scenario bytes.
/// @param size Number of bytes available at data.
/// @return Always zero, as required by libFuzzer.
int ProtoFuzzerTestOneInput(TargetProfile profile, const std::uint8_t* data, std::size_t size) {
  allocation_fault_injection::Reset();
  EnsureTargetPostProcessor(profile);
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  if (profile == TargetProfile::kTiming) {
    static const bool mutation_helpers_probed = [] {
      ProbeTimingMutationHelpers();
      return true;
    }();
    (void)mutation_helpers_probed;
  }
#endif
  curl::fuzzer::proto::Scenario scenario;
  if (protobuf_mutator::libfuzzer::LoadProtoInput(kUseBinaryFormat, data, size, &scenario)) {
    NormalizeScenarioForExecution(&scenario);
    allocation_fault_injection::Configure(scenario.fail_allocations().data(),
                                          static_cast<std::size_t>(scenario.fail_allocations_size()));
    allocation_fault_injection::Arm();
    proto_fuzzer::RunScenario(scenario, RunModeFor(profile));
    allocation_fault_injection::Reset();
    if (profile == TargetProfile::kResolver &&
        scenario.resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_GLOBAL_LIFECYCLE) {
      curl_global_cleanup();
      if (!allocation_fault_injection::ReinitializeCurl()) {
        std::fputs("warning: libcurl reinitialization failed\n", stderr);
        (void)curl_global_init(CURL_GLOBAL_ALL);
      }
    }
  }
  return 0;
}

}  // namespace proto_fuzzer
