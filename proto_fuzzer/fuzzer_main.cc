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

#include <cassert>
#include <csignal>
#include <cstdlib>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/option_apply.h"
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
        proto_fuzzer::ApplyTargetPolicy(scenario, registered_profile);
        proto_fuzzer::CanonicalizeOptionValueCases(scenario);
      });

  // A second profile in one process would cause LPM's global registry to
  // enforce the wrong lane. Real fuzz binaries cannot do this; keep the
  // assertion to make misuse by future in-process callers immediately clear.
  assert(profile == registered_profile);
  (void)policy_registration;
}

// Wire curl_global_init once so repeated fuzz iterations don't pay for it on every call. libFuzzer reuses the process;
// static ctors run once.
struct CurlGlobalBootstrap {
  CurlGlobalBootstrap() {
    // Open curl's TLS keylog at backend init. Curl_tls_keylog_open() runs once
    // inside curl_global_init, so setting this after bootstrap would be too
    // late. Keep the output in /dev/null and let a reproducer override it.
    (void)setenv("SSLKEYLOGFILE", "/dev/null", 0);

    // Keep parity with the legacy harness. libcurl normally suppresses
    // SIGPIPE for its own writes, but fuzzed connection lifecycles also race
    // mock-peer teardown; those failures should be reported as socket errors,
    // not mistaken for process crashes.
    std::signal(SIGPIPE, SIG_IGN);
    curl_global_init(CURL_GLOBAL_ALL);
  }
};
const CurlGlobalBootstrap kGlobalBootstrap;

}  // namespace

namespace proto_fuzzer {

std::size_t ProtoFuzzerCustomMutator(TargetProfile profile, std::uint8_t* data, std::size_t size, std::size_t max_size,
                                     unsigned int seed) {
  EnsureTargetPostProcessor(profile);
  curl::fuzzer::proto::Scenario scenario;
  return protobuf_mutator::libfuzzer::CustomProtoMutator(kUseBinaryFormat, data, size, max_size, seed, &scenario);
}

std::size_t ProtoFuzzerCustomCrossOver(TargetProfile profile, const std::uint8_t* data1, std::size_t size1,
                                       const std::uint8_t* data2, std::size_t size2, std::uint8_t* out,
                                       std::size_t max_out_size, unsigned int seed) {
  EnsureTargetPostProcessor(profile);
  curl::fuzzer::proto::Scenario scenario1;
  curl::fuzzer::proto::Scenario scenario2;
  return protobuf_mutator::libfuzzer::CustomProtoCrossOver(kUseBinaryFormat, data1, size1, data2, size2, out,
                                                           max_out_size, seed, &scenario1, &scenario2);
}

int ProtoFuzzerTestOneInput(TargetProfile profile, const std::uint8_t* data, std::size_t size) {
  EnsureTargetPostProcessor(profile);
  curl::fuzzer::proto::Scenario scenario;
  if (protobuf_mutator::libfuzzer::LoadProtoInput(kUseBinaryFormat, data, size, &scenario)) {
    ScenarioRunner().Run(scenario, RunModeFor(profile));
  }
  return 0;
}

}  // namespace proto_fuzzer
