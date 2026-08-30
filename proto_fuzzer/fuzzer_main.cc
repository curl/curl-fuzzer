/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared libFuzzer entrypoint for the policy-split protobuf targets.
///        Wires each binary's LPM policy to ScenarioRunner::Run.

#include <curl/curl.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include <csignal>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/scenario_runner.h"
#include "proto_fuzzer/target_policy.h"

namespace {

#if defined(PROTO_FUZZER_TARGET_COMPATIBILITY)
// The original target deliberately has no policy. Its OSS-Fuzz corpus and
// regression testcases contain mixed schemes and timing controls whose exact
// semantics must remain stable across the target split.
#elif defined(PROTO_FUZZER_TARGET_FAST_HTTP)
constexpr proto_fuzzer::TargetPolicy kTargetPolicy = proto_fuzzer::TargetPolicy::kFastHttp;
#elif defined(PROTO_FUZZER_TARGET_DEEP_HTTP)
constexpr proto_fuzzer::TargetPolicy kTargetPolicy = proto_fuzzer::TargetPolicy::kDeepHttp;
#elif defined(PROTO_FUZZER_TARGET_FAST_HTTPS)
constexpr proto_fuzzer::TargetPolicy kTargetPolicy = proto_fuzzer::TargetPolicy::kFastHttps;
#elif defined(PROTO_FUZZER_TARGET_FAST_WEBSOCKET)
constexpr proto_fuzzer::TargetPolicy kTargetPolicy = proto_fuzzer::TargetPolicy::kFastWebSocket;
#elif defined(PROTO_FUZZER_TARGET_FAST_SECURE_WEBSOCKET)
constexpr proto_fuzzer::TargetPolicy kTargetPolicy = proto_fuzzer::TargetPolicy::kFastSecureWebSocket;
#elif defined(PROTO_FUZZER_TARGET_FAST_TELNET)
constexpr proto_fuzzer::TargetPolicy kTargetPolicy = proto_fuzzer::TargetPolicy::kFastTelnet;
#elif defined(PROTO_FUZZER_TARGET_TIMING)
constexpr proto_fuzzer::TargetPolicy kTargetPolicy = proto_fuzzer::TargetPolicy::kTiming;
#else
#error "A proto fuzzer target policy must be selected"
#endif

// The fast HTTP and TELNET binaries trade generic post-transfer getinfo/header
// probes for throughput. Every other compiled lane retains them, so aggregate
// coverage does not charge every HTTP or TELNET mutation for those APIs.
#if defined(PROTO_FUZZER_TARGET_FAST_HTTP) || defined(PROTO_FUZZER_TARGET_FAST_TELNET)
constexpr bool kProbeTransferResults = false;
#else
constexpr bool kProbeTransferResults = true;
#endif

#if !defined(PROTO_FUZZER_TARGET_COMPATIBILITY)
/// Restore the target's protocol and timing invariants after every mutation.
/// Registering this during static initialization matters: corpus inputs pass
/// through LPM's Fix() before the first fuzz callback, so a function-local
/// registration would let the first input bypass the target policy.
void PostProcessScenario(curl::fuzzer::proto::Scenario* scenario, unsigned int /*seed*/) {
  proto_fuzzer::ApplyTargetPolicy(scenario, kTargetPolicy);
  proto_fuzzer::CanonicalizeOptionValueCases(scenario);
}

const protobuf_mutator::libfuzzer::PostProcessorRegistration<curl::fuzzer::proto::Scenario> kPolicyRegistration(
    &PostProcessScenario);
#endif

// Wire curl_global_init once so repeated fuzz iterations don't pay for it on every call. libFuzzer reuses the process;
// static ctors run once.
struct CurlGlobalBootstrap {
  CurlGlobalBootstrap() {
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

/// @brief libFuzzer entry point. libFuzzer will call this function with a valid Scenario protobuf message on each
/// fuzzing iteration. The function is expected to run the scenario and return. Any crashes or undefined behavior during
/// scenario execution will be reported by libFuzzer as fuzzing bugs.
/// @param scenario The Scenario describing the curl operations to perform.
DEFINE_BINARY_PROTO_FUZZER(const curl::fuzzer::proto::Scenario& scenario) {
  proto_fuzzer::ScenarioRunner().Run(scenario, kProbeTransferResults);
}
