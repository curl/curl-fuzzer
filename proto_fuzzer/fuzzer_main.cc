/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared LPM mutation and execution for policy-split protobuf targets.

#include "proto_fuzzer/fuzzer_main.h"

#include <curl/curl.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include <csignal>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/scenario_runner.h"
#include "proto_fuzzer/target_policy.h"

namespace {

constexpr bool kUseBinaryFormat = true;

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

/// Mutate a binary Scenario through LPM. This symbol deliberately remains in
/// the shared implementation: mutation policy is identical within one binary,
/// while only the test entrypoint needs a unique source basename for static
/// coverage attribution.
/// @param data Mutable serialized Scenario storage.
/// @param size Current serialized size.
/// @param max_size Capacity of data.
/// @param seed Mutation random seed supplied by libFuzzer.
/// @return Serialized size after mutation.
extern "C" std::size_t LLVMFuzzerCustomMutator(std::uint8_t* data, std::size_t size, std::size_t max_size,
                                               unsigned int seed) {
  curl::fuzzer::proto::Scenario scenario;
  return protobuf_mutator::libfuzzer::CustomProtoMutator(kUseBinaryFormat, data, size, max_size, seed, &scenario);
}

/// Cross two binary Scenarios through LPM while preserving target policy.
/// @param data1 First serialized parent.
/// @param size1 Size of data1.
/// @param data2 Second serialized parent.
/// @param size2 Size of data2.
/// @param out Destination storage.
/// @param max_out_size Capacity of out.
/// @param seed Crossover random seed supplied by libFuzzer.
/// @return Serialized child size.
extern "C" std::size_t LLVMFuzzerCustomCrossOver(const std::uint8_t* data1, std::size_t size1,
                                                 const std::uint8_t* data2, std::size_t size2, std::uint8_t* out,
                                                 std::size_t max_out_size, unsigned int seed) {
  curl::fuzzer::proto::Scenario scenario1;
  curl::fuzzer::proto::Scenario scenario2;
  return protobuf_mutator::libfuzzer::CustomProtoCrossOver(kUseBinaryFormat, data1, size1, data2, size2, out,
                                                           max_out_size, seed, &scenario1, &scenario2);
}

namespace proto_fuzzer {

int ProtoFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  curl::fuzzer::proto::Scenario scenario;
  if (protobuf_mutator::libfuzzer::LoadProtoInput(kUseBinaryFormat, data, size, &scenario)) {
    ScenarioRunner().Run(scenario, kProbeTransferResults);
  }
  return 0;
}

}  // namespace proto_fuzzer
