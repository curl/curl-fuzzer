/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared execution for profile-split protobuf targets.

#include "proto_fuzzer/fuzzer_main.h"

#include <curl/curl.h>

#include <cstdio>

#include "proto_fuzzer/allocation_fault_injection.h"
#include "proto_fuzzer/curl_global_lifecycle.h"
#include "proto_fuzzer/scenario_runner.h"
#include "proto_fuzzer/target_policy.h"

namespace {

// libFuzzer reuses one process, so the static object initializes curl once and
// releases its global resolver/TLS state only after the engine has stopped.
proto_fuzzer::CurlGlobalLifecycle kGlobalBootstrap;

}  // namespace

namespace proto_fuzzer {

/// Load and execute one generated-profile input under its fixed target lane.
/// @param data Serialized generated-profile input bytes.
/// @param size Number of bytes available at `data`.
/// @param profile Mutation and execution policy selected by the entrypoint.
/// @param load_profile_input Typed bridge that owns profile parsing/lowering.
/// @return Always zero, as required by the libFuzzer entrypoint contract.
int ProtoFuzzerTestOneInput(const std::uint8_t* data, std::size_t size, TargetProfile profile,
                            ProfileInputLoader load_profile_input) {
  allocation_fault_injection::Reset();
  curl::fuzzer::proto::Scenario scenario;
  if (load_profile_input == nullptr || !load_profile_input(data, size, &scenario)) {
    return 0;
  }

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
  return 0;
}

}  // namespace proto_fuzzer
