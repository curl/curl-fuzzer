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

/// Execute one generated-profile input after its direct lowering step.
/// @param profile Mutation and execution policy selected by the entrypoint.
/// @param scenario Owned internal runtime state; nullptr is ignored.
void ExecuteProfileScenario(TargetProfile profile, curl::fuzzer::proto::Scenario* scenario) {
  if (scenario == nullptr) {
    return;
  }
  NormalizeScenarioForExecution(scenario);
  allocation_fault_injection::Configure(scenario->fail_allocations().data(),
                                        static_cast<std::size_t>(scenario->fail_allocations_size()));
  allocation_fault_injection::Arm();
  proto_fuzzer::RunScenario(*scenario, RunModeFor(profile));
  allocation_fault_injection::Reset();
  if (profile == TargetProfile::kResolver &&
      scenario->resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_GLOBAL_LIFECYCLE) {
    curl_global_cleanup();
    if (!allocation_fault_injection::ReinitializeCurl()) {
      std::fputs("warning: libcurl reinitialization failed\n", stderr);
      (void)curl_global_init(CURL_GLOBAL_ALL);
    }
  }
}

}  // namespace proto_fuzzer
