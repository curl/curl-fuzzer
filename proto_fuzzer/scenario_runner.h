/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Orchestrates a single fuzz iteration from a Scenario proto through
///        to a completed curl transfer.

#ifndef PROTO_FUZZER_SCENARIO_RUNNER_H_
#define PROTO_FUZZER_SCENARIO_RUNNER_H_

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/target_profile.h"

namespace proto_fuzzer {

int RunScenario(const curl::fuzzer::proto::Scenario& scenario, ScenarioRunMode mode);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_SCENARIO_RUNNER_H_
