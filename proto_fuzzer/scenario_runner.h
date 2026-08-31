/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief ScenarioRunner — orchestrates a single fuzz iteration from a
///        Scenario proto through to a completed curl transfer.

#ifndef PROTO_FUZZER_SCENARIO_RUNNER_H_
#define PROTO_FUZZER_SCENARIO_RUNNER_H_

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/target_profile.h"

namespace proto_fuzzer {

class ScenarioRunner {
 public:
  ScenarioRunner();
  ~ScenarioRunner();

  ScenarioRunner(const ScenarioRunner&) = delete;
  ScenarioRunner& operator=(const ScenarioRunner&) = delete;

  /// Execute one scenario under a complete target behaviour. An enum makes
  /// the supported fast, coverage, and API paths explicit and prevents callers
  /// from constructing meaningless combinations of independent switches.
  /// @param scenario Structured transfer and optional API plan.
  /// @param mode Runtime coverage and lifecycle policy for this invocation.
  /// @return zero after either a bounded run or an ignored invalid scenario.
  int Run(const curl::fuzzer::proto::Scenario& scenario, ScenarioRunMode mode);
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_SCENARIO_RUNNER_H_
