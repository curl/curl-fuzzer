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

namespace proto_fuzzer {

class ScenarioRunner {
 public:
  ScenarioRunner();
  ~ScenarioRunner();

  ScenarioRunner(const ScenarioRunner&) = delete;
  ScenarioRunner& operator=(const ScenarioRunner&) = delete;

  int Run(const curl::fuzzer::proto::Scenario& scenario);
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_SCENARIO_RUNNER_H_
