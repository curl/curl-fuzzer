/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Mutation policies that keep each proto fuzzer in one intentional
///        performance and protocol lane.

#ifndef PROTO_FUZZER_TARGET_POLICY_H_
#define PROTO_FUZZER_TARGET_POLICY_H_

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/target_profile.h"

namespace proto_fuzzer {

void NormalizeScenarioForTarget(curl::fuzzer::proto::Scenario* scenario, TargetProfile profile);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TARGET_POLICY_H_
