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

/// Restore the invariants for one target after LPM mutates a Scenario.
/// Besides dispatch and timing controls, fixed lanes trim repeated-field and
/// metadata suffixes that the runtime cannot consume. WebSocket lanes also
/// remove follow-on sockets and MIME bodies their single-upgrade driver cannot
/// use; all remaining observable bytes, options, frames, and probes stay
/// fuzz-controlled.
/// @param scenario Scenario to canonicalize in place.
/// @param profile Target lane whose invariants must be restored.
void ApplyTargetPolicy(curl::fuzzer::proto::Scenario* scenario, TargetProfile profile);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TARGET_POLICY_H_
