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

namespace proto_fuzzer {

/// Selects the invariants enforced after every LPM mutation. Separating these
/// lanes prevents rare clock-dependent inputs from consuming the mutation
/// budget intended for ordinary protocol parsing.
enum class TargetPolicy {
  /// Keep ordinary HTTP iterations cheap enough to compete with the legacy
  /// byte fuzzers. Stateful bodies, follow-on sockets, structured frames, and
  /// the more expensive option families live in kDeepHttp instead.
  kFastHttp,
  /// Exercise HTTP's complete structured surface without wall-clock waits.
  /// This is the coverage-preserving successor to the original kFastHttp
  /// policy: all request shapes and options remain mutation-controlled.
  kDeepHttp,
  /// Exercise HTTPS setup without wall-clock waits.
  kFastHttps,
  /// Exercise WebSocket framing without wall-clock waits.
  kFastWebSocket,
  /// Exercise secure WebSocket setup without wall-clock waits.
  kFastSecureWebSocket,
  /// Exercise TELNET negotiation with a preloaded peer and callback-backed
  /// input without permitting terminal or socket waits.
  kFastTelnet,
  /// Isolate deterministic backpressure and timed-wait behavior.
  kTiming,
};

/// Restore the invariants for one target after LPM mutates a Scenario.
/// Besides dispatch and timing controls, fixed lanes trim repeated-field and
/// metadata suffixes that the runtime cannot consume. WebSocket lanes also
/// remove follow-on sockets and MIME bodies their single-upgrade driver cannot
/// use; all remaining observable bytes, options, frames, and probes stay
/// fuzz-controlled.
/// @param scenario Scenario to canonicalize in place.
/// @param policy Target lane whose invariants must be restored.
void ApplyTargetPolicy(curl::fuzzer::proto::Scenario* scenario, TargetPolicy policy);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TARGET_POLICY_H_
