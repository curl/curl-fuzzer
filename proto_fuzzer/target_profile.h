/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Compile-time identities and execution modes for proto fuzz targets.

#ifndef PROTO_FUZZER_TARGET_PROFILE_H_
#define PROTO_FUZZER_TARGET_PROFILE_H_

namespace proto_fuzzer {

/// Identifies one compiled proto-fuzzer lane. A profile is the single source
/// of truth for both mutation constraints and runtime coverage policy, which
/// prevents independent flags from describing combinations no target uses.
enum class TargetProfile {
  /// Preserve the original mixed target and its accumulated corpus exactly.
  kCompatibility,
  /// Keep ordinary HTTP iterations competitive with the legacy byte fuzzers.
  kFastHttp,
  /// Retain HTTP's complete structured request and response surface.
  kDeepHttp,
  /// Exercise a complete HTTPS exchange against the in-process TLS peer.
  kFastHttps,
  /// Exercise plaintext WebSocket framing without wall-clock waits.
  kFastWebSocket,
  /// Exercise secure WebSocket setup without wall-clock waits.
  kFastSecureWebSocket,
  /// Exercise bounded TELNET negotiation and callback-backed input.
  kFastTelnet,
  /// Exercise easy, share, multi, URL, and result API lifecycles.
  kApi,
  /// Isolate deterministic backpressure and timed-wait behavior.
  kTiming,
};

/// Selects one of the complete, valid ScenarioRunner behaviours. Keeping this
/// closed set avoids boolean combinations that have no useful interpretation.
enum class ScenarioRunMode {
  /// Drive the protocol without charging its hot loop for generic API probes.
  kFastProtocol,
  /// Drive the protocol and inspect a compact set of public result APIs.
  kProtocolCoverage,
  /// Drive HTTPS through a real TLS peer and inspect live TLS result state.
  kTlsCoverage,
  /// Honour ApiPlan and run the dedicated lifecycle and typed-result probes.
  kApiLifecycle,
};

/// Derive runtime behaviour from the compiled target identity. Mutation policy
/// remains profile-specific, while targets that need the same execution cost
/// deliberately share a run mode.
/// @param profile Compiled target whose runner behaviour is required.
/// @return The only ScenarioRunner mode valid for that target.
constexpr ScenarioRunMode RunModeFor(TargetProfile profile) {
  switch (profile) {
    case TargetProfile::kFastHttp:
    case TargetProfile::kFastTelnet:
      return ScenarioRunMode::kFastProtocol;

    case TargetProfile::kApi:
      return ScenarioRunMode::kApiLifecycle;

    case TargetProfile::kFastHttps:
      return ScenarioRunMode::kTlsCoverage;

    case TargetProfile::kCompatibility:
    case TargetProfile::kDeepHttp:
    case TargetProfile::kFastWebSocket:
    case TargetProfile::kFastSecureWebSocket:
    case TargetProfile::kTiming:
      return ScenarioRunMode::kProtocolCoverage;
  }
  return ScenarioRunMode::kProtocolCoverage;
}

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TARGET_PROFILE_H_
