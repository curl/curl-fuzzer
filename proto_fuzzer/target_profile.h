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
  /// Exercise HTTP/3 over a valid in-process QUIC/TLS connection.
  kFastHttp3,
  /// Exercise an HTTP/1.1 origin through an HTTPS/HTTP2 CONNECT proxy.
  kH2Proxy,
  /// Exercise plaintext WebSocket framing without wall-clock waits.
  kFastWebSocket,
  /// Exercise secure WebSocket setup without wall-clock waits.
  kFastSecureWebSocket,
  /// Exercise bounded TELNET negotiation and callback-backed input.
  kFastTelnet,
  /// Exercise FTP control and passive data connections without external I/O.
  kFastFtp,
  /// Exercise packet-preserving TFTP exchanges over the loopback UDP peer.
  kFastTftp,
  /// Exercise easy, share, multi, URL, and result API lifecycles.
  kApi,
  /// Exercise several easy handles through one shared multi handle.
  kMulti,
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
  /// Drive ordered plaintext HTTP/3 actions through the QUIC peer.
  kHttp3Coverage,
  /// Drive raw HTTP/2 proxy frames around one CONNECT tunnel.
  kH2ProxyCoverage,
  /// Drive FTP through its concurrent control/passive-data peer.
  kFtpCoverage,
  /// Drive TFTP through its datagram-preserving loopback peer.
  kTftpCoverage,
  /// Honour ApiPlan and run the dedicated lifecycle and typed-result probes.
  kApiLifecycle,
  /// Honour MultiPlan and drive several HTTP transfers through one multi.
  kMultiTransfer,
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

    case TargetProfile::kMulti:
      return ScenarioRunMode::kMultiTransfer;

    case TargetProfile::kFastHttps:
      return ScenarioRunMode::kTlsCoverage;

    case TargetProfile::kFastHttp3:
      return ScenarioRunMode::kHttp3Coverage;

    case TargetProfile::kH2Proxy:
      return ScenarioRunMode::kH2ProxyCoverage;

    case TargetProfile::kFastFtp:
      return ScenarioRunMode::kFtpCoverage;

    case TargetProfile::kFastTftp:
      return ScenarioRunMode::kTftpCoverage;

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
