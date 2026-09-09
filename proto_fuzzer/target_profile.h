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
  /// Exercise raw HTTP/2 origin frames after a verified TLS/ALPN handshake.
  kHttpsH2,
  /// Exercise HTTP/3 over a valid in-process QUIC/TLS connection.
  kFastHttp3,
  /// Exercise an HTTP/1.1 origin through an HTTPS/HTTP2 CONNECT proxy.
  kH2Proxy,
  /// Exercise HTTP through an in-process SOCKS4/SOCKS4A proxy.
  kSocks4,
  /// Exercise localhost lookup and structured CURLOPT_RESOLVE host-cache work.
  kResolver,
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
  /// Exercise Gopher selectors through the bounded stream peer.
  kFastGopher,
  /// Exercise easy, share, multi, URL, and result API lifecycles.
  kApi,
  /// Exercise several easy handles through one shared multi handle.
  kMulti,
  /// Isolate deterministic backpressure and timed-wait behavior.
  kTiming,
};

/// Selects one of the complete, valid RunScenario behaviours. Keeping this
/// closed set avoids boolean combinations that have no useful interpretation.
enum class ScenarioRunMode {
  /// Drive the protocol without charging its hot loop for generic API probes.
  kFastProtocol,
  /// Drive the protocol and inspect a compact set of public result APIs.
  kProtocolCoverage,
  /// Drive deep HTTP plus its bounded filename-backed parser inputs.
  kDeepHttpCoverage,
  /// Drive HTTPS through a real TLS peer and inspect live TLS result state.
  kTlsCoverage,
  /// Drive an HTTPS origin through fixed ALPN h2 with push/upkeep probes.
  kTlsHttp2Coverage,
  /// Drive ordered plaintext HTTP/3 actions through the QUIC peer.
  kHttp3Coverage,
  /// Drive raw HTTP/2 proxy frames around one CONNECT tunnel.
  kH2ProxyCoverage,
  /// Drive a request-triggered SOCKS4 reply followed by tunneled HTTP.
  kSocks4Coverage,
  /// Let curl resolve the origin while the socket callback still owns I/O.
  kResolverCoverage,
  /// Drive FTP through its concurrent control/passive-data peer.
  kFtpCoverage,
  /// Drive TFTP through its datagram-preserving loopback peer.
  kTftpCoverage,
  /// Drive Gopher through the bounded stream peer.
  kGopherCoverage,
  /// Honour ApiPlan and run the dedicated lifecycle and typed-result probes.
  kApiLifecycle,
  /// Honour MultiPlan and drive several HTTP transfers through one multi.
  kMultiTransfer,
};

/// Derive runtime behaviour from the compiled target identity. Mutation policy
/// remains profile-specific, while targets that need the same execution cost
/// deliberately share a run mode.
/// @param profile Compiled target whose runner behaviour is required.
/// @return The only RunScenario mode valid for that target.
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

    case TargetProfile::kHttpsH2:
      return ScenarioRunMode::kTlsHttp2Coverage;

    case TargetProfile::kFastHttp3:
      return ScenarioRunMode::kHttp3Coverage;

    case TargetProfile::kH2Proxy:
      return ScenarioRunMode::kH2ProxyCoverage;

    case TargetProfile::kSocks4:
      return ScenarioRunMode::kSocks4Coverage;

    case TargetProfile::kResolver:
      return ScenarioRunMode::kResolverCoverage;

    case TargetProfile::kFastFtp:
      return ScenarioRunMode::kFtpCoverage;

    case TargetProfile::kFastTftp:
      return ScenarioRunMode::kTftpCoverage;

    case TargetProfile::kFastGopher:
      return ScenarioRunMode::kGopherCoverage;

    case TargetProfile::kCompatibility:
    case TargetProfile::kFastWebSocket:
    case TargetProfile::kFastSecureWebSocket:
    case TargetProfile::kTiming:
      return ScenarioRunMode::kProtocolCoverage;

    case TargetProfile::kDeepHttp:
      return ScenarioRunMode::kDeepHttpCoverage;
  }
  return ScenarioRunMode::kProtocolCoverage;
}

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TARGET_PROFILE_H_
