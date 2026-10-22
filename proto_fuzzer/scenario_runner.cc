/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of RunScenario.

#include "proto_fuzzer/scenario_runner.h"

#include <curl/curl.h>
#include <curl/header.h>

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/api_lifecycle.h"
#include "proto_fuzzer/ftp_mock_server.h"
#include "proto_fuzzer/h2_cleartext_mock_server.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/multi_transfer_runner.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/socks4_mock_server.h"
#include "proto_fuzzer/telnet_mock_server.h"
#include "proto_fuzzer/tftp_mock_server.h"
#include "proto_fuzzer/transfer_session.h"
#include "proto_fuzzer/websocket_mock_server.h"

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
#include "proto_fuzzer/h2_origin_mock_server.h"
#include "proto_fuzzer/h2_proxy_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"
#include "proto_fuzzer/tls_websocket_mock_server.h"
#endif
#if defined(PROTO_FUZZER_HAS_HTTP3_MOCK_SERVER)
#include "proto_fuzzer/connect_udp_proxy_mock_server.h"
#include "proto_fuzzer/http3_mock_server.h"
#endif

namespace proto_fuzzer {

namespace {

constexpr unsigned int kAllHeaderOrigins = CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX | CURLH_PSEUDO;
constexpr std::size_t kMaxResultHeaders = 16;
/// Probe each public getinfo return family and the response-header API after
/// curl has settled the transfer. Applications commonly inspect these APIs,
/// but a harness that only drives I/O leaves their type dispatch and
/// post-transfer state unexecuted even when the corresponding parser ran.
/// The chosen values are handle-owned or scalar: notably CERTINFO exercises
/// the pointer/slist dispatch family without materialising a separately-owned
/// cookie/engine list. Header iteration is capped independently of response
/// size so this unconditional coverage cannot dominate a fuzz iteration.
void ProbeTransferResults(CURL* easy) {
  char* string_result = nullptr;
  long long_result = 0;
  double double_result = 0;
  curl_off_t offset_result = 0;
  curl_socket_t socket_result = CURL_SOCKET_BAD;
  struct curl_certinfo* certinfo_result = nullptr;

  (void)curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &string_result);
  (void)curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &long_result);
  (void)curl_easy_getinfo(easy, CURLINFO_TOTAL_TIME, &double_result);
  (void)curl_easy_getinfo(easy, CURLINFO_SIZE_DOWNLOAD_T, &offset_result);
  (void)curl_easy_getinfo(easy, CURLINFO_ACTIVESOCKET, &socket_result);
  (void)curl_easy_getinfo(easy, CURLINFO_CERTINFO, &certinfo_result);

  struct curl_header* header = nullptr;
  (void)curl_easy_header(easy, "Content-Type", 0, kAllHeaderOrigins, -1, &header);
  header = nullptr;
  for (std::size_t index = 0; index < kMaxResultHeaders; ++index) {
    header = curl_easy_nextheader(easy, kAllHeaderOrigins, -1, header);
    if (header == nullptr) {
      break;
    }
  }
}

/// Map a Scheme enum to the URL scheme literal.
const char* SchemePrefix(curl::fuzzer::proto::Scheme scheme) {
  switch (scheme) {
    case curl::fuzzer::proto::SCHEME_HTTP:
      return "http";
    case curl::fuzzer::proto::SCHEME_HTTPS:
      return "https";
    case curl::fuzzer::proto::SCHEME_WS:
      return "ws";
    case curl::fuzzer::proto::SCHEME_WSS:
      return "wss";
    case curl::fuzzer::proto::SCHEME_TELNET:
      return "telnet";
    case curl::fuzzer::proto::SCHEME_FTP:
      return "ftp";
    case curl::fuzzer::proto::SCHEME_TFTP:
      return "tftp";
    case curl::fuzzer::proto::SCHEME_GOPHER:
      return "gopher";
    case curl::fuzzer::proto::SCHEME_GOPHERS:
      return "gophers";
    case curl::fuzzer::proto::SCHEME_UNSPECIFIED:
    default:
      return nullptr;
  }
}

/// Pick the peer implementation authorized by both protocol and target mode.
/// The compatibility target must keep its historical raw-wire interpretation
/// of secure schemes, while dedicated TLS lanes expose decrypted application
/// protocols. Keeping that semantic boundary in the closed run-mode enum
/// prevents a new peer from silently changing old OSS-Fuzz reproducers.
std::unique_ptr<MockServerBase> MakeMockServerForScenario(const curl::fuzzer::proto::Scenario& scenario,
                                                          ScenarioRunMode mode) {
  if (mode == ScenarioRunMode::kHttp3Coverage) {
#if defined(PROTO_FUZZER_HAS_HTTP3_MOCK_SERVER)
    if (scenario.http3_plan().use_h1_connect_udp_proxy()) {
      return std::make_unique<ConnectUdpProxyMockServer>();
    }
    return std::make_unique<Http3MockServer>(scenario.tls_certificate_chain());
#else
    return nullptr;
#endif
  }

  if (mode == ScenarioRunMode::kH2ProxyCoverage) {
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
    return std::make_unique<H2ProxyMockServer>();
#else
    // MemorySanitizer builds deliberately omit OpenSSL. Keep the target
    // binary available to OSS-Fuzz, but do not pretend a plaintext mock can
    // negotiate the ALPN gate required to enter cf-h2-proxy.
    return nullptr;
#endif
  }

  if (mode == ScenarioRunMode::kHttp2Coverage) {
    return std::make_unique<H2CleartextMockServer>();
  }

  if (mode == ScenarioRunMode::kTlsHttp2Coverage) {
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
    return std::make_unique<H2OriginMockServer>(scenario.tls_certificate_chain(), scenario.tls_group_profile());
#else
    // This target remains buildable under MemorySanitizer, whose curl build
    // omits the OpenSSL server dependency required for TLS/ALPN h2.
    return nullptr;
#endif
  }

  if (mode == ScenarioRunMode::kSocks4Coverage) {
    return std::make_unique<Socks4MockServer>(scenario.socks_proxy_mode());
  }

  switch (scenario.scheme()) {
    case curl::fuzzer::proto::SCHEME_HTTP:
      if (mode == ScenarioRunMode::kApiLifecycle) {
        return std::make_unique<MockServer>(MultiDrivePolicy::kFromApiPlan);
      }
      return std::make_unique<MockServer>();
    case curl::fuzzer::proto::SCHEME_HTTPS:
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kTlsCoverage) {
        return std::make_unique<TlsMockServer>(scenario.tls_certificate_chain());
      }
#else
      (void)mode;
#endif
      return std::make_unique<MockServer>();
    case curl::fuzzer::proto::SCHEME_GOPHER:
      return mode == ScenarioRunMode::kGopherCoverage ? std::make_unique<MockServer>() : nullptr;
    case curl::fuzzer::proto::SCHEME_GOPHERS:
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kGopherCoverage) {
        return std::make_unique<TlsMockServer>(scenario.tls_certificate_chain());
      }
      return nullptr;
#else
      return nullptr;
#endif
    case curl::fuzzer::proto::SCHEME_WS:
      return std::make_unique<WebSocketMockServer>();
    case curl::fuzzer::proto::SCHEME_WSS:
      if (mode == ScenarioRunMode::kTlsWebSocketCoverage) {
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
        return std::make_unique<TlsWebSocketMockServer>(scenario.tls_certificate_chain());
#else
        // MemorySanitizer builds deliberately omit OpenSSL. Keep the target
        // available without pretending plaintext can carry a WSS exchange.
        return nullptr;
#endif
      }
      // Preserve the compatibility target's historical interpretation of WSS
      // inputs, which exposed TLS bytes directly to the plaintext WS peer.
      return std::make_unique<WebSocketMockServer>();
    case curl::fuzzer::proto::SCHEME_TELNET:
      return std::make_unique<TelnetMockServer>();
    case curl::fuzzer::proto::SCHEME_FTP:
      // New numeric enum values may already occur in the historical mixed
      // corpus as unknown fields. Only the fixed FTP profile may reinterpret
      // one as a live two-channel protocol exchange.
      if (mode == ScenarioRunMode::kFtpCoverage) {
        return std::make_unique<FtpMockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_TFTP:
      // TFTP changes the callback transport from a preconnected stream to a
      // real UDP endpoint, so compatibility inputs must not opt into it merely
      // because this build learned a new enum value.
      if (mode == ScenarioRunMode::kTftpCoverage) {
        return std::make_unique<TftpMockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_UNSPECIFIED:
    default:
      return nullptr;
  }
}

#if defined(PROTO_FUZZER_OBSERVE_STATE)
/// Retain protocol-specific outcomes in coverage and introspector builds.
/// These peers already collect bounded state for focused tests; reading it
/// after the transfer gives profiling builds visibility into the completed
/// exchange without changing the protocol work performed by ordinary fuzzers.
void ObserveProtocolPeerState(MockServerBase* mock) {
  if (auto* ftp = dynamic_cast<FtpMockServer*>(mock)) {
    const volatile std::size_t ftp_observation[] = {ftp->control_transcript().size(), ftp->uploaded_data().size(),
                                                    ftp->opened_data_connection_count()};
    (void)ftp_observation;
  }

  if (auto* tftp = dynamic_cast<TftpMockServer*>(mock)) {
    const volatile std::size_t tftp_observation[] = {tftp->received_datagrams().size(), tftp->request_port(),
                                                     tftp->transfer_port()};
    (void)tftp_observation;
  }

  if (auto* websocket = dynamic_cast<WebSocketMockServer*>(mock)) {
    const volatile std::size_t websocket_observation = websocket->manual_received_bytes();
    (void)websocket_observation;
  }

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
  if (auto* websocket = dynamic_cast<TlsWebSocketMockServer*>(mock)) {
    const volatile std::size_t tls_websocket_observation = websocket->completed_handshake_count();
    (void)tls_websocket_observation;
  }
#endif

#if defined(PROTO_FUZZER_HAS_HTTP3_MOCK_SERVER)
  if (auto* http3 = dynamic_cast<Http3MockServer*>(mock)) {
    const volatile std::size_t http3_observation[] = {http3->handshake_complete(), http3->request_headers_received(),
                                                      http3->executed_action_count(), http3->server_port()};
    (void)http3_observation;
  }
#endif
}
#endif

}  // namespace

/// Execute one scenario under a complete target behaviour. An enum makes the
/// supported fast, coverage, and API paths explicit and prevents callers from
/// constructing meaningless combinations of independent switches.
/// @param scenario Structured transfer and optional API plan.
/// @param mode Runtime coverage and lifecycle policy for this invocation.
/// @return zero after either a bounded run or an ignored invalid scenario.
int RunScenario(const curl::fuzzer::proto::Scenario& scenario, ScenarioRunMode mode) {
  // Every input starts from a known off trace baseline (and returns to it when
  // the scope exits), so one input's trace selection cannot leak into another.
  proto_fuzzer::ScopedTraceReset trace_reset;

  if (mode == ScenarioRunMode::kMultiTransfer) {
    (void)proto_fuzzer::RunMultiTransferScenario(scenario);
    return 0;
  }

  const char* prefix = SchemePrefix(scenario.scheme());
  if (prefix == nullptr || scenario.host_path().empty()) {
    return 0;
  }

  std::unique_ptr<MockServerBase> mock = MakeMockServerForScenario(scenario, mode);
  if (!mock) {
    return 0;
  }

  // The peer survives every easy option/callback, including cleanup of a
  // bounded incomplete transfer. TransferSession owns the rest of that graph.
  TransferSession transfer;
  (void)transfer.PrepareInputFiles(scenario, mode);
  if (!transfer.Initialize()) {
    return 0;
  }
  CURL* easy = transfer.easy();
  const std::string url = std::string(prefix) + "://" + scenario.host_path();
  const auto configure_easy = [&] {
    transfer.ApplyBaseline(scenario);
    (void)curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
    mock->Install(easy);
    transfer.ApplyInputFiles();
    // Repeat the option-count bound for compatibility and direct callers.
    (void)ApplyScenarioOptions(easy, scenario);
  };
  configure_easy();
  transfer.ConfigureAltSvcRouting(scenario.host_path());

  if (mode == ScenarioRunMode::kResolverCoverage) {
    // The normal CONNECT_TO baseline deliberately bypasses DNS. This lane
    // removes only that override; OPENSOCKET still returns the in-process
    // socketpair, so no resolved address can receive network traffic.
    (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
  }

  const curl::fuzzer::proto::ApiPlan* api_plan =
      mode == ScenarioRunMode::kApiLifecycle && scenario.has_api_plan() ? &scenario.api_plan() : nullptr;
  if (api_plan != nullptr && api_plan->reset_easy() && transfer.ResetConfiguration()) {
    configure_easy();
  }

  ApiLifecycle* api_lifecycle = nullptr;
  if (api_plan != nullptr) {
    api_lifecycle = transfer.InstallApiLifecycle(*api_plan, url);
    mock->SetMultiObserver([api_lifecycle](CURLM* multi) { api_lifecycle->SetActiveMulti(multi); });
  }

  ScenarioRequestData* request_data = transfer.InstallRequestData(scenario, mode == ScenarioRunMode::kResolverCoverage);
  if (mode == ScenarioRunMode::kResolverCoverage && !request_data->resolve_entries_ready()) {
    return 0;
  }
  mock->ConfigureRequestData(request_data);
  const auto drive_mode = api_plan == nullptr ? curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM : api_plan->drive_mode();
  CURLcode transfer_result = CURLE_FAILED_INIT;
  if (drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_PERFORM) {
    transfer_result = mock->DriveEasyScenario(easy, scenario);
  } else if (drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_EVENTS) {
    transfer_result = mock->DriveEasyScenario(easy, scenario, true);
  } else if (drive_mode == curl::fuzzer::proto::API_DRIVE_CONNECT_ONLY) {
    transfer_result = mock->DriveConnectOnlyScenario(easy, scenario).connect_result;
  } else {
    transfer_result = mock->DriveScenario(easy, scenario);
  }
  if (api_lifecycle != nullptr) {
    const bool retains_internal_multi = drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_PERFORM ||
                                        drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_EVENTS ||
                                        drive_mode == curl::fuzzer::proto::API_DRIVE_CONNECT_ONLY;
    // An easy entrypoint can fail before attaching its private multi. The
    // drive mode alone therefore cannot establish curl_easy_upkeep's state
    // precondition. These are the two pre-attachment failure results.
    const bool probe_upkeep =
        retains_internal_multi && transfer_result != CURLE_OUT_OF_MEMORY && transfer_result != CURLE_FAILED_INIT;
    api_lifecycle->ProbeTransferResults(probe_upkeep);
    api_lifecycle->ProbeEasyDuplication();
#if defined(PROTO_FUZZER_OBSERVE_STATE)
    const volatile std::size_t api_observation[] = {
        api_lifecycle->response_pause_returned(), api_lifecycle->response_bytes_received(),
        api_lifecycle->reentrant_probes_run(), api_lifecycle->reentrant_recursive_rejections()};
    (void)api_observation;
#endif
  } else if (mode != ScenarioRunMode::kFastProtocol) {
    ProbeTransferResults(easy);
  }

#if defined(PROTO_FUZZER_OBSERVE_STATE)
  // TransferSession still owns these completed callback states. Local volatile
  // stores retain their getter calls during profiling without adding work to
  // ordinary fuzz builds or changing the transfer's callback configuration.
  const RequestBuildStats& stats = request_data->stats();
  const UploadScriptState& upload = request_data->upload_state();
  const volatile std::size_t request_observation[] = {stats.request_headers,
                                                      stats.resolve_entries,
                                                      stats.telnet_options,
                                                      stats.mime_parts,
                                                      stats.mime_headers,
                                                      stats.generated_mime_bytes,
                                                      request_data->upload_callbacks_installed(),
                                                      upload.data_size(),
                                                      upload.read_step_count(),
                                                      upload.offset(),
                                                      upload.scripted()};
  (void)request_observation;
  ObserveProtocolPeerState(mock.get());
#endif
  return 0;
}

}  // namespace proto_fuzzer
