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
#include "proto_fuzzer/dict_mock_server.h"
#include "proto_fuzzer/ftp_mock_server.h"
#include "proto_fuzzer/h2_cleartext_mock_server.h"
#include "proto_fuzzer/happy_eyeballs_mock_server.h"
#include "proto_fuzzer/imap_mock_server.h"
#include "proto_fuzzer/ldap_mock_server.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/mqtt_mock_server.h"
#include "proto_fuzzer/multi_transfer_runner.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/pop3_mock_server.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/smtp_mock_server.h"
#include "proto_fuzzer/socks4_mock_server.h"
#include "proto_fuzzer/telnet_mock_server.h"
#include "proto_fuzzer/tftp_mock_server.h"
#include "proto_fuzzer/transfer_session.h"
#include "proto_fuzzer/websocket_mock_server.h"

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
#include "proto_fuzzer/h2_origin_mock_server.h"
#include "proto_fuzzer/h2_proxy_mock_server.h"
#include "proto_fuzzer/smtps_mock_server.h"
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
    case curl::fuzzer::proto::SCHEME_SMTP:
      return "smtp";
    case curl::fuzzer::proto::SCHEME_IMAP:
      return "imap";
    case curl::fuzzer::proto::SCHEME_POP3:
      return "pop3";
    case curl::fuzzer::proto::SCHEME_MQTT:
      return "mqtt";
    case curl::fuzzer::proto::SCHEME_LDAP:
      return "ldap";
    case curl::fuzzer::proto::SCHEME_SMTPS:
      return "smtps";
    case curl::fuzzer::proto::SCHEME_DICT:
      return "dict";
    case curl::fuzzer::proto::SCHEME_GOPHER:
      return "gopher";
    case curl::fuzzer::proto::SCHEME_GOPHERS:
      return "gophers";
    case curl::fuzzer::proto::SCHEME_FILE:
      return "file";
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

  if (mode == ScenarioRunMode::kResolverCoverage && scenario.happy_eyeballs()) {
    // The loopback race peer returns real unconnected sockets, so curl's
    // happy-eyeballs filter can keep several connect attempts in progress
    // instead of accepting the first preconnected socketpair.
    return std::make_unique<HappyEyeballsMockServer>();
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
    case curl::fuzzer::proto::SCHEME_SMTP:
      // SMTP reuses the stream socketpair but needs command-aligned replies
      // and a DATA body drain. Only the dedicated lane may reinterpret an
      // append-only scheme value that historical corpus inputs could carry.
      if (mode == ScenarioRunMode::kSmtpCoverage) {
        return std::make_unique<SmtpMockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_IMAP:
      // IMAP replies are tag-aligned. Only the dedicated lane may reinterpret
      // an append-only scheme value that historical inputs could carry.
      if (mode == ScenarioRunMode::kImapCoverage) {
        return std::make_unique<ImapMockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_POP3:
      if (mode == ScenarioRunMode::kPop3Coverage) {
        return std::make_unique<Pop3MockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_MQTT:
      // MQTT reuses the stream socketpair but speaks a binary packet grammar
      // with server-initiated packets. Only the dedicated lane may
      // reinterpret an append-only scheme value that historical corpus
      // inputs could carry.
      if (mode == ScenarioRunMode::kMqttCoverage) {
        return std::make_unique<MqttMockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_DICT:
      // DICT sends its command sequence in one write and reads an EOF-framed
      // text body. Only the dedicated lane may reinterpret an append-only
      // scheme value that historical inputs could carry.
      if (mode == ScenarioRunMode::kDictCoverage) {
        return std::make_unique<DictMockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_SMTPS:
      // Implicit TLS shares the SMTP lane, parser, and command budget with the
      // plaintext scheme; only the transport factory differs. Keep it gated on
      // the same fixed run mode so no other target can turn an appended enum
      // value into a TLS exchange.
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kSmtpCoverage) {
        return std::make_unique<SmtpsMockServer>();
      }
#endif
      return nullptr;
    case curl::fuzzer::proto::SCHEME_FILE:
      // FILE reads the local filesystem directly. The dedicated lane pins its
      // path to /dev/null, so there is no socket or scriptable peer to install.
      return nullptr;
    case curl::fuzzer::proto::SCHEME_LDAP:
      // LDAP is BER/ASN.1 rather than line-oriented and OpenLDAP performs its
      // own reads on a duplicate of curl's socket. Only the dedicated lane
      // may turn an appended scheme value into a live bind/search exchange.
      if (mode == ScenarioRunMode::kLdapCoverage) {
        return std::make_unique<LdapMockServer>();
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

  if (auto* smtp = dynamic_cast<SmtpMockServer*>(mock)) {
    const volatile std::size_t smtp_observation[] = {smtp->control_transcript().size(), smtp->uploaded_data().size()};
    (void)smtp_observation;
  }

  if (auto* imap = dynamic_cast<ImapMockServer*>(mock)) {
    const volatile std::size_t imap_observation[] = {imap->control_transcript().size(), imap->uploaded_data().size()};
    (void)imap_observation;
  }

  if (auto* pop3 = dynamic_cast<Pop3MockServer*>(mock)) {
    const volatile std::size_t pop3_observation[] = {pop3->control_transcript().size(), pop3->uploaded_data().size()};
    (void)pop3_observation;
  }

  if (auto* mqtt = dynamic_cast<MqttMockServer*>(mock)) {
    const volatile std::size_t mqtt_observation[] = {mqtt->packet_transcript().size(), mqtt->packet_count(),
                                                     mqtt->publish_count(), mqtt->subscribe_count(),
                                                     mqtt->published_payload().size()};
    (void)mqtt_observation;
  }

  if (auto* dict = dynamic_cast<DictMockServer*>(mock)) {
    const volatile std::size_t dict_observation[] = {dict->control_transcript().size(), dict->uploaded_data().size()};
    (void)dict_observation;
  }

  if (auto* ldap = dynamic_cast<LdapMockServer*>(mock)) {
    const volatile std::size_t ldap_observation[] = {ldap->packet_transcript().size(), ldap->bind_request_count(),
                                                     ldap->search_request_count(), ldap->scripted_message_count(),
                                                     ldap->synthesized_done_count()};
    (void)ldap_observation;
  }

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
  if (auto* smtps = dynamic_cast<SmtpsMockServer*>(mock)) {
    const volatile std::size_t smtps_observation[] = {smtps->completed_handshake_count(),
                                                      static_cast<std::size_t>(smtps->negotiated_tls_version()),
                                                      smtps->negotiated_alpn().size()};
    (void)smtps_observation;
  }
#endif

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

  // FILE is the one peerless lane. Gate it on the dedicated run mode so the
  // compatibility target cannot reinterpret the append-only enum value as a
  // local filesystem read from an accumulated corpus entry.
  const bool file_lane =
      mode == ScenarioRunMode::kFileCoverage && scenario.scheme() == curl::fuzzer::proto::SCHEME_FILE;
  if (scenario.scheme() == curl::fuzzer::proto::SCHEME_FILE && !file_lane) {
    return 0;
  }

  std::unique_ptr<MockServerBase> mock = MakeMockServerForScenario(scenario, mode);
  if (!mock && !file_lane) {
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
    if (mock) {
      mock->Install(easy);
    }
    transfer.ApplyInputFiles();
    // Repeat the option-count bound for compatibility and direct callers.
    (void)ApplyScenarioOptions(easy, scenario);
  };
  configure_easy();
  transfer.ConfigureAltSvcRouting(scenario.host_path());

  if (file_lane) {
    // The file:// handler reads the pinned /dev/null target (or rejects a
    // mutated authority) synchronously and never opens a socket, so no mock
    // peer or request-data callbacks exist to drive. The baseline's short
    // timeout still bounds the transfer.
    const CURLcode transfer_result = curl_easy_perform(easy);
    (void)transfer_result;
    ProbeTransferResults(easy);
    return 0;
  }

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
