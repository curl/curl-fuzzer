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

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

#include "proto_fuzzer/api_lifecycle.h"
#include "proto_fuzzer/dict_mock_server.h"
#include "proto_fuzzer/ftp_mock_server.h"
#include "proto_fuzzer/gopher_mock_server.h"
#include "proto_fuzzer/h2_cleartext_mock_server.h"
#include "proto_fuzzer/happy_eyeballs_mock_server.h"
#include "proto_fuzzer/http_transport_mock_server.h"
#include "proto_fuzzer/imap_mock_server.h"
#include "proto_fuzzer/ipfs_url.h"
#include "proto_fuzzer/ldap_mock_server.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/mqtt_mock_server.h"
#include "proto_fuzzer/multi_transfer_runner.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/pop3_mock_server.h"
#include "proto_fuzzer/proxy_option_mock_server.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/resolver_cancel_gate.h"
#include "proto_fuzzer/rtsp_mock_server.h"
#include "proto_fuzzer/smtp_mock_server.h"
#include "proto_fuzzer/socks4_mock_server.h"
#include "proto_fuzzer/telnet_mock_server.h"
#include "proto_fuzzer/tftp_mock_server.h"
#include "proto_fuzzer/transfer_session.h"
#include "proto_fuzzer/websocket_mock_server.h"

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
#include "proto_fuzzer/doh_https_rr_mock_server.h"
#include "proto_fuzzer/ftps_mock_server.h"
#include "proto_fuzzer/h2_origin_mock_server.h"
#include "proto_fuzzer/h2_proxy_mock_server.h"
#include "proto_fuzzer/imaps_mock_server.h"
#include "proto_fuzzer/ldaps_mock_server.h"
#include "proto_fuzzer/mqtts_mock_server.h"
#include "proto_fuzzer/pop3s_mock_server.h"
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
constexpr char kResolverUnixSocketPath[] = "/curl-fuzzer-resolver.sock";
constexpr char kResolverCancelDuplicateUrl[] = "http://resolver-queued-cancel.test:81/queued-cancel-duplicate";
constexpr auto kResolverCancelGateWait = std::chrono::milliseconds(500);
constexpr int kResolverIdlePollAttempts = 4;
constexpr int kResolverIdlePollTimeoutMs = 250;

/// Return whether a fixed plaintext lane requests an explicit TLS upgrade.
/// Compatibility preserves these append-only selectors without interpreting
/// them, so the run mode remains part of the decision.
bool ScenarioRequestsStartTls(const curl::fuzzer::proto::Scenario& scenario, ScenarioRunMode mode) {
  switch (mode) {
    case ScenarioRunMode::kLdapCoverage:
      return scenario.scheme() == curl::fuzzer::proto::SCHEME_LDAP && scenario.ldap_starttls();
    case ScenarioRunMode::kPop3Coverage:
      return scenario.scheme() == curl::fuzzer::proto::SCHEME_POP3 &&
             scenario.pop3_starttls_filter_allocation_failure();
    default:
      return false;
  }
}

struct ResolverIdleTraceState {
  explicit ResolverIdleTraceState(CURL* handle) : easy(handle) {}

  ~ResolverIdleTraceState() {
    // The callback is static, but its data is stack-owned. Disable tracing and
    // clear that pointer before the easy handle outlives this focused drive.
    (void)curl_easy_setopt(easy, CURLOPT_VERBOSE, 0L);
    (void)curl_easy_setopt(easy, CURLOPT_DEBUGDATA, nullptr);
  }

  CURL* easy;
  bool observe_idle = false;
  bool saw_idle = false;
};

int ObserveResolverIdleTrace(CURL* /*easy*/, curl_infotype type, char* data, std::size_t size, void* client_data) {
  auto* state = static_cast<ResolverIdleTraceState*>(client_data);
  if (state == nullptr || !state->observe_idle || type != CURLINFO_TEXT || data == nullptr) {
    return 0;
  }
  const std::string_view trace(data, size);
  if (trace.find("[TPOOL-DNS]") != std::string_view::npos && trace.find("idle for") != std::string_view::npos) {
    state->saw_idle = true;
  }
  return 0;
}

int CountResolverStart(void* /*resolver_state*/, void* /*reserved*/, void* client_data) {
  ++*static_cast<int*>(client_data);
  return 0;
}

/// Apply only harness-owned resolver controls. Target policy has already
/// replaced the URL authority with a fixed name understood by the target-local
/// getaddrinfo shim and removed fuzzed cache entries for these modes.
bool ApplyResolverMode(CURL* easy, curl::fuzzer::proto::ResolverMode mode) {
  switch (mode) {
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_POSITIVE:
      return curl_easy_setopt(easy, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4) == CURLE_OK &&
             curl_easy_setopt(easy, CURLOPT_DNS_SHUFFLE_ADDRESSES, 1L) == CURLE_OK;
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_PARTIAL:
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_QUEUED_CANCEL:
      return curl_easy_setopt(easy, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER) == CURLE_OK;
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_NEGATIVE:
      return curl_easy_setopt(easy, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_WHATEVER) == CURLE_OK;
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_LINK_LOCAL:
      return curl_easy_setopt(easy, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6) == CURLE_OK;
    case curl::fuzzer::proto::RESOLVER_MODE_UNIX_SOCKET:
      return curl_easy_setopt(easy, CURLOPT_UNIX_SOCKET_PATH, kResolverUnixSocketPath) == CURLE_OK;
    case curl::fuzzer::proto::RESOLVER_MODE_DEFAULT:
    case curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR:
    case curl::fuzzer::proto::RESOLVER_MODE_GLOBAL_LIFECYCLE:
    default:
      return true;
  }
}

/// Resolve two public easy handles through one worker. The first handle queues
/// AAAA then A. Its first getaddrinfo call cannot return through the target
/// gate, so the sole worker cannot take the second family. Only then is the
/// duplicate added on a distinct origin and allowed to queue its own AAAA and
/// A work behind the blocked lookup.
///
/// The resolver-start callback fires before curl submits the duplicate's
/// queries, but curl_multi_perform cannot return until that synchronous
/// submission finishes. A successful perform, a live duplicate, and the
/// observed callback therefore prove the duplicate resolver work is queued.
/// Removing that active duplicate is the public cancellation operation: curl
/// synchronously shuts down its live async resolver, scans the queue, and
/// destroys the matching items before clearing the handle's multi pointer.
/// The gate's scope ends after this removal and before cleanup can join the
/// worker, so teardown cannot wait in a cycle with the shim.
CURLcode RunQueuedResolverCancellation(CURL* easy, MockServer* mock, const curl::fuzzer::proto::Scenario& scenario) {
  int duplicate_resolver_starts = 0;
  ResolverIdleTraceState idle_trace(easy);
  // Keep callback data alive until both handles are gone. Declaring the
  // duplicate before the multi also makes exceptional teardown destroy the
  // multi (and detach any handle whose public removal failed) first.
  CurlEasyPtr duplicate(curl_easy_duphandle(easy));
  CurlMultiPtr multi(curl_multi_init());
  // This drive is bounded by the gate wait and explicit removals. Clear the
  // ordinary 200 ms transfer/connect settings (zero selects no operation
  // deadline and curl's default connect deadline) so host scheduling cannot
  // cancel either handle before the queue invariant is established.
  if (multi == nullptr || duplicate == nullptr ||
      curl_multi_setopt(multi.get(), CURLMOPT_RESOLVE_THREADS_MAX, 1L) != CURLM_OK ||
      curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 0L) != CURLE_OK ||
      curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 0L) != CURLE_OK ||
      curl_easy_setopt(duplicate.get(), CURLOPT_TIMEOUT_MS, 0L) != CURLE_OK ||
      curl_easy_setopt(duplicate.get(), CURLOPT_CONNECTTIMEOUT_MS, 0L) != CURLE_OK ||
      curl_easy_setopt(duplicate.get(), CURLOPT_URL, kResolverCancelDuplicateUrl) != CURLE_OK ||
      curl_easy_setopt(duplicate.get(), CURLOPT_FRESH_CONNECT, 1L) != CURLE_OK ||
      curl_easy_setopt(duplicate.get(), CURLOPT_RESOLVER_START_FUNCTION, &CountResolverStart) != CURLE_OK ||
      curl_easy_setopt(duplicate.get(), CURLOPT_RESOLVER_START_DATA, &duplicate_resolver_starts) != CURLE_OK ||
      curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, &ObserveResolverIdleTrace) != CURLE_OK ||
      curl_easy_setopt(easy, CURLOPT_DEBUGDATA, &idle_trace) != CURLE_OK ||
      curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L) != CURLE_OK) {
    return CURLE_FAILED_INIT;
  }

  mock->SetScripts(scenario);
  CURLMcode add_easy_result = curl_multi_add_handle(multi.get(), easy);
  CURLMcode add_duplicate_result = CURLM_BAD_HANDLE;
  CURLMcode perform_result = CURLM_BAD_HANDLE;
  CURLMcode remove_duplicate_result = CURLM_BAD_HANDLE;
  bool lookup_started = false;
  bool duplicate_resolver_queued = false;
  bool resolver_worker_idle = false;
  int still_running = 0;
  if (add_easy_result == CURLM_OK) {
    ScopedResolverCancelGate gate;
    perform_result = curl_multi_perform(multi.get(), &still_running);
    if (perform_result == CURLM_OK && still_running > 0) {
      lookup_started = WaitForResolverCancelLookup(kResolverCancelGateWait);
    }
    // The signal is sent from inside Q1's getaddrinfo. Q1 is worker-owned,
    // and the only worker cannot return to the queue to take original Q2.
    if (lookup_started) {
      add_duplicate_result = curl_multi_add_handle(multi.get(), duplicate.get());
    }
    if (add_duplicate_result == CURLM_OK) {
      perform_result = curl_multi_perform(multi.get(), &still_running);
    }
    // Resolver-start precedes the two sends, but the public perform call does
    // not return until Curl_async_getaddrinfo has submitted them. Since Q1 is
    // still blocked, a live duplicate here has queue-owned work to cancel.
    duplicate_resolver_queued = perform_result == CURLM_OK && still_running == 2 && duplicate_resolver_starts > 0;
    // Always detach a successfully added duplicate before its easy handle can
    // be destroyed. On the proved path this is the intentional cancellation;
    // on a failed proof it is bounded cleanup while Q1 still owns the worker.
    if (add_duplicate_result == CURLM_OK) {
      remove_duplicate_result = curl_multi_remove_handle(multi.get(), duplicate.get());
    }
  }

  // Releasing the gate lets the worker finish the original handle's two
  // queries. Wait on curl's public internal wakeup and perform until the
  // THREADS trace reports that the pool is idle. Curl emits that observation
  // while holding the pool lock; the main thread can acquire it only after the
  // worker has entered Curl_cond_timedwait and released the lock. The trace is
  // therefore the proof, while the poll timeout merely bounds a failed run.
  if (lookup_started && duplicate_resolver_queued && remove_duplicate_result == CURLM_OK) {
    idle_trace.observe_idle = true;
    for (int attempt = 0; attempt < kResolverIdlePollAttempts && !idle_trace.saw_idle; ++attempt) {
      int numfds = 0;
      const CURLMcode poll_result = curl_multi_poll(multi.get(), nullptr, 0, kResolverIdlePollTimeoutMs, &numfds);
      if (poll_result != CURLM_OK) {
        perform_result = poll_result;
        break;
      }
      perform_result = curl_multi_perform(multi.get(), &still_running);
      if (perform_result != CURLM_OK) {
        break;
      }
    }
    resolver_worker_idle = idle_trace.saw_idle;
  }

  const CURLMcode remove_easy_result =
      add_easy_result == CURLM_OK ? curl_multi_remove_handle(multi.get(), easy) : CURLM_BAD_HANDLE;
  return lookup_started && duplicate_resolver_queued && resolver_worker_idle && perform_result == CURLM_OK &&
                 remove_duplicate_result == CURLM_OK && remove_easy_result == CURLM_OK
             ? CURLE_OK
             : CURLE_FAILED_INIT;
}

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
    case curl::fuzzer::proto::SCHEME_FTPS:
      return "ftps";
    case curl::fuzzer::proto::SCHEME_TFTP:
      return "tftp";
    case curl::fuzzer::proto::SCHEME_SMTP:
      return "smtp";
    case curl::fuzzer::proto::SCHEME_IMAP:
      return "imap";
    case curl::fuzzer::proto::SCHEME_IMAPS:
      return "imaps";
    case curl::fuzzer::proto::SCHEME_POP3:
      return "pop3";
    case curl::fuzzer::proto::SCHEME_POP3S:
      return "pop3s";
    case curl::fuzzer::proto::SCHEME_MQTT:
      return "mqtt";
    case curl::fuzzer::proto::SCHEME_MQTTS:
      return "mqtts";
    case curl::fuzzer::proto::SCHEME_LDAP:
      return "ldap";
    case curl::fuzzer::proto::SCHEME_LDAPS:
      return "ldaps";
    case curl::fuzzer::proto::SCHEME_RTSP:
      return "rtsp";
    case curl::fuzzer::proto::SCHEME_IPFS:
      return "ipfs";
    case curl::fuzzer::proto::SCHEME_IPNS:
      return "ipns";
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

/// Build the URL curl actually receives. For IPFS/IPNS this reproduces curl's
/// command-line gateway rewrite: `<gateway>/<protocol>/<cid-or-name><suffix>`.
/// The gateway itself is the fixed loopback authority above; host_path already
/// holds the canonical CID/name followed by the mutation-controlled suffix.
/// @param scenario Scenario whose scheme and gateway path select the URL.
/// @param prefix Scheme literal returned by SchemePrefix().
/// @return Effective URL before CONNECT_TO and OPENSOCKET confinement.
std::string ScenarioUrl(const curl::fuzzer::proto::Scenario& scenario, const char* prefix) {
  if (scenario.scheme() == curl::fuzzer::proto::SCHEME_IPFS || scenario.scheme() == curl::fuzzer::proto::SCHEME_IPNS) {
    return BuildIpfsGatewayUrl(scenario.scheme(), scenario.host_path());
  }
  return std::string(prefix) + "://" + scenario.host_path();
}

/// Detect the ECH modes that ask the TLS backend to obtain its configuration
/// from an HTTPS resource record. A literal ECHConfigList already supplies the
/// configuration, while GREASE deliberately does not wait for DNS.
bool EchNeedsPendingHttpsRr(const curl::fuzzer::proto::Scenario& scenario) {
  const std::size_t option_count = RuntimeOptionCount(scenario);
  for (std::size_t index = 0; index < option_count; ++index) {
    const auto& option = scenario.options(static_cast<int>(index));
    if (option.option_id() != curl::fuzzer::proto::CURLOPT_ECH) {
      continue;
    }
    const std::string& value = option.string_value();
    if (value == "true" || value == "hard" || value.rfind("pn:", 0) == 0) {
      return true;
    }
  }
  return false;
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
    return std::make_unique<H2ProxyMockServer>(
        scenario.h2_forward_proxy() ? H2ProxyMode::kForward : H2ProxyMode::kTunnel,
        scenario.connection().proxy_protocol());
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

  if (mode == ScenarioRunMode::kProxyTransportCoverage) {
    return std::make_unique<ProxyTransportMockServer>(scenario.socks_proxy_mode(), scenario.haproxy_protocol());
  }

  if (mode == ScenarioRunMode::kDeepHttpCoverage) {
    if (scenario.proxy_socket_option_mode() == curl::fuzzer::proto::PROXY_SOCKET_OPTION_LOOPBACK_INTERFACE_KEEPALIVE) {
      return std::make_unique<InterfaceOptionMockServer>();
    }
    if (scenario.proxy_socket_option_mode() != curl::fuzzer::proto::PROXY_SOCKET_OPTION_DEFAULT) {
      return std::make_unique<ProxyOptionMockServer>(scenario.proxy_socket_option_mode());
    }
    if (scenario.http_transport_mode() != curl::fuzzer::proto::HTTP_TRANSPORT_DIRECT) {
      return std::make_unique<HttpTransportMockServer>(scenario.http_transport_mode(), scenario.haproxy_protocol());
    }
  }

  if (mode == ScenarioRunMode::kResolverCoverage && scenario.doh_https_rr()) {
    // The DoH responder answers both the address and HTTPS resource-record
    // queries; its TLS/ALPN h2 carrier then completes the outer HTTPS
    // transfer selected from the record.
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
    return std::make_unique<DohHttpsRrMockServer>(
        scenario.tls_certificate_chain(), scenario.resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR,
        EchNeedsPendingHttpsRr(scenario));
#else
    // MemorySanitizer builds deliberately omit OpenSSL, so no verified TLS
    // peer exists for the HTTPS-RR lane. Keep the target available while
    // refusing to fall through to an unrelated transport.
    return nullptr;
#endif
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
        return std::make_unique<TlsMockServer>(scenario.tls_certificate_chain(), scenario.tls_handshake_profile());
      }
#else
      (void)mode;
#endif
      return std::make_unique<MockServer>();
    case curl::fuzzer::proto::SCHEME_GOPHER:
      return mode == ScenarioRunMode::kGopherCoverage ? std::make_unique<GopherMockServer>(scenario.gopher_probe_mode())
                                                      : nullptr;
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
    case curl::fuzzer::proto::SCHEME_FTPS:
      // Implicit TLS shares the FTP lane, parser, and bounded data-channel
      // budget with the plaintext scheme; only the transport factory and the
      // passive-only restriction differ. Keep it gated on the same run mode so
      // no other target can turn an appended enum value into a TLS exchange.
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kFtpCoverage) {
        return std::make_unique<FtpsMockServer>();
      }
#endif
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
    case curl::fuzzer::proto::SCHEME_IMAPS:
      // Implicit TLS reuses the IMAP lane and tag-aware parser; only the
      // transport factory differs. Gate it on the same fixed run mode so no
      // other target can turn the appended enum value into a TLS exchange.
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kImapCoverage) {
        return std::make_unique<ImapsMockServer>();
      }
#endif
      return nullptr;
    case curl::fuzzer::proto::SCHEME_POP3S:
      // Implicit TLS reuses the POP3 lane and status-line parser; only the
      // transport factory differs. Gate it on the same fixed run mode so no
      // other target can turn the appended enum value into a TLS exchange.
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kPop3Coverage) {
        return std::make_unique<Pop3sMockServer>();
      }
#endif
      return nullptr;
    case curl::fuzzer::proto::SCHEME_MQTTS:
      // Implicit TLS shares the MQTT lane, packet parser, and server-packet
      // budget with the plaintext scheme; only the transport factory differs.
      // Keep it gated on the same fixed run mode so no other target can turn
      // an appended enum value into a TLS exchange.
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kMqttCoverage) {
        return std::make_unique<MqttsMockServer>();
      }
#endif
      return nullptr;
    case curl::fuzzer::proto::SCHEME_FILE:
      // FILE reads a session-owned anonymous descriptor directly, so there is
      // no socket or scriptable peer to install.
      return nullptr;
    case curl::fuzzer::proto::SCHEME_LDAP:
      // LDAP is BER/ASN.1 rather than line-oriented and OpenLDAP performs its
      // own reads on a duplicate of curl's socket. Only the dedicated lane
      // may turn an appended scheme value into a live bind/search exchange.
      if (mode == ScenarioRunMode::kLdapCoverage) {
        return std::make_unique<LdapMockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_LDAPS:
      // Implicit TLS shares the LDAP lane, BER parser, and scripted messages
      // with the plaintext scheme; only the transport factory differs. Keep it
      // gated on the same fixed run mode so no other target can turn an
      // appended enum value into a TLS exchange.
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kLdapCoverage) {
        return std::make_unique<LdapsMockServer>();
      }
#endif
      return nullptr;
    case curl::fuzzer::proto::SCHEME_RTSP:
      // RTSP is request-aligned rather than greeting-aligned, so the
      // dedicated lane is required to select the peer that waits for the
      // request terminator before releasing each scripted response.
      if (mode == ScenarioRunMode::kRtspCoverage) {
        return std::make_unique<RtspMockServer>();
      }
      return nullptr;
    case curl::fuzzer::proto::SCHEME_IPFS:
    case curl::fuzzer::proto::SCHEME_IPNS:
      // The rewrite above turns these into ordinary HTTP GETs. Only the
      // dedicated fast lane may reinterpret an append-only scheme value, and
      // its compatibility peer is the plaintext MockServer.
      if (mode == ScenarioRunMode::kFastProtocol) {
        return std::make_unique<MockServer>();
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
                                                     ldap->search_request_count(),     ldap->scripted_message_count(),
                                                     ldap->synthesized_done_count(),   ldap->starttls_request_count()};
    (void)ldap_observation;
  }

  if (auto* rtsp = dynamic_cast<RtspMockServer*>(mock)) {
    const volatile std::size_t rtsp_observation[] = {rtsp->request_count(),
                                                     rtsp->response_count(),
                                                     rtsp->last_client_cseq(),
                                                     rtsp->control_transcript().size(),
                                                     rtsp->last_request_line().size(),
                                                     rtsp->last_stream_uri().size()};
    (void)rtsp_observation;
  }

  if (auto* proxy = dynamic_cast<ProxyTransportMockServer*>(mock)) {
    const volatile std::size_t proxy_observation = proxy->client_transcript().size();
    (void)proxy_observation;
  }

  if (auto* transport = dynamic_cast<HttpTransportMockServer*>(mock)) {
    const volatile std::size_t transport_observation = transport->client_transcript().size();
    (void)transport_observation;
  }

  if (auto* options = dynamic_cast<ProxyOptionMockServer*>(mock)) {
    const volatile std::size_t option_observation = options->client_transcript().size();
    (void)option_observation;
  }

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
  if (auto* ftps = dynamic_cast<FtpsMockServer*>(mock)) {
    const volatile std::size_t ftps_observation[] = {ftps->completed_handshake_count(),
                                                     static_cast<std::size_t>(ftps->negotiated_tls_version()),
                                                     ftps->negotiated_alpn().size()};
    (void)ftps_observation;
  }

  if (auto* smtps = dynamic_cast<SmtpsMockServer*>(mock)) {
    const volatile std::size_t smtps_observation[] = {smtps->completed_handshake_count(),
                                                      static_cast<std::size_t>(smtps->negotiated_tls_version()),
                                                      smtps->negotiated_alpn().size()};
    (void)smtps_observation;
  }

  if (auto* imaps = dynamic_cast<ImapsMockServer*>(mock)) {
    const volatile std::size_t imaps_observation[] = {imaps->completed_handshake_count(),
                                                      static_cast<std::size_t>(imaps->negotiated_tls_version()),
                                                      imaps->negotiated_alpn().size()};
    (void)imaps_observation;
  }

  if (auto* mqtts = dynamic_cast<MqttsMockServer*>(mock)) {
    const volatile std::size_t mqtts_observation[] = {mqtts->completed_handshake_count(),
                                                      static_cast<std::size_t>(mqtts->negotiated_tls_version()),
                                                      mqtts->negotiated_alpn().size(), mqtts->packet_count()};
    (void)mqtts_observation;
  }

  if (auto* pop3s = dynamic_cast<Pop3sMockServer*>(mock)) {
    const volatile std::size_t pop3s_observation[] = {pop3s->completed_handshake_count(),
                                                      static_cast<std::size_t>(pop3s->negotiated_tls_version()),
                                                      pop3s->negotiated_alpn().size()};
    (void)pop3s_observation;
  }

  if (auto* ldaps = dynamic_cast<LdapsMockServer*>(mock)) {
    const volatile std::size_t ldaps_observation[] = {ldaps->completed_handshake_count(),
                                                      static_cast<std::size_t>(ldaps->negotiated_tls_version()),
                                                      ldaps->negotiated_alpn().size()};
    (void)ldaps_observation;
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
  if (prefix == nullptr) {
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
  if (!file_lane && scenario.host_path().empty()) {
    return 0;
  }

  std::unique_ptr<MockServerBase> mock = MakeMockServerForScenario(scenario, mode);
  if (!mock && !file_lane) {
    return 0;
  }

  // The peer survives every easy option/callback, including cleanup of a
  // bounded incomplete transfer. TransferSession owns the rest of that graph.
  TransferSession transfer;
  if (!transfer.PrepareInputFiles(scenario, mode)) {
    return 0;
  }
  if (!transfer.Initialize()) {
    return 0;
  }
  CURL* easy = transfer.easy();
  std::string url;
  if (file_lane) {
    const char* source_path = transfer.FileSourcePath();
    if (source_path == nullptr) {
      return 0;
    }
    url = std::string("file://") + source_path;
  } else {
    url = ScenarioUrl(scenario, prefix);
  }
  bool resolver_mode_ready = true;
  const auto configure_easy = [&] {
    transfer.ApplyBaseline(scenario);
    (void)curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
    if (mock) {
      mock->Install(easy);
    }
    transfer.ApplyInputFiles();
    // Repeat the option-count bound for compatibility and direct callers.
    (void)ApplyScenarioOptions(easy, scenario);
    if (mode == ScenarioRunMode::kGopherCoverage &&
        scenario.gopher_probe_mode() == curl::fuzzer::proto::GOPHER_PROBE_TLS_SESSION_KEY_LIMIT) {
      (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
      (void)curl_easy_setopt(easy, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_ALLOW_BEAST));
    }
    if (ScenarioRequestsStartTls(scenario, mode)) {
      (void)curl_easy_setopt(easy, CURLOPT_USE_SSL, static_cast<long>(CURLUSESSL_ALL));
    }
    if (mode == ScenarioRunMode::kResolverCoverage) {
      resolver_mode_ready = ApplyResolverMode(easy, scenario.resolver_mode());
    }
    if (mode == ScenarioRunMode::kTlsCoverage) {
      (void)ApplyTlsClientCredentialProfile(easy, scenario.tls_client_credential_profile());
    }
  };
  configure_easy();
  if (!resolver_mode_ready) {
    return 0;
  }
  transfer.ConfigureAltSvcRouting(scenario.host_path());

  if (file_lane) {
    // The file:// handler reads or writes only the session-owned anonymous
    // descriptor and never opens a socket. Install the bounded request-data
    // owner before perform so retained upload options consume Scenario.upload
    // through curl's read callback instead of falling back to stdin. The
    // baseline's short timeout still bounds the transfer.
    (void)transfer.InstallRequestData(scenario);
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

  // The DoH lane lets the loopback responder answer every lookup, including
  // the address query, so it must not install the resolver lane's fixed
  // CURLOPT_RESOLVE cache entries.
  const bool apply_resolve_entries = mode == ScenarioRunMode::kResolverCoverage && !scenario.doh_https_rr() &&
                                     scenario.resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_DEFAULT;
  ScenarioRequestData* request_data = transfer.InstallRequestData(scenario, apply_resolve_entries);
  if (mode == ScenarioRunMode::kResolverCoverage && !request_data->resolve_entries_ready()) {
    return 0;
  }
  mock->ConfigureRequestData(request_data);
  const auto drive_mode = api_plan == nullptr ? curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM : api_plan->drive_mode();
  CURLcode transfer_result = CURLE_FAILED_INIT;
  if (mode == ScenarioRunMode::kResolverCoverage &&
      scenario.resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_THREADED_QUEUED_CANCEL) {
    auto* resolver_mock = dynamic_cast<MockServer*>(mock.get());
    if (resolver_mock != nullptr) {
      transfer_result = RunQueuedResolverCancellation(easy, resolver_mock, scenario);
    }
  } else if (drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_PERFORM) {
    transfer_result = mock->DriveEasyScenario(easy, scenario);
  } else if (drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_EVENTS) {
    transfer_result = mock->DriveEasyScenario(easy, scenario, true);
  } else if (drive_mode == curl::fuzzer::proto::API_DRIVE_CONNECT_ONLY) {
    transfer_result = mock->DriveConnectOnlyScenario(easy, scenario).connect_result;
  } else {
    transfer_result = mock->DriveScenario(easy, scenario);
  }
  if (api_plan != nullptr && api_plan->repeat_mime_post() && transfer_result == CURLE_OK) {
    // Re-enter the public transfer setup with the same easy handle, MIME root,
    // and callback cursor. A completed first body leaves a non-rewindable
    // callback at EOF; curl's second MIME reader setup must then report its
    // normal public rewind failure and clean up the unattached reader before
    // it can send another request.
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
                                                      stats.mime_callback_parts,
                                                      stats.mime_headers,
                                                      stats.generated_mime_bytes,
                                                      request_data->upload_callbacks_installed(),
                                                      upload.data_size(),
                                                      upload.read_step_count(),
                                                      upload.offset(),
                                                      upload.seek_calls(),
                                                      upload.scripted()};
  (void)request_observation;
  ObserveProtocolPeerState(mock.get());
#endif
  return 0;
}

}  // namespace proto_fuzzer
