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

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/api_lifecycle.h"
#include "proto_fuzzer/bounded_anonymous_input_file.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/ftp_mock_server.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/multi_transfer_runner.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/scenario_limits.h"
#include "proto_fuzzer/socks4_mock_server.h"
#include "proto_fuzzer/telnet_mock_server.h"
#include "proto_fuzzer/tftp_mock_server.h"
#include "proto_fuzzer/websocket_mock_server.h"

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
#include "proto_fuzzer/h2_origin_mock_server.h"
#include "proto_fuzzer/h2_proxy_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"
#endif
#if defined(PROTO_FUZZER_HAS_HTTP3_MOCK_SERVER)
#include "proto_fuzzer/http3_mock_server.h"
#endif

namespace proto_fuzzer {

namespace {

constexpr unsigned int kAllHeaderOrigins = CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX | CURLH_PSEUDO;
constexpr std::size_t kMaxResultHeaders = 16;
constexpr char kDevNullPath[] = "/dev/null";
constexpr char kAltSvcOrigin[] = "altsvc-origin.test";
constexpr char kAltSvcLoopbackResolve[] = "*:80:127.0.1.127";

/// Refuse any resolver request not satisfied by the harness-owned Alt-Svc
/// host-cache entry. The callback runs before every supported resolver backend
/// starts work, so a mutated alternate host or port cannot reach ambient DNS.
int AbortUnexpectedAltSvcResolve(void* /*resolver_state*/, void* /*reserved*/, void* /*userdata*/) { return 1; }

/// Direct RunScenario callers do not necessarily pass through target policy.
/// Only detach CONNECT_TO when the URL authority is the canonical host whose
/// default HTTP port is covered by kAltSvcLoopbackResolve.
bool HasCanonicalAltSvcAuthority(const std::string& host_path) {
  const std::size_t host_size = sizeof(kAltSvcOrigin) - 1;
  if (host_path.compare(0, host_size, kAltSvcOrigin) != 0) {
    return false;
  }
  return host_path.size() == host_size || host_path[host_size] == '/' || host_path[host_size] == '?' ||
         host_path[host_size] == '#';
}

/// Copy the runtime-visible prefix of one protobuf field into its anonymous
/// file. ApplyTargetPolicy normally enforces the same bounds before execution;
/// repeating them here keeps direct RunScenario callers safe and observable.
void PrepareInputFile(const std::string& contents, std::size_t* remaining_bytes,
                      BoundedAnonymousInputFile* input_file) {
  if (contents.empty() || *remaining_bytes == 0) {
    return;
  }
  const std::size_t size = std::min(contents.size(), std::min(scenario_limits::kMaxFileInputBytes, *remaining_bytes));
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(contents.data());
  if (input_file->Write(bytes, size)) {
    *remaining_bytes -= size;
  }
}

/// Prefix NETRC bytes with a parser-neutral blank line. curl's text loader
/// drops comment-only lines and otherwise represents an empty result as a null
/// buffer; retaining one newline keeps that upstream edge case out of this
/// general protocol fuzzer while retaining every mutation byte in the file
/// presented to curl's loader.
/// The shared budget is charged only for protobuf bytes, not this fixed guard.
void PrepareNetrcInputFile(const std::string& contents, std::size_t* remaining_bytes,
                           BoundedAnonymousInputFile* input_file) {
  if (contents.empty() || *remaining_bytes == 0) {
    return;
  }
  const std::size_t size = std::min(contents.size(), std::min(scenario_limits::kMaxFileInputBytes, *remaining_bytes));
  std::string guarded_contents;
  guarded_contents.reserve(size + 1);
  guarded_contents.push_back('\n');
  guarded_contents.append(contents.data(), size);
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(guarded_contents.data());
  if (input_file->Write(bytes, guarded_contents.size())) {
    *remaining_bytes -= size;
  }
}

/// Apply parser input paths after the fixed baseline but before scenario
/// options. COOKIEFILE is read-only by definition. Alt-Svc and HSTS use one
/// option for both input and cleanup output, so load the anonymous file first
/// and then restore /dev/null as the final save destination. Both loaders keep
/// entries from earlier files.
void ApplyDeepHttpFileOptions(CURL* easy, const BoundedAnonymousInputFile& cookie_file,
                              const BoundedAnonymousInputFile& altsvc_file, const BoundedAnonymousInputFile& hsts_file,
                              const BoundedAnonymousInputFile& netrc_file) {
  if (const char* path = cookie_file.path()) {
    (void)curl_easy_setopt(easy, CURLOPT_COOKIEFILE, path);
  }
  if (const char* path = altsvc_file.path()) {
    (void)curl_easy_setopt(easy, CURLOPT_ALTSVC, path);
    (void)curl_easy_setopt(easy, CURLOPT_ALTSVC, kDevNullPath);
  }
  if (const char* path = hsts_file.path()) {
    (void)curl_easy_setopt(easy, CURLOPT_HSTS, path);
    (void)curl_easy_setopt(easy, CURLOPT_HSTS, kDevNullPath);
  }
  if (const char* path = netrc_file.path()) {
    (void)curl_easy_setopt(easy, CURLOPT_NETRC_FILE, path);
    (void)curl_easy_setopt(easy, CURLOPT_NETRC, CURL_NETRC_REQUIRED);
  }
}

/// Install CRL input only after the TLS mock has supplied its in-memory trust
/// anchor. CURLOPT_CRLFILE stores the path and each TLS backend opens it while
/// constructing the verified connection; it never writes back to the file.
void ApplyTlsFileOptions(CURL* easy, const BoundedAnonymousInputFile& crl_file) {
  if (const char* path = crl_file.path()) {
    (void)curl_easy_setopt(easy, CURLOPT_CRLFILE, path);
  }
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
/// The compatibility target must keep treating HTTPS response bytes as raw TLS
/// records, while the dedicated HTTPS lane interprets them as decrypted HTTP.
/// Keeping that semantic boundary in the closed run-mode enum prevents a new
/// protobuf field from silently changing old OSS-Fuzz reproducers.
std::unique_ptr<MockServerBase> MakeMockServerForScenario(const curl::fuzzer::proto::Scenario& scenario,
                                                          ScenarioRunMode mode) {
  if (mode == ScenarioRunMode::kHttp3Coverage) {
#if defined(PROTO_FUZZER_HAS_HTTP3_MOCK_SERVER)
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

  if (mode == ScenarioRunMode::kTlsHttp2Coverage) {
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
    return std::make_unique<H2OriginMockServer>(scenario.tls_certificate_chain());
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
    case curl::fuzzer::proto::SCHEME_WSS:
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

}  // namespace

/// Implement the bounded orchestration contract documented on the public
/// declaration; keeping argument docs there avoids two drifting descriptions.
int RunScenario(const curl::fuzzer::proto::Scenario& scenario, ScenarioRunMode mode) {
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

  // Declaration order is an ownership invariant: reverse destruction keeps
  // anonymous parser files, CONNECT_TO/RESOLVE storage, and share callback
  // userdata alive through easy cleanup. This matters for incomplete
  // transfers, where cleanup still flushes caches and can release retained
  // references.
  std::unique_ptr<ApiLifecycle> api_lifecycle;
  CurlSlistPtr connect_to;
  CurlSlistPtr altsvc_resolve;
  BoundedAnonymousInputFile cookie_file(scenario_limits::kMaxFileInputBytes);
  BoundedAnonymousInputFile altsvc_file(scenario_limits::kMaxFileInputBytes);
  BoundedAnonymousInputFile hsts_file(scenario_limits::kMaxFileInputBytes);
  BoundedAnonymousInputFile netrc_file(scenario_limits::kMaxFileInputBytes + 1);
  BoundedAnonymousInputFile crl_file(scenario_limits::kMaxFileInputBytes);
  if (mode == ScenarioRunMode::kDeepHttpCoverage) {
    std::size_t remaining_file_bytes = scenario_limits::kMaxFileInputTotalBytes;
    PrepareInputFile(scenario.cookie_file(), &remaining_file_bytes, &cookie_file);
    PrepareInputFile(scenario.altsvc_file(), &remaining_file_bytes, &altsvc_file);
    PrepareInputFile(scenario.hsts_file(), &remaining_file_bytes, &hsts_file);
    PrepareNetrcInputFile(scenario.netrc_file(), &remaining_file_bytes, &netrc_file);
  } else if (mode == ScenarioRunMode::kTlsCoverage) {
    std::size_t remaining_file_bytes = scenario_limits::kMaxFileInputTotalBytes;
    PrepareInputFile(scenario.crl_file(), &remaining_file_bytes, &crl_file);
  }
  CurlEasyPtr easy(curl_easy_init());
  if (!easy) {
    return 0;
  }

  std::string url = std::string(prefix) + "://" + scenario.host_path();
  const auto configure_easy = [&] {
    connect_to.reset(ApplyBaselineOptions(easy.get(), scenario.scheme(), scenario.trace_ids()));
    curl_easy_setopt(easy.get(), CURLOPT_URL, url.c_str());
    mock->Install(easy.get());

    if (mode == ScenarioRunMode::kDeepHttpCoverage) {
      ApplyDeepHttpFileOptions(easy.get(), cookie_file, altsvc_file, hsts_file, netrc_file);
    } else if (mode == ScenarioRunMode::kTlsCoverage) {
      ApplyTlsFileOptions(easy.get(), crl_file);
    }

    // Compatibility inputs deliberately bypass the mutating postprocessor,
    // so enforce the shared option prefix again at the runtime boundary. The
    // helper still ignores individual CURLcodes: the fuzzer stresses curl
    // rather than treating rejected combinations as harness failures.
    (void)ApplyScenarioOptions(easy.get(), scenario);
  };
  configure_easy();

  if (mode == ScenarioRunMode::kDeepHttpCoverage && altsvc_file.path() != nullptr &&
      HasCanonicalAltSvcAuthority(scenario.host_path())) {
    altsvc_resolve.reset(curl_slist_append(nullptr, kAltSvcLoopbackResolve));
    if (altsvc_resolve != nullptr && curl_easy_setopt(easy.get(), CURLOPT_RESOLVE, altsvc_resolve.get()) == CURLE_OK &&
        curl_easy_setopt(easy.get(), CURLOPT_RESOLVER_START_FUNCTION, &AbortUnexpectedAltSvcResolve) == CURLE_OK) {
      // CONNECT_TO wins before curl consults Alt-Svc. The wildcard DNS-cache
      // entry keeps both the fixed origin and port-80 alternate destinations
      // inside the socket callback; the resolver hook fails closed otherwise.
      (void)curl_easy_setopt(easy.get(), CURLOPT_CONNECT_TO, nullptr);
    }
  }

  if (mode == ScenarioRunMode::kResolverCoverage) {
    // The normal CONNECT_TO baseline deliberately bypasses DNS. This lane
    // removes only that override; OPENSOCKET still returns the in-process
    // socketpair, so no resolved address can receive network traffic.
    (void)curl_easy_setopt(easy.get(), CURLOPT_CONNECT_TO, nullptr);
  }

  const curl::fuzzer::proto::ApiPlan* api_plan =
      mode == ScenarioRunMode::kApiLifecycle && scenario.has_api_plan() ? &scenario.api_plan() : nullptr;
  if (api_plan != nullptr && api_plan->reset_easy()) {
    // Reset deliberately drops every pointer-valued option before its backing
    // list is freed. Reapplying the exact scenario then lets the transfer
    // populate post-reset state instead of turning reset coverage into a
    // guaranteed malformed request.
    curl_easy_reset(easy.get());
    connect_to.reset();
    configure_easy();
  }

  if (api_plan != nullptr) {
    api_lifecycle = std::make_unique<ApiLifecycle>(easy.get(), *api_plan, url);
  }

  {
    // HTTP headers, MIME bodies, TELNET options, and callback userdata are
    // pointer-valued state that libcurl does not copy. Keep their owner around
    // the entire multi-handle drive, then let it detach them while `easy` is
    // still valid. This inner scope is deliberate: easy.reset() below must
    // never run before the owner's destructor clears those options.
    ScenarioRequestData request_data(easy.get(), scenario, mode == ScenarioRunMode::kResolverCoverage);
    if (mode == ScenarioRunMode::kResolverCoverage && !request_data.resolve_entries_ready()) {
      return 0;
    }
    mock->ConfigureRequestData(&request_data);
    const auto drive_mode = api_plan == nullptr ? curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM : api_plan->drive_mode();
    if (drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_PERFORM) {
      mock->DriveEasyScenario(easy.get(), scenario);
    } else if (drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_EVENTS) {
      mock->DriveEasyScenario(easy.get(), scenario, true);
    } else if (drive_mode == curl::fuzzer::proto::API_DRIVE_CONNECT_ONLY) {
      (void)mock->DriveConnectOnlyScenario(easy.get(), scenario);
    } else {
      mock->DriveScenario(
          easy.get(), scenario,
          mode == ScenarioRunMode::kHttp3Coverage || drive_mode == curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET,
          api_plan != nullptr && api_plan->wake_multi(), api_plan != nullptr && api_plan->pause_response_once());
    }
    if (api_lifecycle != nullptr) {
      const bool retains_internal_multi = drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_PERFORM ||
                                          drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_EVENTS ||
                                          drive_mode == curl::fuzzer::proto::API_DRIVE_CONNECT_ONLY;
      api_lifecycle->ProbeTransferResults(retains_internal_multi);
      api_lifecycle->ProbeEasyDuplication();
    } else if (mode != ScenarioRunMode::kFastProtocol) {
      ProbeTransferResults(easy.get());
    }
  }

  // Easy cleanup is the reliable share-detach boundary even if the bounded
  // drive stopped with a connection attached. The lifecycle object—and thus
  // lock callback userdata—outlives it, then releases share-owned caches.
  easy.reset();
  connect_to.reset();
  api_lifecycle.reset();
  return 0;
}

}  // namespace proto_fuzzer
