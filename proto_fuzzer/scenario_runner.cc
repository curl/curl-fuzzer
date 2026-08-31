/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of ScenarioRunner::Run.

#include "proto_fuzzer/scenario_runner.h"

#include <curl/curl.h>
#include <curl/header.h>

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/api_lifecycle.h"
#include "proto_fuzzer/ftp_mock_server.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/telnet_mock_server.h"
#include "proto_fuzzer/tftp_mock_server.h"
#include "proto_fuzzer/websocket_mock_server.h"

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
#include "proto_fuzzer/h2_proxy_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"
#endif

namespace proto_fuzzer {

namespace {

/// @brief RAII wrapper for CURL* easy handles.
struct CurlEasyDeleter {
  void operator()(CURL* h) const noexcept {
    if (h) curl_easy_cleanup(h);
  }
};
using CurlEasyPtr = std::unique_ptr<CURL, CurlEasyDeleter>;

/// @brief RAII wrapper for caller-owned curl_slist option data.
struct CurlSlistDeleter {
  void operator()(curl_slist* list) const noexcept { curl_slist_free_all(list); }
};
using CurlSlistPtr = std::unique_ptr<curl_slist, CurlSlistDeleter>;

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

  switch (scenario.scheme()) {
    case curl::fuzzer::proto::SCHEME_HTTP:
      return std::make_unique<MockServer>();
    case curl::fuzzer::proto::SCHEME_HTTPS:
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
      if (mode == ScenarioRunMode::kTlsCoverage) {
        return std::make_unique<TlsMockServer>();
      }
#else
      (void)mode;
#endif
      return std::make_unique<MockServer>();
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

/// @class proto_fuzzer::ScenarioRunner
/// @brief Executes one Scenario end-to-end: applies options, picks a mock
///        server for the scheme, and hands off to the mock's DriveScenario.
///        Instances are cheap; create one per fuzz case so per-scenario state
///        is torn down cleanly.

/// Default-construct an empty runner. All state is set up inside Run().
ScenarioRunner::ScenarioRunner() = default;

/// Default destructor; per-run state is local to Run() so nothing to tear
/// down at instance scope.
ScenarioRunner::~ScenarioRunner() = default;

/// Implement the bounded orchestration contract documented on Run's public
/// declaration; keeping argument docs there avoids two drifting descriptions.
int ScenarioRunner::Run(const curl::fuzzer::proto::Scenario& scenario, ScenarioRunMode mode) {
  const char* prefix = SchemePrefix(scenario.scheme());
  if (prefix == nullptr || scenario.host_path().empty()) {
    return 0;
  }

  std::unique_ptr<MockServerBase> mock = MakeMockServerForScenario(scenario, mode);
  if (!mock) {
    return 0;
  }

  // Declaration order is an ownership invariant: reverse destruction keeps
  // CONNECT_TO storage and share callback userdata alive through easy cleanup.
  // This matters for incomplete transfers, where an explicit share detach can
  // be rejected while easy cleanup can still release the reference safely.
  std::unique_ptr<ApiLifecycle> api_lifecycle;
  CurlSlistPtr connect_to;
  CurlEasyPtr easy(curl_easy_init());
  if (!easy) {
    return 0;
  }

  std::string url = std::string(prefix) + "://" + scenario.host_path();
  const auto configure_easy = [&] {
    connect_to.reset(ApplyBaselineOptions(easy.get(), scenario.scheme()));
    curl_easy_setopt(easy.get(), CURLOPT_URL, url.c_str());
    mock->Install(easy.get());

    // Compatibility inputs deliberately bypass the mutating postprocessor,
    // so enforce the shared option prefix again at the runtime boundary. The
    // helper still ignores individual CURLcodes: the fuzzer stresses curl
    // rather than treating rejected combinations as harness failures.
    (void)ApplyScenarioOptions(easy.get(), scenario);
  };
  configure_easy();

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
    ScenarioRequestData request_data(easy.get(), scenario);
    mock->ConfigureRequestData(&request_data);
    const auto drive_mode = api_plan == nullptr ? curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM : api_plan->drive_mode();
    if (drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_PERFORM) {
      mock->DriveEasyScenario(easy.get(), scenario);
    } else {
      mock->DriveScenario(easy.get(), scenario, drive_mode == curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET,
                          api_plan != nullptr && api_plan->wake_multi());
    }
    if (api_lifecycle != nullptr) {
      api_lifecycle->ProbeTransferResults(drive_mode == curl::fuzzer::proto::API_DRIVE_EASY_PERFORM);
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
