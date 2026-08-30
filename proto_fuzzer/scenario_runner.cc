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

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/telnet_mock_server.h"
#include "proto_fuzzer/websocket_mock_server.h"

namespace proto_fuzzer {

namespace {

/// @brief RAII wrapper for CURL* easy handles.
struct CurlEasyDeleter {
  void operator()(CURL* h) const noexcept {
    if (h) curl_easy_cleanup(h);
  }
};
using CurlEasyPtr = std::unique_ptr<CURL, CurlEasyDeleter>;

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
    case curl::fuzzer::proto::SCHEME_UNSPECIFIED:
    default:
      return nullptr;
  }
}

/// Pick the MockServerBase subclass to use for 'scenario'. The scheme is the
/// sole classifier today: WS / WSS → WebSocketMockServer, TELNET → the
/// synchronous TelnetMockServer, HTTP / HTTPS → MockServer. Returns nullptr
/// for unsupported / unspecified schemes so the runner can skip cleanly.
std::unique_ptr<MockServerBase> MakeMockServerForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  switch (scenario.scheme()) {
    case curl::fuzzer::proto::SCHEME_HTTP:
    case curl::fuzzer::proto::SCHEME_HTTPS:
      return std::make_unique<MockServer>();
    case curl::fuzzer::proto::SCHEME_WS:
    case curl::fuzzer::proto::SCHEME_WSS:
      return std::make_unique<WebSocketMockServer>();
    case curl::fuzzer::proto::SCHEME_TELNET:
      return std::make_unique<TelnetMockServer>();
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

/// Run the scenario. Classifies the scheme to pick a MockServer subclass,
/// applies baseline + per-option setopt calls, builds the URL from
/// scenario.scheme + scenario.host_path, and drives the transfer via the
/// mock's own DriveScenario.
/// @param scenario The Scenario describing the curl operations to perform.
/// @param probe_transfer_results Whether to exercise post-transfer easy-handle
///        result APIs. The multi driver always consumes curl_multi_info_read;
///        this flag controls only the separate getinfo/header probes here.
/// @return 0 on normal completion (including curl errors that aren't harness
///         failures). The libFuzzer entrypoint doesn't care about the return
///         value; it's there for tests.
int ScenarioRunner::Run(const curl::fuzzer::proto::Scenario& scenario, bool probe_transfer_results) {
  const char* prefix = SchemePrefix(scenario.scheme());
  if (prefix == nullptr || scenario.host_path().empty()) {
    return 0;
  }

  std::unique_ptr<MockServerBase> mock = MakeMockServerForScenario(scenario);
  if (!mock) {
    return 0;
  }

  CurlEasyPtr easy(curl_easy_init());
  if (!easy) {
    return 0;
  }

  struct curl_slist* connect_to = ApplyBaselineOptions(easy.get(), scenario.scheme());

  std::string url = std::string(prefix) + "://" + scenario.host_path();
  curl_easy_setopt(easy.get(), CURLOPT_URL, url.c_str());

  mock->Install(easy.get());

  // Compatibility inputs deliberately bypass the mutating postprocessor, so
  // enforce the shared option prefix again at the runtime boundary. The helper
  // still ignores individual CURLcodes: the fuzzer stresses curl rather than
  // treating rejected option combinations as harness failures.
  (void)ApplyScenarioOptions(easy.get(), scenario);

  {
    // HTTP headers, MIME bodies, TELNET options, and callback userdata are
    // pointer-valued state that libcurl does not copy. Keep their owner around
    // the entire multi-handle drive, then let it detach them while `easy` is
    // still valid. This inner scope is deliberate: easy.reset() below must
    // never run before the owner's destructor clears those options.
    ScenarioRequestData request_data(easy.get(), scenario);
    mock->ConfigureRequestData(&request_data);
    mock->DriveScenario(easy.get(), scenario);
    if (probe_transfer_results) {
      ProbeTransferResults(easy.get());
    }
  }

  easy.reset();
  curl_slist_free_all(connect_to);
  return 0;
}

}  // namespace proto_fuzzer
