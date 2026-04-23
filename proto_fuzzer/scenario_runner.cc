/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of ScenarioRunner::Run.

#include "proto_fuzzer/scenario_runner.h"

#include <curl/curl.h>

#include <memory>
#include <string>
#include <vector>

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/option_apply.h"
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
    case curl::fuzzer::proto::SCHEME_UNSPECIFIED:
    default:
      return nullptr;
  }
}

/// Pick the MockServerBase subclass to use for 'scenario'. The scheme is the
/// sole classifier today: WS / WSS → WebSocketMockServer, HTTP / HTTPS →
/// MockServer. Returns nullptr for unsupported / unspecified schemes so the
/// runner can skip the scenario cleanly.
std::unique_ptr<MockServerBase> MakeMockServerForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  switch (scenario.scheme()) {
    case curl::fuzzer::proto::SCHEME_HTTP:
    case curl::fuzzer::proto::SCHEME_HTTPS:
      return std::make_unique<MockServer>();
    case curl::fuzzer::proto::SCHEME_WS:
    case curl::fuzzer::proto::SCHEME_WSS:
      return std::make_unique<WebSocketMockServer>();
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
/// @return 0 on normal completion (including curl errors that aren't harness
///         failures). The libFuzzer entrypoint doesn't care about the return
///         value; it's there for tests.
int ScenarioRunner::Run(const curl::fuzzer::proto::Scenario& scenario) {
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

  std::vector<std::string> string_storage;
  string_storage.reserve(scenario.options_size());

  struct curl_slist* connect_to = ApplyBaselineOptions(easy.get());

  std::string url = std::string(prefix) + "://" + scenario.host_path();
  curl_easy_setopt(easy.get(), CURLOPT_URL, url.c_str());

  mock->Install(easy.get());

  for (const auto& option : scenario.options()) {
    // Intentionally ignore per-option CURLcode: the fuzzer's job is to stress
    // curl, not to validate that every option is applied cleanly.
    (void)ApplySetOption(easy.get(), option, &string_storage);
  }

  mock->DriveScenario(easy.get(), scenario);

  easy.reset();
  curl_slist_free_all(connect_to);
  return 0;
}

}  // namespace proto_fuzzer
