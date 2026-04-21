/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of ScenarioRunner::Run.

#include "proto_fuzzer/scenario_runner.h"

#include <curl/curl.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/transfer.h"

namespace proto_fuzzer {

namespace {

/// @brief RAII wrapper for CURL* easy handles.
struct CurlEasyDeleter {
  void operator()(CURL* h) const noexcept {
    if (h) curl_easy_cleanup(h);
  }
};
using CurlEasyPtr = std::unique_ptr<CURL, CurlEasyDeleter>;

// Cap per-scenario response chunks so a mutator that creates thousands of
// tiny on_readable entries can't dominate runtime.
constexpr std::size_t kMaxResponseChunks = 16;

bool HasUrl(const curl::fuzzer::proto::Scenario& scenario) {
  for (const auto& opt : scenario.options()) {
    if (opt.option_id() == curl::fuzzer::proto::CURLOPT_URL &&
        opt.value_case() == curl::fuzzer::proto::SetOption::ValueCase::kStringValue) {
      return true;
    }
  }
  return false;
}

}  // namespace

/// @class proto_fuzzer::ScenarioRunner
/// @brief Executes one Scenario end-to-end: applies options, seeds a mock
///        server, runs the transfer. Instances are cheap; create one per
///        fuzz case so per-scenario state (owned strings, mock fds) is torn
///        down cleanly.

/// Default-construct an empty runner. All state is set up inside Run().
ScenarioRunner::ScenarioRunner() = default;

/// Default destructor; per-run state is local to Run() so nothing to tear
/// down at instance scope.
ScenarioRunner::~ScenarioRunner() = default;

/// Run the scenario. Applies baseline + per-option setopt calls, seeds the
/// mock server from scenario.connection(), and drives a single transfer to
/// completion.
/// @param scenario The Scenario describing the curl operations to perform.
/// @return 0 on normal completion (including curl errors that aren't harness
///         failures). The libFuzzer entrypoint doesn't care about the return
///         value; it's there for tests.
int ScenarioRunner::Run(const curl::fuzzer::proto::Scenario& scenario) {
  // Scenarios without a URL can't drive a transfer; skip early so libcurl
  // doesn't fail with a generic error we'd have to filter out.
  if (!HasUrl(scenario)) {
    return 0;
  }

  CurlEasyPtr easy(curl_easy_init());
  if (!easy) {
    return 0;
  }

  std::vector<std::string> string_storage;
  string_storage.reserve(scenario.options_size());

  struct curl_slist* connect_to = ApplyBaselineOptions(easy.get());

  // Install the mock server on the easy handle.
  MockServer mock;
  mock.Install(easy.get());

  for (const auto& option : scenario.options()) {
    // Intentionally ignore per-option CURLcode: the fuzzer's job is to stress
    // curl, not to validate that every option is applied cleanly.
    (void)ApplySetOption(easy.get(), option, &string_storage);
  }

  // Set up the scripted responses.
  const auto& conn = scenario.connection();
  std::vector<std::string> chunks;
  const int chunk_budget = static_cast<int>(std::min<std::size_t>(kMaxResponseChunks, conn.on_readable_size()));
  chunks.reserve(chunk_budget);
  for (int i = 0; i < chunk_budget; ++i) {
    chunks.emplace_back(conn.on_readable(i));
  }
  mock.SetScript(conn.initial_response(), std::move(chunks));

  // Drive the transfer until completion or timeout.
  (void)DriveTransfer(easy.get(), mock);
  easy.reset();  // Free the easy handle before the slist it referenced.
  curl_slist_free_all(connect_to);
  return 0;
}

}  // namespace proto_fuzzer
