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
#include "proto_fuzzer/websocket_mock_server.h"
#include "proto_fuzzer/ws_frame.h"

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

bool IsWebSocketScheme(curl::fuzzer::proto::Scheme scheme) {
  return scheme == curl::fuzzer::proto::SCHEME_WS || scheme == curl::fuzzer::proto::SCHEME_WSS;
}

// If the scenario sets CONNECT_ONLY to 2, the caller wants to drive
// curl_ws_recv/send manually after the handshake — use manual-delivery mode.
bool ScenarioRequestsManualWsDrive(const curl::fuzzer::proto::Scenario& scenario) {
  for (const auto& opt : scenario.options()) {
    if (opt.option_id() != curl::fuzzer::proto::CURLOPT_CONNECT_ONLY) {
      continue;
    }
    if (opt.value_case() == curl::fuzzer::proto::SetOption::ValueCase::kUintValue && opt.uint_value() == 2) {
      return true;
    }
  }
  return false;
}

std::vector<std::string> BuildChunkList(const curl::fuzzer::proto::Connection& conn) {
  std::vector<std::string> chunks;
  chunks.reserve(kMaxResponseChunks);
  const std::size_t raw_budget = std::min<std::size_t>(kMaxResponseChunks, conn.on_readable_size());
  for (std::size_t i = 0; i < raw_budget; ++i) {
    chunks.emplace_back(conn.on_readable(i));
  }
  const std::size_t frame_budget = kMaxResponseChunks - chunks.size();
  const std::size_t frame_count = std::min<std::size_t>(frame_budget, conn.server_frames_size());
  for (std::size_t i = 0; i < frame_count; ++i) {
    chunks.emplace_back(SerializeWebSocketFrame(conn.server_frames(static_cast<int>(i))));
  }
  return chunks;
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

/// Run the scenario. Applies baseline + per-option setopt calls, builds the
/// URL from scenario.scheme + scenario.host_path, seeds the mock server from
/// scenario.connection(), and drives a single transfer to completion.
/// @param scenario The Scenario describing the curl operations to perform.
/// @return 0 on normal completion (including curl errors that aren't harness
///         failures). The libFuzzer entrypoint doesn't care about the return
///         value; it's there for tests.
int ScenarioRunner::Run(const curl::fuzzer::proto::Scenario& scenario) {
  const char* prefix = SchemePrefix(scenario.scheme());
  if (prefix == nullptr || scenario.host_path().empty()) {
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

  const bool is_websocket = IsWebSocketScheme(scenario.scheme());
  const bool manual_ws_drive = is_websocket && ScenarioRequestsManualWsDrive(scenario);

  // Variant-style dispatch: exactly one of these owns the socket trampolines.
  MockServer http_mock;
  WebSocketMockServer ws_mock;
  if (is_websocket) {
    ws_mock.Install(easy.get());
    ws_mock.SetManualDelivery(manual_ws_drive);
  } else {
    http_mock.Install(easy.get());
  }

  for (const auto& option : scenario.options()) {
    // Intentionally ignore per-option CURLcode: the fuzzer's job is to stress
    // curl, not to validate that every option is applied cleanly.
    (void)ApplySetOption(easy.get(), option, &string_storage);
  }

  const auto& conn = scenario.connection();
  std::vector<std::string> chunks = BuildChunkList(conn);

  if (is_websocket) {
    // In WS mode the initial_response field is unused (we dynamically generate
    // the 101 response from curl's own Upgrade request).
    ws_mock.SetFrames(std::move(chunks));

    // Own the multi so the connection can stay alive past handshake
    // completion for DriveWebSocketFrames (manual mode only).
    CURLM* multi = curl_multi_init();
    if (multi != nullptr) {
      if (curl_multi_add_handle(multi, easy.get()) == CURLM_OK) {
        (void)DriveWebSocketTransferWithMulti(multi, easy.get(), ws_mock);
        if (manual_ws_drive) {
          DriveWebSocketFrames(easy.get(), ws_mock);
        }
        curl_multi_remove_handle(multi, easy.get());
      }
      curl_multi_cleanup(multi);
    }
  } else {
    http_mock.SetScript(conn.initial_response(), std::move(chunks));
    (void)DriveTransfer(easy.get(), http_mock);
  }

  easy.reset();
  curl_slist_free_all(connect_to);
  return 0;
}

}  // namespace proto_fuzzer
