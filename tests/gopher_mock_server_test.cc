/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/gopher_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::GopherProbeMode;
using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

struct RunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::size_t partial_write_traces = 0;
};

int CountPartialWriteTraces(CURL * /*easy*/, curl_infotype type, char *data,
                            std::size_t size, void *user_data) {
  constexpr std::string_view kPartialWriteTrace = "SIMULATE partial write of";
  if (type == CURLINFO_TEXT && data != nullptr && user_data != nullptr &&
      std::string_view(data, size).find(kPartialWriteTrace) !=
          std::string_view::npos) {
    ++*static_cast<std::size_t *>(user_data);
  }
  return 0;
}

RunResult RunScenario(GopherProbeMode mode, const std::string &selector) {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_GOPHER);
  scenario.set_gopher_probe_mode(mode);
  scenario.mutable_connection()->set_initial_response("gopher response\r\n");

  RunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "Gopher test could not allocate an easy handle");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_GOPHER));
  Expect(connect_to != nullptr, "Gopher baseline lost CONNECT_TO state");
  const std::string url = "gopher://tls.test/1/" + selector;
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url.c_str()) == CURLE_OK &&
             curl_easy_setopt(easy.get(), CURLOPT_VERBOSE, 1L) == CURLE_OK &&
             curl_easy_setopt(easy.get(), CURLOPT_DEBUGFUNCTION,
                              &CountPartialWriteTraces) == CURLE_OK &&
             curl_easy_setopt(easy.get(), CURLOPT_DEBUGDATA,
                              &result.partial_write_traces) == CURLE_OK,
         "Gopher test could not configure tracing");

  proto_fuzzer::GopherMockServer server(mode);
  server.Install(easy.get());
  result.code = server.DriveScenario(easy.get(), scenario);

  easy.reset();
  connect_to.reset();
  return result;
}

void TestPartialWriteWithoutDeadline() {
  const char *inherited = std::getenv("CURL_DBG_SOCK_WPARTIAL");
  const std::optional<std::string> inherited_value =
      inherited == nullptr ? std::nullopt
                           : std::optional<std::string>(inherited);
  Expect(unsetenv("CURL_DBG_SOCK_WPARTIAL") == 0,
         "could not prepare an unset partial-write environment");

  const RunResult result =
      RunScenario(curl::fuzzer::proto::GOPHER_PROBE_PARTIAL_WRITE_NO_TIMEOUT,
                  std::string(160, 'p'));
  Expect(result.code == CURLE_OK && result.partial_write_traces > 1,
         "Gopher no-timeout probe did not split and complete its selector");
  Expect(std::getenv("CURL_DBG_SOCK_WPARTIAL") == nullptr,
         "Gopher probe did not restore an unset environment value");

  Expect(setenv("CURL_DBG_SOCK_WPARTIAL", "73", 1) == 0,
         "could not prepare an inherited partial-write value");
  const RunResult inherited_result =
      RunScenario(curl::fuzzer::proto::GOPHER_PROBE_PARTIAL_WRITE_NO_TIMEOUT,
                  std::string(160, 'q'));
  const char *restored = std::getenv("CURL_DBG_SOCK_WPARTIAL");
  Expect(inherited_result.code == CURLE_OK &&
             inherited_result.partial_write_traces > 1 && restored != nullptr &&
             std::string(restored) == "73",
         "Gopher probe did not restore the inherited environment value");

  if (inherited_value.has_value()) {
    (void)setenv("CURL_DBG_SOCK_WPARTIAL", inherited_value->c_str(), 1);
  } else {
    (void)unsetenv("CURL_DBG_SOCK_WPARTIAL");
  }
}

void TestSaturatedSelectorTimesOut() {
  const RunResult result = RunScenario(
      curl::fuzzer::proto::GOPHER_PROBE_SEND_TIMEOUT, "selector-timeout");
  Expect(result.code == CURLE_OPERATION_TIMEDOUT,
         "saturated Gopher selector did not reach its fixed timeout");
}

} // namespace

int main() {
  if (curl_global_trace("TCP") != CURLE_OK) {
    Fail("curl_global_trace failed");
  }
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestPartialWriteWithoutDeadline();
  TestSaturatedSelectorTimesOut();
  curl_global_cleanup();
  return 0;
}
