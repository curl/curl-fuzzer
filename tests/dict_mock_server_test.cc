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

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/dict_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/scenario_limits.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kDefineResponse[] =
    "150 1 definitions retrieved\r\n"
    "151 \"word\" dictd \"fuzz database\"\r\n"
    "A fuzzed definition.\r\n"
    ".\r\n";

struct DictRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string transcript;
  std::string uploaded;
  std::size_t outgoing_chunk_count = 0;
};

int CountOutgoingChunks(CURL * /*easy*/, curl_infotype type, char * /*data*/,
                        std::size_t /*size*/, void *user_data) {
  if (type == CURLINFO_DATA_OUT && user_data != nullptr) {
    ++*static_cast<std::size_t *>(user_data);
  }
  return 0;
}

DictRunResult RunScenario(const Scenario &scenario, const char *url,
                          bool count_outgoing_chunks = false) {
  DictRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_DICT));
  Expect(connect_to != nullptr,
         "DICT baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "DICT URL setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);
  if (count_outgoing_chunks) {
    Expect(curl_easy_setopt(easy.get(), CURLOPT_VERBOSE, 1L) == CURLE_OK &&
               curl_easy_setopt(easy.get(), CURLOPT_DEBUGFUNCTION,
                                &CountOutgoingChunks) == CURLE_OK &&
               curl_easy_setopt(easy.get(), CURLOPT_DEBUGDATA,
                                &result.outgoing_chunk_count) == CURLE_OK,
           "DICT partial-write trace setup failed");
  }

  proto_fuzzer::DictMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.uploaded = server.uploaded_data();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void TestDefineCompletesAtResponseEof() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_DICT);
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable(kDefineResponse);

  const DictRunResult result =
      RunScenario(scenario, "dict://dict.test/d:word");
  Expect(result.code == CURLE_OK,
         "DICT DEFINE did not complete after the server closed the body");
  Expect(result.transcript.find("CLIENT ") != std::string::npos,
         "DICT transfer did not announce the CLIENT identity");
  Expect(result.transcript.find("DEFINE ! word\r\n") != std::string::npos,
         "DICT transfer did not issue the URL-derived DEFINE command");
  Expect(result.transcript.find("QUIT\r\n") != std::string::npos,
         "DICT transfer did not finish its request with QUIT");
  Expect(result.uploaded.empty(),
         "DICT peer treated the response as an upload body");
}

void TestQuitOnlyRequestStillGetsTheScriptedBody() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_DICT);
  scenario.mutable_connection()->add_on_readable("552 no command\r\n.\r\n");

  // A bare slash makes curl send its CLIENT and QUIT lines with an empty
  // command; the peer must still answer so the transfer cannot hang.
  const DictRunResult result = RunScenario(scenario, "dict://dict.test/");
  Expect(result.code == CURLE_OK,
         "skip-path DICT request did not complete at response EOF");
  Expect(result.transcript.find("CLIENT ") != std::string::npos &&
             result.transcript.find("QUIT\r\n") != std::string::npos,
         "skip-path DICT request did not send its empty command and QUIT");
}

void TestMissingScriptStillTerminates() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_DICT);

  const DictRunResult result =
      RunScenario(scenario, "dict://dict.test/match:word:db");
  Expect(result.code == CURLE_OK,
         "DICT transfer without a scripted body did not terminate at EOF");
  Expect(result.transcript.find("MATCH db . word\r\n") != std::string::npos,
         "DICT MATCH command was never issued");
}

void TestPartialWriteProbeIsDeterministic() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_DICT);
  scenario.mutable_connection()->add_on_readable(kDefineResponse);

  const char *inherited = std::getenv("CURL_DBG_SOCK_WPARTIAL");
  const std::optional<std::string> inherited_value =
      inherited == nullptr ? std::nullopt
                           : std::optional<std::string>(inherited);
  Expect(unsetenv("CURL_DBG_SOCK_WPARTIAL") == 0,
         "could not prepare an unset partial-write environment");

  const DictRunResult result =
      RunScenario(scenario, "dict://dict.test/d:partial", true);
  Expect(result.code == CURLE_OK,
         "partial-write DICT transfer did not complete");
  // dict_do formats CLIENT, DEFINE, and QUIT into one sendf() call. More than
  // one DATA_OUT notification therefore proves that physical write was split,
  // rather than counting separate logical DICT commands.
  Expect(result.outgoing_chunk_count > 1,
         "DICT request was not split into deterministic partial writes");
  Expect(std::getenv("CURL_DBG_SOCK_WPARTIAL") == nullptr,
         "DICT drive did not restore an unset partial-write environment");
  Expect(result.transcript.find("DEFINE ! partial\r\n") != std::string::npos,
         "partial-write DICT command was not reconstructed by the peer");

  Expect(setenv("CURL_DBG_SOCK_WPARTIAL", "73", 1) == 0,
         "could not prepare an existing partial-write environment");
  const DictRunResult inherited_result =
      RunScenario(scenario, "dict://dict.test/d:inherited", true);
  Expect(inherited_result.code == CURLE_OK &&
             inherited_result.outgoing_chunk_count > 1,
         "DICT partial-write probe did not run over an inherited value");
  const char *restored = std::getenv("CURL_DBG_SOCK_WPARTIAL");
  Expect(restored != nullptr && std::string(restored) == "73",
         "DICT drive did not restore the inherited partial-write value");

  if (inherited_value.has_value()) {
    (void)setenv("CURL_DBG_SOCK_WPARTIAL", inherited_value->c_str(), 1);
  } else {
    (void)unsetenv("CURL_DBG_SOCK_WPARTIAL");
  }
}

void TestMaximumBoundedRequestCompletes() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_DICT);
  scenario.mutable_connection()->add_on_readable(kDefineResponse);

  constexpr char kAuthorityAndSelector[] = "dict.test/d:";
  std::string host_path = kAuthorityAndSelector;
  host_path.append(proto_fuzzer::scenario_limits::kMaxDictHostPathBytes -
                       host_path.size(),
                   '\'');
  const DictRunResult result =
      RunScenario(scenario, ("dict://" + host_path).c_str(), true);
  Expect(result.code == CURLE_OK && result.outgoing_chunk_count > 1,
         "maximum bounded DICT request did not complete through partial writes");
  Expect(result.transcript.find("DEFINE ! ") != std::string::npos,
         "maximum bounded DICT request did not reach the peer");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestDefineCompletesAtResponseEof();
  TestQuitOnlyRequestStillGetsTheScriptedBody();
  TestMissingScriptStillTerminates();
  TestPartialWriteProbeIsDeterministic();
  TestMaximumBoundedRequestCompletes();
  curl_global_cleanup();
  return 0;
}
