/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/dict_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
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
};

DictRunResult RunScenario(const Scenario &scenario, const char *url) {
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

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestDefineCompletesAtResponseEof();
  TestQuitOnlyRequestStillGetsTheScriptedBody();
  TestMissingScriptStillTerminates();
  curl_global_cleanup();
  return 0;
}
