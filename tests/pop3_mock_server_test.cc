/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/pop3_mock_server.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kMessageBody[] = "Hello from POP3\r\n";

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct Pop3RunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  std::size_t active_pollset_probes = 0;
};

Pop3RunResult RunScenario(const Scenario &scenario, const char *url) {
  Pop3RunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_POP3));
  Expect(connect_to != nullptr,
         "POP3 baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "POP3 URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "POP3 write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "POP3 write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::Pop3MockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.active_pollset_probes = server.active_pollset_probe_count();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void AddLoginOptions(Scenario *scenario) {
  auto *username = scenario->add_options();
  username->set_option_id(curl::fuzzer::proto::CURLOPT_USERNAME);
  username->set_string_value("fuzz");
  auto *password = scenario->add_options();
  password->set_option_id(curl::fuzzer::proto::CURLOPT_PASSWORD);
  password->set_string_value("secret");
}

void AddGreetingAndCapability(Scenario *scenario) {
  auto *connection = scenario->mutable_connection();
  connection->set_initial_response("+OK pop3.test ready\r\n");
  connection->add_on_readable("+OK capabilities\r\nUSER\r\n.\r\n");
}

void TestRetrMultilineMessage() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/1");
  scenario.set_probe_multi_pollset(true);
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable("+OK user accepted\r\n");
  connection->add_on_readable("+OK pass accepted\r\n");
  connection->add_on_readable(
      "+OK 17 octets\r\nHello from POP3\r\n.\r\n");

  const Pop3RunResult result = RunScenario(scenario, "pop3://pop3.test/1");
  Expect(result.code == CURLE_OK, "POP3 RETR did not complete");
  Expect(result.body == kMessageBody,
         "POP3 RETR produced the wrong message body");
  Expect(result.transcript.find("CAPA\r\n") != std::string::npos,
         "POP3 transfer did not issue CAPA");
  Expect(result.transcript.find("USER fuzz\r\n") != std::string::npos,
         "POP3 transfer did not issue USER");
  Expect(result.transcript.find("PASS secret\r\n") != std::string::npos,
         "POP3 transfer did not issue PASS");
  Expect(result.transcript.find("RETR 1\r\n") != std::string::npos,
         "POP3 transfer did not issue RETR");
  Expect(result.transcript.find("QUIT\r\n") != std::string::npos,
         "POP3 teardown did not issue QUIT");
  Expect(result.active_pollset_probes != 0,
         "POP3 opt-in did not probe a live protocol pollset");
}

void TestListMultilineMailbox() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/");
  AddGreetingAndCapability(&scenario);
  scenario.mutable_connection()->add_on_readable(
      "+OK 2 messages\r\n1 17\r\n2 20\r\n.\r\n");

  const Pop3RunResult result = RunScenario(scenario, "pop3://pop3.test/");
  Expect(result.code == CURLE_OK, "POP3 LIST did not complete");
  Expect(result.body == "1 17\r\n2 20\r\n",
         "POP3 LIST produced the wrong multi-line listing");
  Expect(result.transcript.find("LIST\r\n") != std::string::npos,
         "POP3 listing did not issue LIST");
  Expect(result.active_pollset_probes == 0,
         "POP3 default path unexpectedly issued a pollset probe");
}

void TestUserDenialIsTerminal() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/1");
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  scenario.mutable_connection()->add_on_readable("-ERR no such user\r\n");

  const Pop3RunResult result = RunScenario(scenario, "pop3://pop3.test/1");
  Expect(result.code == CURLE_LOGIN_DENIED,
         "POP3 USER denial did not produce a login error");
  Expect(result.transcript.find("USER fuzz\r\n") != std::string::npos,
         "POP3 denial scenario never issued USER");
  Expect(result.transcript.find("PASS ") == std::string::npos,
         "POP3 issued PASS after USER was rejected");
  Expect(result.body.empty(),
         "POP3 denial scenario unexpectedly produced a body");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestRetrMultilineMessage();
  TestListMultilineMailbox();
  TestUserDenialIsTerminal();
  curl_global_cleanup();
  return 0;
}
