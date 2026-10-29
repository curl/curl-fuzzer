/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/allocation_fault_injection.h"
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
  if (scenario.scheme() == curl::fuzzer::proto::SCHEME_POP3 &&
      scenario.pop3_starttls_filter_allocation_failure()) {
    (void)curl_easy_setopt(easy.get(), CURLOPT_USE_SSL,
                           static_cast<long>(CURLUSESSL_ALL));
  }

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

void AddStringOption(Scenario *scenario,
                     curl::fuzzer::proto::CurlOptionId option_id,
                     std::string_view value) {
  auto *option = scenario->add_options();
  option->set_option_id(option_id);
  option->set_string_value(std::string(value));
}

void AddBoolOption(Scenario *scenario,
                   curl::fuzzer::proto::CurlOptionId option_id, bool value) {
  auto *option = scenario->add_options();
  option->set_option_id(option_id);
  option->set_bool_value(value);
}

void AddUintOption(Scenario *scenario,
                   curl::fuzzer::proto::CurlOptionId option_id,
                   std::uint64_t value) {
  auto *option = scenario->add_options();
  option->set_option_id(option_id);
  option->set_uint_value(value);
}

void ExpectTranscript(const Pop3RunResult &result, std::string_view expected,
                      const char *message) {
  if (result.transcript != expected) {
    std::cerr << message << "\nExpected:\n"
              << expected << "Actual:\n"
              << result.transcript;
    std::exit(1);
  }
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
  connection->add_on_readable("+OK 17 octets\r\nHello from POP3\r\n.\r\n");

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

void TestCramMd5AuthenticationAndRetrieval() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/1");
  AddLoginOptions(&scenario);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=CRAM-MD5");
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("+OK pop3.test ready\r\n");
  connection->add_on_readable(
      "+OK capabilities\r\nSASL CRAM-MD5\r\nUSER\r\n.\r\n");
  connection->add_on_readable(
      "+ PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UuZXhhbXBsZS5uZXQ+\r\n");
  connection->add_on_readable("+OK authentication succeeded\r\n");
  connection->add_on_readable("+OK 17 octets\r\nHello from POP3\r\n.\r\n");

  const Pop3RunResult result = RunScenario(scenario, "pop3://pop3.test/1");
  Expect(result.code == CURLE_OK, "POP3 CRAM-MD5 retrieval did not complete");
  ExpectTranscript(
      result,
      "CAPA\r\n"
      "AUTH CRAM-MD5\r\n"
      "ZnV6eiBhYmI3ZGU0OWM1OGRhMTQxNjg2NmJiYzU2NmI3ZTU4NQ==\r\n"
      "RETR 1\r\n"
      "QUIT\r\n",
      "POP3 CRAM-MD5 transcript differed from the complete auth and RETR "
      "exchange");
  Expect(result.body == kMessageBody,
         "POP3 CRAM-MD5 retrieval produced the wrong body");
}

void TestInvalidCramChallengeFallsBackToPlain() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/1");
  AddLoginOptions(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("+OK pop3.test ready\r\n");
  connection->add_on_readable(
      "+OK capabilities\r\nSASL CRAM-MD5 PLAIN\r\nUSER\r\n.\r\n");
  connection->add_on_readable("+ !\r\n");
  connection->add_on_readable("-ERR authentication exchange cancelled\r\n");
  connection->add_on_readable("+ \r\n");
  connection->add_on_readable("+OK authentication succeeded\r\n");
  connection->add_on_readable("+OK 17 octets\r\nHello from POP3\r\n.\r\n");

  const Pop3RunResult result = RunScenario(scenario, "pop3://pop3.test/1");
  Expect(result.code == CURLE_OK,
         "POP3 did not fall back from malformed CRAM-MD5 to PLAIN");
  ExpectTranscript(
      result,
      "CAPA\r\n"
      "AUTH CRAM-MD5\r\n"
      "*\r\n"
      "AUTH PLAIN\r\n"
      "AGZ1enoAc2VjcmV0\r\n"
      "RETR 1\r\n"
      "QUIT\r\n",
      "POP3 CRAM-MD5 fallback transcript was incomplete or out of order");
  Expect(result.body == kMessageBody,
         "POP3 CRAM-MD5 fallback returned the wrong body");
}

void TestPlainAuthenticationUsesSaslInitialResponse() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/1");
  AddLoginOptions(&scenario);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=PLAIN");
  AddBoolOption(&scenario, curl::fuzzer::proto::CURLOPT_SASL_IR, true);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("+OK pop3.test ready\r\n");
  connection->add_on_readable(
      "+OK capabilities\r\nSASL PLAIN\r\nUSER\r\n.\r\n");
  connection->add_on_readable("+OK authentication succeeded\r\n");
  connection->add_on_readable("+OK 17 octets\r\nHello from POP3\r\n.\r\n");

  const Pop3RunResult result = RunScenario(scenario, "pop3://pop3.test/1");
  Expect(result.code == CURLE_OK,
         "POP3 AUTH PLAIN with SASL-IR did not complete");
  ExpectTranscript(result,
                   "CAPA\r\n"
                   "AUTH PLAIN AGZ1enoAc2VjcmV0\r\n"
                   "RETR 1\r\n"
                   "QUIT\r\n",
                   "POP3 SASL-IR transcript did not keep the PLAIN payload "
                   "on the AUTH command");
}

void TestApopAuthenticationAndDenial() {
  Scenario success;
  success.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  success.set_host_path("pop3.test/1");
  AddLoginOptions(&success);
  AddStringOption(&success, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=+APOP");
  auto *success_connection = success.mutable_connection();
  success_connection->set_initial_response("+OK pop3.test ready <id@host>\r\n");
  success_connection->add_on_readable("+OK capabilities\r\n.\r\n");
  success_connection->add_on_readable("+OK authentication succeeded\r\n");
  success_connection->add_on_readable(
      "+OK 17 octets\r\nHello from POP3\r\n.\r\n");

  const Pop3RunResult success_result =
      RunScenario(success, "pop3://pop3.test/1");
  Expect(success_result.code == CURLE_OK,
         "POP3 APOP retrieval did not complete");
  ExpectTranscript(success_result,
                   "CAPA\r\n"
                   "APOP fuzz 29c9a05ed81d1bad79e3da0823968960\r\n"
                   "RETR 1\r\n"
                   "QUIT\r\n",
                   "POP3 APOP success transcript was incomplete or used the "
                   "wrong timestamp digest");

  Scenario denied;
  denied.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  denied.set_host_path("pop3.test/1");
  AddLoginOptions(&denied);
  AddStringOption(&denied, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=+APOP");
  auto *denied_connection = denied.mutable_connection();
  denied_connection->set_initial_response("+OK pop3.test ready <id@host>\r\n");
  denied_connection->add_on_readable("+OK capabilities\r\n.\r\n");
  denied_connection->add_on_readable("-ERR invalid digest\r\n");

  const Pop3RunResult denied_result = RunScenario(denied, "pop3://pop3.test/1");
  Expect(denied_result.code == CURLE_LOGIN_DENIED,
         "POP3 APOP denial did not produce a login error");
  ExpectTranscript(denied_result,
                   "CAPA\r\n"
                   "APOP fuzz 29c9a05ed81d1bad79e3da0823968960\r\n",
                   "POP3 APOP denial issued unexpected commands");
  Expect(denied_result.body.empty(),
         "POP3 APOP denial unexpectedly produced a body");
}

void TestUnavailableScramMechanismIsRejected() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/1");
  AddLoginOptions(&scenario);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=SCRAM-SHA-256");
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("+OK pop3.test ready\r\n");
  connection->add_on_readable(
      "+OK capabilities\r\nSASL SCRAM-SHA-256\r\nUSER\r\n.\r\n");

  const Pop3RunResult result = RunScenario(scenario, "pop3://pop3.test/1");
  Expect(result.code == CURLE_LOGIN_DENIED,
         "POP3 unavailable SCRAM mechanism was not rejected");
  ExpectTranscript(
      result, "CAPA\r\n",
      "POP3 unavailable SCRAM path issued AUTH or another command");
}

void TestLongRetrCommandWithReceiveBufferPressure() {
  const std::string message_id(6144, 'A');
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/" + message_id);
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->mutable_backpressure()->set_recv_buf_bytes(2048);
  connection->add_on_readable("+OK user accepted\r\n");
  connection->add_on_readable("+OK pass accepted\r\n");
  connection->add_on_readable("+OK 17 octets\r\nHello from POP3\r\n.\r\n");

  const std::string url = "pop3://pop3.test/" + message_id;
  const Pop3RunResult result = RunScenario(scenario, url.c_str());
  Expect(result.code == CURLE_OK,
         "POP3 long RETR did not complete under receive-buffer pressure");
  Expect(result.body == kMessageBody,
         "POP3 long RETR pressure path produced the wrong body");
  Expect(result.transcript.find("RETR " + message_id + "\r\n") !=
             std::string::npos,
         "POP3 pressure path did not drain the complete long RETR command");
}

void TestRejectedStartTlsDoesNotArmAllocationFailure() {
  proto_fuzzer::allocation_fault_injection::Reset();
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  scenario.set_host_path("pop3.test/1");
  scenario.set_pop3_starttls_filter_allocation_failure(true);
  AddLoginOptions(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("+OK pop3.test ready\r\n");
  connection->add_on_readable("+OK capabilities\r\nSTLS\r\nUSER\r\n.\r\n");
  connection->add_on_readable("-ERR TLS unavailable\r\n");

  const Pop3RunResult result = RunScenario(scenario, "pop3://pop3.test/1");
  const auto statistics =
      proto_fuzzer::allocation_fault_injection::GetStatistics();
  Expect(result.code == CURLE_USE_SSL_FAILED,
         "POP3 rejected STLS did not report the required upgrade failure");
  ExpectTranscript(result, "CAPA\r\nSTLS\r\n",
                   "POP3 rejected STLS issued unexpected commands");
  Expect(!statistics.armed && statistics.configured_failures == 0 &&
             statistics.injected_failures == 0,
         "POP3 rejected STLS armed a semantic allocation failure");
  proto_fuzzer::allocation_fault_injection::Reset();
}

void TestUidlAndTopMultilineBoundaries() {
  Scenario uidl;
  uidl.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  uidl.set_host_path("pop3.test/");
  AddStringOption(&uidl, curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST, "UIDL");
  AddGreetingAndCapability(&uidl);
  uidl.mutable_connection()->add_on_readable(
      "+OK unique ids follow\r\n1 whqtswO00QHEf7kmZ\r\n"
      "2 QhdPYR:00WBw1Ph7x7\r\n.\r\n");

  const Pop3RunResult uidl_result = RunScenario(uidl, "pop3://pop3.test/");
  Expect(uidl_result.code == CURLE_OK,
         "POP3 UIDL mailbox request did not complete");
  ExpectTranscript(uidl_result, "CAPA\r\nUIDL\r\nQUIT\r\n",
                   "POP3 UIDL transcript was incomplete or out of order");
  Expect(uidl_result.body == "1 whqtswO00QHEf7kmZ\r\n2 QhdPYR:00WBw1Ph7x7\r\n",
         "POP3 UIDL returned the wrong multiline body");

  Scenario top;
  top.set_scheme(curl::fuzzer::proto::SCHEME_POP3);
  top.set_host_path("pop3.test/");
  AddStringOption(&top, curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST, "TOP 1 0");
  AddUintOption(&top, curl::fuzzer::proto::CURLOPT_BUFFERSIZE, 1024);
  AddGreetingAndCapability(&top);
  const std::string long_line(1300, 'A');
  top.mutable_connection()->add_on_readable(
      "+OK top follows\r\n..dot-stuffed\r\n" + long_line +
      "\r\n...two-leading-dots\r\n.\r\n");

  const Pop3RunResult top_result = RunScenario(top, "pop3://pop3.test/");
  Expect(top_result.code == CURLE_OK,
         "POP3 TOP boundary response did not complete");
  ExpectTranscript(top_result, "CAPA\r\nTOP 1 0\r\nQUIT\r\n",
                   "POP3 TOP transcript was incomplete or out of order");
  Expect(top_result.body ==
             ".dot-stuffed\r\n" + long_line + "\r\n..two-leading-dots\r\n",
         "POP3 TOP did not preserve long-body boundaries and dot unstuffing");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestRetrMultilineMessage();
  TestListMultilineMailbox();
  TestUserDenialIsTerminal();
  TestCramMd5AuthenticationAndRetrieval();
  TestInvalidCramChallengeFallsBackToPlain();
  TestPlainAuthenticationUsesSaslInitialResponse();
  TestApopAuthenticationAndDenial();
  TestUnavailableScramMechanismIsRejected();
  TestLongRetrCommandWithReceiveBufferPressure();
  TestRejectedStartTlsDoesNotArmAllocationFailure();
  TestUidlAndTopMultilineBoundaries();
  curl_global_cleanup();
  return 0;
}
