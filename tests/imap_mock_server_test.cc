/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/imap_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kMessageBody[] = "Hello from IMAP\r\n";

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct ImapRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  std::string uploaded;
};

ImapRunResult RunScenario(const Scenario &scenario, const char *url) {
  ImapRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_IMAP));
  Expect(connect_to != nullptr,
         "IMAP baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "IMAP URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "IMAP write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "IMAP write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::ImapMockServer server;
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
  connection->set_initial_response("* OK imap.test ready\r\n");
  connection->add_on_readable(
      "* CAPABILITY IMAP4rev1\r\nOK CAPABILITY completed\r\n");
}

void TestFetchLiteralAndTaggedCompletion() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_IMAP);
  scenario.set_host_path("imap.test/INBOX;UID=1");
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable("OK LOGIN completed\r\n");
  connection->add_on_readable(
      "* 1 EXISTS\r\nOK [UIDVALIDITY 7] SELECT completed\r\n");
  connection->add_on_readable(
      "* 1 FETCH (BODY[] {17}\r\nHello from IMAP\r\nOK FETCH completed\r\n");

  const ImapRunResult result =
      RunScenario(scenario, "imap://imap.test/INBOX;UID=1");
  Expect(result.code == CURLE_OK, "IMAP FETCH did not complete");
  Expect(result.body == kMessageBody,
         "IMAP FETCH produced the wrong literal body");
  Expect(result.transcript.find("CAPABILITY\r\n") != std::string::npos,
         "IMAP transfer did not issue CAPABILITY");
  Expect(result.transcript.find("LOGIN fuzz secret\r\n") != std::string::npos,
         "IMAP transfer did not issue LOGIN");
  Expect(result.transcript.find("SELECT INBOX\r\n") != std::string::npos,
         "IMAP transfer did not select the mailbox");
  Expect(result.transcript.find("UID FETCH 1 BODY[]\r\n") != std::string::npos,
         "IMAP transfer did not issue the UID FETCH command");
  Expect(result.transcript.find("LOGOUT\r\n") != std::string::npos,
         "IMAP teardown did not issue LOGOUT");
}

void TestAppendDrainsAnnouncedLiteral() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_IMAP);
  scenario.set_host_path("imap.test/INBOX");
  AddLoginOptions(&scenario);
  auto *upload = scenario.add_options();
  upload->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload->set_bool_value(true);
  auto *size = scenario.add_options();
  size->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  size->set_uint_value(sizeof(kMessageBody) - 1);
  scenario.mutable_upload()->set_data(kMessageBody);
  scenario.mutable_upload()->add_read_sizes(5);
  scenario.mutable_upload()->add_read_sizes(7);
  scenario.mutable_upload()->add_read_sizes(5);

  AddGreetingAndCapability(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable("OK LOGIN completed\r\n");
  connection->add_on_readable("+ Ready for literal\r\n");
  connection->add_on_readable("OK APPEND completed\r\n");

  const ImapRunResult result =
      RunScenario(scenario, "imap://imap.test/INBOX");
  Expect(result.code == CURLE_OK, "IMAP APPEND did not complete");
  Expect(result.transcript.find("APPEND INBOX") != std::string::npos &&
             result.transcript.find("{17}\r\n") != std::string::npos,
         "IMAP transfer did not announce the APPEND literal size");
  Expect(result.uploaded == kMessageBody,
         "IMAP peer did not drain the exact APPEND literal");
  Expect(result.transcript.find("LOGOUT\r\n") != std::string::npos,
         "IMAP APPEND teardown did not issue LOGOUT");
}

void TestLoginDenialIsTerminal() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_IMAP);
  scenario.set_host_path("imap.test/INBOX");
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  scenario.mutable_connection()->add_on_readable(
      "NO [AUTHENTICATIONFAILED] invalid credentials\r\n");

  const ImapRunResult result =
      RunScenario(scenario, "imap://imap.test/INBOX");
  Expect(result.code == CURLE_LOGIN_DENIED,
         "IMAP LOGIN denial did not produce a login error");
  Expect(result.transcript.find("LOGIN fuzz secret\r\n") != std::string::npos,
         "IMAP denial scenario never issued LOGIN");
  Expect(result.body.empty(),
         "IMAP denial scenario unexpectedly produced a body");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestFetchLiteralAndTaggedCompletion();
  TestAppendDrainsAnnouncedLiteral();
  TestLoginDenialIsTerminal();
  curl_global_cleanup();
  return 0;
}
