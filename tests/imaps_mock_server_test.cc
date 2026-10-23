/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <csignal>
#include <cstddef>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/imaps_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kMessageBody[] = "Hello from IMAPS\r\n";

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct ImapsRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  int tls_version = 0;
  std::size_t handshakes = 0;
  std::string alpn;
};

ImapsRunResult RunScenario(const Scenario &scenario, const char *url) {
  ImapsRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_IMAPS));
  Expect(connect_to != nullptr,
         "IMAPS baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "IMAPS URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "IMAPS write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "IMAPS write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::ImapsMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.tls_version = server.negotiated_tls_version();
  result.handshakes = server.completed_handshake_count();
  result.alpn = server.negotiated_alpn();

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
  connection->set_initial_response("* OK imaps.test ready\r\n");
  connection->add_on_readable(
      "* CAPABILITY IMAP4rev1\r\nOK CAPABILITY completed\r\n");
}

void TestFetchLiteralOverImplicitTls() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_IMAPS);
  scenario.set_host_path("tls.test/INBOX;UID=1");
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable("OK LOGIN completed\r\n");
  connection->add_on_readable(
      "* 1 EXISTS\r\nOK [UIDVALIDITY 7] SELECT completed\r\n");
  connection->add_on_readable(
      "* 1 FETCH (BODY[] {18}\r\nHello from IMAPS\r\nOK FETCH completed\r\n");

  const ImapsRunResult result =
      RunScenario(scenario, "imaps://tls.test/INBOX;UID=1");
  Expect(result.code == CURLE_OK, "IMAPS FETCH did not complete");
  Expect(result.handshakes == 1,
         "IMAPS transfer did not complete exactly one TLS handshake");
  Expect(result.tls_version != 0,
         "IMAPS peer did not record a negotiated TLS version");
  Expect(result.alpn.empty(),
         "IMAPS handshake unexpectedly negotiated an ALPN protocol");
  Expect(result.body == kMessageBody,
         "IMAPS FETCH produced the wrong literal body");
  Expect(result.transcript.find("CAPABILITY\r\n") != std::string::npos,
         "IMAPS transfer did not issue CAPABILITY");
  Expect(result.transcript.find("LOGIN fuzz secret\r\n") != std::string::npos,
         "IMAPS transfer did not issue LOGIN");
  Expect(result.transcript.find("SELECT INBOX\r\n") != std::string::npos,
         "IMAPS transfer did not select the mailbox");
  Expect(result.transcript.find("UID FETCH 1 BODY[]\r\n") != std::string::npos,
         "IMAPS transfer did not issue the UID FETCH command");
  Expect(result.transcript.find("LOGOUT\r\n") != std::string::npos,
         "IMAPS teardown did not issue LOGOUT");
}

void TestLoginDenialOverImplicitTls() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_IMAPS);
  scenario.set_host_path("tls.test/INBOX");
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  scenario.mutable_connection()->add_on_readable(
      "NO [AUTHENTICATIONFAILED] invalid credentials\r\n");

  const ImapsRunResult result =
      RunScenario(scenario, "imaps://tls.test/INBOX");
  Expect(result.code == CURLE_LOGIN_DENIED,
         "IMAPS LOGIN denial did not produce a login error");
  Expect(result.handshakes == 1,
         "IMAPS denial scenario did not complete a TLS handshake");
  Expect(result.transcript.find("LOGIN fuzz secret\r\n") != std::string::npos,
         "IMAPS denial scenario never issued LOGIN");
  Expect(result.body.empty(),
         "IMAPS denial scenario unexpectedly produced a body");
}

} // namespace

int main() {
  // The proto fuzzer runtime ignores SIGPIPE before it initializes curl. A
  // rejected login lets curl close while the TLS peer is still flushing its
  // teardown reply, so mirror that invariant here instead of reporting a
  // harness-side socket race as a process crash.
  std::signal(SIGPIPE, SIG_IGN);
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestFetchLiteralOverImplicitTls();
  TestLoginDenialOverImplicitTls();
  curl_global_cleanup();
  return 0;
}
