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
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/pop3s_mock_server.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kMessageBody[] = "Hello from POP3S\r\n";

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct Pop3sRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  int tls_version = 0;
  std::size_t handshakes = 0;
  std::string alpn;
};

Pop3sRunResult RunScenario(const Scenario &scenario, const char *url) {
  Pop3sRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_POP3S));
  Expect(connect_to != nullptr,
         "POP3S baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "POP3S URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "POP3S write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "POP3S write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::Pop3sMockServer server;
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
  connection->set_initial_response("+OK pop3s.test ready\r\n");
  connection->add_on_readable("+OK capabilities\r\nUSER\r\n.\r\n");
}

void TestRetrMultilineOverImplicitTls() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3S);
  scenario.set_host_path("tls.test/1");
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable("+OK user accepted\r\n");
  connection->add_on_readable("+OK pass accepted\r\n");
  connection->add_on_readable(
      "+OK 18 octets\r\nHello from POP3S\r\n.\r\n");

  const Pop3sRunResult result = RunScenario(scenario, "pop3s://tls.test/1");
  Expect(result.code == CURLE_OK, "POP3S RETR did not complete");
  Expect(result.handshakes == 1,
         "POP3S transfer did not complete exactly one TLS handshake");
  Expect(result.tls_version != 0,
         "POP3S peer did not record a negotiated TLS version");
  Expect(result.alpn.empty(),
         "POP3S handshake unexpectedly negotiated an ALPN protocol");
  Expect(result.body == kMessageBody,
         "POP3S RETR produced the wrong message body");
  Expect(result.transcript.find("CAPA\r\n") != std::string::npos,
         "POP3S transfer did not issue CAPA");
  Expect(result.transcript.find("USER fuzz\r\n") != std::string::npos,
         "POP3S transfer did not issue USER");
  Expect(result.transcript.find("PASS secret\r\n") != std::string::npos,
         "POP3S transfer did not issue PASS");
  Expect(result.transcript.find("RETR 1\r\n") != std::string::npos,
         "POP3S transfer did not issue RETR");
  Expect(result.transcript.find("QUIT\r\n") != std::string::npos,
         "POP3S teardown did not issue QUIT");
}

void TestUserDenialOverImplicitTls() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_POP3S);
  scenario.set_host_path("tls.test/1");
  AddLoginOptions(&scenario);
  AddGreetingAndCapability(&scenario);
  scenario.mutable_connection()->add_on_readable("-ERR no such user\r\n");

  const Pop3sRunResult result = RunScenario(scenario, "pop3s://tls.test/1");
  Expect(result.code == CURLE_LOGIN_DENIED,
         "POP3S USER denial did not produce a login error");
  Expect(result.handshakes == 1,
         "POP3S denial scenario did not complete a TLS handshake");
  Expect(result.transcript.find("USER fuzz\r\n") != std::string::npos,
         "POP3S denial scenario never issued USER");
  Expect(result.transcript.find("PASS ") == std::string::npos,
         "POP3S issued PASS after USER was rejected");
  Expect(result.body.empty(),
         "POP3S denial scenario unexpectedly produced a body");
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
  TestRetrMultilineOverImplicitTls();
  TestUserDenialOverImplicitTls();
  curl_global_cleanup();
  return 0;
}
