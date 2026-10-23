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
#include "proto_fuzzer/ldaps_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kBaseDn[] = "dc=example,dc=com";
constexpr char kUrl[] =
    "ldaps://tls.test/dc=example,dc=com?cn?sub?(objectclass=*)";

// LDAPMessage { messageID 1, bindResponse { resultCode 49,
//   matchedDN "", diagnosticMessage "invalid credentials" } }.
const std::string
    kRejectedBind("\x30\x1f\x02\x01\x01\x61\x1a\x0a\x01\x31\x04\x00\x04\x13"
                  "invalid credentials",
                  33);

// LDAPMessage { messageID 2, searchResEntry {
//   objectName "dc=example,dc=com",
//   attributes { cn: fuzz, objectClass: top, person } } }.
const std::string kSearchEntry("\x30\x46\x02\x01\x02\x64\x41\x04\x11"
                               "dc=example,dc=com"
                               "\x30\x2c\x30\x0c\x04\x02"
                               "cn"
                               "\x31\x06\x04\x04"
                               "fuzz"
                               "\x30\x1c\x04\x0b"
                               "objectClass"
                               "\x31\x0d\x04\x03"
                               "top"
                               "\x04\x06"
                               "person",
                               72);

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct LdapsRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  std::size_t binds = 0;
  std::size_t searches = 0;
  std::size_t scripted_messages = 0;
  std::size_t synthesized_dones = 0;
  std::size_t scripted_bind_responses = 0;
  int tls_version = 0;
  std::size_t handshakes = 0;
  std::string alpn;
};

LdapsRunResult RunScenario(const Scenario &scenario) {
  LdapsRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_LDAPS));
  Expect(connect_to != nullptr,
         "LDAPS baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, kUrl) == CURLE_OK,
         "LDAPS URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "LDAPS write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "LDAPS write data setup failed");

  proto_fuzzer::LdapsMockServer server;
  server.Install(easy.get());
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.packet_transcript();
  result.binds = server.bind_request_count();
  result.searches = server.search_request_count();
  result.scripted_messages = server.scripted_message_count();
  result.synthesized_dones = server.synthesized_done_count();
  result.scripted_bind_responses = server.scripted_bind_response_count();
  result.tls_version = server.negotiated_tls_version();
  result.handshakes = server.completed_handshake_count();
  result.alpn = server.negotiated_alpn();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void AddCredentials(Scenario *scenario) {
  scenario->set_scheme(curl::fuzzer::proto::SCHEME_LDAPS);
  auto *username = scenario->add_options();
  username->set_option_id(curl::fuzzer::proto::CURLOPT_USERNAME);
  username->set_string_value("cn=admin,dc=example,dc=com");
  auto *password = scenario->add_options();
  password->set_option_id(curl::fuzzer::proto::CURLOPT_PASSWORD);
  password->set_string_value("secret");
}

void TestBindAndSearchOverImplicitTls() {
  Scenario scenario;
  AddCredentials(&scenario);
  scenario.mutable_connection()->add_on_readable(kSearchEntry);

  const LdapsRunResult result = RunScenario(scenario);
  Expect(result.code == CURLE_OK,
         "LDAPS bind + search did not complete over TLS");
  Expect(result.handshakes == 1,
         "LDAPS transfer did not complete exactly one TLS handshake");
  Expect(result.tls_version != 0,
         "LDAPS peer did not record a negotiated TLS version");
  Expect(result.alpn.empty(),
         "LDAPS handshake unexpectedly negotiated an ALPN protocol");
  Expect(result.binds == 1, "LDAPS peer did not observe one bindRequest");
  Expect(result.searches == 1,
         "LDAPS peer did not observe one searchRequest");
  Expect(result.scripted_messages == 1,
         "LDAPS peer did not forward the scripted searchResEntry");
  Expect(result.synthesized_dones == 1,
         "LDAPS peer did not synthesize searchResDone after the entry");
  Expect(result.body.find(std::string("DN: ") + kBaseDn) != std::string::npos,
         "curl did not format the decrypted search entry DN as LDIF");
  Expect(result.body.find("cn: fuzz") != std::string::npos,
         "curl did not format the decrypted search attribute as LDIF");
  Expect(result.transcript.size() > 0,
         "LDAPS peer captured no decrypted client message transcript");
}

void TestRejectedBindOverImplicitTls() {
  Scenario scenario;
  AddCredentials(&scenario);
  scenario.mutable_connection()->set_initial_response(kRejectedBind);

  const LdapsRunResult result = RunScenario(scenario);
  Expect(result.code != CURLE_OK,
         "rejected LDAPS bind unexpectedly completed the transfer");
  Expect(result.handshakes == 1,
         "rejected LDAPS bind did not complete TLS negotiation");
  Expect(result.binds == 1,
         "LDAPS peer did not observe one bindRequest over TLS");
  Expect(result.searches == 0,
         "LDAPS transfer issued a search after a rejected bind");
  Expect(result.scripted_bind_responses == 1,
         "LDAPS peer did not use the scripted bind response");
  Expect(result.synthesized_dones == 0,
         "LDAPS peer synthesized a search completion after a failed bind");
}

} // namespace

int main() {
  // Match fuzzer_main.cc: fuzzed TLS teardown races can make the peer's
  // OpenSSL write a fatal alert after curl has already closed its end. That is
  // an ordinary socket failure for the harness, not a process fault.
  std::signal(SIGPIPE, SIG_IGN);
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestBindAndSearchOverImplicitTls();
  TestRejectedBindOverImplicitTls();
  curl_global_cleanup();
  return 0;
}
