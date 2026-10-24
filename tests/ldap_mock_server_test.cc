/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/ldap_mock_server.h"
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
    "ldap://ldap.test/dc=example,dc=com?cn?sub?(objectclass=*)";
constexpr char kMechanismAttributeUrl[] =
    "ldap://ldap.test/?supportedSASLMechanisms?base?"
    "(objectclass=*)";

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

// LDAPMessage { messageID 1, searchResDone { resultCode 32,
//   matchedDN "", diagnosticMessage "no such object" } }. The scripted id is
// deliberately 1 so the peer's renumbering to the search request is exercised.
const std::string
    kSearchRejected("\x30\x1a\x02\x01\x01\x65\x15\x0a\x01\x20\x04\x00\x04\x0e"
                    "no such object",
                    28);

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct LdapRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  std::size_t binds = 0;
  std::size_t searches = 0;
  std::size_t mechanism_searches = 0;
  std::size_t starttls_requests = 0;
  std::size_t unbinds = 0;
  std::size_t server_messages = 0;
  std::size_t scripted_messages = 0;
  std::size_t synthesized_dones = 0;
  std::size_t scripted_bind_responses = 0;
};

LdapRunResult RunScenario(const Scenario &scenario, const char *url = kUrl) {
  LdapRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_LDAP));
  Expect(connect_to != nullptr,
         "LDAP baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "LDAP URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "LDAP write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "LDAP write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);
  if (scenario.ldap_starttls()) {
    Expect(curl_easy_setopt(easy.get(), CURLOPT_USE_SSL,
                            static_cast<long>(CURLUSESSL_ALL)) == CURLE_OK,
           "LDAP StartTLS option setup failed");
  }

  proto_fuzzer::LdapMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.packet_transcript();
  result.binds = server.bind_request_count();
  result.searches = server.search_request_count();
  result.mechanism_searches = server.mechanism_search_request_count();
  result.starttls_requests = server.starttls_request_count();
  result.unbinds = server.unbind_request_count();
  result.server_messages = server.server_message_count();
  result.scripted_messages = server.scripted_message_count();
  result.synthesized_dones = server.synthesized_done_count();
  result.scripted_bind_responses = server.scripted_bind_response_count();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void AddCredentials(Scenario *scenario) {
  scenario->set_scheme(curl::fuzzer::proto::SCHEME_LDAP);
  auto *username = scenario->add_options();
  username->set_option_id(curl::fuzzer::proto::CURLOPT_USERNAME);
  username->set_string_value("cn=admin,dc=example,dc=com");
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

void TestBindAndSearchFormatsLdif() {
  Scenario scenario;
  AddCredentials(&scenario);
  scenario.mutable_connection()->add_on_readable(kSearchEntry);

  const LdapRunResult result = RunScenario(scenario);
  Expect(result.code == CURLE_OK, "LDAP bind + search did not complete");
  Expect(result.binds == 1, "LDAP peer did not observe one bindRequest");
  Expect(result.searches == 1, "LDAP peer did not observe one searchRequest");
  Expect(result.scripted_messages == 1,
         "LDAP peer did not forward the scripted searchResEntry");
  Expect(result.synthesized_dones == 1,
         "LDAP peer did not synthesize searchResDone after the entry");
  // bindResponse + searchResEntry + synthesized searchResDone.
  Expect(result.server_messages == 3,
         "LDAP peer wrote the wrong number of server messages");
  Expect(result.body.find(std::string("DN: ") + kBaseDn) != std::string::npos,
         "curl did not format the search entry DN as LDIF");
  Expect(result.body.find("cn: fuzz") != std::string::npos,
         "curl did not format the search entry attribute as LDIF");
  Expect(result.transcript.size() > 0,
         "LDAP peer captured no client message transcript");
}

void TestRejectedBindStopsBeforeSearch() {
  Scenario scenario;
  AddCredentials(&scenario);
  scenario.mutable_connection()->set_initial_response(kRejectedBind);

  const LdapRunResult result = RunScenario(scenario);
  Expect(result.code != CURLE_OK,
         "rejected LDAP bind unexpectedly completed the transfer");
  Expect(result.binds == 1, "LDAP peer did not observe one bindRequest");
  Expect(result.searches == 0,
         "LDAP transfer issued a search after a rejected bind");
  Expect(result.scripted_bind_responses == 1,
         "LDAP peer did not use the scripted bind response");
  Expect(result.synthesized_dones == 0,
         "LDAP peer synthesized a search completion after a failed bind");
}

void TestSearchErrorUsesScriptedDone() {
  Scenario scenario;
  AddCredentials(&scenario);
  scenario.mutable_connection()->add_on_readable(kSearchRejected);

  const LdapRunResult result = RunScenario(scenario);
  Expect(result.code != CURLE_OK,
         "rejected LDAP search unexpectedly completed the transfer");
  Expect(result.searches == 1, "LDAP peer did not observe one searchRequest");
  Expect(result.scripted_messages == 1,
         "LDAP peer did not forward the scripted search failure");
  Expect(result.synthesized_dones == 0,
         "LDAP peer duplicated a scripted searchResDone");
}

void TestEmptySearchScriptSynthesizesSuccess() {
  Scenario scenario;
  AddCredentials(&scenario);

  const LdapRunResult result = RunScenario(scenario);
  Expect(result.code == CURLE_OK,
         "LDAP search without scripted entries did not complete");
  Expect(result.searches == 1, "LDAP peer did not observe one searchRequest");
  Expect(result.scripted_messages == 0,
         "LDAP peer forwarded a scripted message without a script");
  Expect(result.synthesized_dones == 1,
         "LDAP peer did not synthesize a successful searchResDone");
}

void TestStartTlsExtendedResponseInstallsUpgrade() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_LDAP);
  scenario.set_ldap_starttls(true);

  const LdapRunResult result = RunScenario(scenario);
  Expect(result.code != CURLE_OK,
         "plaintext peer unexpectedly completed the TLS upgrade");
  Expect(result.starttls_requests == 1,
         "LDAP peer did not observe one StartTLS ExtendedRequest");
  Expect(result.binds == 0 && result.searches == 0,
         "LDAP issued bind/search before the TLS upgrade completed");
  Expect(result.server_messages == 1,
         "LDAP peer did not write exactly one StartTLS ExtendedResponse");
}

void TestSaslMechanismDiscoveryAndPlainBind() {
  Scenario scenario;
  AddCredentials(&scenario);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=PLAIN");
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_SASL_AUTHZID,
                  "authorization-id");
  AddBoolOption(&scenario, curl::fuzzer::proto::CURLOPT_SASL_IR, true);
  scenario.mutable_connection()->add_on_readable(kSearchEntry);

  const LdapRunResult result = RunScenario(scenario);
  Expect(result.code == CURLE_OK,
         "LDAP SASL PLAIN bind and search did not complete");
  Expect(result.mechanism_searches == 1,
         "LDAP peer did not recognize the SASL mechanism query");
  Expect(result.searches == 2,
         "LDAP SASL flow did not issue mechanism and data searches");
  Expect(result.binds == 1,
         "LDAP SASL flow did not issue exactly one bindRequest");
  Expect(result.synthesized_dones == 2,
         "LDAP peer did not complete both mechanism and data searches");
  Expect(result.scripted_messages == 1,
         "LDAP mechanism query consumed the scripted data-search entry");
  Expect(result.transcript.find("supportedSASLMechanisms") != std::string::npos,
         "LDAP transcript lost the root-DSE mechanism query");
  Expect(result.transcript.find("PLAIN") != std::string::npos,
         "LDAP transcript did not contain the selected SASL mechanism");
  Expect(result.transcript.find("authorization-id") != std::string::npos,
         "LDAP SASL bind did not carry the configured authorization id");
  Expect(result.body.find("cn: fuzz") != std::string::npos,
         "LDAP SASL search did not reach the LDIF formatter");
}

void TestUnavailableSaslMechanismFailsClosed() {
  Scenario scenario;
  AddCredentials(&scenario);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=LOGIN");

  const LdapRunResult result = RunScenario(scenario);
  Expect(result.code == CURLE_LOGIN_DENIED,
         "LDAP accepted a SASL mechanism the peer did not advertise");
  Expect(result.mechanism_searches == 1 && result.searches == 1,
         "LDAP unavailable-mechanism flow did not stop after discovery");
  Expect(result.binds == 0,
         "LDAP unavailable-mechanism flow unexpectedly issued a bind");
  Expect(result.scripted_messages == 0,
         "LDAP unavailable-mechanism flow consumed data-search script");
}

void TestDataSearchForMechanismAttributeIsNotDiscovery() {
  Scenario scenario;
  AddCredentials(&scenario);
  scenario.mutable_connection()->add_on_readable(kSearchEntry);

  const LdapRunResult result = RunScenario(scenario, kMechanismAttributeUrl);
  Expect(result.code == CURLE_OK,
         "LDAP data search for supportedSASLMechanisms did not complete");
  Expect(result.mechanism_searches == 0 && result.searches == 1,
         "LDAP peer misclassified a post-bind root-DSE search as discovery");
  Expect(result.scripted_messages == 1,
         "LDAP data search did not consume its scripted result");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestBindAndSearchFormatsLdif();
  TestRejectedBindStopsBeforeSearch();
  TestSearchErrorUsesScriptedDone();
  TestEmptySearchScriptSynthesizesSuccess();
  TestStartTlsExtendedResponseInstallsUpgrade();
  TestSaslMechanismDiscoveryAndPlainBind();
  TestUnavailableSaslMechanismFailsClosed();
  TestDataSearchForMechanismAttributeIsNotDiscovery();
  curl_global_cleanup();
  return 0;
}
