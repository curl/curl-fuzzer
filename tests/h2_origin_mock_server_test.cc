/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string>

#include "proto_fuzzer/h2_origin_mock_server.h"
#include "proto_fuzzer/option_apply.h"

namespace {

using curl::fuzzer::proto::Scenario;

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

std::size_t CollectResponse(char *contents, std::size_t size, std::size_t nmemb,
                            void *userdata) {
  const std::size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct H2TransferResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string response;
  std::string negotiated_alpn;
  long http_version = CURL_HTTP_VERSION_NONE;
  long new_connection_count = -1;
  std::size_t handshake_count = 0;
  std::size_t push_callback_count = 0;
  std::size_t push_header_count = 0;
  bool saw_push_path = false;
  CURLcode upkeep_result = CURLE_FAILED_INIT;
};

H2TransferResult DriveH2Scenario(const Scenario &scenario) {
  H2TransferResult result;
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "H2 origin test could not allocate an easy handle");
  curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_HTTPS);
  const std::string url = "https://" + scenario.host_path();
  (void)curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
  (void)curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  (void)curl_easy_setopt(easy, CURLOPT_WRITEDATA, &result.response);

  proto_fuzzer::H2OriginMockServer server;
  server.Install(easy);
  for (const auto &option : scenario.options()) {
    Expect(proto_fuzzer::ApplySetOption(easy, option) == CURLE_OK,
           "H2 origin scenario option was rejected by curl");
  }

  result.code = server.DriveScenario(easy, scenario);
  (void)curl_easy_getinfo(easy, CURLINFO_HTTP_VERSION, &result.http_version);
  (void)curl_easy_getinfo(easy, CURLINFO_NUM_CONNECTS,
                          &result.new_connection_count);
  result.negotiated_alpn = server.negotiated_alpn();
  result.handshake_count = server.completed_handshake_count();
  result.push_callback_count = server.push_callback_count();
  result.push_header_count = server.push_header_count();
  result.saw_push_path = server.saw_push_path();
  result.upkeep_result = server.upkeep_result();

  curl_easy_cleanup(easy);
  curl_slist_free_all(connect_to);
  return result;
}

Scenario MakePushScenario() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
  scenario.set_host_path("tls.test/h2-push");
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response(
      std::string("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9));
  connection->add_on_readable(
      std::string("\x00\x00\x00\x04\x01\x00\x00\x00\x00", 9));
  connection->add_on_readable(
      std::string("\x00\x00\x19\x05\x04\x00\x00\x00\x01"
                  "\x00\x00\x00\x02\x82\x87\x01\x08tls.test"
                  "\x04\x07/pushed",
                  34));
  connection->add_on_readable(
      std::string("\x00\x00\x01\x01\x04\x00\x00\x00\x01\x88"
                  "\x00\x00\x02\x00\x01\x00\x00\x00\x01OK",
                  21));
  return scenario;
}

Scenario MakeReuseScenario() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
  scenario.set_host_path("tls.test/h2-start");
  auto *follow = scenario.add_options();
  follow->set_option_id(curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION);
  follow->set_uint_value(1);
  auto *redirects = scenario.add_options();
  redirects->set_option_id(curl::fuzzer::proto::CURLOPT_MAXREDIRS);
  redirects->set_uint_value(2);

  auto *connection = scenario.mutable_connection();
  connection->set_initial_response(
      std::string("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9));
  connection->add_on_readable(
      std::string("\x00\x00\x00\x04\x01\x00\x00\x00\x00"
                  "\x00\x00\x0e\x01\x05\x00\x00\x00\x01"
                  "\x08\x03\x33\x30\x32\x0f\x1f\x06/reuse",
                  32));
  connection->add_on_readable(
      std::string("\x00\x00\x08\x06\x00\x00\x00\x00\x00h2-reuse", 17));
  connection->add_on_readable(
      std::string("\x00\x00\x0d\x01\x04\x00\x00\x00\x03\x88\x5f\x0a"
                  "text/plain\x00\x00\x06\x00\x01\x00\x00\x00\x03"
                  "reused",
                  37));
  return scenario;
}

void TestValidPushPromiseReachesCallback() {
  const H2TransferResult result = DriveH2Scenario(MakePushScenario());

  Expect(result.code == CURLE_OK && result.response == "OK",
         "valid H2 push scenario did not complete its parent transfer");
  Expect(result.negotiated_alpn == "h2" &&
             result.http_version == CURL_HTTP_VERSION_2_0,
         "H2 origin did not negotiate and report HTTP/2");
  Expect(result.push_callback_count == 1 && result.push_header_count == 4 &&
             result.saw_push_path,
         "valid PUSH_PROMISE did not reach both public header accessors");
  Expect(result.upkeep_result == CURLE_OK,
         "H2 push transfer did not complete its upkeep probe");
}

void TestRedirectReusesH2ConnectionAroundPingAndUpkeep() {
  const H2TransferResult result = DriveH2Scenario(MakeReuseScenario());

  Expect(result.code == CURLE_OK && result.response == "reused",
         "H2 redirect did not complete on stream 3");
  Expect(result.handshake_count == 1 && result.new_connection_count == 1,
         "H2 redirect opened another TLS connection instead of reusing h2");
  Expect(result.upkeep_result == CURLE_OK,
         "reused H2 connection did not complete its upkeep PING probe");
}

} // namespace

int main() {
  TestValidPushPromiseReachesCallback();
  TestRedirectReusesH2ConnectionAroundPingAndUpkeep();
  return 0;
}
