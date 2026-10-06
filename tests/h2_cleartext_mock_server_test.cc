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

#include "proto_fuzzer/h2_cleartext_mock_server.h"
#include "proto_fuzzer/option_apply.h"

namespace {

using curl::fuzzer::proto::Scenario;

void Expect(bool condition, const char *message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
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
  long http_version = CURL_HTTP_VERSION_NONE;
  long new_connection_count = -1;
  std::size_t observed_request_count = 0;
  std::size_t observed_client_settings_count = 0;
  std::size_t push_callback_count = 0;
  std::size_t push_header_count = 0;
  bool saw_push_path = false;
  std::size_t accepted_push_count = 0;
  std::size_t cleaned_push_count = 0;
  std::size_t pushed_body_bytes = 0;
  CURLcode upkeep_result = CURLE_FAILED_INIT;
};

H2TransferResult DriveH2Scenario(const Scenario &scenario) {
  H2TransferResult result;
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr,
         "H2 cleartext test could not allocate an easy handle");
  curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_HTTP);
  const std::string url = "http://" + scenario.host_path();
  (void)curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
  (void)curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  (void)curl_easy_setopt(easy, CURLOPT_WRITEDATA, &result.response);

  {
    proto_fuzzer::H2CleartextMockServer server;
    server.Install(easy);
    result.code = server.DriveScenario(easy, scenario);
    (void)curl_easy_getinfo(easy, CURLINFO_HTTP_VERSION, &result.http_version);
    (void)curl_easy_getinfo(easy, CURLINFO_NUM_CONNECTS,
                            &result.new_connection_count);
    result.observed_request_count = server.observed_request_count();
    result.observed_client_settings_count =
        server.observed_client_settings_count();
    result.push_callback_count = server.push_callback_count();
    result.push_header_count = server.push_header_count();
    result.saw_push_path = server.saw_push_path();
    result.accepted_push_count = server.accepted_push_count();
    result.cleaned_push_count = server.cleaned_push_count();
    result.pushed_body_bytes = server.pushed_body_bytes();
    result.upkeep_result = server.upkeep_result();

    // The server intentionally retains its detached multi and connection
    // cache. Clean the caller-owned easy first, matching RunScenario.
    curl_easy_cleanup(easy);
  }
  curl_slist_free_all(connect_to);
  return result;
}

Scenario MakeStructuredScenario() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("tls.test/h2-cleartext");
  auto *plan = scenario.mutable_http2_plan();

  auto *wait = plan->add_actions()->mutable_wait();
  wait->set_event(curl::fuzzer::proto::HTTP2_CLIENT_EVENT_HEADERS);
  wait->mutable_stream()->set_request_index(0);
  wait->set_count(1);

  auto *headers = plan->add_actions()->mutable_headers();
  headers->mutable_stream()->set_request_index(0);
  headers->set_status_code(200);
  auto *data = plan->add_actions()->mutable_data();
  data->mutable_stream()->set_request_index(0);
  data->set_data("h2c");
  data->set_end_stream(true);
  return scenario;
}

Scenario MakeRawScenario() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("tls.test/h2-raw");
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response(
      std::string("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9));
  connection->add_on_readable(
      std::string("\x00\x00\x00\x04\x01\x00\x00\x00\x00", 9));
  connection->add_on_readable(
      std::string("\x00\x00\x01\x01\x04\x00\x00\x00\x01\x88"
                  "\x00\x00\x03\x00\x01\x00\x00\x00\x01raw",
                  22));
  return scenario;
}

Scenario MakePushScenario(bool accept_push = false,
                          bool offer_second_push = false) {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("tls.test/h2-push");
  scenario.set_accept_h2_push(accept_push);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response(
      std::string("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9));
  connection->add_on_readable(
      std::string("\x00\x00\x00\x04\x01\x00\x00\x00\x00", 9));
  // Indexed :scheme is http (0x86) for this carrier; all other promise and
  // response fields match the TLS origin's accepted-push fixture.
  connection->add_on_readable(
      std::string("\x00\x00\x19\x05\x04\x00\x00\x00\x01"
                  "\x00\x00\x00\x02\x82\x86\x01\x08tls.test"
                  "\x04\x07/pushed",
                  34));
  if (offer_second_push) {
    connection->add_on_readable(
        std::string("\x00\x00\x19\x05\x04\x00\x00\x00\x01"
                    "\x00\x00\x00\x04\x82\x86\x01\x08tls.test"
                    "\x04\x07/second",
                    34));
  }
  if (accept_push) {
    connection->add_on_readable(
        std::string("\x00\x00\x01\x01\x04\x00\x00\x00\x02\x88"
                    "\x00\x00\x06\x00\x01\x00\x00\x00\x02pushed",
                    25));
  }
  connection->add_on_readable(
      std::string("\x00\x00\x01\x01\x04\x00\x00\x00\x01\x88"
                  "\x00\x00\x02\x00\x01\x00\x00\x00\x01OK",
                  21));
  return scenario;
}

void TestStructuredPriorKnowledgeExchange() {
  const H2TransferResult result = DriveH2Scenario(MakeStructuredScenario());

  Expect(result.code == CURLE_OK && result.response == "h2c",
         "structured h2c response did not complete");
  Expect(result.http_version == CURL_HTTP_VERSION_2_0 &&
             result.new_connection_count == 1,
         "h2c peer did not use one HTTP/2 prior-knowledge connection");
  Expect(result.observed_request_count == 1 &&
             result.observed_client_settings_count >= 1,
         "structured h2c peer did not observe client setup and request HEADERS");
  Expect(result.upkeep_result == CURLE_OK,
         "structured h2c peer did not complete its upkeep probe");
}

void TestRawPriorKnowledgeExchange() {
  const H2TransferResult result = DriveH2Scenario(MakeRawScenario());

  Expect(result.code == CURLE_OK && result.response == "raw",
         "raw h2c response did not complete");
  Expect(result.http_version == CURL_HTTP_VERSION_2_0,
         "raw h2c peer did not report HTTP/2");
}

void TestValidPushPromiseReachesCallback() {
  const H2TransferResult result = DriveH2Scenario(MakePushScenario());

  Expect(result.code == CURLE_OK && result.response == "OK",
         "valid h2c push scenario did not complete its parent transfer");
  Expect(result.push_callback_count == 1 && result.push_header_count == 4 &&
             result.saw_push_path,
         "valid h2c PUSH_PROMISE did not reach both public header accessors");
  Expect(result.accepted_push_count == 0 && result.cleaned_push_count == 0 &&
             result.pushed_body_bytes == 0,
         "default h2c push mode did not preserve rejection semantics");
  Expect(result.upkeep_result == CURLE_OK,
         "h2c push transfer did not complete its upkeep probe");
}

void TestAcceptedPushCompletesAndCleansUpOneHandle() {
  const H2TransferResult result = DriveH2Scenario(MakePushScenario(true, true));

  Expect(result.code == CURLE_OK && result.response == "OK",
         "accepted h2c push prevented the parent transfer from completing");
  Expect(result.push_callback_count == 2 && result.push_header_count == 8 &&
             result.saw_push_path,
         "accepted h2c push did not inspect both valid promises");
  Expect(result.accepted_push_count == 1 && result.cleaned_push_count == 1,
         "accepted h2c push did not enforce and clean up its one-handle bound");
  Expect(result.pushed_body_bytes == 6,
         "accepted h2c push did not consume the promised response body");
  Expect(result.upkeep_result == CURLE_OK,
         "accepted h2c push did not complete its upkeep probe");
}

} // namespace

int main() {
  TestStructuredPriorKnowledgeExchange();
  TestRawPriorKnowledgeExchange();
  TestValidPushPromiseReachesCallback();
  TestAcceptedPushCompletesAndCleansUpOneHandle();
  return 0;
}
