/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/http3_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

std::size_t CollectBytes(char *contents, std::size_t size, std::size_t nmemb,
                         void *userdata) {
  const std::size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct Http3RunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string headers;
  long response_code = 0;
  long http_version = CURL_HTTP_VERSION_NONE;
  bool handshake_complete = false;
  bool request_headers_received = false;
  std::size_t executed_action_count = 0;
  std::uint16_t server_port = 0;
};

Http3RunResult RunScenario(const Scenario &scenario, const char *path) {
  Http3RunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_HTTPS));
  Expect(connect_to != nullptr,
         "HTTP/3 baseline did not create CONNECT_TO state");

  const std::string url = std::string("https://tls.test/") + path;
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url.c_str()) == CURLE_OK,
         "HTTP/3 URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION, &CollectBytes) ==
             CURLE_OK,
         "HTTP/3 write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "HTTP/3 write data setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_HEADERFUNCTION, &CollectBytes) ==
             CURLE_OK,
         "HTTP/3 header callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_HEADERDATA, &result.headers) ==
             CURLE_OK,
         "HTTP/3 header data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::Http3MockServer server(scenario.tls_certificate_chain());
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario, true);
  }
  (void)curl_easy_getinfo(easy.get(), CURLINFO_RESPONSE_CODE,
                          &result.response_code);
  (void)curl_easy_getinfo(easy.get(), CURLINFO_HTTP_VERSION,
                          &result.http_version);
  result.handshake_complete = server.handshake_complete();
  result.request_headers_received = server.request_headers_received();
  result.executed_action_count = server.executed_action_count();
  result.server_port = server.server_port();

  // Pointer-valued baseline options must outlive easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void TestStructuredResponseWithTrailers() {
  Scenario scenario;
  auto *action = scenario.mutable_http3_plan()->add_actions();
  auto *response = action->mutable_structured_response();
  response->set_status_code(200);
  auto *header = response->add_response_headers();
  header->set_name("content-type");
  header->set_value("text/plain");
  response->add_body_chunks("hello ");
  response->add_body_chunks("http3");
  auto *trailer = response->add_response_trailers();
  trailer->set_name("x-h3-trailer");
  trailer->set_value("complete");
  response->set_finish_stream(true);

  const Http3RunResult result = RunScenario(scenario, "structured");
  if (result.code != CURLE_OK) {
    std::cerr << "structured HTTP/3 CURLcode " << result.code << ": "
              << curl_easy_strerror(result.code)
              << ", handshake=" << result.handshake_complete
              << ", request_headers=" << result.request_headers_received
              << ", actions=" << result.executed_action_count
              << ", port=" << result.server_port << '\n';
  }
  Expect(result.code == CURLE_OK,
         "structured HTTP/3 transfer did not complete");
  Expect(result.response_code == 200,
         "structured HTTP/3 response did not report status 200");
  Expect(result.http_version == CURL_HTTP_VERSION_3,
         "structured transfer did not use HTTP/3");
  Expect(result.body == "hello http3",
         "structured HTTP/3 response produced the wrong body");
  Expect(result.headers.find("x-h3-trailer: complete") != std::string::npos,
         "structured HTTP/3 response did not deliver its trailer");
  Expect(result.handshake_complete,
         "HTTP/3 server did not complete its QUIC TLS handshake");
  Expect(result.request_headers_received,
         "HTTP/3 server did not decode the request field section");
  Expect(result.executed_action_count == 1,
         "HTTP/3 server did not execute exactly one structured action");
  Expect(result.server_port != 0,
         "HTTP/3 server did not expose its kernel-selected UDP port");
}

void TestRawResponseStreamDataFrame() {
  Scenario scenario;
  auto *headers_action = scenario.mutable_http3_plan()->add_actions();
  auto *response = headers_action->mutable_structured_response();
  response->set_status_code(200);
  response->set_finish_stream(false);

  // HTTP/3 DATA frame: type=0, length=3, payload="raw". The peer writes
  // these bytes directly to the response QUIC stream after nghttp3 has made
  // the preceding HEADERS block, so curl parses mutator-controlled plaintext.
  auto *raw_action = scenario.mutable_http3_plan()->add_actions();
  auto *write = raw_action->mutable_stream_write();
  write->set_role(curl::fuzzer::proto::HTTP3_STREAM_RESPONSE);
  write->set_data(std::string("\x00\x03raw", 5));
  write->set_finish_stream(true);

  const Http3RunResult result = RunScenario(scenario, "raw-data-frame");
  Expect(result.code == CURLE_OK,
         "raw response-stream HTTP/3 transfer did not complete");
  Expect(result.http_version == CURL_HTTP_VERSION_3,
         "raw response-stream transfer did not use HTTP/3");
  Expect(result.body == "raw",
         "curl did not parse the directly-written HTTP/3 DATA frame");
  Expect(result.handshake_complete && result.request_headers_received,
         "raw response-stream case did not reach HTTP/3 application data");
  Expect(result.executed_action_count == 2,
         "HTTP/3 server did not execute both structured and raw actions");
  Expect(result.server_port != 0,
         "raw HTTP/3 case did not bind a private UDP port");
}

void TestRawResponseFromFrameZero() {
  Scenario scenario;
  auto *action = scenario.mutable_http3_plan()->add_actions();
  auto *write = action->mutable_stream_write();
  write->set_role(curl::fuzzer::proto::HTTP3_STREAM_RESPONSE);

  // HEADERS(type=1, length=3), followed by a QPACK field section with zero
  // dynamic-table state and the static :status=200 entry. DATA then carries
  // "raw-first". No byte on the response stream is generated by nghttp3.
  write->set_data(std::string("\x01\x03\x00\x00\xd9\x00\x09raw-first", 16));
  write->set_finish_stream(true);

  const Http3RunResult result = RunScenario(scenario, "raw-from-frame-zero");
  Expect(result.code == CURLE_OK, "raw-first HTTP/3 response did not complete");
  Expect(result.response_code == 200,
         "curl did not decode the raw-first QPACK status field");
  Expect(result.http_version == CURL_HTTP_VERSION_3,
         "raw-first response did not use HTTP/3");
  Expect(result.body == "raw-first",
         "curl did not parse response bytes written from frame zero");
  Expect(result.executed_action_count == 1,
         "HTTP/3 server did not execute the raw-first response action");
}

void TestFreshUnknownUnidirectionalStream() {
  Scenario scenario;
  auto *raw_action = scenario.mutable_http3_plan()->add_actions();
  auto *stream = raw_action->mutable_open_unidirectional_stream();
  // 0x21 is an unknown HTTP/3 unidirectional stream type. Because this action
  // owns a new QUIC stream, it is also the literal first byte curl receives.
  stream->set_data(std::string("\x21unknown-stream", 15));
  stream->set_finish_stream(true);

  auto *response_action = scenario.mutable_http3_plan()->add_actions();
  auto *response = response_action->mutable_structured_response();
  response->set_status_code(200);
  response->add_body_chunks("after unknown stream");
  response->set_finish_stream(true);

  const Http3RunResult result = RunScenario(scenario, "unknown-uni-stream");
  Expect(result.code == CURLE_OK,
         "an unknown unidirectional stream prevented response completion");
  Expect(result.http_version == CURL_HTTP_VERSION_3,
         "unknown-stream transfer did not use HTTP/3");
  Expect(result.body == "after unknown stream",
         "curl did not ignore the fresh unknown unidirectional stream");
  Expect(result.executed_action_count == 2,
         "HTTP/3 server did not execute the fresh-stream and response actions");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestStructuredResponseWithTrailers();
  TestRawResponseStreamDataFrame();
  TestRawResponseFromFrameZero();
  TestFreshUnknownUnidirectionalStream();
  curl_global_cleanup();
  return 0;
}
