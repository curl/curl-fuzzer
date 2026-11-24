/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/http3_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

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
  std::size_t request_body_bytes = 0;
  std::size_t request_body_turns = 0;
  std::size_t executed_action_count = 0;
  std::uint16_t server_port = 0;
};

Http3RunResult RunScenario(const Scenario &scenario, const char *path,
                          const char *hostname = "tls.test") {
  Http3RunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_HTTPS));
  Expect(connect_to != nullptr,
         "HTTP/3 baseline did not create CONNECT_TO state");

  const std::string url = std::string("https://") + hostname + "/" + path;
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
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  (void)curl_easy_getinfo(easy.get(), CURLINFO_RESPONSE_CODE,
                          &result.response_code);
  (void)curl_easy_getinfo(easy.get(), CURLINFO_HTTP_VERSION,
                          &result.http_version);
  result.handshake_complete = server.handshake_complete();
  result.request_headers_received = server.request_headers_received();
  result.request_body_bytes = server.request_body_bytes();
  result.request_body_turns = server.request_body_turns();
  result.executed_action_count = server.executed_action_count();
  result.server_port = server.server_port();

  // Pointer-valued baseline options must outlive easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void TestHostnameMismatchIsRejected() {
  Scenario scenario;
  auto *response = scenario.mutable_http3_plan()
                       ->add_actions()
                       ->mutable_structured_response();
  response->set_status_code(200);
  response->add_body_chunks("unreachable");
  response->set_finish_stream(true);

  const Http3RunResult result =
      RunScenario(scenario, "hostname-mismatch", "wrong.test");
  Expect(result.code == CURLE_PEER_FAILED_VERIFICATION,
         "HTTP/3 peer certificate was accepted for a mismatched hostname");
  Expect(result.body.empty() && result.headers.empty(),
         "curl delivered HTTP/3 data after rejecting the peer hostname");
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

void TestUploadExceedsQuicStreamWindow() {
  Scenario scenario;
  scenario.mutable_http3_plan()->set_small_upload_window(true);
  auto* response = scenario.mutable_http3_plan()->add_actions()->mutable_structured_response();
  response->set_status_code(200);
  response->set_finish_stream(true);
  scenario.mutable_upload()->set_data(std::string(256, 'a'));
  scenario.mutable_upload()->set_terminal(curl::fuzzer::proto::UPLOAD_TERMINAL_EOF);
  auto* upload_option = scenario.add_options();
  upload_option->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload_option->set_bool_value(true);
  auto* size_option = scenario.add_options();
  size_option->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  size_option->set_uint_value(256);
  scenario.add_request_headers("Expect:");

  const Http3RunResult result = RunScenario(scenario, "upload-flow-control");
  Expect(result.code == CURLE_OK, "HTTP/3 flow-controlled upload did not complete");
  Expect(result.http_version == CURL_HTTP_VERSION_3, "flow-controlled upload did not use HTTP/3");
  Expect(result.request_headers_received && result.request_body_bytes == 256,
         "peer did not consume the full flow-controlled upload");
  // The body exceeds the initial window. A later turn must receive the rest
  // after the peer sends more credit.
  Expect(result.request_body_turns >= 2,
         "upload data did not require a QUIC receive-credit round trip");
  Expect(result.executed_action_count == 1, "peer did not send the response after the upload");

  // The peer waits for the request FIN, not for all scripted bytes: curl can
  // legitimately stop before the end of the script at its declared size.
  size_option->set_uint_value(160);
  const Http3RunResult shorter = RunScenario(scenario, "shorter-upload");
  Expect(shorter.code == CURLE_OK && shorter.request_body_bytes == 160,
         "peer waited beyond the declared HTTP/3 upload size");

  // Exercise the case where the first response must arrive before curl can
  // send the body and the peer can send the final response.
  size_option->set_uint_value(256);
  scenario.set_request_headers(0, "Expect: 100-continue");
  auto* actions = scenario.mutable_http3_plan()->mutable_actions();
  actions->Add()->mutable_structured_response()->set_status_code(100);
  actions->SwapElements(0, 1);

  const Http3RunResult continued = RunScenario(scenario, "expect-continue");
  if (continued.code != CURLE_OK || continued.response_code != 200) {
    std::cerr << "expect-continue CURLcode=" << continued.code
              << " (" << curl_easy_strerror(continued.code) << ")"
              << " status=" << continued.response_code
              << " handshake=" << continued.handshake_complete
              << " headers_received=" << continued.request_headers_received
              << " body_bytes=" << continued.request_body_bytes
              << " body_turns=" << continued.request_body_turns
              << " actions=" << continued.executed_action_count
              << " response_headers=" << continued.headers << '\n';
  }
  Expect(continued.code == CURLE_OK && continued.response_code == 200,
         "HTTP/3 upload did not complete after 100 Continue");
  Expect(continued.headers.find("HTTP/3 100") != std::string::npos &&
             continued.request_body_bytes == 256 && continued.request_body_turns >= 2 &&
             continued.executed_action_count == 2,
         "peer did not send the interim response and receive the full flow-controlled upload");
}

void TestRejectedRequestStream() {
  Scenario scenario;
  auto* reset = scenario.mutable_http3_plan()->add_actions()->mutable_stream_reset();
  reset->set_role(curl::fuzzer::proto::HTTP3_STREAM_RESPONSE);
  reset->set_application_error_code(267);  // H3_REQUEST_REJECTED

  const Http3RunResult result = RunScenario(scenario, "request-rejected");
  Expect(result.handshake_complete && result.request_headers_received,
         "HTTP/3 rejected request did not reach the peer");
  Expect(result.executed_action_count == 1,
         "HTTP/3 peer did not send the request rejection");
  Expect(result.code != CURLE_OK,
         "HTTP/3 rejected request unexpectedly completed successfully");
}

void TestDownloadReceiveRate() {
  Scenario scenario;
  auto* rate = scenario.add_options();
  rate->set_option_id(curl::fuzzer::proto::CURLOPT_MAX_RECV_SPEED_LARGE);
  rate->set_uint_value(65536);
  auto* response = scenario.mutable_http3_plan()->add_actions()->mutable_structured_response();
  response->set_status_code(200);
  response->add_body_chunks("rate-limited response body");
  response->set_finish_stream(true);

  const Http3RunResult result = RunScenario(scenario, "limited-download");
  Expect(result.code == CURLE_OK && result.body == "rate-limited response body",
         "HTTP/3 rate-limited response did not complete");
  Expect(result.http_version == CURL_HTTP_VERSION_3 && result.executed_action_count == 1,
         "HTTP/3 rate-limited response did not reach the scripted peer");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestStructuredResponseWithTrailers();
  TestHostnameMismatchIsRejected();
  TestRawResponseStreamDataFrame();
  TestRawResponseFromFrameZero();
  TestFreshUnknownUnidirectionalStream();
  TestUploadExceedsQuicStreamWindow();
  TestRejectedRequestStream();
  TestDownloadReceiveRate();
  curl_global_cleanup();
  return 0;
}
