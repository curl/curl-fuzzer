/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/rtsp_mock_server.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kSdpBody[] =
    "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=curl-fuzzer\r\nt=0 0\r\n"
    "a=control:rtsp://rtsp.test/twister/video\r\n";
constexpr char kParameterBody[] = "key: value\r\n";
// One RFC 2326 interleaved frame: '$', channel 0, 12-byte payload length, then
// a minimal RTP header and sequence/timestamp fields.
constexpr char kInterleavedRtp[] =
    "$\x00\x00\x0c\x80\xe0\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01";

struct RtspRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string transcript;
  std::string uploaded;
  std::string body;
  std::size_t request_count = 0;
  std::size_t response_count = 0;
  std::uint32_t client_cseq = 0;
  std::string method;
  std::string stream_uri;
};

std::size_t CaptureBody(char *ptr, std::size_t size, std::size_t nmemb,
                        void *userdata) {
  auto *body = static_cast<std::string *>(userdata);
  body->append(ptr, size * nmemb);
  return size * nmemb;
}

RtspRunResult RunScenario(const Scenario &scenario, const char *url) {
  RtspRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_RTSP));
  Expect(connect_to != nullptr,
         "RTSP baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "RTSP URL setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION, &CaptureBody) ==
             CURLE_OK,
         "RTSP write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "RTSP write data setup failed");

  proto_fuzzer::RtspMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.uploaded = server.uploaded_data();
  result.request_count = server.request_count();
  result.response_count = server.response_count();
  result.client_cseq = server.last_client_cseq();
  result.method = server.last_method();
  result.stream_uri = server.last_stream_uri();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void AddDescribe(Scenario *scenario) {
  scenario->set_scheme(curl::fuzzer::proto::SCHEME_RTSP);
  scenario->set_host_path("rtsp.test/twister/video");
  auto *request = scenario->add_options();
  request->set_option_id(curl::fuzzer::proto::CURLOPT_RTSP_REQUEST);
  request->set_uint_value(CURL_RTSPREQ_DESCRIBE);
  auto *stream = scenario->add_options();
  stream->set_option_id(curl::fuzzer::proto::CURLOPT_RTSP_STREAM_URI);
  stream->set_string_value("rtsp://rtsp.test/twister/video");
}

void TestDescribeResponseBody() {
  Scenario scenario;
  AddDescribe(&scenario);
  const std::string response =
      std::string("RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
                  "Content-Type: application/sdp\r\nContent-Length: ") +
      std::to_string(sizeof(kSdpBody) - 1) + "\r\n\r\n" + kSdpBody;
  scenario.mutable_connection()->add_on_readable(response);

  const RtspRunResult result =
      RunScenario(scenario, "rtsp://rtsp.test/twister/video");
  Expect(result.code == CURLE_OK, "DESCRIBE transfer did not complete");
  Expect(result.request_count == 1 && result.response_count == 1,
         "RTSP peer did not pair one DESCRIBE request with one response");
  Expect(result.method == "DESCRIBE",
         "RTSP peer did not parse the DESCRIBE method");
  Expect(result.stream_uri == "rtsp://rtsp.test/twister/video",
         "RTSP peer did not parse the explicit stream URI");
  Expect(result.client_cseq == 1,
         "RTSP peer did not parse the client CSeq");
  Expect(result.transcript.find("DESCRIBE rtsp://rtsp.test/twister/video "
                                "RTSP/1.0\r\n") != std::string::npos,
         "curl did not send the configured DESCRIBE request line");
  Expect(result.transcript.find("CSeq: 1\r\n") != std::string::npos,
         "curl did not send the expected client CSeq");
  Expect(result.body == kSdpBody,
         "RTSP peer did not deliver the complete DESCRIBE entity body");
}

void TestOptionsUsesDefaultMethod() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_RTSP);
  scenario.set_host_path("rtsp.test/stream");
  scenario.mutable_connection()->add_on_readable(
      "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, OPTIONS, SETUP, PLAY, "
      "PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER\r\n\r\n");

  const RtspRunResult result =
      RunScenario(scenario, "rtsp://rtsp.test/stream");
  Expect(result.code == CURLE_OK, "OPTIONS transfer did not complete");
  Expect(result.method == "OPTIONS",
         "RTSP peer did not observe curl's default OPTIONS method");
  Expect(result.stream_uri == "*",
         "curl's default RTSP stream URI was not the wildcard target");
  Expect(result.transcript.find("OPTIONS * RTSP/1.0\r\n") != std::string::npos,
         "curl did not send a well-formed default OPTIONS request");
  Expect(result.body.empty(),
         "bodyless OPTIONS response produced unexpected entity bytes");
}

void TestCseqMismatchFailsTransfer() {
  Scenario scenario;
  AddDescribe(&scenario);
  scenario.mutable_connection()->add_on_readable(
      "RTSP/1.0 200 OK\r\nCSeq: 7\r\nContent-Length: 0\r\n\r\n");

  const RtspRunResult result =
      RunScenario(scenario, "rtsp://rtsp.test/mismatch");
  Expect(result.code == CURLE_RTSP_CSEQ_ERROR,
         "mismatched RTSP response CSeq did not fail the transfer");
  Expect(result.request_count == 1 && result.client_cseq == 1,
         "RTSP peer lost the request that triggered the CSeq mismatch");
  Expect(result.transcript.find("CSeq: 1\r\n") != std::string::npos,
         "mismatched exchange did not send the original client CSeq");
}

void TestSetParameterDrainsExactRequestBody() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_RTSP);
  scenario.set_host_path("rtsp.test/stream");
  auto *request = scenario.add_options();
  request->set_option_id(curl::fuzzer::proto::CURLOPT_RTSP_REQUEST);
  request->set_uint_value(CURL_RTSPREQ_SET_PARAMETER);
  auto *upload = scenario.add_options();
  upload->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload->set_bool_value(true);
  auto *size = scenario.add_options();
  size->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  size->set_uint_value(sizeof(kParameterBody) - 1);
  scenario.mutable_upload()->set_data(kParameterBody);
  scenario.mutable_connection()->add_on_readable(
      "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n");

  const RtspRunResult result =
      RunScenario(scenario, "rtsp://rtsp.test/stream");
  Expect(result.code == CURLE_OK,
         "SET_PARAMETER transfer with a request body did not complete");
  Expect(result.method == "SET_PARAMETER",
         "RTSP peer did not parse the SET_PARAMETER method");
  Expect(result.uploaded == kParameterBody,
         "RTSP peer did not drain exactly the announced request body");
  Expect(result.transcript.find("Content-Length: 12\r\n") != std::string::npos,
         "curl did not announce the SET_PARAMETER body length");
}

void TestPlayDeliversInterleavedRtp() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_RTSP);
  scenario.set_host_path("rtsp.test/stream");
  auto *request = scenario.add_options();
  request->set_option_id(curl::fuzzer::proto::CURLOPT_RTSP_REQUEST);
  request->set_uint_value(CURL_RTSPREQ_PLAY);
  auto *session = scenario.add_options();
  session->set_option_id(curl::fuzzer::proto::CURLOPT_RTSP_SESSION_ID);
  session->set_string_value("12345678");
  auto *range = scenario.add_options();
  range->set_option_id(curl::fuzzer::proto::CURLOPT_RANGE);
  range->set_string_value("npt=0.000-");
  scenario.mutable_connection()->add_on_readable(
      std::string("RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: 12345678\r\n"
                  "Range: npt=0.000-\r\n"
                  "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
                  "Content-Length: 0\r\n\r\n") +
      std::string(kInterleavedRtp, sizeof(kInterleavedRtp) - 1));

  const RtspRunResult result =
      RunScenario(scenario, "rtsp://rtsp.test/stream");
  Expect(result.code == CURLE_OK, "PLAY transfer did not complete");
  Expect(result.method == "PLAY", "RTSP peer did not parse the PLAY method");
  Expect(result.transcript.find("Session: 12345678\r\n") != std::string::npos,
         "curl did not send the configured RTSP session id");
  Expect(result.transcript.find("Range: npt=0.000-\r\n") != std::string::npos,
         "curl did not send the configured PLAY range");
  Expect(result.body.size() == sizeof(kInterleavedRtp) - 1 &&
             result.body.size() > 4 && result.body[0] == '$' &&
             result.body[1] == '\x00',
         "curl did not deliver the validated interleaved RTP frame");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestDescribeResponseBody();
  TestOptionsUsesDefaultMethod();
  TestCseqMismatchFailsTransfer();
  TestSetParameterDrainsExactRequestBody();
  TestPlayDeliversInterleavedRtp();
  curl_global_cleanup();
  return 0;
}
