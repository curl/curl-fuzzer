/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/http_transport_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::HttpTransportMode;
using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  auto *response = static_cast<std::string *>(userdata);
  const std::size_t bytes = size * nmemb;
  response->append(contents, bytes);
  return bytes;
}

struct RunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string response;
  std::string transcript;
  std::size_t opened_connections = 0;
};

RunResult RunScenario(const Scenario &scenario, HttpTransportMode mode) {
  RunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_HTTP));
  Expect(connect_to != nullptr, "HTTP baseline did not create CONNECT_TO");
  const std::string url = "http://" + scenario.host_path();
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url.c_str()) == CURLE_OK,
         "HTTP transport URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK &&
             curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA,
                              &result.response) == CURLE_OK,
         "HTTP transport response callback setup failed");

  proto_fuzzer::HttpTransportMockServer server(mode);
  server.Install(easy.get());
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  if (server.connection() != nullptr) {
    (void)server.connection()->DrainIncoming();
  }
  result.transcript = server.client_transcript();
  result.opened_connections = server.opened_connection_count();

  easy.reset();
  connect_to.reset();
  return result;
}

void ExpectCompleted(const RunResult &result, const char *message) {
  if (result.code != CURLE_OK) {
    Fail((std::string(message) + ": " + curl_easy_strerror(result.code))
             .c_str());
  }
  Expect(result.opened_connections == 1,
         "HTTP transport opened an unexpected number of sockets");
}

void TestForwardProxyUsesAbsoluteForm() {
  Scenario scenario;
  scenario.set_host_path("transport.test/forward?mode=proxy");
  scenario.mutable_connection()->add_on_readable(
      "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n"
      "forward");

  const RunResult result =
      RunScenario(scenario, curl::fuzzer::proto::HTTP_TRANSPORT_FORWARD_PROXY);
  ExpectCompleted(result, "forward-proxy transfer did not complete");
  Expect(result.response == "forward",
         "forward proxy returned the wrong response body");
  if (result.transcript.find(
          "GET http://transport.test/forward?mode=proxy HTTP/1.1\r\n") != 0) {
    Fail(("forward proxy request did not use absolute form: " +
          result.transcript)
             .c_str());
  }
}

void TestConnectProxyCarriesOriginRequest() {
  Scenario scenario;
  scenario.set_host_path("transport.test/tunneled");
  scenario.set_probe_multi_pollset(true);
  scenario.mutable_connection()->add_on_readable(
      "HTTP/1.1 200 Connection Established\r\n"
      "Proxy-Agent: proto-fuzzer\r\n\r\n");
  scenario.mutable_connection()->add_on_readable(
      "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n"
      "tunneled");

  const RunResult result =
      RunScenario(scenario, curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY);
  ExpectCompleted(result, "CONNECT-proxy transfer did not complete");
  Expect(result.response == "tunneled",
         "CONNECT proxy returned the wrong tunneled response body");
  const std::string connect = "CONNECT transport.test:80 HTTP/1.1\r\n";
  Expect(result.transcript.find(connect) == 0,
         "CONNECT proxy request line changed");
  const std::size_t request =
      result.transcript.find("GET /tunneled HTTP/1.1\r\n");
  if (request == std::string::npos || request <= connect.size()) {
    Fail(("origin request did not follow the CONNECT handshake: " +
          result.transcript)
             .c_str());
  }
}

void TestUnixSocketUsesOriginForm() {
  Scenario scenario;
  scenario.set_host_path("transport.test/unix");
  scenario.mutable_connection()->add_on_readable(
      "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"
      "unix");

  const RunResult result =
      RunScenario(scenario, curl::fuzzer::proto::HTTP_TRANSPORT_UNIX_SOCKET);
  ExpectCompleted(result, "Unix-domain HTTP transfer did not complete");
  Expect(result.response == "unix",
         "Unix-domain origin returned the wrong response body");
  Expect(result.transcript.find("GET /unix HTTP/1.1\r\n") == 0,
         "Unix-domain origin request did not use origin form");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestForwardProxyUsesAbsoluteForm();
  TestConnectProxyCarriesOriginRequest();
  TestUnixSocketUsesOriginForm();
  curl_global_cleanup();
  return 0;
}
