/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>

#include "curl_fuzzer.pb.h"
#include "generated/deep_http/deep_http_traits.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/http_transport_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/target_policy.h"
#include "test_assertions.h"
#include "tests/projected_scenario_loader.h"

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

  proto_fuzzer::HttpTransportMockServer server(mode,
                                               scenario.haproxy_protocol());
  server.Install(easy.get());
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  if (server.connection() != nullptr) {
    // The transfer is over, so release any test-only drain cap before taking
    // the final transcript snapshot. Backpressure may leave accepted request
    // bytes queued in the socket even though curl has completed its send.
    server.connection()->ApplyBackpressure(0, 0);
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

void TestConnectProxyHaproxyPendingSendSeed() {
  const std::string path =
      std::string(PROTO_FUZZER_SCENARIO_DIR) +
      "/http_deep/http_connect_haproxy_backpressure.textproto";
  std::ifstream input(path);
  Expect(input.is_open(), "could not read the CONNECT/HAProxy seed");
  const std::string text((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
  Scenario scenario;
  Expect(test_support::ParseAndLowerProjectedScenario<
             proto_fuzzer::generated::DeepHttpTraits>(text, &scenario),
         "could not parse the CONNECT/HAProxy seed");
  proto_fuzzer::NormalizeScenarioForTarget(
      &scenario, proto_fuzzer::generated::DeepHttpTraits::kProfile,
      &proto_fuzzer::generated::DeepHttpTraits::PruneConditionalEligibility);
  Expect(scenario.http_transport_mode() ==
                 curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY &&
             scenario.haproxy_protocol() && scenario.probe_multi_pollset() &&
             scenario.connection().backpressure().recv_buf_bytes() == 2048 &&
             scenario.connection().backpressure().drain_limit() == 48,
         "CONNECT/HAProxy seed lost its correlated pressure controls");

  const RunResult result =
      RunScenario(scenario, scenario.http_transport_mode());
  ExpectCompleted(result, "CONNECT/HAProxy transfer did not complete");
  Expect(result.response == "proxied",
         "CONNECT/HAProxy transfer returned the wrong response body");

  const std::string connect = "CONNECT transport.test:80 HTTP/1.1\r\n";
  Expect(result.transcript.find(connect) == 0,
         "CONNECT/HAProxy request line changed");
  const std::size_t connect_end = result.transcript.find("\r\n\r\n");
  Expect(connect_end != std::string::npos,
         "CONNECT/HAProxy request was not terminated");
  const std::size_t connect_padding =
      result.transcript.find("X-Haproxy-Pad-1: ");
  Expect(connect_padding != std::string::npos && connect_padding < connect_end,
         "HAProxy pressure headers did not fill the CONNECT request");
  const std::size_t proxy_start = connect_end + 4;
  if (result.transcript.find("PROXY TCP6 ", proxy_start) != proxy_start) {
    Fail(("HAProxy prefix did not immediately follow CONNECT: " +
          result.transcript.substr(proxy_start, 256))
             .c_str());
  }
  const std::size_t proxy_end = result.transcript.find("\r\n", proxy_start);
  Expect(proxy_end != std::string::npos, "HAProxy prefix was not terminated");
  Expect(proxy_end - proxy_start + 2 >
             2 * scenario.connection().backpressure().drain_limit(),
         "two bounded peer drains can release the complete HAProxy prefix");
  std::istringstream fields(
      result.transcript.substr(proxy_start, proxy_end - proxy_start));
  std::string marker;
  std::string family;
  std::string source;
  std::string destination;
  int source_port = -1;
  int destination_port = -1;
  std::string trailing;
  fields >> marker >> family >> source >> destination >> source_port >>
      destination_port >> trailing;
  constexpr char kFixedIpv6[] = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
  Expect(marker == "PROXY" && family == "TCP6" && source == kFixedIpv6 &&
             destination == kFixedIpv6 && source_port >= 0 &&
             source_port <= 65535 && destination_port >= 0 &&
             destination_port <= 65535 && trailing.empty(),
         "HAProxy prefix did not use the fixed IPv6 endpoint shape");

  const std::size_t request =
      result.transcript.find("GET /haproxy-poll HTTP/1.1\r\n", proxy_end + 2);
  Expect(request == proxy_end + 2,
         "origin request did not immediately follow the HAProxy prefix");
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
  TestConnectProxyHaproxyPendingSendSeed();
  TestUnixSocketUsesOriginForm();
  curl_global_cleanup();
  return 0;
}
