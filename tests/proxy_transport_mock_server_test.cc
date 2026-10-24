/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/socks4_mock_server.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using curl::fuzzer::proto::SocksProxyMode;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

const std::string kSocks5Connected("\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50",
                                   10);
const std::string kHttpOk(
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

size_t DiscardResponse(char * /*contents*/, size_t size, size_t nmemb,
                       void * /*userdata*/) {
  return size * nmemb;
}

struct RunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string transcript;
};

RunResult RunScenario(const Scenario &scenario, SocksProxyMode mode,
                      bool haproxy_protocol, const char *url) {
  RunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_HTTP));
  Expect(connect_to != nullptr,
         "HTTP baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "proxy-transport URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &DiscardResponse) == CURLE_OK,
         "proxy-transport write callback setup failed");

  proto_fuzzer::ProxyTransportMockServer server(mode, haproxy_protocol);
  server.Install(easy.get());
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.client_transcript();

  easy.reset();
  connect_to.reset();
  return result;
}

void ExpectStartsWith(std::string_view actual, std::string_view expected,
                      const char *message) {
  Expect(actual.size() >= expected.size() &&
             actual.substr(0, expected.size()) == expected,
         message);
}

std::string HexTranscript(std::string_view transcript) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const unsigned char byte : transcript) {
    output << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return output.str();
}

void ExpectCompleted(const RunResult &result, const char *message) {
  if (result.code == CURLE_OK) {
    return;
  }
  const std::string diagnostic =
      std::string(message) + ": " + curl_easy_strerror(result.code) +
      "; transcript=" + HexTranscript(result.transcript);
  Fail(diagnostic.c_str());
}

void TestSocks5LocalNoAuthTranscript() {
  Scenario scenario;
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable(std::string("\x05\x00", 2));
  connection->add_on_readable(kSocks5Connected);
  connection->add_on_readable(kHttpOk);

  const RunResult result =
      RunScenario(scenario, curl::fuzzer::proto::SOCKS_PROXY_SOCKS5, false,
                  "http://localhost/local");
  ExpectCompleted(result, "locally resolved SOCKS5 transfer did not complete");

  const std::string greeting("\x05\x02\x00\x02", 4);
  const std::string connect =
      std::string("\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50", 10);
  const std::string expected = greeting + connect;
  ExpectStartsWith(result.transcript, expected,
                   "SOCKS5 local handshake transcript changed");
  Expect(result.transcript.find("GET /local HTTP/1.1\r\n", expected.size()) ==
             expected.size(),
         "HTTP request did not immediately follow the SOCKS5 tunnel");
}

void TestSocks5HostnameAuthAndHaproxyTranscript() {
  Scenario scenario;
  scenario.set_probe_multi_pollset(true);
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable(std::string("\x05\x02", 2));
  connection->add_on_readable(std::string("\x01\x00", 2));
  connection->add_on_readable(kSocks5Connected);
  connection->add_on_readable(kHttpOk);

  const RunResult result =
      RunScenario(scenario, curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME,
                  true, "http://socks.test/auth");
  ExpectCompleted(result,
                  "authenticated SOCKS5/HAProxy transfer did not complete");

  const std::string greeting("\x05\x02\x00\x02", 4);
  const std::string authentication = std::string("\x01\x09", 2) + "fuzz-user" +
                                     std::string("\x09", 1) + "fuzz-pass";
  const std::string connect = std::string("\x05\x01\x00\x03\x0a", 5) +
                              "socks.test" + std::string("\x00\x50", 2);
  const std::string socks_transcript = greeting + authentication + connect;
  ExpectStartsWith(result.transcript, socks_transcript,
                   "SOCKS5 username/password transcript changed");

  const std::size_t proxy_end =
      result.transcript.find("\r\n", socks_transcript.size());
  Expect(proxy_end != std::string::npos,
         "HAProxy protocol prefix was not terminated");
  const std::string proxy_line = result.transcript.substr(
      socks_transcript.size(), proxy_end - socks_transcript.size());
  std::istringstream fields(proxy_line);
  std::string marker;
  std::string family;
  std::string source;
  std::string destination;
  int source_port = -1;
  int destination_port = -1;
  std::string trailing;
  fields >> marker >> family >> source >> destination >> source_port >>
      destination_port >> trailing;
  Expect(marker == "PROXY" && family == "TCP4" && source == "127.0.0.1" &&
             destination == "127.0.0.1" && source_port >= 0 &&
             source_port <= 65535 && destination_port >= 0 &&
             destination_port <= 65535 && trailing.empty(),
         "HAProxy prefix did not use the fixed IPv4 endpoint shape");
  Expect(result.transcript.find("GET /auth HTTP/1.1\r\n", proxy_end + 2) ==
             proxy_end + 2,
         "HTTP request did not immediately follow the HAProxy prefix");
}

void TestSocks5RejectedAuthenticationStopsBeforeConnect() {
  Scenario scenario;
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable(std::string("\x05\x02", 2));
  connection->add_on_readable(std::string("\x01\x01", 2));

  const RunResult result =
      RunScenario(scenario, curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME,
                  false, "http://socks.test/rejected");
  Expect(result.code != CURLE_OK,
         "rejected SOCKS5 authentication unexpectedly completed");

  const std::string expected = std::string("\x05\x02\x00\x02\x01\x09", 6) +
                               "fuzz-user" + std::string("\x09", 1) +
                               "fuzz-pass";
  Expect(result.transcript == expected,
         "SOCKS5 continued after the username/password rejection");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestSocks5LocalNoAuthTranscript();
  TestSocks5HostnameAuthAndHaproxyTranscript();
  TestSocks5RejectedAuthenticationStopsBeforeConnect();
  curl_global_cleanup();
  return 0;
}
