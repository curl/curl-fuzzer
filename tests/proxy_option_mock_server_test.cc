/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdlib>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/proxy_option_mock_server.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::ProxySocketOptionMode;
using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct RunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string response;
  std::string transcript;
};

RunResult RunSocketpairMode(ProxySocketOptionMode mode,
                            const std::string &host_path) {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path(host_path);
  scenario.mutable_connection()->add_on_readable(
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");

  RunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "proxy-option test could not allocate easy handle");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_HTTP));
  const std::string url = "http://" + host_path;
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url.c_str()) == CURLE_OK &&
             curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                              &CollectResponse) == CURLE_OK &&
             curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA,
                              &result.response) == CURLE_OK,
         "proxy-option test could not configure its request");

  proto_fuzzer::ProxyOptionMockServer server(mode);
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  if (server.connection() != nullptr) {
    (void)server.connection()->DrainIncoming();
  }
  result.transcript = server.client_transcript();
  easy.reset();
  connect_to.reset();
  return result;
}

void ExpectOriginForm(ProxySocketOptionMode mode, const std::string &host_path,
                      const char *request_target) {
  const RunResult result = RunSocketpairMode(mode, host_path);
  Expect(result.code == CURLE_OK && result.response == "ok",
         "fixed no-proxy transfer did not complete");
  const std::string request =
      std::string("GET ") + request_target + " HTTP/1.1\r\n";
  Expect(result.transcript.find(request) == 0,
         "fixed no-proxy transfer did not use origin form");
}

void TestNoProxyMatchers() {
  ExpectOriginForm(curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_HOSTNAME,
                   "service.proxy.test/hostname", "/hostname");
  ExpectOriginForm(curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_IPV4_CIDR,
                   "127.0.0.2/ipv4", "/ipv4");
  ExpectOriginForm(curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_IPV6_CIDR,
                   "[::1]/ipv6", "/ipv6");
}

void TestEnvironmentProxyIsScopedAndUsesAbsoluteForm() {
  const char *current = std::getenv("http_proxy");
  const bool was_set = current != nullptr;
  const std::string saved = current == nullptr ? std::string() : current;

  const RunResult result =
      RunSocketpairMode(curl::fuzzer::proto::PROXY_SOCKET_OPTION_ENV_HTTP_PROXY,
                        "proxy-origin.test/environment");
  Expect(result.code == CURLE_OK && result.response == "ok",
         "fixed environment proxy transfer did not complete");
  Expect(result.transcript.find(
             "GET http://proxy-origin.test/environment HTTP/1.1\r\n") == 0,
         "environment proxy request did not use absolute form");

  current = std::getenv("http_proxy");
  Expect((current != nullptr) == was_set,
         "environment proxy changed whether http_proxy was set");
  if (was_set) {
    Expect(saved == current,
           "environment proxy did not restore the prior http_proxy value");
  }
}

void TestLoopbackInterfaceAndKeepalive() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("resolve.test/interface");
  scenario.mutable_connection()->add_on_readable(
      "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n"
      "loopback");

  std::string response;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr,
         "interface-option test could not allocate easy handle");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_HTTP));
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL,
                          "http://resolve.test/interface") == CURLE_OK &&
             curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                              &CollectResponse) == CURLE_OK &&
             curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &response) ==
                 CURLE_OK,
         "interface-option test could not configure its request");

  proto_fuzzer::InterfaceOptionMockServer server;
  server.Install(easy.get());
  CURLcode code = CURLE_FAILED_INIT;
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    server.ConfigureRequestData(&request_data);
    code = server.DriveScenario(easy.get(), scenario);
  }

  char *local_ip = nullptr;
  Expect(code == CURLE_OK && response == "loopback",
         "interface/keepalive transfer did not complete");
  Expect(server.opened_socket_count() >= 2 && server.accepted_peer_count() >= 1,
         "interface/keepalive mode did not use owned loopback TCP sockets");
  Expect(curl_easy_getinfo(easy.get(), CURLINFO_LOCAL_IP, &local_ip) ==
                 CURLE_OK &&
             local_ip != nullptr && std::string(local_ip) == "127.0.0.1",
         "interface option did not bind the client to loopback");

  easy.reset();
  connect_to.reset();
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    test_support::Fail("curl_global_init failed");
  }
  TestNoProxyMatchers();
  TestEnvironmentProxyIsScopedAndUsesAbsoluteForm();
  TestLoopbackInterfaceAndKeepalive();
  curl_global_cleanup();
  return 0;
}
