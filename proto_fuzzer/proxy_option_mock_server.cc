/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of closed proxy and socket option peers.

#include "proto_fuzzer/proxy_option_mock_server.h"

#include <curl/curl.h>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <string>

namespace proto_fuzzer {

namespace {

constexpr char kHostnameNoProxy[] = "not-proxy.test, .proxy.test.";
constexpr char kIpv4NoProxy[] = "192.0.2.0/24, 127.0.0.0/8";
constexpr char kIpv6NoProxy[] = "2001:db8::/32, ::1/128";
constexpr char kEnvironmentProxy[] = "http://127.0.0.1:8080";
constexpr char kLoopbackInterface[] = "host!127.0.0.1";

}  // namespace

/// Construct an idle peer for one policy-normalized mode.
/// @param mode Fixed no-proxy or environment-proxy behavior to install.
ProxyOptionMockServer::ProxyOptionMockServer(curl::fuzzer::proto::ProxySocketOptionMode mode)
    : mode_(mode), setup_ok_(true), proxy_environment_active_(false), saved_http_proxy_was_set_(false) {}

/// Restore process environment after curl has released the easy handle.
ProxyOptionMockServer::~ProxyOptionMockServer() { EndProxyEnvironment(); }

/// Install socket callbacks and one fixed routing option. No mode consumes a
/// fuzz-controlled endpoint, token, interface, or environment value.
/// @param easy Easy handle to configure.
void ProxyOptionMockServer::Install(CURL* easy) {
  MockServer::Install(easy);
  client_transcript_.clear();
  setup_ok_ = true;

  CURLcode result = CURLE_OK;
  switch (mode_) {
    case curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_HOSTNAME:
      result = curl_easy_setopt(easy, CURLOPT_NOPROXY, kHostnameNoProxy);
      break;
    case curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_IPV4_CIDR:
      result = curl_easy_setopt(easy, CURLOPT_NOPROXY, kIpv4NoProxy);
      break;
    case curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_IPV6_CIDR:
      result = curl_easy_setopt(easy, CURLOPT_NOPROXY, kIpv6NoProxy);
      break;
    case curl::fuzzer::proto::PROXY_SOCKET_OPTION_ENV_HTTP_PROXY:
      setup_ok_ = BeginProxyEnvironment();
      if (setup_ok_) {
        result = curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
      }
      if (result == CURLE_OK) {
        result = curl_easy_setopt(easy, CURLOPT_NOPROXY, "");
      }
      if (result == CURLE_OK) {
        result = curl_easy_setopt(easy, CURLOPT_PROXY, nullptr);
      }
      break;
    case curl::fuzzer::proto::PROXY_SOCKET_OPTION_DEFAULT:
    case curl::fuzzer::proto::PROXY_SOCKET_OPTION_LOOPBACK_INTERFACE_KEEPALIVE:
    default:
      break;
  }
  setup_ok_ = setup_ok_ && result == CURLE_OK;
}

/// @return Bounded bytes curl wrote during the latest socketpair transfer.
const std::string& ProxyOptionMockServer::client_transcript() const { return client_transcript_; }

/// Attach the transcript observer to a fresh in-process connection.
/// @return Fresh socketpair stream connection.
std::unique_ptr<MockConnection> ProxyOptionMockServer::CreateConnection() {
  auto connection = std::make_unique<MockConnection>();
  connection->SetIncomingDataObserver(this);
  return connection;
}

/// Retain a bounded request transcript for exact routing assertions.
/// @param data First byte in this drained fragment.
/// @param size Number of bytes available at `data`.
void ProxyOptionMockServer::ObserveIncomingData(const unsigned char* data, std::size_t size) {
  if (data == nullptr || size == 0 || client_transcript_.size() >= kMaxTranscriptBytes) {
    return;
  }
  const std::size_t remaining = kMaxTranscriptBytes - client_transcript_.size();
  client_transcript_.append(reinterpret_cast<const char*>(data), std::min(size, remaining));
}

/// Refuse to perform if the scoped environment or fixed setopts failed.
/// @param multi Multi handle already containing `easy`.
/// @param easy Easy handle driving the transfer.
/// @param scenario Bounded response script.
void ProxyOptionMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  if (setup_ok_) {
    MockServer::RunLoop(multi, easy, scenario);
  }
}

/// Replace `http_proxy` with a fixed numeric loopback URL, preserving any
/// caller value for restoration. The fuzzer executes one input per thread;
/// curl consults the variable synchronously before starting resolver work.
/// @return true when the fixed value is active.
bool ProxyOptionMockServer::BeginProxyEnvironment() {
  if (proxy_environment_active_) {
    return true;
  }
  saved_http_proxy_.clear();
  const char* current = std::getenv("http_proxy");
  saved_http_proxy_was_set_ = current != nullptr;
  if (current != nullptr) {
    saved_http_proxy_.assign(current);
  }
  proxy_environment_active_ = true;
  if (setenv("http_proxy", kEnvironmentProxy, 1) != 0) {
    EndProxyEnvironment();
    return false;
  }
  return true;
}

/// Restore the exact `http_proxy` state saved before the fixed override.
void ProxyOptionMockServer::EndProxyEnvironment() {
  if (!proxy_environment_active_) {
    return;
  }
  if (saved_http_proxy_was_set_) {
    (void)setenv("http_proxy", saved_http_proxy_.c_str(), 1);
  } else {
    (void)unsetenv("http_proxy");
  }
  saved_http_proxy_.clear();
  saved_http_proxy_was_set_ = false;
  proxy_environment_active_ = false;
}

/// Install the inherited owned loopback TCP listener, then require curl to
/// perform its normal INET setup with a fixed local bind and keepalive policy.
/// @param easy Easy handle to configure.
void InterfaceOptionMockServer::Install(CURL* easy) {
  HappyEyeballsMockServer::Install(easy);
  (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
  (void)curl_easy_setopt(easy, CURLOPT_INTERFACE, kLoopbackInterface);
  (void)curl_easy_setopt(easy, CURLOPT_TCP_KEEPALIVE, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_TCP_KEEPIDLE, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_TCP_KEEPINTVL, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_TCP_KEEPCNT, 1L);
}

}  // namespace proto_fuzzer
