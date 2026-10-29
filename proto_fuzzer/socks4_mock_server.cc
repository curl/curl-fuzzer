/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief SOCKS/HAProxy option policy layered over the stream mock.

#include "proto_fuzzer/socks4_mock_server.h"

#include <curl/curl.h>

#include <algorithm>
#include <cstddef>
#include <memory>

namespace proto_fuzzer {

namespace {

long ProxyType(curl::fuzzer::proto::SocksProxyMode mode) {
  switch (mode) {
    case curl::fuzzer::proto::SOCKS_PROXY_SOCKS4A:
      return CURLPROXY_SOCKS4A;
    case curl::fuzzer::proto::SOCKS_PROXY_SOCKS5:
      return CURLPROXY_SOCKS5;
    case curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME:
      return CURLPROXY_SOCKS5_HOSTNAME;
    case curl::fuzzer::proto::SOCKS_PROXY_SOCKS4:
    default:
      return CURLPROXY_SOCKS4;
  }
}

const char* ProxyUrl(curl::fuzzer::proto::SocksProxyMode mode) {
  switch (mode) {
    case curl::fuzzer::proto::SOCKS_PROXY_SOCKS4A:
      return "socks4a://127.0.0.1:1080";
    case curl::fuzzer::proto::SOCKS_PROXY_SOCKS5:
      return "socks5://127.0.0.1:1080";
    case curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME:
      return "socks5h://127.0.0.1:1080";
    case curl::fuzzer::proto::SOCKS_PROXY_SOCKS4:
    default:
      return "socks4://127.0.0.1:1080";
  }
}

}  // namespace

/// Select a fixed SOCKS wire version, resolution side, and optional HAProxy
/// prefix. Script bytes still decide which advertised SOCKS5 authentication
/// method the peer selects.
/// @param mode Proxy protocol and hostname-resolution mode to install.
/// @param haproxy_protocol Whether to send a fixed protocol-v1 prefix after
///        SOCKS tunnel establishment.
ProxyTransportMockServer::ProxyTransportMockServer(curl::fuzzer::proto::SocksProxyMode mode, bool haproxy_protocol)
    : mode_(mode), haproxy_protocol_(haproxy_protocol) {}

/// Install common socket callbacks and the fixed SOCKS proxy policy.
/// @param easy Easy handle to configure.
void ProxyTransportMockServer::Install(CURL* easy) {
  MockServer::Install(easy);
  client_transcript_.clear();

  // CONNECT_TO applies to the origin and would replace the hostname that the
  // SOCKS request is meant to exercise. The numeric proxy cannot require DNS,
  // while OPENSOCKETFUNCTION still replaces its outbound socket with the
  // in-process peer.
  static constexpr char kProxyUser[] = "fuzz-user";
  static constexpr char kProxyPassword[] = "fuzz-pass";
  static constexpr char kHaproxyClientIp[] = "127.0.0.1";
  (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY, ProxyUrl(mode_));
  (void)curl_easy_setopt(easy, CURLOPT_PROXYTYPE, ProxyType(mode_));
  (void)curl_easy_setopt(easy, CURLOPT_NOPROXY, "");
  (void)curl_easy_setopt(easy, CURLOPT_PROXYUSERNAME, kProxyUser);
  (void)curl_easy_setopt(easy, CURLOPT_PROXYPASSWORD, kProxyPassword);
  // Advertise no-auth plus username/password only. This keeps the client hello
  // deterministic while letting the scripted method-selection response enter
  // either SOCKS5 branch.
  (void)curl_easy_setopt(easy, CURLOPT_SOCKS5_AUTH, static_cast<long>(CURLAUTH_BASIC));
  // The locally resolved SOCKS5 mode must be deterministic across hosts that
  // expose both ::1 and 127.0.0.1 for localhost.
  (void)curl_easy_setopt(easy, CURLOPT_IPRESOLVE, static_cast<long>(CURL_IPRESOLVE_V4));
  (void)curl_easy_setopt(easy, CURLOPT_HAPROXY_CLIENT_IP, haproxy_protocol_ ? kHaproxyClientIp : nullptr);
  (void)curl_easy_setopt(easy, CURLOPT_HAPROXYPROTOCOL, haproxy_protocol_ ? 1L : 0L);
}

/// @return Bounded client bytes observed during the latest transfer.
const std::string& ProxyTransportMockServer::client_transcript() const { return client_transcript_; }

/// Create one socketpair peer and attach the raw-byte transcript observer.
/// @return A fresh in-process stream connection.
std::unique_ptr<MockConnection> ProxyTransportMockServer::CreateConnection() {
  auto connection = std::make_unique<MockConnection>();
  connection->SetIncomingDataObserver(this);
  return connection;
}

/// @return True because the proxy peer services each bounded perform turn.
bool ProxyTransportMockServer::SupportsRepeatedPollsetProbe() const { return true; }

/// Retain a bounded prefix of client bytes for strict integration tests.
/// @param data First byte in this drained fragment.
/// @param size Number of bytes available at `data`.
void ProxyTransportMockServer::ObserveIncomingData(const unsigned char* data, std::size_t size) {
  if (data == nullptr || size == 0 || client_transcript_.size() >= kMaxTranscriptBytes) {
    return;
  }
  const std::size_t remaining = kMaxTranscriptBytes - client_transcript_.size();
  client_transcript_.append(reinterpret_cast<const char*>(data), std::min(size, remaining));
}

/// Retain protocol outcomes in coverage and introspector builds.
void ProxyTransportMockServer::ObserveState() {
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  MockServer::ObserveState();
  const volatile std::size_t proxy_observation = client_transcript().size();
  (void)proxy_observation;
#endif
}

}  // namespace proto_fuzzer
