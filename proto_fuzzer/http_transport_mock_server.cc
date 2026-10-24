/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Fixed HTTP proxy and Unix-domain option policy.

#include "proto_fuzzer/http_transport_mock_server.h"

#include <curl/curl.h>

#include <algorithm>
#include <cstddef>
#include <memory>

namespace proto_fuzzer {

namespace {

constexpr char kProxyUrl[] = "http://127.0.0.1:8080";
constexpr char kAbstractUnixSocket[] = "curl-fuzzer-http-origin";

}  // namespace

/// Construct an idle transport peer for one policy-normalized mode.
/// @param mode Fixed proxy or Unix-domain route to install.
HttpTransportMockServer::HttpTransportMockServer(curl::fuzzer::proto::HttpTransportMode mode) : mode_(mode) {}

/// Install socket callbacks followed by the fixed routing options. The
/// scenario's scalar option allowlist contains no routing options, so these
/// settings remain authoritative when the common runner applies mutations.
/// @param easy Easy handle to configure.
void HttpTransportMockServer::Install(CURL* easy) {
  MockServer::Install(easy);
  client_transcript_.clear();

  switch (mode_) {
    case curl::fuzzer::proto::HTTP_TRANSPORT_FORWARD_PROXY:
    case curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY:
      // The baseline CONNECT_TO entry belongs to direct origins. A numeric
      // proxy avoids DNS, while OPENSOCKETFUNCTION replaces its socket with
      // the in-process peer before any network I/O can occur.
      (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
      (void)curl_easy_setopt(easy, CURLOPT_PROXY, kProxyUrl);
      (void)curl_easy_setopt(easy, CURLOPT_PROXYTYPE, static_cast<long>(CURLPROXY_HTTP));
      (void)curl_easy_setopt(easy, CURLOPT_NOPROXY, "");
      (void)curl_easy_setopt(easy, CURLOPT_HTTPPROXYTUNNEL,
                             mode_ == curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY ? 1L : 0L);
      break;

    case curl::fuzzer::proto::HTTP_TRANSPORT_UNIX_SOCKET:
      // Abstract namespace sockets create no filesystem entry. The callback
      // still substitutes a preconnected socketpair, but curl constructs its
      // production Unix peer, resolver result, and socket filter first.
      (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
      (void)curl_easy_setopt(easy, CURLOPT_ABSTRACT_UNIX_SOCKET, kAbstractUnixSocket);
      break;

    case curl::fuzzer::proto::HTTP_TRANSPORT_DIRECT:
    default:
      break;
  }
}

/// @return Bounded client bytes observed during the latest transfer.
const std::string& HttpTransportMockServer::client_transcript() const { return client_transcript_; }

/// Create one socketpair and attach the transcript observer.
/// @return Fresh in-process stream connection.
std::unique_ptr<MockConnection> HttpTransportMockServer::CreateConnection() {
  auto connection = std::make_unique<MockConnection>();
  connection->SetIncomingDataObserver(this);
  return connection;
}

/// The request-aware peer drains every bounded perform turn, so repeated
/// zero-timeout poll probes cannot strand client output.
/// @return true for all fixed transport modes.
bool HttpTransportMockServer::SupportsRepeatedPollsetProbe() const { return true; }

/// Retain a bounded raw transcript for strict request-shape tests.
/// @param data First byte in this drained fragment.
/// @param size Number of bytes available at `data`.
void HttpTransportMockServer::ObserveIncomingData(const unsigned char* data, std::size_t size) {
  if (data == nullptr || size == 0 || client_transcript_.size() >= kMaxTranscriptBytes) {
    return;
  }
  const std::size_t remaining = kMaxTranscriptBytes - client_transcript_.size();
  client_transcript_.append(reinterpret_cast<const char*>(data), std::min(size, remaining));
}

}  // namespace proto_fuzzer
