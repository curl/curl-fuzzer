/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief SOCKS4 proxy option policy layered over the stream mock.

#include "proto_fuzzer/socks4_mock_server.h"

#include <curl/curl.h>

namespace proto_fuzzer {

Socks4MockServer::Socks4MockServer(curl::fuzzer::proto::SocksProxyMode mode) : mode_(mode) {}

void Socks4MockServer::Install(CURL* easy) {
  MockServer::Install(easy);

  // CONNECT_TO applies to the origin and would replace the hostname that the
  // SOCKS request is meant to exercise. The numeric proxy cannot require DNS,
  // while OPENSOCKETFUNCTION still replaces its outbound socket with the
  // in-process peer.
  static constexpr char kProxyUrl[] = "socks4://127.0.0.1:1080";
  static constexpr char kProxyUser[] = "fuzz-user";
  (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY, kProxyUrl);
  (void)curl_easy_setopt(
      easy, CURLOPT_PROXYTYPE,
      static_cast<long>(mode_ == curl::fuzzer::proto::SOCKS_PROXY_SOCKS4A ? CURLPROXY_SOCKS4A : CURLPROXY_SOCKS4));
  (void)curl_easy_setopt(easy, CURLOPT_NOPROXY, "");
  (void)curl_easy_setopt(easy, CURLOPT_PROXYUSERNAME, kProxyUser);
}

}  // namespace proto_fuzzer
