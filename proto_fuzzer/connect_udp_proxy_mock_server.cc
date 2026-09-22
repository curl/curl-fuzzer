/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief HTTP/1.1 CONNECT-UDP option policy over the stream mock transport.

#include "proto_fuzzer/connect_udp_proxy_mock_server.h"

#include <curl/curl.h>

#include "proto_fuzzer/tls_test_credentials.h"

namespace proto_fuzzer {

void ConnectUdpProxyMockServer::Install(CURL* easy) {
  MockServer::Install(easy);

  // The numeric proxy authority avoids DNS before OPENSOCKETFUNCTION replaces
  // its transport with MockServer's socketpair. Clearing CONNECT_TO preserves
  // the scenario's origin in the MASQUE URI template rather than rewriting it
  // to the baseline loopback sentinel.
  static constexpr char kProxyUrl[] = "http://127.0.0.1:80";
  struct curl_blob trust_anchor = {const_cast<char*>(tls_test_credentials::kCertificatePem),
                                   sizeof(tls_test_credentials::kCertificatePem) - 1, CURL_BLOB_NOCOPY};
  (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY, kProxyUrl);
  (void)curl_easy_setopt(easy, CURLOPT_PROXYTYPE, static_cast<long>(CURLPROXY_HTTP));
  (void)curl_easy_setopt(easy, CURLOPT_NOPROXY, "");
  (void)curl_easy_setopt(easy, CURLOPT_HTTPPROXYTUNNEL, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3ONLY);

  // Capsules carry the origin's QUIC/TLS exchange, so retain the same fixed
  // trust anchor and hostname verification as the direct HTTP/3 peer.
  (void)curl_easy_setopt(easy, CURLOPT_CAINFO_BLOB, &trust_anchor);
  (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
}

}  // namespace proto_fuzzer
