/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief HTTPS/HTTP2 proxy option policy layered over the TLS mock transport.

#include "proto_fuzzer/h2_proxy_mock_server.h"

#include <curl/curl.h>

#include "proto_fuzzer/tls_test_credentials.h"

namespace proto_fuzzer {

/// Select h2 before any connection opens; ALPN is the gate that makes curl
/// install cf-h2-proxy rather than its HTTP/1 CONNECT implementation.
H2ProxyMockServer::H2ProxyMockServer() : TlsMockServer(TlsApplicationProtocol::kHttp2) {}

/// Fix only routing and outer TLS properties. Response frames, origin method,
/// headers, and body remain scenario-controlled so mutations continue beyond
/// proxy setup instead of selecting arbitrary external proxy endpoints.
void H2ProxyMockServer::Install(CURL* easy) {
  MockServer::Install(easy);

  // A numeric loopback authority avoids DNS before OPENSOCKETFUNCTION replaces
  // the transport with its socketpair. The certificate is still verified
  // against the fixed trust anchor; hostname verification is disabled because
  // its SAN intentionally names tls.test rather than an IP address.
  static constexpr char kProxyUrl[] = "https://127.0.0.1:443";
  struct curl_blob trust_anchor = {const_cast<char*>(tls_test_credentials::kCertificatePem),
                                   sizeof(tls_test_credentials::kCertificatePem) - 1, CURL_BLOB_NOCOPY};
  // The shared baseline maps direct destinations to a loopback sentinel. Once
  // a proxy is selected that mapping instead rewrites the CONNECT authority,
  // hiding the scenario's canonical origin from cf-h2-proxy. The proxy socket
  // remains confined by OPENSOCKETFUNCTION, so detaching CONNECT_TO here is
  // both safe and necessary for meaningful authority/header coverage.
  (void)curl_easy_setopt(easy, CURLOPT_CONNECT_TO, nullptr);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY, kProxyUrl);
  (void)curl_easy_setopt(easy, CURLOPT_PROXYTYPE, static_cast<long>(CURLPROXY_HTTPS2));
  (void)curl_easy_setopt(easy, CURLOPT_NOPROXY, "");
  (void)curl_easy_setopt(easy, CURLOPT_HTTPPROXYTUNNEL, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY_CAINFO_BLOB, &trust_anchor);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY_SSL_VERIFYPEER, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY_SSL_VERIFYHOST, 0L);
}

}  // namespace proto_fuzzer
