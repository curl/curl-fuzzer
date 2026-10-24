/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief HTTPS/HTTP2 proxy option policy layered over the TLS mock transport.

#include "proto_fuzzer/h2_proxy_mock_server.h"

#include <curl/curl.h>

#include <algorithm>

#include "proto_fuzzer/tls_test_credentials.h"

namespace proto_fuzzer {

/// Select the closed proxy protocol profile before any connection opens. ALPN
/// is the gate that chooses curl's H2 proxy filter or HTTP/1 CONNECT parser.
/// HTTP/1 has no direct-forwarding mode, so it always uses a tunnel.
/// @param mode Origin request shape for an HTTP/2 proxy.
/// @param protocol Fixed proxy application protocol for this server.
H2ProxyMockServer::H2ProxyMockServer(H2ProxyMode mode, curl::fuzzer::proto::ProxyProtocol protocol)
    : TlsMockServer(protocol == curl::fuzzer::proto::PROXY_PROTOCOL_HTTP1 ? TlsApplicationProtocol::kHttp11
                                                                          : TlsApplicationProtocol::kHttp2),
      mode_(protocol == curl::fuzzer::proto::PROXY_PROTOCOL_HTTP1 ? H2ProxyMode::kTunnel : mode),
      protocol_(protocol) {}

/// Install the socket transport and force one verified HTTPS proxy. Tunnel
/// mode keeps the plaintext HTTP origin inside CONNECT; the HTTP/2-only
/// forward mode submits that origin request directly on the proxy stream.
/// Only routing and outer TLS properties are fixed: response frames, origin
/// method, headers, and body remain scenario-controlled beyond setup.
/// @param easy Easy handle that will connect through this proxy.
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
  const long proxy_type = protocol_ == curl::fuzzer::proto::PROXY_PROTOCOL_HTTP1 ? static_cast<long>(CURLPROXY_HTTPS)
                                                                                 : static_cast<long>(CURLPROXY_HTTPS2);
  (void)curl_easy_setopt(easy, CURLOPT_PROXYTYPE, proxy_type);
  (void)curl_easy_setopt(easy, CURLOPT_NOPROXY, "");
  (void)curl_easy_setopt(easy, CURLOPT_HTTPPROXYTUNNEL, mode_ == H2ProxyMode::kTunnel ? 1L : 0L);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY_CAINFO_BLOB, &trust_anchor);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY_SSL_VERIFYPEER, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_PROXY_SSL_VERIFYHOST, 0L);
}

/// Attach a bounded observer after TLS decoding so tests can verify the real
/// CONNECT request rather than inferring it from the response status alone.
/// @return Newly allocated TLS connection with the transcript observer.
std::unique_ptr<MockConnection> H2ProxyMockServer::CreateConnection() {
  std::unique_ptr<MockConnection> connection = TlsMockServer::CreateConnection();
  if (connection != nullptr) {
    connection->SetIncomingDataObserver(this);
  }
  return connection;
}

/// Retain only the bounded application-data prefix emitted by curl.
void H2ProxyMockServer::ObserveIncomingData(const unsigned char* data, std::size_t size) {
  if (data == nullptr || size == 0 || client_transcript_.size() >= scenario_limits::kMaxHttp2ObservedBytes) {
    return;
  }
  const std::size_t remaining = scenario_limits::kMaxHttp2ObservedBytes - client_transcript_.size();
  client_transcript_.append(reinterpret_cast<const char*>(data), std::min(size, remaining));
}

/// @return Bounded decrypted bytes curl sent to the proxy peer.
const std::string& H2ProxyMockServer::client_transcript() const { return client_transcript_; }

}  // namespace proto_fuzzer
