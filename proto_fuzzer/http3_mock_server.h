/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded ngtcp2/OpenSSL QUIC peer for HTTP/3 scenarios.

#ifndef PROTO_FUZZER_HTTP3_MOCK_SERVER_H_
#define PROTO_FUZZER_HTTP3_MOCK_SERVER_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "proto_fuzzer/mock_server_base.h"

namespace proto_fuzzer {

class Http3MockServerImpl;

/// @class proto_fuzzer::Http3MockServer
/// @brief In-process HTTP/3 server backed by ngtcp2 and OpenSSL TLS.
///
/// The peer uses a real nonblocking IPv4 UDP socket, negotiates TLS 1.3 and
/// ALPN `h3`, and lets nghttp3 generate protocol-valid structured responses.
/// Raw Http3StreamWrite actions deliberately bypass nghttp3 and write their
/// bytes straight to an established QUIC stream. Open-unidirectional-stream
/// actions additionally create an unbound stream whose first byte is entirely
/// mutation-controlled. ngtcp2 applies QUIC framing and uses OpenSSL's EVP/TLS
/// integration for encryption, so malformed HTTP/3/QPACK plaintext reaches
/// curl only after a valid transport handshake.
class Http3MockServer final : public MockServerBase {
 public:
  Http3MockServer();

  explicit Http3MockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain);

  ~Http3MockServer() override;

  Http3MockServer(const Http3MockServer&) = delete;
  Http3MockServer& operator=(const Http3MockServer&) = delete;

  void Install(CURL* easy) override;

  bool handshake_complete() const;

  bool request_headers_received() const;

  std::size_t executed_action_count() const;

  std::uint16_t server_port() const;

 protected:
  curl_socket_t HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) override;

  SocketSetupDisposition GetSocketSetupDisposition(curl_socket_t curlfd, curlsocktype purpose) const override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  std::unique_ptr<Http3MockServerImpl> impl_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_HTTP3_MOCK_SERVER_H_
