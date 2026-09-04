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
  /// Construct a peer with the default checked-in EC certificate.
  Http3MockServer();

  /// Construct a peer with a bounded, parseable certificate-chain profile.
  /// @param certificate_chain Certificate material presented during QUIC TLS.
  explicit Http3MockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain);

  ~Http3MockServer() override;

  Http3MockServer(const Http3MockServer&) = delete;
  Http3MockServer& operator=(const Http3MockServer&) = delete;

  /// Install UDP socket callbacks, the local trust anchor, and HTTP/3-only
  /// negotiation on an easy handle.
  /// @param easy Easy handle that will connect to the in-process QUIC peer.
  void Install(CURL* easy) override;

  /// @return true after the server has completed a QUIC TLS handshake.
  bool handshake_complete() const;

  /// @return true after nghttp3 has decoded a complete request field section.
  bool request_headers_received() const;

  /// @return number of ordered Http3Action entries accepted by the peer.
  std::size_t executed_action_count() const;

  /// @return kernel-selected UDP port in host byte order, or zero before use.
  std::uint16_t server_port() const;

 protected:
  /// Create curl's real UDP descriptor and rewrite its destination to the
  /// private loopback QUIC listener.
  /// @param purpose Socket purpose supplied by curl's open-socket callback.
  /// @param address Mutable destination description supplied by curl.
  /// @return client UDP descriptor, or CURL_SOCKET_BAD on setup failure.
  curl_socket_t HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) override;

  /// Alternate nonblocking curl and QUIC server turns under fixed operation
  /// and idle budgets.
  /// @param multi Multi handle containing the scenario's easy handle.
  /// @param easy Easy handle being driven; all work is reached through multi.
  /// @param scenario Scenario whose Http3Plan supplies ordered plaintext work.
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  std::unique_ptr<Http3MockServerImpl> impl_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_HTTP3_MOCK_SERVER_H_
