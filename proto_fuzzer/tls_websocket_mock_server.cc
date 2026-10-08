/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Secure WebSocket peer carried by the in-process TLS transport.

#include "proto_fuzzer/tls_websocket_mock_server.h"

namespace proto_fuzzer {

/// Construct a secure WebSocket peer with the selected certificate chain.
/// @param certificate_chain Fixed certificate-chain profile to present.
TlsWebSocketMockServer::TlsWebSocketMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain)
    : transport_(TlsApplicationProtocol::kHttp11, certificate_chain) {}

TlsWebSocketMockServer::~TlsWebSocketMockServer() {
  // The connection borrows transport_'s server context. Release it before the
  // derived member is destroyed rather than relying on OpenSSL ref-counting.
  connection_.reset();
}

/// Install the common WebSocket callbacks, then require verification against
/// the checked-in TLS test certificate.
/// @param easy Easy handle that will initiate the WSS exchange.
void TlsWebSocketMockServer::Install(CURL* easy) {
  WebSocketMockServer::Install(easy);
  transport_.Install(easy);
}

/// Create one TLS-wrapped socketpair for the WebSocket exchange.
/// @return Newly allocated nonblocking TLS connection.
std::unique_ptr<MockConnection> TlsWebSocketMockServer::CreateConnection() { return transport_.CreateConnection(); }

/// Advance TLS and expose only decrypted application bytes to the inherited
/// WebSocket observer.
/// @return Decrypted bytes plus TLS state transitions made during this call.
std::size_t TlsWebSocketMockServer::DrainHandshakeData() {
  return connection_ == nullptr ? 0 : connection_->DrainIncoming();
}

/// Turn queued application plaintext into TLS records before curl's next
/// receive call, including the final frame in a manual-drive scenario.
void TlsWebSocketMockServer::FlushTransport() {
  if (connection_ != nullptr) {
    (void)connection_->DrainIncoming();
  }
}

/// @return Number of TLS handshakes completed by this peer.
std::size_t TlsWebSocketMockServer::completed_handshake_count() const { return transport_.completed_handshake_count(); }

}  // namespace proto_fuzzer
