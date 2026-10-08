/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Secure WebSocket peer carried by the in-process TLS transport.

#ifndef PROTO_FUZZER_TLS_WEBSOCKET_MOCK_SERVER_H_
#define PROTO_FUZZER_TLS_WEBSOCKET_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/tls_mock_server.h"
#include "proto_fuzzer/websocket_mock_server.h"

namespace proto_fuzzer {

/// Runs the existing WebSocket Upgrade, framing, callback, and manual-I/O
/// behavior over a verified nonblocking TLS connection.
class TlsWebSocketMockServer final : public WebSocketMockServer {
 public:
  explicit TlsWebSocketMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain =
                                      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC);
  ~TlsWebSocketMockServer() override;

  TlsWebSocketMockServer(const TlsWebSocketMockServer&) = delete;
  TlsWebSocketMockServer& operator=(const TlsWebSocketMockServer&) = delete;

  void Install(CURL* easy) override;

  std::size_t completed_handshake_count() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;
  std::size_t DrainHandshakeData() override;
  void FlushTransport() override;

 private:
  TlsMockTransport transport_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TLS_WEBSOCKET_MOCK_SERVER_H_
