/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Deterministic HTTPS/HTTP2 proxy for structured scenarios.

#ifndef PROTO_FUZZER_H2_PROXY_MOCK_SERVER_H_
#define PROTO_FUZZER_H2_PROXY_MOCK_SERVER_H_

#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// Origin-request shape carried by the fixed HTTPS/HTTP2 proxy transport.
enum class H2ProxyMode {
  /// Establish CONNECT, then carry a plaintext HTTP/1.1 origin exchange.
  kTunnel,
  /// Submit an absolute-form origin request directly as an HTTP/2 stream.
  kForward,
};

/// Reuses MockServer's bounded raw response script as decrypted HTTP/2 proxy
/// frames. The fixed proxy transport is deliberately separate from the
/// mutation-controlled HTTP origin: every accepted input reaches TLS ALPN and
/// proxy request setup without DNS, while frame bytes still explore
/// curl/nghttp2's success and error paths.
class H2ProxyMockServer final : public TlsMockServer, private IncomingDataObserver {
 public:
  explicit H2ProxyMockServer(H2ProxyMode mode = H2ProxyMode::kTunnel,
                             curl::fuzzer::proto::ProxyProtocol protocol = curl::fuzzer::proto::PROXY_PROTOCOL_HTTP2);
  ~H2ProxyMockServer() override = default;

  H2ProxyMockServer(const H2ProxyMockServer&) = delete;
  H2ProxyMockServer& operator=(const H2ProxyMockServer&) = delete;

  void Install(CURL* easy) override;

  const std::string& client_transcript() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

 private:
  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

  H2ProxyMode mode_;
  curl::fuzzer::proto::ProxyProtocol protocol_;
  std::string client_transcript_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_H2_PROXY_MOCK_SERVER_H_
