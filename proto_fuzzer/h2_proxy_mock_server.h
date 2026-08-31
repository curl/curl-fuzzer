/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Deterministic HTTPS/HTTP2 CONNECT proxy for structured scenarios.

#ifndef PROTO_FUZZER_H2_PROXY_MOCK_SERVER_H_
#define PROTO_FUZZER_H2_PROXY_MOCK_SERVER_H_

#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// Reuses MockServer's bounded raw response script as decrypted HTTP/2 proxy
/// frames. The fixed proxy transport is deliberately separate from the
/// mutation-controlled HTTP origin: every accepted input reaches TLS ALPN and
/// CONNECT setup without DNS, while frame bytes still explore curl/nghttp2's
/// success and error paths.
class H2ProxyMockServer final : public TlsMockServer {
 public:
  H2ProxyMockServer();
  ~H2ProxyMockServer() override = default;

  H2ProxyMockServer(const H2ProxyMockServer&) = delete;
  H2ProxyMockServer& operator=(const H2ProxyMockServer&) = delete;

  /// Install the socket transport and force one verified HTTPS2 proxy tunnel.
  /// The origin remains plaintext HTTP inside CONNECT so the same peer can
  /// service both protocol layers without a nested TLS state machine.
  /// @param easy Easy handle that will connect through this proxy.
  void Install(CURL* easy) override;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_H2_PROXY_MOCK_SERVER_H_
