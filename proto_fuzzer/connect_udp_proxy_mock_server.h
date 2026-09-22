/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Deterministic HTTP/1.1 CONNECT-UDP proxy for HTTP/3 scenarios.

#ifndef PROTO_FUZZER_CONNECT_UDP_PROXY_MOCK_SERVER_H_
#define PROTO_FUZZER_CONNECT_UDP_PROXY_MOCK_SERVER_H_

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Reuses MockServer's bounded response script for an HTTP/1.1 proxy upgrade.
/// Curl reaches the proxy through the in-process socketpair, then carries QUIC
/// datagrams as RFC 9297 capsules over the upgraded byte stream.
class ConnectUdpProxyMockServer final : public MockServer {
 public:
  ConnectUdpProxyMockServer() = default;
  ~ConnectUdpProxyMockServer() override = default;

  ConnectUdpProxyMockServer(const ConnectUdpProxyMockServer&) = delete;
  ConnectUdpProxyMockServer& operator=(const ConnectUdpProxyMockServer&) = delete;

  /// Install the socket transport and force an HTTP/3 origin through a fixed
  /// plaintext HTTP/1.1 proxy. The response script supplies the 101 upgrade
  /// and any capsule bytes that follow it.
  /// @param easy Easy handle that will connect through this proxy.
  void Install(CURL* easy) override;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_CONNECT_UDP_PROXY_MOCK_SERVER_H_
