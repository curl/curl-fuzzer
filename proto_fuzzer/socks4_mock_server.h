/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Deterministic SOCKS4/SOCKS4A proxy transport for HTTP scenarios.

#ifndef PROTO_FUZZER_SOCKS4_MOCK_SERVER_H_
#define PROTO_FUZZER_SOCKS4_MOCK_SERVER_H_

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Reuses MockServer's request-triggered raw chunk delivery: the first chunks
/// become a SOCKS reply and later chunks become the tunneled HTTP response.
/// Routing is fixed to a numeric loopback proxy whose socket is replaced by
/// MockServer's socketpair, so neither proxy nor origin can reach the network.
class Socks4MockServer final : public MockServer {
 public:
  /// Select local (SOCKS4) or proxy-side (SOCKS4A) name resolution.
  /// @param mode Proxy protocol and hostname-resolution mode to install.
  explicit Socks4MockServer(curl::fuzzer::proto::SocksProxyMode mode);
  ~Socks4MockServer() override = default;

  Socks4MockServer(const Socks4MockServer&) = delete;
  Socks4MockServer& operator=(const Socks4MockServer&) = delete;

  /// Install common socket callbacks and the fixed SOCKS proxy policy.
  /// @param easy Easy handle to configure.
  void Install(CURL* easy) override;

 private:
  curl::fuzzer::proto::SocksProxyMode mode_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_SOCKS4_MOCK_SERVER_H_
