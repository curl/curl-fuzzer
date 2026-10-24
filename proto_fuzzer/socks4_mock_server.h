/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Deterministic SOCKS/HAProxy transport for HTTP scenarios.

#ifndef PROTO_FUZZER_SOCKS4_MOCK_SERVER_H_
#define PROTO_FUZZER_SOCKS4_MOCK_SERVER_H_

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/incoming_data_observer.h"
#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Reuses MockServer's request-triggered raw chunk delivery: the first chunks
/// become SOCKS negotiation replies and later chunks become the tunneled HTTP
/// response. Routing is fixed to a numeric loopback proxy whose socket is
/// replaced by MockServer's socketpair, so neither proxy nor origin can reach
/// the network. The historical source filename follows the packaged target
/// basename; the class name reflects the broader append-only transport lane.
class ProxyTransportMockServer final : public MockServer, public IncomingDataObserver {
 public:
  ProxyTransportMockServer(curl::fuzzer::proto::SocksProxyMode mode, bool haproxy_protocol);
  ~ProxyTransportMockServer() override = default;

  ProxyTransportMockServer(const ProxyTransportMockServer&) = delete;
  ProxyTransportMockServer& operator=(const ProxyTransportMockServer&) = delete;

  void Install(CURL* easy) override;

  // Bounded raw client bytes from SOCKS negotiation through tunneled HTTP.
  // Tests use this to assert exact handshake and HAProxy prefix ordering.
  const std::string& client_transcript() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

  bool SupportsRepeatedPollsetProbe() const override;

 private:
  static constexpr std::size_t kMaxTranscriptBytes = 64 * 1024;

  curl::fuzzer::proto::SocksProxyMode mode_;
  bool haproxy_protocol_;
  std::string client_transcript_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_SOCKS4_MOCK_SERVER_H_
