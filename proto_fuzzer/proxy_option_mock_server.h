/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Closed proxy, no-proxy, interface, and TCP-option peers.

#ifndef PROTO_FUZZER_PROXY_OPTION_MOCK_SERVER_H_
#define PROTO_FUZZER_PROXY_OPTION_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/happy_eyeballs_mock_server.h"
#include "proto_fuzzer/incoming_data_observer.h"
#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Socketpair-backed peer that applies one fixed no-proxy or environment-
/// proxy setup. The environment mode saves and restores `http_proxy` and uses
/// only a numeric loopback endpoint intercepted by the socket callback.
class ProxyOptionMockServer final : public MockServer, public IncomingDataObserver {
 public:
  explicit ProxyOptionMockServer(curl::fuzzer::proto::ProxySocketOptionMode mode);
  ~ProxyOptionMockServer() override;

  void ObserveState() override;

  ProxyOptionMockServer(const ProxyOptionMockServer&) = delete;
  ProxyOptionMockServer& operator=(const ProxyOptionMockServer&) = delete;

  void Install(CURL* easy) override;

  const std::string& client_transcript() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  bool BeginProxyEnvironment();
  void EndProxyEnvironment();

  static constexpr std::size_t kMaxTranscriptBytes = 64 * 1024;

  curl::fuzzer::proto::ProxySocketOptionMode mode_;
  bool setup_ok_;
  bool proxy_environment_active_;
  bool saved_http_proxy_was_set_;
  std::string saved_http_proxy_;
  std::string client_transcript_;
};

/// Real-loopback variant used only for interface binding and TCP keepalive.
/// It inherits the bounded listener, destination validation, accept budget,
/// and response driver from the resolver lane's loopback TCP peer.
class InterfaceOptionMockServer final : public HappyEyeballsMockServer {
 public:
  InterfaceOptionMockServer() = default;
  ~InterfaceOptionMockServer() override = default;

  InterfaceOptionMockServer(const InterfaceOptionMockServer&) = delete;
  InterfaceOptionMockServer& operator=(const InterfaceOptionMockServer&) = delete;

  void Install(CURL* easy) override;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_PROXY_OPTION_MOCK_SERVER_H_
