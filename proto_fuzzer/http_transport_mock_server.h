/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded HTTP proxy and Unix-domain transports for deep scenarios.

#ifndef PROTO_FUZZER_HTTP_TRANSPORT_MOCK_SERVER_H_
#define PROTO_FUZZER_HTTP_TRANSPORT_MOCK_SERVER_H_

#include <cstddef>
#include <memory>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/incoming_data_observer.h"
#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Drives ordinary HTTP response scripts through one of three fixed routing
/// shapes: an absolute-form forward proxy request, an HTTP/1.1 CONNECT tunnel,
/// or an abstract Unix-domain socket. Every outbound socket is replaced by the
/// inherited socketpair callback, and no fuzzed byte selects a destination.
class HttpTransportMockServer final : public MockServer, public IncomingDataObserver {
 public:
  HttpTransportMockServer(curl::fuzzer::proto::HttpTransportMode mode, bool haproxy_protocol);
  ~HttpTransportMockServer() override = default;

  HttpTransportMockServer(const HttpTransportMockServer&) = delete;
  HttpTransportMockServer& operator=(const HttpTransportMockServer&) = delete;

  void Install(CURL* easy) override;

  const std::string& client_transcript() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

  bool SupportsRepeatedPollsetProbe() const override;

 private:
  static constexpr std::size_t kMaxTranscriptBytes = 64 * 1024;

  curl::fuzzer::proto::HttpTransportMode mode_;
  bool haproxy_protocol_;
  std::string client_transcript_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_HTTP_TRANSPORT_MOCK_SERVER_H_
