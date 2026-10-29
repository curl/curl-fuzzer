/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implicit-TLS in-process peer for curl's MQTTS state machine.

#ifndef PROTO_FUZZER_MQTTS_MOCK_SERVER_H_
#define PROTO_FUZZER_MQTTS_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/mqtt_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::MqttsMockServer
/// @brief Runs the binary MQTT packet exchange over implicit TLS.
///
/// MQTTS differs from MQTT only in transport setup: curl establishes TLS
/// immediately after CONNECT and then executes the same CONNECT/CONNACK,
/// PUBLISH or SUBSCRIBE/SUBACK, server-PUBLISH, and DISCONNECT sequence. This
/// peer therefore inherits the packet-aware parser and replaces only the
/// connection factory and trust installation.
///
/// MQTT handshakes carry no ALPN extension. The carrier is constructed with
/// its closed HTTP/1.1 default, but OpenSSL only invokes the selector when the
/// client offers ALPN, so curl negotiates no application protocol here.
class MqttsMockServer final : public MqttMockServer {
 public:
  MqttsMockServer();

  ~MqttsMockServer() override;

  void ObserveState() override;

  MqttsMockServer(const MqttsMockServer&) = delete;
  MqttsMockServer& operator=(const MqttsMockServer&) = delete;

  void Install(CURL* easy) override;

  int negotiated_tls_version() const;

  std::size_t completed_handshake_count() const;

  std::string negotiated_alpn() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

 private:
  TlsMockTransport transport_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MQTTS_MOCK_SERVER_H_
