/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the implicit-TLS MQTT peer.

#include "proto_fuzzer/mqtts_mock_server.h"

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Construct the OpenSSL server carrier used by every MQTTS scenario. MQTT
/// sends no ALPN extension, so the closed HTTP/1.1 default is never selected
/// and the handshake completes without an application protocol.
MqttsMockServer::MqttsMockServer() : transport_(TlsApplicationProtocol::kHttp11) {}

/// Release the TLS connection before the carrier-owned server context. The
/// inherited packet parser holds no transport state of its own.
MqttsMockServer::~MqttsMockServer() { connection_.reset(); }

/// Install the shared socket callbacks and a stable local trust anchor. Curl
/// copies the blob descriptor during setopt and borrows the inline certificate
/// bytes, whose program lifetime safely exceeds every easy handle. Scenario
/// options run afterwards and can still disable verification.
/// @param easy Easy handle that will initiate the MQTTS exchange.
void MqttsMockServer::Install(CURL* easy) {
  MqttMockServer::Install(easy);
  transport_.Install(easy);
}

/// Wrap one socketpair endpoint in an OpenSSL acceptor. The inherited MQTT
/// loop advances the handshake and then parses only decrypted packets.
/// @return Newly allocated nonblocking TLS connection.
std::unique_ptr<MockConnection> MqttsMockServer::CreateConnection() { return transport_.CreateConnection(); }

/// @return Protocol version selected by the most recent handshake, or zero.
int MqttsMockServer::negotiated_tls_version() const { return transport_.negotiated_tls_version(); }

/// @return Number of connections that completed TLS negotiation.
std::size_t MqttsMockServer::completed_handshake_count() const { return transport_.completed_handshake_count(); }

/// @return ALPN protocol selected by curl, or an empty string when absent.
std::string MqttsMockServer::negotiated_alpn() const { return transport_.negotiated_alpn(); }

}  // namespace proto_fuzzer
