/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the implicit-TLS POP3 peer.

#include "proto_fuzzer/pop3s_mock_server.h"

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Construct the OpenSSL server carrier used by every POP3S scenario. POP3
/// sends no ALPN extension, so the closed HTTP/1.1 default is never selected
/// and the handshake completes without an application protocol.
Pop3sMockServer::Pop3sMockServer() : transport_(TlsApplicationProtocol::kHttp11) {}

/// Release the TLS connection before the carrier-owned server context. The
/// inherited status-line parser holds no transport state of its own.
Pop3sMockServer::~Pop3sMockServer() { connection_.reset(); }

/// Install the shared socket callbacks and a stable local trust anchor. Curl
/// copies the blob descriptor during setopt and borrows the inline certificate
/// bytes, whose program lifetime safely exceeds every easy handle. Scenario
/// options run afterwards and can still disable verification.
/// @param easy Easy handle that will initiate the POP3S exchange.
void Pop3sMockServer::Install(CURL* easy) {
  Pop3MockServer::Install(easy);
  transport_.Install(easy);
}

/// Wrap one socketpair endpoint in an OpenSSL acceptor. The inherited POP3
/// loop advances the handshake and then parses only decrypted commands.
/// @return Newly allocated nonblocking TLS connection.
std::unique_ptr<MockConnection> Pop3sMockServer::CreateConnection() { return transport_.CreateConnection(); }

/// @return Protocol version selected by the most recent handshake, or zero.
int Pop3sMockServer::negotiated_tls_version() const { return transport_.negotiated_tls_version(); }

/// @return Number of connections that completed TLS negotiation.
std::size_t Pop3sMockServer::completed_handshake_count() const { return transport_.completed_handshake_count(); }

/// @return ALPN protocol selected by curl, or an empty string when absent.
std::string Pop3sMockServer::negotiated_alpn() const { return transport_.negotiated_alpn(); }

/// Retain protocol outcomes in coverage and introspector builds.
void Pop3sMockServer::ObserveState() {
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  Pop3MockServer::ObserveState();
  const volatile std::size_t pop3s_observation[] = {
      completed_handshake_count(), static_cast<std::size_t>(negotiated_tls_version()), negotiated_alpn().size()};
  (void)pop3s_observation;
#endif
}

}  // namespace proto_fuzzer
