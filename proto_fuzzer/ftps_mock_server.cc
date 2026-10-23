/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the implicit-TLS FTP peer.

#include "proto_fuzzer/ftps_mock_server.h"

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Construct the OpenSSL server carrier used by every FTPS scenario. FTP
/// sends no ALPN extension, so the closed HTTP/1.1 default is never selected
/// and each control or data handshake completes without an application
/// protocol.
FtpsMockServer::FtpsMockServer() : transport_(TlsApplicationProtocol::kHttp11) {}

/// Release the TLS connections before the carrier-owned server context. The
/// inherited FTP peer owns both the control and passive data connections, so
/// resetting only the base's generic connection would leave their SSL objects
/// alive past this transport's lifetime.
FtpsMockServer::~FtpsMockServer() { ReleaseConnections(); }

/// Install the shared socket callbacks and a stable local trust anchor. Curl
/// copies the blob descriptor during setopt and borrows the inline certificate
/// bytes, whose program lifetime safely exceeds every easy handle. Scenario
/// options run afterwards and can still disable verification.
/// @param easy Easy handle that will initiate the FTPS control connection.
void FtpsMockServer::Install(CURL* easy) {
  FtpMockServer::Install(easy);
  transport_.Install(easy);
}

/// Wrap one control or passive-data socketpair endpoint in an OpenSSL
/// acceptor. The inherited FTP loop advances each handshake and then parses
/// only decrypted control replies or drains decrypted upload bytes.
/// @return Newly allocated nonblocking TLS connection.
std::unique_ptr<MockConnection> FtpsMockServer::CreateConnection() { return transport_.CreateConnection(); }

/// Reject active-mode listener creation. FTPS data channels must carry TLS,
/// but curl's PORT/EPRT path expects a real loopback TCP socket that this
/// peer cannot wrap; the lane therefore stays on EPSV/PASV.
/// @return false for every FTPS drive.
bool FtpsMockServer::SupportsActiveMode() const { return false; }

/// @return Protocol version selected by the most recent handshake, or zero.
int FtpsMockServer::negotiated_tls_version() const { return transport_.negotiated_tls_version(); }

/// @return Number of control and data connections that completed TLS
///         negotiation.
std::size_t FtpsMockServer::completed_handshake_count() const { return transport_.completed_handshake_count(); }

/// @return ALPN protocol selected by curl, or an empty string when absent.
std::string FtpsMockServer::negotiated_alpn() const { return transport_.negotiated_alpn(); }

}  // namespace proto_fuzzer
