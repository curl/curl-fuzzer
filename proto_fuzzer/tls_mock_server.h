/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief TLS transport for the structured HTTP mock server.

#ifndef PROTO_FUZZER_TLS_MOCK_SERVER_H_
#define PROTO_FUZZER_TLS_MOCK_SERVER_H_

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Application protocol selected by the in-process TLS peer. Keeping this a
/// closed enum prevents a caller-controlled ALPN string from making a fixed
/// protocol lane negotiate an unrelated transport.
enum class TlsApplicationProtocol {
  /// Ordinary HTTPS scripts contain HTTP/1.1 response bytes.
  kHttp11,
  /// The dedicated proxy peer exchanges HTTP/2 frames after its handshake.
  kHttp2,
};

/// Owns the OpenSSL server context without exposing OpenSSL types through the
/// public mock-server headers used by sanitizer builds that disable TLS.
class TlsServerContext;

/// Runs MockServer's existing bounded HTTP scripts through a real TLS peer.
/// The TLS connection itself remains nonblocking and is advanced by the same
/// deterministic outer loop that services plaintext socketpairs.
class TlsMockServer : public MockServer {
 public:
  TlsMockServer();
  ~TlsMockServer() override;

  TlsMockServer(const TlsMockServer&) = delete;
  TlsMockServer& operator=(const TlsMockServer&) = delete;

  /// Install the ordinary socket callbacks plus a stable local trust anchor.
  /// Scenario options run afterwards and can still disable verification or
  /// select failure-producing TLS settings.
  /// @param easy Easy handle that will connect to this TLS peer.
  void Install(CURL* easy) override;

  /// @return true once curl exposed a live TLS backend session during drive.
  bool saw_live_tls_session() const;

  /// @return protocol version selected by the most recent completed handshake,
  /// or zero when no connection completed TLS negotiation.
  int negotiated_tls_version() const;

  /// @return number of connections that completed TLS negotiation.
  std::size_t completed_handshake_count() const;

  /// @return number of completed connections that resumed an earlier session.
  std::size_t reused_session_count() const;

  /// @return number of application writes OpenSSL required an exact retry for.
  std::size_t write_retry_count() const;

  /// @return ALPN protocol selected by the most recent completed handshake.
  std::string negotiated_alpn() const;

  /// @return OpenSSL's ECH status for the most recent completed handshake.
  /// Builds without ECH return a negative sentinel.
  int ech_status() const;

  /// @return encrypted inner SNI recovered by the ECH-capable server.
  std::string ech_inner_name() const;

  /// @return public outer SNI visible before ECH decryption.
  std::string ech_outer_name() const;

 protected:
  /// Construct a TLS transport for a protocol-specific derived peer.
  /// @param protocol Fixed application protocol the server must negotiate.
  explicit TlsMockServer(TlsApplicationProtocol protocol);

  /// Wrap one socketpair server endpoint in an OpenSSL acceptor.
  /// @return a failed connection when context setup was unavailable.
  std::unique_ptr<MockConnection> CreateConnection() override;

  /// Probe result APIs only until curl exposes the active backend connection.
  /// @param easy Easy handle whose active TLS connection is inspected.
  void ObserveActiveTransfer(CURL* easy) override;

 private:
  std::unique_ptr<TlsServerContext> context_;
  bool saw_live_tls_session_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TLS_MOCK_SERVER_H_
