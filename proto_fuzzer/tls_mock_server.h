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

  explicit TlsMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain);
  ~TlsMockServer() override;

  TlsMockServer(const TlsMockServer&) = delete;
  TlsMockServer& operator=(const TlsMockServer&) = delete;

  void Install(CURL* easy) override;

  bool saw_live_tls_session() const;

  std::size_t exported_session_count() const;

  std::size_t imported_session_count() const;

  int negotiated_tls_version() const;

  std::size_t completed_handshake_count() const;

  std::size_t reused_session_count() const;

  std::size_t write_retry_count() const;

  std::string negotiated_alpn() const;

  int ech_status() const;

  std::string ech_inner_name() const;

  std::string ech_outer_name() const;

 protected:
  explicit TlsMockServer(TlsApplicationProtocol protocol,
                         curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain =
                             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC);

  std::unique_ptr<MockConnection> CreateConnection() override;

  void ObserveActiveTransfer(CURL* easy) override;

 private:
  std::unique_ptr<TlsServerContext> context_;
  bool saw_live_tls_session_;
  std::size_t session_export_attempt_count_;
  std::size_t exported_session_count_;
  std::size_t imported_session_count_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TLS_MOCK_SERVER_H_
