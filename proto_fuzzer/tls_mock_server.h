/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Reusable TLS transport for structured in-process protocol peers.

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

/// Key-exchange group policy fixed when a TLS peer is constructed. Keeping
/// this separate from mutable transfer options prevents a scenario from
/// configuring incompatible client and server group sets.
enum class TlsGroupPolicy {
  /// Retain the linked OpenSSL provider's preferred group ordering.
  kProviderDefault,
  /// Restrict negotiation to the inexpensive X25519 group.
  kX25519,
};

/// TLS 1.3 early-data behavior fixed when a TLS peer is constructed. Keeping
/// this explicit prevents unrelated secure protocol lanes from advertising
/// 0-RTT merely because their shared carrier supports it.
enum class TlsEarlyDataPolicy {
  /// Do not advertise early-data support in session tickets.
  kDisabled,
  /// Advertise a bounded allowance, then reject 0-RTT during SSL_accept.
  kAdvertiseAndReject,
};

TlsEarlyDataPolicy EarlyDataPolicyForScenario(const curl::fuzzer::proto::Scenario& scenario);

/// Owns the OpenSSL server context without exposing OpenSSL types through the
/// public mock-server headers used by sanitizer builds that disable TLS.
class TlsServerContext;

/// Reusable TLS carrier for protocol-specific mock peers. It owns the
/// per-scenario server context, creates nonblocking TLS connections, and
/// installs the checked-in trust anchor without taking ownership of curl's
/// socket callbacks or application-protocol drive loop.
class TlsMockTransport {
 public:
  explicit TlsMockTransport(
      TlsApplicationProtocol protocol = TlsApplicationProtocol::kHttp11,
      curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain =
          curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC,
      TlsGroupPolicy group_policy = TlsGroupPolicy::kProviderDefault,
      curl::fuzzer::proto::TlsHandshakeProfile handshake_profile = curl::fuzzer::proto::TLS_HANDSHAKE_DEFAULT,
      TlsEarlyDataPolicy early_data_policy = TlsEarlyDataPolicy::kDisabled);
  ~TlsMockTransport();

  TlsMockTransport(const TlsMockTransport&) = delete;
  TlsMockTransport& operator=(const TlsMockTransport&) = delete;

  void Install(CURL* easy) const;

  std::unique_ptr<MockConnection> CreateConnection();

  std::unique_ptr<MockConnection> CreateAcceptedConnection(int accepted_fd);

  int negotiated_tls_version() const;
  std::size_t completed_handshake_count() const;
  std::size_t reused_session_count() const;
  std::size_t write_retry_count() const;
  std::string negotiated_alpn() const;
  TlsGroupPolicy group_policy() const;
  std::string negotiated_group() const;
  int ech_status() const;
  std::string ech_inner_name() const;
  std::string ech_outer_name() const;

 private:
  const TlsGroupPolicy group_policy_;
  const bool openssl_close_notify_;
  const bool openssl_hello_request_;
  std::unique_ptr<TlsServerContext> context_;
};

/// Runs MockServer's existing bounded HTTP scripts through a real TLS peer.
/// The TLS connection itself remains nonblocking and is advanced by the same
/// deterministic outer loop that services plaintext socketpairs.
class TlsMockServer : public MockServer {
 public:
  explicit TlsMockServer(const curl::fuzzer::proto::Scenario& scenario);
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

  std::string negotiated_group() const;

  int ech_status() const;

  std::string ech_inner_name() const;

  std::string ech_outer_name() const;

 protected:
  /// Fixed transport role selected by a derived peer before it initializes
  /// from the complete Scenario.
  enum class PeerRole {
    /// Direct HTTP/1.1 or Gopher-over-TLS peer.
    kHttp11,
    /// Direct HTTP/2 origin peer.
    kHttp2Origin,
    /// HTTPS proxy using the Scenario's fixed proxy protocol.
    kProxy,
  };

  /// Defer transport setup for a derived peer that will call Init in its
  /// constructor body.
  TlsMockServer() = default;

  void Init(const curl::fuzzer::proto::Scenario& scenario, PeerRole role);

  TlsGroupPolicy group_policy() const;

  std::unique_ptr<MockConnection> CreateConnection() override;

  void ObserveActiveTransfer(CURL* easy) override;

 private:
  std::unique_ptr<TlsMockTransport> transport_;
  bool saw_live_tls_session_ = false;
  std::size_t session_export_attempt_count_ = 0;
  std::size_t exported_session_count_ = 0;
  std::size_t imported_session_count_ = 0;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TLS_MOCK_SERVER_H_
