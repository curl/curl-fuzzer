/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Nonblocking OpenSSL server transport for structured HTTPS inputs.

#include "proto_fuzzer/tls_mock_server.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ech.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/tls_test_credential_cache.h"
#include "proto_fuzzer/tls_test_credentials.h"

namespace proto_fuzzer {

namespace {

constexpr std::size_t kMaxSessionExportAttempts = 8;
constexpr std::uint32_t kMaxEarlyDataSize = 16 * 1024;

/// The TLS carrier always uses OpenSSL on its server side, but the HTTPS seed
/// corpus is also replayed by curl clients built with GnuTLS and mbedTLS.
/// Backend-specific handshake terminals must not replace their ordinary peer.
bool CurlClientUsesOpenSsl() {
  const curl_version_info_data* version = curl_version_info(CURLVERSION_NOW);
  constexpr char kOpenSslPrefix[] = "OpenSSL/";
  return version != nullptr && version->ssl_version != nullptr &&
         std::strncmp(version->ssl_version, kOpenSslPrefix, sizeof(kOpenSslPrefix) - 1) == 0;
}

/// Isolate the server and curl client even though both OpenSSL instances run
/// on one thread. SSL_get_error requires an empty queue before its I/O call;
/// clearing at both boundaries also prevents a server failure from changing
/// curl's subsequent error classification.
class OpenSslErrorQueueGuard {
 public:
  OpenSslErrorQueueGuard() { ERR_clear_error(); }

  ~OpenSslErrorQueueGuard() { ERR_clear_error(); }

  OpenSslErrorQueueGuard(const OpenSslErrorQueueGuard&) = delete;
  OpenSslErrorQueueGuard& operator=(const OpenSslErrorQueueGuard&) = delete;
};

/// Select the one protocol owned by this peer. A fixed server preference keeps
/// ordinary HTTPS scripts on HTTP/1.1 while allowing the proxy lane to prove
/// curl installed its HTTP/2 connection filter after TLS.
int SelectAlpn(SSL* /*ssl*/, const unsigned char** selected, unsigned char* selected_length,
               const unsigned char* client_protocols, unsigned int client_protocols_length, void* userdata) {
  const auto protocol = *static_cast<const TlsApplicationProtocol*>(userdata);
  // OpenSSL may return a pointer into the server preference list. Function-
  // local static storage keeps that result valid for the rest of the
  // handshake without reintroducing mutable transport policy as a global.
  static constexpr unsigned char http11_alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  static constexpr unsigned char http2_alpn[] = {2, 'h', '2'};
  const unsigned char* server_protocols = protocol == TlsApplicationProtocol::kHttp2 ? http2_alpn : http11_alpn;
  const unsigned int server_protocols_length =
      protocol == TlsApplicationProtocol::kHttp2 ? sizeof(http2_alpn) : sizeof(http11_alpn);
  unsigned char* match = nullptr;
  unsigned char match_length = 0;
  const int result = SSL_select_next_proto(&match, &match_length, server_protocols, server_protocols_length,
                                           client_protocols, client_protocols_length);
  if (result != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  *selected = match;
  *selected_length = match_length;
  return SSL_TLSEXT_ERR_OK;
}

using OcspBasicResponsePtr = std::unique_ptr<OCSP_BASICRESP, decltype(&OCSP_BASICRESP_free)>;
using OcspCertIdPtr = std::unique_ptr<OCSP_CERTID, decltype(&OCSP_CERTID_free)>;
using OcspResponsePtr = std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)>;

/// Encode one owned OpenSSL response for the status callback.
/// @param response Parsed response whose ownership stays with the caller.
/// @return DER bytes, or an empty vector when encoding failed.
std::vector<unsigned char> EncodeOcspResponse(OCSP_RESPONSE* response) {
  if (response == nullptr) {
    return {};
  }
  const int encoded_size = i2d_OCSP_RESPONSE(response, nullptr);
  if (encoded_size <= 0) {
    return {};
  }
  std::vector<unsigned char> encoded(static_cast<std::size_t>(encoded_size));
  unsigned char* output = encoded.data();
  if (i2d_OCSP_RESPONSE(response, &output) != encoded_size) {
    return {};
  }
  return encoded;
}

/// Build a response carrying only its top-level OCSP status.
std::vector<unsigned char> BuildTopLevelOcspResponse(int response_status) {
  OcspResponsePtr response(OCSP_response_create(response_status, nullptr), &OCSP_RESPONSE_free);
  return EncodeOcspResponse(response.get());
}

/// Build and sign one single-certificate OCSP response.
std::vector<unsigned char> BuildSignedOcspResponse(X509* certificate, X509* issuer, EVP_PKEY* issuer_private_key,
                                                   int certificate_status, bool sha256_certificate_id, bool expired,
                                                   bool bad_signature) {
  OcspBasicResponsePtr basic(OCSP_BASICRESP_new(), &OCSP_BASICRESP_free);
  const EVP_MD* certificate_id_digest = sha256_certificate_id ? EVP_sha256() : EVP_sha1();
  OcspCertIdPtr certificate_id(OCSP_cert_to_id(certificate_id_digest, certificate, issuer), &OCSP_CERTID_free);
  const long this_update_offset = expired ? -2L * 24L * 60L * 60L : -60L;
  const long next_update_offset = expired ? -24L * 60L * 60L : 24L * 60L * 60L;
  Asn1TimePtr this_update(X509_gmtime_adj(nullptr, this_update_offset), &ASN1_TIME_free);
  Asn1TimePtr next_update(X509_gmtime_adj(nullptr, next_update_offset), &ASN1_TIME_free);
  Asn1TimePtr revocation_time(
      certificate_status == V_OCSP_CERTSTATUS_REVOKED ? X509_gmtime_adj(nullptr, -60L * 60L) : nullptr,
      &ASN1_TIME_free);
  if (basic == nullptr || certificate_id == nullptr || this_update == nullptr || next_update == nullptr ||
      (certificate_status == V_OCSP_CERTSTATUS_REVOKED && revocation_time == nullptr)) {
    return {};
  }

  const int revocation_reason = certificate_status == V_OCSP_CERTSTATUS_REVOKED ? OCSP_REVOKED_STATUS_KEYCOMPROMISE : 0;
  if (OCSP_basic_add1_status(basic.get(), certificate_id.get(), certificate_status, revocation_reason,
                             revocation_time.get(), this_update.get(), next_update.get()) == nullptr ||
      OCSP_basic_sign(basic.get(), issuer, issuer_private_key, EVP_sha256(), nullptr, OCSP_NOCERTS | OCSP_RESPID_KEY) !=
          1) {
    return {};
  }

  OcspResponsePtr response(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.get()), &OCSP_RESPONSE_free);
  std::vector<unsigned char> encoded = EncodeOcspResponse(response.get());
  // OCSP_NOCERTS leaves the signature as the final DER value. Changing one
  // payload byte preserves the ASN.1 shape while making verification fail.
  if (bad_signature && !encoded.empty()) {
    encoded.back() ^= 1U;
  }
  return encoded;
}

/// Generate each signed profile once. Per-connection callbacks copy only the
/// selected DER, avoiding asymmetric signing work in the fuzzing hot path.
class TlsOcspResponseCache {
 public:
  TlsOcspResponseCache(X509* certificate, X509* issuer, EVP_PKEY* issuer_private_key)
      : good_(BuildSignedOcspResponse(certificate, issuer, issuer_private_key, V_OCSP_CERTSTATUS_GOOD, false, false,
                                      false)),
        revoked_(BuildSignedOcspResponse(certificate, issuer, issuer_private_key, V_OCSP_CERTSTATUS_REVOKED, false,
                                         false, false)),
        unknown_(BuildSignedOcspResponse(certificate, issuer, issuer_private_key, V_OCSP_CERTSTATUS_UNKNOWN, false,
                                         false, false)),
        try_later_(BuildTopLevelOcspResponse(OCSP_RESPONSE_STATUS_TRYLATER)),
        empty_successful_(BuildTopLevelOcspResponse(OCSP_RESPONSE_STATUS_SUCCESSFUL)),
        sha256_certificate_id_(BuildSignedOcspResponse(certificate, issuer, issuer_private_key, V_OCSP_CERTSTATUS_GOOD,
                                                       true, false, false)),
        expired_(BuildSignedOcspResponse(certificate, issuer, issuer_private_key, V_OCSP_CERTSTATUS_GOOD, false, true,
                                         false)),
        bad_signature_(BuildSignedOcspResponse(certificate, issuer, issuer_private_key, V_OCSP_CERTSTATUS_GOOD, false,
                                               false, true)) {}

  const std::vector<unsigned char>& Get(curl::fuzzer::proto::TlsOcspStapleProfile profile) const {
    switch (profile) {
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_GOOD:
        return good_;
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_REVOKED:
        return revoked_;
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_UNKNOWN:
        return unknown_;
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_TRY_LATER:
        return try_later_;
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_EMPTY_SUCCESSFUL:
        return empty_successful_;
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_SHA256_CERT_ID:
        return sha256_certificate_id_;
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_EXPIRED:
        return expired_;
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_BAD_SIGNATURE:
        return bad_signature_;
      case curl::fuzzer::proto::TLS_OCSP_STAPLE_NONE:
      default:
        return none_;
    }
  }

 private:
  const std::vector<unsigned char> none_;
  const std::vector<unsigned char> good_;
  const std::vector<unsigned char> revoked_;
  const std::vector<unsigned char> unknown_;
  const std::vector<unsigned char> try_later_;
  const std::vector<unsigned char> empty_successful_;
  const std::vector<unsigned char> sha256_certificate_id_;
  const std::vector<unsigned char> expired_;
  const std::vector<unsigned char> bad_signature_;
};

const std::vector<unsigned char>& CachedOcspResponse(curl::fuzzer::proto::TlsOcspStapleProfile profile,
                                                     X509* certificate, X509* issuer, EVP_PKEY* issuer_private_key) {
  static const TlsOcspResponseCache cache(certificate, issuer, issuer_private_key);
  return cache.Get(profile);
}

/// @return whether the selected value owns a generated stapled response.
bool IsKnownOcspStapleProfile(curl::fuzzer::proto::TlsOcspStapleProfile profile) {
  switch (profile) {
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_GOOD:
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_REVOKED:
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_UNKNOWN:
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_TRY_LATER:
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_EMPTY_SUCCESSFUL:
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_SHA256_CERT_ID:
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_EXPIRED:
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_BAD_SIGNATURE:
      return true;
    case curl::fuzzer::proto::TLS_OCSP_STAPLE_NONE:
    default:
      return false;
  }
}

}  // namespace

/// Derive the correlated peer policy from the same bounded option prefix curl
/// receives. Later duplicate options replace earlier values, matching
/// sequential curl_easy_setopt calls.
/// @param scenario Structured input whose retained option prefix is inspected.
/// @return Server policy matching the effective SSL_OPTIONS value.
TlsEarlyDataPolicy EarlyDataPolicyForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  std::uint64_t ssl_options = 0;
  const std::size_t option_count = RuntimeOptionCount(scenario);
  for (std::size_t index = 0; index < option_count; ++index) {
    const auto& option = scenario.options(static_cast<int>(index));
    if (option.option_id() == curl::fuzzer::proto::CURLOPT_SSL_OPTIONS) {
      ssl_options = DecodeIntegralOptionValue(option);
    }
  }
  return (ssl_options & static_cast<std::uint64_t>(CURLSSLOPT_EARLYDATA)) != 0 ? TlsEarlyDataPolicy::kAdvertiseAndReject
                                                                               : TlsEarlyDataPolicy::kDisabled;
}

/// Own the certificate, key, session cache, ALPN policy, and observations
/// shared by every bounded connection in one Scenario. Keeping both session
/// state and its measurements here makes redirects related while preventing
/// one fuzz input from affecting the next.
class TlsServerContext {
 public:
  // Doxygen's no-preprocessing pass would see both conditional body openings.
  // Skip this implementation-only constructor to preserve the enclosing scope.
  /// @cond
  TlsServerContext(TlsApplicationProtocol protocol, curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain,
                   TlsGroupPolicy group_policy, TlsEarlyDataPolicy early_data_policy,
                   curl::fuzzer::proto::TlsOcspStapleProfile ocsp_staple_profile)
      : context_(nullptr),
        protocol_(protocol),
        group_policy_(group_policy),
        early_data_policy_(early_data_policy),
        ocsp_response_(nullptr),
        negotiated_tls_version_(0),
        completed_handshake_count_(0),
        reused_session_count_(0),
        write_retry_count_(0),
#ifndef OPENSSL_NO_ECH
        ech_status_(SSL_ECH_STATUS_NOT_TRIED) {
#else
        ech_status_(-1) {
#endif
    OpenSslErrorQueueGuard error_guard;
    context_ = SSL_CTX_new(TLS_server_method());
    const bool use_issuer_signed_leaf = IsKnownOcspStapleProfile(ocsp_staple_profile);
    if (context_ == nullptr || !ApplyGroupPolicy() || !ApplyEarlyDataPolicy() ||
        !InstallCachedTlsTestCredentials(context_, certificate_chain, use_issuer_signed_leaf) ||
        !ApplyOcspStapleProfile(ocsp_staple_profile) || !LoadEchConfig()) {
      SSL_CTX_free(context_);
      context_ = nullptr;
      return;
    }

    (void)SSL_CTX_set_min_proto_version(context_, TLS1_2_VERSION);
    (void)SSL_CTX_set_options(context_, SSL_OP_NO_COMPRESSION);
    (void)SSL_CTX_set_session_cache_mode(context_, SSL_SESS_CACHE_SERVER);
    constexpr unsigned char session_id_context[] = "curl-fuzzer";
    (void)SSL_CTX_set_session_id_context(context_, session_id_context, sizeof(session_id_context) - 1);
    SSL_CTX_set_alpn_select_cb(context_, &SelectAlpn, &protocol_);
  }
  /// @endcond

  ~TlsServerContext() {
    OpenSslErrorQueueGuard error_guard;
    SSL_CTX_free(context_);
  }

  TlsServerContext(const TlsServerContext&) = delete;
  TlsServerContext& operator=(const TlsServerContext&) = delete;

  /// @return the configured context, or nullptr when credential setup failed.
  SSL_CTX* get() const { return context_; }

  /// Retain only scalar handshake results; SSL itself remains connection-owned.
  /// @param ssl connection that has just completed SSL_accept.
  void RecordHandshake(SSL* ssl) {
    if (ssl == nullptr) {
      return;
    }
    negotiated_tls_version_ = SSL_version(ssl);
    const unsigned char* alpn = nullptr;
    unsigned int alpn_length = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_length);
    if (alpn != nullptr && alpn_length != 0) {
      negotiated_alpn_.assign(reinterpret_cast<const char*>(alpn), alpn_length);
    } else {
      negotiated_alpn_.clear();
    }
    ++completed_handshake_count_;
    if (SSL_session_reused(ssl) == 1) {
      ++reused_session_count_;
    }
    const int negotiated_group = SSL_get_negotiated_group(ssl);
    const char* group_name = negotiated_group == 0 ? nullptr : SSL_group_to_name(ssl, negotiated_group);
    negotiated_group_ = group_name == nullptr ? std::string() : group_name;
#ifndef OPENSSL_NO_ECH
    char* inner_name = nullptr;
    char* outer_name = nullptr;
    ech_status_ = SSL_ech_get1_status(ssl, &inner_name, &outer_name);
    ech_inner_name_ = inner_name == nullptr ? std::string() : inner_name;
    ech_outer_name_ = outer_name == nullptr ? std::string() : outer_name;
    OPENSSL_free(inner_name);
    OPENSSL_free(outer_name);
#endif
  }

  /// Record that OpenSSL requires an identical application-write retry.
  void RecordWriteRetry() { ++write_retry_count_; }

  /// @return protocol version from the most recent completed handshake.
  int negotiated_tls_version() const { return negotiated_tls_version_; }
  /// @return number of connections that completed their handshake.
  std::size_t completed_handshake_count() const { return completed_handshake_count_; }
  /// @return number of completed handshakes that reused a session.
  std::size_t reused_session_count() const { return reused_session_count_; }
  /// @return number of application writes that OpenSSL asked to retry.
  std::size_t write_retry_count() const { return write_retry_count_; }
  /// @return ALPN protocol from the most recent completed handshake.
  const std::string& negotiated_alpn() const { return negotiated_alpn_; }
  /// @return key-exchange group from the most recent completed handshake.
  const std::string& negotiated_group() const { return negotiated_group_; }
  /// @return fixed application protocol this context offers.
  TlsApplicationProtocol protocol() const { return protocol_; }
  /// @return OpenSSL ECH result from the latest completed handshake.
  int ech_status() const { return ech_status_; }
  /// @return latest decrypted inner SNI, if ECH was attempted.
  const std::string& ech_inner_name() const { return ech_inner_name_; }
  /// @return latest public outer SNI, if ECH was attempted.
  const std::string& ech_outer_name() const { return ech_outer_name_; }

 private:
  /// Apply the constructor-selected group policy before any SSL is created.
  /// @return true when the provider accepted the requested policy.
  bool ApplyGroupPolicy() {
    switch (group_policy_) {
      case TlsGroupPolicy::kProviderDefault:
        return true;
      case TlsGroupPolicy::kX25519:
        return SSL_CTX_set1_groups_list(context_, "X25519") == 1;
    }
    return false;
  }

  /// Advertise a bounded TLS 1.3 allowance without consuming early data. The
  /// ordinary SSL_accept path rejects it, so curl must replay the request
  /// after completing the resumed handshake.
  /// @return true when OpenSSL accepted the selected policy.
  bool ApplyEarlyDataPolicy() {
    switch (early_data_policy_) {
      case TlsEarlyDataPolicy::kDisabled:
        return true;
      case TlsEarlyDataPolicy::kAdvertiseAndReject:
        return SSL_CTX_set_max_early_data(context_, kMaxEarlyDataSize) == 1;
    }
    return false;
  }

  /// Install a context callback that copies one cached DER response into each
  /// SSL object whose client requested certificate status.
  bool ApplyOcspStapleProfile(curl::fuzzer::proto::TlsOcspStapleProfile profile) {
    if (!IsKnownOcspStapleProfile(profile)) {
      return true;
    }
    X509* certificate = SSL_CTX_get0_certificate(context_);
    X509* issuer = CachedTlsTestIssuerCertificate();
    EVP_PKEY* issuer_private_key = CachedTlsTestIssuerPrivateKey();
    const std::vector<unsigned char>& response = CachedOcspResponse(profile, certificate, issuer, issuer_private_key);
    if (response.empty()) {
      return false;
    }
    ocsp_response_ = &response;
    return SSL_CTX_set_tlsext_status_cb(context_, &ServeOcspStaple) == 1 &&
           SSL_CTX_set_tlsext_status_arg(context_, this) == 1;
  }

  /// Copy the immutable process-cached response into one connection. OpenSSL
  /// takes ownership only after SSL_set_tlsext_status_ocsp_resp succeeds.
  static int ServeOcspStaple(SSL* ssl, void* user_data) {
    auto* server = static_cast<TlsServerContext*>(user_data);
    if (ssl == nullptr || server == nullptr || server->ocsp_response_ == nullptr) {
      return SSL_TLSEXT_ERR_NOACK;
    }
    const std::vector<unsigned char>& response = *server->ocsp_response_;
    auto* copy = static_cast<unsigned char*>(OPENSSL_memdup(response.data(), response.size()));
    if (copy == nullptr) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    if (SSL_set_tlsext_status_ocsp_resp(ssl, copy, response.size()) != 1) {
      OPENSSL_free(copy);
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
  }

  /// Load a fixed test-only ECH private key and matching public config. This
  /// makes a successful encrypted ClientHello deterministic without DNS or
  /// filesystem state; builds configured without ECH retain the TLS mock.
  bool LoadEchConfig() {
#ifndef OPENSSL_NO_ECH
    BIO* ech_bio = BIO_new_mem_buf(tls_test_credentials::kEchConfigPem, -1);
    OSSL_ECHSTORE* store = OSSL_ECHSTORE_new(nullptr, nullptr);
    if (ech_bio == nullptr || store == nullptr) {
      BIO_free(ech_bio);
      OSSL_ECHSTORE_free(store);
      return false;
    }
    const bool loaded =
        OSSL_ECHSTORE_read_pem(store, ech_bio, OSSL_ECH_NO_RETRY) == 1 && SSL_CTX_set1_echstore(context_, store) == 1;
    BIO_free(ech_bio);
    OSSL_ECHSTORE_free(store);
    return loaded;
#else
    return true;
#endif
  }

  SSL_CTX* context_;
  TlsApplicationProtocol protocol_;
  const TlsGroupPolicy group_policy_;
  const TlsEarlyDataPolicy early_data_policy_;
  const std::vector<unsigned char>* ocsp_response_;
  std::string negotiated_alpn_;
  std::string negotiated_group_;
  int negotiated_tls_version_;
  std::size_t completed_handshake_count_;
  std::size_t reused_session_count_;
  std::size_t write_retry_count_;
  int ech_status_;
  std::string ech_inner_name_;
  std::string ech_outer_name_;
};

namespace {

/// TLS-aware MockConnection. Application writes are queued before the client
/// starts, then encrypted only after SSL_accept has completed. This preserves
/// MockServer's useful initial_response semantics without ever putting those
/// plaintext bytes onto the TLS wire.
class TlsMockConnection final : public MockConnection {
 public:
  explicit TlsMockConnection(TlsServerContext* context)
      : ssl_(nullptr),
        context_(context),
        pending_offset_(0),
        pending_write_end_(0),
        handshake_complete_(false),
        shutdown_requested_(false),
        write_shutdown_(false),
        failed_(false) {
    InitializeSsl();
  }

  TlsMockConnection(TlsServerContext* context, int accepted_fd)
      : MockConnection(accepted_fd),
        ssl_(nullptr),
        context_(context),
        pending_offset_(0),
        pending_write_end_(0),
        handshake_complete_(false),
        shutdown_requested_(false),
        write_shutdown_(false),
        failed_(false) {
    InitializeSsl();
  }

  ~TlsMockConnection() override {
    OpenSslErrorQueueGuard error_guard;
    if (ssl_ != nullptr) {
      SSL_free(ssl_);
    }
  }

  /// Require both the socketpair and its OpenSSL wrapper to be usable.
  bool ok() const override { return MockConnection::ok() && ssl_ != nullptr; }

  /// Queue bounded application bytes until the handshake can encrypt them.
  bool WriteAll(const unsigned char* data, std::size_t size) override {
    if (failed_ || (data == nullptr && size != 0) || size > pending_plaintext_.max_size() - pending_plaintext_.size()) {
      return false;
    }
    if (size != 0) {
      pending_plaintext_.append(reinterpret_cast<const char*>(data), size);
    }
    return true;
  }

  /// Advance the handshake, consume encrypted request records, flush queued
  /// response records, and finish a requested close without ever waiting.
  /// @return decrypted/application bytes plus state transitions made this turn.
  std::size_t DrainIncoming() override {
    if (!ok() || failed_) {
      return 0;
    }

    OpenSslErrorQueueGuard error_guard;
    std::size_t progress = 0;
    if (!handshake_complete_) {
      const int state_before = static_cast<int>(SSL_get_state(ssl_));
      const int result = SSL_accept(ssl_);
      // SSL_get_error must be the next OpenSSL call after failed I/O. Even a
      // state query in between would make its use formally unreliable.
      const int error = result == 1 ? SSL_ERROR_NONE : SSL_get_error(ssl_, result);
      const int state_after = static_cast<int>(SSL_get_state(ssl_));
      if (state_after != state_before) {
        ++progress;
      }
      if (result == 1) {
        handshake_complete_ = true;
        if (context_ != nullptr) {
          context_->RecordHandshake(ssl_);
        }
        ++progress;
      } else {
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
          return progress;
        }
        failed_ = true;
        return progress;
      }
    }

    // A WANT result leaves SSL_write_ex in flight. OpenSSL requires the next
    // I/O operation to retry that exact write, so do not interpose SSL_read_ex
    // merely because the outer driver has yielded back to us.
    if (pending_write_end_ != 0) {
      progress += FlushPendingWrites();
      if (failed_ || pending_write_end_ != 0) {
        return progress;
      }
    }

    unsigned char request[4096];
    while (true) {
      std::size_t received = 0;
      const int result = SSL_read_ex(ssl_, request, sizeof(request), &received);
      if (result == 1 && received != 0) {
        NotifyIncomingData(request, received);
        progress += received;
        continue;
      }
      if (result != 1) {
        const int error = SSL_get_error(ssl_, result);
        if (error == SSL_ERROR_ZERO_RETURN) {
          // The client sent close_notify. TLS requires a reciprocal close_notify
          // before the orderly shutdown completes; protocols such as FTP upload
          // wait for that completion even though the application data is done.
          shutdown_requested_ = true;
        } else if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
          failed_ = true;
        }
      }
      break;
    }

    progress += FlushPendingWrites();

    if (!failed_ && shutdown_requested_ && pending_plaintext_.empty() && !write_shutdown_) {
      const int result = SSL_shutdown(ssl_);
      if (result >= 0) {
        // The first successful call sends close_notify. The fuzzer does not
        // need to wait for the client's reciprocal alert before exposing EOF.
        (void)::shutdown(server_fd(), SHUT_WR);
        write_shutdown_ = true;
        ++progress;
      } else {
        const int error = SSL_get_error(ssl_, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
          failed_ = true;
        }
      }
    }
    return progress;
  }

  /// Defer close_notify until every queued plaintext byte has become a record.
  void ShutdownWrite() override {
    // An HTTP/2 proxy connection outlives the scripted origin response inside
    // its CONNECT stream. Half-closing TLS when the last script chunk is
    // queued would make curl observe a dead proxy rather than exercise its
    // own stream/session shutdown and GOAWAY handling.
    if (context_ != nullptr && context_->protocol() == TlsApplicationProtocol::kHttp2) {
      return;
    }
    shutdown_requested_ = true;
    (void)DrainIncoming();
  }

 private:
  /// Bind a server-side SSL object to the already-owned transport endpoint.
  void InitializeSsl() {
    OpenSslErrorQueueGuard error_guard;
    SSL_CTX* ssl_context = context_ == nullptr ? nullptr : context_->get();
    ssl_ = ssl_context == nullptr ? nullptr : SSL_new(ssl_context);
    if (ssl_ == nullptr) {
      return;
    }
    SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (SSL_set_fd(ssl_, server_fd()) != 1) {
      SSL_free(ssl_);
      ssl_ = nullptr;
      return;
    }
    SSL_set_accept_state(ssl_);
  }

  /// Flush queued response bytes while preserving any OpenSSL retry boundary.
  /// @return plaintext bytes OpenSSL accepted during this call.
  std::size_t FlushPendingWrites() {
    std::size_t progress = 0;
    while (!failed_ && pending_offset_ < pending_plaintext_.size()) {
      if (pending_write_end_ == 0) {
        // Freeze one write boundary until OpenSSL accepts it. WriteAll may
        // append the next scripted chunk after WANT_READ/WANT_WRITE, but the
        // retry contract permits only pointer relocation—not changed bytes or
        // length—for the outstanding SSL_write_ex call.
        pending_write_end_ = pending_plaintext_.size();
      }
      std::size_t written = 0;
      const int result = SSL_write_ex(ssl_, pending_plaintext_.data() + pending_offset_,
                                      pending_write_end_ - pending_offset_, &written);
      if (result == 1) {
        if (written == 0) {
          failed_ = true;
          break;
        }
        pending_offset_ += written;
        progress += written;
        if (pending_offset_ == pending_write_end_) {
          pending_write_end_ = 0;
        }
        continue;
      }
      const int error = SSL_get_error(ssl_, result);
      if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        if (context_ != nullptr) {
          context_->RecordWriteRetry();
        }
      } else {
        failed_ = true;
      }
      break;
    }
    if (pending_offset_ == pending_plaintext_.size()) {
      pending_plaintext_.clear();
      pending_offset_ = 0;
      pending_write_end_ = 0;
    }
    return progress;
  }

  SSL* ssl_;
  TlsServerContext* context_;
  std::string pending_plaintext_;
  std::size_t pending_offset_;
  /// Exclusive end of a write that OpenSSL may require us to retry exactly.
  std::size_t pending_write_end_;
  bool handshake_complete_;
  bool shutdown_requested_;
  bool write_shutdown_;
  bool failed_;
};

/// Emit one fixed clean-shutdown alert without completing a server handshake.
/// OpenSSL classifies this as SSL_ERROR_ZERO_RETURN with an empty error queue;
/// ignoring scripted response bytes keeps protobuf data out of the TLS record.
class TlsCloseNotifyConnection final : public MockConnection {
 public:
  TlsCloseNotifyConnection() : alert_sent_(false) {}

  bool WriteAll(const unsigned char* /*data*/, std::size_t /*size*/) override { return true; }

  void ShutdownWrite() override {
    if (alert_sent_) {
      return;
    }
    static constexpr unsigned char kCloseNotify[] = {
        0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00,
    };
    alert_sent_ = true;
    (void)MockConnection::WriteAll(kCloseNotify, sizeof(kCloseNotify));
    MockConnection::ShutdownWrite();
  }

 private:
  bool alert_sent_;
};

/// Emit one fixed TLS handshake record containing an empty HelloRequest.
/// This deliberately predates negotiation and ignores scripted HTTP bytes:
/// its only purpose is to drive OpenSSL's message callback through the
/// SSL3_MT_HELLO_REQUEST label with harness-owned bytes.
class TlsHelloRequestConnection final : public MockConnection {
 public:
  TlsHelloRequestConnection() : record_sent_(false) {}

  bool WriteAll(const unsigned char* /*data*/, std::size_t /*size*/) override { return SendOnce(); }

  void ShutdownWrite() override {
    (void)SendOnce();
    MockConnection::ShutdownWrite();
  }

 private:
  bool SendOnce() {
    if (record_sent_) {
      return true;
    }
    static constexpr unsigned char kHelloRequest[] = {
        0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    };
    record_sent_ = MockConnection::WriteAll(kHelloRequest, sizeof(kHelloRequest));
    return record_sent_;
  }

  bool record_sent_;
};

}  // namespace

/// Construct one reusable TLS context for a protocol-specific peer.
/// @param protocol Fixed ALPN application protocol offered by the server.
/// @param certificate_chain Certificate-chain profile presented to curl.
/// @param group_policy Immutable server key-exchange group policy.
/// @param handshake_profile Closed peer-side handshake terminal.
/// @param early_data_policy Fixed server-side TLS 1.3 early-data behavior.
/// @param ocsp_staple_profile Fixed server-side stapled OCSP response.
TlsMockTransport::TlsMockTransport(TlsApplicationProtocol protocol,
                                   curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain,
                                   TlsGroupPolicy group_policy,
                                   curl::fuzzer::proto::TlsHandshakeProfile handshake_profile,
                                   TlsEarlyDataPolicy early_data_policy,
                                   curl::fuzzer::proto::TlsOcspStapleProfile ocsp_staple_profile)
    : group_policy_(group_policy),
      openssl_close_notify_(handshake_profile == curl::fuzzer::proto::TLS_HANDSHAKE_OPENSSL_CLOSE_NOTIFY &&
                            CurlClientUsesOpenSsl()),
      openssl_hello_request_(handshake_profile == curl::fuzzer::proto::TLS_HANDSHAKE_OPENSSL_HELLO_REQUEST &&
                             CurlClientUsesOpenSsl()),
      context_(std::make_unique<TlsServerContext>(protocol, certificate_chain, group_policy, early_data_policy,
                                                  ocsp_staple_profile)) {}

TlsMockTransport::~TlsMockTransport() = default;

/// Install the stable local trust anchor and strict peer verification. Socket
/// callbacks remain owned by the protocol-specific server using this carrier.
/// @param easy Easy handle that will connect to this TLS transport.
void TlsMockTransport::Install(CURL* easy) const {
  struct curl_blob trust_anchor = {const_cast<char*>(tls_test_credentials::kCertificatePem),
                                   sizeof(tls_test_credentials::kCertificatePem) - 1, CURL_BLOB_NOCOPY};
  (void)curl_easy_setopt(easy, CURLOPT_CAINFO_BLOB, &trust_anchor);
  (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
}

/// Wrap one socketpair server endpoint in an OpenSSL acceptor.
/// @return A failed connection when context setup was unavailable.
std::unique_ptr<MockConnection> TlsMockTransport::CreateConnection() {
  if (openssl_close_notify_) {
    return std::make_unique<TlsCloseNotifyConnection>();
  }
  if (openssl_hello_request_) {
    return std::make_unique<TlsHelloRequestConnection>();
  }
  return std::make_unique<TlsMockConnection>(context_.get());
}

/// Wrap one accepted loopback descriptor in this transport's OpenSSL server
/// context. The special pre-handshake terminal profiles apply only to the
/// socketpair fuzz lanes; a listener-backed peer always performs real TLS.
/// @param accepted_fd Connected descriptor whose ownership transfers.
/// @return TLS connection owning `accepted_fd`.
std::unique_ptr<MockConnection> TlsMockTransport::CreateAcceptedConnection(int accepted_fd) {
  return std::make_unique<TlsMockConnection>(context_.get(), accepted_fd);
}

/// @return Protocol version selected by the most recent handshake, or zero.
int TlsMockTransport::negotiated_tls_version() const {
  return context_ == nullptr ? 0 : context_->negotiated_tls_version();
}

/// @return Number of connections that completed TLS negotiation.
std::size_t TlsMockTransport::completed_handshake_count() const {
  return context_ == nullptr ? 0 : context_->completed_handshake_count();
}

/// @return Number of completed connections that resumed a cached session.
std::size_t TlsMockTransport::reused_session_count() const {
  return context_ == nullptr ? 0 : context_->reused_session_count();
}

/// @return Number of application writes OpenSSL required an exact retry for.
std::size_t TlsMockTransport::write_retry_count() const {
  return context_ == nullptr ? 0 : context_->write_retry_count();
}

/// @return ALPN protocol selected by the most recent handshake.
std::string TlsMockTransport::negotiated_alpn() const {
  return context_ == nullptr ? std::string() : context_->negotiated_alpn();
}

/// @return Immutable key-exchange group policy selected at construction.
TlsGroupPolicy TlsMockTransport::group_policy() const { return group_policy_; }

/// @return Key-exchange group from the most recent completed handshake.
std::string TlsMockTransport::negotiated_group() const {
  return context_ == nullptr ? std::string() : context_->negotiated_group();
}

/// @return OpenSSL's ECH result, or a negative sentinel when unavailable.
int TlsMockTransport::ech_status() const { return context_ == nullptr ? -1 : context_->ech_status(); }

/// @return Decrypted inner SNI recovered by the ECH-capable server.
std::string TlsMockTransport::ech_inner_name() const {
  return context_ == nullptr ? std::string() : context_->ech_inner_name();
}

/// @return Public outer SNI visible before ECH decryption.
std::string TlsMockTransport::ech_outer_name() const {
  return context_ == nullptr ? std::string() : context_->ech_outer_name();
}

/// Build one reusable in-process server context from the complete Scenario.
/// @param scenario Bounded scenario configuring both sides of the transfer.
TlsMockServer::TlsMockServer(const curl::fuzzer::proto::Scenario& scenario) { Init(scenario, PeerRole::kHttp11); }

/// Initialize the transport policy for this server's fixed role. Keeping the
/// Scenario intact here prevents call sites and delegating constructors from
/// growing parallel parameter lists as correlated TLS controls are added.
/// @param scenario Bounded scenario configuring both sides of the transfer.
/// @param role Fixed application protocol role implemented by this peer.
void TlsMockServer::Init(const curl::fuzzer::proto::Scenario& scenario, PeerRole role) {
  assert(transport_ == nullptr);

  TlsApplicationProtocol protocol = TlsApplicationProtocol::kHttp11;
  auto certificate_chain = scenario.tls_certificate_chain();
  TlsGroupPolicy group_policy = TlsGroupPolicy::kProviderDefault;
  auto handshake_profile = curl::fuzzer::proto::TLS_HANDSHAKE_DEFAULT;
  TlsEarlyDataPolicy early_data_policy = TlsEarlyDataPolicy::kDisabled;
  auto ocsp_staple_profile = curl::fuzzer::proto::TLS_OCSP_STAPLE_NONE;
  session_cache_profile_ = curl::fuzzer::proto::TLS_SESSION_CACHE_DEFAULT;

  switch (role) {
    case PeerRole::kHttp11:
      if (scenario.scheme() == curl::fuzzer::proto::SCHEME_HTTPS) {
        handshake_profile = scenario.tls_handshake_profile();
        early_data_policy = EarlyDataPolicyForScenario(scenario);
        ocsp_staple_profile = scenario.tls_ocsp_staple_profile();
        session_cache_profile_ = scenario.tls_session_cache_profile();
      }
      break;
    case PeerRole::kHttp2Origin:
      protocol = TlsApplicationProtocol::kHttp2;
      group_policy = scenario.tls_group_profile() == curl::fuzzer::proto::TLS_GROUP_PROVIDER_DEFAULT
                         ? TlsGroupPolicy::kProviderDefault
                         : TlsGroupPolicy::kX25519;
      break;
    case PeerRole::kProxy:
      protocol = scenario.connection().proxy_protocol() == curl::fuzzer::proto::PROXY_PROTOCOL_HTTP1
                     ? TlsApplicationProtocol::kHttp11
                     : TlsApplicationProtocol::kHttp2;
      certificate_chain = curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC;
      break;
  }

  transport_ = std::make_unique<TlsMockTransport>(protocol, certificate_chain, group_policy, handshake_profile,
                                                  early_data_policy, ocsp_staple_profile);
}

/// Release SSL objects before their owning server context. OpenSSL reference
/// counting makes the reverse order legal, but making the ownership order
/// explicit keeps future transport state from acquiring a hidden dependency.
TlsMockServer::~TlsMockServer() { ResetConnections(); }

/// Install common socket callbacks and a stable local trust anchor. Curl copies
/// the blob descriptor during setopt and borrows the inline certificate bytes,
/// whose program lifetime safely exceeds every easy handle. Scenario options run
/// afterwards and can still disable verification or select failing TLS settings.
/// @param easy Easy handle that will connect to this TLS peer.
void TlsMockServer::Install(CURL* easy) {
  MockServer::Install(easy);
  transport_->Install(easy);
}

/// @return true once curl exposed a live TLS backend session during drive.
bool TlsMockServer::saw_live_tls_session() const { return saw_live_tls_session_; }

/// @return number of session representations copied by the export callback
/// out of curl's cache.
std::size_t TlsMockServer::exported_session_count() const { return exported_session_count_; }

/// @return number of copied session representations successfully imported
/// into curl's cache again.
std::size_t TlsMockServer::imported_session_count() const { return imported_session_count_; }

/// Import the retained session into a caller-configured cache.
/// @param easy Fresh easy handle whose cache receives the session.
/// @return The public import result for the selected profile.
CURLcode TlsMockServer::ImportArchivedSession(CURL* easy) {
  CURLcode result = CURLE_BAD_FUNCTION_ARGUMENT;
  switch (session_cache_profile_) {
    case curl::fuzzer::proto::TLS_SESSION_CACHE_FRESH_SALTED_HASH:
      result = session_archive_.ImportBySaltedHash(easy);
      break;
    case curl::fuzzer::proto::TLS_SESSION_CACHE_FRESH_SESSION_KEY:
      result = session_archive_.ImportBySessionKey(easy);
      break;
    case curl::fuzzer::proto::TLS_SESSION_CACHE_MALFORMED_SALTED_HASH:
      result = session_archive_.ImportMalformedSaltedHash(easy);
      break;
    case curl::fuzzer::proto::TLS_SESSION_CACHE_DEFAULT:
    default:
      result = session_archive_.ImportBySaltedHash(easy);
      break;
  }
  if (result == CURLE_OK) {
    ++imported_session_count_;
  }
  return result;
}

/// @return the one bounded session retained from curl's export callback.
const TlsSessionArchive& TlsMockServer::session_archive() const { return session_archive_; }

/// @return protocol version selected by the most recent completed handshake,
/// or zero when no connection completed TLS negotiation.
int TlsMockServer::negotiated_tls_version() const { return transport_->negotiated_tls_version(); }

/// @return number of connections that completed TLS negotiation.
std::size_t TlsMockServer::completed_handshake_count() const { return transport_->completed_handshake_count(); }

/// @return number of completed connections that resumed an earlier session.
std::size_t TlsMockServer::reused_session_count() const { return transport_->reused_session_count(); }

/// @return number of application writes OpenSSL required an exact retry for.
std::size_t TlsMockServer::write_retry_count() const { return transport_->write_retry_count(); }

/// @return ALPN protocol selected by the most recent completed handshake.
std::string TlsMockServer::negotiated_alpn() const { return transport_->negotiated_alpn(); }

/// @return Immutable key-exchange group policy selected at construction.
TlsGroupPolicy TlsMockServer::group_policy() const { return transport_->group_policy(); }

/// @return Key-exchange group from the most recent completed handshake.
std::string TlsMockServer::negotiated_group() const { return transport_->negotiated_group(); }

/// @return OpenSSL's ECH status for the most recent completed handshake.
/// Builds without ECH return a negative sentinel.
int TlsMockServer::ech_status() const { return transport_->ech_status(); }

/// @return encrypted inner SNI recovered by the ECH-capable server.
std::string TlsMockServer::ech_inner_name() const { return transport_->ech_inner_name(); }

/// @return public outer SNI visible before ECH decryption.
std::string TlsMockServer::ech_outer_name() const { return transport_->ech_outer_name(); }

/// Wrap one socketpair server endpoint in an OpenSSL acceptor consumed by
/// MockServer.
/// @return a failed connection when context setup was unavailable.
std::unique_ptr<MockConnection> TlsMockServer::CreateConnection() { return transport_->CreateConnection(); }

/// Query while the connection filters are attached. Result-info probes stop
/// after the first live result, and session export has its own fixed attempt
/// bound, so neither recurs throughout every HTTP parser iteration.
/// @param easy Active easy handle whose connection filters remain attached.
void TlsMockServer::ObserveActiveTransfer(CURL* easy) {
  if (!saw_live_tls_session_) {
    long verify_result = 0;
    curl_off_t appconnect_time = 0;
    struct curl_certinfo* certificate_info = nullptr;
    struct curl_tlssessioninfo* tls_session = nullptr;
    (void)curl_easy_getinfo(easy, CURLINFO_SSL_VERIFYRESULT, &verify_result);
    (void)curl_easy_getinfo(easy, CURLINFO_APPCONNECT_TIME_T, &appconnect_time);
    (void)curl_easy_getinfo(easy, CURLINFO_CERTINFO, &certificate_info);
    if (curl_easy_getinfo(easy, CURLINFO_TLS_SSL_PTR, &tls_session) == CURLE_OK && tls_session != nullptr &&
        tls_session->internals != nullptr) {
      saw_live_tls_session_ = true;
    }
  }

  // A TLS 1.3 ticket may arrive after the peer first completes its handshake.
  // Retry only a small fixed number of outer-loop observations, and stop
  // permanently once one copied ticket has made one import attempt.
  const bool completed_live_handshake = transport_->completed_handshake_count() != 0;
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  // Read the owned peer observations once after a real handshake. Signed
  // status values retain their unavailable sentinels; string results are
  // consumed immediately while their temporaries and context are still live.
  static bool observed = false;
  if (completed_live_handshake && !observed) {
    observed = true;
    const volatile bool live = saw_live_tls_session();
    const volatile int status[] = {negotiated_tls_version(), ech_status()};
    const volatile std::size_t counts[] = {
        exported_session_count(),  imported_session_count(), completed_handshake_count(),
        reused_session_count(),    write_retry_count(),      negotiated_alpn().size(),
        negotiated_group().size(), ech_inner_name().size(),  ech_outer_name().size()};
    (void)live;
    (void)status;
    (void)counts;
  }
#endif
  if (!completed_live_handshake || exported_session_count_ != 0 ||
      session_export_attempt_count_ >= kMaxSessionExportAttempts) {
    return;
  }
  ++session_export_attempt_count_;
  const CURLcode export_result = session_archive_.CaptureFrom(easy);
  if (export_result != CURLE_OK || session_archive_.empty()) {
    return;
  }
  ++exported_session_count_;

  // curl holds the cache lock throughout export. Import only after the public
  // export call returns. Nondefault profiles wait until the runner destroys
  // this handle and installs a new cache on the replay handle.
  if (session_cache_profile_ == curl::fuzzer::proto::TLS_SESSION_CACHE_DEFAULT) {
    (void)ImportArchivedSession(easy);
  }
}

}  // namespace proto_fuzzer
