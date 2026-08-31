/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Nonblocking OpenSSL server transport for structured HTTPS inputs.

#include "proto_fuzzer/tls_mock_server.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sys/socket.h>

#include <cstddef>
#include <string>

#include "proto_fuzzer/tls_test_credentials.h"

namespace proto_fuzzer {

namespace {

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

/// Select HTTP/1.1 when curl offers it. Keeping the server preference fixed
/// lets the existing HTTP corpus reach successful application traffic; seeds
/// that force HTTP/2 still exercise negotiation and failure handling.
int SelectAlpn(SSL* /*ssl*/, const unsigned char** selected, unsigned char* selected_length,
               const unsigned char* client_protocols, unsigned int client_protocols_length, void* /*userdata*/) {
  // OpenSSL may return a pointer into the server preference list. Function-
  // local static storage keeps that result valid for the rest of the
  // handshake without reintroducing transport policy as a namespace global.
  static constexpr unsigned char http11_alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  unsigned char* match = nullptr;
  unsigned char match_length = 0;
  const int result = SSL_select_next_proto(&match, &match_length, http11_alpn, sizeof(http11_alpn), client_protocols,
                                           client_protocols_length);
  if (result != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  *selected = match;
  *selected_length = match_length;
  return SSL_TLSEXT_ERR_OK;
}

}  // namespace

/// Own the certificate, key, session cache, ALPN policy, and observations
/// shared by every bounded connection in one Scenario. Keeping both session
/// state and its measurements here makes redirects related while preventing
/// one fuzz input from affecting the next.
class TlsServerContext {
 public:
  TlsServerContext()
      : context_(nullptr),
        negotiated_tls_version_(0),
        completed_handshake_count_(0),
        reused_session_count_(0),
        write_retry_count_(0) {
    OpenSslErrorQueueGuard error_guard;
    context_ = SSL_CTX_new(TLS_server_method());
    if (context_ == nullptr || !LoadCredentials()) {
      SSL_CTX_free(context_);
      context_ = nullptr;
      return;
    }

    (void)SSL_CTX_set_min_proto_version(context_, TLS1_2_VERSION);
    (void)SSL_CTX_set_options(context_, SSL_OP_NO_COMPRESSION);
    (void)SSL_CTX_set_session_cache_mode(context_, SSL_SESS_CACHE_SERVER);
    constexpr unsigned char session_id_context[] = "curl-fuzzer";
    (void)SSL_CTX_set_session_id_context(context_, session_id_context, sizeof(session_id_context) - 1);
    SSL_CTX_set_alpn_select_cb(context_, &SelectAlpn, nullptr);
  }

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
    ++completed_handshake_count_;
    if (SSL_session_reused(ssl) == 1) {
      ++reused_session_count_;
    }
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

 private:
  /// Parse the checked-in test-only PEM values entirely in memory.
  bool LoadCredentials() {
    BIO* certificate_bio = BIO_new_mem_buf(tls_test_credentials::kCertificatePem, -1);
    BIO* key_bio = BIO_new_mem_buf(tls_test_credentials::kPrivateKeyPem, -1);
    if (certificate_bio == nullptr || key_bio == nullptr) {
      BIO_free(certificate_bio);
      BIO_free(key_bio);
      return false;
    }

    X509* certificate = PEM_read_bio_X509(certificate_bio, nullptr, nullptr, nullptr);
    EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    BIO_free(certificate_bio);
    BIO_free(key_bio);
    if (certificate == nullptr || key == nullptr) {
      X509_free(certificate);
      EVP_PKEY_free(key);
      return false;
    }

    const bool loaded = SSL_CTX_use_certificate(context_, certificate) == 1 &&
                        SSL_CTX_use_PrivateKey(context_, key) == 1 && SSL_CTX_check_private_key(context_) == 1;
    X509_free(certificate);
    EVP_PKEY_free(key);
    return loaded;
  }

  SSL_CTX* context_;
  int negotiated_tls_version_;
  std::size_t completed_handshake_count_;
  std::size_t reused_session_count_;
  std::size_t write_retry_count_;
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
    OpenSslErrorQueueGuard error_guard;
    SSL_CTX* ssl_context = context_ == nullptr ? nullptr : context_->get();
    ssl_ = ssl_context == nullptr ? nullptr : SSL_new(ssl_context);
    if (ssl_ != nullptr) {
      SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
      if (SSL_set_fd(ssl_, server_fd()) != 1) {
        SSL_free(ssl_);
        ssl_ = nullptr;
      } else {
        SSL_set_accept_state(ssl_);
      }
    }
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
        progress += received;
        continue;
      }
      if (result != 1) {
        const int error = SSL_get_error(ssl_, result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE && error != SSL_ERROR_ZERO_RETURN) {
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
    shutdown_requested_ = true;
    (void)DrainIncoming();
  }

 private:
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

}  // namespace

/// Build one reusable in-process server context per fuzz iteration.
TlsMockServer::TlsMockServer() : context_(std::make_unique<TlsServerContext>()), saw_live_tls_session_(false) {}

/// Release SSL objects before their owning server context. OpenSSL reference
/// counting makes the reverse order legal, but making the ownership order
/// explicit keeps future transport state from acquiring a hidden dependency.
TlsMockServer::~TlsMockServer() { ResetConnections(); }

/// Add verification to the common socket callbacks. Curl copies the blob
/// descriptor during setopt and borrows the inline certificate bytes, whose
/// program lifetime safely exceeds every easy handle.
void TlsMockServer::Install(CURL* easy) {
  MockServer::Install(easy);
  struct curl_blob trust_anchor = {const_cast<char*>(tls_test_credentials::kCertificatePem),
                                   sizeof(tls_test_credentials::kCertificatePem) - 1, CURL_BLOB_NOCOPY};
  (void)curl_easy_setopt(easy, CURLOPT_CAINFO_BLOB, &trust_anchor);
  (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
}

/// Report whether the drive reached curl's live TLS backend-query path.
bool TlsMockServer::saw_live_tls_session() const { return saw_live_tls_session_; }

/// Report the protocol selected by the latest successful server handshake.
int TlsMockServer::negotiated_tls_version() const {
  return context_ == nullptr ? 0 : context_->negotiated_tls_version();
}

/// Report how many bounded connections finished their TLS handshake.
std::size_t TlsMockServer::completed_handshake_count() const {
  return context_ == nullptr ? 0 : context_->completed_handshake_count();
}

/// Report how many later connections resumed state from this scenario.
std::size_t TlsMockServer::reused_session_count() const {
  return context_ == nullptr ? 0 : context_->reused_session_count();
}

/// Report how often response delivery reached OpenSSL's exact-retry path.
std::size_t TlsMockServer::write_retry_count() const { return context_ == nullptr ? 0 : context_->write_retry_count(); }

/// Create the polymorphic record-layer connection consumed by MockServer.
std::unique_ptr<MockConnection> TlsMockServer::CreateConnection() {
  return std::make_unique<TlsMockConnection>(context_.get());
}

/// Query while the connection filters are attached. Stop after the first live
/// result so these coverage probes add a bounded handful of calls during the
/// handshake rather than recurring throughout every HTTP parser iteration.
/// @param easy Active easy handle whose connection filters remain attached.
void TlsMockServer::ObserveActiveTransfer(CURL* easy) {
  if (saw_live_tls_session_) {
    return;
  }
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

}  // namespace proto_fuzzer
