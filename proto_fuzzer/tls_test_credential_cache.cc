/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Process-lifetime parsed credentials for in-process stream TLS peers.

#include "proto_fuzzer/tls_test_credential_cache.h"

#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "proto_fuzzer/tls_test_credentials.h"

namespace proto_fuzzer {

namespace {

/// Decode one checked-in PEM certificate.
/// @param pem NUL-terminated PEM text to decode.
/// @return A newly allocated certificate owned by the caller, or nullptr.
X509* ParseCertificate(const char* pem) {
  BIO* bio = BIO_new_mem_buf(pem, -1);
  if (bio == nullptr) {
    return nullptr;
  }
  X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return certificate;
}

/// Decode the checked-in PEM private key.
/// @param pem NUL-terminated PEM text to decode.
/// @return A newly allocated private key owned by the caller, or nullptr.
EVP_PKEY* ParsePrivateKey(const char* pem) {
  BIO* bio = BIO_new_mem_buf(pem, -1);
  if (bio == nullptr) {
    return nullptr;
  }
  EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return key;
}

/// Give one cached certificate reference to the context through the same
/// context-wide extra-chain API used before the credentials were cached.
/// @param context Fresh server context that will own the added reference.
/// @param certificate Cache-owned certificate to add.
/// @return true when the context took ownership of a new reference.
bool AddCachedExtraChainCertificate(SSL_CTX* context, X509* certificate) {
  if (certificate == nullptr || X509_up_ref(certificate) != 1) {
    return false;
  }
  if (SSL_CTX_add_extra_chain_cert(context, certificate) != 1) {
    X509_free(certificate);
    return false;
  }
  return true;
}

/// Own the parsed leaf certificate and matching private key retained by the
/// process cache.
class PrimaryCredentials {
 public:
  /// Decode the fixed leaf certificate and its private key once.
  PrimaryCredentials()
      : certificate_(ParseCertificate(tls_test_credentials::kCertificatePem)),
        key_(ParsePrivateKey(tls_test_credentials::kPrivateKeyPem)) {}

  /// Release the cache-owned certificate and key references.
  ~PrimaryCredentials() {
    X509_free(certificate_);
    EVP_PKEY_free(key_);
  }

  /// Keep ownership of the cached references process-unique.
  PrimaryCredentials(const PrimaryCredentials&) = delete;
  /// Prevent replacing the process cache's owning references.
  PrimaryCredentials& operator=(const PrimaryCredentials&) = delete;

  /// @return true when both fixed PEM values decoded successfully.
  bool valid() const { return certificate_ != nullptr && key_ != nullptr; }
  /// @return the cache-owned leaf certificate.
  X509* certificate() const { return certificate_; }
  /// @return the cache-owned private key.
  EVP_PKEY* key() const { return key_; }

 private:
  X509* certificate_;
  EVP_PKEY* key_;
};

/// Own the parsed issuer-signed leaf and its matching private key retained by
/// the process cache.
class OcspLeafCredentials {
 public:
  /// Decode the fixed OCSP leaf certificate and its private key once.
  OcspLeafCredentials()
      : certificate_(ParseCertificate(tls_test_credentials::kOcspLeafCertificatePem)),
        key_(ParsePrivateKey(tls_test_credentials::kOcspLeafPrivateKeyPem)) {}

  /// Release the cache-owned certificate and key references.
  ~OcspLeafCredentials() {
    X509_free(certificate_);
    EVP_PKEY_free(key_);
  }

  /// Keep ownership of the cached references process-unique.
  OcspLeafCredentials(const OcspLeafCredentials&) = delete;
  /// Prevent replacing the process cache's owning references.
  OcspLeafCredentials& operator=(const OcspLeafCredentials&) = delete;

  /// @return true when both fixed PEM values decoded successfully.
  bool valid() const { return certificate_ != nullptr && key_ != nullptr; }
  /// @return the cache-owned leaf certificate.
  X509* certificate() const { return certificate_; }
  /// @return the cache-owned private key.
  EVP_PKEY* key() const { return key_; }

 private:
  X509* certificate_;
  EVP_PKEY* key_;
};

/// Own the optional parsed certificates used by the all-key-types profile.
class AuxiliaryCertificates {
 public:
  /// Decode the fixed RSA, DSA, and DH certificates once.
  AuxiliaryCertificates()
      : rsa_(ParseCertificate(tls_test_credentials::kRsaCertificatePem)),
        dsa_(ParseCertificate(tls_test_credentials::kDsaCertificatePem)),
        dh_(ParseCertificate(tls_test_credentials::kDhCertificatePem)) {}

  /// Release the cache-owned auxiliary certificate references.
  ~AuxiliaryCertificates() {
    X509_free(rsa_);
    X509_free(dsa_);
    X509_free(dh_);
  }

  /// Keep ownership of the cached references process-unique.
  AuxiliaryCertificates(const AuxiliaryCertificates&) = delete;
  /// Prevent replacing the process cache's owning references.
  AuxiliaryCertificates& operator=(const AuxiliaryCertificates&) = delete;

  /// @return true when every auxiliary PEM value decoded successfully.
  bool valid() const { return rsa_ != nullptr && dsa_ != nullptr && dh_ != nullptr; }
  /// @return the cache-owned RSA certificate.
  X509* rsa() const { return rsa_; }
  /// @return the cache-owned DSA certificate.
  X509* dsa() const { return dsa_; }
  /// @return the cache-owned DH certificate.
  X509* dh() const { return dh_; }

 private:
  X509* rsa_;
  X509* dsa_;
  X509* dh_;
};

/// @return the process-lifetime leaf certificate and private key cache.
const PrimaryCredentials& CachedPrimaryCredentials() {
  static const PrimaryCredentials credentials;
  return credentials;
}

/// Lazily avoid parsing the issuer-signed leaf for non-OCSP scenarios.
/// @return the process-lifetime OCSP leaf certificate and private key cache.
const OcspLeafCredentials& CachedOcspLeafCredentials() {
  static const OcspLeafCredentials credentials;
  return credentials;
}

/// Lazily avoid parsing auxiliary certificates for the default profile.
/// @return the process-lifetime auxiliary certificate cache.
const AuxiliaryCertificates& CachedAuxiliaryCertificates() {
  static const AuxiliaryCertificates certificates;
  return certificates;
}

}  // namespace

/// Install references to immutable, process-lifetime test credentials in one
/// fresh TLS context. SSL_CTX_use_certificate and SSL_CTX_use_PrivateKey retain
/// their own references. Each extra-chain insertion receives an explicit
/// X509_up_ref because SSL_CTX_add_extra_chain_cert takes ownership on success.
/// No session, connection, callback, or observation state is shared.
/// @param context Fresh server context that will own the installed references.
/// @param certificate_chain Checked-in auxiliary certificate profile to use.
/// @param use_issuer_signed_leaf Whether to install the dedicated OCSP leaf and
/// add the ordinary self-signed certificate as its issuer.
/// @return true when the leaf, key, and selected chain were installed.
bool InstallCachedTlsTestCredentials(SSL_CTX* context,
                                     curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain,
                                     bool use_issuer_signed_leaf) {
  if (context == nullptr) {
    return false;
  }

  const PrimaryCredentials& primary = CachedPrimaryCredentials();
  X509* certificate = primary.certificate();
  EVP_PKEY* key = primary.key();
  if (!primary.valid()) {
    return false;
  }
  if (use_issuer_signed_leaf) {
    const OcspLeafCredentials& ocsp_leaf = CachedOcspLeafCredentials();
    if (!ocsp_leaf.valid()) {
      return false;
    }
    certificate = ocsp_leaf.certificate();
    key = ocsp_leaf.key();
  }
  if (SSL_CTX_use_certificate(context, certificate) != 1 || SSL_CTX_use_PrivateKey(context, key) != 1 ||
      SSL_CTX_check_private_key(context) != 1) {
    return false;
  }

  if (use_issuer_signed_leaf && !AddCachedExtraChainCertificate(context, primary.certificate())) {
    return false;
  }

  if (certificate_chain != curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES) {
    return true;
  }

  const AuxiliaryCertificates& auxiliary = CachedAuxiliaryCertificates();
  return auxiliary.valid() && AddCachedExtraChainCertificate(context, auxiliary.rsa()) &&
         AddCachedExtraChainCertificate(context, auxiliary.dsa()) &&
         AddCachedExtraChainCertificate(context, auxiliary.dh());
}

/// @return the process-lifetime issuer certificate borrowed by OCSP response
/// generation, or nullptr when its checked-in PEM could not be decoded.
X509* CachedTlsTestIssuerCertificate() {
  const PrimaryCredentials& primary = CachedPrimaryCredentials();
  return primary.valid() ? primary.certificate() : nullptr;
}

/// @return the process-lifetime issuer private key borrowed by OCSP response
/// generation, or nullptr when its checked-in PEM could not be decoded.
EVP_PKEY* CachedTlsTestIssuerPrivateKey() {
  const PrimaryCredentials& primary = CachedPrimaryCredentials();
  return primary.valid() ? primary.key() : nullptr;
}

}  // namespace proto_fuzzer
