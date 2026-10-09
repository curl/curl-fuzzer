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

X509* ParseCertificate(const char* pem) {
  BIO* bio = BIO_new_mem_buf(pem, -1);
  if (bio == nullptr) {
    return nullptr;
  }
  X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return certificate;
}

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

class PrimaryCredentials {
 public:
  PrimaryCredentials()
      : certificate_(ParseCertificate(tls_test_credentials::kCertificatePem)),
        key_(ParsePrivateKey(tls_test_credentials::kPrivateKeyPem)) {}

  ~PrimaryCredentials() {
    X509_free(certificate_);
    EVP_PKEY_free(key_);
  }

  PrimaryCredentials(const PrimaryCredentials&) = delete;
  PrimaryCredentials& operator=(const PrimaryCredentials&) = delete;

  bool valid() const { return certificate_ != nullptr && key_ != nullptr; }
  X509* certificate() const { return certificate_; }
  EVP_PKEY* key() const { return key_; }

 private:
  X509* certificate_;
  EVP_PKEY* key_;
};

class AuxiliaryCertificates {
 public:
  AuxiliaryCertificates()
      : rsa_(ParseCertificate(tls_test_credentials::kRsaCertificatePem)),
        dsa_(ParseCertificate(tls_test_credentials::kDsaCertificatePem)),
        dh_(ParseCertificate(tls_test_credentials::kDhCertificatePem)) {}

  ~AuxiliaryCertificates() {
    X509_free(rsa_);
    X509_free(dsa_);
    X509_free(dh_);
  }

  AuxiliaryCertificates(const AuxiliaryCertificates&) = delete;
  AuxiliaryCertificates& operator=(const AuxiliaryCertificates&) = delete;

  bool valid() const { return rsa_ != nullptr && dsa_ != nullptr && dh_ != nullptr; }
  X509* rsa() const { return rsa_; }
  X509* dsa() const { return dsa_; }
  X509* dh() const { return dh_; }

 private:
  X509* rsa_;
  X509* dsa_;
  X509* dh_;
};

const PrimaryCredentials& CachedPrimaryCredentials() {
  static const PrimaryCredentials credentials;
  return credentials;
}

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
/// @return true when the leaf, key, and selected chain were installed.
bool InstallCachedTlsTestCredentials(SSL_CTX* context,
                                     curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain) {
  if (context == nullptr) {
    return false;
  }

  const PrimaryCredentials& primary = CachedPrimaryCredentials();
  if (!primary.valid() || SSL_CTX_use_certificate(context, primary.certificate()) != 1 ||
      SSL_CTX_use_PrivateKey(context, primary.key()) != 1 || SSL_CTX_check_private_key(context) != 1) {
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

}  // namespace proto_fuzzer
