/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <openssl/ssl.h>

#include <cstdlib>
#include <iostream>
#include <memory>

#include "proto_fuzzer/tls_test_credential_cache.h"

namespace {

using SslContextPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;

/// Exit the focused test with a diagnostic.
/// @param message Failure text written to standard error.
void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

/// Require one ownership or lifetime invariant.
/// @param condition Invariant result.
/// @param message Failure text used when the invariant is false.
void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

/// @return a separately owned, mutable server context.
SslContextPtr MakeContext() {
  return SslContextPtr(SSL_CTX_new(TLS_server_method()), &SSL_CTX_free);
}

/// Verify that parsed credential objects are shared by reference while the
/// contexts and their mutable TLS state remain separately owned.
void TestCachedCredentialsInstallInIndependentContexts() {
  SslContextPtr default_context = MakeContext();
  SslContextPtr first_chain_context = MakeContext();
  SslContextPtr second_chain_context = MakeContext();
  Expect(default_context != nullptr && first_chain_context != nullptr &&
             second_chain_context != nullptr,
         "credential-cache test could not allocate fresh TLS contexts");

  Expect(proto_fuzzer::InstallCachedTlsTestCredentials(
             default_context.get(),
             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC),
         "cached default TLS credentials could not be installed");
  Expect(proto_fuzzer::InstallCachedTlsTestCredentials(
             first_chain_context.get(),
             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES),
         "cached alternate TLS chain could not be installed");
  Expect(proto_fuzzer::InstallCachedTlsTestCredentials(
             second_chain_context.get(),
             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES),
         "cached alternate TLS chain could not be reused");

  Expect(default_context.get() != first_chain_context.get() &&
             first_chain_context.get() != second_chain_context.get(),
         "credential cache reused mutable TLS contexts");
  Expect(SSL_CTX_get0_certificate(default_context.get()) ==
                 SSL_CTX_get0_certificate(first_chain_context.get()) &&
             SSL_CTX_get0_certificate(first_chain_context.get()) ==
                 SSL_CTX_get0_certificate(second_chain_context.get()),
         "TLS contexts did not retain the same cached leaf certificate");
  Expect(SSL_CTX_get0_privatekey(default_context.get()) ==
                 SSL_CTX_get0_privatekey(first_chain_context.get()) &&
             SSL_CTX_get0_privatekey(first_chain_context.get()) ==
                 SSL_CTX_get0_privatekey(second_chain_context.get()),
         "TLS contexts did not retain the same cached private key");

  STACK_OF(X509) *default_leaf_chain = nullptr;
  STACK_OF(X509) *first_leaf_chain = nullptr;
  STACK_OF(X509) *second_leaf_chain = nullptr;
  Expect(SSL_CTX_get0_chain_certs(default_context.get(), &default_leaf_chain) ==
                 1 &&
             SSL_CTX_get0_chain_certs(first_chain_context.get(),
                                      &first_leaf_chain) == 1 &&
             SSL_CTX_get0_chain_certs(second_chain_context.get(),
                                      &second_leaf_chain) == 1,
         "TLS contexts did not expose their leaf-associated chains");
  Expect(
      (default_leaf_chain == nullptr || sk_X509_num(default_leaf_chain) == 0) &&
          (first_leaf_chain == nullptr || sk_X509_num(first_leaf_chain) == 0) &&
          (second_leaf_chain == nullptr || sk_X509_num(second_leaf_chain) == 0),
      "cached credentials unexpectedly changed a leaf-associated chain");

  STACK_OF(X509) *default_extra_chain = nullptr;
  STACK_OF(X509) *first_extra_chain = nullptr;
  STACK_OF(X509) *second_extra_chain = nullptr;
  Expect(SSL_CTX_get_extra_chain_certs_only(default_context.get(),
                                            &default_extra_chain) == 1 &&
             SSL_CTX_get_extra_chain_certs_only(first_chain_context.get(),
                                                &first_extra_chain) == 1 &&
             SSL_CTX_get_extra_chain_certs_only(second_chain_context.get(),
                                                &second_extra_chain) == 1,
         "TLS contexts did not expose their context-wide extra chains");
  Expect(default_extra_chain == nullptr ||
             sk_X509_num(default_extra_chain) == 0,
         "default TLS profile unexpectedly gained auxiliary certificates");
  Expect(first_extra_chain != nullptr && second_extra_chain != nullptr &&
             sk_X509_num(first_extra_chain) == 3 &&
             sk_X509_num(second_extra_chain) == 3,
         "alternate TLS profile did not retain all cached certificates");
  for (int index = 0; index < 3; ++index) {
    Expect(sk_X509_value(first_extra_chain, index) ==
               sk_X509_value(second_extra_chain, index),
           "alternate TLS contexts did not share cached chain references");
  }

  Expect(SSL_CTX_sess_number(default_context.get()) == 0 &&
             SSL_CTX_sess_number(first_chain_context.get()) == 0 &&
             SSL_CTX_sess_number(second_chain_context.get()) == 0,
         "credential installation shared TLS session state");
}

/// Record cached credential addresses from one context, destroy it, then prove
/// the cache can install the same objects in a later context.
void TestCachedCredentialsOutliveContexts() {
  SslContextPtr first = MakeContext();
  Expect(first != nullptr &&
             proto_fuzzer::InstallCachedTlsTestCredentials(
                 first.get(),
                 curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES),
         "first lifetime test context could not install cached credentials");
  X509 *leaf = SSL_CTX_get0_certificate(first.get());
  EVP_PKEY *key = SSL_CTX_get0_privatekey(first.get());
  STACK_OF(X509) *chain = nullptr;
  Expect(SSL_CTX_get_extra_chain_certs_only(first.get(), &chain) == 1 &&
             chain != nullptr && sk_X509_num(chain) == 3,
         "first lifetime test context did not expose its cached chain");
  X509 *auxiliary[3] = {sk_X509_value(chain, 0), sk_X509_value(chain, 1),
                        sk_X509_value(chain, 2)};
  first.reset();

  SslContextPtr second = MakeContext();
  Expect(
      second != nullptr &&
          proto_fuzzer::InstallCachedTlsTestCredentials(
              second.get(),
              curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES),
      "cached credentials did not survive destruction of an earlier context");
  STACK_OF(X509) *second_chain = nullptr;
  Expect(SSL_CTX_get0_certificate(second.get()) == leaf &&
             SSL_CTX_get0_privatekey(second.get()) == key &&
             SSL_CTX_get_extra_chain_certs_only(second.get(), &second_chain) ==
                 1 &&
             second_chain != nullptr && sk_X509_num(second_chain) == 3,
         "later context did not reuse the process-lifetime credentials");
  for (int index = 0; index < 3; ++index) {
    Expect(sk_X509_value(second_chain, index) == auxiliary[index],
           "cached auxiliary certificate did not outlive its first context");
  }
}

/// Reject installation when no destination context can own references.
void TestNullContextIsRejected() {
  Expect(!proto_fuzzer::InstallCachedTlsTestCredentials(
             nullptr, curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC),
         "credential cache accepted a null TLS context");
}

} // namespace

/// Run the parsed-credential ownership and lifetime regressions.
/// @return zero when every invariant holds.
int main() {
  TestNullContextIsRejected();
  TestCachedCredentialsInstallInIndependentContexts();
  TestCachedCredentialsOutliveContexts();
  return 0;
}
