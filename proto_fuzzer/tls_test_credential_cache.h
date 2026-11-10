/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Installs cached test credentials into fresh TLS contexts.

#ifndef PROTO_FUZZER_TLS_TEST_CREDENTIAL_CACHE_H_
#define PROTO_FUZZER_TLS_TEST_CREDENTIAL_CACHE_H_

#include <openssl/types.h>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

bool InstallCachedTlsTestCredentials(SSL_CTX* context,
                                     curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain,
                                     bool use_issuer_signed_leaf);

/// @return the process-lifetime issuer certificate borrowed by OCSP response
/// generation, or nullptr when its checked-in PEM could not be decoded.
X509* CachedTlsTestIssuerCertificate();

/// @return the process-lifetime issuer private key borrowed by OCSP response
/// generation, or nullptr when its checked-in PEM could not be decoded.
EVP_PKEY* CachedTlsTestIssuerPrivateKey();

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TLS_TEST_CREDENTIAL_CACHE_H_
