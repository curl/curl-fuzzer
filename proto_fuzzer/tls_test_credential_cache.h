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
                                     curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TLS_TEST_CREDENTIAL_CACHE_H_
