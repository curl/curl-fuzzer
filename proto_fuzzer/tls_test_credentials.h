/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Public test-only credentials for the in-process TLS peer.

#ifndef PROTO_FUZZER_TLS_TEST_CREDENTIALS_H_
#define PROTO_FUZZER_TLS_TEST_CREDENTIALS_H_

namespace proto_fuzzer::tls_test_credentials {

/// Self-signed P-256 certificate for tls.test. It is deliberately checked in
/// with its key: authenticity is irrelevant to the isolated socketpair, while
/// stable credentials make verification, certificate-info, and session-cache
/// paths deterministic across fuzz workers. The hostname is a PrintableString
/// common name so OpenSSL converts it to owned UTF-8 before curl performs its
/// embedded-NUL check. OpenSSL's fuzzing mode deliberately omits the courtesy
/// NUL it normally appends to ASN.1 strings, exposing curl's unsafe strlen on
/// SAN data; using the common-name path keeps successful TLS coverage possible
/// while still reaching Curl_cert_hostcheck.
inline constexpr char kCertificatePem[] = R"PEM(-----BEGIN CERTIFICATE-----
MIIBoTCCAUigAwIBAgIUTrd5BlbzPwzAZVPyiMSWVcHWgoowCgYIKoZIzj0EAwIw
EzERMA8GA1UEAxMIdGxzLnRlc3QwIBcNMjYwODMxMTUyMTQ1WhgPMjEyNjA4MDcx
NTIxNDVaMBMxETAPBgNVBAMTCHRscy50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEr/RA8idLSfFXwuj+q8c+vSOWCiByiVUqTt9tN1RGNrxwa/4HuVet9SCk
XKXqaDjjz6E9osU1U5vsLf5MV/KfxqN4MHYwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAoQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFAs69Bbr
sqQ7Elj+Be/JurMNf3kRMB8GA1UdIwQYMBaAFAs69BbrsqQ7Elj+Be/JurMNf3kR
MAoGCCqGSM49BAMCA0cAMEQCICHgECQlZ7uDVLFlUIw2kFI4r7bgjdfYShhiCPCT
MNp/AiAOx/lLgYPkZlukA/yG3Wm96JM7tTMr9ZdlR4owOjuJig==
-----END CERTIFICATE-----
)PEM";

/// SHA-256 SubjectPublicKeyInfo pin for kCertificatePem. Keeping the digest
/// beside the credential lets runtime tests prove curl's in-memory pin path
/// without introducing a filename-backed fixture.
inline constexpr char kPublicKeyPin[] = "sha256//ohF20oHrdt/MM3YpyIewiTdtTbgZwq3qatd40TjMtYg=";

/// Matching unencrypted private key. This is not a secret and must never be
/// reused outside the fuzzer's local, non-routable test transport.
inline constexpr char kPrivateKeyPem[] = R"PEM(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJCwIFvJA7cQnxvlN
TwarAITPg4Sy83sqQZevrIdPhRihRANCAASv9EDyJ0tJ8VfC6P6rxz69I5YKIHKJ
VSpO3203VEY2vHBr/ge5V631IKRcpepoOOPPoT2ixTVTm+wt/kxX8p/G
-----END PRIVATE KEY-----
)PEM";

}  // namespace proto_fuzzer::tls_test_credentials

#endif  // PROTO_FUZZER_TLS_TEST_CREDENTIALS_H_
