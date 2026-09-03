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

/// Auxiliary certificates signed by kPrivateKeyPem. The all-key-types chain
/// sends them after the ordinary EC leaf: they are peer-controlled untrusted
/// entries rather than issuers, so OpenSSL can verify the directly trusted
/// leaf while curl still formats every public key in SSL_get_peer_cert_chain.
/// Their private keys are intentionally omitted because they never
/// authenticate the handshake.
inline constexpr char kRsaCertificatePem[] = R"PEM(-----BEGIN CERTIFICATE-----
MIIB3DCCAYECAjABMAoGCCqGSM49BAMCMBMxETAPBgNVBAMTCHRscy50ZXN0MCAX
DTI2MDkwMzE0MjE0OVoYDzIxMjYwODEwMTQyMTQ5WjASMRAwDgYDVQQDDAdyc2Eu
YXV4MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Ww/8s0nqQ72eJyv
Ogbi8JvbXCvl2sOutCDNAP0xTGCCUAlZDOmK1M+LBP8tn6E5Ea6i52sYhXc6Dhx2
cXY11LQ3IrVzORPQ4ONsxgsqmUIcDG4Kujac0qev3SpmfI+eRoRIj7A62yevhvkp
/iUfVj5K5jk5sQtOCezY2OYiNqLZjVdBPDJwJjX+wCe0TCj/uN65hyLarNSbHRxw
jUfhjUpK52KiP/tigyEcftvqM+WqZi74yo59OME7C+Nz9CC3irQD/LnaS66Z6Gxv
QjoiexgrXLRQeu06SALsJy2vCZQYpvfGG0w8TBDULtOLecj9a1q+nlJZEUvU5zH5
lvFHbwIDAQABMAoGCCqGSM49BAMCA0kAMEYCIQDZv+GxAR9JNuttTIxE/Z/0lJRI
Pri54HdZ4lLEiiGZ1AIhAK8mgr7CWGpPF1Wi2R4qumDi4awk0+MpK5JOudetQ2R5
-----END CERTIFICATE-----
)PEM";

/// Extension-free X.509 v1 DSA certificate with a deliberately negative
/// serial. Besides DSA parameter formatting, it covers certinfo's negative
/// serial and no-extension paths.
inline constexpr char kDsaCertificatePem[] = R"PEM(-----BEGIN CERTIFICATE-----
MIID+jCCA6ACAf8wCgYIKoZIzj0EAwIwEzERMA8GA1UEAxMIdGxzLnRlc3QwIBcN
MjYwOTAzMTQyMjUwWhgPMjEyNjA4MTAxNDIyNTBaMBIxEDAOBgNVBAMMB2RzYS5h
dXgwggNCMIICNQYHKoZIzjgEATCCAigCggEBAMxwZWGyiSVNbJOKMwiPceUhxBxX
Vz7YIbfQnqg2SFn3X/BXJ9FCbrnPyylyjMRe5ntgZq5DkiPK8x2rTr22G6Gs91cv
6iOBPIuO5srSTc/ZPW4eUeMDlmSVpnvh6mWD2AnNilBOcfgChdjQZNl1vKmJPB0T
J8O9jNyMguJldUFqME7gMUUxZdTLwEN6wFgnB6jw7LrY4zecRvTcXozAKoTYLbts
7btXSQGzREZLIsyF9WWHklylHl21TV2UdXyeu8AXz7HyvEvUkzA0y6qsMMLNqbVR
xFfScHQ8lLpYkkZNfNX7tEqYRMAdzRCXJw6sSMt8CYLdbB+kfIoB5dfygEkCHQDH
JVDypQC4FLz76FR9V+65BKAsh+qqkyTeC/d1AoIBAEC9jvlks7MjV3ju8CNr+AOn
HeecK3jCrRy2qZz3ylGUa76ZJDzlOIvTE79EjFXMnKKhRrVS8Y6l3y5oRxfa4juc
dve1agSOI6N9En7x3alE1miNsle+oVL5Agth3OgBifyoMjOofyBk5Jl6xUVOHLwK
Xp78KyvZEhh3CVOlmdI5UAFCYbD7YjPNZ92jZrH3u09ue/mLdPyDpxGWSlcazsSD
IGdGZIv9gcR6Qou+zZBJkZBRf+Pu70sJAJuyzRFlddmilzg3AjJ5t5cstsz1LgD4
vcat41HHp0M9n70DfhSZ4e7W66RJQ0Bsa9suBgVSaIQlYFq6vDSSXK2Al/K8sycD
ggEFAAKCAQBB+fqotHwXpzyLcZI1ay7YZ0NLY+eD+thfMLCxI5BVHsrP2p0khpKx
DJvr9HrBCGgrtpFRSmWazZP0O/Q9higv8wGZKn/asIjqqufGZ7ZZ7u0qwNJTAGc3
GARbNq/Y+UG0CmYStBKx8NNxg29Fkpk9KQkJkkQpslZwqZ30TSzx4xuzF5AGBHY6
ZGQEijSqsRX7bJnUG2+5qIl+cWJWVb+ceNeIJEGjeSVJFl/t09wTLf9b0uPQKVr/
lopxOZ8n30iM0zcDb/3+fmGoZZgi376GINlm5Vlsq158aT2wOC9e1auUohhcScxg
1av12vUzI8MfOS8K52ebSFFDuv1PLlu5MAoGCCqGSM49BAMCA0gAMEUCIQCg72PS
xpa/xm8prESb2ai1TRPEOdp0ZFF88TuhSGyyHwIgBPE76ZktynQhPthr3oEu4doz
/VfEwnI57qaOvvRaL0g=
-----END CERTIFICATE-----
)PEM";

/// Finite-field PKCS#3 DH certificate. Its dhKeyAgreement SubjectPublicKeyInfo
/// maps to EVP_PKEY_DH; a DHX certificate would miss curl's dedicated branch.
inline constexpr char kDhCertificatePem[] = R"PEM(-----BEGIN CERTIFICATE-----
MIIC3TCCAoMCAjADMAoGCCqGSM49BAMCMBMxETAPBgNVBAMTCHRscy50ZXN0MCAX
DTI2MDkwMzE0MjE0OVoYDzIxMjYwODEwMTQyMTQ5WjARMQ8wDQYDVQQDDAZkaC5h
dXgwggIlMIIBFwYJKoZIhvcNAQMBMIIBCAKCAQEA//////////+t+FRYortKmq/c
ViAnPTzx2LnFg84tNpWp4TZBFGQz+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPf
HtXV/WVhJDP1H18GbtCFY2VVPe0a87VXE15/V8k1mE8McODmi3fipona8+/och3x
WKE2rec1MKzKT0g6eXq8CrGCsyT7YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W
7edjcrsZCwenyO4KbXCeAvzhzffi7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+
OxtMb61zO7X8vC7CIAXFjvGDfRaDssbzSibBsu/6iGtCOGEoXJf//////////wIB
AgOCAQYAAoIBAQCnkXCngCfUjptFONM31hKrPugv8wWDtnLEUP0DWldFWh5sI1HN
dtBnao8hTIjSLBCep8j6puMfjdMhNRv/jqutYEUKF8cUhNbAXuSPyyzloC1v6RfC
bRvyqH9km1ymTV5xg7TTBZdHIQ1MeecbiE8PctzXgEKaRIgTou3avwTmAiJxPXj2
3Zqw2LYxUCXM1S46FhC0zo0kSDtirGYjixNg8euOnJ/4aQHIxLHjbth2PWO1RgGJ
UAplUBWk9jZinDF1JdK5y5Icrc6Z0ah3K9l66xGM7gAwgqbpQxdceHHYM5DlFWVr
2pJgcm8Ld93nXNuGPpvRb0YUgRQuJL9slrp9MAoGCCqGSM49BAMCA0gAMEUCIAYb
DdtuyE3z5UvUm+ic9PSLVgDeGSiL5uzgqRATHboOAiEAw1oL2zLcq6cRyTGtfl9j
av8pRT4U2I6ZW71jktZp754=
-----END CERTIFICATE-----
)PEM";

/// Stable RFC 9849 ECHConfigList advertised to curl by the successful ECH
/// seed. Its public name is public.test; curl keeps tls.test in the encrypted
/// inner ClientHello and uses the ordinary certificate above to authenticate
/// that inner name.
inline constexpr char kEchConfigListBase64[] =
    "AD7+DQA67AAgACDGVurJKeQ5Lwz2+XX6+hJyRdz6OmmPMFnsTfn1fD9ISgAEAAEA"
    "AQALcHVibGljLnRlc3QAAA==";

/// Test-only X25519 private key and its matching ECHConfigList. OpenSSL's ECH
/// store consumes this PEM pair on the server; it is unrelated to the TLS
/// certificate key and must never be used outside the isolated socketpair.
inline constexpr char kEchConfigPem[] = R"PEM(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIJg0AUAFk+vW0YmYjKkdPxF/jMy7DSBkNRe2p5hXJXpd
-----END PRIVATE KEY-----
-----BEGIN ECHCONFIG-----
AD7+DQA67AAgACDGVurJKeQ5Lwz2+XX6+hJyRdz6OmmPMFnsTfn1fD9ISgAEAAEA
AQALcHVibGljLnRlc3QAAA==
-----END ECHCONFIG-----
)PEM";

}  // namespace proto_fuzzer::tls_test_credentials

#endif  // PROTO_FUZZER_TLS_TEST_CREDENTIALS_H_
