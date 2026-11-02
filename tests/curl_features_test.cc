/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#if (defined(CURL_FUZZER_EXPECT_OPENSSL) ||                                    \
     defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)) &&             \
    defined(CURL_FUZZER_EXPECT_GNUTLS)
#error "A curl feature test must select exactly one expected TLS backend"
#endif
#if defined(CURL_FUZZER_EXPECT_MBEDTLS) &&                                     \
    (defined(CURL_FUZZER_EXPECT_OPENSSL) ||                                    \
     defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES) ||              \
     defined(CURL_FUZZER_EXPECT_GNUTLS))
#error "A curl feature test must select exactly one expected TLS backend"
#endif

namespace {

bool HasNamedFeature(const curl_version_info_data *info, const char *expected) {
  if (!info->feature_names) {
    return false;
  }
  for (const char *const *feature = info->feature_names; *feature; ++feature) {
    if (std::strcmp(*feature, expected) == 0) {
      return true;
    }
  }
  return false;
}

#ifdef CURL_FUZZER_EXPECT_MULTI_SSL
bool HasSslBackend(const curl_ssl_backend *const *available,
                   curl_sslbackend expected) {
  if (!available) {
    return false;
  }
  for (; *available; ++available) {
    if ((*available)->id == expected) {
      return true;
    }
  }
  return false;
}

class CurlGlobalCleanup final {
public:
  CurlGlobalCleanup() = default;
  ~CurlGlobalCleanup() { curl_global_cleanup(); }

  CurlGlobalCleanup(const CurlGlobalCleanup &) = delete;
  CurlGlobalCleanup &operator=(const CurlGlobalCleanup &) = delete;
};

bool SelectAndCheckSslBackend(curl_sslbackend selected,
                              curl_sslbackend rejected,
                              const char *version_prefix) {
  const CURLsslset selection = curl_global_sslset(selected, nullptr, nullptr);
  if (selection != CURLSSLSET_OK) {
    std::fprintf(stderr, "curl_global_sslset failed for backend %d: %d\n",
                 static_cast<int>(selected), static_cast<int>(selection));
    return false;
  }
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    std::fprintf(stderr, "curl_global_init failed for backend %d\n",
                 static_cast<int>(selected));
    return false;
  }
  const curl_version_info_data *const info = curl_version_info(CURLVERSION_NOW);
  const char *const version =
      info && info->ssl_version ? std::strstr(info->ssl_version, version_prefix)
                                : nullptr;
  // MultiSSL lists every linked backend and parenthesizes inactive ones.
  const bool version_matches =
      version && (version == info->ssl_version || version[-1] != '(');
  const CURLsslset rejected_result =
      curl_global_sslset(rejected, nullptr, nullptr);
  const bool selection_locked = rejected_result == CURLSSLSET_TOO_LATE;
  if (!version_matches) {
    std::fprintf(stderr, "backend %d reported unexpected version: %s\n",
                 static_cast<int>(selected),
                 info && info->ssl_version ? info->ssl_version : "<null>");
  }
  if (!selection_locked) {
    std::fprintf(stderr, "backend %d accepted late switch with result %d\n",
                 static_cast<int>(selected), static_cast<int>(rejected_result));
  }
  curl_global_cleanup();
  return version_matches && selection_locked;
}
#endif

#if defined(CURL_FUZZER_EXPECT_OPENSSL) ||                                     \
    defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES) ||               \
    defined(CURL_FUZZER_EXPECT_GNUTLS) || defined(CURL_FUZZER_EXPECT_MBEDTLS)
bool HasPrefix(const char *value, const char *expected) {
  return value && std::strncmp(value, expected, std::strlen(expected)) == 0;
}
#endif

} // namespace

int main() {
#ifdef CURL_FUZZER_EXPECT_MULTI_SSL
  (void)unsetenv("CURL_SSL_BACKEND");
  const curl_ssl_backend **available = nullptr;
  if (curl_global_sslset(CURLSSLBACKEND_NONE, nullptr, &available) !=
      CURLSSLSET_UNKNOWN_BACKEND) {
    std::fputs("libcurl did not expose its available TLS backends\n", stderr);
    return 1;
  }
  if (!HasSslBackend(available, CURLSSLBACKEND_MBEDTLS) ||
      !HasSslBackend(available, CURLSSLBACKEND_OPENSSL)) {
    std::fputs("libcurl was not built with mbedTLS and OpenSSL backends\n",
               stderr);
    return 1;
  }
  if (!SelectAndCheckSslBackend(CURLSSLBACKEND_MBEDTLS, CURLSSLBACKEND_OPENSSL,
                                "mbedTLS/") ||
      !SelectAndCheckSslBackend(CURLSSLBACKEND_OPENSSL, CURLSSLBACKEND_MBEDTLS,
                                "OpenSSL/")) {
    std::fputs("libcurl could not cycle through its MultiSSL backends\n",
               stderr);
    return 1;
  }
  available = nullptr;
  if (curl_global_sslset(CURLSSLBACKEND_NONE, nullptr, &available) !=
          CURLSSLSET_UNKNOWN_BACKEND ||
      available == nullptr) {
    std::fputs("libcurl did not reset MultiSSL after global cleanup\n", stderr);
    return 1;
  }
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    std::fputs("curl_global_init failed\n", stderr);
    return 1;
  }
  CurlGlobalCleanup cleanup;
#endif

  const curl_version_info_data *const info = curl_version_info(CURLVERSION_NOW);
  if (!info) {
    std::fputs("curl_version_info returned null\n", stderr);
    return 1;
  }
  if (!(info->features & CURL_VERSION_BROTLI)) {
    std::fputs("libcurl was built without Brotli support\n", stderr);
    return 1;
  }
  if (!info->brotli_version || info->brotli_ver_num == 0) {
    std::fputs("libcurl did not report its linked Brotli version\n", stderr);
    return 1;
  }
  if (HasNamedFeature(info, "gsasl")) {
    std::fputs("libcurl was built with unexpected GSASL support\n", stderr);
    return 1;
  }
#ifdef CURL_FUZZER_EXPECT_MULTI_SSL
  if (!(info->features & CURL_VERSION_MULTI_SSL) ||
      !HasNamedFeature(info, "MultiSSL")) {
    std::fputs("libcurl was built without MultiSSL support\n", stderr);
    return 1;
  }
#endif
#if defined(CURL_FUZZER_EXPECT_OPENSSL) ||                                     \
    defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)
  if (!HasPrefix(info->ssl_version, "OpenSSL/")) {
    std::fputs("libcurl does not report OpenSSL as its TLS backend\n", stderr);
    return 1;
  }
#endif
#ifdef CURL_FUZZER_EXPECT_GNUTLS
  if (!HasPrefix(info->ssl_version, "GnuTLS/")) {
    std::fputs("libcurl does not report GnuTLS as its TLS backend\n", stderr);
    return 1;
  }
#endif
#ifdef CURL_FUZZER_EXPECT_MBEDTLS
  if (!HasPrefix(info->ssl_version, "mbedTLS/")) {
    std::fputs("libcurl does not report mbedTLS as its TLS backend\n", stderr);
    return 1;
  }
#endif
#ifdef CURL_FUZZER_EXPECT_HTTP3
  if (!(info->features & CURL_VERSION_HTTP3)) {
    std::fputs("libcurl was built without HTTP/3 support\n", stderr);
    return 1;
  }
  if (!info->quic_version ||
      std::strstr(info->quic_version, "ngtcp2/") == nullptr ||
      std::strstr(info->quic_version, "nghttp3/") == nullptr) {
    std::fputs("libcurl does not report the ngtcp2/nghttp3 stack\n", stderr);
    return 1;
  }
#endif
#if defined(CURL_FUZZER_EXPECT_HTTPSRR) ||                                     \
    defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)
  if (!HasNamedFeature(info, "HTTPSRR")) {
    std::fputs("libcurl was built without HTTPS RR support\n", stderr);
    return 1;
  }
#endif
#if defined(CURL_FUZZER_EXPECT_ECH) ||                                         \
    defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)
  if (!HasNamedFeature(info, "ECH")) {
    std::fputs("libcurl was built without ECH support\n", stderr);
    return 1;
  }
#endif
#if defined(CURL_FUZZER_EXPECT_HTTPSIG) ||                                     \
    defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)
  if (!HasNamedFeature(info, "HTTPSIG")) {
    std::fputs("libcurl was built without HTTP Message Signatures support\n",
               stderr);
    return 1;
  }
#endif
  bool has_telnet = false;
  bool has_ftp = false;
  bool has_tftp = false;
  bool has_smb = false;
  if (info->protocols) {
    for (const char *const *protocol = info->protocols; *protocol; ++protocol) {
      if (std::strcmp(*protocol, "telnet") == 0) {
        has_telnet = true;
      } else if (std::strcmp(*protocol, "ftp") == 0) {
        has_ftp = true;
      } else if (std::strcmp(*protocol, "tftp") == 0) {
        has_tftp = true;
      } else if (std::strcmp(*protocol, "smb") == 0 ||
                 std::strcmp(*protocol, "smbs") == 0) {
        has_smb = true;
      }
    }
  }
  // curl exposes no per-protocol feature bits for these handlers. Its
  // advertised list is therefore the runtime guard against a future default
  // change silently turning a dedicated fuzzer into a no-op error path.
  if (!has_telnet) {
    std::fputs("libcurl was built without TELNET support\n", stderr);
    return 1;
  }
  if (!has_ftp) {
    std::fputs("libcurl was built without FTP support\n", stderr);
    return 1;
  }
  if (!has_tftp) {
    std::fputs("libcurl was built without TFTP support\n", stderr);
    return 1;
  }
  if (has_smb) {
    std::fputs("libcurl was built with deprecated SMB support\n", stderr);
    return 1;
  }
  return 0;
}
