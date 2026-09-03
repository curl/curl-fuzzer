/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdio>
#include <cstring>

#if (defined(CURL_FUZZER_EXPECT_OPENSSL) || \
     defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)) && \
    defined(CURL_FUZZER_EXPECT_GNUTLS)
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

#if defined(CURL_FUZZER_EXPECT_OPENSSL) || \
    defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES) || \
    defined(CURL_FUZZER_EXPECT_GNUTLS)
bool HasPrefix(const char *value, const char *expected) {
  return value && std::strncmp(value, expected, std::strlen(expected)) == 0;
}
#endif

}  // namespace

int main() {
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
  if (HasNamedFeature(info, "NTLM")) {
    std::fputs("libcurl was built with deprecated NTLM support\n", stderr);
    return 1;
  }
#if defined(CURL_FUZZER_EXPECT_OPENSSL) || \
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
#if defined(CURL_FUZZER_EXPECT_HTTPSRR) || \
    defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)
  if (!HasNamedFeature(info, "HTTPSRR")) {
    std::fputs("libcurl was built without HTTPS RR support\n", stderr);
    return 1;
  }
#endif
#if defined(CURL_FUZZER_EXPECT_ECH) || \
    defined(CURL_FUZZER_EXPECT_OPENSSL_EXPERIMENTAL_FEATURES)
  if (!HasNamedFeature(info, "ECH")) {
    std::fputs("libcurl was built without ECH support\n", stderr);
    return 1;
  }
#endif
#if defined(CURL_FUZZER_EXPECT_HTTPSIG) || \
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
