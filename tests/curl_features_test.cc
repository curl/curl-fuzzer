/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdio>
#include <cstring>

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
  bool has_telnet = false;
  bool has_ftp = false;
  bool has_tftp = false;
  if (info->protocols) {
    for (const char *const *protocol = info->protocols; *protocol; ++protocol) {
      if (std::strcmp(*protocol, "telnet") == 0) {
        has_telnet = true;
      } else if (std::strcmp(*protocol, "ftp") == 0) {
        has_ftp = true;
      } else if (std::strcmp(*protocol, "tftp") == 0) {
        has_tftp = true;
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
  return 0;
}
