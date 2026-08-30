/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdio>

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
  return 0;
}
