/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Common ownership types for independently cleaned-up curl handles.

#ifndef PROTO_FUZZER_CURL_RAII_H_
#define PROTO_FUZZER_CURL_RAII_H_

#include <curl/curl.h>

#include <memory>

namespace proto_fuzzer {

/// @brief Destroy an independently owned easy handle.
struct CurlEasyDeleter {
  /// Release an easy handle through libcurl's matching cleanup API.
  /// @param easy Handle owned by the invoking smart pointer.
  void operator()(CURL* easy) const noexcept {
    if (easy != nullptr) {
      curl_easy_cleanup(easy);
    }
  }
};

/// @brief Destroy an independently owned multi handle.
struct CurlMultiDeleter {
  /// Release a multi handle through libcurl's matching cleanup API.
  /// @param multi Handle owned by the invoking smart pointer.
  void operator()(CURLM* multi) const noexcept {
    if (multi != nullptr) {
      (void)curl_multi_cleanup(multi);
    }
  }
};

/// @brief Destroy a caller-owned curl_slist.
struct CurlSlistDeleter {
  /// Release a complete caller-owned linked list.
  /// @param list List owned by the invoking smart pointer.
  void operator()(curl_slist* list) const noexcept { curl_slist_free_all(list); }
};

/// Unique ownership of a CURL easy handle.
using CurlEasyPtr = std::unique_ptr<CURL, CurlEasyDeleter>;
/// Unique ownership of a CURL multi handle.
using CurlMultiPtr = std::unique_ptr<CURLM, CurlMultiDeleter>;
/// Unique ownership of a caller-owned curl_slist.
using CurlSlistPtr = std::unique_ptr<curl_slist, CurlSlistDeleter>;

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_CURL_RAII_H_
