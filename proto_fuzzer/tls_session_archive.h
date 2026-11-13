/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Owns one bounded session copied through curl's public TLS APIs.

#ifndef PROTO_FUZZER_TLS_SESSION_ARCHIVE_H_
#define PROTO_FUZZER_TLS_SESSION_ARCHIVE_H_

#include <curl/curl.h>

#include <cstddef>
#include <string>
#include <vector>

namespace proto_fuzzer {

/// Own every value from one curl_easy_ssls_export callback. Curl owns the
/// callback pointers, so the archive copies them before the callback returns.
class TlsSessionArchive {
 public:
  /// Create an empty archive.
  TlsSessionArchive() = default;

  /// The archive has unique ownership of its copied session data.
  TlsSessionArchive(const TlsSessionArchive&) = delete;
  /// The archive has unique ownership of its copied session data.
  TlsSessionArchive& operator=(const TlsSessionArchive&) = delete;
  /// Move all copied session data into a new archive.
  TlsSessionArchive(TlsSessionArchive&&) = default;
  /// Replace this archive with moved session data.
  /// @return this archive after the replacement.
  TlsSessionArchive& operator=(TlsSessionArchive&&) = default;

  CURLcode CaptureFrom(CURL* easy);

  CURLcode ImportBySaltedHash(CURL* easy) const;
  CURLcode ImportBySessionKey(CURL* easy) const;
  CURLcode ImportMalformedSaltedHash(CURL* easy) const;

  bool empty() const;
  const std::string& session_key() const;
  const std::vector<unsigned char>& salted_hash() const;
  const std::vector<unsigned char>& session_data() const;
  curl_off_t valid_until() const;
  int ietf_tls_id() const;
  const std::string& alpn() const;
  std::size_t early_data_max() const;

 private:
  static CURLcode Capture(CURL* easy, void* user_data, const char* session_key, const unsigned char* salted_hash,
                          std::size_t salted_hash_size, const unsigned char* session_data,
                          std::size_t session_data_size, curl_off_t valid_until, int ietf_tls_id, const char* alpn,
                          std::size_t early_data_max);

  std::string session_key_;
  std::vector<unsigned char> salted_hash_;
  std::vector<unsigned char> session_data_;
  curl_off_t valid_until_ = 0;
  int ietf_tls_id_ = 0;
  std::string alpn_;
  std::size_t early_data_max_ = 0;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TLS_SESSION_ARCHIVE_H_
