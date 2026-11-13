/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded ownership for public TLS session export and import.

#include "proto_fuzzer/tls_session_archive.h"

#include <cstring>

namespace proto_fuzzer {
namespace {

constexpr std::size_t kMaxSessionKeySize = 4 * 1024;
constexpr std::size_t kMaxSessionHashSize = 128;
constexpr std::size_t kMaxSessionDataSize = 16 * 1024;
constexpr std::size_t kMaxAlpnSize = 255;

}  // namespace

/// Copy the first bounded session offered by curl. Later callback entries are
/// ignored so one fuzz input cannot retain work in proportion to cache size.
CURLcode TlsSessionArchive::Capture(CURL* /*easy*/, void* user_data, const char* session_key,
                                    const unsigned char* salted_hash, std::size_t salted_hash_size,
                                    const unsigned char* session_data, std::size_t session_data_size,
                                    curl_off_t valid_until, int ietf_tls_id, const char* alpn,
                                    std::size_t early_data_max) {
  auto* archive = static_cast<TlsSessionArchive*>(user_data);
  if (archive == nullptr || !archive->empty() || salted_hash == nullptr || salted_hash_size == 0 ||
      salted_hash_size > kMaxSessionHashSize || session_data == nullptr || session_data_size == 0 ||
      session_data_size > kMaxSessionDataSize) {
    return CURLE_OK;
  }

  const std::size_t session_key_size = session_key == nullptr ? 0 : strnlen(session_key, kMaxSessionKeySize + 1);
  const std::size_t alpn_size = alpn == nullptr ? 0 : strnlen(alpn, kMaxAlpnSize + 1);
  if (session_key_size <= kMaxSessionKeySize && session_key != nullptr) {
    archive->session_key_.assign(session_key, session_key_size);
  }

  archive->salted_hash_.assign(salted_hash, salted_hash + salted_hash_size);
  archive->session_data_.assign(session_data, session_data + session_data_size);
  archive->valid_until_ = valid_until;
  archive->ietf_tls_id_ = ietf_tls_id;
  if (alpn_size <= kMaxAlpnSize && alpn != nullptr) {
    archive->alpn_.assign(alpn, alpn_size);
  }
  archive->early_data_max_ = early_data_max;
  return CURLE_OK;
}

/// Copy the first bounded session from an easy handle cache.
/// @param easy Easy handle whose cache curl exports.
/// @return The public export result.
CURLcode TlsSessionArchive::CaptureFrom(CURL* easy) {
  return easy == nullptr ? CURLE_BAD_FUNCTION_ARGUMENT : curl_easy_ssls_export(easy, &TlsSessionArchive::Capture, this);
}

/// Import the session without its clear peer key.
/// @param easy Easy handle whose cache receives the session.
/// @return The public import result.
CURLcode TlsSessionArchive::ImportBySaltedHash(CURL* easy) const {
  if (easy == nullptr || empty() || salted_hash_.empty()) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return curl_easy_ssls_import(easy, nullptr, salted_hash_.data(), salted_hash_.size(), session_data_.data(),
                               session_data_.size());
}

/// Import the session through the clear peer key returned by curl.
/// @param easy Easy handle whose cache receives the session.
/// @return The public import result.
CURLcode TlsSessionArchive::ImportBySessionKey(CURL* easy) const {
  if (easy == nullptr || empty() || session_key_.empty()) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return curl_easy_ssls_import(easy, session_key_.c_str(), nullptr, 0, session_data_.data(), session_data_.size());
}

/// Truncate the salted hash by one byte to cover deterministic rejection.
/// @param easy Easy handle whose cache receives the malformed entry.
/// @return The public import result.
CURLcode TlsSessionArchive::ImportMalformedSaltedHash(CURL* easy) const {
  if (easy == nullptr || empty() || salted_hash_.empty()) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  return curl_easy_ssls_import(easy, nullptr, salted_hash_.data(), salted_hash_.size() - 1, session_data_.data(),
                               session_data_.size());
}

/// @return true when no session data was captured.
bool TlsSessionArchive::empty() const { return session_data_.empty(); }
/// @return the copied clear peer key, or an empty string.
const std::string& TlsSessionArchive::session_key() const { return session_key_; }
/// @return the copied salted peer hash.
const std::vector<unsigned char>& TlsSessionArchive::salted_hash() const { return salted_hash_; }
/// @return the copied serialized TLS session.
const std::vector<unsigned char>& TlsSessionArchive::session_data() const { return session_data_; }
/// @return the exported session expiry time.
curl_off_t TlsSessionArchive::valid_until() const { return valid_until_; }
/// @return the exported IETF TLS protocol identifier.
int TlsSessionArchive::ietf_tls_id() const { return ietf_tls_id_; }
/// @return the copied ALPN protocol name, or an empty string.
const std::string& TlsSessionArchive::alpn() const { return alpn_; }
/// @return the exported maximum early-data size.
std::size_t TlsSessionArchive::early_data_max() const { return early_data_max_; }

}  // namespace proto_fuzzer
