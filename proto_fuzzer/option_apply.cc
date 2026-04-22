/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the option-translation helpers declared in
///        option_apply.h.

#include "proto_fuzzer/option_apply.h"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace proto_fuzzer {

/// How a SetOption oneof should be decoded before calling curl_easy_setopt.
enum class OptionValueKind {
  kString,  ///< string_value → const char* option.
  kUint,    ///< uint_value → long or curl_off_t option.
  kBool     ///< bool_value → 0/1 long option.
};

/// One row in the build-time-generated option manifest: binds a proto enum
/// value to the matching curl_easy_setopt option id and value kind.
struct OptionDescriptor {
  /// Proto enum identifier for this option.
  curl::fuzzer::proto::CurlOptionId id;
  /// How the oneof value should be decoded.
  OptionValueKind kind;
  /// Human-readable option name (e.g. "CURLOPT_URL") for diagnostics.
  const char* name;
  /// The native CURLoption to pass to curl_easy_setopt.
  CURLoption curlopt;
};

// Pulls in kOptionManifest[] and kOptionManifestSize.
#include "curl_fuzzer_option_manifest.inc"

namespace {

constexpr char kProtocolsAllowed[] = "http";
constexpr char kConnectToOverride[] = "::127.0.1.127:";
constexpr char kDevNull[] = "/dev/null";
constexpr char kVerboseEnvVar[] = "FUZZ_VERBOSE";
constexpr long kConnectTimeoutMs = 200;
constexpr long kTimeoutMs = 2000;
constexpr long kMaxRecvSpeed = 16 * 1024;

size_t SilentWriteCallback(void* /*contents*/, size_t size, size_t nmemb, void* /*userdata*/) { return size * nmemb; }

const OptionDescriptor* Lookup(curl::fuzzer::proto::CurlOptionId id) {
  for (std::size_t i = 0; i < kOptionManifestSize; ++i) {
    if (kOptionManifest[i].id == id) {
      return &kOptionManifest[i];
    }
  }
  return nullptr;
}

}  // namespace

/// Apply the fixed baseline options the harness always wants: output sinks,
/// protocol restrictions, DNS overrides, timeouts. Call before applying any
/// scenario options.
/// @param easy The curl easy handle to configure.
/// @return the curl_slist owned by the caller (for CURLOPT_CONNECT_TO), which
///         must be freed with curl_slist_free_all after curl_easy_cleanup.
struct curl_slist* ApplyBaselineOptions(CURL* easy) {
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &SilentWriteCallback);
  curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, &SilentWriteCallback);

  // Confine the easy handle to plain HTTP; refuse redirects to any other
  // scheme. CURLOPT_PROTOCOLS_STR arrived in 7.85.0.
  curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, kProtocolsAllowed);
  curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, kProtocolsAllowed);

  // Force every name lookup to the fuzzer's in-process mock peer. The caller
  // owns the returned slist and must free it after curl_easy_cleanup.
  struct curl_slist* connect_to = curl_slist_append(nullptr, kConnectToOverride);
  curl_easy_setopt(easy, CURLOPT_CONNECT_TO, connect_to);

  // Short bounds: fuzzing should never sit waiting on real I/O.
  curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, kConnectTimeoutMs);
  curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, kTimeoutMs);
  curl_easy_setopt(easy, CURLOPT_MAX_RECV_SPEED_LARGE, static_cast<curl_off_t>(kMaxRecvSpeed));

  // Prevent scenarios from leaking state onto the filesystem.
  curl_easy_setopt(easy, CURLOPT_COOKIEJAR, kDevNull);
  curl_easy_setopt(easy, CURLOPT_ALTSVC, kDevNull);
  curl_easy_setopt(easy, CURLOPT_HSTS, kDevNull);
  curl_easy_setopt(easy, CURLOPT_NETRC_FILE, kDevNull);

  // Match the legacy TLV fuzzer: FUZZ_VERBOSE in the environment flips curl's
  // own verbose logging on. Useful when reproducing a crashing corpus entry.
  if (std::getenv(kVerboseEnvVar) != nullptr) {
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  }
  return connect_to;
}

/// Apply one SetOption to the easy handle, copying any owned strings into
/// 'string_storage' so the pointer stays alive for the duration of
/// curl_easy_perform.
/// @param easy           The curl easy handle to configure.
/// @param option         The SetOption proto describing which option and
///                       value to set.
/// @param string_storage Backing store that the option's string value is
///                       copied into; must outlive curl_easy_perform.
/// @return CURLE_OK on success, an error code if the option is unsupported or
///         the setopt call itself failed.
CURLcode ApplySetOption(CURL* easy, const curl::fuzzer::proto::SetOption& option,
                        std::vector<std::string>* string_storage) {
  const OptionDescriptor* desc = Lookup(option.option_id());
  if (desc == nullptr) {
    return CURLE_UNKNOWN_OPTION;
  }

  switch (desc->kind) {
    // Store a copy of the string in string_storage and pass a pointer to the copy to curl_easy_setopt.
    case OptionValueKind::kString: {
      const std::string& src = option.string_value();
      string_storage->emplace_back(src.data(), src.size());
      const std::string& stored = string_storage->back();

      // Handling for POSTFIELDS to set the size.
      if (desc->curlopt == CURLOPT_POSTFIELDS) {
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(stored.size()));
      }

      return curl_easy_setopt(easy, desc->curlopt, stored.c_str());
    }

    // Decode the uint_value and pass it as either a long or a curl_off_t depending on the option.
    case OptionValueKind::kUint: {
      std::uint64_t raw = option.uint_value();
      // CURLOPTTYPE_OFF_T options start at 30000. Everything below takes a
      // long; everything at/above takes a curl_off_t.
      if (static_cast<int>(desc->curlopt) >= 30000) {
        return curl_easy_setopt(easy, desc->curlopt, static_cast<curl_off_t>(raw));
      }
      return curl_easy_setopt(easy, desc->curlopt, static_cast<long>(raw));
    }

    // Decode the bool_value and pass it as a long flag (0 or 1).
    case OptionValueKind::kBool: {
      long flag = option.bool_value() ? 1L : 0L;
      return curl_easy_setopt(easy, desc->curlopt, flag);
    }
  }
  return CURLE_UNKNOWN_OPTION;
}

}  // namespace proto_fuzzer
