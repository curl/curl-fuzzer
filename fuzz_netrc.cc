/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

// Direct fuzz harness for curl's netrc file loader and lexer. The public
// CURLOPT_NETRC path is useful for end-to-end protocol coverage, but it makes
// mutations pay for URL setup and a connection before they can reach quoted
// tokens, macdef skipping, or entry selection. This target calls curl's
// internal file-backed scanner directly while still presenting it with a real
// FILE path through /proc/self/fd.

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "proto_fuzzer/bounded_anonymous_input_file.h"

extern "C" {
#include "creds.h"
#include "netrc.h"
} // extern "C"

namespace {

constexpr std::size_t kMaxNetrcBytes = 128 * 1024;

struct CurlBootstrap {
  CurlBootstrap() { (void)curl_global_init(CURL_GLOBAL_ALL); }
  ~CurlBootstrap() { curl_global_cleanup(); }
};

CurlBootstrap kCurlBootstrap;
proto_fuzzer::BoundedAnonymousInputFile kInputFile(kMaxNetrcBytes + 1);

/// Preserve every fuzz byte while ensuring curl's filtered file buffer is
/// non-null. curl currently drops comment lines before calling its lexer and
/// passes nullptr when that leaves an empty file; one leading newline is
/// parser-neutral but gives the lexer a valid empty string in that case.
/// @param data Fuzz-controlled NETRC bytes after the harness selector.
/// @param size Number of fuzz-controlled bytes to retain.
/// @return true when the complete prefixed input is ready to scan.
bool WriteNetrcInput(const std::uint8_t *data, std::size_t size) {
  if (size > kMaxNetrcBytes) {
    return false;
  }

  std::string file_contents(1, '\n');
  if (size != 0) {
    file_contents.append(reinterpret_cast<const char *>(data), size);
  }
  return kInputFile.Write(
      reinterpret_cast<const std::uint8_t *>(file_contents.data()),
      file_contents.size());
}

void ProbeErrorStringsOnce() {
  static const bool probed = [] {
    for (int value = 0; value < static_cast<int>(NETRC_LAST); ++value) {
      (void)Curl_netrc_strerror(static_cast<NETRCcode>(value));
    }
    return true;
  }();
  (void)probed;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  if (size == 0 || !WriteNetrcInput(data + 1, size - 1) ||
      kInputFile.path() == nullptr) {
    return 0;
  }

  ProbeErrorStringsOnce();

  CURL *easy = curl_easy_init();
  if (easy == nullptr) {
    return 0;
  }

  // Use curl's real private type so layout/API changes fail at compile time.
  struct store_netrc store;
  struct Curl_creds *creds = nullptr;
  Curl_netrc_init(&store);

  const char *hostname = (data[0] & 1U) != 0 ? "other.test" : "fuzz.test";
  const char *user = (data[0] & 2U) != 0 ? "fuzz-user" : nullptr;
  const NETRCcode result =
      Curl_netrc_scan(reinterpret_cast<struct Curl_easy *>(easy), &store,
                      hostname, user, kInputFile.path(), &creds);
  (void)Curl_netrc_strerror(result);

  Curl_creds_unlink(&creds);
  Curl_netrc_cleanup(&store);
  curl_easy_cleanup(easy);
  return 0;
}
