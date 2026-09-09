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

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "creds.h"
#include "netrc.h"
} // extern "C"

namespace {

constexpr std::size_t kMaxNetrcBytes = 128 * 1024;

class NetrcInputFile {
public:
  NetrcInputFile() : file_(std::tmpfile()) {
    if (file_ != nullptr) {
      path_ = "/proc/self/fd/" + std::to_string(fileno(file_));
    }
  }

  ~NetrcInputFile() {
    if (file_ != nullptr) {
      std::fclose(file_);
    }
  }

  NetrcInputFile(const NetrcInputFile &) = delete;
  NetrcInputFile &operator=(const NetrcInputFile &) = delete;

  bool Write(const std::uint8_t *data, std::size_t size) {
    if (file_ == nullptr || size > kMaxNetrcBytes) {
      return false;
    }
    const int fd = fileno(file_);
    if (ftruncate(fd, 0) != 0) {
      return false;
    }
    std::size_t offset = 0;
    while (offset < size) {
      const ssize_t written =
          pwrite(fd, data + offset, size - offset, static_cast<off_t>(offset));
      if (written < 0 && errno == EINTR) {
        continue;
      }
      if (written <= 0) {
        return false;
      }
      offset += static_cast<std::size_t>(written);
    }
    return true;
  }

  const char *path() const { return path_.empty() ? nullptr : path_.c_str(); }

private:
  std::FILE *file_;
  std::string path_;
};

struct CurlBootstrap {
  CurlBootstrap() { (void)curl_global_init(CURL_GLOBAL_ALL); }
  ~CurlBootstrap() { curl_global_cleanup(); }
};

CurlBootstrap kCurlBootstrap;
NetrcInputFile kInputFile;

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
  if (size == 0 || !kInputFile.Write(data + 1, size - 1) ||
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
