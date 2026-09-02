/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "legacy_protocol_allowlist.h"

#include <curl/curl.h>

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

bool ContainsToken(const std::string &list, const std::string &token) {
  std::string::size_type start = 0;
  while (start <= list.size()) {
    const std::string::size_type end = list.find(',', start);
    if (list.compare(start, end - start, token) == 0) {
      return true;
    }
    if (end == std::string::npos) {
      return false;
    }
    start = end + 1;
  }
  return false;
}

/**
 * Ensures missing dependency backends remove only their own protocols instead
 * of making libcurl reject the generic fuzzer's complete allow-list.
 */
void TestBuildIntersectsSupportedProtocols() {
  const char *const supported[] = {"telnet", "http", "made-up", "sftp",
                                   "rtmps",  "smb",  "smbs",    "wss",
                                   nullptr};
  const std::string allowed = legacy_protocol_allowlist::Build(supported);

  Expect(allowed == "http,rtmps,sftp,wss",
         "allow-list was not the ordered supported intersection");
  Expect(!ContainsToken(allowed, "telnet"),
         "generic legacy allow-list enabled TELNET");
  Expect(!ContainsToken(allowed, "made-up"),
         "generic legacy allow-list enabled an unreviewed protocol");
  Expect(!ContainsToken(allowed, "smb"),
         "generic legacy allow-list enabled SMB");
  Expect(!ContainsToken(allowed, "smbs"),
         "generic legacy allow-list enabled SMBS");
}

/**
 * A missing version-info list should fail closed rather than accidentally
 * expanding the generic fuzzer to libcurl's default protocol set.
 */
void TestBuildFailsClosedWithoutVersionInfo() {
  Expect(legacy_protocol_allowlist::Build(nullptr).empty(),
         "missing protocol metadata did not produce an empty allow-list");
}

/**
 * Exercises the actual linked libcurl because the original regression was an
 * apparently reasonable string that CURLOPT_PROTOCOLS_STR rejected in full.
 */
void TestCurrentCurlAcceptsAllowList() {
  const std::string &allowed = legacy_protocol_allowlist::ForCurrentCurl();
  const std::string &cached = legacy_protocol_allowlist::ForCurrentCurl();
  Expect(&allowed == &cached, "current libcurl allow-list was rebuilt");
  Expect(!allowed.empty(), "current libcurl produced an empty allow-list");
  Expect(!ContainsToken(allowed, "telnet"),
         "current libcurl allow-list enabled TELNET");

  CURL *const easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed");
  const CURLcode rc =
      curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, allowed.c_str());
  curl_easy_cleanup(easy);
  Expect(rc == CURLE_OK,
         "current libcurl rejected the generated protocol allow-list");
}

}  // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    Fail("curl_global_init failed");
  }

  TestBuildIntersectsSupportedProtocols();
  TestBuildFailsClosedWithoutVersionInfo();
  TestCurrentCurlAcceptsAllowList();

  curl_global_cleanup();
  return 0;
}
