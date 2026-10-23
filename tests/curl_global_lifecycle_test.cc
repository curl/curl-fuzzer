/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdio>
#include <cstdlib>

#include "proto_fuzzer/curl_global_lifecycle.h"

namespace {

std::size_t cleanup_calls = 0;

void Fail(const char *message) {
  std::fputs(message, stderr);
  std::fputc('\n', stderr);
  std::exit(EXIT_FAILURE);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

void CountCleanup() {
  ++cleanup_calls;
  curl_global_cleanup();
}

struct ExitVerifier {
  ~ExitVerifier() {
    if (cleanup_calls != 1) {
      std::fputs("curl cleanup did not release the global initialization at "
                 "process exit\n",
                 stderr);
      std::_Exit(EXIT_FAILURE);
    }
  }
};

// Construction order makes lifecycle run its destructor before exit_verifier,
// so the verifier observes cleanup performed by the static process lifecycle.
ExitVerifier exit_verifier;
proto_fuzzer::CurlGlobalLifecycle lifecycle(&CountCleanup);

} // namespace

int main() {
  Expect(lifecycle.initialized(), "curl global initialization failed");
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr,
         "initialized runtime could not allocate an easy handle");
  curl_easy_cleanup(easy);
  Expect(cleanup_calls == 0, "curl cleanup ran before process exit");
  return EXIT_SUCCESS;
}
