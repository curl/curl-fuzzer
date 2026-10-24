/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>

#include "proto_fuzzer/resolver_cancel_gate.h"

namespace {

void Expect(bool condition, const char *message) {
  if (!condition) {
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
  }
}

int CountResolverStart(void * /*resolver_state*/, void * /*reserved*/,
                       void *client_data) {
  ++*static_cast<int *>(client_data);
  return 0;
}

} // namespace

int main() {
  bool ok = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
  CURL *easy = curl_easy_init();
  CURLM *multi = curl_multi_init();
  int duplicate_resolver_starts = 0;
  ok = ok && easy != nullptr && multi != nullptr;
  if (ok) {
    ok = curl_easy_setopt(easy, CURLOPT_URL,
                          "http://resolver-queued-cancel.test/queued-cancel") ==
             CURLE_OK &&
         curl_easy_setopt(easy, CURLOPT_PROXY, "") == CURLE_OK &&
         curl_easy_setopt(easy, CURLOPT_IPRESOLVE,
                          static_cast<long>(CURL_IPRESOLVE_WHATEVER)) ==
             CURLE_OK &&
         curl_multi_setopt(multi, CURLMOPT_RESOLVE_THREADS_MAX, 1L) == CURLM_OK;
  }

  CURL *duplicate = ok ? curl_easy_duphandle(easy) : nullptr;
  ok = ok && duplicate != nullptr &&
       curl_easy_setopt(
           duplicate, CURLOPT_URL,
           "http://resolver-queued-cancel.test:81/queued-cancel-duplicate") ==
           CURLE_OK &&
       curl_easy_setopt(duplicate, CURLOPT_FRESH_CONNECT, 1L) == CURLE_OK &&
       curl_easy_setopt(duplicate, CURLOPT_RESOLVER_START_FUNCTION,
                        &CountResolverStart) == CURLE_OK &&
       curl_easy_setopt(duplicate, CURLOPT_RESOLVER_START_DATA,
                        &duplicate_resolver_starts) == CURLE_OK;

  CURLMcode add_result = CURLM_BAD_HANDLE;
  CURLMcode add_duplicate_result = CURLM_BAD_HANDLE;
  CURLMcode perform_result = CURLM_BAD_HANDLE;
  CURLMcode remove_result = CURLM_BAD_HANDLE;
  CURLMcode remove_duplicate_result = CURLM_BAD_HANDLE;
  int still_running = 0;
  bool lookup_started = false;
  bool duplicate_resolver_queued = false;
  if (ok) {
    add_result = curl_multi_add_handle(multi, easy);
  }
  if (add_result == CURLM_OK) {
    proto_fuzzer::ScopedResolverCancelGate gate;
    perform_result = curl_multi_perform(multi, &still_running);
    if (perform_result == CURLM_OK && still_running > 0) {
      lookup_started = proto_fuzzer::WaitForResolverCancelLookup(
          std::chrono::milliseconds(5000));
    }
    // The signal comes from the worker-owned Q1. With max_threads=1 and Q1
    // blocked inside getaddrinfo, the worker cannot dequeue original Q2.
    if (lookup_started) {
      add_duplicate_result = curl_multi_add_handle(multi, duplicate);
    }
    if (add_duplicate_result == CURLM_OK) {
      perform_result = curl_multi_perform(multi, &still_running);
    }
    // Resolver-start runs before query submission. The perform return plus a
    // live duplicate proves submission finished while Q1 still held the only
    // worker, so duplicate resolver work remains in the send queue.
    duplicate_resolver_queued = perform_result == CURLM_OK &&
                                still_running == 2 &&
                                duplicate_resolver_starts > 0;
    // Detach the duplicate on every post-add path. The coverage assertion
    // below still requires that its resolver work was proved queue-owned.
    if (add_duplicate_result == CURLM_OK) {
      remove_duplicate_result = curl_multi_remove_handle(multi, duplicate);
    }
  }

  if (add_result == CURLM_OK) {
    remove_result = curl_multi_remove_handle(multi, easy);
  }

  // The duplicate was cancelled while its work was provably queued. The
  // scoped gate then released the in-flight lookup before blocker removal or
  // multi cleanup could join the resolver pool.
  const CURLMcode cleanup_result =
      multi != nullptr ? curl_multi_cleanup(multi) : CURLM_BAD_HANDLE;
  if (duplicate != nullptr) {
    curl_easy_cleanup(duplicate);
  }
  if (easy != nullptr) {
    curl_easy_cleanup(easy);
  }
  curl_global_cleanup();

  ok = ok && add_result == CURLM_OK && add_duplicate_result == CURLM_OK &&
       perform_result == CURLM_OK && lookup_started &&
       duplicate_resolver_queued && remove_duplicate_result == CURLM_OK &&
       remove_result == CURLM_OK && cleanup_result == CURLM_OK;
  Expect(ok, "queued resolver cancellation lifecycle failed");
  return 0;
}
