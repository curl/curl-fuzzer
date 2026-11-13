/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Runs one TLS session import through a fresh client cache.

#ifndef PROTO_FUZZER_TLS_SESSION_REPLAY_H_
#define PROTO_FUZZER_TLS_SESSION_REPLAY_H_

#include <curl/curl.h>

#include <string>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

class TlsMockServer;

/// Public API results from one bounded fresh-cache replay.
struct TlsSessionReplayResult {
  /// Result from importing the archived session into the fresh cache.
  CURLcode import_result = CURLE_FAILED_INIT;
  /// Result from the transfer that used the fresh cache.
  CURLcode transfer_result = CURLE_FAILED_INIT;
};

TlsSessionReplayResult ReplayTlsSession(const curl::fuzzer::proto::Scenario& scenario, const std::string& url,
                                        TlsMockServer* server);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TLS_SESSION_REPLAY_H_
