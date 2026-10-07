/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Translates Scenario SetOption messages into curl_easy_setopt calls,
///        plus the fixed baseline setopts the harness always applies.

#ifndef PROTO_FUZZER_OPTION_APPLY_H_
#define PROTO_FUZZER_OPTION_APPLY_H_

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/option_model.h"

namespace proto_fuzzer {

struct curl_slist* ApplyBaselineOptions(CURL* easy, curl::fuzzer::proto::Scheme scheme, bool trace_ids = false);

CURLcode ApplySetOption(CURL* easy, const curl::fuzzer::proto::SetOption& option);

std::size_t RuntimeOptionCount(const curl::fuzzer::proto::Scenario& scenario);

std::size_t ApplyScenarioOptions(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_OPTION_APPLY_H_
