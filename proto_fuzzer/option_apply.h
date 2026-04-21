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

#include <string>
#include <vector>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

struct curl_slist* ApplyBaselineOptions(CURL* easy);

CURLcode ApplySetOption(CURL* easy, const curl::fuzzer::proto::SetOption& option,
                        std::vector<std::string>* string_storage);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_OPTION_APPLY_H_
