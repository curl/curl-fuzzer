/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared TELNET response normalization.

#ifndef PROTO_FUZZER_TELNET_SCENARIO_H_
#define PROTO_FUZZER_TELNET_SCENARIO_H_

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

/// Retain the response prefix that TelnetMockServer can preload safely.
///
/// TELNET runs synchronously inside curl_multi_perform(), so the harness
/// cannot deliver later fragments or drain an arbitrary number of replies
/// between parser transitions. This function applies both the byte budget and
/// the stricter IAC budget shared by the LPM postprocessor and runtime. Once a
/// fragment is truncated, every later fragment is removed because it can no
/// longer affect curl.
/// @param connection Response script to normalize in place.
void BoundTelnetResponse(curl::fuzzer::proto::Connection* connection);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TELNET_SCENARIO_H_
