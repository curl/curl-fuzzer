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

void BoundTelnetResponse(curl::fuzzer::proto::Connection* connection);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TELNET_SCENARIO_H_
