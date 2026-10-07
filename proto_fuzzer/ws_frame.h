/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Serialize a proto WebSocketFrame message into RFC 6455 wire bytes.

#ifndef PROTO_FUZZER_WS_FRAME_H_
#define PROTO_FUZZER_WS_FRAME_H_

#include <string>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

std::string SerializeWebSocketFrame(const curl::fuzzer::proto::WebSocketFrame& frame);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_WS_FRAME_H_
