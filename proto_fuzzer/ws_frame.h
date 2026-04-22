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

// Render 'frame' into raw RFC 6455 wire bytes. No validation: invalid
// combinations (reserved bits set, opcode > 15, oversized length_form for a
// tiny payload) round-trip into the byte stream unchanged so the decoder sees
// them.
std::string SerializeWebSocketFrame(const curl::fuzzer::proto::WebSocketFrame& frame);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_WS_FRAME_H_
