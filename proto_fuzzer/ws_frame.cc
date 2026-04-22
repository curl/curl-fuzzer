/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of SerializeWebSocketFrame.

#include "proto_fuzzer/ws_frame.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace proto_fuzzer {

namespace {

// RFC 6455 §5.2 length-form selectors.
constexpr std::uint32_t kLenFormAuto = 0;
constexpr std::uint32_t kLenForm7 = 1;
constexpr std::uint32_t kLenForm16 = 2;
constexpr std::uint32_t kLenForm64 = 3;

/// Pick a length encoding for 'payload_len' honouring an explicit override.
/// When 'form' names a shorter encoding than the payload actually needs, we
/// still emit the shorter form and let the decoder reject it — the point is
/// to exercise the error path.
std::uint32_t ResolveLengthForm(std::uint32_t form, std::size_t payload_len) {
  if (form == kLenForm7 || form == kLenForm16 || form == kLenForm64) {
    return form;
  }
  if (payload_len < 126) {
    return kLenForm7;
  }
  if (payload_len <= 0xFFFF) {
    return kLenForm16;
  }
  return kLenForm64;
}

/// Append 'value' as big-endian bytes of width 'width' to 'out'.
void AppendBigEndian(std::string* out, std::uint64_t value, std::size_t width) {
  for (std::size_t i = 0; i < width; ++i) {
    std::size_t shift = (width - 1 - i) * 8;
    out->push_back(static_cast<char>((value >> shift) & 0xFF));
  }
}

}  // namespace

/// Serialise a proto WebSocketFrame into RFC 6455 wire bytes. No validation
/// is performed — invalid combinations (reserved bits set, oversized
/// length_form for a tiny payload, opcode > 15) round-trip to the decoder
/// unchanged, which is the point.
/// @param frame The WebSocketFrame proto message to render.
/// @return The serialised byte string, ready to push onto the mock socket.
std::string SerializeWebSocketFrame(const curl::fuzzer::proto::WebSocketFrame& frame) {
  std::string out;
  const std::string& payload = frame.payload();
  const std::size_t payload_len = payload.size();

  // Byte 0: FIN | RSV1 | RSV2 | RSV3 | opcode(4 bits).
  std::uint8_t byte0 = 0;
  if (frame.fin()) byte0 |= 0x80;
  if (frame.rsv1()) byte0 |= 0x40;
  if (frame.rsv2()) byte0 |= 0x20;
  if (frame.rsv3()) byte0 |= 0x10;
  byte0 |= static_cast<std::uint8_t>(frame.opcode() & 0x0F);
  out.push_back(static_cast<char>(byte0));

  // Byte 1: MASK bit | payload-length indicator (7 bits).
  const std::uint32_t length_form = ResolveLengthForm(frame.length_form(), payload_len);
  std::uint8_t byte1 = frame.masked() ? 0x80 : 0x00;
  switch (length_form) {
    case kLenForm7:
      // Clamp the 7-bit length to the payload's actual size. If the payload
      // is > 125 bytes and the caller forced 7-bit form, low 7 bits of size
      // are what the decoder sees — which is exactly the malformed-frame
      // path we want to reach.
      byte1 |= static_cast<std::uint8_t>(payload_len & 0x7F);
      out.push_back(static_cast<char>(byte1));
      break;
    case kLenForm16:
      byte1 |= 126;
      out.push_back(static_cast<char>(byte1));
      AppendBigEndian(&out, static_cast<std::uint64_t>(payload_len & 0xFFFF), 2);
      break;
    case kLenForm64:
    default:
      byte1 |= 127;
      out.push_back(static_cast<char>(byte1));
      AppendBigEndian(&out, static_cast<std::uint64_t>(payload_len), 8);
      break;
  }

  // Masking key (4 bytes) and XORed payload. Client-to-server frames must be
  // masked per spec; server-to-client frames must NOT — but we emit whatever
  // the scenario says, so the decoder's "masked server frame" error path is
  // reachable.
  if (frame.masked()) {
    const std::uint32_t key = frame.mask_key();
    std::uint8_t key_bytes[4] = {
        static_cast<std::uint8_t>((key >> 24) & 0xFF),
        static_cast<std::uint8_t>((key >> 16) & 0xFF),
        static_cast<std::uint8_t>((key >> 8) & 0xFF),
        static_cast<std::uint8_t>(key & 0xFF),
    };
    for (unsigned char b : key_bytes) {
      out.push_back(static_cast<char>(b));
    }
    out.reserve(out.size() + payload_len);
    for (std::size_t i = 0; i < payload_len; ++i) {
      out.push_back(static_cast<char>(static_cast<std::uint8_t>(payload[i]) ^ key_bytes[i & 0x3]));
    }
  } else {
    out.append(payload);
  }

  return out;
}

}  // namespace proto_fuzzer
