/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Minimal standalone SHA-1 + base64 for the WebSocket Sec-WebSocket-Accept
///        computation (RFC 6455 §4.2.2).  This removes the hard OpenSSL dependency
///        from the proto fuzzer — the only crypto it needs is a single SHA-1 hash
///        of a handshake nonce which has no security implications inside a fuzzer.

#ifndef PROTO_FUZZER_WS_ACCEPT_KEY_H_
#define PROTO_FUZZER_WS_ACCEPT_KEY_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace proto_fuzzer {
namespace detail {

/// Minimal SHA-1 (FIPS 180-4) — not for security use; only for the WS accept key.
/// @param data Pointer to the input bytes to hash.
/// @param len  Number of input bytes.
/// @return 20-byte SHA-1 digest.
inline std::array<uint8_t, 20> Sha1(const uint8_t *data, std::size_t len) {
  // Initial hash values.
  uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

  // Pre-processing: build the padded message.
  uint64_t bit_len = static_cast<uint64_t>(len) * 8;
  // Number of bytes after original message: 1 (0x80) + padding + 8 (length).
  std::size_t padded_len = ((len + 8) / 64 + 1) * 64;
  // Use a small stack buffer for typical WebSocket key sizes (< 128 bytes).
  // Fall back to heap for anything larger.
  uint8_t stack_buf[128];
  uint8_t *msg;
  bool heap = padded_len > sizeof(stack_buf);
  if (heap) {
    msg = new uint8_t[padded_len]();
  } else {
    msg = stack_buf;
    std::memset(msg, 0, padded_len);
  }
  std::memcpy(msg, data, len);
  msg[len] = 0x80;
  // Append original length in bits as big-endian 64-bit.
  for (int i = 0; i < 8; ++i) {
    msg[padded_len - 1 - i] = static_cast<uint8_t>(bit_len >> (i * 8));
  }

  auto left_rotate = [](uint32_t v, unsigned n) -> uint32_t { return (v << n) | (v >> (32 - n)); };

  for (std::size_t offset = 0; offset < padded_len; offset += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
      w[i] = static_cast<uint32_t>(msg[offset + 4 * i]) << 24 | static_cast<uint32_t>(msg[offset + 4 * i + 1]) << 16 |
             static_cast<uint32_t>(msg[offset + 4 * i + 2]) << 8 | static_cast<uint32_t>(msg[offset + 4 * i + 3]);
    }
    for (int i = 16; i < 80; ++i) {
      w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      uint32_t temp = left_rotate(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = left_rotate(b, 30);
      b = a;
      a = temp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  if (heap) {
    delete[] msg;
  }

  std::array<uint8_t, 20> digest;
  auto store = [&](int idx, uint32_t val) {
    digest[idx * 4 + 0] = static_cast<uint8_t>(val >> 24);
    digest[idx * 4 + 1] = static_cast<uint8_t>(val >> 16);
    digest[idx * 4 + 2] = static_cast<uint8_t>(val >> 8);
    digest[idx * 4 + 3] = static_cast<uint8_t>(val);
  };
  store(0, h0);
  store(1, h1);
  store(2, h2);
  store(3, h3);
  store(4, h4);
  return digest;
}

/// Minimal base64 encoder.
/// @param data Pointer to the input bytes to encode.
/// @param len  Number of input bytes.
/// @return Base64-encoded string.
inline std::string Base64Encode(const uint8_t *data, std::size_t len) {
  static const char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(4 * ((len + 2) / 3));
  for (std::size_t i = 0; i < len; i += 3) {
    uint32_t n = static_cast<uint32_t>(data[i]) << 16;
    if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
    if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
    out.push_back(kTable[(n >> 18) & 0x3F]);
    out.push_back(kTable[(n >> 12) & 0x3F]);
    out.push_back((i + 1 < len) ? kTable[(n >> 6) & 0x3F] : '=');
    out.push_back((i + 2 < len) ? kTable[n & 0x3F] : '=');
  }
  return out;
}

}  // namespace detail

/// Compute the RFC 6455 Sec-WebSocket-Accept value for a given client key.
/// @param key The client-supplied Sec-WebSocket-Key header value.
/// @return The base64-encoded Sec-WebSocket-Accept string.
inline std::string ComputeWebSocketAcceptKey(const std::string &key) {
  static const char kGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::string combined = key + kGuid;
  auto digest = detail::Sha1(reinterpret_cast<const uint8_t *>(combined.data()), combined.size());
  return detail::Base64Encode(digest.data(), digest.size());
}

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_WS_ACCEPT_KEY_H_
