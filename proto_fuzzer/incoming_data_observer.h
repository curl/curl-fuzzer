/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Optional observer for application bytes consumed by mock peers.

#ifndef PROTO_FUZZER_INCOMING_DATA_OBSERVER_H_
#define PROTO_FUZZER_INCOMING_DATA_OBSERVER_H_

#include <cstddef>

namespace proto_fuzzer {

/// Receives bytes after any transport decoding. Protocol peers use this to
/// track client frame state without changing how MockConnection drains data.
class IncomingDataObserver {
 public:
  virtual ~IncomingDataObserver() = default;

  /// Observe one contiguous application-data fragment.
  /// @param data First byte of the fragment.
  /// @param size Number of bytes available at `data`.
  virtual void ObserveIncomingData(const unsigned char* data, std::size_t size) = 0;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_INCOMING_DATA_OBSERVER_H_
