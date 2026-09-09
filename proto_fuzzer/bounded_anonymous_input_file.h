/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Owns bounded bytes exposed to filename-only APIs through procfs.

#ifndef PROTO_FUZZER_BOUNDED_ANONYMOUS_INPUT_FILE_H_
#define PROTO_FUZZER_BOUNDED_ANONYMOUS_INPUT_FILE_H_

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

namespace proto_fuzzer {

/// A reusable anonymous regular file whose descriptor remains reachable as a
/// pathname. libcurl and its TLS backends expose several parsers only through
/// filename options; /proc/self/fd lets fuzz-controlled bytes reach those APIs
/// without accepting a mutation-controlled filesystem path.
class BoundedAnonymousInputFile {
 public:
  /// Construct a lazy owner. No file is opened until Write succeeds far enough
  /// to need one, keeping ordinary fuzz iterations free of filesystem work.
  /// @param max_bytes Largest input this owner will expose.
  explicit BoundedAnonymousInputFile(std::size_t max_bytes);

  /// Close the anonymous file, invalidating the procfs pathname.
  ~BoundedAnonymousInputFile();

  BoundedAnonymousInputFile(const BoundedAnonymousInputFile&) = delete;
  BoundedAnonymousInputFile& operator=(const BoundedAnonymousInputFile&) = delete;

  /// Replace the complete file contents with one bounded byte string.
  /// A failed or oversized write invalidates path() so a previous iteration's
  /// bytes can never be consumed accidentally.
  /// @param data Bytes to write; may be null only when size is zero.
  /// @param size Number of bytes to expose.
  /// @return True when the complete input is ready for a filename API.
  bool Write(const std::uint8_t* data, std::size_t size);

  /// Return the stable procfs pathname after a successful Write.
  /// @return NUL-terminated path, or nullptr when no complete input is ready.
  const char* path() const;

 private:
  /// Lazily create the anonymous file and its stable procfs pathname.
  /// @return True when a usable file descriptor and pathname are available.
  bool EnsureOpen();

  std::size_t max_bytes_;  ///< Maximum content size accepted by Write.
  std::FILE* file_;        ///< Owned anonymous file, opened lazily.
  std::string path_;       ///< Stable `/proc/self/fd` path for `file_`.
  bool ready_;             ///< True only after the latest complete write.
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_BOUNDED_ANONYMOUS_INPUT_FILE_H_
