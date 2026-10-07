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
  explicit BoundedAnonymousInputFile(std::size_t max_bytes);

  ~BoundedAnonymousInputFile();

  BoundedAnonymousInputFile(const BoundedAnonymousInputFile&) = delete;
  BoundedAnonymousInputFile& operator=(const BoundedAnonymousInputFile&) = delete;

  bool Write(const std::uint8_t* data, std::size_t size);

  const char* path() const;

 private:
  bool EnsureOpen();

  std::size_t max_bytes_;  ///< Maximum content size accepted by Write.
  std::FILE* file_;        ///< Owned anonymous file, opened lazily.
  std::string path_;       ///< Stable `/proc/self/fd` path for `file_`.
  bool ready_;             ///< True only after the latest complete write.
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_BOUNDED_ANONYMOUS_INPUT_FILE_H_
