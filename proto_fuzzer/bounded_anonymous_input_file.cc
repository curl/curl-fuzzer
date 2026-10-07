/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of bounded procfs-backed filename input.

#include "proto_fuzzer/bounded_anonymous_input_file.h"

#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <string>

namespace proto_fuzzer {

/// Construct a lazy owner. No file is opened until Write succeeds far enough
/// to need one, keeping ordinary fuzz iterations free of filesystem work.
/// @param max_bytes Largest input this owner will expose.
BoundedAnonymousInputFile::BoundedAnonymousInputFile(std::size_t max_bytes)
    : max_bytes_(max_bytes), file_(nullptr), ready_(false) {}

/// Close the anonymous file, invalidating the procfs pathname.
BoundedAnonymousInputFile::~BoundedAnonymousInputFile() {
  if (file_ != nullptr) {
    std::fclose(file_);
  }
}

/// Lazily create the anonymous file and its stable procfs pathname.
/// @return True when a usable file descriptor and pathname are available.
bool BoundedAnonymousInputFile::EnsureOpen() {
  if (file_ != nullptr) {
    return true;
  }

  file_ = std::tmpfile();
  if (file_ == nullptr) {
    return false;
  }
  const int fd = fileno(file_);
  if (fd < 0) {
    std::fclose(file_);
    file_ = nullptr;
    return false;
  }
  path_ = "/proc/self/fd/" + std::to_string(fd);
  return true;
}

/// Replace the complete file contents with one bounded byte string.
/// A failed or oversized write invalidates path() so a previous iteration's
/// bytes can never be consumed accidentally.
/// @param data Bytes to write; may be null only when size is zero.
/// @param size Number of bytes to expose.
/// @return True when the complete input is ready for a filename API.
bool BoundedAnonymousInputFile::Write(const std::uint8_t* data, std::size_t size) {
  ready_ = false;
  if (size > max_bytes_ || (data == nullptr && size != 0) || !EnsureOpen()) {
    return false;
  }

  const int fd = fileno(file_);
  if (fd < 0 || ftruncate(fd, 0) != 0) {
    return false;
  }

  std::size_t offset = 0;
  while (offset < size) {
    const ssize_t written = pwrite(fd, data + offset, size - offset, static_cast<off_t>(offset));
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return false;
    }
    offset += static_cast<std::size_t>(written);
  }

  ready_ = true;
  return true;
}

/// Return the stable procfs pathname after a successful Write.
/// @return NUL-terminated path, or nullptr when no complete input is ready.
const char* BoundedAnonymousInputFile::path() const { return ready_ ? path_.c_str() : nullptr; }

}  // namespace proto_fuzzer
