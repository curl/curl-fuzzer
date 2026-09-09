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

BoundedAnonymousInputFile::BoundedAnonymousInputFile(std::size_t max_bytes)
    : max_bytes_(max_bytes), file_(nullptr), ready_(false) {}

BoundedAnonymousInputFile::~BoundedAnonymousInputFile() {
  if (file_ != nullptr) {
    std::fclose(file_);
  }
}

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

const char* BoundedAnonymousInputFile::path() const { return ready_ ? path_.c_str() : nullptr; }

}  // namespace proto_fuzzer
