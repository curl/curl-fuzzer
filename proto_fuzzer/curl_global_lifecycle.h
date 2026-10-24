/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Process-wide libcurl initialization and final cleanup.

#ifndef PROTO_FUZZER_CURL_GLOBAL_LIFECYCLE_H_
#define PROTO_FUZZER_CURL_GLOBAL_LIFECYCLE_H_

namespace proto_fuzzer {

/** Own the proto runtime's one curl global initialization. */
class CurlGlobalLifecycle final {
 public:
  /** Process-exit cleanup callback, injectable for lifecycle regression tests. */
  using CleanupFunction = void (*)();

  explicit CurlGlobalLifecycle(CleanupFunction cleanup = nullptr) noexcept;
  ~CurlGlobalLifecycle();

  CurlGlobalLifecycle(const CurlGlobalLifecycle&) = delete;
  CurlGlobalLifecycle& operator=(const CurlGlobalLifecycle&) = delete;
  CurlGlobalLifecycle(CurlGlobalLifecycle&&) = delete;
  CurlGlobalLifecycle& operator=(CurlGlobalLifecycle&&) = delete;

  /** @return Whether this object owns a successful curl initialization. */
  bool initialized() const noexcept { return initialized_; }

  void FinalizeForProcessExit() noexcept;

 private:
  friend void FinalizeRegisteredCurlGlobalLifecyclesForExit() noexcept;

  CleanupFunction cleanup_;
  CurlGlobalLifecycle* next_registered_ = nullptr;
  unsigned int initialization_count_ = 0;
  bool initialized_ = false;
};

void FinalizeRegisteredCurlGlobalLifecyclesForExit() noexcept;

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_CURL_GLOBAL_LIFECYCLE_H_
