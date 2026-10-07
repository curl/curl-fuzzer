/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Safe ownership and typed probes for the dedicated public-API lane.

#ifndef PROTO_FUZZER_API_LIFECYCLE_H_
#define PROTO_FUZZER_API_LIFECYCLE_H_

#include <curl/curl.h>
#include <curl/multi.h>

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::ApiLifecycle
/// @brief Exercises public easy/share/query APIs while preserving all caller-
///        owned option and callback lifetimes.
///
/// Construct this only after the easy handle has its final pre-transfer
/// configuration. The owner must destroy the easy before this object: easy
/// cleanup reliably releases its share reference even when an incomplete
/// connection makes explicit detachment fail. Result and duplication probes
/// remain explicit because they run before either teardown step.
class ApiLifecycle {
 public:
  ApiLifecycle(CURL* easy, const curl::fuzzer::proto::ApiPlan& plan, std::string_view url);

  /// A temporary plan cannot satisfy the retained reference's lifetime.
  ApiLifecycle(CURL* easy, curl::fuzzer::proto::ApiPlan&& plan, std::string_view url) = delete;
  ApiLifecycle(CURL* easy, const curl::fuzzer::proto::ApiPlan&& plan, std::string_view url) = delete;

  ~ApiLifecycle();

  ApiLifecycle(const ApiLifecycle&) = delete;
  ApiLifecycle& operator=(const ApiLifecycle&) = delete;

  void ProbeTransferResults(bool probe_upkeep);

  void ProbeEasyDuplication();

  bool response_pause_returned() const;

  std::size_t response_bytes_received() const;

  void SetActiveMulti(CURLM* multi);

  std::size_t reentrant_probes_run() const;

  std::size_t reentrant_recursive_rejections() const;

 private:
  /// Counters provide real callback userdata without synchronization: this
  /// fuzzer drives one easy handle on one thread.
  struct ShareCallbackState {
    std::uint64_t locks = 0;
    std::uint64_t unlocks = 0;
  };

  /// State borrowed by CURLOPT_WRITEDATA for the complete easy lifetime.
  struct ResponseCallbackState {
    ApiLifecycle* owner = nullptr;
    bool pause_once = false;
    bool pause_returned = false;
    std::size_t bytes_received = 0;
    bool probes_done = false;
    std::size_t probes_run = 0;
    std::size_t recursive_rejections = 0;
  };

  static std::size_t ResponseWrite(char* contents, std::size_t size, std::size_t nmemb, void* user_data);

  void ConfigureShare();

  static void ShareLock(CURL* easy, curl_lock_data data, curl_lock_access access, void* user_data);

  static void ShareUnlock(CURL* easy, curl_lock_data data, void* user_data);

  void CleanupShare();

  void ProbeUrlAndEscaping(std::string_view url);

  void RunReentrantProbes();

  CURL* easy_;
  const curl::fuzzer::proto::ApiPlan& plan_;
  ResponseCallbackState response_callback_state_;
  CURLSH* share_;
  ShareCallbackState share_callback_state_;
  CURLM* active_multi_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_API_LIFECYCLE_H_
