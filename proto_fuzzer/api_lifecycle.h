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
  /// Configure the plan's share handle and cover public error-string tables.
  /// @param easy Live easy handle used by explicit probes; clean it before
  ///        destroying this lifecycle so its share reference is gone first.
  /// @param plan Bounded API plan retained by the API target policy.
  /// @param url Bounded scenario URL used by URL and escaping probes during
  ///        construction; it is not retained.
  ApiLifecycle(CURL* easy, const curl::fuzzer::proto::ApiPlan& plan, std::string_view url);
  ~ApiLifecycle();

  ApiLifecycle(const ApiLifecycle&) = delete;
  ApiLifecycle& operator=(const ApiLifecycle&) = delete;

  /// Run correctly typed CURLINFO and response-header probes selected by the
  /// plan. Call only after the transfer entrypoint has returned.
  /// @param probe_upkeep True only after curl_easy_perform, whose internal
  ///        multi remains attached and can service curl_easy_upkeep safely.
  void ProbeTransferResults(bool probe_upkeep);

  /// Duplicate, reset, and destroy a scratch easy handle while every pointer-
  /// valued option copied from the source still has a live owner.
  void ProbeEasyDuplication();

 private:
  /// Counters provide real callback userdata without synchronization: this
  /// fuzzer drives one easy handle on one thread.
  struct ShareCallbackState {
    std::uint64_t locks = 0;
    std::uint64_t unlocks = 0;
  };

  /// Install and attach a share according to bounded typed selectors.
  void ConfigureShare();

  /// Count one share lock callback without introducing synchronization into
  /// the fuzzer's single-threaded lifecycle.
  static void ShareLock(CURL* easy, curl_lock_data data, curl_lock_access access, void* user_data);

  /// Count the matching unlock callback using the same live userdata.
  static void ShareUnlock(CURL* easy, curl_lock_data data, void* user_data);

  /// Destroy the share after easy cleanup has released its final reference.
  /// Shared domains remain enabled so curl can release caches they created.
  void CleanupShare();

  /// Exercise URL parsing, typed part retrieval, duplication, and escaping
  /// against bytes already selected by the scenario.
  void ProbeUrlAndEscaping(std::string_view url);

  CURL* easy_;
  const curl::fuzzer::proto::ApiPlan& plan_;
  CURLSH* share_;
  ShareCallbackState share_callback_state_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_API_LIFECYCLE_H_
