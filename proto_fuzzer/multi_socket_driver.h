/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded event-loop state for driving curl_multi_socket_action.

#ifndef PROTO_FUZZER_MULTI_SOCKET_DRIVER_H_
#define PROTO_FUZZER_MULTI_SOCKET_DRIVER_H_

#include <curl/curl.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace proto_fuzzer {

/// @class proto_fuzzer::MultiSocketDriver
/// @brief Owns the socket and timer callback state required by libcurl's
///        event-driven multi API.
///
/// The fuzzer must retain callback storage until after the easy handle leaves
/// the multi and the multi is cleaned up: either operation can synchronously
/// issue CURL_POLL_REMOVE. A fixed watch table provides stable addresses for
/// curl_multi_assign while preventing a mutated transfer from allocating an
/// unbounded application-side poll set.
class MultiSocketDriver {
 public:
  /// Result from one non-blocking event-loop turn.
  struct DriveResult {
    /// libcurl's result for the last socket action in the turn.
    CURLMcode code = CURLM_OK;
    /// True when an action ran or callback/handle state changed.
    bool made_progress = false;
  };

  MultiSocketDriver();
  ~MultiSocketDriver();

  MultiSocketDriver(const MultiSocketDriver&) = delete;
  MultiSocketDriver& operator=(const MultiSocketDriver&) = delete;

  /// Install socket/timer callbacks on a caller-owned multi handle.
  /// @param multi Multi handle that outlives this driver.
  /// @return true when every callback option was accepted.
  bool Install(CURLM* multi);

  /// Start libcurl's socket state machine without waiting for a real timer.
  /// @param running_handles Receives the number of unfinished transfers.
  /// @return Result from curl_multi_socket_action.
  CURLMcode Start(int* running_handles);

  /// Poll the current callback-provided watch set with a zero timeout and
  /// report its readiness back to libcurl. A deferred zero timer is serviced
  /// after socket callbacks, never recursively from the timer callback.
  /// @param running_handles In/out unfinished-transfer count.
  /// @return Result code and whether observable driver state advanced.
  DriveResult DriveReady(int* running_handles);

  /// Exercise the wakeup and timeout-query APIs while the multi is live.
  /// Neither call waits or changes the deterministic operation budget.
  void ProbeControlApis();

 private:
  /// One stable curl_multi_assign association.
  struct Watch {
    curl_socket_t socket = CURL_SOCKET_BAD;
    int interest = CURL_POLL_NONE;
    bool active = false;
  };

  /// Trampoline registered as CURLMOPT_SOCKETFUNCTION.
  static int SocketCallback(CURL* easy, curl_socket_t socket, int what, void* user_data, void* socket_data);

  /// Trampoline registered as CURLMOPT_TIMERFUNCTION. It records work only;
  /// invoking libcurl here would recursively re-enter the callback API.
  static int TimerCallback(CURLM* multi, long timeout_ms, void* user_data);

  /// Apply one socket callback transition to the fixed watch table.
  int UpdateSocket(curl_socket_t socket, int what, void* socket_data);

  /// Record libcurl's latest timer request for deferred processing.
  int UpdateTimer(long timeout_ms);

  /// Find an active watch by fd.
  Watch* FindWatch(curl_socket_t socket);

  /// Find storage for a newly observed fd.
  Watch* FindFreeWatch();

  /// Number of stable watch slots. The HTTP mock permits four connections;
  /// extra slots leave room for transient resolver/filter descriptors.
  static constexpr std::size_t kMaxWatches = 16;

  CURLM* multi_;
  std::array<Watch, kMaxWatches> watches_;
  long timeout_ms_;
  bool timer_pending_;
  std::uint64_t generation_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MULTI_SOCKET_DRIVER_H_
