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

  bool Install(CURLM* multi);

  CURLMcode Start(int* running_handles);

  DriveResult DriveReady(int* running_handles);

  void ProbeControlApis();

 private:
  /// One stable curl_multi_assign association.
  struct Watch {
    curl_socket_t socket = CURL_SOCKET_BAD;
    int interest = CURL_POLL_NONE;
    bool active = false;
  };

  static int SocketCallback(CURL* easy, curl_socket_t socket, int what, void* user_data, void* socket_data);

  static int TimerCallback(CURLM* multi, long timeout_ms, void* user_data);

  int UpdateSocket(curl_socket_t socket, int what, void* socket_data);

  int UpdateTimer(long timeout_ms);

  Watch* FindWatch(curl_socket_t socket);

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
