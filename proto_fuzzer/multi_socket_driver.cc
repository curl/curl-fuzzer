/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the bounded curl_multi_socket_action driver.

#include "proto_fuzzer/multi_socket_driver.h"

#include <poll.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace proto_fuzzer {

namespace {

/// Translate libcurl's read/write interest into poll(2) events.
short PollEventsForInterest(int interest) {
  short events = 0;
  if ((interest & CURL_POLL_IN) != 0) {
    events |= POLLIN;
  }
  if ((interest & CURL_POLL_OUT) != 0) {
    events |= POLLOUT;
  }
  return events;
}

/// Translate an observed poll result into curl_multi_socket_action flags.
int CurlEventsForPollResult(short events) {
  int result = 0;
  if ((events & (POLLIN | POLLHUP)) != 0) {
    // A stream hangup remains readable until curl consumes EOF.
    result |= CURL_CSELECT_IN;
  }
  if ((events & POLLOUT) != 0) {
    result |= CURL_CSELECT_OUT;
  }
  if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
    result |= CURL_CSELECT_ERR;
  }
  return result;
}

}  // namespace

/// Construct detached callback state. Install() supplies the multi only after
/// all watch storage has reached its final address.
MultiSocketDriver::MultiSocketDriver() : multi_(nullptr), timeout_ms_(-1), timer_pending_(false), generation_(0) {}

/// The owner deliberately destroys this after curl_multi_cleanup, so there is
/// no callback deregistration or libcurl access left for the destructor.
MultiSocketDriver::~MultiSocketDriver() = default;

/// Register all callbacks before an easy handle is added. curl may announce a
/// timer during curl_multi_add_handle, so installing later would miss the
/// event that starts an otherwise idle socket-action application.
bool MultiSocketDriver::Install(CURLM* multi) {
  multi_ = multi;
  if (multi_ == nullptr) {
    return false;
  }
  return curl_multi_setopt(multi_, CURLMOPT_SOCKETFUNCTION, &MultiSocketDriver::SocketCallback) == CURLM_OK &&
         curl_multi_setopt(multi_, CURLMOPT_SOCKETDATA, this) == CURLM_OK &&
         curl_multi_setopt(multi_, CURLMOPT_TIMERFUNCTION, &MultiSocketDriver::TimerCallback) == CURLM_OK &&
         curl_multi_setopt(multi_, CURLMOPT_TIMERDATA, this) == CURLM_OK;
}

/// Kick the state machine through the documented timeout pseudo-socket. This
/// creates the first real socket and therefore gives the callback its initial
/// watch without introducing a wall-clock dependency.
CURLMcode MultiSocketDriver::Start(int* running_handles) {
  if (multi_ == nullptr) {
    return CURLM_BAD_HANDLE;
  }
  timer_pending_ = false;
  return curl_multi_socket_action(multi_, CURL_SOCKET_TIMEOUT, 0, running_handles);
}

/// Run one bounded, non-blocking application event-loop turn. The snapshot is
/// intentional: a socket action may synchronously remove the current watch or
/// install another one, so the callback-owned table must not be iterated as a
/// live container across that call.
MultiSocketDriver::DriveResult MultiSocketDriver::DriveReady(int* running_handles) {
  DriveResult result;
  if (multi_ == nullptr) {
    result.code = CURLM_BAD_HANDLE;
    return result;
  }

  std::array<struct pollfd, kMaxWatches> poll_fds{};
  std::size_t poll_count = 0;
  for (const Watch& watch : watches_) {
    if (!watch.active) {
      continue;
    }
    poll_fds[poll_count].fd = watch.socket;
    poll_fds[poll_count].events = PollEventsForInterest(watch.interest);
    ++poll_count;
  }

  const std::uint64_t generation_before = generation_;
  const int running_before = running_handles == nullptr ? 0 : *running_handles;
  bool action_dispatched = false;
  if (poll_count != 0 && ::poll(poll_fds.data(), static_cast<nfds_t>(poll_count), 0) > 0) {
    for (std::size_t index = 0; index < poll_count; ++index) {
      if (running_handles != nullptr && *running_handles == 0) {
        break;
      }
      // An earlier action can synchronously remove or repurpose any later fd
      // in the snapshot. Revalidate it against the callback-owned table so a
      // stale readiness notification never reaches curl under a new meaning.
      Watch* current = FindWatch(poll_fds[index].fd);
      if (current == nullptr) {
        continue;
      }
      const int events = CurlEventsForPollResult(poll_fds[index].revents);
      if (events == 0) {
        continue;
      }
      result.code = curl_multi_socket_action(multi_, poll_fds[index].fd, events, running_handles);
      action_dispatched = true;
      // Process at most one snapshot entry. Its callbacks can repurpose an fd
      // with the same numeric value and interest, which no post-hoc lookup can
      // distinguish; the outer loop rebuilds readiness from fresh watches.
      break;
    }
  }

  if (result.code == CURLM_OK && timer_pending_ && timeout_ms_ == 0) {
    // Clear first: the action may synchronously install another zero timer,
    // which belongs to the next outer loop turn rather than recursive work.
    timer_pending_ = false;
    result.code = curl_multi_socket_action(multi_, CURL_SOCKET_TIMEOUT, 0, running_handles);
    action_dispatched = true;
  }

  const int running_after = running_handles == nullptr ? 0 : *running_handles;
  // A successful action can consume buffered protocol bytes without changing
  // either callbacks or handle count, so dispatch itself is observable
  // progress. The outer fixed operation cap still bounds permanently-ready
  // sockets.
  result.made_progress = action_dispatched || generation_ != generation_before || running_after != running_before;
  return result;
}

/// Touch the control APIs from a valid live-multi state. A zero-timeout query
/// is informational; wakeup is also non-blocking when no other thread is in a
/// poll call, which is exactly the deterministic behavior this lane needs.
void MultiSocketDriver::ProbeControlApis() {
  if (multi_ == nullptr) {
    return;
  }
  long timeout_ms = -1;
  (void)curl_multi_timeout(multi_, &timeout_ms);
  (void)curl_multi_wakeup(multi_);
}

/// Route the C callback into state whose lifetime is owned by DriveScenario.
int MultiSocketDriver::SocketCallback(CURL* /*easy*/, curl_socket_t socket, int what, void* user_data,
                                      void* socket_data) {
  return static_cast<MultiSocketDriver*>(user_data)->UpdateSocket(socket, what, socket_data);
}

/// Defer timer processing so a zero timer cannot recursively call back into
/// curl_multi_socket_action from inside libcurl.
int MultiSocketDriver::TimerCallback(CURLM* /*multi*/, long timeout_ms, void* user_data) {
  return static_cast<MultiSocketDriver*>(user_data)->UpdateTimer(timeout_ms);
}

/// Maintain a stable association for every observed fd. `socket_data` is used
/// only as a consistency hint: libcurl owns it and may legitimately pass null
/// for the first notification, while our fd lookup remains authoritative.
int MultiSocketDriver::UpdateSocket(curl_socket_t socket, int what, void* socket_data) {
  Watch* watch = FindWatch(socket);
  if (what == CURL_POLL_REMOVE) {
    if (watch != nullptr) {
      (void)curl_multi_assign(multi_, socket, nullptr);
      watch->active = false;
      watch->socket = CURL_SOCKET_BAD;
      watch->interest = CURL_POLL_NONE;
      ++generation_;
    }
    return 0;
  }

  if (watch == nullptr) {
    watch = FindFreeWatch();
    if (watch == nullptr) {
      return 0;
    }
    watch->socket = socket;
    watch->active = true;
    (void)curl_multi_assign(multi_, socket, watch);
    ++generation_;
  } else if (socket_data != nullptr && socket_data != watch) {
    // Reassert the stable association if an unusual transition supplied a
    // different application pointer. Never dereference foreign socket_data.
    (void)curl_multi_assign(multi_, socket, watch);
  }

  if (watch->interest != what) {
    watch->interest = what;
    ++generation_;
  }
  return 0;
}

/// Record only meaningful timer transitions. Repeated identical callbacks do
/// not count as progress, otherwise an unproductive transfer could consume
/// the full operation budget instead of the much smaller idle budget.
int MultiSocketDriver::UpdateTimer(long timeout_ms) {
  if (!timer_pending_ || timeout_ms_ != timeout_ms) {
    ++generation_;
  }
  timeout_ms_ = timeout_ms;
  timer_pending_ = timeout_ms >= 0;
  return 0;
}

/// Locate an existing association without allocating or depending on fd
/// magnitude (socket descriptors are not safe array indexes).
MultiSocketDriver::Watch* MultiSocketDriver::FindWatch(curl_socket_t socket) {
  for (Watch& watch : watches_) {
    if (watch.active && watch.socket == socket) {
      return &watch;
    }
  }
  return nullptr;
}

/// Return the first inactive stable slot. Exhaustion is harmless: curl keeps
/// owning the socket and the deterministic idle budget ends the fuzz case.
MultiSocketDriver::Watch* MultiSocketDriver::FindFreeWatch() {
  for (Watch& watch : watches_) {
    if (!watch.active) {
      return &watch;
    }
  }
  return nullptr;
}

}  // namespace proto_fuzzer
