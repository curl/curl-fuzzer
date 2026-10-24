/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded rendezvous for the resolver queued-cancellation scenario.

#ifndef PROTO_FUZZER_RESOLVER_CANCEL_GATE_H_
#define PROTO_FUZZER_RESOLVER_CANCEL_GATE_H_

#include <chrono>
#include <condition_variable>
#include <mutex>

namespace proto_fuzzer {

namespace resolver_cancel_detail {

struct GateState {
  std::mutex mutex;
  std::condition_variable released;
  bool armed = false;
  bool first_lookup_waiting = false;
};

inline GateState& State() {
  static GateState state;
  return state;
}

}  // namespace resolver_cancel_detail

/// Hold the first opt-in getaddrinfo call until the public multi owner has
/// queued the cancellation handle's lookups. The owning thread releases this
/// gate before removing the blocked handle or cleaning up the multi. Removing
/// the later queued handle does not join the resolver pool, so it is safe and
/// intentional while the gate is held.
class ScopedResolverCancelGate {
 public:
  ScopedResolverCancelGate() {
    auto& state = resolver_cancel_detail::State();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.first_lookup_waiting = false;
    state.armed = true;
  }

  ~ScopedResolverCancelGate() {
    auto& state = resolver_cancel_detail::State();
    {
      std::lock_guard<std::mutex> lock(state.mutex);
      state.armed = false;
    }
    state.released.notify_all();
  }

  ScopedResolverCancelGate(const ScopedResolverCancelGate&) = delete;
  ScopedResolverCancelGate& operator=(const ScopedResolverCancelGate&) = delete;
};

/// Give curl's single resolver worker a bounded opportunity to take the first
/// family before the main thread queues the cancellation handle.
inline bool WaitForResolverCancelLookup(std::chrono::milliseconds timeout) {
  auto& state = resolver_cancel_detail::State();
  std::unique_lock<std::mutex> lock(state.mutex);
  return state.released.wait_for(lock, timeout, [&state] { return state.first_lookup_waiting; });
}

/// Block only the first lookup issued while ScopedResolverCancelGate is live.
/// The scope owns the release: every exit path destroys it before multi
/// destruction or blocker removal can join this worker. Waiting for that
/// explicit release prevents scheduler speed from changing the queue shape.
inline void WaitAtResolverCancelGate() {
  auto& state = resolver_cancel_detail::State();
  std::unique_lock<std::mutex> lock(state.mutex);
  if (!state.armed || state.first_lookup_waiting) {
    return;
  }
  state.first_lookup_waiting = true;
  state.released.notify_all();
  state.released.wait(lock, [&state] { return !state.armed; });
}

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_RESOLVER_CANCEL_GATE_H_
