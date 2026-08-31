/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of MockServerBase — shared trampolines, shared
///        select() helper, DriveScenario multi-handle RAII, and the scheme
///        classifier that produces the right subclass for a Scenario.

#include "proto_fuzzer/mock_server_base.h"

#include <sys/select.h>

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/multi_socket_driver.h"

namespace proto_fuzzer {

namespace {

constexpr long kSelectTimeoutUs = 1000;  // 1 ms; explicit timing cases only.

/// @brief Noop function to satisfy CURLOPT_SOCKOPTFUNCTION.
/// @return CURL_SOCKOPT_ALREADY_CONNECTED: the socketpair is already connected.
int SockOptTrampoline(void* /*clientp*/, curl_socket_t /*curlfd*/, curlsocktype /*purpose*/) {
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

}  // namespace

/// @brief C trampoline for CURLOPT_OPENSOCKETFUNCTION. Declared at namespace
///        scope so it can be a friend of MockServerBase.
/// @param clientp Pointer to the MockServerBase instance.
/// @return The client-side socket fd as a curl_socket_t.
curl_socket_t MockServerBaseOpenSocketTrampoline(void* clientp, curlsocktype /*purpose*/,
                                                 struct curl_sockaddr* /*address*/) {
  return static_cast<MockServerBase*>(clientp)->HandleOpenSocket();
}

/// Default-construct an empty base instance with no connection.
MockServerBase::MockServerBase()
    : connection_(nullptr), pending_recv_buf_bytes_(0), pending_drain_limit_(0), multi_socket_driver_(nullptr) {}

/// Out-of-line destructor so MockConnection can stay forward-declared in the
/// base header (its complete type is only needed where unique_ptr is
/// instantiated for destruction).
MockServerBase::~MockServerBase() = default;

/// @return the owned MockConnection, or nullptr if one has not been opened.
MockConnection* MockServerBase::connection() { return connection_.get(); }

/// Install the common socket-callback trio. All subclasses share the same
/// trampoline; dispatch to the subclass happens through HandleOpenSocket().
void MockServerBase::Install(CURL* easy) {
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, &MockServerBaseOpenSocketTrampoline);
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA, this);
  curl_easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, &SockOptTrampoline);
}

/// Ordinary event-driven mocks need no upload-callback hook; their RunLoop
/// regains control after each perform and drains client traffic there.
void MockServerBase::ConfigureRequestData(ScenarioRequestData* /*request_data*/) {}

/// Allocate a multi, attach 'easy', delegate to the subclass RunLoop, consume
/// its completion message, and clean up. Failures in multi_init / add_handle
/// silently no-op: the fuzzer cares about what curl does when driven, not
/// about harness-level errors.
void MockServerBase::DriveScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario, bool use_multi_socket,
                                   bool wake_multi) {
  // Cache backpressure knobs so HandleOpenSocket can apply them the moment
  // connection_ exists. Both default to 0, which matches the legacy "drain
  // greedily, kernel-default buffers" behaviour exactly.
  const auto& bp = scenario.connection().backpressure();
  pending_recv_buf_bytes_ = static_cast<int>(bp.recv_buf_bytes());
  pending_drain_limit_ = static_cast<std::size_t>(bp.drain_limit());

  CURLM* multi = curl_multi_init();
  if (multi == nullptr) {
    return;
  }

  // Callback data must survive both remove_handle and multi_cleanup, since
  // either may emit CURL_POLL_REMOVE. Keeping it in this outer scope provides
  // that lifetime without allocating per-watch state.
  MultiSocketDriver socket_driver;
  if (use_multi_socket && socket_driver.Install(multi)) {
    multi_socket_driver_ = &socket_driver;
  }
  if (curl_multi_add_handle(multi, easy) == CURLM_OK) {
    if (wake_multi) {
      if (multi_socket_driver_ != nullptr) {
        multi_socket_driver_->ProbeControlApis();
      } else {
        long timeout_ms = -1;
        (void)curl_multi_timeout(multi, &timeout_ms);
        (void)curl_multi_wakeup(multi);
      }
    }
    RunLoop(multi, easy, scenario);

    // Completion messages are the multi API's only durable record of the
    // transfer result. Consume them while the easy handle is still attached:
    // otherwise every scenario systematically skips curl_multi_info_read's
    // result path and removal discards the opportunity. With one easy handle
    // attached, this drain has at most one completion message regardless of
    // fuzzed response size or redirect count.
    int messages_remaining = 0;
    while (curl_multi_info_read(multi, &messages_remaining) != nullptr) {
    }

    curl_multi_remove_handle(multi, easy);
  }
  curl_multi_cleanup(multi);
  multi_socket_driver_ = nullptr;
}

/// Preserve a safe fallback for protocol mocks that require an outer driver
/// to make progress. The API policy currently forces HTTP, whose override can
/// preload its bounded response and call curl_easy_perform without a thread.
void MockServerBase::DriveEasyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  DriveScenario(easy, scenario);
}

/// Expose only the current callback state to protocol drive loops. Ownership
/// remains in DriveScenario so no subclass can accidentally shorten it.
MultiSocketDriver* MockServerBase::multi_socket_driver() { return multi_socket_driver_; }

/// Hand the cached backpressure config to the connection. Safe to call when
/// connection_ is null (no-op) or when both knobs are 0 (ApplyBackpressure
/// itself is a no-op in that case).
void MockServerBase::ApplyPendingBackpressure() {
  if (connection_) {
    connection_->ApplyBackpressure(pending_recv_buf_bytes_, pending_drain_limit_);
  }
}

/// Treat a non-default BackpressureConfig as an explicit request for the
/// slower, timed drive policy. Proto3 scalar defaults make this deterministic:
/// a present-but-empty message remains on the ordinary fast path.
/// @param scenario Scenario whose backpressure settings select the policy.
/// @return true when the scenario explicitly opted into socket backpressure.
bool MockServerBase::UsesTimedDrive(const curl::fuzzer::proto::Scenario& scenario) {
  const auto& bp = scenario.connection().backpressure();
  return bp.recv_buf_bytes() != 0 || bp.drain_limit() != 0;
}

/// Wait on curl's fdset with a short timeout. Returns select()'s result; on
/// error sets *rc to the corresponding CURLMcode.
int MockServerBase::WaitOnMultiFdset(CURLM* multi, CURLMcode* rc) {
  fd_set readfds;
  fd_set writefds;
  fd_set excfds;
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_ZERO(&excfds);
  int maxfd = -1;
  *rc = curl_multi_fdset(multi, &readfds, &writefds, &excfds, &maxfd);
  if (*rc != CURLM_OK) {
    return -1;
  }
  if (maxfd < 0) {
    return 0;
  }
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = kSelectTimeoutUs;
  return ::select(maxfd + 1, &readfds, &writefds, &excfds, &timeout);
}

/// Exercise curl_multi_poll's pollset/filter traversal once without sleeping.
/// The result is deliberately ignored: this is an API/state probe, while the
/// protocol-specific perform loop remains the authority on transfer progress.
void MockServerBase::ProbeMultiPollset(CURLM* multi) {
  int numfds = 0;
  (void)curl_multi_poll(multi, nullptr, 0, 0, &numfds);
}

}  // namespace proto_fuzzer
