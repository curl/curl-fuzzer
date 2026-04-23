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

namespace proto_fuzzer {

namespace {

constexpr long kSelectTimeoutUs = 10 * 1000;  // 10 ms

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
MockServerBase::MockServerBase() : connection_(nullptr), pending_recv_buf_bytes_(0), pending_drain_limit_(0) {}

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

/// Allocate a multi, attach 'easy', delegate to the subclass RunLoop, clean
/// up. Failures in multi_init / add_handle silently no-op: the fuzzer cares
/// about what curl does when driven, not about harness-level errors.
void MockServerBase::DriveScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
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
  if (curl_multi_add_handle(multi, easy) == CURLM_OK) {
    RunLoop(multi, easy, scenario);
    curl_multi_remove_handle(multi, easy);
  }
  curl_multi_cleanup(multi);
}

/// Hand the cached backpressure config to the connection. Safe to call when
/// connection_ is null (no-op) or when both knobs are 0 (ApplyBackpressure
/// itself is a no-op in that case).
void MockServerBase::ApplyPendingBackpressure() {
  if (connection_) {
    connection_->ApplyBackpressure(pending_recv_buf_bytes_, pending_drain_limit_);
  }
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

}  // namespace proto_fuzzer
