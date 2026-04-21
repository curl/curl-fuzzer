/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of DriveTransfer.

#include "proto_fuzzer/transfer.h"

#include <sys/select.h>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

namespace {

constexpr long kSelectTimeoutUs = 10 * 1000;  // 10 ms
constexpr int kMaxIdleIterations = 256;

}  // namespace

/// Drive a curl_multi perform loop for 'easy' using 'mock' as the only peer.
/// Bounded by select() timeouts so a misbehaving scenario cannot spin
/// forever.
/// @param easy The curl easy handle already attached to a MockServer.
/// @param mock The mock server whose queued chunks feed this transfer.
/// @return the CURLMcode of the final perform call, or CURLM_OK if the
///         transfer completed normally.
CURLMcode DriveTransfer(CURL* easy, MockServer& mock) {
  CURLM* multi = curl_multi_init();
  if (!multi) {
    return CURLM_OUT_OF_MEMORY;
  }
  CURLMcode add_rc = curl_multi_add_handle(multi, easy);
  if (add_rc != CURLM_OK) {
    curl_multi_cleanup(multi);
    return add_rc;
  }

  int still_running = 1;
  int idle_iterations = 0;
  CURLMcode rc = CURLM_OK;

  while (still_running && idle_iterations < kMaxIdleIterations) {
    rc = curl_multi_perform(multi, &still_running);
    if (rc != CURLM_OK) {
      break;
    }
    if (!still_running) {
      break;
    }

    fd_set readfds;
    fd_set writefds;
    fd_set excfds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&excfds);
    int maxfd = -1;

    // Get the file descriptors from curl_multi that we need to wait on.
    rc = curl_multi_fdset(multi, &readfds, &writefds, &excfds, &maxfd);
    if (rc != CURLM_OK) {
      break;
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = kSelectTimeoutUs;
    int ready = 0;
    if (maxfd >= 0) {
      ready = ::select(maxfd + 1, &readfds, &writefds, &excfds, &timeout);
    }

    // Whenever curl wants to read more from the peer, push the next queued
    // chunk. The mock's internal bookkeeping handles the "no more chunks"
    // case by shutting the write side.
    if (ready > 0 && mock.connection() != nullptr && FD_ISSET(mock.connection()->server_fd(), &writefds)) {
      // curl is ready to send data; nothing to do here.
    }
    if (mock.has_more_chunks()) {
      mock.DeliverNextChunk();
      idle_iterations = 0;
    } else if (ready == 0) {
      ++idle_iterations;
    } else {
      idle_iterations = 0;
    }
  }

  curl_multi_remove_handle(multi, easy);
  curl_multi_cleanup(multi);
  return rc;
}

}  // namespace proto_fuzzer
