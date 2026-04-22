/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of DriveTransfer and WebSocket drive helpers.

#include "proto_fuzzer/transfer.h"

#include <curl/easy.h>
#include <curl/websockets.h>
#include <sys/select.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/websocket_mock_server.h"

namespace proto_fuzzer {

namespace {

constexpr long kSelectTimeoutUs = 10 * 1000;  // 10 ms
constexpr int kMaxIdleIterations = 256;

/// Wait on curl's fdset with a short timeout. Returns select()'s result; on
/// error sets *rc to the corresponding CURLMcode.
int WaitOnMultiFdset(CURLM* multi, CURLMcode* rc) {
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

}  // namespace

/// Drive a curl_multi perform loop for 'easy' using 'mock' as the only peer.
/// Allocates its own multi handle and cleans up. Bounded by select() timeouts
/// so a misbehaving scenario cannot spin forever.
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
  CURLMcode rc = DriveTransferWithMulti(multi, easy, mock);
  curl_multi_remove_handle(multi, easy);
  curl_multi_cleanup(multi);
  return rc;
}

/// Run the perform loop against a caller-owned multi. Identical bounds and
/// behaviour to DriveTransfer, but does not own the multi — the caller is
/// responsible for curl_multi_add_handle before the call and
/// curl_multi_remove_handle + curl_multi_cleanup afterwards.
/// @param multi The caller-owned curl_multi handle.
/// @param easy  The curl easy handle attached to the multi and the mock.
/// @param mock  The mock server feeding this transfer.
/// @return the CURLMcode of the final perform call.
CURLMcode DriveTransferWithMulti(CURLM* multi, CURL* easy, MockServer& mock) {
  (void)easy;
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

    int ready = WaitOnMultiFdset(multi, &rc);
    if (rc != CURLM_OK) {
      break;
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

  return rc;
}

/// Run the perform loop for a WebSocket transfer against a caller-owned
/// multi. Drives the 101 handshake on every iteration; in streaming mode
/// also pushes queued frame chunks as curl becomes readable. In manual mode
/// (mock.manual_delivery() is true) chunks are left alone — the caller pushes
/// them via DriveWebSocketFrames after this function returns.
/// @param multi The caller-owned curl_multi handle.
/// @param easy  The curl easy handle attached to the multi and the mock.
/// @param mock  The WebSocket mock server driving the handshake + frames.
/// @return the CURLMcode of the final perform call.
CURLMcode DriveWebSocketTransferWithMulti(CURLM* multi, CURL* easy, WebSocketMockServer& mock) {
  (void)easy;
  int still_running = 1;
  int idle_iterations = 0;
  CURLMcode rc = CURLM_OK;

  while (still_running && idle_iterations < kMaxIdleIterations) {
    rc = curl_multi_perform(multi, &still_running);
    if (rc != CURLM_OK) {
      break;
    }
    // Drive the 101 handshake on every iteration; no-op once sent.
    if (!mock.handshake_sent()) {
      if (mock.TryAdvanceHandshake()) {
        idle_iterations = 0;
      }
    }
    if (!still_running) {
      break;
    }

    int ready = WaitOnMultiFdset(multi, &rc);
    if (rc != CURLM_OK) {
      break;
    }

    // Only push frame chunks in streaming mode — in manual mode the caller
    // will push them via DriveWebSocketFrames after the handshake.
    if (!mock.manual_delivery() && mock.handshake_sent() && mock.has_more_chunks()) {
      mock.DeliverNextChunk();
      idle_iterations = 0;
    } else if (ready == 0) {
      ++idle_iterations;
    } else {
      idle_iterations = 0;
    }
  }

  return rc;
}

namespace {

constexpr std::size_t kMaxWsRecvIterations = 128;
constexpr std::size_t kMaxWsSendIterations = 16;

/// One representative flag combination per major curl_ws_send code path.
/// Order matters: CONT only makes sense after a non-FINAL TEXT/BINARY start,
/// but we don't chase correctness here — invalid sequences exercise error
/// handling in ws_enc_add_frame / ws_send_raw.
constexpr unsigned int kWsSendFlagMatrix[] = {
    CURLWS_TEXT, CURLWS_BINARY, CURLWS_TEXT | CURLWS_OFFSET, CURLWS_BINARY | CURLWS_OFFSET, CURLWS_CONT, CURLWS_PING,
    CURLWS_PONG, CURLWS_CLOSE,
};

void DrainWsRecv(CURL* easy) {
  for (std::size_t i = 0; i < kMaxWsRecvIterations; ++i) {
    unsigned char buffer[4096];
    std::size_t nread = 0;
    const struct curl_ws_frame* meta = nullptr;
    CURLcode rr = curl_ws_recv(easy, buffer, sizeof(buffer), &nread, &meta);
    if (rr == CURLE_AGAIN) {
      break;
    }
    if (rr != CURLE_OK && rr != CURLE_GOT_NOTHING) {
      break;
    }
    if (nread == 0 && meta == nullptr) {
      break;
    }
  }
}

}  // namespace

/// Post-handshake manual WS drive. Feeds every remaining queued chunk into
/// curl as raw frame bytes, draining curl_ws_recv between each push, then
/// exercises curl_ws_send against a small flag matrix. Bounded by internal
/// iteration caps; no-op if the handshake has not completed.
/// @param easy The curl easy handle that completed the WS handshake.
/// @param mock The WebSocket mock server whose queued chunks are the
///             frame wire-bytes to push.
void DriveWebSocketFrames(CURL* easy, WebSocketMockServer& mock) {
  if (!mock.handshake_sent()) {
    return;
  }

  // Push every remaining scripted chunk straight onto the server fd as raw
  // bytes: these are the frame bytes the fuzzer wants curl to parse.
  while (mock.remaining_chunks() > 0) {
    const std::string& chunk = mock.PeekChunk(0);
    if (!chunk.empty()) {
      mock.PushRawBytes(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
    }
    mock.ConsumeChunk();
    DrainWsRecv(easy);
  }

  // Final drain: in case frame parsing produced more work after the last
  // chunk was pushed.
  DrainWsRecv(easy);

  // Exercise curl_ws_send with a fixed matrix of flags. We don't care whether
  // the send actually lands on the wire — the point is to reach the encode
  // paths in ws_enc_add_frame.
  static const unsigned char kPayload[] = "hello-from-proto-fuzzer";
  const std::size_t payload_len = sizeof(kPayload) - 1;
  std::size_t iteration = 0;
  for (unsigned int flags : kWsSendFlagMatrix) {
    if (iteration++ >= kMaxWsSendIterations) {
      break;
    }
    std::size_t sent = 0;
    curl_off_t fragsize = (flags & CURLWS_OFFSET) ? static_cast<curl_off_t>(payload_len) : 0;
    (void)curl_ws_send(easy, kPayload, payload_len, &sent, fragsize, flags);
    if (mock.connection() != nullptr) {
      mock.connection()->DrainIncoming();
    }
  }
}

}  // namespace proto_fuzzer
