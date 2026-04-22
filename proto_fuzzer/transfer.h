/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Select()-based curl_multi perform loops for driving a single
///        transfer against a MockServer or WebSocketMockServer.

#ifndef PROTO_FUZZER_TRANSFER_H_
#define PROTO_FUZZER_TRANSFER_H_

#include <curl/curl.h>

namespace proto_fuzzer {

class MockServer;
class WebSocketMockServer;

// HTTP transfers. DriveTransfer allocates its own multi handle and cleans up.
// Prefer DriveTransferWithMulti when the caller wants to keep the multi alive
// past transfer completion.
CURLMcode DriveTransfer(CURL* easy, MockServer& mock);
CURLMcode DriveTransferWithMulti(CURLM* multi, CURL* easy, MockServer& mock);

// WebSocket transfers. Runs the perform loop while advancing the 101
// handshake; in streaming mode (default) also pushes queued frame chunks as
// curl becomes readable. In manual mode (WebSocketMockServer::SetManualDelivery(true),
// for CURLOPT_CONNECT_ONLY=2L) the loop leaves chunks alone — the caller uses
// DriveWebSocketFrames to push them after handshake completion.
CURLMcode DriveWebSocketTransferWithMulti(CURLM* multi, CURL* easy, WebSocketMockServer& mock);

// Post-handshake manual WS drive: feed any remaining queued chunks as raw
// frame bytes into curl, then exercise curl_ws_recv / curl_ws_send with a
// small flag matrix. Bounded by internal iteration caps. No-op if the
// handshake has not completed.
void DriveWebSocketFrames(CURL* easy, WebSocketMockServer& mock);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TRANSFER_H_
