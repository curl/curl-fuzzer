/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief WebSocketMockServer — an in-process WebSocket peer that drives a
///        dynamic 101 handshake and then feeds RFC 6455 frame bytes to libcurl.

#ifndef PROTO_FUZZER_WEBSOCKET_MOCK_SERVER_H_
#define PROTO_FUZZER_WEBSOCKET_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <string>
#include <vector>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/mock_server_base.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::WebSocketMockServer
/// @brief In-process WebSocket peer. Dynamically generates a 101 response
///        against curl's Upgrade request, then either pushes queued frame
///        bytes via the drive loop (streaming mode) or, for
///        CURLOPT_CONNECT_ONLY=2L, hands them to the caller-driven manual
///        path exercised from DriveScenario.
class WebSocketMockServer : public MockServerBase {
 public:
  WebSocketMockServer();
  ~WebSocketMockServer() override;

  void SetFrames(std::vector<std::string> frames);

  void SetManualDelivery(bool manual);
  bool manual_delivery() const;

  bool TryAdvanceHandshake();
  bool handshake_sent() const;

  void DeliverNextChunk();
  bool has_more_chunks() const;

  std::size_t remaining_chunks() const;
  const std::string& PeekChunk(std::size_t index) const;
  void ConsumeChunk();
  bool PushRawBytes(const unsigned char* data, std::size_t size);

 protected:
  curl_socket_t HandleOpenSocket() override;
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  std::vector<std::string> frames_;
  std::size_t next_chunk_;
  bool manual_delivery_;
  bool handshake_sent_;
  std::string ws_request_buffer_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_WEBSOCKET_MOCK_SERVER_H_
