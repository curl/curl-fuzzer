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
#include <memory>
#include <string>
#include <vector>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

class WebSocketMockServer {
 public:
  WebSocketMockServer();
  ~WebSocketMockServer();

  WebSocketMockServer(const WebSocketMockServer&) = delete;
  WebSocketMockServer& operator=(const WebSocketMockServer&) = delete;

  void Install(CURL* easy);

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

  MockConnection* connection();
  curl_socket_t HandleOpenSocket();

 private:
  std::unique_ptr<MockConnection> connection_;
  std::vector<std::string> frames_;
  std::size_t next_chunk_;
  bool manual_delivery_;
  bool handshake_sent_;
  std::string ws_request_buffer_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_WEBSOCKET_MOCK_SERVER_H_
