/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of WebSocketMockServer.

#include "proto_fuzzer/websocket_mock_server.h"

#include <cstddef>
#include <string>
#include <utility>

#include "proto_fuzzer/ws_accept_key.h"

namespace proto_fuzzer {

namespace {

/// @brief Noop function to satisfy CURLOPT_SOCKOPTFUNCTION.
/// @return CURL_SOCKOPT_ALREADY_CONNECTED to indicate the socket is ready.
int SockOptTrampoline(void* /*clientp*/, curl_socket_t /*curlfd*/, curlsocktype /*purpose*/) {
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

/// @brief C trampoline for CURLOPT_OPENSOCKETFUNCTION.
/// @param clientp Pointer to the WebSocketMockServer instance.
/// @return The client-side socket fd as a curl_socket_t.
curl_socket_t OpenSocketTrampoline(void* clientp, curlsocktype /*purpose*/, struct curl_sockaddr* /*address*/) {
  return static_cast<WebSocketMockServer*>(clientp)->HandleOpenSocket();
}

/// Find "Sec-WebSocket-Key:" in the request and return the trimmed value.
/// @param request The raw HTTP request bytes buffered from the client.
/// @return The header value, or an empty string if not found.
std::string ExtractWebSocketKey(const std::string& request) {
  static const char kHeader[] = "Sec-WebSocket-Key:";
  std::size_t pos = request.find(kHeader);
  if (pos == std::string::npos) {
    return {};
  }
  pos += sizeof(kHeader) - 1;
  while (pos < request.size() && (request[pos] == ' ' || request[pos] == '\t')) {
    ++pos;
  }
  std::size_t end = request.find("\r\n", pos);
  if (end == std::string::npos) {
    return {};
  }
  while (end > pos && (request[end - 1] == ' ' || request[end - 1] == '\t')) {
    --end;
  }
  return request.substr(pos, end - pos);
}

/// SHA1(key + WS magic guid), base64-encoded — RFC 6455 §4.2.2.
/// Delegates to the standalone implementation in ws_accept_key.h so we don't
/// need OpenSSL.
std::string ComputeWebSocketAccept(const std::string& key) { return proto_fuzzer::ComputeWebSocketAcceptKey(key); }

}  // namespace

/// @class proto_fuzzer::WebSocketMockServer
/// @brief In-process WebSocket peer. Owns the socketpair, parses curl's
///        Upgrade request, synthesises a valid 101 response, and then either
///        pushes queued frame bytes via the transfer loop (streaming mode) or
///        hands them to the caller for manual drive via curl_ws_recv/send
///        (manual mode, used with CURLOPT_CONNECT_ONLY=2L).

/// Construct an idle WebSocketMockServer with no connection and no queued
/// frames. Install() and SetFrames() must be called before the easy handle
/// performs.
WebSocketMockServer::WebSocketMockServer()
    : connection_(nullptr), next_chunk_(0), manual_delivery_(false), handshake_sent_(false) {}

/// Default destructor; the owned MockConnection (if any) cleans up its socketpair.
WebSocketMockServer::~WebSocketMockServer() = default;

/// Install CURLOPT_OPENSOCKETFUNCTION / OPENSOCKETDATA / SOCKOPTFUNCTION on
/// 'easy'. Must be called before curl_easy_perform / curl_multi_perform.
/// @param easy The curl easy handle to configure.
void WebSocketMockServer::Install(CURL* easy) {
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, &OpenSocketTrampoline);
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA, this);
  curl_easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, &SockOptTrampoline);
}

/// Queue RFC 6455 wire-byte chunks to emit once the handshake has completed.
/// Resets the next-chunk cursor.
/// @param frames Ordered list of chunk byte strings.
void WebSocketMockServer::SetFrames(std::vector<std::string> frames) {
  frames_ = std::move(frames);
  next_chunk_ = 0;
}

/// Toggle streaming (false, default) vs manual (true) chunk delivery.
/// @param manual Whether to suppress automatic chunk pushing by the
///        transfer loop.
void WebSocketMockServer::SetManualDelivery(bool manual) { manual_delivery_ = manual; }

/// @return true if chunks are caller-driven rather than transfer-loop-driven.
bool WebSocketMockServer::manual_delivery() const { return manual_delivery_; }

/// @return true once a 101 Switching Protocols response has been written.
bool WebSocketMockServer::handshake_sent() const { return handshake_sent_; }

/// @return true if at least one frame chunk has not yet been sent.
bool WebSocketMockServer::has_more_chunks() const { return next_chunk_ < frames_.size(); }

/// @return the number of queued chunks not yet consumed.
std::size_t WebSocketMockServer::remaining_chunks() const {
  return next_chunk_ >= frames_.size() ? 0 : frames_.size() - next_chunk_;
}

/// Access a pending chunk without consuming it.
/// @param index Offset from the next-pending cursor.
/// @return reference to the chunk byte string.
const std::string& WebSocketMockServer::PeekChunk(std::size_t index) const { return frames_[next_chunk_ + index]; }

/// Advance the pending-chunk cursor by one. No-op when no chunks remain.
void WebSocketMockServer::ConsumeChunk() {
  if (next_chunk_ < frames_.size()) {
    ++next_chunk_;
  }
}

/// @return the active MockConnection, or nullptr if none has been opened.
MockConnection* WebSocketMockServer::connection() { return connection_.get(); }

/// Called by the OPENSOCKETFUNCTION C trampoline. Creates the MockConnection
/// but does NOT write anything — the handshake is driven later by
/// TryAdvanceHandshake().
/// @return the client-side fd to hand to libcurl, or CURL_SOCKET_BAD on
///         failure.
curl_socket_t WebSocketMockServer::HandleOpenSocket() {
  if (connection_) {
    return CURL_SOCKET_BAD;
  }
  connection_ = std::make_unique<MockConnection>();
  if (!connection_->ok()) {
    connection_.reset();
    return CURL_SOCKET_BAD;
  }
  // Wait for curl's Upgrade request before we write anything — the transfer
  // loop calls TryAdvanceHandshake() to drive that exchange.
  return connection_->take_client_fd();
}

/// Push raw bytes onto the server fd. Used by the manual-drive path to feed
/// frame bytes directly into curl without any mock-side framing.
/// @param data Buffer to send.
/// @param size Number of bytes in 'data'.
/// @return false on short or failed write.
bool WebSocketMockServer::PushRawBytes(const unsigned char* data, std::size_t size) {
  if (!connection_) {
    return false;
  }
  connection_->DrainIncoming();
  return connection_->WriteAll(data, size);
}

/// Push the next queued frame when curl is ready. Used in streaming mode;
/// the transfer loop calls this after the handshake has been sent. Shuts
/// the write side once the last chunk is delivered.
void WebSocketMockServer::DeliverNextChunk() {
  if (!connection_ || next_chunk_ >= frames_.size()) {
    return;
  }
  connection_->DrainIncoming();
  const std::string& chunk = frames_[next_chunk_++];
  if (!chunk.empty()) {
    connection_->WriteAll(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
  }
  if (next_chunk_ >= frames_.size()) {
    connection_->ShutdownWrite();
  }
}

/// Drive the WebSocket opening handshake: read whatever curl has written so
/// far, and once we've seen the end of the request headers, reply with a
/// valid 101 Switching Protocols.
/// @return true once the 101 response has been written (idempotent afterwards).
bool WebSocketMockServer::TryAdvanceHandshake() {
  if (handshake_sent_ || !connection_) {
    return handshake_sent_;
  }
  connection_->ReadAvailable(&ws_request_buffer_);
  if (ws_request_buffer_.find("\r\n\r\n") == std::string::npos) {
    return false;
  }
  std::string key = ExtractWebSocketKey(ws_request_buffer_);
  // Even if parsing failed, reply with *something* so curl doesn't wedge.
  // A bad Accept exercises curl's handshake-error path.
  std::string accept = key.empty() ? std::string("AAAAAAAAAAAAAAAAAAAAAAAAAAA=") : ComputeWebSocketAccept(key);
  std::string response =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: " +
      accept + "\r\n\r\n";
  connection_->WriteAll(reinterpret_cast<const unsigned char*>(response.data()), response.size());
  handshake_sent_ = true;
  return true;
}

}  // namespace proto_fuzzer
