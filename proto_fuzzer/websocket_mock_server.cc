/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of WebSocketMockServer.

#include "proto_fuzzer/websocket_mock_server.h"

#include <curl/websockets.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>

#include "proto_fuzzer/ws_accept_key.h"
#include "proto_fuzzer/ws_frame.h"

namespace proto_fuzzer {

namespace {

// Cap per-scenario frame chunks so a mutator that creates thousands of tiny
// entries can't dominate runtime.
constexpr std::size_t kMaxResponseChunks = 16;

// Iteration caps for the post-handshake manual WS drive. Kept small because
// every iteration makes a curl_ws_recv / curl_ws_send call.
constexpr std::size_t kMaxWsRecvIterations = 128;
constexpr std::size_t kMaxWsSendIterations = 32;

/// Ordered list of flag combinations fed to curl_ws_send / curl_ws_start_frame
/// during the manual-drive tail. Sequencing matters: the TEXT|CONT entry puts
/// the encoder into `contfragment=true`, so subsequent CONT / TEXT|CONT /
/// BINARY|CONT entries then take the contfragment-aware branches in
/// ws_frame_flags2firstbyte that would otherwise be unreachable from the
/// fuzzer. A lone CURLWS_CONT runs first (contfragment=false → "No ongoing
/// fragmented message" failf), and a bare `0` directly after CURLWS_CONT
/// drives the "no flags given; interpreting as continuation" compatibility
/// path. (TEXT|BINARY), (CLOSE|CONT), (PING|CONT), (PONG|CONT) cover the
/// invalid-combination failf() branches; the trailing lone `0` reaches the
/// ordinary "no flags given" rejection with contfragment=false.
constexpr unsigned int kWsSendFlagMatrix[] = {
    CURLWS_CONT,
    CURLWS_TEXT,
    CURLWS_BINARY,
    CURLWS_TEXT | CURLWS_OFFSET,
    CURLWS_BINARY | CURLWS_OFFSET,
    CURLWS_TEXT | CURLWS_CONT,
    CURLWS_CONT,
    0,
    CURLWS_TEXT,
    CURLWS_BINARY | CURLWS_CONT,
    CURLWS_BINARY,
    CURLWS_PING,
    CURLWS_PONG,
    CURLWS_CLOSE,
    0,
    CURLWS_CLOSE | CURLWS_CONT,
    CURLWS_PING | CURLWS_CONT,
    CURLWS_PONG | CURLWS_CONT,
    CURLWS_TEXT | CURLWS_BINARY,
};

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

/// Build the ordered list of chunks to deliver once the 101 handshake has
/// completed. Mixes raw `on_readable` bytes (fuzzer-controlled) with serialised
/// `server_frames` (structured RFC 6455 frames from the proto) under a shared
/// kMaxResponseChunks budget.
std::vector<std::string> BuildFrameChunks(const curl::fuzzer::proto::Connection& conn) {
  std::vector<std::string> chunks;
  chunks.reserve(kMaxResponseChunks);
  const std::size_t raw_budget = std::min<std::size_t>(kMaxResponseChunks, conn.on_readable_size());
  for (std::size_t i = 0; i < raw_budget; ++i) {
    chunks.emplace_back(conn.on_readable(i));
  }
  const std::size_t frame_budget = kMaxResponseChunks - chunks.size();
  const std::size_t frame_count = std::min<std::size_t>(frame_budget, conn.server_frames_size());
  for (std::size_t i = 0; i < frame_count; ++i) {
    chunks.emplace_back(SerializeWebSocketFrame(conn.server_frames(static_cast<int>(i))));
  }
  return chunks;
}

/// @return true if any scenario option sets CURLOPT_CONNECT_ONLY to 2, which
///         is curl's "WebSocket connect-only, drive recv/send manually" mode.
bool ScenarioRequestsManualWsDrive(const curl::fuzzer::proto::Scenario& scenario) {
  for (const auto& opt : scenario.options()) {
    if (opt.option_id() != curl::fuzzer::proto::CURLOPT_CONNECT_ONLY) {
      continue;
    }
    if (opt.value_case() == curl::fuzzer::proto::SetOption::ValueCase::kUintValue && opt.uint_value() == 2) {
      return true;
    }
  }
  return false;
}

/// WRITEFUNCTION / HEADERFUNCTION installed on the easy handle by
/// WebSocketMockServer::Install. Pokes curl_ws_meta on every invocation (so
/// the Curl_is_in_callback-guarded branch stays covered), and fires a
/// one-shot curl_ws_send probe to reach ws_send_raw_blocking — that target
/// is unreachable unless CURLWS_RAW_MODE is set AND the caller is inside a
/// callback. The probe is sized larger than typical backpressure recv
/// buffers so the partial-write / SOCKET_WRITABLE loop engages under a
/// tightened SO_RCVBUF. The one-shot gate keeps the per-scenario cost
/// bounded when SOCKET_WRITABLE times out. WRITEDATA is the owning
/// WebSocketMockServer so callback state lives on the server, not globals.
size_t WebSocketWriteCallback(void* /*contents*/, size_t size, size_t nmemb, void* userdata) {
  auto* server = static_cast<WebSocketMockServer*>(userdata);
  if (server != nullptr) {
    CURL* easy = server->easy_handle();
    if (easy != nullptr) {
      (void)curl_ws_meta(easy);
      if (!server->ws_probe_fired()) {
        server->MarkWsProbeFired();
        static unsigned char kProbe[16384];
        std::fill(kProbe, kProbe + sizeof(kProbe), 'P');
        std::size_t sent = 0;
        (void)curl_ws_send(easy, kProbe, sizeof(kProbe), &sent, 0, 0);
      }
    }
  }
  return size * nmemb;
}

/// Drain curl_ws_recv in a tight loop until it returns CURLE_AGAIN / nothing
/// pending. Bounded; not expected to do anything on well-formed scenarios.
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

/// Construct an idle WebSocketMockServer with no queued frames. Install()
/// on the base class and DriveScenario() configure it from a Scenario proto.
WebSocketMockServer::WebSocketMockServer()
    : next_chunk_(0), manual_delivery_(false), handshake_sent_(false), ws_probe_fired_(false), easy_handle_(nullptr) {}

/// Default destructor; the owned MockConnection (if any) cleans up its socketpair.
WebSocketMockServer::~WebSocketMockServer() = default;

/// Install the common socket callbacks via the base, then overwrite
/// WRITEFUNCTION / HEADERFUNCTION with a ws-aware variant and wire
/// WRITEDATA to this server instance so the callback can consult per-
/// scenario state (easy handle, one-shot probe flag).
void WebSocketMockServer::Install(CURL* easy) {
  MockServerBase::Install(easy);
  easy_handle_ = easy;
  ws_probe_fired_ = false;
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &WebSocketWriteCallback);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, this);
  curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, &WebSocketWriteCallback);
}

/// @return true once the one-shot WS probe has fired for this scenario.
bool WebSocketMockServer::ws_probe_fired() const { return ws_probe_fired_; }

/// Flip the one-shot gate closed. Called from the write callback before it
/// invokes curl_ws_send, so subsequent callback entries skip the probe.
void WebSocketMockServer::MarkWsProbeFired() { ws_probe_fired_ = true; }

/// @return the curl easy handle cached by Install() for the write callback.
CURL* WebSocketMockServer::easy_handle() const { return easy_handle_; }

/// Queue RFC 6455 wire-byte chunks to emit once the handshake has completed.
/// Resets the next-chunk cursor.
/// @param frames Ordered list of chunk byte strings.
void WebSocketMockServer::SetFrames(std::vector<std::string> frames) {
  frames_ = std::move(frames);
  next_chunk_ = 0;
}

/// Toggle streaming (false, default) vs manual (true) chunk delivery.
/// @param manual Whether to suppress automatic chunk pushing by the
///        drive loop.
void WebSocketMockServer::SetManualDelivery(bool manual) { manual_delivery_ = manual; }

/// @return true if chunks are caller-driven rather than drive-loop-driven.
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

/// Called by the OPENSOCKETFUNCTION trampoline in the base class. Creates the
/// MockConnection but does NOT write anything — the handshake is driven later
/// by TryAdvanceHandshake().
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
  ApplyPendingBackpressure();
  // Wait for curl's Upgrade request before we write anything — the drive
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
/// the drive loop calls this after the handshake has been sent. Shuts
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

/// Seed the mock from the scenario, then run the perform loop. Drives the 101
/// handshake on every iteration; in streaming mode also pushes queued frame
/// chunks as curl becomes readable. In manual mode (CURLOPT_CONNECT_ONLY=2)
/// chunks are left alone during the loop — once the loop returns, this method
/// pushes them as raw bytes and exercises curl_ws_recv / curl_ws_send against
/// a small flag matrix.
/// @param multi    caller-owned multi; 'easy' is already added.
/// @param easy     the curl easy handle attached to this mock.
/// @param scenario source of the frame chunks and CONNECT_ONLY setting.
void WebSocketMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  SetManualDelivery(ScenarioRequestsManualWsDrive(scenario));
  // initial_response is unused in WS mode; we synthesise the 101 dynamically
  // from curl's Upgrade request.
  SetFrames(BuildFrameChunks(scenario.connection()));

  int still_running = 1;
  int idle_iterations = 0;
  CURLMcode rc = CURLM_OK;

  while (still_running && idle_iterations < kMaxIdleIterations) {
    rc = curl_multi_perform(multi, &still_running);
    if (rc != CURLM_OK) {
      break;
    }
    // Drive the 101 handshake on every iteration; no-op once sent.
    if (!handshake_sent()) {
      if (TryAdvanceHandshake()) {
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
    // will push them below after the handshake.
    if (!manual_delivery() && handshake_sent() && has_more_chunks()) {
      DeliverNextChunk();
      idle_iterations = 0;
    } else if (ready == 0) {
      ++idle_iterations;
    } else {
      idle_iterations = 0;
    }
  }

  if (!manual_delivery() || !handshake_sent()) {
    return;
  }

  // Manual-drive tail: feed every remaining scripted chunk straight onto the
  // server fd as raw frame bytes, draining curl_ws_recv between each push.
  while (remaining_chunks() > 0) {
    const std::string& chunk = PeekChunk(0);
    if (!chunk.empty()) {
      PushRawBytes(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
    }
    ConsumeChunk();
    DrainWsRecv(easy);
  }
  // Final drain in case frame parsing produced more work after the last push.
  DrainWsRecv(easy);

  const auto& probes = scenario.connection().manual_probes();
  static const unsigned char kPayload[] = "hello-from-proto-fuzzer";
  const std::size_t payload_len = sizeof(kPayload) - 1;

  if (probes.flag_matrix()) {
    // Exercise curl_ws_send with a fixed matrix of flags. We don't care whether
    // the send actually lands on the wire — the point is to reach the encode
    // paths in ws_enc_add_frame / ws_enc_write_head.
    std::size_t iteration = 0;
    for (unsigned int flags : kWsSendFlagMatrix) {
      if (iteration++ >= kMaxWsSendIterations) {
        break;
      }
      // Announce the frame via the public curl_ws_start_frame entrypoint before
      // the actual send. In non-raw mode this writes the frame head into the
      // sendbuf; the follow-up curl_ws_send with the same flags finishes the
      // exchange or fails cleanly on invalid flag combos.
      (void)curl_ws_start_frame(easy, flags, static_cast<curl_off_t>(payload_len));
      std::size_t sent = 0;
      curl_off_t fragsize = (flags & CURLWS_OFFSET) ? static_cast<curl_off_t>(payload_len) : 0;
      (void)curl_ws_send(easy, kPayload, payload_len, &sent, fragsize, flags);
      if (connection() != nullptr) {
        connection()->DrainIncoming();
      }
    }
  }

  if (probes.unaligned_send()) {
    // Multi-call mis-sized send probe: declare a fragsize=200 frame, send 23
    // bytes, then call curl_ws_send again with a buflen much bigger than the
    // remaining payload. Hits the "unaligned frame size" failf in ws_enc_send.
    constexpr curl_off_t kBigFrag = 200;
    (void)curl_ws_start_frame(easy, CURLWS_TEXT | CURLWS_OFFSET, kBigFrag);
    std::size_t sent = 0;
    (void)curl_ws_send(easy, kPayload, payload_len, &sent, kBigFrag, CURLWS_TEXT | CURLWS_OFFSET);
    // Now enc.payload_remain ≈ kBigFrag - payload_len. A follow-up send with
    // buflen > remaining trips the guard at ws_enc_send:~1050.
    std::size_t sent2 = 0;
    constexpr std::size_t kOverrun = 500;
    unsigned char overrun[kOverrun];
    std::fill(overrun, overrun + kOverrun, 'X');
    (void)curl_ws_send(easy, overrun, kOverrun, &sent2, kBigFrag, CURLWS_TEXT | CURLWS_OFFSET);
    if (connection() != nullptr) {
      connection()->DrainIncoming();
    }
  }

  if (probes.raw_send()) {
    // Raw-mode send path: reachable only when CURLOPT_WS_OPTIONS has
    // CURLWS_RAW_MODE set. curl_ws_send with flags=0, fragsize=0 takes the
    // data->set.ws_raw_mode branch → ws_send_raw. No-op for non-raw scenarios
    // (hits the "no flags given" failure path instead).
    std::size_t sent = 0;
    (void)curl_ws_send(easy, kPayload, payload_len, &sent, 0, 0);
    if (connection() != nullptr) {
      connection()->DrainIncoming();
    }
  }
}

}  // namespace proto_fuzzer
