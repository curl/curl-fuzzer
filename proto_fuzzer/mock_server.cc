/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of MockConnection and MockServer.

#include "proto_fuzzer/mock_server.h"

#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "proto_fuzzer/ws_frame.h"

namespace proto_fuzzer {

namespace {

// fd_set can only represent file descriptors < FD_SETSIZE. Reject any pair that couldn't participate in select()
// without memory corruption.
bool FdFitsInFdSet(int fd) { return fd >= 0 && fd < FD_SETSIZE; }

// Cap per-scenario response chunks so a mutator that creates thousands of
// tiny on_readable entries can't dominate runtime.
constexpr std::size_t kMaxResponseChunks = 16;

/// Combine the scenario's raw on_readable strings with any serialised
/// WebSocket frames into a single ordered chunk list, capped at
/// kMaxResponseChunks. Historical behaviour: HTTP scenarios can carry
/// server_frames too; the fuzzer just feeds those bytes to curl.
std::vector<std::string> BuildChunkList(const curl::fuzzer::proto::Connection& conn) {
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

}  // namespace

/// @class proto_fuzzer::MockConnection
/// @brief Owns one half of a socketpair used to feed canned responses to libcurl. The destructor closes the server-side
/// fd; the client-side fd is handed to libcurl via CURLOPT_OPENSOCKETFUNCTION and becomes curl's to close.

/// Construct a non-blocking AF_UNIX/SOCK_STREAM socketpair. Both fds are validated to fit inside FD_SETSIZE; on any
/// failure ok() returns false and the instance is unusable.
MockConnection::MockConnection() : server_fd_(-1), client_fd_(-1), drain_limit_(0) {
  int fds[2];

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
    return;
  }

  // The fds must be small enough to fit in an fd_set for select(). If not, close them and fail the constructor.
  if (!FdFitsInFdSet(fds[0]) || !FdFitsInFdSet(fds[1])) {
    close(fds[0]);
    close(fds[1]);
    return;
  }

  // Set the server-side fd non-blocking so we can write to it without risk of hanging the fuzzer.
  int flags = fcntl(fds[0], F_GETFL, 0);
  if (flags < 0 || fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) < 0) {
    close(fds[0]);
    close(fds[1]);
    return;
  }

  // Success: store the file descriptors.
  server_fd_ = fds[0];
  client_fd_ = fds[1];
}

/// Close the server-side fd (and the client-side fd if it was never handed off via take_client_fd()).
MockConnection::~MockConnection() {
  if (server_fd_ >= 0) {
    close(server_fd_);
  }
  if (client_fd_ >= 0) {
    close(client_fd_);
  }
}

/// @return true if the underlying socketpair was set up successfully.
bool MockConnection::ok() const { return server_fd_ >= 0; }

/// @return the server-side fd (still owned by this MockConnection).
int MockConnection::server_fd() const { return server_fd_; }

/// Hand the client-side fd to libcurl. After this call the caller owns the fd and the MockConnection will not close it
/// on destruction.
/// @return the client-side socket fd as a curl_socket_t.
curl_socket_t MockConnection::take_client_fd() {
  int fd = client_fd_;
  client_fd_ = -1;
  return static_cast<curl_socket_t>(fd);
}

/// Write 'size' bytes from 'data' to the server fd, looping until the whole buffer is sent or a short/failed write
/// occurs.
/// @param data Buffer to send.
/// @param size Number of bytes in 'data'.
/// @return false on short or failed write (treat the connection as lost).
bool MockConnection::WriteAll(const unsigned char* data, std::size_t size) {
  if (server_fd_ < 0) {
    return false;
  }
  std::size_t written = 0;
  while (written < size) {
    ssize_t n = ::write(server_fd_, data + written, size - written);
    if (n <= 0) {
      return false;
    }
    written += static_cast<std::size_t>(n);
  }
  return true;
}

/// Drain bytes curl has written. When a backpressure drain limit has been
/// applied (see ApplyBackpressure), stops after drain_limit_ bytes so the
/// kernel recv buffer stays near-full and curl keeps seeing short writes.
/// Otherwise drains until read() returns 0/EAGAIN, matching legacy behaviour.
void MockConnection::DrainIncoming() {
  if (server_fd_ < 0) {
    return;
  }
  unsigned char scratch[4096];
  std::size_t drained = 0;
  while (drain_limit_ == 0 || drained < drain_limit_) {
    std::size_t want = sizeof(scratch);
    if (drain_limit_ != 0) {
      const std::size_t remaining = drain_limit_ - drained;
      if (remaining < want) {
        want = remaining;
      }
    }
    ssize_t n = ::read(server_fd_, scratch, want);
    if (n <= 0) {
      break;
    }
    drained += static_cast<std::size_t>(n);
  }
}

/// Tighten both halves of the socketpair buffer and/or cap DrainIncoming's
/// per-call byte budget. SO_RCVBUF on the server fd caps how much curl can
/// push into the pipe; SO_SNDBUF on the client fd (which curl will soon own
/// but hasn't yet, so we can still tune it) caps how much curl's send() can
/// buffer before short-writing. Linux socketpairs effectively use max(SNDBUF,
/// RCVBUF*2) as pipe capacity, so we need both to see short writes reliably.
/// See header docs.
void MockConnection::ApplyBackpressure(int recv_buf_bytes, std::size_t drain_limit) {
  if (recv_buf_bytes > 0) {
    if (server_fd_ >= 0) {
      (void)setsockopt(server_fd_, SOL_SOCKET, SO_RCVBUF, &recv_buf_bytes, sizeof(recv_buf_bytes));
    }
    if (client_fd_ >= 0) {
      (void)setsockopt(client_fd_, SOL_SOCKET, SO_SNDBUF, &recv_buf_bytes, sizeof(recv_buf_bytes));
    }
  }
  drain_limit_ = drain_limit;
}

/// Non-blocking read: append whatever bytes are currently available on the
/// server fd to 'out'. Used by the WS handshake path to collect curl's HTTP
/// Upgrade request without losing any bytes.
/// @param out Destination buffer; unchanged if no bytes are pending.
void MockConnection::ReadAvailable(std::string* out) {
  if (server_fd_ < 0 || out == nullptr) {
    return;
  }
  unsigned char scratch[4096];
  while (true) {
    ssize_t n = ::read(server_fd_, scratch, sizeof(scratch));
    if (n <= 0) {
      break;
    }
    out->append(reinterpret_cast<const char*>(scratch), static_cast<std::size_t>(n));
  }
}

/// Signal end-of-response to libcurl by half-closing the write side.
void MockConnection::ShutdownWrite() {
  if (server_fd_ < 0) {
    return;
  }
  ::shutdown(server_fd_, SHUT_WR);
}

/// @class proto_fuzzer::MockServer
/// @brief Orchestrates a single mock HTTP exchange: installs the socket callbacks on an easy handle, then feeds queued
/// responses as libcurl reads them.

/// Construct an idle MockServer with no scripted responses. Install() on the
/// base class and DriveScenario() configure it from a Scenario proto.
MockServer::MockServer() : next_chunk_(0), initial_sent_(false) {}

/// Default destructor; the owned MockConnection (if any) cleans up its socketpair.
MockServer::~MockServer() = default;

/// Queue bytes to emit. initial_response is written synchronously in the
/// OPENSOCKETFUNCTION callback (HandleOpenSocket); on_readable entries are
/// written one-at-a-time when libcurl makes the fd readable.
/// @param initial_response Bytes written immediately on connection open.
/// @param on_readable      Additional chunks delivered one per iteration.
void MockServer::SetScript(std::string initial_response, std::vector<std::string> on_readable) {
  initial_response_ = std::move(initial_response);
  on_readable_ = std::move(on_readable);
  next_chunk_ = 0;
  initial_sent_ = false;
}

/// @return true if at least one on_readable chunk has not yet been sent.
bool MockServer::has_more_chunks() const { return next_chunk_ < on_readable_.size(); }

/// Called by the OPENSOCKETFUNCTION trampoline in the base class. Creates the
/// MockConnection, writes initial_response into it, and returns the
/// client-side fd to hand to libcurl.
/// @return the client-side fd to hand to libcurl, or CURL_SOCKET_BAD on
///         failure.
curl_socket_t MockServer::HandleOpenSocket() {
  if (connection_) {
    // This mock supports exactly one connection per scenario.
    return CURL_SOCKET_BAD;
  }
  connection_ = std::make_unique<MockConnection>();
  if (!connection_->ok()) {
    connection_.reset();
    return CURL_SOCKET_BAD;
  }
  ApplyPendingBackpressure();
  if (!initial_response_.empty()) {
    if (!connection_->WriteAll(reinterpret_cast<const unsigned char*>(initial_response_.data()),
                               initial_response_.size())) {
      connection_.reset();
      return CURL_SOCKET_BAD;
    }
  }
  initial_sent_ = true;
  if (on_readable_.empty()) {
    connection_->ShutdownWrite();
  }
  return connection_->take_client_fd();
}

/// Push the next queued chunk. Called by the drive loop when curl is ready
/// for more data. No-op if the queue is empty or no connection is open.
void MockServer::DeliverNextChunk() {
  if (!connection_ || next_chunk_ >= on_readable_.size()) {
    return;
  }
  connection_->DrainIncoming();
  const std::string& chunk = on_readable_[next_chunk_++];
  if (!chunk.empty()) {
    connection_->WriteAll(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
  }
  if (next_chunk_ >= on_readable_.size()) {
    connection_->ShutdownWrite();
  }
}

/// Seed the mock from the scenario, then drive the perform loop until curl is
/// done or the idle-iteration cap is hit. Bounded by select() timeouts so a
/// misbehaving scenario cannot spin forever.
/// @param multi    caller-owned multi; 'easy' is already added.
/// @param easy     the curl easy handle attached to this mock.
/// @param scenario source of the initial_response and on_readable chunks.
void MockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  (void)easy;
  const auto& conn = scenario.connection();
  SetScript(conn.initial_response(), BuildChunkList(conn));

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

    // Always drain whatever curl has written. Under backpressure the kernel
    // recv buffer would otherwise stay full — curl short-writes, the mock
    // never consumes, and the transfer wedges until kMaxIdleIterations. With
    // drain_limit set this still honours the per-tick byte budget.
    if (connection_) {
      connection_->DrainIncoming();
    }
    if (has_more_chunks()) {
      DeliverNextChunk();
      idle_iterations = 0;
    } else if (ready == 0) {
      ++idle_iterations;
    } else {
      idle_iterations = 0;
    }
  }
}

}  // namespace proto_fuzzer
