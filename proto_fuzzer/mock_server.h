/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief MockConnection and MockServer — the in-process peer that feeds
///        canned response bytes to libcurl over a socketpair.

#ifndef PROTO_FUZZER_MOCK_SERVER_H_
#define PROTO_FUZZER_MOCK_SERVER_H_

#include <curl/curl.h>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

class MockConnection {
 public:
  MockConnection();
  ~MockConnection();

  MockConnection(const MockConnection&) = delete;
  MockConnection& operator=(const MockConnection&) = delete;

  bool ok() const;
  curl_socket_t take_client_fd();
  int server_fd() const;

  bool WriteAll(const unsigned char* data, std::size_t size);
  /// Drain bytes curl has written according to the configured per-call limit.
  /// @return number of bytes consumed during this call.
  std::size_t DrainIncoming();
  void ReadAvailable(std::string* out);
  void ShutdownWrite();

  /// Apply deterministic backpressure knobs. Set SO_RCVBUF on the server
  /// side (if recv_buf_bytes > 0) to cap how much curl can write before it
  /// short-writes / EAGAINs, and cap DrainIncoming()'s per-call byte budget
  /// (0 = unlimited). Must be called before any traffic for the recv_buf
  /// setting to matter.
  /// @param recv_buf_bytes SO_RCVBUF size in bytes, or 0 to leave default.
  /// @param drain_limit    Max bytes drained per DrainIncoming call, 0 for unlimited.
  void ApplyBackpressure(int recv_buf_bytes, std::size_t drain_limit);

 private:
  int server_fd_;
  int client_fd_;
  std::size_t drain_limit_;
};

/// @class proto_fuzzer::MockServer
/// @brief HTTP in-process mock peer. Assigns one bounded response script to
///        each socket curl opens, allowing redirects and authentication
///        retries to progress without permitting an unbounded connection
///        graph. WebSocketMockServer keeps its separate single-socket model.
class MockServer : public MockServerBase {
 public:
  MockServer();
  ~MockServer() override;

  /// Borrow the primary and bounded follow-on HTTP scripts from `scenario`.
  /// The caller must keep the scenario alive and unmodified until the current
  /// synchronous drive has finished. ScenarioRunner already provides exactly
  /// that lifetime, so retaining pointers avoids copying response bytes before
  /// curl has even requested the corresponding socket or chunk.
  void SetScripts(const curl::fuzzer::proto::Scenario& scenario);

  /// Deliver one queued response chunk.
  /// @return true when a chunk was consumed from the script.
  bool DeliverNextChunk();
  bool has_more_chunks() const;

 protected:
  curl_socket_t HandleOpenSocket() override;
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// One socket's borrowed response configuration plus its delivery cursor.
  /// The fixed script array is fully populated before curl runs, so both this
  /// object and its pointer into the caller-owned Scenario remain stable across
  /// callbacks. Counts record the exact runtime-visible prefix: raw chunks come
  /// first and structured frames consume only the remaining shared budget.
  struct ConnectionScript {
    const curl::fuzzer::proto::Connection* connection = nullptr;
    std::size_t raw_chunk_count = 0;
    std::size_t frame_chunk_count = 0;
    std::size_t next_chunk = 0;

    /// @return Number of raw and structured chunks visible to the runtime.
    std::size_t chunk_count() const { return raw_chunk_count + frame_chunk_count; }
  };

  /// Drain client request bytes from both the current socket and sockets curl
  /// has moved past. Keeping old peers responsive prevents a late write/close
  /// on a redirect source connection from stalling the new exchange.
  /// @return total bytes drained during this call.
  std::size_t DrainIncomingConnections();

  std::array<ConnectionScript, scenario_limits::kMaxConnections> scripts_;
  std::size_t script_count_;
  std::size_t next_script_;
  ConnectionScript* active_script_;

  /// Old server halves must outlive their active role: libcurl owns the client
  /// fds and may close or briefly revisit them after opening the next socket.
  /// Destroying a MockConnection at that boundary would turn valid lifecycle
  /// traffic into harness-generated ECONNRESET/SIGPIPE behavior.
  std::vector<std::unique_ptr<MockConnection>> previous_connections_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MOCK_SERVER_H_
