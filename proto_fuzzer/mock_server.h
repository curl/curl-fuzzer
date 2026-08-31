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

  /// Return the capacity curl's endpoint reports for queued client writes.
  /// Protocol mocks use this before transferring fd ownership when their
  /// synchronous send path cannot rely on the outer driver to make room.
  /// @return SO_SNDBUF in bytes, or zero when it cannot be queried.
  std::size_t client_send_buffer_size() const;

  /// Ensure curl's endpoint reports at least `minimum` bytes of send buffer,
  /// requesting a larger SO_SNDBUF when the platform default is smaller.
  /// @param minimum Smallest acceptable reported capacity in bytes.
  /// @return true when the queried postcondition holds.
  bool EnsureClientSendBufferSize(std::size_t minimum);

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

  /// Preload the bounded HTTP response, half-close the peer, and invoke
  /// curl_easy_perform. This avoids a helper thread while guaranteeing that
  /// curl never waits for the outer chunk-delivery loop.
  void DriveEasyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

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

  /// Service one deterministic application event-loop turn by draining all
  /// request bytes currently available and releasing at most one response
  /// chunk. Both multi APIs use this ordering so selecting socket_action
  /// changes only how readiness reaches curl, not the mock protocol script.
  /// @return true when any request or response byte advanced.
  bool ServiceConnections();

  /// Drive the HTTP exchange through curl_multi_socket_action using the
  /// callback state owned by MockServerBase::DriveScenario.
  /// @param multi Multi handle containing `easy`.
  /// @return after curl finishes or a deterministic idle/operation cap wins.
  void RunSocketActionLoop(CURLM* multi);

  std::array<ConnectionScript, scenario_limits::kMaxConnections> scripts_;
  std::size_t script_count_;
  std::size_t next_script_;
  ConnectionScript* active_script_;

  /// True only while HandleOpenSocket is preparing a synchronous easy drive.
  /// Every response chunk must be queued before the callback returns because
  /// curl_easy_perform does not yield control to the mock.
  bool preload_all_chunks_;

  /// Old server halves must outlive their active role: libcurl owns the client
  /// fds and may close or briefly revisit them after opening the next socket.
  /// Destroying a MockConnection at that boundary would turn valid lifecycle
  /// traffic into harness-generated ECONNRESET/SIGPIPE behavior.
  std::vector<std::unique_ptr<MockConnection>> previous_connections_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MOCK_SERVER_H_
