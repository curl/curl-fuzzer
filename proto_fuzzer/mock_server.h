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
#include "proto_fuzzer/incoming_data_observer.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

class MockConnection {
 public:
  MockConnection();
  virtual ~MockConnection();

  MockConnection(const MockConnection&) = delete;
  MockConnection& operator=(const MockConnection&) = delete;

  virtual bool ok() const;
  curl_socket_t take_client_fd();
  int server_fd() const;

  std::size_t client_send_buffer_size() const;

  bool EnsureClientSendBufferSize(std::size_t minimum);

  virtual bool WriteAll(const unsigned char* data, std::size_t size);
  virtual std::size_t DrainIncoming();
  void SetIncomingDataObserver(IncomingDataObserver* observer);
  void ReadAvailable(std::string* out);
  virtual void ShutdownWrite();

  void ApplyBackpressure(int recv_buf_bytes, std::size_t drain_limit);

 protected:
  void NotifyIncomingData(const unsigned char* data, std::size_t size);

 private:
  int server_fd_;
  int client_fd_;
  std::size_t drain_limit_;
  IncomingDataObserver* incoming_data_observer_;
};

/// @class proto_fuzzer::MockServer
/// @brief HTTP in-process mock peer. Assigns one bounded response script to
///        each socket curl opens, allowing redirects and authentication
///        retries to progress without permitting an unbounded connection
///        graph. WebSocketMockServer keeps its separate single-socket model.
class MockServer : public MockServerBase {
 public:
  explicit MockServer(MultiDrivePolicy drive_policy = MultiDrivePolicy::kPerform);
  ~MockServer() override;

  void SetScripts(const curl::fuzzer::proto::Scenario& scenario);

  void SetKeepConnectionsOpen(bool keep_open);

  void DriveEasyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario, bool use_events = false) override;

  ConnectOnlyRunStats DriveConnectOnlyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

  bool DeliverNextChunk();
  bool has_more_chunks() const;

  bool ServiceConnections();

  std::size_t opened_connection_count() const;

 protected:
  virtual std::unique_ptr<MockConnection> CreateConnection();

  void ResetConnections();

  virtual void ObserveActiveTransfer(CURL* easy);

  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;
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

  std::size_t DrainIncomingConnections();

  void RunSocketActionLoop(CURLM* multi, CURL* easy);

  std::array<ConnectionScript, scenario_limits::kMaxConnections> scripts_;
  std::size_t script_count_;
  std::size_t next_script_;
  ConnectionScript* active_script_;

  /// True only while HandleOpenSocket is preparing a synchronous easy drive.
  /// Every response chunk must be queued before the callback returns because
  /// curl_easy_perform does not yield control to the mock.
  bool preload_all_chunks_;

  /// Suppress response-side half-close after the final scripted chunk. This
  /// is false for every historical target and enabled only by MultiPlan.
  bool keep_connections_open_;

  /// Old server halves must outlive their active role: libcurl owns the client
  /// fds and may close or briefly revisit them after opening the next socket.
  /// Destroying a MockConnection at that boundary would turn valid lifecycle
  /// traffic into harness-generated ECONNRESET/SIGPIPE behavior.
  std::vector<std::unique_ptr<MockConnection>> previous_connections_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MOCK_SERVER_H_
