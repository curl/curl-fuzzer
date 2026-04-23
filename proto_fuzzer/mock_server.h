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

#include <cstddef>
#include <string>
#include <vector>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/mock_server_base.h"

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
  void DrainIncoming();
  void ReadAvailable(std::string* out);
  void ShutdownWrite();

 private:
  int server_fd_;
  int client_fd_;
};

/// @class proto_fuzzer::MockServer
/// @brief HTTP (and other stream-oriented) in-process mock peer. Writes an
///        optional initial response synchronously on open, then pushes queued
///        chunks one-at-a-time as curl becomes readable. Drives its own
///        curl_multi perform loop via DriveScenario.
class MockServer : public MockServerBase {
 public:
  MockServer();
  ~MockServer() override;

  void SetScript(std::string initial_response, std::vector<std::string> on_readable);

  void DeliverNextChunk();
  bool has_more_chunks() const;

 protected:
  curl_socket_t HandleOpenSocket() override;
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  std::string initial_response_;
  std::vector<std::string> on_readable_;
  std::size_t next_chunk_;
  bool initial_sent_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MOCK_SERVER_H_
