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
#include <memory>
#include <string>
#include <vector>

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
  void ShutdownWrite();

 private:
  int server_fd_;
  int client_fd_;
};

class MockServer {
 public:
  MockServer();
  ~MockServer();

  MockServer(const MockServer&) = delete;
  MockServer& operator=(const MockServer&) = delete;

  void Install(CURL* easy);

  void SetScript(std::string initial_response, std::vector<std::string> on_readable);

  void DeliverNextChunk();

  bool has_more_chunks() const;
  MockConnection* connection();

  curl_socket_t HandleOpenSocket();

 private:
  std::unique_ptr<MockConnection> connection_;
  std::string initial_response_;
  std::vector<std::string> on_readable_;
  std::size_t next_chunk_;
  bool initial_sent_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MOCK_SERVER_H_
