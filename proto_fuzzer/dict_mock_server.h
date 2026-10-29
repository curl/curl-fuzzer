/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Command-aware in-process peer for curl's DICT request/response.

#ifndef PROTO_FUZZER_DICT_MOCK_SERVER_H_
#define PROTO_FUZZER_DICT_MOCK_SERVER_H_

#include <string_view>

#include "proto_fuzzer/pingpong_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::DictMockServer
/// @brief Services curl's single-connection, line-based DICT exchange.
///
/// curl's DICT handler writes its complete request in one send: a CLIENT
/// identification line, one lookup command (DEFINE, MATCH, SHOW, or a raw
/// command derived from the URL path), then QUIT. It then reads the response
/// as an unbounded byte stream, so the server half-closes the write side after
/// the scripted body to make the next perform observe end-of-response.
///
/// Scenario.connection has no greeting in this protocol. `initial_response`
/// is normally empty, and the first non-CLIENT/non-QUIT `on_readable` entry is
/// the complete multi-line response body, including the RFC 2229 `.\r\n`
/// terminator when the seed wants one. Remaining entries are unused because
/// curl never waits for a per-command reply.
class DictMockServer : public PingpongMockServer {
 public:
  DictMockServer();

  ~DictMockServer() override;

  void ObserveState() override;

  DictMockServer(const DictMockServer&) = delete;
  DictMockServer& operator=(const DictMockServer&) = delete;

  void Install(CURL* easy) override;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

  void HandleLine(std::string_view line) override;

  void ResetProtocolState() override;

 private:
  void FinishResponse();

  /// True after the scripted response body was written or the script was
  /// exhausted for the current drive.
  bool reply_sent_;
  /// True after the write side was half-closed for the current drive.
  bool write_closed_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_DICT_MOCK_SERVER_H_
