/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Command-aware in-process peer for curl's POP3 state machine.

#ifndef PROTO_FUZZER_POP3_MOCK_SERVER_H_
#define PROTO_FUZZER_POP3_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::Pop3MockServer
/// @brief Services curl's single-connection, line-based POP3 exchange.
///
/// POP3 has no data channel and no command tags. Curl sends one command at a
/// time and waits for a `+OK` or `-ERR` status line, so this peer treats
/// Scenario.connection as a command-aligned reply script. `initial_response` is
/// the greeting; each `on_readable` entry answers the next command (CAPA,
/// USER/PASS, APOP, AUTH, LIST, RETR, DELE, or a custom request).
///
/// Multi-line replies are ordinary script bytes. A CAPA or LIST reply includes
/// its terminating `.\r\n`, while RETR supplies the message body before the
/// same terminator. Curl's POP3 reader strips dot-stuffing and detects the end
/// of the body itself, so the peer writes the complete bounded script as soon
/// as the command arrives.
class Pop3MockServer final : public MockServerBase {
 public:
  Pop3MockServer();

  ~Pop3MockServer() override;

  Pop3MockServer(const Pop3MockServer&) = delete;
  Pop3MockServer& operator=(const Pop3MockServer&) = delete;

  // Bounded record of complete command lines sent by curl.
  const std::string& control_transcript() const;

  // POP3 has no upload direction. Present for a uniform peer observation API.
  const std::string& uploaded_data() const;

 protected:
  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

  void HandleDetachedMulti(CurlMultiPtr multi) override;

 private:
  /// Liveness reply for curl's blocking QUIT during teardown.
  static constexpr std::string_view kShutdownReply = "+OK mock closing POP3 connection\r\n";

  /// Observability must not grow with a future curl command loop.
  static constexpr std::size_t kMaxCapturedControlBytes = 64 * 1024;

  void ResetForScenario(const curl::fuzzer::proto::Scenario& scenario);

  static void ApplyScriptBackpressure(MockConnection* connection, const curl::fuzzer::proto::Connection& script);

  bool ServiceControlConnection();

  void HandleControlCommand(std::string_view command);

  const std::string* NextControlReply();

  bool WriteControlBytes(std::string_view bytes);

  static void CapturePrefix(std::string_view source, std::size_t limit, std::string* destination);

  void FinishConnections();

  /// Borrowed only while RunLoop is active, including every socket callback.
  const curl::fuzzer::proto::Scenario* scenario_;
  /// Runtime-visible prefix of on_readable response fragments.
  std::size_t control_reply_count_;
  /// Cursor advanced once per command.
  std::size_t next_control_reply_;
  /// Partial command bytes retained until the next read.
  std::string pending_control_bytes_;
  /// Bounded test-facing record of complete commands sent by curl.
  std::string control_transcript_;
  /// Kept empty so observation code can treat both mail peers uniformly.
  std::string uploaded_data_;
  /// Prevent a second control socket from displacing the live first one.
  bool control_opened_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_POP3_MOCK_SERVER_H_
