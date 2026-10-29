/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Command-aware in-process peer for curl's POP3 state machine.

#ifndef PROTO_FUZZER_POP3_MOCK_SERVER_H_
#define PROTO_FUZZER_POP3_MOCK_SERVER_H_

#include <string_view>

#include "proto_fuzzer/pingpong_mock_server.h"

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
///
/// Subclasses replace the transport through CreateConnection(). The implicit-
/// TLS POP3S peer uses that hook to wrap the identical status-line exchange in
/// a verified OpenSSL connection without changing the parser.
class Pop3MockServer : public PingpongMockServer {
 public:
  Pop3MockServer();

  ~Pop3MockServer() override;

  void ObserveState() override;

  Pop3MockServer(const Pop3MockServer&) = delete;
  Pop3MockServer& operator=(const Pop3MockServer&) = delete;

 protected:
  void HandleLine(std::string_view line) override;

  void QueueShutdownReply() override;

 private:
  /// Liveness reply for curl's blocking QUIT during teardown.
  static constexpr std::string_view kShutdownReply = "+OK mock closing POP3 connection\r\n";
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_POP3_MOCK_SERVER_H_
