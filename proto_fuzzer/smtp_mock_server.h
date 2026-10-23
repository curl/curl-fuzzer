/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Command-aware in-process peer for curl's SMTP state machine.

#ifndef PROTO_FUZZER_SMTP_MOCK_SERVER_H_
#define PROTO_FUZZER_SMTP_MOCK_SERVER_H_

#include <cstddef>
#include <memory>
#include <string_view>

#include "proto_fuzzer/pingpong_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::SmtpMockServer
/// @brief Services curl's single-connection, line-based SMTP exchange.
///
/// SMTP needs neither a data channel nor a second script per socket: curl
/// sends one command at a time and waits for the matching response. This peer
/// therefore treats Scenario.connection as a client-line-aligned reply script.
/// `initial_response` is the 220 greeting; each `on_readable` entry is the
/// reply to the next command or SASL continuation (EHLO/HELO, AUTH, MAIL FROM,
/// RCPT TO, DATA, and finally the reply after the message body).
///
/// The one exception to the command/reply rhythm is the message body. After a
/// 354 reply to DATA, curl writes the bounded upload script followed by the
/// SMTP end-of-body marker. Those bytes arrive on the same control socket and
/// are not commands, so the shared pingpong transport drains them until it
/// observes "\r\n.\r\n". The post-body 250 is queued at DATA-acceptance time
/// because curl's blocking smtp_done() wait cannot be serviced by the outer
/// loop.
///
/// Subclasses replace the transport through CreateConnection(). The implicit-
/// TLS SMTPS peer uses that hook to wrap the identical command exchange in a
/// verified OpenSSL connection; incoming bytes are observed after transport
/// decoding so the state machine does not depend on the carrier.
class SmtpMockServer : public PingpongMockServer {
 public:
  SmtpMockServer();

  ~SmtpMockServer() override;

  SmtpMockServer(const SmtpMockServer&) = delete;
  SmtpMockServer& operator=(const SmtpMockServer&) = delete;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

  void HandleLine(std::string_view line) override;

  void ResetProtocolState() override;

  void QueueShutdownReply() override;

 private:
  /// The SMTP end-of-body marker curl's dot-stuffing reader appends.
  static constexpr std::string_view kEndOfBody = "\r\n.\r\n";

  /// Liveness reply for curl's blocking QUIT during teardown.
  static constexpr std::string_view kShutdownReply = "221 mock closing SMTP connection\r\n";

  static int FirstReplyCode(std::string_view response);

  bool AllowsRecipientFailures() const;

  /// Number of recipients configured for this drive, bounded by the runtime
  /// limit. Used to recognize the final RCPT TO failure.
  std::size_t recipient_count_;
  /// Number of RCPT TO commands observed in this drive.
  std::size_t rcpt_command_count_;
  /// True after a 334 AUTH reply and until the final authentication reply.
  /// SASL cancellation keeps this set because curl may immediately try
  /// another mechanism on the same connection.
  bool auth_exchange_active_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_SMTP_MOCK_SERVER_H_
