/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Command-aware in-process peer for curl's SMTP state machine.

#ifndef PROTO_FUZZER_SMTP_MOCK_SERVER_H_
#define PROTO_FUZZER_SMTP_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/incoming_data_observer.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::SmtpMockServer
/// @brief Services curl's single-connection, line-based SMTP exchange.
///
/// SMTP needs neither a data channel nor a second script per socket: curl
/// sends one command at a time and waits for the matching response. This peer
/// therefore treats Scenario.connection as a command-aligned reply script.
/// `initial_response` is the 220 greeting; each `on_readable` entry is the
/// reply to the next command (EHLO/HELO, MAIL FROM, RCPT TO, DATA, and finally
/// the reply after the message body).
///
/// The one exception to the command/reply rhythm is the message body. After a
/// 354 reply to DATA, curl writes the bounded upload script followed by the
/// SMTP end-of-body marker. Those bytes arrive on the same control socket and
/// are not commands, so the peer drains them until it observes "\r\n.\r\n".
/// The post-body 250 is queued at DATA-acceptance time because curl's blocking
/// smtp_done() wait cannot be serviced by the outer loop.
///
/// Subclasses replace the transport through CreateConnection(). The implicit-
/// TLS SMTPS peer uses that hook to wrap the identical command exchange in a
/// verified OpenSSL connection; incoming bytes are observed after transport
/// decoding so the state machine does not depend on the carrier.
class SmtpMockServer : public MockServerBase, public IncomingDataObserver {
 public:
  SmtpMockServer();

  ~SmtpMockServer() override;

  SmtpMockServer(const SmtpMockServer&) = delete;
  SmtpMockServer& operator=(const SmtpMockServer&) = delete;

  // Bounded record of complete command lines sent by curl.
  const std::string& control_transcript() const;

  // Bounded record of the message body, including the terminating EOB.
  const std::string& uploaded_data() const;

 protected:
  virtual std::unique_ptr<MockConnection> CreateConnection();

  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

  void HandleDetachedMulti(CurlMultiPtr multi) override;

  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

 private:
  /// The SMTP end-of-body marker curl's dot-stuffing reader appends.
  static constexpr std::string_view kEndOfBody = "\r\n.\r\n";

  /// Liveness reply for curl's blocking QUIT during teardown.
  static constexpr std::string_view kShutdownReply = "221 mock closing SMTP connection\r\n";

  /// Observability must not grow with a future curl loop; these caps exceed
  /// the normalized upload and command budgets without affecting draining.
  static constexpr std::size_t kMaxCapturedControlBytes = 64 * 1024;
  static constexpr std::size_t kMaxCapturedUploadBytes = 2 * scenario_limits::kMaxUploadBytes;

  void ResetForScenario(const curl::fuzzer::proto::Scenario& scenario);

  static void ApplyScriptBackpressure(MockConnection* connection, const curl::fuzzer::proto::Connection& script);

  bool ServiceControlConnection();

  void HandleControlCommand(std::string_view command);

  // Consume the reply that completes the mail; queued when DATA is accepted.
  bool WriteNextReply();
  const std::string* NextControlReply();

  bool WriteControlBytes(std::string_view bytes);

  static std::string_view CommandVerb(std::string_view command);

  static bool VerbEquals(std::string_view verb, std::string_view expected_uppercase);

  static int FirstReplyCode(std::string_view response);

  bool AllowsRecipientFailures() const;

  static void CapturePrefix(std::string_view source, std::size_t limit, std::string* destination);

  void FinishConnections();

  /// Borrowed only while RunLoop is active, including every socket callback.
  const curl::fuzzer::proto::Scenario* scenario_;
  /// Runtime-visible prefix of primary on_readable response fragments.
  std::size_t control_reply_count_;
  /// Cursor advanced once per command, plus the post-body reply queued with
  /// the accepted DATA command.
  std::size_t next_control_reply_;
  /// Number of recipients configured for this drive, bounded by the runtime
  /// limit. Used to recognize the final RCPT TO failure.
  std::size_t recipient_count_;
  /// Number of RCPT TO commands observed in this drive.
  std::size_t rcpt_command_count_;
  /// Partial command or body bytes retained until the next read.
  std::string pending_control_bytes_;
  /// Bounded test-facing record of complete commands sent by curl.
  std::string control_transcript_;
  /// Bounded test-facing prefix of the DATA body, including its EOB.
  std::string uploaded_data_;
  /// DATA has been accepted; incoming bytes are body content, not commands.
  bool draining_body_;
  /// Prevent a second control socket from displacing the live first one.
  bool control_opened_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_SMTP_MOCK_SERVER_H_
