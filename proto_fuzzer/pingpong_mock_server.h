/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief PingpongMockServer — shared line-oriented command/response transport
///        for the mail-style protocol peers.

#ifndef PROTO_FUZZER_PINGPONG_MOCK_SERVER_H_
#define PROTO_FUZZER_PINGPONG_MOCK_SERVER_H_

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

class MockConnection;

/// @class proto_fuzzer::PingpongMockServer
/// @brief Drives one control socketpair that speaks a line-oriented
///        command/response protocol.
///
/// The base owns the transport lifecycle, the bounded perform loop, line
/// buffering, the reply cursor, and the test-facing transcript. A concrete
/// peer supplies HandleLine() and may switch the parser into body mode after a
/// command that uploads data (SMTP DATA, IMAP APPEND). Replies are emitted
/// exactly as scripted; a peer that needs protocol-specific rewriting, such as
/// IMAP tag insertion, does so inside HandleLine().
///
/// Scenario.connection is a command-aligned script: initial_response is the
/// server greeting and each on_readable entry answers the next command in
/// order. Subclasses replace the transport through CreateConnection(); the
/// implicit-TLS SMTPS peer uses that hook without touching the parser.
class PingpongMockServer : public MockServerBase, public IncomingDataObserver {
 public:
  ~PingpongMockServer() override;

  PingpongMockServer(const PingpongMockServer&) = delete;
  PingpongMockServer& operator=(const PingpongMockServer&) = delete;

  // Bounded record of complete command lines sent by curl.
  const std::string& control_transcript() const;

  // Bounded record of the body most recently drained by a body phase. Peers
  // without an upload direction keep this empty.
  const std::string& uploaded_data() const;

 protected:
  explicit PingpongMockServer(MultiDrivePolicy drive_policy = MultiDrivePolicy::kPerform);

  // Create the transport that carries the exchange. Overridden by TLS peers.
  virtual std::unique_ptr<MockConnection> CreateConnection();

  /// Answer one complete, newline-terminated command line.
  /// @param line Complete command line, including its line ending.
  virtual void HandleLine(std::string_view line) = 0;

  // Body phase control. Only valid while HandleLine() is running; the parser
  // consumes the body before processing further command lines.

  // Consume bytes through the first occurrence of `terminator`, capturing the
  // body and the terminator itself. Used by SMTP's "\r\n.\r\n" end-of-body.
  void BeginMarkerBody(std::string_view terminator);

  // Consume exactly `length` bytes, capturing them, followed by a CRLF line
  // terminator that is not captured. Used by IMAP's {N} literal uploads.
  void BeginLiteralBody(std::size_t length);

  /// Called after a body phase reached its terminator and the parser returned
  /// to command mode. The default does nothing.
  virtual void HandleBodyComplete() {}

  /// Queue protocol-specific teardown liveness bytes before the control socket
  /// is half-closed.
  virtual void QueueShutdownReply() {}

  /// Reset protocol-specific parser state for a new drive. The transport,
  /// cursors, transcript, upload capture, and body phase are already reset.
  virtual void ResetProtocolState() {}

  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

  void HandleDetachedMulti(CurlMultiPtr multi) override;

  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

  /// Borrowed scenario for the synchronous drive, or nullptr outside RunLoop().
  /// @return The Scenario borrowed by the active drive, or nullptr.
  const curl::fuzzer::proto::Scenario* scenario() const { return scenario_; }

  // Return the next command-aligned reply, or nullptr once the bounded script
  // is exhausted. Empty entries still advance the cursor.
  const std::string* NextControlReply();

  // Queue one reply fragment, returning false only when the transport write
  // failed. An empty fragment is a successful no-op.
  bool WriteControlBytes(std::string_view bytes);

  // Write the next scripted reply. Returns false when none remains.
  bool WriteNextReply();

  // First and second whitespace-delimited tokens of a command line, without
  // interpreting any protocol-specific arguments.
  static std::string_view FirstToken(std::string_view line);
  static std::string_view SecondToken(std::string_view line);

  // Compare an ASCII protocol token to an uppercase literal, ignoring case.
  static bool TokenEquals(std::string_view token, std::string_view expected_uppercase);

 private:
  /// Parser mode after the most recent command.
  enum class BodyMode {
    kCommand,  ///< Splitting newline-terminated command lines.
    kMarker,   ///< Scanning for an opaque end-of-body marker.
    kLiteral,  ///< Draining an announced number of bytes, then CRLF.
  };

  // Observability must not grow with a future curl loop; these caps exceed the
  // normalized upload and command budgets without affecting draining.
  static constexpr std::size_t kMaxCapturedControlBytes = 64 * 1024;
  static constexpr std::size_t kMaxCapturedUploadBytes = 2 * scenario_limits::kMaxUploadBytes;

  void ResetForScenario(const curl::fuzzer::proto::Scenario& scenario);

  static void ApplyScriptBackpressure(MockConnection* connection, const curl::fuzzer::proto::Connection& script);

  bool ServiceControlConnection();

  void FinishConnections();

  // Retain a bounded prefix for assertions without affecting parser progress.
  static void CapturePrefix(std::string_view source, std::size_t limit, std::string* destination);

  /// Borrowed only while RunLoop is active, including every socket callback.
  const curl::fuzzer::proto::Scenario* scenario_;
  /// Runtime-visible prefix of on_readable response fragments.
  std::size_t control_reply_count_;
  /// Cursor advanced once per command, plus any pre-queued body completion.
  std::size_t next_control_reply_;
  /// Partial command or body bytes retained until the next read.
  std::string pending_control_bytes_;
  /// Bounded test-facing record of complete commands sent by curl.
  std::string control_transcript_;
  /// Bounded test-facing prefix of the body drained in the last body phase.
  std::string uploaded_data_;
  /// Opaque terminator for BodyMode::kMarker.
  std::string body_marker_;
  /// Literal bytes still to drain for BodyMode::kLiteral.
  std::size_t body_length_remaining_;
  /// Remaining bytes of the CRLF sent after a literal body.
  std::size_t body_terminator_remaining_;
  /// Current parser phase.
  BodyMode body_mode_;
  /// Prevent a second control socket from displacing the live first one.
  bool control_opened_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_PINGPONG_MOCK_SERVER_H_
