/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the command-aware in-process SMTP peer.

#include "proto_fuzzer/smtp_mock_server.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// Begin without a borrowed protobuf or open socketpair. RunLoop borrows a
/// Scenario only for the synchronous DriveScenario call in which socket
/// callbacks can run.
SmtpMockServer::SmtpMockServer()
    : scenario_(nullptr),
      control_reply_count_(0),
      next_control_reply_(0),
      recipient_count_(0),
      rcpt_command_count_(0),
      draining_body_(false),
      control_opened_(false) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
SmtpMockServer::~SmtpMockServer() = default;

/// Expose the bounded command capture from the most recent drive so tests can
/// verify SMTP states without coupling assertions to curl debug output.
/// @return A prefix of complete control commands, including line endings.
const std::string& SmtpMockServer::control_transcript() const { return control_transcript_; }

/// Expose a bounded prefix of the DATA body while continuing to drain every
/// client byte, so test observability cannot create backpressure.
/// @return Body bytes curl sent during the most recent DATA phase, including
///         the terminating "\r\n.\r\n" marker.
const std::string& SmtpMockServer::uploaded_data() const { return uploaded_data_; }

/// Reset every borrowed pointer, descriptor, parser cursor, and observable
/// capture before borrowing the next Scenario.
/// @param scenario Scenario whose Connection supplies the greeting and replies.
void SmtpMockServer::ResetForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  connection_.reset();
  scenario_ = &scenario;
  control_reply_count_ = std::min<std::size_t>(scenario_limits::kMaxResponseChunks,
                                               static_cast<std::size_t>(scenario.connection().on_readable_size()));
  next_control_reply_ = 0;
  recipient_count_ =
      std::min<std::size_t>(scenario_limits::kMaxMailRecipients, static_cast<std::size_t>(scenario.mail_rcpt_size()));
  rcpt_command_count_ = 0;
  pending_control_bytes_.clear();
  control_transcript_.clear();
  uploaded_data_.clear();
  draining_body_ = false;
  control_opened_ = false;
}

/// Apply bounded transport knobs when creating the scripted socket. Target
/// policies normally clear SMTP backpressure, but direct corpus replay must
/// retain deterministic, well-defined behavior.
/// @param connection Peer receiving the socket settings.
/// @param script Connection script carrying optional backpressure values.
void SmtpMockServer::ApplyScriptBackpressure(MockConnection* connection,
                                             const curl::fuzzer::proto::Connection& script) {
  if (connection == nullptr) {
    return;
  }

  const std::uint32_t int_max = static_cast<std::uint32_t>(std::numeric_limits<int>::max());
  const auto& backpressure = script.backpressure();
  const int receive_buffer = static_cast<int>(std::min(backpressure.recv_buf_bytes(), int_max));
  connection->ApplyBackpressure(receive_buffer, static_cast<std::size_t>(backpressure.drain_limit()));
}

/// Create the single control socketpair and queue the server greeting. SMTP
/// never opens a second application socket, so any later request is rejected
/// rather than silently replacing the live peer.
/// @param purpose Socket role requested by curl.
/// @param address Unused stream destination metadata required by the callback
///                signature.
/// @return Client descriptor for the control channel, or CURL_SOCKET_BAD.
curl_socket_t SmtpMockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* /*address*/) {
  if (scenario_ == nullptr || purpose != CURLSOCKTYPE_IPCXN || control_opened_) {
    return CURL_SOCKET_BAD;
  }

  connection_ = std::make_unique<MockConnection>();
  if (!connection_->ok()) {
    connection_.reset();
    return CURL_SOCKET_BAD;
  }

  ApplyScriptBackpressure(connection_.get(), scenario_->connection());
  const std::string& greeting = scenario_->connection().initial_response();
  if (!greeting.empty() &&
      !connection_->WriteAll(reinterpret_cast<const unsigned char*>(greeting.data()), greeting.size())) {
    connection_.reset();
    return CURL_SOCKET_BAD;
  }

  control_opened_ = true;
  return connection_->take_client_fd();
}

/// Return whether the effective option list enables curl's
/// CURLOPT_MAIL_RCPT_ALLOWFAILS behavior. Scan backwards because repeated
/// setopt calls are legal and libcurl keeps the last value.
/// @return true when recipient errors may be followed by another RCPT TO.
bool SmtpMockServer::AllowsRecipientFailures() const {
  if (scenario_ == nullptr) {
    return false;
  }
  for (int index = scenario_->options_size() - 1; index >= 0; --index) {
    const auto& option = scenario_->options(index);
    if (option.option_id() != curl::fuzzer::proto::CURLOPT_MAIL_RCPT_ALLOWFAILS) {
      continue;
    }
    if (option.value_case() == curl::fuzzer::proto::SetOption::kBoolValue) {
      return option.bool_value();
    }
    if (option.value_case() == curl::fuzzer::proto::SetOption::kUintValue) {
      return option.uint_value() != 0;
    }
    return false;
  }
  return false;
}

/// Retain only a bounded prefix for assertions. Parsing and draining continue
/// against the full transport bytes, so reaching the cap cannot change curl's
/// behavior or manufacture socket backpressure.
/// @param source Newly observed bytes.
/// @param limit Maximum retained destination size.
/// @param destination Capture buffer receiving the available prefix.
void SmtpMockServer::CapturePrefix(std::string_view source, std::size_t limit, std::string* destination) {
  if (destination == nullptr || destination->size() >= limit) {
    return;
  }
  const std::size_t available = limit - destination->size();
  destination->append(source.data(), std::min(source.size(), available));
}

/// Remove SMTP's optional leading horizontal whitespace and return just the
/// verb without allocating. Arguments remain untouched because only curl, not
/// the mock harness, should interpret fuzzed addresses and commands.
/// @param command Complete command line.
/// @return View of its first non-whitespace token.
std::string_view SmtpMockServer::CommandVerb(std::string_view command) {
  std::size_t begin = 0;
  while (begin < command.size() && (command[begin] == ' ' || command[begin] == '\t')) {
    ++begin;
  }

  std::size_t end = begin;
  while (end < command.size() && command[end] != ' ' && command[end] != '\t' && command[end] != '\r' &&
         command[end] != '\n') {
    ++end;
  }
  return command.substr(begin, end - begin);
}

/// Fold only ASCII lowercase command letters. SMTP verbs are ASCII tokens, so
/// locale-aware case conversion would add state and undefined signed-char
/// behavior without accepting anything curl can legitimately send.
/// @param verb Parsed command token.
/// @param expected_uppercase Literal uppercase command name.
/// @return true when the verbs are equal ignoring ASCII case.
bool SmtpMockServer::VerbEquals(std::string_view verb, std::string_view expected_uppercase) {
  if (verb.size() != expected_uppercase.size()) {
    return false;
  }
  for (std::size_t index = 0; index < verb.size(); ++index) {
    unsigned char actual = static_cast<unsigned char>(verb[index]);
    if (actual >= 'a' && actual <= 'z') {
      actual = static_cast<unsigned char>(actual - 'a' + 'A');
    }
    if (actual != static_cast<unsigned char>(expected_uppercase[index])) {
      return false;
    }
  }
  return true;
}

/// Scan complete lines because a legal SMTP response fragment may start with
/// one or more informational lines. curl ends a response at the first line
/// whose first three bytes are digits and whose fourth byte is a space.
/// @param response Raw control fragment.
/// @return numeric status, or -1 when no terminating line is present.
int SmtpMockServer::FirstReplyCode(std::string_view response) {
  std::size_t line_start = 0;
  while (line_start < response.size()) {
    const std::size_t newline = response.find('\n', line_start);
    if (newline == std::string_view::npos) {
      return -1;
    }
    const std::size_t line_size = newline - line_start + 1;
    if (line_size > 3) {
      const unsigned char first = static_cast<unsigned char>(response[line_start]);
      const unsigned char second = static_cast<unsigned char>(response[line_start + 1]);
      const unsigned char third = static_cast<unsigned char>(response[line_start + 2]);
      if (first >= '0' && first <= '9' && second >= '0' && second <= '9' && third >= '0' && third <= '9' &&
          response[line_start + 3] == ' ') {
        return 100 * (first - '0') + 10 * (second - '0') + (third - '0');
      }
    }
    line_start = newline + 1;
  }
  return -1;
}

/// Return the next command-aligned response within the shared response-count
/// budget. Empty strings still advance the cursor: they are meaningful
/// truncation mutations for ordinary command states.
/// @return Scenario-owned reply, or nullptr after the bounded prefix.
const std::string* SmtpMockServer::NextControlReply() {
  if (scenario_ == nullptr || next_control_reply_ >= control_reply_count_) {
    return nullptr;
  }
  return &scenario_->connection().on_readable(static_cast<int>(next_control_reply_++));
}

/// Keep failed peer writes local to the mock. Response cursors must still
/// advance after curl closes early, otherwise a replacement socket could see
/// a reply intended for an earlier command.
/// @param bytes Response fragment to queue.
/// @return true when the complete fragment was queued.
bool SmtpMockServer::WriteControlBytes(std::string_view bytes) {
  return bytes.empty() || (connection_ != nullptr &&
                           connection_->WriteAll(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
}

/// Consume the reply that follows the DATA body. Curl's smtp_done() enters a
/// blocking POSTDATA wait after uploading, so the peer must queue this reply as
/// soon as it accepts DATA. The fuzzed 250 (or error) still decides curl's
/// outcome; a missing script leaves the transfer to the bounded idle budget
/// and the final half-close.
/// @return true when a queued reply was successfully written.
bool SmtpMockServer::WriteNextReply() {
  const std::string* response = NextControlReply();
  return response == nullptr ? false : WriteControlBytes(*response);
}

/// Advance one reply for every complete command. A successful DATA reply
/// switches the parser into body-draining mode. The reply that follows DATA is
/// queued immediately: curl's smtp_done() runs a blocking POSTDATA wait inside
/// curl_multi_perform, so the outer peer service loop cannot run after the body
/// has been written. Pre-queuing it, as the FTP peer does for its final
/// transfer reply, keeps that wait deterministic without changing the order
/// curl observes (354 first, then the post-body response).
/// @param command One newline-terminated command from curl.
void SmtpMockServer::HandleControlCommand(std::string_view command) {
  const std::string* response = NextControlReply();
  if (response == nullptr) {
    return;
  }

  const int response_code = FirstReplyCode(*response);
  (void)WriteControlBytes(*response);

  const std::string_view verb = CommandVerb(command);
  if (VerbEquals(verb, "DATA")) {
    if (response_code == 354) {
      draining_body_ = true;
      (void)WriteNextReply();
    } else if (response_code > 0) {
      // curl treats every non-354 DATA reply as terminal. Pre-queue the
      // shutdown reply so its blocking cleanup QUIT does not wait one second.
      (void)WriteControlBytes(kShutdownReply);
    }
    return;
  }

  if (VerbEquals(verb, "RCPT")) {
    ++rcpt_command_count_;
  }

  // A terminal command error is followed by curl's blocking QUIT during
  // teardown. EHLO errors fall back to HELO, and an early RCPT error may still
  // be followed by another recipient, so those replies must not consume the
  // shutdown reply. Everything else can safely see a queued 221 next.
  const bool final_rcpt_error =
      VerbEquals(verb, "RCPT") && (rcpt_command_count_ >= recipient_count_ || !AllowsRecipientFailures());
  const bool terminal_error =
      response_code >= 400 && !VerbEquals(verb, "EHLO") && (!VerbEquals(verb, "RCPT") || final_rcpt_error);
  if (terminal_error) {
    (void)WriteControlBytes(kShutdownReply);
  }
}

/// Read without waiting, retain partial final commands, and process all full
/// lines already emitted by curl. After an accepted DATA command the same
/// buffer is interpreted as message body until "\r\n.\r\n" is observed.
/// @return true when bytes or a command/reply cursor advanced.
bool SmtpMockServer::ServiceControlConnection() {
  if (connection_ == nullptr) {
    return false;
  }

  const std::size_t size_before_read = pending_control_bytes_.size();
  connection_->ReadAvailable(&pending_control_bytes_);
  bool made_progress = pending_control_bytes_.size() != size_before_read;

  std::size_t consumed = 0;
  while (consumed < pending_control_bytes_.size()) {
    if (draining_body_) {
      const std::size_t eob = pending_control_bytes_.find(kEndOfBody.data(), consumed, kEndOfBody.size());
      if (eob == std::string::npos) {
        break;
      }
      const std::size_t body_end = eob + kEndOfBody.size();
      CapturePrefix(std::string_view(pending_control_bytes_.data() + consumed, body_end - consumed),
                    kMaxCapturedUploadBytes, &uploaded_data_);
      consumed = body_end;
      draining_body_ = false;
      made_progress = true;
      continue;
    }

    const std::size_t newline = pending_control_bytes_.find('\n', consumed);
    if (newline == std::string::npos) {
      break;
    }
    const std::size_t command_size = newline - consumed + 1;
    const std::string_view command(pending_control_bytes_.data() + consumed, command_size);
    CapturePrefix(command, kMaxCapturedControlBytes, &control_transcript_);
    HandleControlCommand(command);
    consumed += command_size;
    made_progress = true;
  }

  if (consumed != 0) {
    pending_control_bytes_.erase(0, consumed);
  }
  return made_progress;
}

/// Prepare cleanup while the mock can still write to curl's control socket.
/// Always queue a 221: even an unfinished transfer can enter curl's graceful
/// shutdown after a protocol error, and SMTP's blocking QUIT read has a
/// one-second timeout when no reply is available. The synthetic reply is only
/// a liveness guard; any real scripted response already consumed by curl still
/// determines the transfer result.
void SmtpMockServer::FinishConnections() {
  if (connection_ != nullptr) {
    (void)WriteControlBytes(kShutdownReply);
    connection_->ShutdownWrite();
  }
}

/// Give curl's graceful shutdown one last chance to emit QUIT while the peer
/// still owns its read half, then release the multi as the base class would.
/// The matching 221 was already queued by FinishConnections.
/// @param multi Detached multi handle whose connection cache may be shutting
///              the protocol connection down.
void SmtpMockServer::HandleDetachedMulti(CurlMultiPtr multi) {
  multi.reset();
  (void)ServiceControlConnection();
}
/// Alternate curl transitions with immediate peer service until the transfer
/// completes or deterministic idle/operation caps win. No select(), poll(), or
/// sleep is needed: every transport is in-process, and malformed scripts are
/// terminated by half-close after the bounded loop.
/// @param multi Multi handle containing `easy`.
/// @param easy Easy handle already installed on this mock.
/// @param scenario Control script to borrow.
void SmtpMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  (void)easy;
  ResetForScenario(scenario);

  int still_running = 1;
  int idle_iterations = 0;
  int drive_iterations = 0;
  CURLMcode result = CURLM_OK;
  while (still_running && idle_iterations < kMaxIdleIterations && drive_iterations++ < kMaxDriveIterations) {
    const int running_before = still_running;
    result = curl_multi_perform(multi, &still_running);
    if (result != CURLM_OK) {
      break;
    }

    bool made_progress = still_running != running_before;
    made_progress = ServiceControlConnection() || made_progress;
    if (made_progress) {
      idle_iterations = 0;
    } else {
      ++idle_iterations;
    }
  }

  // The final perform may have emitted the last command or body bytes
  // immediately before marking the transfer done. Drain them before cleanup.
  (void)ServiceControlConnection();
  FinishConnections();
  scenario_ = nullptr;
}

}  // namespace proto_fuzzer
