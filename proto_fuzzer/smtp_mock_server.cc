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
#include <memory>
#include <string>
#include <string_view>

#include "proto_fuzzer/allocation_fault_injection.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// Begin without a borrowed protobuf or open socketpair. RunLoop borrows a
/// Scenario only for the synchronous DriveScenario call in which socket
/// callbacks can run.
/// @param mode Closed SMTP transport probe selected by target policy.
SmtpMockServer::SmtpMockServer(curl::fuzzer::proto::SmtpProbeMode mode)
    : recipient_count_(0),
      rcpt_command_count_(0),
      auth_exchange_active_(false),
      mode_(mode),
      tls_upgrade_started_(false) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
SmtpMockServer::~SmtpMockServer() = default;

namespace {

/// A fixed command large enough to leave curl's pingpong send queue pending
/// under the probe's bounded receive-buffer pressure.
/// @return Process-lifetime command bytes copied by CURLOPT_CUSTOMREQUEST.
const std::string& SendBackpressureCommand() {
  static const std::string command = "NOOP " + std::string(16 * 1024, 'S');
  return command;
}

}  // namespace

/// Apply only closed, harness-owned client controls. The ordinary scenario
/// option list has already run when the production runner calls this hook.
/// @param easy Easy handle configured for the SMTP transfer.
void SmtpMockServer::ConfigureClient(CURL* easy) const {
  if (easy == nullptr) {
    return;
  }
  switch (mode_) {
    case curl::fuzzer::proto::SMTP_PROBE_STARTTLS_TRY:
      (void)curl_easy_setopt(easy, CURLOPT_USE_SSL, static_cast<long>(CURLUSESSL_TRY));
      break;
    case curl::fuzzer::proto::SMTP_PROBE_STARTTLS_REQUIRE:
    case curl::fuzzer::proto::SMTP_PROBE_STARTTLS_FILTER_ALLOCATION_FAILURE:
      (void)curl_easy_setopt(easy, CURLOPT_USE_SSL, static_cast<long>(CURLUSESSL_ALL));
      break;
    case curl::fuzzer::proto::SMTP_PROBE_SEND_BACKPRESSURE:
      (void)curl_easy_setopt(easy, CURLOPT_UPLOAD, 0L);
      (void)curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, SendBackpressureCommand().c_str());
      break;
    case curl::fuzzer::proto::SMTP_PROBE_DEFAULT:
    default:
      break;
  }
}

/// Create the default plaintext transport for the SMTP exchange. The SMTPS
/// subclass overrides this factory while retaining the command/reply parser.
/// @return A new socketpair-backed connection.
std::unique_ptr<MockConnection> SmtpMockServer::CreateConnection() { return std::make_unique<MockConnection>(); }

/// Reset SMTP's recipient bookkeeping for a new drive. The shared base has
/// already cleared the transport, reply cursor, transcript, upload capture,
/// and any in-flight body phase.
void SmtpMockServer::ResetProtocolState() {
  const curl::fuzzer::proto::Scenario* script = scenario();
  recipient_count_ = script == nullptr ? 0
                                       : std::min<std::size_t>(scenario_limits::kMaxMailRecipients,
                                                               static_cast<std::size_t>(script->mail_rcpt_size()));
  rcpt_command_count_ = 0;
  auth_exchange_active_ = false;
  tls_upgrade_started_ = false;
}

/// Return whether the selected probe asks curl to issue STARTTLS.
/// @return true when STARTTLS is enabled by the closed probe mode.
bool SmtpMockServer::IsStartTlsMode() const {
  return mode_ == curl::fuzzer::proto::SMTP_PROBE_STARTTLS_TRY ||
         mode_ == curl::fuzzer::proto::SMTP_PROBE_STARTTLS_REQUIRE ||
         mode_ == curl::fuzzer::proto::SMTP_PROBE_STARTTLS_FILTER_ALLOCATION_FAILURE;
}

/// Return whether the effective option list enables curl's
/// CURLOPT_MAIL_RCPT_ALLOWFAILS behavior. Scan backwards because repeated
/// setopt calls are legal and libcurl keeps the last value.
/// @return true when recipient errors may be followed by another RCPT TO.
bool SmtpMockServer::AllowsRecipientFailures() const {
  const curl::fuzzer::proto::Scenario* script = scenario();
  if (script == nullptr) {
    return false;
  }
  for (int index = script->options_size() - 1; index >= 0; --index) {
    const auto& option = script->options(index);
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

/// Advance one reply for every complete command. A successful DATA reply
/// switches the parser into body-draining mode. The reply that follows DATA is
/// queued immediately: curl's smtp_done() runs a blocking POSTDATA wait inside
/// curl_multi_perform, so the outer peer service loop cannot run after the body
/// has been written. Pre-queuing it, as the FTP peer does for its final
/// transfer reply, keeps that wait deterministic without changing the order
/// curl observes (354 first, then the post-body response).
/// @param command One newline-terminated command from curl.
void SmtpMockServer::HandleLine(std::string_view command) {
  const std::string_view verb = FirstToken(command);
  const bool is_auth_continuation_reply = auth_exchange_active_;

  const std::string* response = NextControlReply();
  if (response == nullptr) {
    return;
  }

  const int response_code = FirstReplyCode(*response);
  const bool response_written = WriteControlBytes(*response);

  if (TokenEquals(verb, "STARTTLS") && IsStartTlsMode() && response_code == 220) {
    if (response_written && mode_ == curl::fuzzer::proto::SMTP_PROBE_STARTTLS_FILTER_ALLOCATION_FAILURE) {
      allocation_fault_injection::ArmNextAllocationFailure();
    }
    tls_upgrade_started_ = true;
    BeginOpaqueDrain();
    ShutdownControlWrite();
    return;
  }

  if (TokenEquals(verb, "AUTH")) {
    // A 334 reply is the only wire-visible distinction between SMTP AUTH and
    // a mutation-selected custom command that happens to start with AUTH.
    auth_exchange_active_ = response_code == 334;
  } else if (is_auth_continuation_reply) {
    if (TokenEquals(verb, "*")) {
      // Curl accepts the cancellation reply before trying another enabled
      // SASL mechanism, so the exchange remains active across this error.
      auth_exchange_active_ = true;
    } else if (response_code != 334) {
      auth_exchange_active_ = false;
    }
  }

  if (TokenEquals(verb, "DATA")) {
    if (response_code == 354) {
      BeginMarkerBody(kEndOfBody);
      (void)WriteNextReply();
    } else if (response_code > 0) {
      // curl treats every non-354 DATA reply as terminal. Pre-queue the
      // shutdown reply so its blocking cleanup QUIT does not wait one second.
      (void)WriteControlBytes(kShutdownReply);
    }
    return;
  }

  if (TokenEquals(verb, "RCPT")) {
    ++rcpt_command_count_;
  }

  // A terminal command error is followed by curl's blocking QUIT during
  // teardown. EHLO errors fall back to HELO, an early RCPT error may still be
  // followed by another recipient, and a failed AUTH exchange can cancel and
  // retry another mechanism. Those replies must not consume the shutdown
  // reply. Everything else can safely see a queued 221 next.
  const bool final_rcpt_error =
      TokenEquals(verb, "RCPT") && (rcpt_command_count_ >= recipient_count_ || !AllowsRecipientFailures());
  const bool starttls_denial = TokenEquals(verb, "STARTTLS") && IsStartTlsMode();
  const bool terminal_error = response_code >= 400 && !TokenEquals(verb, "EHLO") && !starttls_denial &&
                              !is_auth_continuation_reply && (!TokenEquals(verb, "RCPT") || final_rcpt_error);
  if (terminal_error) {
    (void)WriteControlBytes(kShutdownReply);
  }
}

/// Queue a 221 before the shared transport half-closes. SMTP's blocking QUIT
/// read has a one-second timeout when no reply is available, so even an
/// unfinished transfer gets a liveness reply; any real scripted response
/// already consumed by curl still determines the transfer result.
void SmtpMockServer::QueueShutdownReply() {
  if (!tls_upgrade_started_) {
    (void)WriteControlBytes(kShutdownReply);
  }
}

}  // namespace proto_fuzzer
