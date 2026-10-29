/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the command-aware in-process IMAP peer.

#include "proto_fuzzer/imap_mock_server.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace proto_fuzzer {

namespace {

/// Fold only ASCII lowercase command bytes. IMAP status keywords are ASCII
/// tokens, so locale-aware conversion would add state without accepting
/// anything curl can legitimately send.
bool AsciiEqualsIgnoreCase(std::string_view value, std::string_view expected_lowercase) {
  if (value.size() != expected_lowercase.size()) {
    return false;
  }
  for (std::size_t index = 0; index < value.size(); ++index) {
    unsigned char actual = static_cast<unsigned char>(value[index]);
    if (actual >= 'A' && actual <= 'Z') {
      actual = static_cast<unsigned char>(actual - 'A' + 'a');
    }
    if (actual != static_cast<unsigned char>(expected_lowercase[index])) {
      return false;
    }
  }
  return true;
}

}  // namespace

/// Begin without a borrowed protobuf or open socketpair. RunLoop borrows a
/// Scenario only for the synchronous DriveScenario call in which socket
/// callbacks can run.
ImapMockServer::ImapMockServer() = default;

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
ImapMockServer::~ImapMockServer() = default;

/// Clear the tag remembered from the previous drive. The shared base has
/// already reset the transport, reply cursor, transcript, upload capture, and
/// body phase.
void ImapMockServer::ResetProtocolState() {
  current_tag_.clear();
  authentication_continuation_active_ = false;
}

/// Return whether a scripted line is a tagged status response. Untagged (`*`)
/// and continuation (`+`) lines are left alone, as are already-tagged or
/// arbitrary bytes that curl should observe verbatim.
/// @param line One complete response line, including its line ending.
/// @return true when the current command tag must be prepended.
bool ImapMockServer::StatusLineNeedsTag(std::string_view line) {
  const std::size_t space = line.find_first_of(" \r\n");
  const std::string_view keyword = line.substr(0, space);
  if (keyword.empty()) {
    return false;
  }
  if (!AsciiEqualsIgnoreCase(keyword, "ok") && !AsciiEqualsIgnoreCase(keyword, "no") &&
      !AsciiEqualsIgnoreCase(keyword, "bad") && !AsciiEqualsIgnoreCase(keyword, "preauth")) {
    return false;
  }
  return space != std::string_view::npos;
}

/// Return whether a scripted response contains an IMAP continuation line.
/// Literal bodies are skipped with the same rules as RewriteReply so their
/// arbitrary bytes cannot start a continuation exchange.
/// @param response Scenario-owned reply fragment.
/// @return true when a non-literal response line begins with `+`.
bool ImapMockServer::ResponseHasContinuation(std::string_view response) {
  std::size_t position = 0;
  while (position < response.size()) {
    const std::size_t newline = response.find('\n', position);
    const std::size_t line_end = newline == std::string_view::npos ? response.size() : newline + 1;
    const std::string_view line = response.substr(position, line_end - position);
    if (!line.empty() && line.front() == '+') {
      return true;
    }

    const std::size_t literal = LiteralSize(line);
    const std::size_t available = response.size() - line_end;
    position = line_end + std::min(literal, available);
  }
  return false;
}

/// Return whether a scripted response contains a terminal status for the
/// current tag. Literal bodies are skipped with the same rules as RewriteReply
/// so body bytes that happen to begin with an IMAP status word cannot end
/// authentication. Both tag-relative placeholders and an exact already-tagged
/// line are accepted.
/// @param response Scenario-owned reply fragment.
/// @return true when the response completes the current tagged command.
bool ImapMockServer::ResponseHasTaggedCompletion(std::string_view response) const {
  std::size_t position = 0;
  while (position < response.size()) {
    const std::size_t newline = response.find('\n', position);
    const std::size_t line_end = newline == std::string_view::npos ? response.size() : newline + 1;
    const std::string_view line = response.substr(position, line_end - position);
    const bool tag_relative = StatusLineNeedsTag(line);
    const bool has_current_tag = !current_tag_.empty() && line.size() > current_tag_.size() &&
                                 line.compare(0, current_tag_.size(), current_tag_) == 0 &&
                                 line[current_tag_.size()] == ' ' &&
                                 StatusLineNeedsTag(line.substr(current_tag_.size() + 1));
    if (tag_relative || has_current_tag) {
      return true;
    }

    const std::size_t literal = LiteralSize(line);
    const std::size_t available = response.size() - line_end;
    position = line_end + std::min(literal, available);
  }
  return false;
}

/// Parse a trailing IMAP literal marker such as `{42}` or `{42+}`.
/// @param line One response or command line.
/// @return Literal byte count, or 0 when no well-formed marker is present.
std::size_t ImapMockServer::LiteralSize(std::string_view line) {
  while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
    line.remove_suffix(1);
  }
  if (line.empty() || line.back() != '}') {
    return 0;
  }
  const std::size_t open = line.rfind('{');
  if (open == std::string_view::npos || open + 2 > line.size()) {
    return 0;
  }

  std::size_t position = open + 1;
  std::size_t value = 0;
  bool digits = false;
  while (position < line.size() && line[position] >= '0' && line[position] <= '9') {
    const std::size_t digit = static_cast<std::size_t>(line[position] - '0');
    if (value > (std::numeric_limits<std::size_t>::max() - digit) / 10) {
      return 0;
    }
    value = value * 10 + digit;
    digits = true;
    ++position;
  }
  if (!digits) {
    return 0;
  }
  if (position < line.size() && line[position] == '+') {
    ++position;
  }
  return position + 1 == line.size() ? value : 0;
}

/// Parse the literal size from an APPEND command. Only the command's final
/// marker matters; earlier braces in a mailbox name are ignored.
/// @param command Complete APPEND command line.
/// @return Announced literal size, or the maximum size_t when the command has
///         no well-formed marker. Zero is a valid literal length.
std::size_t ImapMockServer::AppendLiteralSize(std::string_view command) {
  while (!command.empty() && (command.back() == '\r' || command.back() == '\n')) {
    command.remove_suffix(1);
  }
  if (command.empty() || command.back() != '}') {
    return std::numeric_limits<std::size_t>::max();
  }
  const std::size_t open = command.rfind('{');
  if (open == std::string_view::npos) {
    return std::numeric_limits<std::size_t>::max();
  }

  std::size_t position = open + 1;
  std::size_t value = 0;
  bool digits = false;
  while (position < command.size() && command[position] >= '0' && command[position] <= '9') {
    const std::size_t digit = static_cast<std::size_t>(command[position] - '0');
    if (value > (std::numeric_limits<std::size_t>::max() - digit) / 10) {
      return std::numeric_limits<std::size_t>::max();
    }
    value = value * 10 + digit;
    digits = true;
    ++position;
  }
  if (!digits) {
    return std::numeric_limits<std::size_t>::max();
  }
  if (position < command.size() && command[position] == '+') {
    ++position;
  }
  return position + 1 == command.size() ? value : std::numeric_limits<std::size_t>::max();
}

/// Resolve one scripted reply to wire bytes. A tagged status line gains the
/// tag of the command currently being answered. Literal bodies are copied
/// verbatim so fuzzed body bytes cannot be mistaken for status lines.
/// @param response Scenario-owned reply fragment.
/// @return Bytes to queue on the control socket.
std::string ImapMockServer::RewriteReply(std::string_view response) const {
  std::string output;
  output.reserve(response.size() + 16);

  std::size_t position = 0;
  while (position < response.size()) {
    const std::size_t newline = response.find('\n', position);
    const std::size_t line_end = newline == std::string_view::npos ? response.size() : newline + 1;
    const std::string_view line = response.substr(position, line_end - position);

    if (!current_tag_.empty() && StatusLineNeedsTag(line)) {
      output.append(current_tag_);
      output.push_back(' ');
    }
    output.append(line);

    const std::size_t literal = LiteralSize(line);
    if (literal == 0) {
      position = line_end;
      continue;
    }

    const std::size_t body_start = line_end;
    const std::size_t available = response.size() - body_start;
    const std::size_t body_size = std::min(literal, available);
    output.append(response.substr(body_start, body_size));
    position = body_start + body_size;
  }
  return output;
}

/// Derive the tag curl will assign to its next command. Curl formats the tag
/// as `<letter><3-digit connection-local command id>`; the letter is stable
/// for a connection and the id increments once per command. The predicted tag
/// only drives a teardown liveness reply, so a malformed previous tag simply
/// falls back to an untagged BYE and the final half-close.
/// @return Predicted tag, or empty when the previous tag was not numeric.
std::string ImapMockServer::NextCommandTag() const {
  std::size_t digits_start = current_tag_.size();
  while (digits_start > 0 && current_tag_[digits_start - 1] >= '0' && current_tag_[digits_start - 1] <= '9') {
    --digits_start;
  }
  if (digits_start == current_tag_.size() || digits_start == 0) {
    return std::string();
  }

  std::uint64_t number = 0;
  for (std::size_t index = digits_start; index < current_tag_.size(); ++index) {
    number = number * 10 + static_cast<std::uint64_t>(current_tag_[index] - '0');
    if (number > 999999) {
      return std::string();
    }
  }
  ++number;

  std::string digits = std::to_string(number);
  const std::size_t width = current_tag_.size() - digits_start;
  if (digits.size() < width) {
    digits.insert(0, width - digits.size(), '0');
  }
  return current_tag_.substr(0, digits_start) + digits;
}

/// Advance one reply for every complete command or AUTHENTICATE continuation.
/// Continuation data keeps the initiating command tag until a scripted tagged
/// status ends the exchange. A `+` reply to APPEND enters literal-draining mode
/// and pre-queues the next scripted reply as the final tagged completion.
/// Curl's imap_done() waits for that completion inside curl_multi_perform, so
/// the outer peer loop cannot provide it later.
/// @param command One newline-terminated client line from curl.
void ImapMockServer::HandleLine(std::string_view command) {
  if (scenario() == nullptr) {
    return;
  }

  const bool authentication_payload = authentication_continuation_active_;
  if (!authentication_payload) {
    current_tag_ = std::string(FirstToken(command));
  }

  const std::string* response = NextControlReply();
  if (response == nullptr) {
    return;
  }

  const bool continuation = ResponseHasContinuation(*response);
  const bool tagged_completion = ResponseHasTaggedCompletion(*response);
  (void)WriteControlBytes(RewriteReply(*response));

  if (authentication_payload) {
    if (tagged_completion) {
      authentication_continuation_active_ = false;
    }
    return;
  }

  const std::string_view verb = SecondToken(command);
  if (continuation && TokenEquals(verb, "AUTHENTICATE")) {
    authentication_continuation_active_ = !tagged_completion;
    return;
  }

  if (!continuation || !TokenEquals(verb, "APPEND")) {
    return;
  }

  const std::size_t literal = AppendLiteralSize(command);
  if (literal == std::numeric_limits<std::size_t>::max()) {
    // Curl always announces the literal size here. Without one, leave the
    // transfer to the bounded idle budget and final half-close instead of
    // guessing where an arbitrary body ends.
    return;
  }

  BeginLiteralBody(literal);

  const std::string* final_response = NextControlReply();
  if (final_response != nullptr) {
    (void)WriteControlBytes(RewriteReply(*final_response));
  }
}

/// Queue a tagged completion for curl's blocking LOGOUT during teardown. Any
/// real scripted response already consumed by curl still determines the
/// transfer result; this line only prevents a teardown timeout.
void ImapMockServer::QueueShutdownReply() {
  const std::string next_tag = NextCommandTag();
  if (!next_tag.empty()) {
    (void)WriteControlBytes(next_tag + std::string(kShutdownTail));
  } else {
    (void)WriteControlBytes("* BYE imap mock closing\r\n");
  }
}

/// Retain protocol outcomes in coverage and introspector builds.
void ImapMockServer::ObserveState() {
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  PingpongMockServer::ObserveState();
  const volatile std::size_t imap_observation[] = {control_transcript().size(), uploaded_data().size()};
  (void)imap_observation;
#endif
}

}  // namespace proto_fuzzer
