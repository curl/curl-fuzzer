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
#include <memory>
#include <string>
#include <string_view>

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/scenario_limits.h"

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
ImapMockServer::ImapMockServer()
    : scenario_(nullptr),
      control_reply_count_(0),
      next_control_reply_(0),
      draining_upload_(false),
      upload_remaining_(0),
      upload_terminator_remaining_(0),
      control_opened_(false) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
ImapMockServer::~ImapMockServer() = default;

/// Expose the bounded command capture from the most recent drive so tests can
/// verify IMAP states without coupling assertions to curl debug output.
/// @return A prefix of complete control commands, including line endings.
const std::string& ImapMockServer::control_transcript() const { return control_transcript_; }

/// Expose a bounded prefix of the APPEND literal while continuing to drain
/// every client byte, so test observability cannot create backpressure.
/// @return Literal bytes curl sent during the most recent APPEND.
const std::string& ImapMockServer::uploaded_data() const { return uploaded_data_; }

/// Reset every borrowed pointer, descriptor, parser cursor, and observable
/// capture before borrowing the next Scenario.
/// @param scenario Scenario whose Connection supplies the greeting and replies.
void ImapMockServer::ResetForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  connection_.reset();
  scenario_ = &scenario;
  control_reply_count_ = std::min<std::size_t>(scenario_limits::kMaxResponseChunks,
                                               static_cast<std::size_t>(scenario.connection().on_readable_size()));
  next_control_reply_ = 0;
  pending_control_bytes_.clear();
  control_transcript_.clear();
  uploaded_data_.clear();
  current_tag_.clear();
  draining_upload_ = false;
  upload_remaining_ = 0;
  upload_terminator_remaining_ = 0;
  control_opened_ = false;
}

/// Apply bounded transport knobs when creating the scripted socket. Target
/// policies normally clear IMAP backpressure, but direct corpus replay must
/// retain deterministic, well-defined behavior.
/// @param connection Peer receiving the socket settings.
/// @param script Connection script carrying optional backpressure values.
void ImapMockServer::ApplyScriptBackpressure(MockConnection* connection,
                                             const curl::fuzzer::proto::Connection& script) {
  if (connection == nullptr) {
    return;
  }

  const std::uint32_t int_max = static_cast<std::uint32_t>(std::numeric_limits<int>::max());
  const auto& backpressure = script.backpressure();
  const int receive_buffer = static_cast<int>(std::min(backpressure.recv_buf_bytes(), int_max));
  connection->ApplyBackpressure(receive_buffer, static_cast<std::size_t>(backpressure.drain_limit()));
}

/// Create the single control socketpair and queue the server greeting. IMAP
/// never opens a second application socket, so any later request is rejected
/// rather than silently replacing the live peer.
/// @param purpose Socket role requested by curl.
/// @param address Unused stream destination metadata required by the callback
///                signature.
/// @return Client descriptor for the control channel, or CURL_SOCKET_BAD.
curl_socket_t ImapMockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* /*address*/) {
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

/// Return the next command-aligned response within the shared response-count
/// budget. Empty strings still advance the cursor: they are meaningful
/// truncation mutations for ordinary command states.
/// @return Scenario-owned reply, or nullptr after the bounded prefix.
const std::string* ImapMockServer::NextControlReply() {
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
bool ImapMockServer::WriteControlBytes(std::string_view bytes) {
  return bytes.empty() || (connection_ != nullptr &&
                           connection_->WriteAll(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
}

/// Remove optional leading horizontal whitespace and return the first token
/// without allocating. IMAP's first token is the command tag.
/// @param command Complete command line.
/// @return View of its first non-whitespace token.
std::string_view ImapMockServer::CommandTag(std::string_view command) {
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

/// Remove the tag and return just the verb without allocating.
/// @param command Complete command line.
/// @return View of the second whitespace-delimited token.
std::string_view ImapMockServer::CommandVerb(std::string_view command) {
  std::size_t position = 0;
  while (position < command.size() && (command[position] == ' ' || command[position] == '\t')) {
    ++position;
  }
  while (position < command.size() && command[position] != ' ' && command[position] != '\t' &&
         command[position] != '\r' && command[position] != '\n') {
    ++position;
  }
  while (position < command.size() && (command[position] == ' ' || command[position] == '\t')) {
    ++position;
  }
  std::size_t end = position;
  while (end < command.size() && command[end] != ' ' && command[end] != '\t' && command[end] != '\r' &&
         command[end] != '\n') {
    ++end;
  }
  return command.substr(position, end - position);
}

/// Fold only ASCII lowercase command letters.
/// @param verb Parsed command token.
/// @param expected_uppercase Literal uppercase command name.
/// @return true when the verbs are equal ignoring ASCII case.
bool ImapMockServer::VerbEquals(std::string_view verb, std::string_view expected_uppercase) {
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

/// Retain only a bounded prefix for assertions. Parsing and draining continue
/// against the full transport bytes, so reaching the cap cannot change curl's
/// behavior or manufacture socket backpressure.
/// @param source Newly observed bytes.
/// @param limit Maximum retained destination size.
/// @param destination Capture buffer receiving the available prefix.
void ImapMockServer::CapturePrefix(std::string_view source, std::size_t limit, std::string* destination) {
  if (destination == nullptr || destination->size() >= limit) {
    return;
  }
  const std::size_t available = limit - destination->size();
  destination->append(source.data(), std::min(source.size(), available));
}

/// Advance one reply for every complete command. A `+` reply to APPEND enters
/// literal-draining mode and pre-queues the next scripted reply as the final
/// tagged completion. Curl's imap_done() waits for that completion inside
/// curl_multi_perform, so the outer peer loop cannot provide it later.
/// @param command One newline-terminated command from curl.
void ImapMockServer::HandleControlCommand(std::string_view command) {
  if (scenario_ == nullptr) {
    return;
  }

  current_tag_ = std::string(CommandTag(command));

  const std::string* response = NextControlReply();
  if (response == nullptr) {
    return;
  }

  const std::string_view verb = CommandVerb(command);
  const bool continuation = !response->empty() && response->front() == '+';
  (void)WriteControlBytes(RewriteReply(*response));

  if (!continuation || !VerbEquals(verb, "APPEND")) {
    return;
  }

  const std::size_t literal = AppendLiteralSize(command);
  if (literal == std::numeric_limits<std::size_t>::max()) {
    // Curl always announces the literal size here. Without one, leave the
    // transfer to the bounded idle budget and final half-close instead of
    // guessing where an arbitrary body ends.
    return;
  }

  draining_upload_ = true;
  upload_remaining_ = literal;
  upload_terminator_remaining_ = 2;

  const std::string* final_response = NextControlReply();
  if (final_response != nullptr) {
    (void)WriteControlBytes(RewriteReply(*final_response));
  }
}

/// Read without waiting, retain partial final commands, and process all full
/// lines already emitted by curl. After an accepted APPEND continuation the
/// same buffer is interpreted as exactly the announced literal body.
/// @return true when bytes, a command cursor, or a reply cursor advanced.
bool ImapMockServer::ServiceControlConnection() {
  if (connection_ == nullptr) {
    return false;
  }

  const std::size_t size_before_read = pending_control_bytes_.size();
  connection_->ReadAvailable(&pending_control_bytes_);
  bool made_progress = pending_control_bytes_.size() != size_before_read;

  std::size_t consumed = 0;
  while (consumed < pending_control_bytes_.size()) {
    if (draining_upload_) {
      if (upload_remaining_ != 0) {
        const std::size_t available = pending_control_bytes_.size() - consumed;
        const std::size_t take = std::min(available, upload_remaining_);
        CapturePrefix(std::string_view(pending_control_bytes_.data() + consumed, take), kMaxCapturedUploadBytes,
                      &uploaded_data_);
        consumed += take;
        upload_remaining_ -= take;
        made_progress = true;
        continue;
      }

      const std::size_t available = pending_control_bytes_.size() - consumed;
      if (upload_terminator_remaining_ == 2 && available >= 2 && pending_control_bytes_[consumed] == '\r' &&
          pending_control_bytes_[consumed + 1] == '\n') {
        consumed += 2;
        upload_terminator_remaining_ = 0;
        draining_upload_ = false;
        made_progress = true;
        continue;
      }
      if (available >= 1) {
        const char byte = pending_control_bytes_[consumed];
        if (byte == '\r' || byte == '\n') {
          ++consumed;
          if (byte == '\n' || upload_terminator_remaining_ == 0) {
            upload_terminator_remaining_ = 0;
            draining_upload_ = false;
          } else {
            upload_terminator_remaining_ = 1;
          }
          made_progress = true;
          continue;
        }
        // No terminating empty line is recognisable. Resume command parsing so
        // malformed uploads still make bounded progress.
        upload_terminator_remaining_ = 0;
        draining_upload_ = false;
        continue;
      }
      break;
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
/// Curl sends LOGOUT during connection teardown and performs a blocking read,
/// so queue the predicted tagged completion before half-closing. Any real
/// scripted response already consumed by curl still determines the transfer
/// result; this line only prevents a teardown timeout.
void ImapMockServer::FinishConnections() {
  if (connection_ != nullptr) {
    const std::string next_tag = NextCommandTag();
    if (!next_tag.empty()) {
      (void)WriteControlBytes(next_tag + std::string(kShutdownTail));
    } else {
      (void)WriteControlBytes("* BYE imap mock closing\r\n");
    }
    connection_->ShutdownWrite();
  }
}

/// Give curl's graceful shutdown one last chance to emit LOGOUT while the peer
/// still owns its read half, then release the multi as the base class would.
/// @param multi Detached multi handle whose connection cache may be shutting
///              the protocol connection down.
void ImapMockServer::HandleDetachedMulti(CurlMultiPtr multi) {
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
void ImapMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
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

  // The final perform may have emitted the last command or literal bytes
  // immediately before marking the transfer done. Drain them before cleanup.
  (void)ServiceControlConnection();
  FinishConnections();
  scenario_ = nullptr;
}

}  // namespace proto_fuzzer
