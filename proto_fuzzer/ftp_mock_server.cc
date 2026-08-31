/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the command-aware in-process FTP peer.

#include "proto_fuzzer/ftp_mock_server.h"

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

/// Begin without a borrowed protobuf or any open socketpairs. Keeping all
/// session state in the object avoids process globals that could leak one
/// libFuzzer iteration's protocol position into the next.
FtpMockServer::FtpMockServer()
    : scenario_(nullptr),
      next_data_script_(0),
      control_reply_count_(0),
      next_control_reply_(0),
      control_opened_(false) {}

/// Loopback peers are ordinary unique_ptr-owned transports; the out-of-line
/// destructor also permits MockConnection to remain forward-declared
/// in the header.
FtpMockServer::~FtpMockServer() = default;

/// Return the bounded command capture accumulated by the most recent drive.
const std::string& FtpMockServer::control_transcript() const { return control_transcript_; }

/// Return the bounded upload capture accumulated by the most recent drive.
const std::string& FtpMockServer::uploaded_data() const { return uploaded_data_; }

/// Report how many passive peers curl actually requested, rather than how many
/// scripts happened to be present in the protobuf.
std::size_t FtpMockServer::opened_data_connection_count() const { return next_data_script_; }

/// Clear descriptor and parser state before borrowing the next Scenario. A
/// FtpMockServer can be reused serially, but no connection or response cursor
/// is meaningful across easy-handle drives.
void FtpMockServer::ResetForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  control_connection_.reset();
  for (DataChannel& channel : data_channels_) {
    channel.connection.reset();
    channel.script = nullptr;
    channel.transfer_started = false;
    channel.upload = false;
  }

  scenario_ = &scenario;
  next_data_script_ = 0;
  control_reply_count_ = std::min<std::size_t>(scenario_limits::kMaxResponseChunks,
                                               static_cast<std::size_t>(scenario.connection().on_readable_size()));
  next_control_reply_ = 0;
  pending_control_bytes_.clear();
  control_transcript_.clear();
  uploaded_data_.clear();
  control_opened_ = false;
}

/// Clamp a compatibility input's raw protobuf socket size before crossing the
/// platform int boundary. Target policies normally clear FTP backpressure,
/// but direct corpus replay must retain deterministic, well-defined behavior.
void FtpMockServer::ApplyScriptBackpressure(MockConnection* connection, const curl::fuzzer::proto::Connection& script) {
  if (connection == nullptr) {
    return;
  }

  const std::uint32_t int_max = static_cast<std::uint32_t>(std::numeric_limits<int>::max());
  const auto& backpressure = script.backpressure();
  const int receive_buffer = static_cast<int>(std::min(backpressure.recv_buf_bytes(), int_max));
  connection->ApplyBackpressure(receive_buffer, static_cast<std::size_t>(backpressure.drain_limit()));
}

/// Allocate one control socket followed by a bounded sequence of passive data
/// sockets. Data is intentionally not preloaded here: curl opens EPSV/PASV's
/// socket before it has sent the command that determines whether the stream is
/// a listing, download, or upload.
/// @param purpose Socket role requested by curl; active-mode accepts are
///                deliberately unsupported.
/// @param address Original IP destination retained by curl for FTP's passive
///                host selection; the connected socketpair need not alter it.
/// @return An already-connected client fd, or CURL_SOCKET_BAD when the bounded
///         control/data script has no matching peer.
curl_socket_t FtpMockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) {
  (void)address;
  // Passive control/data sockets are ordinary outbound connections. Reject an
  // active-mode accept request rather than handing curl a connected socketpair
  // whose semantics cannot model listen/accept or a server callback.
  if (scenario_ == nullptr || purpose != CURLSOCKTYPE_IPCXN) {
    return CURL_SOCKET_BAD;
  }

  if (!control_opened_) {
    control_connection_ = std::make_unique<MockConnection>();
    if (!control_connection_->ok()) {
      control_connection_.reset();
      return CURL_SOCKET_BAD;
    }

    ApplyScriptBackpressure(control_connection_.get(), scenario_->connection());
    const std::string& greeting = scenario_->connection().initial_response();
    if (!greeting.empty() &&
        !control_connection_->WriteAll(reinterpret_cast<const unsigned char*>(greeting.data()), greeting.size())) {
      control_connection_.reset();
      return CURL_SOCKET_BAD;
    }
    // Do not consume the unique control slot until its peer is usable. Curl
    // may retry a failed application socket callback, and that retry must not
    // be mistaken for the first passive data connection.
    control_opened_ = true;
    return control_connection_->take_client_fd();
  }

  const std::size_t available_scripts =
      std::min<std::size_t>(kMaxDataChannels, static_cast<std::size_t>(scenario_->subsequent_connections_size()));
  if (next_data_script_ >= available_scripts) {
    return CURL_SOCKET_BAD;
  }

  DataChannel& channel = data_channels_[next_data_script_];
  channel.script = &scenario_->subsequent_connections(static_cast<int>(next_data_script_));
  channel.connection = std::make_unique<MockConnection>();
  if (!channel.connection->ok()) {
    channel.connection.reset();
    channel.script = nullptr;
    return CURL_SOCKET_BAD;
  }

  ApplyScriptBackpressure(channel.connection.get(), *channel.script);
  ++next_data_script_;
  return channel.connection->take_client_fd();
}

/// Retain only a bounded prefix for assertions. Parsing and draining continue
/// against the full transport bytes, so reaching the cap cannot change curl's
/// behavior or manufacture socket backpressure.
void FtpMockServer::CapturePrefix(std::string_view source, std::size_t limit, std::string* destination) {
  if (destination == nullptr || destination->size() >= limit) {
    return;
  }
  const std::size_t available = limit - destination->size();
  destination->append(source.data(), std::min(source.size(), available));
}

/// Remove FTP's optional leading horizontal whitespace and return just the
/// verb. Arguments remain untouched because only curl, not the mock harness,
/// should interpret fuzzed paths and offsets.
std::string_view FtpMockServer::CommandVerb(std::string_view command) {
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

/// Fold only ASCII lowercase command letters. FTP verbs are ASCII tokens, so
/// locale-aware case conversion would add state and undefined signed-char
/// behavior without accepting anything curl can legitimately send.
bool FtpMockServer::VerbEquals(std::string_view verb, std::string_view expected_uppercase) {
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

/// Recognize curl's built-in data commands plus MLSD, the useful structured
/// listing custom request. PRET deliberately remains control-only even though
/// its argument can contain RETR/STOR: no data transfer has begun at that
/// point.
FtpMockServer::TransferDirection FtpMockServer::DirectionForVerb(std::string_view verb) {
  if (VerbEquals(verb, "STOR") || VerbEquals(verb, "APPE")) {
    return TransferDirection::kUpload;
  }
  if (VerbEquals(verb, "RETR") || VerbEquals(verb, "LIST") || VerbEquals(verb, "NLST") || VerbEquals(verb, "MLSD")) {
    return TransferDirection::kDownload;
  }
  return TransferDirection::kNone;
}

/// Scan backwards because repeated setopt calls are legal and libcurl keeps
/// the last value. Comparing only the verb preserves arbitrary custom
/// arguments while still avoiding false positives on preparatory FTP commands
/// that happen to receive a fuzzed 125/150 reply after EPSV opened a socket.
bool FtpMockServer::IsConfiguredCustomDownload(std::string_view verb) const {
  if (scenario_ == nullptr || verb.empty()) {
    return false;
  }

  for (int index = scenario_->options_size() - 1; index >= 0; --index) {
    const auto& option = scenario_->options(index);
    if (option.option_id() != curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST) {
      continue;
    }
    if (option.value_case() != curl::fuzzer::proto::SetOption::kStringValue) {
      return false;
    }
    return VerbEquals(verb, CommandVerb(option.string_value()));
  }
  return false;
}

/// Scan complete lines because a legal FTP response fragment may start with
/// one or more informational lines. curl ends a response at the first line
/// whose first three bytes are digits and whose fourth byte is a space.
int FtpMockServer::FirstReplyCode(std::string_view response) {
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

/// A raw completion such as "226 done" needs only its missing newline. In
/// that common mutation, appending a second synthetic reply would leave bytes
/// in curl's control cache and misalign a later wildcard transfer.
bool FtpMockServer::TailNeedsOnlyNewline(std::string_view response) {
  const std::size_t last_newline = response.rfind('\n');
  const std::size_t tail = last_newline == std::string_view::npos ? 0 : last_newline + 1;
  if (response.size() - tail <= 3) {
    return false;
  }
  const unsigned char first = static_cast<unsigned char>(response[tail]);
  const unsigned char second = static_cast<unsigned char>(response[tail + 1]);
  const unsigned char third = static_cast<unsigned char>(response[tail + 2]);
  return first >= '0' && first <= '9' && second >= '0' && second <= '9' && third >= '0' && third <= '9' &&
         response[tail + 3] == ' ';
}

/// Return the next bounded primary response. Empty strings still advance the
/// cursor: they are meaningful truncation mutations for ordinary command
/// states and explicitly select control EOF at transfer completion.
const std::string* FtpMockServer::NextControlReply() {
  if (scenario_ == nullptr || next_control_reply_ >= control_reply_count_) {
    return nullptr;
  }
  return &scenario_->connection().on_readable(static_cast<int>(next_control_reply_++));
}

/// Keep failed peer writes local to the mock. Response cursors must still
/// advance after curl closes early, otherwise a replacement socket could see
/// a reply intended for an earlier command.
bool FtpMockServer::WriteControlBytes(std::string_view bytes) {
  return bytes.empty() ||
         (control_connection_ != nullptr &&
          control_connection_->WriteAll(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
}

/// Queue a scenario-provided final reply and make it guaranteed non-blocking.
/// ftp_done_control_reply() calls getftpresponse() synchronously after data
/// EOF; if the fuzzed fragment lacks a terminating numeric line, append the
/// smallest completion needed so curl returns to the harness immediately. An
/// explicitly empty repeated value instead half-closes the peer: this retains
/// deterministic liveness while making curl's missing-completion error path
/// directly seedable.
void FtpMockServer::QueueTransferCompletion() {
  const std::string* response = NextControlReply();
  if (response != nullptr && response->empty()) {
    if (control_connection_ != nullptr) {
      control_connection_->ShutdownWrite();
    }
    return;
  }
  if (response != nullptr && !response->empty()) {
    (void)WriteControlBytes(*response);
    if (FirstReplyCode(*response) >= 0) {
      return;
    }
    if (TailNeedsOnlyNewline(*response)) {
      (void)WriteControlBytes("\r\n");
      return;
    }
    if (response->back() != '\n') {
      (void)WriteControlBytes("\r\n");
    }
  }

  // This line is a liveness guard, not a forced successful outcome: any
  // complete fuzzed final response above remains the reply curl consumes.
  (void)WriteControlBytes("226 mock transfer complete\r\n");
}

/// Send every runtime-visible data fragment before half-closing the peer. The
/// serialized fuzz input is already length-bounded; sending the complete
/// prefix lets curl drain its data state without event-loop sleeps while each
/// protobuf fragment still affects byte content and parser behavior.
void FtpMockServer::PreloadDownload(DataChannel* channel) {
  if (channel == nullptr || channel->connection == nullptr || channel->script == nullptr) {
    return;
  }

  const std::string& initial = channel->script->initial_response();
  bool complete = initial.empty() ||
                  channel->connection->WriteAll(reinterpret_cast<const unsigned char*>(initial.data()), initial.size());
  const std::size_t chunk_count = std::min<std::size_t>(scenario_limits::kMaxResponseChunks,
                                                        static_cast<std::size_t>(channel->script->on_readable_size()));
  for (std::size_t index = 0; complete && index < chunk_count; ++index) {
    const std::string& chunk = channel->script->on_readable(static_cast<int>(index));
    complete = chunk.empty() ||
               channel->connection->WriteAll(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
  }
  (void)complete;
  channel->connection->ShutdownWrite();
}

/// Pair the next transfer command with the oldest passive socket that EPSV or
/// PASV opened but no command has used. FTP serializes data transfers, so this
/// simple cursor is sufficient and avoids interpreting fuzzed port numbers.
void FtpMockServer::StartNextTransfer(TransferDirection direction) {
  for (std::size_t index = 0; index < next_data_script_; ++index) {
    DataChannel& channel = data_channels_[index];
    if (channel.connection == nullptr || channel.transfer_started) {
      continue;
    }

    channel.transfer_started = true;
    channel.upload = direction == TransferDirection::kUpload;
    if (!channel.upload) {
      PreloadDownload(&channel);
    }
    // Upload peers keep their write half open until cleanup. A real FTP server
    // does not send an early FIN while receiving a file, and a readiness
    // backend could otherwise report that FIN alongside POLLOUT before curl
    // has delivered the upload callback's bytes.
    return;
  }
}

/// Advance one reply for every complete command. Accepted transfer commands
/// additionally consume their final reply now, because waiting until data EOF
/// would be too late to escape curl's blocking completion read.
void FtpMockServer::HandleControlCommand(std::string_view command) {
  const std::string* response = NextControlReply();
  if (response == nullptr) {
    return;
  }

  const int response_code = FirstReplyCode(*response);
  (void)WriteControlBytes(*response);

  const std::string_view verb = CommandVerb(command);
  TransferDirection direction = DirectionForVerb(verb);
  if (direction == TransferDirection::kNone && IsConfiguredCustomDownload(verb)) {
    direction = TransferDirection::kDownload;
  }
  const bool starts_download =
      direction == TransferDirection::kDownload && (response_code == 125 || response_code == 150);
  // curl's STOR handler accepts every response below 400 before initiating
  // the upload, even though 125/150 are the conventional successful replies.
  const bool starts_upload = direction == TransferDirection::kUpload && response_code >= 100 && response_code < 400;
  if (starts_download || starts_upload) {
    StartNextTransfer(direction);
    QueueTransferCompletion();
  }
}

/// Read without waiting, retain partial final commands, and process all full
/// lines already emitted by curl. The number of replies is bounded even if a
/// malformed command stream contains many newlines.
bool FtpMockServer::ServiceControlConnection() {
  if (control_connection_ == nullptr) {
    return false;
  }

  const std::size_t size_before_read = pending_control_bytes_.size();
  control_connection_->ReadAvailable(&pending_control_bytes_);
  bool made_progress = pending_control_bytes_.size() != size_before_read;

  std::size_t consumed = 0;
  while (consumed < pending_control_bytes_.size()) {
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

/// Drain uploads into a temporary buffer so data beyond the observable cap is
/// still removed from the socket. This keeps curl's progress independent of
/// how much a unit test chooses to retain.
bool FtpMockServer::ServiceUploadConnections() {
  bool made_progress = false;
  for (std::size_t index = 0; index < next_data_script_; ++index) {
    DataChannel& channel = data_channels_[index];
    if (!channel.upload || channel.connection == nullptr) {
      continue;
    }

    std::string bytes;
    channel.connection->ReadAvailable(&bytes);
    if (!bytes.empty()) {
      CapturePrefix(bytes, kMaxCapturedUploadBytes, &uploaded_data_);
      made_progress = true;
    }
  }
  return made_progress;
}

/// Prepare cleanup while the mock can still write to curl's control socket.
/// A completed easy remains in multi's connection cache until cleanup, where
/// FTP sends QUIT and performs a blocking read. Preloading 221 handles that
/// path; an unfinished drive instead gets EOF so cleanup fails fast.
void FtpMockServer::FinishConnections(bool completed) {
  if (control_connection_ != nullptr) {
    if (completed) {
      (void)WriteControlBytes("221 mock closing control connection\r\n");
    }
    control_connection_->ShutdownWrite();
  }
  for (std::size_t index = 0; index < next_data_script_; ++index) {
    if (data_channels_[index].connection != nullptr) {
      data_channels_[index].connection->ShutdownWrite();
    }
  }
}

/// Alternate curl transitions with immediate peer service until the transfer
/// completes or deterministic idle/operation caps win. No select(), poll(),
/// or sleep is needed: every transport is a local socketpair, and malformed
/// scripts are terminated by half-close after the bounded loop.
void FtpMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
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
    made_progress = ServiceUploadConnections() || made_progress;
    if (made_progress) {
      idle_iterations = 0;
    } else {
      ++idle_iterations;
    }
  }

  // The final perform may have emitted upload or control bytes immediately
  // before marking the transfer done. Drain/capture them before cleanup.
  (void)ServiceControlConnection();
  (void)ServiceUploadConnections();
  FinishConnections(still_running == 0 && result == CURLM_OK);
  scenario_ = nullptr;
}

}  // namespace proto_fuzzer
