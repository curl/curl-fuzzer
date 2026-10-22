/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the command-aware in-process POP3 peer.

#include "proto_fuzzer/pop3_mock_server.h"

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
Pop3MockServer::Pop3MockServer()
    : scenario_(nullptr), control_reply_count_(0), next_control_reply_(0), control_opened_(false) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
Pop3MockServer::~Pop3MockServer() = default;

/// Expose the bounded command capture from the most recent drive so tests can
/// verify POP3 states without coupling assertions to curl debug output.
/// @return A prefix of complete control commands, including line endings.
const std::string& Pop3MockServer::control_transcript() const { return control_transcript_; }

/// POP3 has no upload direction, so the uniform observation hook stays empty.
/// @return An empty string.
const std::string& Pop3MockServer::uploaded_data() const { return uploaded_data_; }

/// Reset every borrowed pointer, descriptor, parser cursor, and observable
/// capture before borrowing the next Scenario.
/// @param scenario Scenario whose Connection supplies the greeting and replies.
void Pop3MockServer::ResetForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  connection_.reset();
  scenario_ = &scenario;
  control_reply_count_ = std::min<std::size_t>(scenario_limits::kMaxResponseChunks,
                                               static_cast<std::size_t>(scenario.connection().on_readable_size()));
  next_control_reply_ = 0;
  pending_control_bytes_.clear();
  control_transcript_.clear();
  uploaded_data_.clear();
  control_opened_ = false;
}

/// Apply bounded transport knobs when creating the scripted socket. Target
/// policies normally clear POP3 backpressure, but direct corpus replay must
/// retain deterministic, well-defined behavior.
/// @param connection Peer receiving the socket settings.
/// @param script Connection script carrying optional backpressure values.
void Pop3MockServer::ApplyScriptBackpressure(MockConnection* connection,
                                             const curl::fuzzer::proto::Connection& script) {
  if (connection == nullptr) {
    return;
  }

  const std::uint32_t int_max = static_cast<std::uint32_t>(std::numeric_limits<int>::max());
  const auto& backpressure = script.backpressure();
  const int receive_buffer = static_cast<int>(std::min(backpressure.recv_buf_bytes(), int_max));
  connection->ApplyBackpressure(receive_buffer, static_cast<std::size_t>(backpressure.drain_limit()));
}

/// Create the single control socketpair and queue the server greeting. POP3
/// never opens a second application socket, so any later request is rejected
/// rather than silently replacing the live peer.
/// @param purpose Socket role requested by curl.
/// @param address Unused stream destination metadata required by the callback
///                signature.
/// @return Client descriptor for the control channel, or CURL_SOCKET_BAD.
curl_socket_t Pop3MockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* /*address*/) {
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
const std::string* Pop3MockServer::NextControlReply() {
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
bool Pop3MockServer::WriteControlBytes(std::string_view bytes) {
  return bytes.empty() || (connection_ != nullptr &&
                           connection_->WriteAll(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
}

/// Retain only a bounded prefix for assertions. Parsing continues against the
/// full transport bytes, so reaching the cap cannot change curl's behavior or
/// manufacture socket backpressure.
/// @param source Newly observed bytes.
/// @param limit Maximum retained destination size.
/// @param destination Capture buffer receiving the available prefix.
void Pop3MockServer::CapturePrefix(std::string_view source, std::size_t limit, std::string* destination) {
  if (destination == nullptr || destination->size() >= limit) {
    return;
  }
  const std::size_t available = limit - destination->size();
  destination->append(source.data(), std::min(source.size(), available));
}

/// Advance one reply for every complete command. POP3's status lines are
/// self-describing, so the scripted bytes are written unchanged; curl chooses
/// multi-line handling from the command it sent, not from the reply.
/// @param command One newline-terminated command from curl.
void Pop3MockServer::HandleControlCommand(std::string_view command) {
  (void)command;
  if (scenario_ == nullptr) {
    return;
  }
  const std::string* response = NextControlReply();
  if (response != nullptr) {
    (void)WriteControlBytes(*response);
  }
}

/// Read without waiting, retain partial final commands, and process all full
/// lines already emitted by curl. The number of replies is bounded even if a
/// malformed command stream contains many newlines.
/// @return true when bytes or a command/reply cursor advanced.
bool Pop3MockServer::ServiceControlConnection() {
  if (connection_ == nullptr) {
    return false;
  }

  const std::size_t size_before_read = pending_control_bytes_.size();
  connection_->ReadAvailable(&pending_control_bytes_);
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

/// Prepare cleanup while the mock can still write to curl's control socket.
/// Queue a +OK for the blocking QUIT that follows easy cleanup, then half-close
/// so an unfinished transfer cannot wait on a reply that will never arrive.
void Pop3MockServer::FinishConnections() {
  if (connection_ != nullptr) {
    (void)WriteControlBytes(kShutdownReply);
    connection_->ShutdownWrite();
  }
}

/// Give curl's graceful shutdown one last chance to emit QUIT while the peer
/// still owns its read half, then release the multi as the base class would.
/// The matching +OK was already queued by FinishConnections.
/// @param multi Detached multi handle whose connection cache may be shutting
///              the protocol connection down.
void Pop3MockServer::HandleDetachedMulti(CurlMultiPtr multi) {
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
void Pop3MockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
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

  // The final perform may have emitted the last command immediately before
  // marking the transfer done. Drain it before cleanup.
  (void)ServiceControlConnection();
  FinishConnections();
  scenario_ = nullptr;
}

}  // namespace proto_fuzzer
