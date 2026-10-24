/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the shared line-oriented pingpong peer.

#include "proto_fuzzer/pingpong_mock_server.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <string_view>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Construct the shared transport state without a borrowed protobuf or open
/// socketpair. RunLoop borrows a Scenario only for the synchronous
/// DriveScenario call in which socket callbacks can run.
/// @param drive_policy Multi-loop policy inherited from MockServerBase.
PingpongMockServer::PingpongMockServer(MultiDrivePolicy drive_policy)
    : MockServerBase(drive_policy),
      scenario_(nullptr),
      control_reply_count_(0),
      next_control_reply_(0),
      active_pollset_probe_count_(0),
      body_length_remaining_(0),
      body_terminator_remaining_(0),
      body_mode_(BodyMode::kCommand),
      control_opened_(false) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
PingpongMockServer::~PingpongMockServer() = default;

/// Expose the bounded command capture from the most recent drive so tests can
/// verify protocol states without coupling assertions to curl debug output.
/// @return A prefix of complete control commands, including line endings.
const std::string& PingpongMockServer::control_transcript() const { return control_transcript_; }

/// Expose a bounded prefix of bytes drained during the most recent body phase
/// while continuing to drain every client byte, so test observability cannot
/// create backpressure.
/// @return Body bytes curl sent, or an empty string when the peer has no
///         upload direction.
const std::string& PingpongMockServer::uploaded_data() const { return uploaded_data_; }

/// Report how many requested zero-timeout multi-poll probes ran during the
/// most recent drive. RunLoop increments this only after a successful perform
/// turn while curl still owns an active transfer and the control socket is
/// open, making the count a focused test assertion rather than a syscall
/// counter for default scenarios.
/// @return Number of active, connected pollset probes in the previous drive.
std::size_t PingpongMockServer::active_pollset_probe_count() const { return active_pollset_probe_count_; }

/// Create the default plaintext transport. The SMTPS subclass overrides this
/// factory while retaining the command/reply parser.
/// @return A new socketpair-backed connection.
std::unique_ptr<MockConnection> PingpongMockServer::CreateConnection() { return std::make_unique<MockConnection>(); }

/// Enter marker-terminated body mode. The marker and any body bytes before it
/// are captured together, matching SMTP's inclusion of its end-of-body CRLF.
/// @param terminator Byte sequence that ends the body phase.
void PingpongMockServer::BeginMarkerBody(std::string_view terminator) {
  body_mode_ = BodyMode::kMarker;
  body_marker_.assign(terminator.data(), terminator.size());
  body_length_remaining_ = 0;
  body_terminator_remaining_ = 0;
}

/// Enter length-announced literal body mode. Exactly `length` bytes are
/// captured; the CRLF that follows the literal is consumed but not captured.
/// A zero length is valid and waits directly for that terminator.
/// @param length Announced literal byte count.
void PingpongMockServer::BeginLiteralBody(std::size_t length) {
  body_mode_ = BodyMode::kLiteral;
  body_marker_.clear();
  body_length_remaining_ = length;
  body_terminator_remaining_ = 2;
}

/// Enter exact-length body mode. Exactly `length` bytes are captured and no
/// terminator is consumed, so the next byte after the body starts the next
/// command. A zero length completes immediately.
/// @param length Announced body byte count.
void PingpongMockServer::BeginExactBody(std::size_t length) {
  body_mode_ = BodyMode::kExact;
  body_marker_.clear();
  body_length_remaining_ = length;
  body_terminator_remaining_ = 0;
}

/// Append decoded application bytes to the pending parser buffer. The outer
/// service loop drains this buffer after every transport call, so it remains
/// bounded by the scenario's command and upload budgets.
/// @param data First decoded byte.
/// @param size Number of bytes available at `data`.
void PingpongMockServer::ObserveIncomingData(const unsigned char* data, std::size_t size) {
  if (data == nullptr || size == 0) {
    return;
  }
  pending_control_bytes_.append(reinterpret_cast<const char*>(data), size);
}

/// Create the single control socketpair and queue the server greeting. These
/// peers never open a second application socket, so any later request is
/// rejected rather than silently replacing the live peer.
/// @param purpose Socket role requested by curl.
/// @param address Unused stream destination metadata required by the callback
///                signature.
/// @return Client descriptor for the control channel, or CURL_SOCKET_BAD.
curl_socket_t PingpongMockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* /*address*/) {
  if (scenario_ == nullptr || purpose != CURLSOCKTYPE_IPCXN || control_opened_) {
    return CURL_SOCKET_BAD;
  }

  connection_ = CreateConnection();
  if (!connection_ || !connection_->ok()) {
    connection_.reset();
    return CURL_SOCKET_BAD;
  }
  connection_->SetIncomingDataObserver(this);

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

/// Reset every borrowed pointer, descriptor, parser cursor, and observable
/// capture before borrowing the next Scenario, then let the subclass clear its
/// own protocol state.
/// @param scenario Scenario whose Connection supplies the greeting and replies.
void PingpongMockServer::ResetForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  connection_.reset();
  scenario_ = &scenario;
  control_reply_count_ = std::min<std::size_t>(scenario_limits::kMaxResponseChunks,
                                               static_cast<std::size_t>(scenario.connection().on_readable_size()));
  next_control_reply_ = 0;
  pending_control_bytes_.clear();
  control_transcript_.clear();
  uploaded_data_.clear();
  active_pollset_probe_count_ = 0;
  body_marker_.clear();
  body_length_remaining_ = 0;
  body_terminator_remaining_ = 0;
  body_mode_ = BodyMode::kCommand;
  control_opened_ = false;
  ResetProtocolState();
}

/// Apply bounded transport knobs when creating the scripted socket. Target
/// policies normally clear mail backpressure, but direct corpus replay must
/// retain deterministic, well-defined behavior.
/// @param connection Peer receiving the socket settings.
/// @param script Connection script carrying optional backpressure values.
void PingpongMockServer::ApplyScriptBackpressure(MockConnection* connection,
                                                 const curl::fuzzer::proto::Connection& script) {
  if (connection == nullptr) {
    return;
  }

  const std::uint32_t int_max = static_cast<std::uint32_t>(std::numeric_limits<int>::max());
  const auto& backpressure = script.backpressure();
  const int receive_buffer = static_cast<int>(std::min(backpressure.recv_buf_bytes(), int_max));
  connection->ApplyBackpressure(receive_buffer, static_cast<std::size_t>(backpressure.drain_limit()));
}

/// Return the next command-aligned response within the shared response-count
/// budget. Empty strings still advance the cursor: they are meaningful
/// truncation mutations for ordinary command states.
/// @return Scenario-owned reply, or nullptr after the bounded prefix.
const std::string* PingpongMockServer::NextControlReply() {
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
bool PingpongMockServer::WriteControlBytes(std::string_view bytes) {
  return bytes.empty() || (connection_ != nullptr &&
                           connection_->WriteAll(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
}

/// Consume the next scripted reply. Protocol peers use this when the reply
/// that completes an upload must be queued at command-acceptance time because
/// curl performs a blocking completion wait.
/// @return true when a scripted reply existed and was successfully written.
bool PingpongMockServer::WriteNextReply() {
  const std::string* response = NextControlReply();
  return response == nullptr ? false : WriteControlBytes(*response);
}

/// Remove optional leading horizontal whitespace and return the first token
/// without allocating. Protocol arguments are never interpreted here.
/// @param line Complete command line.
/// @return View of its first non-whitespace token.
std::string_view PingpongMockServer::FirstToken(std::string_view line) {
  std::size_t begin = 0;
  while (begin < line.size() && (line[begin] == ' ' || line[begin] == '\t')) {
    ++begin;
  }

  std::size_t end = begin;
  while (end < line.size() && line[end] != ' ' && line[end] != '\t' && line[end] != '\r' && line[end] != '\n') {
    ++end;
  }
  return line.substr(begin, end - begin);
}

/// Skip the first token and return the second whitespace-delimited token
/// without allocating. IMAP uses this to read the verb after the command tag.
/// @param line Complete command line.
/// @return View of its second whitespace-delimited token, or an empty view.
std::string_view PingpongMockServer::SecondToken(std::string_view line) {
  std::size_t position = 0;
  while (position < line.size() && (line[position] == ' ' || line[position] == '\t')) {
    ++position;
  }
  while (position < line.size() && line[position] != ' ' && line[position] != '\t' && line[position] != '\r' &&
         line[position] != '\n') {
    ++position;
  }
  while (position < line.size() && (line[position] == ' ' || line[position] == '\t')) {
    ++position;
  }

  std::size_t end = position;
  while (end < line.size() && line[end] != ' ' && line[end] != '\t' && line[end] != '\r' && line[end] != '\n') {
    ++end;
  }
  return line.substr(position, end - position);
}

/// Fold only ASCII lowercase command letters. Protocol verbs are ASCII tokens,
/// so locale-aware case conversion would add state and undefined signed-char
/// behavior without accepting anything curl can legitimately send.
/// @param token Parsed command token.
/// @param expected_uppercase Literal uppercase command name.
/// @return true when the tokens are equal ignoring ASCII case.
bool PingpongMockServer::TokenEquals(std::string_view token, std::string_view expected_uppercase) {
  if (token.size() != expected_uppercase.size()) {
    return false;
  }
  for (std::size_t index = 0; index < token.size(); ++index) {
    unsigned char actual = static_cast<unsigned char>(token[index]);
    if (actual >= 'a' && actual <= 'z') {
      actual = static_cast<unsigned char>(actual - 'a' + 'A');
    }
    if (actual != static_cast<unsigned char>(expected_uppercase[index])) {
      return false;
    }
  }
  return true;
}

/// Retain only a bounded prefix for assertions. Parsing and draining continue
/// against the full transport bytes, so reaching the cap cannot change curl's
/// behavior or manufacture socket backpressure.
/// @param source Newly observed bytes.
/// @param limit Maximum retained destination size.
/// @param destination Capture buffer receiving the available prefix.
void PingpongMockServer::CapturePrefix(std::string_view source, std::size_t limit, std::string* destination) {
  if (destination == nullptr || destination->size() >= limit) {
    return;
  }
  const std::size_t available = limit - destination->size();
  destination->append(source.data(), std::min(source.size(), available));
}

/// Advance the carrier without waiting, then process every complete command or
/// body segment already decoded into the pending buffer. A plaintext
/// connection yields raw socket bytes; a TLS carrier completes its handshake
/// and yields decrypted application bytes through ObserveIncomingData.
/// @return true when bytes, transport state, or a command/reply cursor advanced.
bool PingpongMockServer::ServiceControlConnection() {
  if (connection_ == nullptr) {
    return false;
  }

  const std::size_t size_before_read = pending_control_bytes_.size();
  const std::size_t transport_progress = connection_->DrainIncoming();
  bool made_progress = pending_control_bytes_.size() != size_before_read || transport_progress != 0;

  std::size_t consumed = 0;
  while (consumed < pending_control_bytes_.size()) {
    if (body_mode_ == BodyMode::kMarker) {
      const std::size_t marker = pending_control_bytes_.find(body_marker_, consumed);
      if (marker == std::string::npos) {
        break;
      }
      const std::size_t body_end = marker + body_marker_.size();
      CapturePrefix(std::string_view(pending_control_bytes_.data() + consumed, body_end - consumed),
                    kMaxCapturedUploadBytes, &uploaded_data_);
      consumed = body_end;
      body_mode_ = BodyMode::kCommand;
      made_progress = true;
      HandleBodyComplete();
      continue;
    }

    if (body_mode_ == BodyMode::kExact) {
      const std::size_t available = pending_control_bytes_.size() - consumed;
      const std::size_t take = std::min(available, body_length_remaining_);
      CapturePrefix(std::string_view(pending_control_bytes_.data() + consumed, take), kMaxCapturedUploadBytes,
                    &uploaded_data_);
      consumed += take;
      body_length_remaining_ -= take;
      if (take != 0) {
        made_progress = true;
      }
      if (body_length_remaining_ == 0) {
        body_mode_ = BodyMode::kCommand;
        made_progress = true;
        HandleBodyComplete();
        continue;
      }
      break;
    }

    if (body_mode_ == BodyMode::kLiteral) {
      if (body_length_remaining_ != 0) {
        const std::size_t available = pending_control_bytes_.size() - consumed;
        const std::size_t take = std::min(available, body_length_remaining_);
        CapturePrefix(std::string_view(pending_control_bytes_.data() + consumed, take), kMaxCapturedUploadBytes,
                      &uploaded_data_);
        consumed += take;
        body_length_remaining_ -= take;
        made_progress = true;
        continue;
      }

      const std::size_t available = pending_control_bytes_.size() - consumed;
      if (body_terminator_remaining_ == 2 && available >= 2 && pending_control_bytes_[consumed] == '\r' &&
          pending_control_bytes_[consumed + 1] == '\n') {
        consumed += 2;
        body_terminator_remaining_ = 0;
        body_mode_ = BodyMode::kCommand;
        made_progress = true;
        HandleBodyComplete();
        continue;
      }
      if (available >= 1) {
        const char byte = pending_control_bytes_[consumed];
        if (byte == '\r' || byte == '\n') {
          ++consumed;
          if (byte == '\n' || body_terminator_remaining_ == 0) {
            body_terminator_remaining_ = 0;
            body_mode_ = BodyMode::kCommand;
            HandleBodyComplete();
          } else {
            body_terminator_remaining_ = 1;
          }
          made_progress = true;
          continue;
        }
        // No terminating empty line is recognisable. Resume command parsing so
        // malformed uploads still make bounded progress.
        body_terminator_remaining_ = 0;
        body_mode_ = BodyMode::kCommand;
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
    HandleLine(command);
    consumed += command_size;
    made_progress = true;
  }

  if (consumed != 0) {
    pending_control_bytes_.erase(0, consumed);
  }
  return made_progress;
}

/// Prepare cleanup while the mock can still write to curl's control socket.
/// Let the peer queue its protocol-specific liveness reply, then half-close so
/// an unfinished transfer cannot wait on a reply that will never arrive.
void PingpongMockServer::FinishConnections() {
  if (connection_ != nullptr) {
    QueueShutdownReply();
    connection_->ShutdownWrite();
  }
}

/// Give curl's graceful shutdown one last chance to emit its teardown command
/// while the peer still owns its read half, then release the multi as the base
/// class would. The matching liveness reply was already queued by
/// FinishConnections.
/// @param multi Detached multi handle whose connection cache may be shutting
///              the protocol connection down.
void PingpongMockServer::HandleDetachedMulti(CurlMultiPtr multi) {
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
void PingpongMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
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

    // Pollset construction is coverage work, not part of the default driver:
    // keep the extra public-API call behind the scenario opt-in. Waiting until
    // the socket callback has run and the transfer remains active ensures the
    // pollset belongs to a live protocol state rather than setup or cleanup.
    if (scenario.probe_multi_pollset() && still_running && control_opened_) {
      ProbeMultiPollset(multi);
      ++active_pollset_probe_count_;
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
