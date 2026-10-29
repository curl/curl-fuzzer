/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the packet-aware in-process MQTT peer.

#include "proto_fuzzer/mqtt_mock_server.h"

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

// MQTT 3.1.1 control packet types, already shifted into the fixed header's
// high nibble. The low nibble carries type-specific flags such as PUBLISH QoS.
constexpr unsigned char kMqttConnect = 0x10;
constexpr unsigned char kMqttPublish = 0x30;
constexpr unsigned char kMqttPuback = 0x40;
constexpr unsigned char kMqttSubscribe = 0x80;
constexpr unsigned char kMqttSuback = 0x90;
constexpr unsigned char kMqttPingreq = 0xc0;
constexpr unsigned char kMqttPingresp = 0xd0;
constexpr unsigned char kMqttDisconnect = 0xe0;
constexpr std::size_t kMqttProbePublishBytes = 16 * 1024;
constexpr std::size_t kOversizedMqttCredentialBytes = 0x10000;

unsigned char ByteAt(std::string_view bytes, std::size_t index) { return static_cast<unsigned char>(bytes[index]); }

}  // namespace

/// Begin without a borrowed protobuf or open socketpair. RunLoop borrows a
/// Scenario only for the synchronous DriveScenario call in which socket
/// callbacks can run.
/// @param mode Closed harness-owned probe shape to apply before the transfer.
MqttMockServer::MqttMockServer(curl::fuzzer::proto::MqttProbeMode mode)
    : mode_(mode),
      scenario_(nullptr),
      server_chunk_count_(0),
      next_server_chunk_(0),
      packet_count_(0),
      connect_count_(0),
      publish_count_(0),
      subscribe_count_(0),
      qos1_publish_count_(0),
      active_pollset_probe_count_(0),
      release_script_chunks_(false),
      protocol_error_(false),
      socket_opened_(false) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
MqttMockServer::~MqttMockServer() = default;

/// @return A prefix of complete client packets from the most recent drive.
const std::string& MqttMockServer::packet_transcript() const { return packet_transcript_; }

/// @return A prefix of the first PUBLISH packet's topic.
const std::string& MqttMockServer::published_topic() const { return published_topic_; }

/// @return A prefix of the first PUBLISH packet's application payload.
const std::string& MqttMockServer::published_payload() const { return published_payload_; }

/// @return Number of complete client packets observed in the most recent drive.
std::size_t MqttMockServer::packet_count() const { return packet_count_; }

/// @return Number of CONNECT packets observed.
std::size_t MqttMockServer::connect_count() const { return connect_count_; }

/// @return Number of PUBLISH packets observed.
std::size_t MqttMockServer::publish_count() const { return publish_count_; }

/// @return Number of SUBSCRIBE packets observed.
std::size_t MqttMockServer::subscribe_count() const { return subscribe_count_; }

/// @return Number of PUBLISH packets that requested QoS 1.
std::size_t MqttMockServer::qos1_publish_count() const { return qos1_publish_count_; }

/// Report how many requested zero-timeout multi-poll probes ran during the
/// most recent drive. RunLoop increments this only after a successful perform
/// turn while curl still owns an active transfer and the MQTT socket is open.
/// @return Number of active, connected pollset probes in the previous drive.
std::size_t MqttMockServer::active_pollset_probe_count() const { return active_pollset_probe_count_; }

/// Reset every borrowed pointer, parser cursor, and observable capture before
/// borrowing the next Scenario.
/// @param scenario Scenario whose Connection supplies the CONNACK and any
///                 server-initiated packet chunks.
void MqttMockServer::ResetForScenario(const curl::fuzzer::proto::Scenario& scenario) {
  connection_.reset();
  scenario_ = &scenario;
  server_chunk_count_ = std::min<std::size_t>(scenario_limits::kMaxResponseChunks,
                                              static_cast<std::size_t>(scenario.connection().on_readable_size()));
  next_server_chunk_ = 0;
  packet_count_ = 0;
  connect_count_ = 0;
  publish_count_ = 0;
  subscribe_count_ = 0;
  qos1_publish_count_ = 0;
  active_pollset_probe_count_ = 0;
  pending_client_bytes_.clear();
  packet_transcript_.clear();
  published_topic_.clear();
  published_payload_.clear();
  release_script_chunks_ = false;
  protocol_error_ = false;
  socket_opened_ = false;
}

/// Apply bounded transport knobs when creating the scripted socket. Target
/// policies normally clear MQTT backpressure, but direct corpus replay must
/// retain deterministic, well-defined behavior.
/// @param connection Peer receiving the socket settings.
/// @param script Connection script carrying optional backpressure values.
void MqttMockServer::ApplyScriptBackpressure(MockConnection* connection,
                                             const curl::fuzzer::proto::Connection& script) {
  if (connection == nullptr) {
    return;
  }

  const std::uint32_t int_max = static_cast<std::uint32_t>(std::numeric_limits<int>::max());
  const auto& backpressure = script.backpressure();
  const int receive_buffer = static_cast<int>(std::min(backpressure.recv_buf_bytes(), int_max));
  connection->ApplyBackpressure(receive_buffer, static_cast<std::size_t>(backpressure.drain_limit()));
}

/// Create the default plaintext transport for the MQTT packet exchange. The
/// MQTTS subclass overrides this factory while retaining the binary parser.
/// @return A new socketpair-backed connection.
std::unique_ptr<MockConnection> MqttMockServer::CreateConnection() { return std::make_unique<MockConnection>(); }

/// Append decoded application bytes to the pending parser buffer. The outer
/// service loop drains this buffer after every transport call, so it remains
/// bounded by the scenario's packet budget.
/// @param data First decoded byte.
/// @param size Number of bytes available at `data`.
void MqttMockServer::ObserveIncomingData(const unsigned char* data, std::size_t size) {
  if (data == nullptr || size == 0) {
    return;
  }
  pending_client_bytes_.append(reinterpret_cast<const char*>(data), size);
}

/// Create the single MQTT socketpair and queue the scenario's first server
/// bytes. curl sends CONNECT immediately, so a normal scenario preloads the
/// CONNACK here; an empty or malformed greeting remains a reachable error path.
/// @param purpose Socket role requested by curl.
/// @param address Unused stream destination metadata required by the callback
///                signature.
/// @return Client descriptor for the MQTT channel, or CURL_SOCKET_BAD.
curl_socket_t MqttMockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* /*address*/) {
  if (scenario_ == nullptr || purpose != CURLSOCKTYPE_IPCXN || socket_opened_) {
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

  socket_opened_ = true;
  return connection_->take_client_fd();
}

/// Decode MQTT's base-128 remaining-length field. MQTT 3.1.1 permits at most
/// four length bytes; a fifth continuation is a malformed fixed header rather
/// than an invitation to wait for more input.
/// @param bytes Fixed header and whatever length bytes have arrived.
/// @param header_size Receives the fixed-header size when complete.
/// @param remaining_length Receives the declared body size when complete.
/// @return kComplete, kNeedMore, or kInvalid.
MqttMockServer::ParseResult MqttMockServer::ParseRemainingLength(std::string_view bytes, std::size_t* header_size,
                                                                 std::size_t* remaining_length) {
  std::size_t value = 0;
  std::size_t multiplier = 1;
  for (std::size_t index = 1; index <= 4; ++index) {
    if (bytes.size() <= index) {
      return ParseResult::kNeedMore;
    }
    const unsigned char encoded = ByteAt(bytes, index);
    value += static_cast<std::size_t>(encoded & 0x7fU) * multiplier;
    if ((encoded & 0x80U) == 0) {
      *header_size = index + 1;
      *remaining_length = value;
      return ParseResult::kComplete;
    }
    multiplier *= 128;
  }
  return ParseResult::kInvalid;
}

/// Retain only a bounded prefix for assertions. Parsing and draining continue
/// against the full transport bytes, so reaching the cap cannot change curl's
/// behavior or manufacture socket backpressure.
/// @param source Newly observed bytes.
/// @param limit Maximum retained destination size.
/// @param destination Capture buffer receiving the available prefix.
void MqttMockServer::CapturePrefix(std::string_view source, std::size_t limit, std::string* destination) {
  if (destination == nullptr || destination->size() >= limit) {
    return;
  }
  const std::size_t available = limit - destination->size();
  destination->append(source.data(), std::min(source.size(), available));
}

/// Keep failed peer writes local to the mock. Response cursors must still
/// advance after curl closes early, otherwise a replacement socket could see a
/// reply intended for an earlier packet.
/// @param bytes Response bytes to queue.
/// @return true when the complete fragment was queued.
bool MqttMockServer::WriteServerBytes(std::string_view bytes) {
  return bytes.empty() || (connection_ != nullptr &&
                           connection_->WriteAll(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
}

/// Interpret one complete client packet. Packet classification uses only the
/// fixed header, so a malformed variable header cannot desynchronize the
/// remaining-length parser that already found the next boundary.
/// @param first_byte Fixed header byte carrying the type and flags.
/// @param body Variable header plus payload, exactly `remaining_length` bytes.
void MqttMockServer::HandleClientPacket(unsigned char first_byte, std::string_view body) {
  const unsigned char type = static_cast<unsigned char>(first_byte & 0xf0U);
  switch (type) {
    case kMqttConnect:
      ++connect_count_;
      return;

    case kMqttPublish: {
      ++publish_count_;
      if (body.size() < 2) {
        return;
      }
      const std::size_t topic_length =
          (static_cast<std::size_t>(ByteAt(body, 0)) << 8U) | static_cast<std::size_t>(ByteAt(body, 1));
      std::size_t cursor = 2;
      const std::size_t available = body.size() - cursor;
      const std::size_t captured_topic = std::min(topic_length, available);
      CapturePrefix(body.substr(cursor, captured_topic), scenario_limits::kMaxMetadataBytes, &published_topic_);
      cursor += captured_topic;
      if (captured_topic < topic_length) {
        return;
      }

      const unsigned qos = (static_cast<unsigned>(first_byte) >> 1U) & 0x03U;
      if (qos == 1U) {
        if (body.size() - cursor < 2) {
          return;
        }
        const unsigned char packet_id_high = ByteAt(body, cursor);
        const unsigned char packet_id_low = ByteAt(body, cursor + 1);
        cursor += 2;
        // PUBACK has no flags and a two-byte remaining length followed by the
        // packet identifier it acknowledges. Current curl always publishes at
        // QoS 0; this branch keeps the acknowledgement path correct if a
        // future revision makes QoS configurable.
        const unsigned char puback[] = {kMqttPuback, 0x02, packet_id_high, packet_id_low};
        (void)WriteServerBytes(std::string_view(reinterpret_cast<const char*>(puback), sizeof(puback)));
        ++qos1_publish_count_;
      }

      CapturePrefix(body.substr(cursor), kMaxCapturedPayloadBytes, &published_payload_);
      return;
    }

    case kMqttSubscribe: {
      ++subscribe_count_;
      const unsigned char packet_id_high = body.empty() ? 0 : ByteAt(body, 0);
      const unsigned char packet_id_low = body.size() < 2 ? 0 : ByteAt(body, 1);
      // SUBACK echoes the SUBSCRIBE packet id and reports success for the
      // single requested topic filter. curl's MQTT state machine compares both
      // identifier bytes and the return code before accepting the packet.
      const unsigned char suback[] = {kMqttSuback, 0x03, packet_id_high, packet_id_low, 0x00};
      (void)WriteServerBytes(std::string_view(reinterpret_cast<const char*>(suback), sizeof(suback)));
      // Only the subscribe flow remains readable after its acknowledgement.
      // on_readable chunks carry server-initiated packets such as PUBLISH.
      release_script_chunks_ = true;
      return;
    }

    case kMqttPingreq: {
      const unsigned char pingresp[] = {kMqttPingresp, 0x00};
      (void)WriteServerBytes(std::string_view(reinterpret_cast<const char*>(pingresp), sizeof(pingresp)));
      return;
    }

    case kMqttDisconnect:
      // curl sends DISCONNECT after PUBLISH. No reply is defined, and the
      // cleanup half-close below still terminates the socket.
      return;

    default:
      // CONNACK/SUBACK/PUBACK and unknown types are server-to-client packets.
      // Recording them in the transcript is enough; inventing a reply would
      // only add bytes curl never reads in this direction.
      return;
  }
}

/// Release one scenario-provided server chunk after SUBACK. Chunks are opaque
/// bytes, not newline commands: each one is expected to be a complete MQTT
/// packet (for example PUBLISH followed by DISCONNECT). An explicitly empty
/// chunk half-closes the peer, retaining a scripted truncation/EOF path.
/// @return true when a script slot was consumed.
bool MqttMockServer::ReleaseNextServerChunk() {
  if (!release_script_chunks_ || scenario_ == nullptr || connection_ == nullptr ||
      next_server_chunk_ >= server_chunk_count_) {
    return false;
  }

  const std::string& chunk = scenario_->connection().on_readable(static_cast<int>(next_server_chunk_++));
  if (chunk.empty()) {
    connection_->ShutdownWrite();
    release_script_chunks_ = false;
    return true;
  }

  (void)WriteServerBytes(chunk);
  if (next_server_chunk_ >= server_chunk_count_) {
    connection_->ShutdownWrite();
  }
  return true;
}

/// Advance the carrier without waiting, then process every complete packet
/// already decoded into the pending buffer. A plaintext connection yields raw
/// socket bytes; a TLS carrier completes its handshake and yields decrypted
/// application bytes through ObserveIncomingData. A packet is delivered only
/// after its fixed header and declared body have both arrived, so fragmentation
/// cannot shift the parser.
/// @return true when bytes, transport state, a packet, or a response cursor
///         advanced.
bool MqttMockServer::ServiceClientConnection() {
  if (connection_ == nullptr || protocol_error_) {
    return false;
  }

  const std::size_t size_before_read = pending_client_bytes_.size();
  const std::size_t transport_progress = connection_->DrainIncoming();
  bool made_progress = pending_client_bytes_.size() != size_before_read || transport_progress != 0;

  std::size_t consumed = 0;
  int packets = 0;
  while (consumed < pending_client_bytes_.size() && packets < kMaxPacketsPerService) {
    const std::string_view available(pending_client_bytes_.data() + consumed, pending_client_bytes_.size() - consumed);
    if (available.size() < 2) {
      break;
    }

    std::size_t header_size = 0;
    std::size_t remaining_length = 0;
    const ParseResult parsed = ParseRemainingLength(available, &header_size, &remaining_length);
    if (parsed == ParseResult::kNeedMore) {
      break;
    }
    if (parsed == ParseResult::kInvalid || remaining_length > kMaxPacketBytes) {
      protocol_error_ = true;
      break;
    }

    const std::size_t packet_size = header_size + remaining_length;
    if (available.size() < packet_size) {
      break;
    }

    const std::string_view packet = available.substr(0, packet_size);
    CapturePrefix(packet, kMaxCapturedPacketBytes, &packet_transcript_);
    ++packet_count_;
    HandleClientPacket(ByteAt(packet, 0), packet.substr(header_size));
    consumed += packet_size;
    ++packets;
    made_progress = true;
  }

  if (protocol_error_) {
    pending_client_bytes_.clear();
    // curl's malformed-packet paths are bounded, but closing the write half
    // immediately keeps a bogus remaining length from waiting on the idle
    // budget for an impossible body.
    connection_->ShutdownWrite();
    release_script_chunks_ = false;
  } else if (consumed != 0) {
    pending_client_bytes_.erase(0, consumed);
  }
  return made_progress;
}

/// Half-close the peer so curl observes a deterministic end of server packets
/// after the transfer has stopped or the idle budget expired.
void MqttMockServer::FinishConnections() {
  if (connection_ != nullptr) {
    connection_->ShutdownWrite();
  }
}

/// Install one fixed option shape after ordinary scenario options but before
/// curl starts the transfer. The static strings outlive the easy handle;
/// notably CURLOPT_POSTFIELDS borrows rather than copies its pointer.
/// @param easy Handle receiving the harness-owned probe values.
void MqttMockServer::ApplyProbeOptions(CURL* easy) const {
  if (easy == nullptr) {
    return;
  }

  switch (mode_) {
    case curl::fuzzer::proto::MQTT_PROBE_SEND_BACKPRESSURE: {
      static const std::string publish_body(kMqttProbePublishBytes, 'p');
      (void)curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(publish_body.size()));
      (void)curl_easy_setopt(easy, CURLOPT_POSTFIELDS, publish_body.c_str());
      return;
    }

    case curl::fuzzer::proto::MQTT_PROBE_OVERSIZED_USERNAME: {
      static const std::string username(kOversizedMqttCredentialBytes, 'u');
      (void)curl_easy_setopt(easy, CURLOPT_USERNAME, username.c_str());
      (void)curl_easy_setopt(easy, CURLOPT_PASSWORD, "");
      return;
    }

    case curl::fuzzer::proto::MQTT_PROBE_OVERSIZED_PASSWORD: {
      static const std::string password(kOversizedMqttCredentialBytes, 'p');
      (void)curl_easy_setopt(easy, CURLOPT_USERNAME, "");
      (void)curl_easy_setopt(easy, CURLOPT_PASSWORD, password.c_str());
      return;
    }

    case curl::fuzzer::proto::MQTT_PROBE_DEFAULT:
    default:
      return;
  }
}

/// Alternate curl transitions with immediate peer service until the transfer
/// completes or deterministic idle/operation caps win. No select(), poll(), or
/// sleep is needed: the CONNACK is preloaded, synthesized acknowledgements are
/// written from the same thread, and scripted server packets are released one
/// per turn so curl consumes the preceding acknowledgement first.
/// @param multi Multi handle containing `easy`.
/// @param easy Easy handle already installed on this mock.
/// @param scenario Connection script to borrow.
void MqttMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  ApplyProbeOptions(easy);
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

    // Pollset construction is opt-in coverage work. Waiting until the socket
    // callback has run and the transfer remains active keeps the default hot
    // loop syscall-free and asks curl for a live MQTT protocol pollset.
    if (scenario.probe_multi_pollset() && still_running && socket_opened_) {
      ProbeMultiPollset(multi);
      ++active_pollset_probe_count_;
    }

    bool made_progress = still_running != running_before;
    made_progress = ServiceClientConnection() || made_progress;
    made_progress = ReleaseNextServerChunk() || made_progress;
    if (made_progress) {
      idle_iterations = 0;
    } else {
      ++idle_iterations;
    }
  }

  // The final perform may have emitted CONNECT/PUBLISH/DISCONNECT immediately
  // before marking the transfer done. Drain those bytes before cleanup.
  (void)ServiceClientConnection();
  (void)ReleaseNextServerChunk();
  FinishConnections();
  scenario_ = nullptr;
}

/// Retain protocol outcomes in coverage and introspector builds.
void MqttMockServer::ObserveState() {
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  MockServerBase::ObserveState();
  const volatile std::size_t mqtt_observation[] = {packet_transcript().size(), packet_count(), publish_count(),
                                                   subscribe_count(), published_payload().size()};
  (void)mqtt_observation;
#endif
}

}  // namespace proto_fuzzer
