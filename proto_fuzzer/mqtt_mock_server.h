/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Packet-aware in-process peer for curl's binary MQTT state machine.

#ifndef PROTO_FUZZER_MQTT_MOCK_SERVER_H_
#define PROTO_FUZZER_MQTT_MOCK_SERVER_H_

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

/// @class proto_fuzzer::MqttMockServer
/// @brief Services curl's single-connection binary MQTT exchange.
///
/// MQTT has no line grammar: every packet starts with a one-byte fixed header
/// (message type plus flags) followed by a 1-4 byte base-128 remaining-length
/// field. This peer therefore treats Scenario.connection as opaque server
/// bytes rather than a command/reply script:
///
/// - `initial_response` is queued as soon as curl opens the socket and is
///   expected to contain a CONNACK (`20 02 00 00`).
/// - The peer reads and reassembles complete client packets from the same
///   socket, using the fixed header and remaining length to find boundaries.
/// - CONNECT needs no synthetic reply because the CONNACK was preloaded.
/// - SUBSCRIBE receives a synthesized SUBACK that echoes its packet id. After
///   that acknowledgement the peer releases the bounded `on_readable` chunks
///   one at a time as server-initiated packets (for example PUBLISH followed
///   by a server DISCONNECT).
/// - PUBLISH is recorded as the fuzz-controlled topic and payload. A QoS 1
///   PUBLISH receives the matching PUBACK, even though the current curl
///   revision always emits QoS 0.
/// - PINGREQ receives PINGRESP. A client DISCONNECT only ends the packet
///   stream; the peer still half-closes during cleanup.
///
/// All work remains in-process and non-waiting, so malformed packet headers
/// terminate by the operation budget or a half-close instead of a timeout.
///
/// Subclasses replace the transport through CreateConnection(). The implicit-
/// TLS MQTTS peer uses that hook to wrap the identical packet exchange in a
/// verified OpenSSL connection; incoming bytes are observed after transport
/// decoding so the parser does not depend on the carrier.
class MqttMockServer : public MockServerBase, public IncomingDataObserver {
 public:
  MqttMockServer();

  ~MqttMockServer() override;

  MqttMockServer(const MqttMockServer&) = delete;
  MqttMockServer& operator=(const MqttMockServer&) = delete;

  // Bounded raw capture of complete client packets, including their fixed
  // headers. Tests use it to assert CONNECT/CONNECT acknowledgement order
  // without parsing curl's debug output.
  const std::string& packet_transcript() const;

  // Bounded topic capture from the first PUBLISH packet.
  const std::string& published_topic() const;

  // Bounded payload capture from the first PUBLISH packet.
  const std::string& published_payload() const;

  std::size_t packet_count() const;

  std::size_t connect_count() const;

  std::size_t publish_count() const;

  std::size_t subscribe_count() const;

  // Number of PUBLISH packets whose fixed-header QoS bits requested QoS 1.
  std::size_t qos1_publish_count() const;

 protected:
  virtual std::unique_ptr<MockConnection> CreateConnection();

  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

 private:
  /// Outcome of decoding the base-128 remaining-length field.
  enum class ParseResult {
    kNeedMore,
    kInvalid,
    kComplete,
  };

  // Decode a fixed header whose first byte is already present at offset zero.
  // Returns complete, need-more-data, or invalid (>4 length bytes).
  static ParseResult ParseRemainingLength(std::string_view bytes, std::size_t* header_size,
                                          std::size_t* remaining_length);

  void ResetForScenario(const curl::fuzzer::proto::Scenario& scenario);

  static void ApplyScriptBackpressure(MockConnection* connection, const curl::fuzzer::proto::Connection& script);

  bool ServiceClientConnection();

  void HandleClientPacket(unsigned char first_byte, std::string_view body);

  bool ReleaseNextServerChunk();

  bool WriteServerBytes(std::string_view bytes);

  static void CapturePrefix(std::string_view source, std::size_t limit, std::string* destination);

  void FinishConnections();

  /// A client packet larger than this cannot be produced by the bounded
  /// scenario surface. Treating it as a protocol error prevents a mutated
  /// remaining-length field from retaining data until the drive budget.
  static constexpr std::size_t kMaxPacketBytes = 64 * 1024;

  /// Observability must not grow with a future curl packet loop.
  static constexpr std::size_t kMaxCapturedPacketBytes = 64 * 1024;
  static constexpr std::size_t kMaxCapturedPayloadBytes = 2 * scenario_limits::kMaxMetadataBytes;

  /// Complete packets handled per service turn. A bounded batch keeps
  /// several coalesced packets progressing without letting a malformed stream
  /// occupy the whole drive iteration.
  static constexpr int kMaxPacketsPerService = 16;

  /// Borrowed only while RunLoop is active, including every socket callback.
  const curl::fuzzer::proto::Scenario* scenario_;
  /// Runtime-visible prefix of primary on_readable server-packet fragments.
  std::size_t server_chunk_count_;
  /// Cursor advanced once per released server chunk.
  std::size_t next_server_chunk_;
  /// Total complete client packets observed in this drive.
  std::size_t packet_count_;
  std::size_t connect_count_;
  std::size_t publish_count_;
  std::size_t subscribe_count_;
  std::size_t qos1_publish_count_;
  /// Partial fixed header or packet body retained until the next read.
  std::string pending_client_bytes_;
  /// Bounded test-facing capture of complete client packets.
  std::string packet_transcript_;
  /// Bounded test-facing capture of the first PUBLISH variable header.
  std::string published_topic_;
  /// Bounded test-facing capture of the first PUBLISH payload.
  std::string published_payload_;
  /// SUBACK has been queued; on_readable chunks are now server packets.
  bool release_script_chunks_;
  /// An invalid remaining-length field ended the client packet stream.
  bool protocol_error_;
  /// Prevent a second socket from displacing the live first one.
  bool socket_opened_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MQTT_MOCK_SERVER_H_
