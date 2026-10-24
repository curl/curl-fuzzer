/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief BER/ASN.1-aware in-process peer for curl's OpenLDAP-backed LDAP
///        client.

#ifndef PROTO_FUZZER_LDAP_MOCK_SERVER_H_
#define PROTO_FUZZER_LDAP_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/incoming_data_observer.h"
#include "proto_fuzzer/mock_server_base.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::LdapMockServer
/// @brief Services curl's single-connection LDAP bind and search exchange.
///
/// LDAP is not line-oriented: every message is a BER-encoded LDAPMessage
/// (RFC 4511), so this peer treats Scenario.connection as a binary script. It
/// parses each complete client TLV, answers bind requests with a bindResponse
/// that echoes the client's message id, and replays the scenario's on_readable
/// chunks as search-result messages before synthesizing a searchResDone.
///
/// Socket confinement: curl's LDAP handler opens its transport through the
/// ordinary connection filter (and therefore the harness OPENSOCKETFUNCTION),
/// then duplicates that descriptor for OpenLDAP's own socket I/O. Because the
/// duplicate names the same socketpair endpoint, every byte still stays inside
/// the in-process peer; no loopback listener or real network socket is needed.
///
/// Transport selection: subclasses replace CreateConnection(). The implicit-TLS
/// LDAPS peer uses that hook to run the identical BER exchange inside a
/// verified OpenSSL acceptor. Incoming application bytes arrive through
/// ObserveIncomingData() after any transport decoding, so the parser does not
/// depend on whether the socketpair is plaintext or TLS.
///
/// Script semantics:
/// - `initial_response`, when non-empty, is the bind reply. The peer releases
///   it only after the client's bindRequest and rewrites its envelope
///   messageID to match, so a seed can script both success and failure without
///   hard-coding OpenLDAP's message counter. When empty, the peer synthesizes
///   a successful bindResponse.
/// - Before any bind, OpenLDAP's exact root-DSE supportedSASLMechanisms query
///   receives a peer-owned entry advertising only PLAIN and a successful done.
///   This discovery exchange never consumes mutation-controlled result chunks.
/// - Each `on_readable` chunk is one complete server LDAPMessage (for example a
///   searchResEntry). Chunks are forwarded in order after the searchRequest and
///   are renumbered to the search message id when their envelope parses.
/// - A chunk carrying searchResDone ends the search. Otherwise the peer writes
///   a successful searchResDone once every chunk has been released.
/// - An empty chunk half-closes the peer, preserving a deterministic
///   truncated-stream path instead of inventing a completion.
///
/// BER scope: this is intentionally a minimal encoder/decoder. It understands
/// definite-length, one-byte and long-form lengths up to four bytes, and the
/// primitive tags needed to delimit LDAPMessage envelopes and recognize the
/// fixed mechanism query. Scripted server operation bodies remain opaque so
/// malformed server data still reaches OpenLDAP's full parser. All sizes are
/// bounded by kMaxClientMessageBytes.
class LdapMockServer : public MockServerBase, public IncomingDataObserver {
 public:
  LdapMockServer();

  ~LdapMockServer() override;

  LdapMockServer(const LdapMockServer&) = delete;
  LdapMockServer& operator=(const LdapMockServer&) = delete;

  // Append one transport-decoded client fragment to the BER parser input.
  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

  // Bounded raw capture of complete client LDAPMessages, including envelope.
  const std::string& packet_transcript() const;

  // Number of bindRequest messages observed in the most recent drive.
  std::size_t bind_request_count() const;

  // Number of searchRequest messages observed.
  std::size_t search_request_count() const;

  // Number of root-DSE supportedSASLMechanisms searches observed.
  std::size_t mechanism_search_request_count() const;

  // Number of unbindRequest messages observed during teardown.
  std::size_t unbind_request_count() const;

  // Number of server messages written, both scripted and synthesized.
  std::size_t server_message_count() const;

  // Number of on_readable chunks forwarded during a search.
  std::size_t scripted_message_count() const;

  // Number of searchResDone messages this peer generated itself.
  std::size_t synthesized_done_count() const;

  // Number of bind requests answered from initial_response rather than by the
  // synthesized success response.
  std::size_t scripted_bind_response_count() const;

 protected:
  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;

  // Construct the transport wrapping curl's socketpair endpoint. The default
  // is a plaintext MockConnection; the LDAPS peer overrides this to return a
  // server-side TLS acceptor over the same socket.
  virtual std::unique_ptr<MockConnection> CreateConnection();

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// Outcome of decoding one complete TLV or LDAPMessage envelope.
  enum class ParseResult {
    kNeedMore,
    kInvalid,
    kComplete,
  };

  /// Decoded BER TLV header plus its bounded extent within the input view.
  struct TlvView {
    unsigned char tag = 0;         ///< BER identifier octet.
    std::size_t value_offset = 0;  ///< Offset of the first value byte.
    std::size_t value_length = 0;  ///< Declared value size in bytes.
    std::size_t total_length = 0;  ///< Encoded TLV size including header.
  };

  /// Decoded LDAPMessage envelope: enough to route a request and echo its id.
  struct MessageView {
    unsigned char op_tag = 0;           ///< Protocol operation identifier.
    std::uint32_t message_id = 0;       ///< Envelope INTEGER value.
    std::size_t total_length = 0;       ///< Encoded LDAPMessage size.
    bool sasl_mechanism_query = false;  ///< Root-DSE mechanism query shape.
  };

  // Decode one definite-length TLV starting at `offset`.
  static ParseResult ParseTlv(std::string_view bytes, std::size_t offset, TlvView* view);

  // Decode an LDAPMessage SEQUENCE { messageID INTEGER, protocolOp ... }.
  static ParseResult ParseMessage(std::string_view bytes, MessageView* message);

  // Recognize OpenLDAP's fixed root-DSE SASL mechanism query.
  static bool IsSaslMechanismSearch(std::string_view value);

  static void AppendBerLength(std::string* out, std::size_t length);

  static void AppendTlv(std::string* out, unsigned char tag, std::string_view value);

  static void AppendBerInteger(std::string* out, std::uint32_t value);

  // Encode LDAPResult-shaped protocol operations (bindResponse, searchResDone).
  static void BuildResultMessage(std::uint32_t message_id, unsigned char op_tag, int result_code, std::string* out);

  // Encode a root-DSE entry advertising the bounded PLAIN SASL mechanism.
  static void BuildSaslMechanismsEntry(std::uint32_t message_id, std::string* out);

  // Replace the envelope messageID while preserving the rest of the message.
  static bool RewriteMessageId(std::string_view message, std::uint32_t message_id, std::string* out);

  static bool MessageOpTag(std::string_view message, unsigned char* op_tag);

  void ResetForScenario(const curl::fuzzer::proto::Scenario& scenario);

  static void ApplyScriptBackpressure(MockConnection* connection, const curl::fuzzer::proto::Connection& script);

  bool ServiceClientConnection();

  void HandleClientMessage(const MessageView& message);

  void HandleBindRequest(std::uint32_t message_id);

  void HandleSearchRequest(std::uint32_t message_id);

  void HandleMechanismSearchRequest(std::uint32_t message_id);

  bool ReleaseNextServerChunk();

  bool FinishSearchIfReady();

  bool WriteServerBytes(std::string_view bytes);

  static void CapturePrefix(std::string_view source, std::size_t limit, std::string* destination);

  void FinishConnections();

  /// A client message larger than this cannot be produced by the bounded
  /// scenario surface. Treating it as a protocol error prevents a mutated
  /// length field from retaining data until the drive budget expires.
  static constexpr std::size_t kMaxClientMessageBytes = 64 * 1024;

  /// Observability must not grow with a future curl request loop.
  static constexpr std::size_t kMaxCapturedMessageBytes = 64 * 1024;

  /// Complete messages handled per service turn.
  static constexpr int kMaxMessagesPerService = 16;

  /// Borrowed only while RunLoop is active, including every socket callback.
  const curl::fuzzer::proto::Scenario* scenario_;
  /// Runtime-visible prefix of primary on_readable search-result chunks.
  std::size_t server_chunk_count_;
  /// Cursor advanced once per released search-result chunk.
  std::size_t next_server_chunk_;
  std::size_t bind_request_count_;
  std::size_t search_request_count_;
  std::size_t mechanism_search_request_count_;
  std::size_t unbind_request_count_;
  std::size_t server_message_count_;
  std::size_t scripted_message_count_;
  std::size_t synthesized_done_count_;
  std::size_t scripted_bind_response_count_;
  /// Partial TLV or message body retained until the next read.
  std::string pending_client_bytes_;
  /// Bounded test-facing capture of complete client messages.
  std::string packet_transcript_;
  /// Message id of the most recent search request, used to renumber results.
  std::uint32_t search_message_id_;
  /// A searchRequest is outstanding and its done response is still pending.
  bool search_active_;
  /// A searchResDone has been scripted or synthesized for the active search.
  bool search_done_sent_;
  /// initial_response has already been used as the bind reply.
  bool scripted_bind_consumed_;
  /// on_readable chunks are now search-result messages.
  bool release_script_chunks_;
  /// An invalid envelope or an explicit empty chunk ended the byte stream.
  bool peer_closed_;
  /// An invalid TLV ended the client message stream.
  bool protocol_error_;
  /// Prevent a second socket from displacing the live first one.
  bool socket_opened_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_LDAP_MOCK_SERVER_H_
