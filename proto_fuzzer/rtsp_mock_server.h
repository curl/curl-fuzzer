/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Request-aligned in-process peer for curl's RTSP state machine.

#ifndef PROTO_FUZZER_RTSP_MOCK_SERVER_H_
#define PROTO_FUZZER_RTSP_MOCK_SERVER_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "proto_fuzzer/pingpong_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::RtspMockServer
/// @brief Services curl's single-socket RTSP exchange.
///
/// RTSP is HTTP-like but starts with a client request: there is no server
/// greeting, and every response is tied to exactly one request line plus its
/// header block. That request/response rhythm is line-aligned, so this peer
/// reuses PingpongMockServer rather than duplicating its bounded transport
/// loop. Scenario.connection.initial_response is normally empty; each
/// on_readable entry is one complete response to the next request. A response
/// may contain a status line, headers, an entity body, and RFC 2326
/// interleaved RTP packets in the same byte string.
///
/// The peer parses the request start line and CSeq to track the exchange, and
/// drains an announced request body with BeginExactBody() because RTSP body
/// bytes are followed immediately by the next request rather than by a line
/// terminator. The response text remains entirely fuzz-controlled: it is not
/// rewritten to match the observed CSeq, so a mismatch still reaches curl's
/// CURLE_RTSP_CSEQ_ERROR path. RTSP cannot open follow-on sockets or pipeline
/// multiple outstanding requests, so a second socket is refused by the shared
/// base class.
class RtspMockServer : public PingpongMockServer {
 public:
  RtspMockServer();

  ~RtspMockServer() override;

  RtspMockServer(const RtspMockServer&) = delete;
  RtspMockServer& operator=(const RtspMockServer&) = delete;

  std::size_t request_count() const;

  std::size_t response_count() const;

  std::uint32_t last_client_cseq() const;

  const std::string& last_request_line() const;

  const std::string& last_method() const;

  const std::string& last_stream_uri() const;

 protected:
  void HandleLine(std::string_view line) override;

  void HandleBodyComplete() override;

  void ResetProtocolState() override;

 private:
  void BeginRequest(std::string_view line);

  void FinishRequest();

  void ParseHeader(std::string_view line);

  bool in_request_;
  bool in_headers_;
  bool have_client_cseq_;
  bool have_content_length_;
  std::uint32_t client_cseq_;
  std::uint32_t last_client_cseq_;
  std::size_t content_length_;
  std::size_t request_count_;
  std::size_t response_count_;
  std::string last_request_line_;
  std::string last_method_;
  std::string last_stream_uri_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_RTSP_MOCK_SERVER_H_
