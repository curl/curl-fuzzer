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

#include "curl_fuzzer.pb.h"
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
/// CURLE_RTSP_CSEQ_ERROR path. An ordinary drive cannot open follow-on sockets
/// or pipeline multiple outstanding requests. The closed lifecycle probe runs
/// three sequential drives so curl can replace one half-closed cached
/// transport before changing origins.
class RtspMockServer : public PingpongMockServer {
 public:
  RtspMockServer();

  ~RtspMockServer() override;

  void ObserveState() override;

  RtspMockServer(const RtspMockServer&) = delete;
  RtspMockServer& operator=(const RtspMockServer&) = delete;

  void ConfigureClient(CURL* easy, curl::fuzzer::proto::RtspProbeMode mode);

  CURLcode DriveCrossOriginReuseScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

  std::size_t request_count() const;

  std::size_t response_count() const;

  std::uint32_t last_client_cseq() const;

  const std::string& last_request_line() const;

  const std::string& last_method() const;

  const std::string& last_stream_uri() const;

  std::size_t client_write_failure_count() const;

  std::size_t opened_transport_count() const;

 protected:
  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;

  void HandleLine(std::string_view line) override;

  void HandleBodyComplete() override;

  void ResetProtocolState() override;

 private:
  static std::size_t ProbeWriteCallback(char* contents, std::size_t size, std::size_t nmemb, void* userdata);

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
  curl::fuzzer::proto::RtspProbeMode probe_mode_;
  std::size_t client_write_failure_count_;
  std::size_t opened_transport_count_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_RTSP_MOCK_SERVER_H_
