/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded loopback UDP peer for structured TFTP scenarios.

#ifndef PROTO_FUZZER_TFTP_MOCK_SERVER_H_
#define PROTO_FUZZER_TFTP_MOCK_SERVER_H_

#include <netinet/in.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// Identifies which stable server transfer ID received a client datagram.
/// Tests use this distinction to prove that curl moves from the well-known
/// request endpoint to the transfer endpoint selected by the first reply.
enum class TftpSocketRole {
  kRequest,   ///< Endpoint placed in curl's rewritten destination address.
  kTransfer,  ///< Endpoint used for replies and the rest of the exchange.
};

/// One bounded observation of a datagram curl sent to the in-process peer.
/// Keeping observations on the server object avoids callbacks or globals in
/// protocol tests, while the fixed count cap prevents a malformed exchange
/// from retaining traffic in proportion to the drive-loop budget.
struct TftpReceivedDatagram {
  TftpSocketRole received_on;  ///< Server endpoint that received the packet.
  std::uint16_t source_port;   ///< Curl's UDP transfer ID in host byte order.
  std::string bytes;           ///< Complete UDP payload, including TFTP header.
};

/// @class proto_fuzzer::TftpMockServer
/// @brief Real, nonblocking UDP peer for curl's TFTP state machine.
///
/// An AF_UNIX socketpair cannot model TFTP: curl binds the returned descriptor
/// as an IP datagram socket and uses sendto/recvfrom with a mutable transfer
/// address. This peer binds two ephemeral loopback endpoints. The request
/// endpoint receives RRQ/WRQ, while every response originates at the transfer
/// endpoint so curl exercises the RFC transfer-ID pinning path.
///
/// `Connection.initial_response`, when nonempty, is the first response
/// datagram. Each retained `Connection.on_readable` value is one subsequent
/// datagram, including an explicitly empty value. A single datagram is released
/// after each curl state-machine turn, which preserves packet boundaries and
/// permits duplicates, unexpected blocks, and malformed packets without a
/// thread or wall-clock wait.
class TftpMockServer final : public MockServerBase {
 public:
  TftpMockServer();
  ~TftpMockServer() override;

  TftpMockServer(const TftpMockServer&) = delete;
  TftpMockServer& operator=(const TftpMockServer&) = delete;

  const std::vector<TftpReceivedDatagram>& received_datagrams() const;

  std::uint16_t request_port() const;

  std::uint16_t transfer_port() const;

 protected:
  curl_socket_t HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) override;

  SocketSetupDisposition GetSocketSetupDisposition(curl_socket_t curlfd, curlsocktype purpose) const override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// One client packet can follow the initial request and every retained server
  /// packet. Capturing anything beyond that useful prefix would make test-only
  /// observation memory follow malformed retry traffic rather than coverage.
  static constexpr std::size_t kMaxCapturedDatagrams = scenario_limits::kMaxResponseChunks + 2;

  void PrepareScript(const curl::fuzzer::proto::Connection& connection);

  void ResetPeer();

  static bool ConfigureSocket(int fd);

  static int OpenLoopbackSocket(struct sockaddr_in* bound_address);

  static bool RewriteDestination(struct curl_sockaddr* address, const struct sockaddr_in& destination);

  std::size_t DrainSocket(int fd, TftpSocketRole role);

  std::size_t DrainClientDatagrams();

  void RememberClientAddress(const struct sockaddr_in& address, socklen_t length);

  bool SendNextDatagram();

  std::array<const std::string*, scenario_limits::kMaxResponseChunks + 1> response_datagrams_;
  std::size_t response_datagram_count_;
  std::size_t next_response_datagram_;

  int request_fd_;
  int transfer_fd_;
  struct sockaddr_in client_address_;
  socklen_t client_address_length_;
  bool has_client_address_;
  bool socket_opened_;
  std::uint16_t request_port_;
  std::uint16_t transfer_port_;
  std::vector<TftpReceivedDatagram> received_datagrams_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TFTP_MOCK_SERVER_H_
