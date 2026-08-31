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

  /// Return the bounded client datagrams observed during the most recent run.
  /// @return Borrowed observations that remain valid until the next drive or
  ///         destruction of this server.
  const std::vector<TftpReceivedDatagram>& received_datagrams() const;

  /// Expose the request endpoint for transfer-ID assertions, not for routing.
  /// @return request UDP port in host byte order, or zero before socket setup.
  std::uint16_t request_port() const;

  /// Expose the response endpoint for transfer-ID assertions, not for routing.
  /// @return transfer UDP port in host byte order, or zero before socket setup.
  std::uint16_t transfer_port() const;

 protected:
  /// Create the real UDP client descriptor and replace curl's destination with
  /// the private request endpoint. Curl owns a successful return value.
  /// @param purpose Socket purpose supplied by curl's open-socket callback.
  /// @param address Mutable destination storage supplied by curl.
  /// @return client UDP descriptor, or CURL_SOCKET_BAD on setup failure.
  curl_socket_t HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) override;

  /// Alternate curl and peer state-machine turns without blocking. This makes
  /// packet ordering deterministic and lets incomplete scripts terminate by an
  /// operation/idle budget instead of curl's wall-clock TFTP retransmit timer.
  /// @param multi Multi handle containing the scenario's easy handle.
  /// @param easy Easy handle being driven; all work is reached through multi.
  /// @param scenario Scenario whose primary Connection supplies UDP packets.
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// One client packet can follow the initial request and every retained server
  /// packet. Capturing anything beyond that useful prefix would make test-only
  /// observation memory follow malformed retry traffic rather than coverage.
  static constexpr std::size_t kMaxCapturedDatagrams = scenario_limits::kMaxResponseChunks + 2;

  /// Build the borrowed response-pointer table before curl can open a socket.
  /// @param connection Primary connection whose packet boundaries are retained.
  void PrepareScript(const curl::fuzzer::proto::Connection& connection);

  /// Close only server-owned sockets and clear address/routing state. The
  /// returned client descriptor is deliberately absent because curl owns it.
  void ResetPeer();

  /// Set nonblocking and close-on-exec explicitly because callback-created
  /// descriptors cannot rely on curl's native socket() flags.
  /// @param fd Descriptor to configure.
  /// @return true only when both descriptor invariants were established.
  static bool ConfigureSocket(int fd);

  /// Bind one IPv4 UDP endpoint to an ephemeral loopback port.
  /// @param bound_address Receives the exact address selected by the kernel.
  /// @return owned descriptor, or -1 after closing any failed descriptor.
  static int OpenLoopbackSocket(struct sockaddr_in* bound_address);

  /// Replace every destination field curl may retain, preventing a mutated URL
  /// from selecting a real network endpoint after the callback returns.
  /// @param address Mutable callback address to rewrite.
  /// @param destination Bound request endpoint to install.
  /// @return true when the public address storage can represent IPv4 safely.
  static bool RewriteDestination(struct curl_sockaddr* address, const struct sockaddr_in& destination);

  /// Drain all immediately available packets from one server endpoint.
  /// @param fd Nonblocking server descriptor to read.
  /// @param role Which endpoint the descriptor represents.
  /// @return number of datagrams consumed, including zero-length datagrams.
  std::size_t DrainSocket(int fd, TftpSocketRole role);

  /// Drain request and transfer endpoints so neither valid uploads nor
  /// retransmissions can fill a kernel queue between curl turns.
  /// @return total number of client datagrams consumed.
  std::size_t DrainClientDatagrams();

  /// Retain only the first valid client address as the transfer destination.
  /// TFTP's transfer ID must stay stable; accepting later source changes would
  /// hide the very address-pinning behavior the peer is meant to exercise.
  /// @param address Source address returned by recvfrom.
  /// @param length Number of valid bytes in address.
  void RememberClientAddress(const struct sockaddr_in& address, socklen_t length);

  /// Release one scripted packet from the transfer endpoint. UDP sends are
  /// atomic, so an error consumes the entry instead of retrying in a hot loop.
  /// @return true when a script entry was consumed, regardless of send result.
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
