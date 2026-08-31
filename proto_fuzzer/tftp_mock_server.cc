/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the bounded loopback UDP TFTP peer.

#include "proto_fuzzer/tftp_mock_server.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <utility>

namespace proto_fuzzer {

/// Start without live descriptors or borrowed scenario storage. RunLoop builds
/// both immediately before the first curl_multi_perform that can observe them.
TftpMockServer::TftpMockServer()
    : response_datagrams_(),
      response_datagram_count_(0),
      next_response_datagram_(0),
      request_fd_(-1),
      transfer_fd_(-1),
      client_address_(),
      client_address_length_(0),
      has_client_address_(false),
      socket_opened_(false),
      request_port_(0),
      transfer_port_(0),
      received_datagrams_() {}

/// Close the two server endpoints after the base drive has removed curl's
/// separately-owned client descriptor from its multi handle.
TftpMockServer::~TftpMockServer() { ResetPeer(); }

/// Return observations rather than parsing them in the peer. Tests can assert
/// exact RRQ/WRQ/DATA/ACK bytes while production fuzz iterations pay only the
/// bounded copies already required to expose those observations.
const std::vector<TftpReceivedDatagram>& TftpMockServer::received_datagrams() const { return received_datagrams_; }

/// Return the kernel-selected request port in host byte order.
std::uint16_t TftpMockServer::request_port() const { return request_port_; }

/// Return the kernel-selected transfer port in host byte order.
std::uint16_t TftpMockServer::transfer_port() const { return transfer_port_; }

/// Borrow only the response prefix the runtime can emit. The nonempty check on
/// initial_response preserves proto3's absent/empty equivalence; repeated bytes
/// retain presence, so an empty on_readable entry remains a real zero-length
/// UDP datagram useful for curl's short-packet retry path.
void TftpMockServer::PrepareScript(const curl::fuzzer::proto::Connection& connection) {
  response_datagrams_.fill(nullptr);
  response_datagram_count_ = 0;
  next_response_datagram_ = 0;

  if (!connection.initial_response().empty()) {
    response_datagrams_[response_datagram_count_++] = &connection.initial_response();
  }
  const std::size_t chunk_count =
      std::min<std::size_t>(scenario_limits::kMaxResponseChunks, connection.on_readable_size());
  for (std::size_t index = 0; index < chunk_count; ++index) {
    response_datagrams_[response_datagram_count_++] = &connection.on_readable(static_cast<int>(index));
  }
}

/// Tear down only state owned by this mock. Curl takes ownership of the client
/// descriptor as soon as HandleOpenSocket succeeds, so retaining or closing a
/// duplicate here would create cross-owner lifetime bugs during multi cleanup.
void TftpMockServer::ResetPeer() {
  if (request_fd_ >= 0) {
    (void)::close(request_fd_);
    request_fd_ = -1;
  }
  if (transfer_fd_ >= 0) {
    (void)::close(transfer_fd_);
    transfer_fd_ = -1;
  }
  std::memset(&client_address_, 0, sizeof(client_address_));
  client_address_length_ = 0;
  has_client_address_ = false;
  socket_opened_ = false;
  request_port_ = 0;
  transfer_port_ = 0;
}

/// Establish both descriptor properties ourselves. Curl normally requests
/// SOCK_CLOEXEC/SOCK_NONBLOCK from socket(), but an application callback is
/// allowed to ignore those type flags and therefore must return a safe fd.
bool TftpMockServer::ConfigureSocket(int fd) {
  if (fd < 0) {
    return false;
  }
  const int descriptor_flags = ::fcntl(fd, F_GETFD, 0);
  if (descriptor_flags < 0 || ::fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
    return false;
  }
  const int status_flags = ::fcntl(fd, F_GETFL, 0);
  return status_flags >= 0 && ::fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) == 0;
}

/// Use ephemeral loopback ports so parallel fuzz workers cannot collide and no
/// privilege is required for TFTP's conventional port 69. getsockname, rather
/// than assumptions about bind(), is the authority on the chosen destination.
int TftpMockServer::OpenLoopbackSocket(struct sockaddr_in* bound_address) {
  if (bound_address == nullptr) {
    return -1;
  }
  const int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0 || !ConfigureSocket(fd)) {
    if (fd >= 0) {
      (void)::close(fd);
    }
    return -1;
  }

  struct sockaddr_in requested = {};
  requested.sin_family = AF_INET;
  requested.sin_port = htons(0);
  requested.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(fd, reinterpret_cast<const struct sockaddr*>(&requested), sizeof(requested)) != 0) {
    (void)::close(fd);
    return -1;
  }

  socklen_t length = sizeof(*bound_address);
  std::memset(bound_address, 0, sizeof(*bound_address));
  if (::getsockname(fd, reinterpret_cast<struct sockaddr*>(bound_address), &length) != 0 ||
      length != sizeof(*bound_address) || bound_address->sin_family != AF_INET) {
    (void)::close(fd);
    return -1;
  }
  return fd;
}

/// Curl explicitly permits CURLOPT_OPENSOCKETFUNCTION to replace its supplied
/// destination. Replacing the metadata as well as sockaddr is essential: curl
/// copies these values into its connection filter and TFTP later retrieves that
/// copy for sendto(), independently of the returned descriptor's properties.
bool TftpMockServer::RewriteDestination(struct curl_sockaddr* address, const struct sockaddr_in& destination) {
  if (address == nullptr || sizeof(destination) > sizeof(address->addr)) {
    return false;
  }
  address->family = AF_INET;
  address->socktype = SOCK_DGRAM;
  address->protocol = IPPROTO_UDP;
  address->addrlen = sizeof(destination);
  std::memset(&address->addr, 0, sizeof(address->addr));
  std::memcpy(&address->addr, &destination, sizeof(destination));
  return true;
}

/// Create both server transfer IDs before returning curl's client socket. The
/// first response deliberately comes from a port different from the rewritten
/// request destination, matching real TFTP and making curl's address-pinning
/// transition observable through where its next ACK/DATA arrives.
curl_socket_t TftpMockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) {
  if (purpose != CURLSOCKTYPE_IPCXN || address == nullptr || socket_opened_) {
    return CURL_SOCKET_BAD;
  }
  socket_opened_ = true;

  struct sockaddr_in request_address = {};
  struct sockaddr_in transfer_address = {};
  request_fd_ = OpenLoopbackSocket(&request_address);
  transfer_fd_ = OpenLoopbackSocket(&transfer_address);
  if (request_fd_ < 0 || transfer_fd_ < 0 || !RewriteDestination(address, request_address)) {
    ResetPeer();
    return CURL_SOCKET_BAD;
  }

  request_port_ = ntohs(request_address.sin_port);
  transfer_port_ = ntohs(transfer_address.sin_port);

  const int client_fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (client_fd < 0 || !ConfigureSocket(client_fd)) {
    if (client_fd >= 0) {
      (void)::close(client_fd);
    }
    ResetPeer();
    return CURL_SOCKET_BAD;
  }
  return static_cast<curl_socket_t>(client_fd);
}

/// Pin the first IPv4 client endpoint. Later packets are still captured, but
/// they cannot redirect scripted responses; otherwise a mutation could make the
/// harness accept source changes that curl's own TFTP implementation rejects.
void TftpMockServer::RememberClientAddress(const struct sockaddr_in& address, socklen_t length) {
  if (has_client_address_ || length != sizeof(address) || address.sin_family != AF_INET) {
    return;
  }
  client_address_ = address;
  client_address_length_ = length;
  has_client_address_ = true;
}

/// Drain until EAGAIN so curl never experiences harness-created UDP receive
/// backpressure. A 65,536-byte buffer covers the maximum IPv4 UDP payload, and
/// recvfrom preserves even zero-length datagrams as one state-machine event.
std::size_t TftpMockServer::DrainSocket(int fd, TftpSocketRole role) {
  if (fd < 0) {
    return 0;
  }

  std::array<unsigned char, 65536> packet;
  std::size_t count = 0;
  while (true) {
    struct sockaddr_in source = {};
    socklen_t source_length = sizeof(source);
    const ssize_t received =
        ::recvfrom(fd, packet.data(), packet.size(), 0, reinterpret_cast<struct sockaddr*>(&source), &source_length);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    ++count;
    RememberClientAddress(source, source_length);
    if (received_datagrams_.size() < kMaxCapturedDatagrams) {
      TftpReceivedDatagram observation;
      observation.received_on = role;
      observation.source_port =
          source_length == sizeof(source) && source.sin_family == AF_INET ? ntohs(source.sin_port) : 0;
      observation.bytes.assign(reinterpret_cast<const char*>(packet.data()), static_cast<std::size_t>(received));
      received_datagrams_.push_back(std::move(observation));
    }
  }
  return count;
}

/// Drain the well-known request endpoint first because it is the only valid
/// source of the initial client address. Once a response selects the transfer
/// endpoint, draining both remains cheap and captures protocol mistakes without
/// allowing either queue to survive into a later fuzz iteration.
std::size_t TftpMockServer::DrainClientDatagrams() {
  return DrainSocket(request_fd_, TftpSocketRole::kRequest) + DrainSocket(transfer_fd_, TftpSocketRole::kTransfer);
}

/// Consume exactly one script boundary per curl turn. Sending from the transfer
/// endpoint rather than the request endpoint is what makes subsequent client
/// traffic prove curl accepted the peer's new TFTP transfer ID.
bool TftpMockServer::SendNextDatagram() {
  if (!has_client_address_ || transfer_fd_ < 0 || next_response_datagram_ >= response_datagram_count_) {
    return false;
  }

  const std::string& datagram = *response_datagrams_[next_response_datagram_++];
  (void)::sendto(transfer_fd_, datagram.data(), datagram.size(), 0,
                 reinterpret_cast<const struct sockaddr*>(&client_address_), client_address_length_);
  return true;
}

/// Give curl one nonblocking state-machine turn, retain all client packets that
/// turn produced, then release at most one peer packet. Completion gets one
/// final drain so the terminal ACK remains observable. Incomplete scripts stop
/// after a small idle prefix rather than waiting for TFTP's one-second retry
/// clock, keeping mutation throughput independent of wall time.
void TftpMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  (void)easy;
  ResetPeer();
  PrepareScript(scenario.connection());
  received_datagrams_.clear();
  received_datagrams_.reserve(kMaxCapturedDatagrams);

  int still_running = 1;
  int idle_iterations = 0;
  for (int iteration = 0; iteration < kMaxDriveIterations; ++iteration) {
    const CURLMcode result = curl_multi_perform(multi, &still_running);
    if (result != CURLM_OK) {
      break;
    }

    const bool received = DrainClientDatagrams() != 0;
    const bool sent = still_running != 0 && received && SendNextDatagram();
    if (received || sent) {
      idle_iterations = 0;
    } else {
      ++idle_iterations;
    }

    if (still_running == 0 || idle_iterations >= kMaxIdleIterations) {
      break;
    }
  }
}

}  // namespace proto_fuzzer
