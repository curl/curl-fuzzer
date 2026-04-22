/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of MockConnection and MockServer.

#include "proto_fuzzer/mock_server.h"

#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <utility>

namespace proto_fuzzer {

namespace {

// fd_set can only represent file descriptors < FD_SETSIZE. Reject any pair that couldn't participate in select()
// without memory corruption.
bool FdFitsInFdSet(int fd) { return fd >= 0 && fd < FD_SETSIZE; }

/// @brief Noop function to satisfy CURLOPT_SOCKOPTFUNCTION.
/// @param clientp Unused.
/// @param curlfd Unused.
/// @param purpose Unused.
/// @return CURL_SOCKOPT_ALREADY_CONNECTED to indicate the socket is ready for use.
int SockOptTrampoline(void* /*clientp*/, curl_socket_t /*curlfd*/, curlsocktype /*purpose*/) {
  // The socketpair is already "connected" as far as curl is concerned.
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

/// @brief C trampoline for CURLOPT_OPENSOCKETFUNCTION.
/// @param clientp Pointer to the MockServer instance.
/// @param purpose Unused.
/// @param address Unused.
/// @return The client-side socket fd as a curl_socket_t.
curl_socket_t OpenSocketTrampoline(void* clientp, curlsocktype /*purpose*/, struct curl_sockaddr* /*address*/) {
  return static_cast<MockServer*>(clientp)->HandleOpenSocket();
}

}  // namespace

/// @class proto_fuzzer::MockConnection
/// @brief Owns one half of a socketpair used to feed canned responses to libcurl. The destructor closes the server-side
/// fd; the client-side fd is handed to libcurl via CURLOPT_OPENSOCKETFUNCTION and becomes curl's to close.

/// Construct a non-blocking AF_UNIX/SOCK_STREAM socketpair. Both fds are validated to fit inside FD_SETSIZE; on any
/// failure ok() returns false and the instance is unusable.
MockConnection::MockConnection() : server_fd_(-1), client_fd_(-1) {
  int fds[2];

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
    return;
  }

  // The fds must be small enough to fit in an fd_set for select(). If not, close them and fail the constructor.
  if (!FdFitsInFdSet(fds[0]) || !FdFitsInFdSet(fds[1])) {
    close(fds[0]);
    close(fds[1]);
    return;
  }

  // Set the server-side fd non-blocking so we can write to it without risk of hanging the fuzzer.
  int flags = fcntl(fds[0], F_GETFL, 0);
  if (flags < 0 || fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) < 0) {
    close(fds[0]);
    close(fds[1]);
    return;
  }

  // Success: store the file descriptors.
  server_fd_ = fds[0];
  client_fd_ = fds[1];
}

/// Close the server-side fd (and the client-side fd if it was never handed off via take_client_fd()).
MockConnection::~MockConnection() {
  if (server_fd_ >= 0) {
    close(server_fd_);
  }
  if (client_fd_ >= 0) {
    close(client_fd_);
  }
}

/// @return true if the underlying socketpair was set up successfully.
bool MockConnection::ok() const { return server_fd_ >= 0; }

/// @return the server-side fd (still owned by this MockConnection).
int MockConnection::server_fd() const { return server_fd_; }

/// Hand the client-side fd to libcurl. After this call the caller owns the fd and the MockConnection will not close it
/// on destruction.
/// @return the client-side socket fd as a curl_socket_t.
curl_socket_t MockConnection::take_client_fd() {
  int fd = client_fd_;
  client_fd_ = -1;
  return static_cast<curl_socket_t>(fd);
}

/// Write 'size' bytes from 'data' to the server fd, looping until the whole buffer is sent or a short/failed write
/// occurs.
/// @param data Buffer to send.
/// @param size Number of bytes in 'data'.
/// @return false on short or failed write (treat the connection as lost).
bool MockConnection::WriteAll(const unsigned char* data, std::size_t size) {
  if (server_fd_ < 0) {
    return false;
  }
  std::size_t written = 0;
  while (written < size) {
    ssize_t n = ::write(server_fd_, data + written, size - written);
    if (n <= 0) {
      return false;
    }
    written += static_cast<std::size_t>(n);
  }
  return true;
}

/// Drain anything curl has written so the fd returns to "not readable" after the caller pushes the next response.
void MockConnection::DrainIncoming() {
  if (server_fd_ < 0) {
    return;
  }
  unsigned char scratch[4096];
  while (true) {
    ssize_t n = ::read(server_fd_, scratch, sizeof(scratch));
    if (n <= 0) {
      break;
    }
  }
}

/// Non-blocking read: append whatever bytes are currently available on the
/// server fd to 'out'. Used by the WS handshake path to collect curl's HTTP
/// Upgrade request without losing any bytes.
/// @param out Destination buffer; unchanged if no bytes are pending.
void MockConnection::ReadAvailable(std::string* out) {
  if (server_fd_ < 0 || out == nullptr) {
    return;
  }
  unsigned char scratch[4096];
  while (true) {
    ssize_t n = ::read(server_fd_, scratch, sizeof(scratch));
    if (n <= 0) {
      break;
    }
    out->append(reinterpret_cast<const char*>(scratch), static_cast<std::size_t>(n));
  }
}

/// Signal end-of-response to libcurl by half-closing the write side.
void MockConnection::ShutdownWrite() {
  if (server_fd_ < 0) {
    return;
  }
  ::shutdown(server_fd_, SHUT_WR);
}

/// @class proto_fuzzer::MockServer
/// @brief Orchestrates a single mock HTTP exchange: installs the socket callbacks on an easy handle, then feeds queued
/// responses as libcurl reads them.

/// Construct an idle MockServer with no connection and no scripted responses. Install() and SetScript() must be called
/// before the easy handle performs.
MockServer::MockServer() : connection_(nullptr), next_chunk_(0), initial_sent_(false) {}

/// Default destructor; the owned MockConnection (if any) cleans up its socketpair.
MockServer::~MockServer() = default;

/// Install CURLOPT_OPENSOCKETFUNCTION / OPENSOCKETDATA / SOCKOPTFUNCTION on 'easy'. Must be called before
/// curl_easy_perform / curl_multi_perform.
/// @param easy The curl easy handle to configure.
void MockServer::Install(CURL* easy) {
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, &OpenSocketTrampoline);
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA, this);
  curl_easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, &SockOptTrampoline);
}

/// Queue bytes to emit. initial_response is written synchronously in the
/// OPENSOCKETFUNCTION callback (HandleOpenSocket); on_readable entries are written one-at-a-time
/// when libcurl makes the fd readable (driven by DriveTransfer).
/// @param initial_response Bytes written immediately on connection open.
/// @param on_readable      Additional chunks delivered one per iteration.
void MockServer::SetScript(std::string initial_response, std::vector<std::string> on_readable) {
  initial_response_ = std::move(initial_response);
  on_readable_ = std::move(on_readable);
  next_chunk_ = 0;
  initial_sent_ = false;
}

/// @return true if at least one on_readable chunk has not yet been sent.
bool MockServer::has_more_chunks() const { return next_chunk_ < on_readable_.size(); }

/// @return the active MockConnection, or nullptr if none has been opened.
MockConnection* MockServer::connection() { return connection_.get(); }

/// Called by the OPENSOCKETFUNCTION C trampoline. Creates the MockConnection,
/// writes initial_response into it, and returns the client-side fd to hand
/// to libcurl.
/// @return the client-side fd to hand to libcurl, or CURL_SOCKET_BAD on
///         failure.
curl_socket_t MockServer::HandleOpenSocket() {
  if (connection_) {
    // This mock supports exactly one connection per scenario.
    return CURL_SOCKET_BAD;
  }
  connection_ = std::make_unique<MockConnection>();
  if (!connection_->ok()) {
    connection_.reset();
    return CURL_SOCKET_BAD;
  }
  if (!initial_response_.empty()) {
    if (!connection_->WriteAll(reinterpret_cast<const unsigned char*>(initial_response_.data()),
                               initial_response_.size())) {
      connection_.reset();
      return CURL_SOCKET_BAD;
    }
  }
  initial_sent_ = true;
  if (on_readable_.empty()) {
    connection_->ShutdownWrite();
  }
  return connection_->take_client_fd();
}

/// Push the next queued chunk. Called by the transfer loop when curl is ready
/// for more data. No-op if the queue is empty or no connection is open.
void MockServer::DeliverNextChunk() {
  if (!connection_ || next_chunk_ >= on_readable_.size()) {
    return;
  }
  connection_->DrainIncoming();
  const std::string& chunk = on_readable_[next_chunk_++];
  if (!chunk.empty()) {
    connection_->WriteAll(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
  }
  if (next_chunk_ >= on_readable_.size()) {
    connection_->ShutdownWrite();
  }
}

}  // namespace proto_fuzzer
