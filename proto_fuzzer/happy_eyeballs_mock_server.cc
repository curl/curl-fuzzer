/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of HappyEyeballsMockServer.

#include "proto_fuzzer/happy_eyeballs_mock_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

namespace {

/// Bound the number of real connect attempts a single scenario may start.
/// Happy eyeballs itself keeps at most six in flight; headroom covers a
/// redirect or authentication retry without allowing mutation-sized socket
/// work.
constexpr std::size_t kMaxConnectAttempts = 16;

/// Bound retained accepted peers and per-call accept work so a stale race
/// backlog cannot keep the serving listener permanently readable.
constexpr std::size_t kMaxAcceptedPeers = 12;
constexpr int kMaxAcceptsPerCall = 8;

/// The first accepted connections belong to the address race. Serving the
/// same primary script to each means the winning baller always sees a complete
/// response no matter which completion order the kernel reports.
constexpr std::size_t kMaxRaceScriptPeers = 6;

/// Alternate loopback addresses tried for the serving listener, in order. The
/// first address always stays the deliberately stalled race endpoint so the
/// second baller is the one that can win.
constexpr int kFirstServeHostByte = 2;
constexpr int kLastServeHostByte = 9;

/// Number of dummy clients used to fill the race listener's accept queue. The
/// kernel capacity for listen(1) is at least one on Linux; keeping the queue
/// full makes the first baller's SYN stay unanswered, so its non-blocking
/// connect remains in progress while later addresses are started.
constexpr int kRaceBacklog = 1;
constexpr int kRaceFillConnections = 2;

constexpr std::size_t kReadBufferSize = 4096;

/// @param fd Descriptor to close when valid.
void CloseFd(int* fd) {
  if (*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
}

/// @param fd Descriptor to switch to non-blocking mode.
/// @param require_selectable Whether the descriptor must fit in an fd_set.
/// @return true when the descriptor is usable.
bool MakeNonBlocking(int fd, bool require_selectable) {
  if (require_selectable && fd >= FD_SETSIZE) {
    return false;
  }
  const int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

/// @param script Connection script whose raw response chunks are visible.
/// @return Number of on_readable chunks the runtime may consume.
std::size_t RawChunkCount(const curl::fuzzer::proto::Connection& script) {
  return std::min<std::size_t>(scenario_limits::kMaxResponseChunks, script.on_readable_size());
}

/// Build the loopback sockaddr for one 127.0.0.x address.
/// @param host_byte Final dotted-quad byte.
/// @param port Network-order listener port.
/// @return Initialized sockaddr_in.
struct sockaddr_in LoopbackAddress(int host_byte, std::uint16_t port) {
  struct sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(0x7f000000U | static_cast<std::uint32_t>(host_byte));
  addr.sin_port = port;
  return addr;
}

}  // namespace

/// Construct an idle peer with no listener or accepted connections.
HappyEyeballsMockServer::HappyEyeballsMockServer()
    : easy_(nullptr),
      race_fd_(-1),
      serve_fd_(-1),
      listener_port_(0),
      opened_socket_count_(0),
      accepted_peer_count_(0),
      scenario_(nullptr) {}

/// Release listeners and accepted loopback peers. curl owns every socket it
/// received from HandleOpenSocket; only the accepted server halves, listeners,
/// and backlog-filling clients are closed here.
HappyEyeballsMockServer::~HappyEyeballsMockServer() {
  scenario_ = nullptr;
  for (Peer& peer : peers_) {
    ClosePeer(&peer);
  }
  peers_.clear();
  CloseListeners();
}

/// Install the shared socket callbacks and remember the easy handle for the
/// later resolve/port/timeout setopts. The zero happy-eyeballs delay makes the
/// second address eligible as soon as the first connect is in progress.
/// @param easy Easy handle that will drive this peer.
void HappyEyeballsMockServer::Install(CURL* easy) {
  MockServerBase::Install(easy);
  easy_ = easy;
  (void)OpenListeners();
  if (easy_ != nullptr) {
    (void)curl_easy_setopt(easy_, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, 0L);
  }
}

/// Replace the resolver lane's single-address mapping with a two-address entry
/// for the fixed canonical host and point the URL's effective port at the
/// ephemeral listener. This runs after ScenarioRequestData has installed its
/// own list, so the race mapping is the one curl loads.
/// @param request_data Installed request state; unused by this transport.
void HappyEyeballsMockServer::ConfigureRequestData(ScenarioRequestData* /*request_data*/) {
  if (easy_ == nullptr || listener_port_ <= 0 || serve_address_.empty()) {
    return;
  }

  const std::string mapping = "resolve.test:" + std::to_string(listener_port_) + ":127.0.0.1," + serve_address_;

  CurlSlistPtr resolve_list;
  curl_slist* entry = curl_slist_append(nullptr, mapping.c_str());
  if (entry == nullptr) {
    return;
  }
  resolve_list.reset(entry);
  if (curl_easy_setopt(easy_, CURLOPT_RESOLVE, resolve_list.get()) != CURLE_OK) {
    return;
  }
  resolve_list_ = std::move(resolve_list);
  (void)curl_easy_setopt(easy_, CURLOPT_PORT, static_cast<long>(listener_port_));
}

/// Hand curl a fresh unconnected socket for every address its happy-eyeballs
/// filter decides to race. The sockopt callback reports kNeedsSetup, so curl
/// performs the real non-blocking connect on this descriptor.
/// @param purpose Socket role; only outbound IPCXN sockets are produced.
/// @param address curl's mutable destination description.
/// @return A non-blocking socket, or CURL_SOCKET_BAD when the attempt budget
///         or descriptor limits are reached.
curl_socket_t HappyEyeballsMockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) {
  if (purpose != CURLSOCKTYPE_IPCXN || address == nullptr || opened_socket_count_ >= kMaxConnectAttempts) {
    return CURL_SOCKET_BAD;
  }
  if (address->family != AF_INET && address->family != AF_INET6) {
    return CURL_SOCKET_BAD;
  }

  curl_socket_t fd = socket(address->family, address->socktype, address->protocol);
  if (fd == CURL_SOCKET_BAD) {
    return CURL_SOCKET_BAD;
  }
  if (!MakeNonBlocking(fd, true)) {
    close(fd);
    return CURL_SOCKET_BAD;
  }
  ++opened_socket_count_;
  return fd;
}

/// Stream peers must follow curl's ordinary connect path; unlike the socketpair
/// mocks, the descriptor is deliberately not connected yet.
/// @param curlfd Descriptor returned by HandleOpenSocket.
/// @param purpose Socket role assigned by curl.
/// @return Always kNeedsSetup.
SocketSetupDisposition HappyEyeballsMockServer::GetSocketSetupDisposition(curl_socket_t /*curlfd*/,
                                                                          curlsocktype /*purpose*/) const {
  return SocketSetupDisposition::kNeedsSetup;
}

/// Run a bounded perform loop that also accepts real loopback connections and
/// serves their response scripts. Explicit short select waits let the kernel
/// report connect completion without busy-spinning.
/// @param multi Multi handle already containing `easy`.
/// @param easy  Easy handle driving this peer.
/// @param scenario Source of the bounded response scripts.
void HappyEyeballsMockServer::RunLoop(CURLM* multi, CURL* /*easy*/, const curl::fuzzer::proto::Scenario& scenario) {
  scenario_ = &scenario;

  int still_running = 1;
  int idle_iterations = 0;
  int drive_iterations = 0;
  CURLMcode rc = CURLM_OK;

  while (still_running && idle_iterations < kMaxIdleIterations && drive_iterations++ < kMaxDriveIterations) {
    bool made_progress = AcceptPending();
    made_progress = ServicePeers() || made_progress;

    const int running_before = still_running;
    rc = curl_multi_perform(multi, &still_running);
    if (rc != CURLM_OK) {
      break;
    }
    made_progress = still_running != running_before || made_progress;
    made_progress = AcceptPending() || made_progress;
    made_progress = ServicePeers() || made_progress;
    if (!still_running) {
      break;
    }

    if (made_progress) {
      idle_iterations = 0;
      continue;
    }

    CURLMcode wait_rc = CURLM_OK;
    if (WaitOnMultiFdset(multi, &wait_rc) < 0 || wait_rc != CURLM_OK) {
      break;
    }
    ++idle_iterations;
  }

  // Every Peer::script points into the caller-owned scenario. Clear those
  // borrowings before returning even if a peer outlives the drive loop.
  scenario_ = nullptr;
  for (Peer& peer : peers_) {
    ClosePeer(&peer);
  }
  peers_.clear();
}

/// Bind the stalled 127.0.0.1 race endpoint and a serving listener on another
/// 127.0.0.x address using one ephemeral port. The race listener's accept queue
/// is then filled with dummy connections so curl's first baller stays in
/// progress while the second connect can complete.
/// @return true when both listeners are usable.
bool HappyEyeballsMockServer::OpenListeners() {
  CloseListeners();

  const int race_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (race_fd < 0 || race_fd >= FD_SETSIZE) {
    if (race_fd >= 0) {
      close(race_fd);
    }
    return false;
  }

  const int reuse = 1;
  (void)setsockopt(race_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in race_addr = LoopbackAddress(1, 0);
  if (bind(race_fd, reinterpret_cast<const struct sockaddr*>(&race_addr), sizeof(race_addr)) != 0 ||
      listen(race_fd, kRaceBacklog) != 0) {
    close(race_fd);
    return false;
  }

  socklen_t addrlen = sizeof(race_addr);
  if (getsockname(race_fd, reinterpret_cast<struct sockaddr*>(&race_addr), &addrlen) != 0 ||
      !MakeNonBlocking(race_fd, true)) {
    close(race_fd);
    return false;
  }
  race_fd_ = race_fd;
  listener_port_ = static_cast<int>(ntohs(race_addr.sin_port));
  const std::uint16_t network_port = race_addr.sin_port;

  for (int host_byte = kFirstServeHostByte; host_byte <= kLastServeHostByte; ++host_byte) {
    const int serve_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (serve_fd < 0 || serve_fd >= FD_SETSIZE) {
      if (serve_fd >= 0) {
        close(serve_fd);
      }
      continue;
    }
    (void)setsockopt(serve_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in serve_addr = LoopbackAddress(host_byte, network_port);
    if (bind(serve_fd, reinterpret_cast<const struct sockaddr*>(&serve_addr), sizeof(serve_addr)) == 0 &&
        listen(serve_fd, 8) == 0 && MakeNonBlocking(serve_fd, true)) {
      serve_fd_ = serve_fd;
      serve_address_ = "127.0.0." + std::to_string(host_byte);
      break;
    }
    close(serve_fd);
  }

  if (serve_fd_ < 0) {
    CloseListeners();
    return false;
  }

  // Fill the race endpoint's accept queue. SO_SNDTIMEO bounds connect() on the
  // loopback path, which normally completes immediately. These client halves
  // stay open for the whole drive so the queue remains full.
  struct timeval connect_timeout;
  connect_timeout.tv_sec = 0;
  connect_timeout.tv_usec = 10000;
  const struct sockaddr_in race_target = LoopbackAddress(1, network_port);
  for (int index = 0; index < kRaceFillConnections; ++index) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || fd >= FD_SETSIZE) {
      if (fd >= 0) {
        close(fd);
      }
      continue;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &connect_timeout, sizeof(connect_timeout));
    int connect_result;
    do {
      connect_result = connect(fd, reinterpret_cast<const struct sockaddr*>(&race_target), sizeof(race_target));
    } while (connect_result != 0 && errno == EINTR);
    if (connect_result != 0) {
      close(fd);
      continue;
    }
    dummy_fds_.push_back(fd);
  }

  return true;
}

/// Close both listeners, the backlog-filling clients, and the recorded port.
void HappyEyeballsMockServer::CloseListeners() {
  for (int& fd : dummy_fds_) {
    CloseFd(&fd);
  }
  dummy_fds_.clear();
  CloseFd(&race_fd_);
  CloseFd(&serve_fd_);
  listener_port_ = 0;
  serve_address_.clear();
}

/// Accept queued connections from the serving listener. Each accepted
/// descriptor is non-blocking and either retained with a script or closed
/// immediately when the peer budget is exhausted.
/// @return true when at least one connection was accepted.
bool HappyEyeballsMockServer::AcceptPending() {
  bool accepted_any = false;

  int accepted_this_call = 0;
  while (accepted_this_call < kMaxAcceptsPerCall) {
    const int fd = accept(serve_fd_, nullptr, nullptr);
    if (fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    ++accepted_this_call;
    accepted_any = true;
    ++accepted_peer_count_;

    if (!MakeNonBlocking(fd, true) || peers_.size() >= kMaxAcceptedPeers) {
      close(fd);
      continue;
    }

    const curl::fuzzer::proto::Connection* script = ScriptForAccept(accepted_peer_count_ - 1);
    if (script == nullptr) {
      close(fd);
      continue;
    }

    Peer peer;
    peer.fd = fd;
    peer.script = script;
    peer.pending = script->initial_response();
    peers_.push_back(std::move(peer));
  }
  return accepted_any;
}

/// Drain request bytes and deliver response fragments on every accepted peer.
/// A peer is closed after the peer closes or a non-retryable I/O error occurs.
/// @return true when any peer transferred bytes or closed.
bool HappyEyeballsMockServer::ServicePeers() {
  bool made_progress = false;

  for (std::size_t index = 0; index < peers_.size();) {
    Peer& peer = peers_[index];
    bool keep_peer = peer.fd >= 0;

    unsigned char scratch[kReadBufferSize];
    while (keep_peer) {
      const ssize_t count = recv(peer.fd, scratch, sizeof(scratch), 0);
      if (count > 0) {
        made_progress = true;
        continue;
      }
      if (count == 0) {
        keep_peer = false;
        made_progress = true;
      } else if (errno == EINTR) {
        continue;
      } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        keep_peer = false;
        made_progress = true;
      }
      break;
    }

    while (keep_peer && peer.pending_offset >= peer.pending.size()) {
      peer.pending.clear();
      peer.pending_offset = 0;
      if (peer.script != nullptr && peer.next_chunk < RawChunkCount(*peer.script)) {
        peer.pending = peer.script->on_readable(static_cast<int>(peer.next_chunk++));
        if (!peer.pending.empty()) {
          break;
        }
      } else {
        break;
      }
    }

    while (keep_peer && peer.pending_offset < peer.pending.size()) {
      const ssize_t count = send(peer.fd, peer.pending.data() + peer.pending_offset,
                                 peer.pending.size() - peer.pending_offset, MSG_NOSIGNAL);
      if (count > 0) {
        peer.pending_offset += static_cast<std::size_t>(count);
        made_progress = true;
      } else if (count < 0 && errno == EINTR) {
        continue;
      } else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      } else {
        keep_peer = false;
        made_progress = true;
      }
    }

    if (keep_peer && peer.pending_offset >= peer.pending.size() &&
        (peer.script == nullptr || peer.next_chunk >= RawChunkCount(*peer.script)) && !peer.sent_final) {
      (void)shutdown(peer.fd, SHUT_WR);
      peer.sent_final = true;
      made_progress = true;
    }

    if (!keep_peer) {
      ClosePeer(&peer);
      peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(index));
      continue;
    }
    ++index;
  }
  return made_progress;
}

/// @param peer Peer whose descriptor should be closed.
void HappyEyeballsMockServer::ClosePeer(Peer* peer) {
  if (peer != nullptr) {
    CloseFd(&peer->fd);
  }
}

/// @param index Zero-based accepted-connection order.
/// @return Borrowed response script, or nullptr when no script remains.
const curl::fuzzer::proto::Connection* HappyEyeballsMockServer::ScriptForAccept(std::size_t index) const {
  if (scenario_ == nullptr) {
    return nullptr;
  }
  if (index < kMaxRaceScriptPeers) {
    return &scenario_->connection();
  }
  const std::size_t subsequent_index = index - kMaxRaceScriptPeers;
  if (subsequent_index < static_cast<std::size_t>(scenario_->subsequent_connections_size()) &&
      subsequent_index < scenario_limits::kMaxConnections - 1) {
    return &scenario_->subsequent_connections(static_cast<int>(subsequent_index));
  }
  return nullptr;
}

}  // namespace proto_fuzzer
