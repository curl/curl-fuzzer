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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "proto_fuzzer/multi_socket_driver.h"
#include "proto_fuzzer/scenario_limits.h"
#include "proto_fuzzer/ws_frame.h"

namespace proto_fuzzer {

// curl's debug-only event-based easy entrypoint is intentionally used by the
// API coverage lane. curl-fuzzer builds every bundled curl with ENABLE_DEBUG
// and visible symbols, matching curl's own command-line tool declaration.
/// @param easy Configured easy handle to perform.
/// @return The transfer result reported by the event-based entrypoint.
extern "C" CURLcode curl_easy_perform_ev(CURL* easy);

namespace {

constexpr int kMaxConnectOnlyIoIterations = 16;
constexpr std::size_t kConnectOnlyBufferSize = 1024;

// fd_set can only represent file descriptors < FD_SETSIZE. Reject any pair that couldn't participate in select()
// without memory corruption.
bool FdFitsInFdSet(int fd) { return fd >= 0 && fd < FD_SETSIZE; }

}  // namespace

/// @class proto_fuzzer::MockConnection
/// @brief Owns one half of a socketpair used to feed canned responses to libcurl. The destructor closes the server-side
/// fd; the client-side fd is handed to libcurl via CURLOPT_OPENSOCKETFUNCTION and becomes curl's to close.

/// Construct a non-blocking AF_UNIX/SOCK_STREAM socketpair. Both fds are validated to fit inside FD_SETSIZE; on any
/// failure ok() returns false and the instance is unusable.
MockConnection::MockConnection() : server_fd_(-1), client_fd_(-1), drain_limit_(0), incoming_data_observer_(nullptr) {
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

/// Query the capacity curl's endpoint reports for queued client writes while
/// this object still owns that endpoint. Synchronous protocol mocks use this
/// before transferring fd ownership because they cannot rely on the outer
/// driver to make room. A zero result covers both an invalid fd and a platform
/// query failure; callers need a verified capacity before proceeding.
/// @return SO_SNDBUF in bytes, or zero when it cannot be queried.
std::size_t MockConnection::client_send_buffer_size() const {
  if (client_fd_ < 0) {
    return 0;
  }
  int size = 0;
  socklen_t length = sizeof(size);
  if (getsockopt(client_fd_, SOL_SOCKET, SO_SNDBUF, &size, &length) != 0 || size <= 0) {
    return 0;
  }
  return static_cast<std::size_t>(size);
}

/// Ensure curl's endpoint reports at least `minimum` bytes of send buffer,
/// requesting a larger SO_SNDBUF when the platform default is smaller. Linux
/// may transform socket-buffer requests, so the post-set query establishes the
/// contract rather than assuming setsockopt accepted the exact value.
/// @param minimum Smallest acceptable reported capacity in bytes.
/// @return true when the queried postcondition holds.
bool MockConnection::EnsureClientSendBufferSize(std::size_t minimum) {
  if (client_send_buffer_size() >= minimum) {
    return true;
  }
  if (client_fd_ < 0 || minimum > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return false;
  }
  const int requested = static_cast<int>(minimum);
  if (setsockopt(client_fd_, SOL_SOCKET, SO_SNDBUF, &requested, sizeof(requested)) != 0) {
    return false;
  }
  return client_send_buffer_size() >= minimum;
}

/// Hand the client-side fd to libcurl. After this call the caller owns the fd and the MockConnection will not close it
/// on destruction.
/// @return the client-side socket fd as a curl_socket_t.
curl_socket_t MockConnection::take_client_fd() {
  int fd = client_fd_;
  client_fd_ = -1;
  return static_cast<curl_socket_t>(fd);
}

/// Write 'size' bytes from 'data' to the server fd, looping until the whole
/// buffer is sent or a short/failed write occurs. MSG_NOSIGNAL is a harness
/// invariant rather than a curl behavior choice: a response race may leave the
/// peer closed, and that must look like an ordinary failed mock write instead
/// of terminating the fuzz process with SIGPIPE.
/// @param data Buffer to send.
/// @param size Number of bytes in 'data'.
/// @return false on short or failed write (treat the connection as lost).
bool MockConnection::WriteAll(const unsigned char* data, std::size_t size) {
  if (server_fd_ < 0) {
    return false;
  }
  std::size_t written = 0;
  while (written < size) {
    ssize_t n = ::send(server_fd_, data + written, size - written, MSG_NOSIGNAL);
    if (n <= 0) {
      return false;
    }
    written += static_cast<std::size_t>(n);
  }
  return true;
}

/// Advance incoming transport work according to the configured per-call
/// limit. This plaintext implementation reports bytes consumed; layered
/// transports may also report handshake state changes so the bounded outer
/// loop does not mistake useful protocol progress for an idle connection.
/// When a backpressure drain limit has been applied (see ApplyBackpressure),
/// stop after drain_limit_ bytes so the kernel recv buffer stays near-full
/// and curl keeps seeing short writes. Otherwise drain until read() returns
/// 0/EAGAIN, matching legacy behaviour.
/// @return number of bytes consumed during this call.
std::size_t MockConnection::DrainIncoming() {
  if (server_fd_ < 0) {
    return 0;
  }
  unsigned char scratch[4096];
  std::size_t drained = 0;
  while (drain_limit_ == 0 || drained < drain_limit_) {
    std::size_t want = sizeof(scratch);
    if (drain_limit_ != 0) {
      const std::size_t remaining = drain_limit_ - drained;
      if (remaining < want) {
        want = remaining;
      }
    }
    ssize_t n = ::read(server_fd_, scratch, want);
    if (n <= 0) {
      break;
    }
    NotifyIncomingData(scratch, static_cast<std::size_t>(n));
    drained += static_cast<std::size_t>(n);
  }
  return drained;
}

/// Register a non-owning sink for bytes consumed from curl. TLS transports
/// notify it after decryption, while plaintext transports report socket
/// bytes directly. The observer must outlive this connection.
/// @param observer Observer to notify, or nullptr to disable observation.
void MockConnection::SetIncomingDataObserver(IncomingDataObserver* observer) { incoming_data_observer_ = observer; }

/// Forward one application-data fragment to the optional observer.
/// @param data First byte of the fragment.
/// @param size Number of bytes available at `data`.
void MockConnection::NotifyIncomingData(const unsigned char* data, std::size_t size) {
  if (incoming_data_observer_ != nullptr) {
    incoming_data_observer_->ObserveIncomingData(data, size);
  }
}

/// Apply deterministic backpressure knobs before traffic begins. A positive
/// recv_buf_bytes sets SO_RCVBUF on the server fd and SO_SNDBUF on the client
/// fd, which this object still owns, to make curl short-write or see EAGAIN.
/// Linux socketpairs effectively use max(SNDBUF, RCVBUF*2) as pipe capacity,
/// so both settings are needed to produce short writes reliably. Cap each
/// DrainIncoming call at drain_limit bytes; zero leaves the drain unlimited.
/// @param recv_buf_bytes SO_RCVBUF size in bytes, or 0 to leave default.
/// @param drain_limit    Max bytes drained per DrainIncoming call, 0 for unlimited.
void MockConnection::ApplyBackpressure(int recv_buf_bytes, std::size_t drain_limit) {
  if (recv_buf_bytes > 0) {
    if (server_fd_ >= 0) {
      (void)setsockopt(server_fd_, SOL_SOCKET, SO_RCVBUF, &recv_buf_bytes, sizeof(recv_buf_bytes));
    }
    if (client_fd_ >= 0) {
      (void)setsockopt(client_fd_, SOL_SOCKET, SO_SNDBUF, &recv_buf_bytes, sizeof(recv_buf_bytes));
    }
  }
  drain_limit_ = drain_limit;
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
/// @brief Orchestrates a bounded sequence of mock HTTP exchanges: installs
/// socket callbacks on an easy handle, assigns a response script to each new
/// socket, and feeds queued chunks as libcurl reads them.

/// Construct an idle MockServer with no scripted responses or open peers.
/// DriveScenario() configures it from a Scenario before curl can open a socket;
/// the fixed policy decides whether that scenario's ApiPlan controls the loop.
/// @param drive_policy Multi interface loop selected for this server.
MockServer::MockServer(MultiDrivePolicy drive_policy)
    : MockServerBase(drive_policy),
      script_count_(0),
      next_script_(0),
      active_script_(nullptr),
      preload_all_chunks_(false),
      keep_connections_open_(false) {}

/// Default destructor; current and previous MockConnections clean up their
/// server-side descriptors only after curl has been removed from the multi.
MockServer::~MockServer() = default;

/// Build the complete borrowed script table before entering curl. The primary
/// Connection always occupies slot zero for backwards compatibility; only
/// three subsequent pointers are retained so protobuf mutations cannot
/// allocate socketpairs or prolong redirects in proportion to repeated-field
/// size. The caller must keep the Scenario alive and unmodified until the
/// synchronous drive finishes. RunScenario provides that lifetime, making
/// borrowing safe while avoiding copies of response bytes before curl
/// requests the corresponding socket or chunk.
/// @param scenario Source of the primary and bounded follow-on scripts.
void MockServer::SetScripts(const curl::fuzzer::proto::Scenario& scenario) {
  ResetConnections();
  script_count_ = 0;
  next_script_ = 0;

  const auto append_script = [this](const curl::fuzzer::proto::Connection& connection) {
    ConnectionScript& script = scripts_[script_count_++];
    script.connection = &connection;
    script.raw_chunk_count = std::min<std::size_t>(scenario_limits::kMaxResponseChunks, connection.on_readable_size());
    const std::size_t frame_budget = scenario_limits::kMaxResponseChunks - script.raw_chunk_count;
    script.frame_chunk_count = std::min<std::size_t>(frame_budget, connection.server_frames_size());
    script.next_chunk = 0;
  };

  append_script(scenario.connection());
  const std::size_t subsequent_count = std::min<std::size_t>(
      scenario_limits::kMaxConnections - 1, static_cast<std::size_t>(scenario.subsequent_connections_size()));
  for (std::size_t i = 0; i < subsequent_count; ++i) {
    append_script(scenario.subsequent_connections(static_cast<int>(i)));
  }
}

/// Keep completed response sockets writable instead of half-closing them.
/// The multi-transfer lane uses this to let a queued easy handle reuse an
/// HTTP/1.1 connection; ordinary protocol drives retain close-on-completion.
/// @param keep_open Whether the peer should suppress its response-side FIN.
void MockServer::SetKeepConnectionsOpen(bool keep_open) { keep_connections_open_ = keep_open; }

/// @return true if at least one on_readable chunk has not yet been sent.
bool MockServer::has_more_chunks() const {
  return active_script_ != nullptr && active_script_->next_chunk < active_script_->chunk_count();
}

/// Construct the transport used for one HTTP exchange. HTTPS overrides this
/// factory with a TLS record layer while retaining the same bounded response
/// scripts and redirect lifetimes, without copying the HTTP state machine.
/// @return a new connection, whose ok() result is checked before use.
std::unique_ptr<MockConnection> MockServer::CreateConnection() { return std::make_unique<MockConnection>(); }

/// Release all current and retired socketpairs before resetting transport-
/// specific state. Derived destructors call this while their borrowed state
/// is still alive. This is separate from SetScripts because a derived class
/// may need a stricter order than C++'s derived-member-before-base teardown.
void MockServer::ResetConnections() {
  active_script_ = nullptr;
  connection_.reset();
  previous_connections_.clear();
}

/// Observe curl while its connection filters are still attached. Plain HTTP
/// has no transport-specific state to inspect; layered transports override
/// this instead of querying stale state after the multi has been dismantled.
/// @param easy Active easy handle, unused by the plaintext transport.
void MockServer::ObserveActiveTransfer(CURL* /*easy*/) {}

/// Called by the OPENSOCKETFUNCTION trampoline in the base class. Creates the
/// MockConnection, writes initial_response into it, and returns the
/// client-side fd to hand to libcurl.
/// @param purpose Socket role requested by curl; ordinary stream mocks do not
///                need to distinguish outbound HTTP roles.
/// @param address Intended destination retained by curl; the socketpair is
///                already connected and therefore leaves it untouched.
/// @return the client-side fd to hand to libcurl, or CURL_SOCKET_BAD on
///         failure.
curl_socket_t MockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) {
  (void)purpose;
  (void)address;
  if (next_script_ >= script_count_) {
    // Refusing a fifth socket keeps redirect loops bounded even if curl's own
    // redirect limit is mutated upward or an authentication scheme retries.
    return CURL_SOCKET_BAD;
  }

  if (connection_) {
    // libcurl owns the corresponding client fd, so retain the server half
    // until the easy handle leaves the multi instead of closing it at the
    // moment a redirect or retry opens its replacement.
    previous_connections_.push_back(std::move(connection_));
  }

  active_script_ = &scripts_[next_script_++];
  const curl::fuzzer::proto::Connection& script_connection = *active_script_->connection;
  connection_ = CreateConnection();
  if (!connection_ || !connection_->ok()) {
    connection_.reset();
    active_script_ = nullptr;
    return CURL_SOCKET_BAD;
  }

  // Target policies clamp/clear these values before execution. Saturating the
  // compatibility lane's raw uint32 avoids implementation-defined narrowing
  // while preserving its ability to request any representable socket size.
  const std::uint32_t int_max = static_cast<std::uint32_t>(std::numeric_limits<int>::max());
  const auto& backpressure = script_connection.backpressure();
  const int recv_buf_bytes = static_cast<int>(std::min(backpressure.recv_buf_bytes(), int_max));
  connection_->ApplyBackpressure(recv_buf_bytes, static_cast<std::size_t>(backpressure.drain_limit()));

  const std::string& initial_response = script_connection.initial_response();
  if (!initial_response.empty()) {
    if (!connection_->WriteAll(reinterpret_cast<const unsigned char*>(initial_response.data()),
                               initial_response.size())) {
      connection_.reset();
      active_script_ = nullptr;
      return CURL_SOCKET_BAD;
    }
  }
  if (preload_all_chunks_) {
    while (has_more_chunks()) {
      (void)DeliverNextChunk();
    }
  }
  if (active_script_->chunk_count() == 0 && !keep_connections_open_) {
    connection_->ShutdownWrite();
  }
  return connection_->take_client_fd();
}

/// Preload all bounded response bytes from inside OPENSOCKETFUNCTION, where
/// the mock still owns both socketpair ends, and half-close the peer when the
/// preload finishes. This avoids a helper thread and prevents
/// curl from waiting for the outer chunk-delivery loop. The total serialized
/// fuzz input is capped by libFuzzer's max_len. If a non-blocking preload fills
/// the local socket, curl observes only the successfully queued prefix and
/// the timeouts below bound the incomplete response. This drive has no
/// iteration budget of its own, so it reasserts those timeouts after scenario
/// setopts and clears the option that can disable them.
/// @param easy Configured easy handle whose open-socket callback targets this
///        mock.
/// @param scenario Bounded response script to preload before performing.
/// @param use_events Select curl's debug event-based easy entrypoint.
void MockServer::DriveEasyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario, bool use_events) {
  SetScripts(scenario);
  preload_all_chunks_ = true;
  (void)curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 50L);
  (void)curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 50L);
  // CONNECT_ONLY makes curl's timeleft check report "no limit" for the whole
  // post-connect phase, so the timeouts above stop being enforced; value 2
  // additionally skips the connect-only shortcut and runs a complete transfer.
  // Clearing it is not a coverage loss: the multi-driven WebSocket lanes still
  // exercise CONNECT_ONLY under their own iteration budget. Zero rather than
  // one because CONNECT_ONLY=1 also disables the timeout and stays bounded only
  // through a curl-internal shortcut this harness should not depend on.
  (void)curl_easy_setopt(easy, CURLOPT_CONNECT_ONLY, 0L);
  if (use_events) {
    (void)curl_easy_perform_ev(easy);
  } else {
    (void)curl_easy_perform(easy);
  }
  preload_all_chunks_ = false;
}

/// Establish only the HTTP transport, then pass bounded application bytes
/// through curl's public direct-I/O wrappers. Preloading makes receive
/// readiness deterministic without a helper thread; the socketpair peer stays
/// readable after ShutdownWrite and continues accepting the outgoing probe.
/// @param easy Configured easy handle whose transport this mock supplies.
/// @param scenario Source of the bounded response and direct-I/O probe bytes.
/// @return Results and byte counts from connect, send, and receive operations.
ConnectOnlyRunStats MockServer::DriveConnectOnlyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  ConnectOnlyRunStats stats;
  SetScripts(scenario);
  preload_all_chunks_ = true;
  (void)curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 50L);
  (void)curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, 50L);
  (void)curl_easy_setopt(easy, CURLOPT_CONNECT_ONLY, 1L);
  stats.connect_result = curl_easy_perform(easy);
  preload_all_chunks_ = false;
  if (stats.connect_result != CURLE_OK || connection_ == nullptr) {
    return stats;
  }

  constexpr std::string_view kFallbackRequest = "GET / HTTP/1.0\r\n\r\n";
  const std::string& upload = scenario.upload().data();
  const std::string_view source = upload.empty() ? kFallbackRequest : std::string_view(upload);
  const std::string_view outgoing = source.substr(0, scenario_limits::kMaxApiStringBytes);
  stats.send_result = CURLE_OK;
  for (int iteration = 0; stats.sent_bytes < outgoing.size() && iteration < kMaxConnectOnlyIoIterations; ++iteration) {
    std::size_t sent = 0;
    stats.send_result =
        curl_easy_send(easy, outgoing.data() + stats.sent_bytes, outgoing.size() - stats.sent_bytes, &sent);
    stats.sent_bytes += sent;
    (void)connection_->DrainIncoming();
    if (stats.send_result != CURLE_OK && stats.send_result != CURLE_AGAIN) {
      break;
    }
  }

  std::array<unsigned char, kConnectOnlyBufferSize> incoming{};
  for (int iteration = 0; iteration < kMaxConnectOnlyIoIterations; ++iteration) {
    std::size_t received = 0;
    stats.recv_result = curl_easy_recv(easy, incoming.data(), incoming.size(), &received);
    stats.received_bytes += received;
    if ((stats.recv_result != CURLE_OK && stats.recv_result != CURLE_AGAIN) ||
        (stats.recv_result == CURLE_OK && received == 0)) {
      break;
    }
  }
  return stats;
}

/// Push the next queued chunk. Called by the drive loop when curl is ready
/// for more data.
/// @return true when a chunk was consumed from the script.
bool MockServer::DeliverNextChunk() {
  if (!connection_ || !has_more_chunks()) {
    return false;
  }
  connection_->DrainIncoming();
  const std::size_t chunk_index = active_script_->next_chunk++;
  const auto& script_connection = *active_script_->connection;
  if (chunk_index < active_script_->raw_chunk_count) {
    const std::string& chunk = script_connection.on_readable(static_cast<int>(chunk_index));
    if (!chunk.empty()) {
      connection_->WriteAll(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
    }
  } else {
    // HTTP scenarios historically accept structured WebSocket frames as raw
    // response bytes after every on_readable chunk. Serialize only the frame
    // curl is about to receive: follow-on scripts and capped suffix frames may
    // never be consumed, so eagerly materialising all of them wastes mutations.
    const std::size_t frame_index = chunk_index - active_script_->raw_chunk_count;
    const std::string chunk = SerializeWebSocketFrame(script_connection.server_frames(static_cast<int>(frame_index)));
    if (!chunk.empty()) {
      connection_->WriteAll(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
    }
  }
  if (!has_more_chunks() && !keep_connections_open_) {
    connection_->ShutdownWrite();
  }
  return true;
}

/// Drain every live mock peer. Previous connections are normally quiescent,
/// but curl can finish sending a request body or close one after it has begun
/// resolving/opening the redirect target. Servicing both sides makes that
/// overlap deterministic without conflating their response scripts.
/// @return total bytes drained during this call.
std::size_t MockServer::DrainIncomingConnections() {
  std::size_t drained = 0;
  for (const auto& previous : previous_connections_) {
    drained += previous->DrainIncoming();
  }
  if (connection_) {
    drained += connection_->DrainIncoming();
  }
  return drained;
}

/// Service one deterministic application event-loop turn by draining all
/// available request bytes and releasing at most one response chunk. The
/// shared-multi driver owns the outer loop and calls this directly; ordinary
/// perform and socket-action drives use the same peer servicing. Draining
/// first creates request-side space before a response can provoke another
/// write, and releasing only one chunk preserves the scenario's mutation-
/// controlled parser boundaries.
/// @return true when any request or response byte advanced.
bool MockServer::ServiceConnections() {
  bool made_progress = DrainIncomingConnections() != 0;
  if (has_more_chunks()) {
    made_progress = DeliverNextChunk() || made_progress;
  }
  return made_progress;
}

/// Report how many peer sockets curl opened during the current script run.
/// @return Number of response scripts assigned to live or retired sockets.
std::size_t MockServer::opened_connection_count() const { return next_script_; }

/// Run a zero-wait application event loop around curl_multi_socket_action
/// using callback state owned by MockServerBase::DriveScenario. Positive
/// timers are deliberately not slept: the API lane clears timing controls
/// and covers event-driven dispatch, while the timing lane remains
/// responsible for clock-dependent behavior. Return after curl finishes or
/// a deterministic idle/operation cap wins.
/// @param multi Multi handle containing `easy`.
/// @param easy The easy handle attached to the mock.
void MockServer::RunSocketActionLoop(CURLM* multi, CURL* easy) {
  MultiSocketDriver* driver = multi_socket_driver();
  if (driver == nullptr) {
    return;
  }

  int still_running = 1;
  CURLMcode rc = driver->Start(&still_running);
  ObserveActiveTransfer(easy);
  ResumeResponseIfRequested(easy);
  int idle_iterations = 0;
  int drive_iterations = 0;
  while (rc == CURLM_OK && still_running && idle_iterations < kMaxIdleIterations &&
         drive_iterations++ < kMaxDriveIterations) {
    bool made_progress = ServiceConnections();
    const MultiSocketDriver::DriveResult drive_result = driver->DriveReady(&still_running);
    rc = drive_result.code;
    ObserveActiveTransfer(easy);
    ResumeResponseIfRequested(easy);
    made_progress = drive_result.made_progress || made_progress;
    if (made_progress) {
      idle_iterations = 0;
    } else {
      ++idle_iterations;
    }
  }
}

/// Seed the mock from the scenario, then drive the perform loop until curl is
/// done or a deterministic operation/idle budget is hit. Ordinary scenarios
/// never wait; explicit backpressure scenarios may use short select() waits.
/// @param multi    caller-owned multi; 'easy' is already added.
/// @param easy     the curl easy handle attached to this mock.
/// @param scenario source of the initial_response and on_readable chunks.
void MockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  SetScripts(scenario);

  if (multi_socket_driver() != nullptr) {
    RunSocketActionLoop(multi, easy);
    return;
  }

  int still_running = 1;
  int idle_iterations = 0;
  int drive_iterations = 0;
  bool pollset_probed = false;
  // Each newly opened socket can carry its own pressure settings. Inspect only
  // the borrowed, runtime-bounded scripts: ignored repeated protobuf entries must
  // not opt a fast transfer into timed waits.
  const bool timed_drive =
      std::any_of(scripts_.begin(), scripts_.begin() + script_count_, [](const ConnectionScript& script) {
        const auto& backpressure = script.connection->backpressure();
        return backpressure.recv_buf_bytes() != 0 || backpressure.drain_limit() != 0;
      });
  const int idle_limit = timed_drive ? kMaxTimedIdleIterations : kMaxIdleIterations;
  CURLMcode rc = CURLM_OK;

  while (still_running && idle_iterations < idle_limit && drive_iterations++ < kMaxDriveIterations) {
    bool made_progress = false;
    const int running_before = still_running;
    rc = curl_multi_perform(multi, &still_running);
    if (rc != CURLM_OK) {
      break;
    }
    ObserveActiveTransfer(easy);
    ResumeResponseIfRequested(easy);
    made_progress = still_running != running_before;
    if (timed_drive && still_running && !pollset_probed) {
      // Probe only after curl has built the socket/filter chain. A zero-timeout
      // poll adds no wall-clock wait; restricting it to the timing lane keeps
      // the fixed HTTP target free of a per-input polling syscall.
      ProbeMultiPollset(multi);
      pollset_probed = true;
    }
    if (!still_running) {
      break;
    }

    // Always drain whatever curl has written. Under backpressure the kernel
    // recv buffer would otherwise stay full — curl short-writes, the mock
    // never consumes, and the transfer wedges until the drive budget. With
    // drain_limit set this still honours the per-tick byte budget.
    made_progress = ServiceConnections() || made_progress;

    if (made_progress) {
      idle_iterations = 0;
      continue;
    }

    // Ordinary socketpair scenarios never sleep: repeated no-progress
    // performs are enough to settle curl's local state machine. Only an
    // explicit BackpressureConfig opts into short waits so timeout-related
    // behaviour remains fuzzable without taxing every corpus entry.
    if (timed_drive) {
      (void)WaitOnMultiFdset(multi, &rc);
      if (rc != CURLM_OK) {
        break;
      }
    }
    ++idle_iterations;
  }
}

}  // namespace proto_fuzzer
