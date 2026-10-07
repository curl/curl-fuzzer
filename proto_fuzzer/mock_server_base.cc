/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of MockServerBase — shared trampolines, shared
///        select() helper, DriveScenario multi-handle RAII, and the scheme
///        classifier that produces the right subclass for a Scenario.

#include "proto_fuzzer/mock_server_base.h"

#include <curl/multi.h>
#include <sys/select.h>

#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/multi_socket_driver.h"

namespace proto_fuzzer {

namespace {

constexpr long kSelectTimeoutUs = 1000;  // 1 ms; explicit timing cases only.

}  // namespace

/// @brief C trampoline for CURLOPT_OPENSOCKETFUNCTION. Declared at namespace
///        scope so it can be a friend of MockServerBase.
/// @param clientp Pointer to the MockServerBase instance.
/// @param purpose The socket role curl is asking the mock to provide.
/// @param address Curl's mutable description of the intended destination.
/// @return The client-side socket fd as a curl_socket_t.
curl_socket_t MockServerBaseOpenSocketTrampoline(void* clientp, curlsocktype purpose, struct curl_sockaddr* address) {
  return static_cast<MockServerBase*>(clientp)->HandleOpenSocket(purpose, address);
}

/// Translate explicit peer transport metadata into curl's sockopt callback
/// contract. The descriptor is used only as an opaque identity; sandbox
/// policy must not decide whether an otherwise valid in-process transport can
/// run.
/// @param clientp Pointer to the MockServerBase instance.
/// @param curlfd Descriptor returned by the open-socket callback.
/// @param purpose Socket role assigned by curl.
/// @return CURL_SOCKOPT_ALREADY_CONNECTED for prepared stream peers, otherwise
///         CURL_SOCKOPT_OK.
int MockServerBaseSockOptTrampoline(void* clientp, curl_socket_t curlfd, curlsocktype purpose) {
  const auto disposition = static_cast<MockServerBase*>(clientp)->GetSocketSetupDisposition(curlfd, purpose);
  return disposition == SocketSetupDisposition::kAlreadyConnected ? CURL_SOCKOPT_ALREADY_CONNECTED : CURL_SOCKOPT_OK;
}

/// Construct an empty base instance with a fixed multi-drive policy.
/// @param drive_policy Whether to perform, use socket actions, or honor the
///        containing Scenario's ApiPlan.
MockServerBase::MockServerBase(MultiDrivePolicy drive_policy)
    : connection_(nullptr),
      pending_recv_buf_bytes_(0),
      pending_drain_limit_(0),
      multi_socket_driver_(nullptr),
      additional_handle_cleanup_count_(0),
      resume_response_(false),
      drive_policy_(drive_policy) {}

/// Out-of-line destructor so MockConnection can stay forward-declared in the
/// base header (its complete type is only needed where unique_ptr is
/// instantiated for destruction).
MockServerBase::~MockServerBase() = default;

/// @return the owned MockConnection, or nullptr if one has not been opened.
MockConnection* MockServerBase::connection() { return connection_.get(); }

/// Install the common OPENSOCKETFUNCTION / OPENSOCKETDATA / SOCKOPTFUNCTION
/// callbacks on 'easy'. All subclasses share the trampolines, which route
/// back into this instance through HandleOpenSocket. Subclasses may override
/// to layer additional protocol-specific setopts, such as a WRITEFUNCTION
/// that exercises protocol APIs from inside a curl callback.
/// @param easy The curl easy handle to configure.
void MockServerBase::Install(CURL* easy) {
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, &MockServerBaseOpenSocketTrampoline);
  curl_easy_setopt(easy, CURLOPT_OPENSOCKETDATA, this);
  curl_easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, &MockServerBaseSockOptTrampoline);
  curl_easy_setopt(easy, CURLOPT_SOCKOPTDATA, this);
}

/// Describe the socket returned by HandleOpenSocket without issuing native
/// descriptor queries. Stream peers return connected socketpairs; accepted
/// sockets and datagram peers require curl's ordinary setup.
/// @param curlfd Descriptor returned by HandleOpenSocket.
/// @param purpose Role curl assigned to the descriptor.
/// @return Whether curl must perform its normal socket setup.
SocketSetupDisposition MockServerBase::GetSocketSetupDisposition(curl_socket_t /*curlfd*/, curlsocktype purpose) const {
  // curl itself accepted CURLSOCKTYPE_ACCEPT descriptors, so they must follow
  // its normal post-accept option path. Every IPCXN socket returned by the
  // ordinary stream mocks is one end of an already-connected socketpair.
  return purpose == CURLSOCKTYPE_ACCEPT ? SocketSetupDisposition::kNeedsSetup
                                        : SocketSetupDisposition::kAlreadyConnected;
}

/// Bind protocol-specific work to the request-data callbacks after their
/// per-scenario state has been constructed. Ordinary HTTP and WebSocket
/// mocks regain control in their outer perform loops and drain client
/// traffic there. Most mocks therefore need no hook; TELNET uses this
/// upload-callback boundary to drain client replies while curl owns the
/// thread.
/// @param request_data Callback state that outlives the subsequent drive.
void MockServerBase::ConfigureRequestData(ScenarioRequestData* /*request_data*/) {}

/// Run 'scenario' to completion on 'easy': allocate a multi, attach 'easy',
/// delegate protocol-specific work to RunLoop, consume its completion
/// message, and clean up. Read the result before removing the only easy
/// handle so every protocol runner exercises the public multi-result path.
/// Harness setup failures return a stable sentinel; fuzzer callers may
/// ignore it while unit tests can assert the protocol result without adding
/// another callback or global.
/// @param easy     curl easy handle already Install()ed on this mock.
/// @param scenario the Scenario proto to drive.
/// @return the completed transfer's CURLcode, or CURLE_FAILED_INIT when the
/// bounded drive could not produce a completion message.
CURLcode MockServerBase::DriveScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  const curl::fuzzer::proto::ApiPlan* api_plan =
      drive_policy_ == MultiDrivePolicy::kFromApiPlan && scenario.has_api_plan() ? &scenario.api_plan() : nullptr;
  const bool use_multi_socket =
      drive_policy_ == MultiDrivePolicy::kSocketAction ||
      (api_plan != nullptr && api_plan->drive_mode() == curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET);

  // Cache backpressure knobs so HandleOpenSocket can apply them the moment
  // connection_ exists. Both default to 0, which matches the legacy "drain
  // greedily, kernel-default buffers" behaviour exactly.
  const auto& bp = scenario.connection().backpressure();
  pending_recv_buf_bytes_ = static_cast<int>(bp.recv_buf_bytes());
  pending_drain_limit_ = static_cast<std::size_t>(bp.drain_limit());
  additional_handle_cleanup_count_ = 0;
  resume_response_ = api_plan != nullptr && api_plan->pause_response_once();

  CurlMultiPtr multi(curl_multi_init());
  if (multi == nullptr) {
    resume_response_ = false;
    return CURLE_FAILED_INIT;
  }

  CURLcode transfer_result = CURLE_FAILED_INIT;

  // Callback data must survive both remove_handle and multi_cleanup, since
  // either may emit CURL_POLL_REMOVE. Keeping it in this outer scope provides
  // that lifetime without allocating per-watch state.
  MultiSocketDriver socket_driver;
  if (use_multi_socket && socket_driver.Install(multi.get())) {
    multi_socket_driver_ = &socket_driver;
  }
  if (curl_multi_add_handle(multi.get(), easy) == CURLM_OK) {
    if (multi_observer_) {
      multi_observer_(multi.get());
    }
    if (api_plan != nullptr && api_plan->wake_multi()) {
      if (multi_socket_driver_ != nullptr) {
        multi_socket_driver_->ProbeControlApis();
      } else {
        long timeout_ms = -1;
        (void)curl_multi_timeout(multi.get(), &timeout_ms);
        (void)curl_multi_wakeup(multi.get());
      }
    }
    RunLoop(multi.get(), easy, scenario);

    // Completion messages are the multi API's only durable record of the
    // transfer result. Consume them while all easy handles are still attached:
    // otherwise every scenario systematically skips curl_multi_info_read's
    // result path and removal discards the opportunity. An accepted HTTP/2
    // push can contribute one additional completion message; only the caller's
    // parent determines DriveScenario's result.
    int messages_remaining = 0;
    CURLMsg* message = nullptr;
    while ((message = curl_multi_info_read(multi.get(), &messages_remaining)) != nullptr) {
      if (message->msg == CURLMSG_DONE && message->easy_handle == easy) {
        transfer_result = message->data.result;
      }
    }

    // CURL_PUSH_OK transfers ownership of each automatically-added easy to
    // the application. Enumerate attached handles only after draining their
    // completion messages, then honor the public remove-before-cleanup
    // lifecycle. The original `easy` remains caller-owned.
    CURL** handles = curl_multi_get_handles(multi.get());
    if (handles != nullptr) {
      for (std::size_t index = 0; handles[index] != nullptr; ++index) {
        CURL* handle = handles[index];
        if (handle != easy && curl_multi_remove_handle(multi.get(), handle) == CURLM_OK) {
          curl_easy_cleanup(handle);
          ++additional_handle_cleanup_count_;
        }
      }
      curl_free(handles);
    }

    curl_multi_remove_handle(multi.get(), easy);
  }
  // Socket-action callbacks borrow the stack driver above, so that path must
  // clean its multi before this function returns. Perform-based protocol mocks
  // may retain the detached multi when their fixed lifecycle requires it.
  if (use_multi_socket) {
    multi.reset();
  } else {
    HandleDetachedMulti(std::move(multi));
  }
  multi_socket_driver_ = nullptr;
  resume_response_ = false;
  return transfer_result;
}

/// Dispose of or retain the multi after its easy handle has been removed.
/// The default destroys it before DriveScenario returns. A protocol mock
/// may retain it as member state when its fixed lifecycle requires easy
/// cleanup to happen first.
/// @param multi Detached multi handle and its live connection cache.
void MockServerBase::HandleDetachedMulti(CurlMultiPtr /*multi*/) {}

/// Run through the public easy entrypoint when a protocol mock can preload
/// all peer work before curl takes control. The base preserves the ordinary
/// multi-drive fallback for protocols that require an outer driver to make
/// progress. The API policy currently forces HTTP, whose override preloads
/// its bounded response and calls curl_easy_perform without a thread.
/// @param easy curl easy handle already Install()ed on this mock.
/// @param scenario Scenario whose response the mock must prepare.
/// @param use_events Select curl's debug event-based easy entrypoint when
///        the concrete mock supports it.
void MockServerBase::DriveEasyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario, bool /*use_events*/) {
  DriveScenario(easy, scenario);
}

/// Establish a CONNECT_ONLY transport, then perform bounded direct I/O.
/// HTTP overrides this; other protocol mocks retain a safe fallback.
/// @param easy curl easy handle already Install()ed on this mock.
/// @param scenario Scenario supplying response and direct-I/O bytes.
/// @return Results and byte counts from connect, send, and receive probes.
ConnectOnlyRunStats MockServerBase::DriveConnectOnlyScenario(CURL* easy,
                                                             const curl::fuzzer::proto::Scenario& scenario) {
  ConnectOnlyRunStats stats;
  stats.connect_result = DriveScenario(easy, scenario);
  return stats;
}

/// Expose the callback state installed for the current socket-action drive.
/// HTTP's RunLoop uses this instead of reading the proto directly, so only
/// the dedicated API binary can opt into lifecycle work and compatibility
/// inputs containing the new field retain their old behavior. Ownership
/// remains in DriveScenario so no subclass can shorten the driver's lifetime.
/// @return active driver, or nullptr for the ordinary perform path.
MultiSocketDriver* MockServerBase::multi_socket_driver() { return multi_socket_driver_; }

/// @return extra easy handles removed and cleaned after the latest drive.
/// Server push is currently the only path that can add one behind the
/// caller's back; exposing the count to subclasses keeps ownership in this
/// multi-owning base while allowing focused lifecycle assertions.
std::size_t MockServerBase::additional_handle_cleanup_count() const { return additional_handle_cleanup_count_; }

/// Resume receive-side callback output at one bounded drive boundary when
/// the dedicated API plan requested it. Calling CONT before the callback
/// pauses is harmless; repeating it ensures a later response chunk cannot
/// leave the transfer suspended until timeout.
/// @param easy Active easy handle whose receive callbacks may be paused.
void MockServerBase::ResumeResponseIfRequested(CURL* easy) {
  if (resume_response_) {
    (void)curl_easy_pause(easy, CURLPAUSE_CONT);
  }
}

/// Apply the BackpressureConfig cached by DriveScenario to the new
/// connection_. Subclasses call this at the end of HandleOpenSocket, before
/// returning the client fd, so SO_RCVBUF takes effect before traffic flows.
/// Safe to call when connection_ is null or both knobs are zero: those cases
/// are no-ops.
void MockServerBase::ApplyPendingBackpressure() {
  if (connection_) {
    connection_->ApplyBackpressure(pending_recv_buf_bytes_, pending_drain_limit_);
  }
}

/// Treat a non-default BackpressureConfig as an explicit request for the
/// slower, timed drive policy. Proto3 scalar defaults make this deterministic:
/// a present-but-empty message remains on the ordinary fast path.
/// @param scenario Scenario whose backpressure settings select the policy.
/// @return true when the scenario explicitly opted into socket backpressure.
bool MockServerBase::UsesTimedDrive(const curl::fuzzer::proto::Scenario& scenario) {
  const auto& bp = scenario.connection().backpressure();
  return bp.recv_buf_bytes() != 0 || bp.drain_limit() != 0;
}

/// Wait on curl's fdset with a short timeout. Drive loops call this only for
/// scenarios that explicitly request backpressure/timing behaviour; ordinary
/// scenarios run without wall-clock sleeps.
/// @param multi The multi handle whose fdset to poll.
/// @param rc    Out parameter: set to the CURLMcode on error.
/// @return select()'s result, or -1 on curl_multi_fdset failure.
int MockServerBase::WaitOnMultiFdset(CURLM* multi, CURLMcode* rc) {
  fd_set readfds;
  fd_set writefds;
  fd_set excfds;
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_ZERO(&excfds);
  int maxfd = -1;
  *rc = curl_multi_fdset(multi, &readfds, &writefds, &excfds, &maxfd);
  if (*rc != CURLM_OK) {
    return -1;
  }
  if (maxfd < 0) {
    return 0;
  }
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = kSelectTimeoutUs;
  return ::select(maxfd + 1, &readfds, &writefds, &excfds, &timeout);
}

/// Ask curl to construct and inspect its connection-filter pollset without
/// waiting. A perform-only harness can complete local socketpair transfers
/// while skipping the public multi-poll path used by event-driven
/// applications. Timing scenarios make one zero-timeout probe to retain
/// that coverage without taxing the fixed fast lanes. The result is ignored:
/// the protocol-specific perform loop determines transfer progress.
/// @param multi The active multi handle after at least one perform call.
void MockServerBase::ProbeMultiPollset(CURLM* multi) {
  int numfds = 0;
  (void)curl_multi_poll(multi, nullptr, 0, 0, &numfds);
}

}  // namespace proto_fuzzer
