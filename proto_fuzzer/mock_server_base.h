/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief MockServerBase — common plumbing shared by every protocol-specific
///        mock server. Owns the MockConnection, installs the OPENSOCKET /
///        SOCKOPT trampolines, and exposes a single DriveScenario entrypoint
///        that each subclass specialises for its protocol.

#ifndef PROTO_FUZZER_MOCK_SERVER_BASE_H_
#define PROTO_FUZZER_MOCK_SERVER_BASE_H_

#include <curl/curl.h>

#include <memory>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

class MockConnection;
class MultiSocketDriver;
class ScenarioRequestData;

/// @class proto_fuzzer::MockServerBase
/// @brief Abstract base for protocol-specific in-process mock servers. Owns a
///        single MockConnection (the socketpair curl talks to) and dispatches
///        the OPENSOCKET callback through a virtual HandleOpenSocket so the
///        subclass can decide whether to write anything immediately. Each
///        subclass overrides RunLoop to seed itself from the Scenario proto
///        and run its own perform loop; the base's DriveScenario owns the
///        curl_multi handle around that call.
class MockServerBase {
 public:
  virtual ~MockServerBase();

  MockServerBase(const MockServerBase&) = delete;
  MockServerBase& operator=(const MockServerBase&) = delete;

  /// Install the common OPENSOCKETFUNCTION / OPENSOCKETDATA / SOCKOPTFUNCTION
  /// callbacks on 'easy'. The trampolines route back into this instance via
  /// HandleOpenSocket. Subclasses may override to layer additional, protocol-
  /// specific setopts (e.g. a WRITEFUNCTION that pokes protocol-specific APIs
  /// from inside a curl callback).
  /// @param easy The curl easy handle to configure.
  virtual void Install(CURL* easy);

  /// Bind protocol-specific work to the request-data callbacks after their
  /// per-scenario state has been constructed. Ordinary HTTP and WebSocket
  /// mocks drain from their outer perform loops, so they do not need work at
  /// the upload-callback boundary. Most mocks need no hook; TELNET uses this
  /// boundary to drain client replies while curl owns the thread.
  /// @param request_data Callback state that outlives the subsequent drive.
  virtual void ConfigureRequestData(ScenarioRequestData* request_data);

  /// Run 'scenario' to completion on 'easy'. Allocates a curl_multi handle,
  /// attaches 'easy', delegates the protocol-specific drive to RunLoop, and
  /// drains the completion queue before cleanup. Reading the result here is
  /// important because removing the only easy handle would otherwise make
  /// every protocol runner skip the public multi-result path. All protocol-
  /// specific behaviour still lives inside the subclass.
  /// @param easy     curl easy handle already Install()ed on this mock.
  /// @param scenario the Scenario proto to drive.
  /// @param use_multi_socket Select the callback-driven socket-action loop.
  /// @param wake_multi Probe wakeup/timeout control APIs while multi is live.
  /// @return the completed transfer's CURLcode, or CURLE_FAILED_INIT when the
  /// bounded drive could not produce a completion message.
  CURLcode DriveScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario, bool use_multi_socket = false,
                         bool wake_multi = false);

  /// Run through the public easy entrypoint when a protocol mock can preload
  /// all peer work before curl takes control. The base falls back to the
  /// ordinary multi drive; HTTP overrides this with a true easy perform.
  /// @param easy curl easy handle already Install()ed on this mock.
  /// @param scenario Scenario whose response the mock must prepare.
  virtual void DriveEasyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

  /// @return the active MockConnection, or nullptr if none has been opened.
  MockConnection* connection();

 protected:
  MockServerBase();

  /// Subclass hook invoked by the OPENSOCKET trampoline. The subclass owns the
  /// decision to construct `connection_`, push any initial bytes, and hand the
  /// client fd back to libcurl.
  /// @return the client-side fd to hand to libcurl, or CURL_SOCKET_BAD.
  virtual curl_socket_t HandleOpenSocket() = 0;

  /// Subclass hook invoked from DriveScenario. Runs the protocol-specific
  /// perform loop against a caller-owned multi that already has 'easy' added.
  /// @param multi    multi handle owned by DriveScenario; easy already added.
  /// @param easy     the curl easy handle attached to the mock.
  /// @param scenario the Scenario proto to drive.
  virtual void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) = 0;

  /// Wait on curl's fdset with a short timeout. Drive loops call this only for
  /// scenarios that explicitly request backpressure/timing behaviour; ordinary
  /// scenarios run without wall-clock sleeps.
  /// @param multi The multi handle whose fdset to poll.
  /// @param rc    Out parameter: set to the CURLMcode on error.
  /// @return select()'s result, or -1 on curl_multi_fdset failure.
  static int WaitOnMultiFdset(CURLM* multi, CURLMcode* rc);

  /// Ask curl to construct and inspect its current connection-filter pollset
  /// without waiting. A perform-only harness can complete local socketpair
  /// transfers while systematically skipping the public multi-poll path that
  /// event-driven applications use. Timing scenarios make one zero-timeout
  /// probe, retaining that coverage without taxing the fixed fast lanes.
  /// @param multi The active multi handle after at least one perform call.
  static void ProbeMultiPollset(CURLM* multi);

  /// Return the callback state installed for the current socket-action drive.
  /// HTTP's RunLoop uses this instead of reading the proto directly so only
  /// the dedicated API binary can opt into lifecycle work; compatibility
  /// inputs containing the newly-added field retain their old behavior.
  /// @return active driver, or nullptr for the ordinary perform path.
  MultiSocketDriver* multi_socket_driver();

  /// Hard operation budget for one scenario. This bounds cases that continue
  /// making tiny amounts of progress (for example a one-byte backpressure
  /// drain) without relying on wall-clock time.
  static constexpr int kMaxDriveIterations = 512;

  /// Consecutive no-progress budget for ordinary scenarios. Socketpair I/O is
  /// local and should settle immediately, so a handful of extra performs is
  /// enough to flush curl's state machine without sleeping.
  static constexpr int kMaxIdleIterations = 8;

  /// Explicit backpressure scenarios get a larger idle budget and may use the
  /// short timed wait above. This keeps timeout/error branches reachable while
  /// ensuring ordinary mutations never inherit their cost.
  static constexpr int kMaxTimedIdleIterations = 256;

  /// @return true when the scenario explicitly opted into socket backpressure.
  static bool UsesTimedDrive(const curl::fuzzer::proto::Scenario& scenario);

  /// Apply the pending BackpressureConfig (set by DriveScenario from the
  /// Scenario proto) to the newly-created connection_. Subclasses call this
  /// at the end of HandleOpenSocket, right before returning the client fd,
  /// so the SO_RCVBUF setting takes effect before any traffic flows.
  void ApplyPendingBackpressure();

  /// The per-scenario MockConnection, lazily created by HandleOpenSocket().
  /// Subclasses read/write through this pointer inside their RunLoop.
  std::unique_ptr<MockConnection> connection_;

  /// Cached SO_RCVBUF/SO_SNDBUF setting in bytes. Populated by DriveScenario
  /// before the first curl_multi_perform so HandleOpenSocket can consult it
  /// when it constructs the MockConnection.
  int pending_recv_buf_bytes_;
  /// Cached per-call DrainIncoming byte budget. Same population timing as
  /// pending_recv_buf_bytes_; 0 means unlimited (legacy drain behaviour).
  std::size_t pending_drain_limit_;

  /// Non-owning pointer into DriveScenario's stack. That scope encloses easy
  /// removal and multi cleanup, the complete interval in which callbacks may
  /// still fire.
  MultiSocketDriver* multi_socket_driver_;

 private:
  friend curl_socket_t MockServerBaseOpenSocketTrampoline(void*, curlsocktype, struct curl_sockaddr*);
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MOCK_SERVER_BASE_H_
