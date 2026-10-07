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

#include <cstddef>
#include <functional>
#include <memory>
#include <utility>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"

namespace proto_fuzzer {

class MockConnection;
class MultiSocketDriver;
class ScenarioRequestData;

/// Tell curl whether an application-provided socket still needs its normal
/// connect/options setup or already represents a connected stream transport.
/// This is explicit peer metadata: querying the descriptor from a callback is
/// both redundant and unavailable in some fuzzing sandboxes.
enum class SocketSetupDisposition {
  kNeedsSetup,
  kAlreadyConnected,
};

/// Results from the bounded CONNECT_ONLY public-API probe. Keeping byte counts
/// makes focused tests distinguish a successful connection from actual
/// curl_easy_send/curl_easy_recv execution.
struct ConnectOnlyRunStats {
  CURLcode connect_result = CURLE_FAILED_INIT;  ///< Result of establishing the connect-only transport.
  CURLcode send_result = CURLE_FAILED_INIT;     ///< Final result returned by curl_easy_send.
  CURLcode recv_result = CURLE_FAILED_INIT;     ///< Final result returned by curl_easy_recv.
  std::size_t sent_bytes = 0;                   ///< Total application bytes accepted by curl_easy_send.
  std::size_t received_bytes = 0;               ///< Total application bytes returned by curl_easy_recv.
};

/// Fixed policy for interpreting a scenario's multi-drive fields.
enum class MultiDrivePolicy {
  kPerform,       ///< Use the ordinary curl_multi_perform loop.
  kSocketAction,  ///< Use the callback-driven curl_multi_socket_action loop.
  kFromApiPlan,   ///< Read the multi-loop choice and probes from Scenario::api_plan.
};

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

  virtual void Install(CURL* easy);

  virtual void ConfigureRequestData(ScenarioRequestData* request_data);

  CURLcode DriveScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

  virtual void DriveEasyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario, bool use_events = false);

  virtual ConnectOnlyRunStats DriveConnectOnlyScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

  /// Callback type used to publish the driving multi handle to observers.
  using MultiObserver = std::function<void(CURLM*)>;

  /// Register an observer invoked with the live multi handle after 'easy' is
  /// attached and before the drive loop starts. The API lifecycle lane uses it
  /// so public API probes fired from inside callbacks can target the multi that
  /// actually owns the transfer. Passing an empty observer clears it.
  /// @param observer Callback receiving the live multi handle.
  void SetMultiObserver(MultiObserver observer) { multi_observer_ = std::move(observer); }

  MockConnection* connection();

 protected:
  explicit MockServerBase(MultiDrivePolicy drive_policy = MultiDrivePolicy::kPerform);

  virtual void HandleDetachedMulti(CurlMultiPtr multi);

  /// Subclass hook invoked by the OPENSOCKET trampoline. The subclass owns the
  /// decision to construct `connection_`, push any initial bytes, and hand the
  /// client fd back to libcurl. Passing curl's mutable destination through is
  /// essential for datagram protocols: TFTP must replace the nominal URL port
  /// with its per-scenario loopback request socket before curl records the
  /// address used by sendto(). Stream socketpair peers simply ignore it.
  /// @param purpose The role curl intends the new socket to serve.
  /// @param address Mutable destination and native socket description.
  /// @return the client-side fd to hand to libcurl, or CURL_SOCKET_BAD.
  virtual curl_socket_t HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) = 0;

  virtual SocketSetupDisposition GetSocketSetupDisposition(curl_socket_t curlfd, curlsocktype purpose) const;

  /// Subclass hook invoked from DriveScenario. Runs the protocol-specific
  /// perform loop against a caller-owned multi that already has 'easy' added.
  /// @param multi    multi handle owned by DriveScenario; easy already added.
  /// @param easy     the curl easy handle attached to the mock.
  /// @param scenario the Scenario proto to drive.
  virtual void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) = 0;

  static int WaitOnMultiFdset(CURLM* multi, CURLMcode* rc);

  static void ProbeMultiPollset(CURLM* multi);

  MultiSocketDriver* multi_socket_driver();

  std::size_t additional_handle_cleanup_count() const;

  void ResumeResponseIfRequested(CURL* easy);

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

  static bool UsesTimedDrive(const curl::fuzzer::proto::Scenario& scenario);

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

  /// Number of application-created handles, excluding the caller's parent,
  /// successfully removed from the current multi and cleaned up.
  std::size_t additional_handle_cleanup_count_;

  /// True only for an API-plan multi drive with its one-shot write callback.
  bool resume_response_;

  /// Observer receiving the live multi handle at the start of a drive.
  MultiObserver multi_observer_;

 private:
  /// Target-authorized source of multi execution behavior.
  MultiDrivePolicy drive_policy_;

  friend curl_socket_t MockServerBaseOpenSocketTrampoline(void*, curlsocktype, struct curl_sockaddr*);
  friend int MockServerBaseSockOptTrampoline(void*, curl_socket_t, curlsocktype);
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MOCK_SERVER_BASE_H_
