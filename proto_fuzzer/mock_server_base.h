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
  /// HandleOpenSocket.
  /// @param easy The curl easy handle to configure.
  void Install(CURL* easy);

  /// Run 'scenario' to completion on 'easy'. Allocates a curl_multi handle,
  /// attaches 'easy', delegates the protocol-specific drive to RunLoop, and
  /// cleans up. All protocol-specific behaviour lives inside the subclass;
  /// this method is multi-handle RAII only.
  /// @param easy     curl easy handle already Install()ed on this mock.
  /// @param scenario the Scenario proto to drive.
  void DriveScenario(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

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

  /// Wait on curl's fdset with a short timeout so a scenario cannot spin
  /// forever. Shared by every subclass's drive loop.
  /// @param multi The multi handle whose fdset to poll.
  /// @param rc    Out parameter: set to the CURLMcode on error.
  /// @return select()'s result, or -1 on curl_multi_fdset failure.
  static int WaitOnMultiFdset(CURLM* multi, CURLMcode* rc);

  /// Cap on consecutive idle perform iterations before a drive loop bails.
  /// Shared so subclass loops cap identically.
  static constexpr int kMaxIdleIterations = 256;

  /// The per-scenario MockConnection, lazily created by HandleOpenSocket().
  /// Subclasses read/write through this pointer inside their RunLoop.
  std::unique_ptr<MockConnection> connection_;

 private:
  friend curl_socket_t MockServerBaseOpenSocketTrampoline(void*, curlsocktype, struct curl_sockaddr*);
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MOCK_SERVER_BASE_H_
