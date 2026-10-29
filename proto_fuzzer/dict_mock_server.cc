/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the command-aware in-process DICT peer.

#include "proto_fuzzer/dict_mock_server.h"

#include <cstdlib>
#include <string>
#include <string_view>

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

namespace {

// curl builds and sends the complete DICT request synchronously before the
// outer peer loop can drain it. RFC 2229 escaping can double every retained
// path byte; fixed command/version text fits comfortably in the remaining
// headroom. Rejecting a surprising platform socket configuration is safer
// than entering curl's blocking POLLOUT wait without an operation deadline.
constexpr std::size_t kMinClientSendBufferBytes = 64 * 1024;
constexpr std::size_t kMaxBufferedClientBytes = 2 * scenario_limits::kMaxDictHostPathBytes + 4 * 1024;
static_assert(kMaxBufferedClientBytes < kMinClientSendBufferBytes,
              "DICT mutation cap exceeds the verified client send buffer");

/// Temporarily replace one process environment value and restore the caller's
/// exact state on scope exit. libFuzzer drives inputs serially, so the scope
/// around one synchronous DICT drive also scopes curl's debug socket setting
/// to the connection-filter construction that consumes it.
class ScopedEnvironmentOverride {
 public:
  ScopedEnvironmentOverride(const char* name, const char* value) : name_(name) {
    const char* previous = std::getenv(name);
    if (previous != nullptr) {
      had_previous_ = true;
      previous_ = previous;
    }
    active_ = setenv(name, value, 1) == 0;
  }

  ~ScopedEnvironmentOverride() {
    if (!active_) {
      return;
    }
    if (had_previous_) {
      (void)setenv(name_.c_str(), previous_.c_str(), 1);
    } else {
      (void)unsetenv(name_.c_str());
    }
  }

  ScopedEnvironmentOverride(const ScopedEnvironmentOverride&) = delete;
  ScopedEnvironmentOverride& operator=(const ScopedEnvironmentOverride&) = delete;

 private:
  std::string name_;
  std::string previous_;
  bool had_previous_ = false;
  bool active_ = false;
};

}  // namespace

/// Begin without a borrowed protobuf or open socketpair. RunLoop borrows a
/// Scenario only for the synchronous DriveScenario call in which socket
/// callbacks can run.
DictMockServer::DictMockServer() : reply_sent_(false), write_closed_(false) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
DictMockServer::~DictMockServer() = default;

/// Remove the operation deadline so a partial DICT request write exercises
/// sendf()'s explicit no-timeout fallback. The bounded drive and writable
/// socketpair keep this path independent of wall-clock timing.
/// @param easy DICT easy handle configured before the connection is opened.
void DictMockServer::Install(CURL* easy) {
  MockServerBase::Install(easy);
  (void)curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 0L);
}

/// Construct the ordinary plaintext transport only when its client endpoint
/// can queue the complete bounded DICT command. sendf() owns the thread until
/// that command is written, so the outer peer cannot create space meanwhile.
/// @return A verified socketpair, or nullptr on a platform that cannot provide
///         the required capacity.
std::unique_ptr<MockConnection> DictMockServer::CreateConnection() {
  std::unique_ptr<MockConnection> connection = PingpongMockServer::CreateConnection();
  if (connection == nullptr || !connection->ok() ||
      !connection->EnsureClientSendBufferSize(kMinClientSendBufferBytes)) {
    return nullptr;
  }
  return connection;
}

/// Split each sufficiently large socket write while curl constructs and uses
/// this DICT connection. curl's debug socket filter snapshots the environment
/// during its first perform; restoring it before DriveScenario tears down the
/// multi does not change that connection, and prevents a DICT input from
/// perturbing later non-DICT inputs in a mixed process.
/// @param multi Multi handle containing the DICT easy handle.
/// @param easy Easy handle already installed on this mock.
/// @param scenario DICT script borrowed for the synchronous drive.
void DictMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  ScopedEnvironmentOverride partial_writes("CURL_DBG_SOCK_WPARTIAL", "50");
  PingpongMockServer::RunLoop(multi, easy, scenario);
}

/// Reset DICT's response bookkeeping for a new drive. The shared base has
/// already cleared the transport, reply cursor, transcript, upload capture,
/// and any in-flight body phase.
void DictMockServer::ResetProtocolState() {
  reply_sent_ = false;
  write_closed_ = false;
}

/// Queue end-of-response and half-close exactly once per drive.
void DictMockServer::FinishResponse() {
  if (write_closed_) {
    return;
  }
  write_closed_ = true;
  if (connection_ != nullptr) {
    connection_->ShutdownWrite();
  }
}

/// Answer the first lookup command in the request and ignore CLIENT, which is
/// a bare identification line. curl normally writes CLIENT, the lookup, and
/// QUIT together and then waits for the response body; QUIT is therefore only
/// answered when it arrives without a preceding lookup command (for example a
/// URL with no path).
/// @param line One newline-terminated command from curl.
void DictMockServer::HandleLine(std::string_view line) {
  const std::string_view verb = FirstToken(line);
  if (verb.empty()) {
    return;
  }

  if (TokenEquals(verb, "CLIENT")) {
    return;
  }

  if (reply_sent_ || TokenEquals(verb, "QUIT")) {
    if (!reply_sent_) {
      (void)WriteNextReply();
      reply_sent_ = true;
    }
    FinishResponse();
    return;
  }

  // The first lookup command consumes the scripted body. A script without a
  // reply still closes the response so curl cannot wait for a body forever.
  (void)WriteNextReply();
  reply_sent_ = true;
  FinishResponse();
}

/// Retain protocol outcomes in coverage and introspector builds.
void DictMockServer::ObserveState() {
#if defined(PROTO_FUZZER_OBSERVE_STATE)
  PingpongMockServer::ObserveState();
  const volatile std::size_t dict_observation[] = {control_transcript().size(), uploaded_data().size()};
  (void)dict_observation;
#endif
}

}  // namespace proto_fuzzer
