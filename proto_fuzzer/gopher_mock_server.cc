/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded transport probes for curl's synchronous Gopher selector.

#include "proto_fuzzer/gopher_mock_server.h"

#include <cstdlib>
#include <string>

namespace proto_fuzzer {

namespace {

/// Replace one environment value only while curl constructs and drives the
/// probe's debug socket filter. libFuzzer executes callbacks serially.
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

constexpr int kTimeoutProbeBufferBytes = 2048;
constexpr long kTimeoutProbeMilliseconds = 5;

}  // namespace

/// Construct a closed Gopher probe peer.
/// @param mode Fixed probe selected by normalized target policy.
GopherMockServer::GopherMockServer(curl::fuzzer::proto::GopherProbeMode mode) : mode_(mode) {}

GopherMockServer::~GopherMockServer() = default;

/// Build an ordinary socketpair, then saturate the client-to-server direction
/// for the timeout probe before curl can write its selector.
/// @return A ready socketpair, or nullptr if saturation could not be
/// established.
std::unique_ptr<MockConnection> GopherMockServer::CreateConnection() {
  std::unique_ptr<MockConnection> connection = MockServer::CreateConnection();
  if (mode_ != curl::fuzzer::proto::GOPHER_PROBE_SEND_TIMEOUT) {
    return connection;
  }
  if (connection == nullptr || !connection->ok()) {
    return nullptr;
  }
  connection->ApplyBackpressure(kTimeoutProbeBufferBytes, 0);
  if (!connection->FillClientSendBuffer()) {
    return nullptr;
  }
  return connection;
}

/// Apply the two fixed timing policies immediately before curl's first
/// perform. Scenario options cannot replace these harness-owned values.
/// @param multi Multi handle driving the transfer.
/// @param easy Easy handle receiving fixed timeout policy.
/// @param scenario Normalized response script.
void GopherMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  if (mode_ == curl::fuzzer::proto::GOPHER_PROBE_PARTIAL_WRITE_NO_TIMEOUT) {
    (void)curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 0L);
    ScopedEnvironmentOverride partial_writes("CURL_DBG_SOCK_WPARTIAL", "50");
    MockServer::RunLoop(multi, easy, scenario);
    return;
  }
  if (mode_ == curl::fuzzer::proto::GOPHER_PROBE_SEND_TIMEOUT) {
    (void)curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, kTimeoutProbeMilliseconds);
  }
  MockServer::RunLoop(multi, easy, scenario);
}

}  // namespace proto_fuzzer
