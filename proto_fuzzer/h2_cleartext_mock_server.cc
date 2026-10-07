/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the plaintext HTTP/2 prior-knowledge origin.

#include "proto_fuzzer/h2_cleartext_mock_server.h"

#include <utility>

namespace proto_fuzzer {

H2CleartextMockServer::H2CleartextMockServer() = default;

H2CleartextMockServer::~H2CleartextMockServer() {
  // The multi borrows runtime_ for push callbacks, and connections borrow its
  // client-frame observer. Release both while that member is still alive.
  retained_multi_.reset();
  ResetConnections();
}

/// Install the socketpair peer and force HTTP/2 prior-knowledge mode.
/// @param easy Easy handle to configure.
void H2CleartextMockServer::Install(CURL* easy) {
  MockServer::Install(easy);
  (void)curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  (void)curl_easy_setopt(easy, CURLOPT_UPKEEP_INTERVAL_MS, 0L);
}

/// Attach the reusable H2 client-frame tracker to the plaintext connection.
/// @return Newly allocated plaintext connection with the tracker attached.
std::unique_ptr<MockConnection> H2CleartextMockServer::CreateConnection() {
  std::unique_ptr<MockConnection> connection = MockServer::CreateConnection();
  runtime_.AttachConnection(connection.get());
  return connection;
}

/// Drive raw or structured H2 peer work and probe server push and upkeep.
/// @param multi Multi handle containing `easy`.
/// @param easy Easy handle attached to this mock.
/// @param scenario Source of bounded HTTP/2 response work.
void H2CleartextMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  runtime_.PrepareMulti(multi, scenario.accept_h2_push());
  if (!scenario.has_http2_plan()) {
    MockServer::RunLoop(multi, easy, scenario);
  } else {
    // TLS's H2 carrier already keeps its write side open. Plaintext must do so
    // explicitly until the structured plan supplies the response.
    SetKeepConnectionsOpen(true);
    SetScripts(scenario);
    runtime_.ResetPlan(scenario.http2_plan(), "http");
    runtime_.DrivePlan(multi, *this, kMaxIdleIterations, kMaxDriveIterations, [this, easy] {
      ObserveActiveTransfer(easy);
      ResumeResponseIfRequested(easy);
    });
    SetKeepConnectionsOpen(false);
  }
  runtime_.FinishTransfer(easy, connection());
}

/// Retain the detached connection cache until after caller-owned easy cleanup.
/// @param multi Detached multi handle and its live connection cache.
void H2CleartextMockServer::HandleDetachedMulti(CurlMultiPtr multi) { retained_multi_ = std::move(multi); }

/// Expose shared protocol observations without allowing carrier state changes.
/// @return Runtime owned by this plaintext carrier.
const H2Runtime& H2CleartextMockServer::runtime() const { return runtime_; }

/// @return Number of accepted pushed handles explicitly cleaned up.
std::size_t H2CleartextMockServer::cleaned_push_count() const { return additional_handle_cleanup_count(); }

}  // namespace proto_fuzzer
