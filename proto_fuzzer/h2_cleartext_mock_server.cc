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

void H2CleartextMockServer::Install(CURL* easy) {
  MockServer::Install(easy);
  (void)curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  (void)curl_easy_setopt(easy, CURLOPT_UPKEEP_INTERVAL_MS, 0L);
}

std::unique_ptr<MockConnection> H2CleartextMockServer::CreateConnection() {
  std::unique_ptr<MockConnection> connection = MockServer::CreateConnection();
  runtime_.AttachConnection(connection.get());
  return connection;
}

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

void H2CleartextMockServer::HandleDetachedMulti(CurlMultiPtr multi) { retained_multi_ = std::move(multi); }

std::size_t H2CleartextMockServer::push_callback_count() const { return runtime_.push_callback_count(); }

/// @return number of PUSH_PROMISE headers advertised to the callback.
std::size_t H2CleartextMockServer::push_header_count() const { return runtime_.push_header_count(); }

/// @return true when the callback found the promised :path header.
bool H2CleartextMockServer::saw_push_path() const { return runtime_.saw_push_path(); }

std::size_t H2CleartextMockServer::accepted_push_count() const { return runtime_.accepted_push_count(); }

std::size_t H2CleartextMockServer::cleaned_push_count() const { return additional_handle_cleanup_count(); }

/// @return response-body bytes delivered by accepted pushed transfers.
std::size_t H2CleartextMockServer::pushed_body_bytes() const { return runtime_.pushed_body_bytes(); }

CURLcode H2CleartextMockServer::upkeep_result() const { return runtime_.upkeep_result(); }

std::size_t H2CleartextMockServer::observed_request_count() const { return runtime_.observed_request_count(); }

/// @return number of non-ACK client SETTINGS frames observed.
std::size_t H2CleartextMockServer::observed_client_settings_count() const {
  return runtime_.observed_client_settings_count();
}

}  // namespace proto_fuzzer
