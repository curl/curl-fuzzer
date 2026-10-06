/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the fixed HTTPS/HTTP2 origin peer.

#include "proto_fuzzer/h2_origin_mock_server.h"

#include <utility>

namespace proto_fuzzer {

H2OriginMockServer::H2OriginMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain)
    : TlsMockServer(TlsApplicationProtocol::kHttp2, certificate_chain) {}

H2OriginMockServer::~H2OriginMockServer() {
  // The multi borrows runtime_ for push callbacks, and connections borrow its
  // client-frame observer. Release both while that member is still alive.
  retained_multi_.reset();
  ResetConnections();
}

/// Keep transport selection out of the mutation grammar. Applying Scenario
/// options after this hook is safe because the fixed H2 policy removes
/// HTTP_VERSION and does not expose UPKEEP_INTERVAL_MS in the structured
/// option manifest.
void H2OriginMockServer::Install(CURL* easy) {
  TlsMockServer::Install(easy);
  (void)curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  (void)curl_easy_setopt(easy, CURLOPT_UPKEEP_INTERVAL_MS, 0L);
}

std::unique_ptr<MockConnection> H2OriginMockServer::CreateConnection() {
  std::unique_ptr<MockConnection> connection = TlsMockServer::CreateConnection();
  runtime_.AttachConnection(connection.get());
  return connection;
}

void H2OriginMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  runtime_.PrepareMulti(multi, scenario.accept_h2_push());
  if (!scenario.has_http2_plan()) {
    MockServer::RunLoop(multi, easy, scenario);
  } else {
    SetScripts(scenario);
    runtime_.ResetPlan(scenario.http2_plan(), "https");
    runtime_.DrivePlan(multi, *this, kMaxIdleIterations, kMaxDriveIterations, [this, easy] {
      ObserveActiveTransfer(easy);
      ResumeResponseIfRequested(easy);
    });
  }
  runtime_.FinishTransfer(easy, connection());
}

void H2OriginMockServer::HandleDetachedMulti(CurlMultiPtr multi) { retained_multi_ = std::move(multi); }

std::size_t H2OriginMockServer::push_callback_count() const { return runtime_.push_callback_count(); }

std::size_t H2OriginMockServer::push_header_count() const { return runtime_.push_header_count(); }

bool H2OriginMockServer::saw_push_path() const { return runtime_.saw_push_path(); }

std::size_t H2OriginMockServer::accepted_push_count() const { return runtime_.accepted_push_count(); }

std::size_t H2OriginMockServer::cleaned_push_count() const { return additional_handle_cleanup_count(); }

std::size_t H2OriginMockServer::pushed_body_bytes() const { return runtime_.pushed_body_bytes(); }

CURLcode H2OriginMockServer::upkeep_result() const { return runtime_.upkeep_result(); }

std::size_t H2OriginMockServer::observed_request_count() const { return runtime_.observed_request_count(); }

std::size_t H2OriginMockServer::observed_client_settings_count() const {
  return runtime_.observed_client_settings_count();
}

}  // namespace proto_fuzzer
