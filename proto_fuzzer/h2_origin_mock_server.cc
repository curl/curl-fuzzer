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

namespace {

/// Map the schema selector to the transport's immutable constructor policy.
/// Unknown values retain the inexpensive zero-value behavior.
TlsGroupPolicy GroupPolicyFor(curl::fuzzer::proto::TlsGroupProfile profile) {
  return profile == curl::fuzzer::proto::TLS_GROUP_PROVIDER_DEFAULT ? TlsGroupPolicy::kProviderDefault
                                                                    : TlsGroupPolicy::kX25519;
}

}  // namespace

/// Construct an HTTP/2 TLS peer with the selected certificate chain.
/// @param certificate_chain Fixed certificate-chain profile to present.
/// @param group_profile Key-exchange group profile shared by both endpoints.
H2OriginMockServer::H2OriginMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain,
                                       curl::fuzzer::proto::TlsGroupProfile group_profile)
    : TlsMockServer(TlsApplicationProtocol::kHttp2, certificate_chain, GroupPolicyFor(group_profile)) {}

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
/// @param easy Easy handle to configure.
void H2OriginMockServer::Install(CURL* easy) {
  TlsMockServer::Install(easy);
  if (group_policy() == TlsGroupPolicy::kX25519) {
    (void)curl_easy_setopt(easy, CURLOPT_SSL_EC_CURVES, "X25519");
  }
  (void)curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  (void)curl_easy_setopt(easy, CURLOPT_UPKEEP_INTERVAL_MS, 0L);
}

/// Attach the reusable H2 client-frame tracker after TLS decryption.
/// @return Newly allocated TLS connection with the tracker attached.
std::unique_ptr<MockConnection> H2OriginMockServer::CreateConnection() {
  std::unique_ptr<MockConnection> connection = TlsMockServer::CreateConnection();
  runtime_.AttachConnection(connection.get());
  return connection;
}

/// Run the raw HTTP/2 response driver and probe server push and upkeep APIs.
/// @param multi Multi handle containing `easy`.
/// @param easy Easy handle attached to this mock.
/// @param scenario Source of bounded HTTP/2 response bytes.
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

/// Keep the connection cache alive until this mock is destroyed, after the
/// caller has cleaned the detached easy handle.
/// @param multi Detached multi handle and its live connection cache.
void H2OriginMockServer::HandleDetachedMulti(CurlMultiPtr multi) { retained_multi_ = std::move(multi); }

/// Expose shared protocol observations without allowing carrier state changes.
/// @return Runtime owned by this TLS carrier.
const H2Runtime& H2OriginMockServer::runtime() const { return runtime_; }

/// @return Number of accepted pushed handles explicitly cleaned up.
std::size_t H2OriginMockServer::cleaned_push_count() const { return additional_handle_cleanup_count(); }

}  // namespace proto_fuzzer
