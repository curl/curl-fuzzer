/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Fresh easy-handle and share ownership for TLS session replay.

#include "proto_fuzzer/tls_session_replay.h"

#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/tls_mock_server.h"
#include "proto_fuzzer/transfer_session.h"

namespace proto_fuzzer {

/// Replay one archived TLS session after the first transfer owner is gone.
/// The share is declared before the transfer so the easy handle detaches and
/// closes before curl_share_cleanup runs.
/// @param scenario Input used to configure the replay transfer.
/// @param url URL installed on the replay easy handle.
/// @param server TLS peer that owns the archived session.
/// @return Public import and transfer results.
TlsSessionReplayResult ReplayTlsSession(const curl::fuzzer::proto::Scenario& scenario, const std::string& url,
                                        TlsMockServer* server) {
  TlsSessionReplayResult result;
  CurlSharePtr share(curl_share_init());
  if (server == nullptr || share == nullptr ||
      curl_share_setopt(share.get(), CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION) != CURLSHE_OK) {
    return result;
  }

  TransferSession replay;
  if (!replay.PrepareInputFiles(scenario, ScenarioRunMode::kTlsCoverage) || !replay.Initialize()) {
    return result;
  }
  CURL* easy = replay.easy();
  replay.ApplyBaseline(scenario);
  (void)curl_easy_setopt(easy, CURLOPT_URL, url.c_str());
  server->Install(easy);
  replay.ApplyInputFiles();
  (void)ApplyScenarioOptions(easy, scenario);
  replay.ApplyPinnedPublicKeyFile();
  (void)replay.ApplyTlsClientCredentialProfile(scenario.tls_client_credential_profile());
  if (curl_easy_setopt(easy, CURLOPT_SHARE, share.get()) != CURLE_OK) {
    return result;
  }

  ScenarioRequestData* request_data = replay.InstallRequestData(scenario);
  if (request_data == nullptr) {
    return result;
  }
  server->ConfigureRequestData(request_data);
  result.import_result = server->ImportArchivedSession(easy);
  result.transfer_result = server->DriveScenario(easy, scenario);
  return result;
}

}  // namespace proto_fuzzer
