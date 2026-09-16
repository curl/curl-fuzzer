/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the fixed HTTPS/HTTP2 origin peer.

#include "proto_fuzzer/h2_origin_mock_server.h"

#include <curl/multi.h>

#include <algorithm>
#include <string>

namespace proto_fuzzer {

namespace {

// Header accessor work is independently bounded even if a future script
// raises the HTTP/2 decoder's current PUSH_PROMISE header limit.
constexpr std::size_t kMaxInspectedPushHeaders = 16;

// One extra easy handle is enough to exercise accepted server-push lifecycle
// and concurrent stream state without letting mutated promises multiply work.
constexpr std::size_t kMaxAcceptedPushes = 1;

}  // namespace

H2OriginMockServer::H2OriginMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain)
    : TlsMockServer(TlsApplicationProtocol::kHttp2, certificate_chain),
      push_callback_count_(0),
      push_header_count_(0),
      saw_push_path_(false),
      accept_h2_push_(false),
      accepted_push_count_(0),
      pushed_body_bytes_(0),
      upkeep_result_(CURLE_FAILED_INIT) {}

H2OriginMockServer::~H2OriginMockServer() {
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
  // Zero makes the explicit upkeep call immediately eligible without adding
  // a clock wait to a fuzz iteration.
  (void)curl_easy_setopt(easy, CURLOPT_UPKEEP_INTERVAL_MS, 0L);
}

std::unique_ptr<MockConnection> H2OriginMockServer::CreateConnection() {
  std::unique_ptr<MockConnection> connection = TlsMockServer::CreateConnection();
  if (connection != nullptr) {
    connection->SetIncomingDataObserver(&plan_driver_);
  }
  return connection;
}

/// Inspect both public push-header accessor families, then either preserve the
/// historical rejection path or accept one harness-owned pushed transfer.
int H2OriginMockServer::PushCallback(CURL* parent, CURL* pushed, std::size_t header_count,
                                     struct curl_pushheaders* headers, void* userdata) {
  (void)parent;
  auto* self = static_cast<H2OriginMockServer*>(userdata);
  if (self == nullptr) {
    return CURL_PUSH_DENY;
  }

  ++self->push_callback_count_;
  self->push_header_count_ += header_count;
  const std::size_t inspected = std::min(header_count, kMaxInspectedPushHeaders);
  for (std::size_t index = 0; index < inspected; ++index) {
    (void)curl_pushheader_bynum(headers, index);
  }
  self->saw_push_path_ = curl_pushheader_byname(headers, ":path") != nullptr;
  (void)curl_pushheader_byname(headers, "x-fuzzer-missing");

  if (!self->accept_h2_push_ || self->accepted_push_count_ >= kMaxAcceptedPushes) {
    return CURL_PUSH_DENY;
  }

  // Install an explicit no-allocation sink before accepting. The fresh pushed
  // handle otherwise uses libcurl's default output path rather than the
  // parent's harness-owned response callback.
  if (curl_easy_setopt(pushed, CURLOPT_WRITEFUNCTION, &H2OriginMockServer::PushedWriteCallback) != CURLE_OK ||
      curl_easy_setopt(pushed, CURLOPT_WRITEDATA, self) != CURLE_OK) {
    return CURL_PUSH_DENY;
  }
  ++self->accepted_push_count_;
  return CURL_PUSH_OK;
}

std::size_t H2OriginMockServer::PushedWriteCallback(char* contents, std::size_t size, std::size_t nmemb,
                                                    void* userdata) {
  (void)contents;
  auto* self = static_cast<H2OriginMockServer*>(userdata);
  if (self == nullptr || (size != 0 && nmemb > static_cast<std::size_t>(-1) / size)) {
    return 0;
  }
  const std::size_t bytes = size * nmemb;
  const std::size_t remaining = static_cast<std::size_t>(-1) - self->pushed_body_bytes_;
  self->pushed_body_bytes_ += std::min(bytes, remaining);
  return bytes;
}

/// Configure shared-multi HTTP/2 behavior before its first perform, then use
/// the inherited raw response driver. One upkeep call after completion sends
/// an HTTP/2 PING through the still-live connection cache; draining once lets
/// the in-process TLS peer consume it without introducing another event loop.
void H2OriginMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  accept_h2_push_ = scenario.accept_h2_push();
  accepted_push_count_ = 0;
  pushed_body_bytes_ = 0;
  (void)curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  (void)curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, &H2OriginMockServer::PushCallback);
  (void)curl_multi_setopt(multi, CURLMOPT_PUSHDATA, this);

  if (!scenario.has_http2_plan()) {
    MockServer::RunLoop(multi, easy, scenario);
  } else {
    SetScripts(scenario);
    plan_driver_.Reset(scenario.http2_plan(), "https", "tls.test");

    int still_running = 1;
    int idle_iterations = 0;
    int drive_iterations = 0;
    while (still_running && idle_iterations < kMaxIdleIterations && drive_iterations++ < kMaxDriveIterations) {
      bool made_progress = false;
      const int running_before = still_running;
      const CURLMcode result = curl_multi_perform(multi, &still_running);
      if (result != CURLM_OK) {
        break;
      }
      ObserveActiveTransfer(easy);
      ResumeResponseIfRequested(easy);
      made_progress = still_running != running_before;
      if (!still_running) {
        break;
      }

      MockConnection* active_connection = connection();
      if (active_connection != nullptr) {
        made_progress = active_connection->DrainIncoming() != 0 || made_progress;
        std::string chunk;
        if (plan_driver_.NextChunk(&chunk)) {
          made_progress = true;
          if (!chunk.empty()) {
            (void)active_connection->WriteAll(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
          }
          made_progress = active_connection->DrainIncoming() != 0 || made_progress;
        }
      }
      if (made_progress) {
        idle_iterations = 0;
      } else {
        ++idle_iterations;
      }
    }
  }

  upkeep_result_ = curl_easy_upkeep(easy);
  if (connection() != nullptr) {
    (void)connection()->DrainIncoming();
  }
}

void H2OriginMockServer::HandleDetachedMulti(CurlMultiPtr multi) { retained_multi_ = std::move(multi); }

std::size_t H2OriginMockServer::push_callback_count() const { return push_callback_count_; }

std::size_t H2OriginMockServer::push_header_count() const { return push_header_count_; }

bool H2OriginMockServer::saw_push_path() const { return saw_push_path_; }

std::size_t H2OriginMockServer::accepted_push_count() const { return accepted_push_count_; }

std::size_t H2OriginMockServer::cleaned_push_count() const { return additional_handle_cleanup_count(); }

std::size_t H2OriginMockServer::pushed_body_bytes() const { return pushed_body_bytes_; }

CURLcode H2OriginMockServer::upkeep_result() const { return upkeep_result_; }

std::size_t H2OriginMockServer::observed_request_count() const { return plan_driver_.observed_request_count(); }

std::size_t H2OriginMockServer::observed_client_settings_count() const {
  return plan_driver_.observed_client_settings_count();
}

}  // namespace proto_fuzzer
