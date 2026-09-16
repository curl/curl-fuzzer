/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the plaintext HTTP/2 prior-knowledge origin.

#include "proto_fuzzer/h2_cleartext_mock_server.h"

#include <curl/multi.h>

#include <algorithm>
#include <string>

namespace proto_fuzzer {

namespace {

constexpr std::size_t kMaxInspectedPushHeaders = 16;
constexpr std::size_t kMaxAcceptedPushes = 1;

}  // namespace

H2CleartextMockServer::H2CleartextMockServer()
    : push_callback_count_(0),
      accept_h2_push_(false),
      accepted_push_count_(0),
      pushed_body_bytes_(0),
      upkeep_result_(CURLE_FAILED_INIT) {}

H2CleartextMockServer::~H2CleartextMockServer() {
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
  if (connection != nullptr) {
    connection->SetIncomingDataObserver(&plan_driver_);
  }
  return connection;
}

int H2CleartextMockServer::PushCallback(CURL* parent, CURL* pushed, std::size_t header_count,
                                        struct curl_pushheaders* headers, void* userdata) {
  (void)parent;
  auto* self = static_cast<H2CleartextMockServer*>(userdata);
  if (self == nullptr) {
    return CURL_PUSH_DENY;
  }

  ++self->push_callback_count_;
  const std::size_t inspected = std::min(header_count, kMaxInspectedPushHeaders);
  for (std::size_t index = 0; index < inspected; ++index) {
    (void)curl_pushheader_bynum(headers, index);
  }
  (void)curl_pushheader_byname(headers, ":path");
  (void)curl_pushheader_byname(headers, "x-fuzzer-missing");

  if (!self->accept_h2_push_ || self->accepted_push_count_ >= kMaxAcceptedPushes) {
    return CURL_PUSH_DENY;
  }
  if (curl_easy_setopt(pushed, CURLOPT_WRITEFUNCTION, &H2CleartextMockServer::PushedWriteCallback) != CURLE_OK ||
      curl_easy_setopt(pushed, CURLOPT_WRITEDATA, self) != CURLE_OK) {
    return CURL_PUSH_DENY;
  }
  ++self->accepted_push_count_;
  return CURL_PUSH_OK;
}

std::size_t H2CleartextMockServer::PushedWriteCallback(char* contents, std::size_t size, std::size_t nmemb,
                                                       void* userdata) {
  (void)contents;
  auto* self = static_cast<H2CleartextMockServer*>(userdata);
  if (self == nullptr || (size != 0 && nmemb > static_cast<std::size_t>(-1) / size)) {
    return 0;
  }
  const std::size_t bytes = size * nmemb;
  self->pushed_body_bytes_ += std::min(bytes, static_cast<std::size_t>(-1) - self->pushed_body_bytes_);
  return bytes;
}

void H2CleartextMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  accept_h2_push_ = scenario.accept_h2_push();
  accepted_push_count_ = 0;
  pushed_body_bytes_ = 0;
  (void)curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  (void)curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, &H2CleartextMockServer::PushCallback);
  (void)curl_multi_setopt(multi, CURLMOPT_PUSHDATA, this);

  if (!scenario.has_http2_plan()) {
    MockServer::RunLoop(multi, easy, scenario);
  } else {
    // Structured actions provide the response after curl has emitted its
    // preface and request. Keep an otherwise empty Connection from sending a
    // premature FIN when HandleOpenSocket creates the plaintext socketpair.
    SetKeepConnectionsOpen(true);
    SetScripts(scenario);
    plan_driver_.Reset(scenario.http2_plan(), "http", "tls.test");

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
    SetKeepConnectionsOpen(false);
  }

  upkeep_result_ = curl_easy_upkeep(easy);
  if (connection() != nullptr) {
    (void)connection()->DrainIncoming();
  }
}

void H2CleartextMockServer::HandleDetachedMulti(CurlMultiPtr multi) { retained_multi_ = std::move(multi); }

std::size_t H2CleartextMockServer::push_callback_count() const { return push_callback_count_; }

std::size_t H2CleartextMockServer::accepted_push_count() const { return accepted_push_count_; }

std::size_t H2CleartextMockServer::cleaned_push_count() const { return additional_handle_cleanup_count(); }

CURLcode H2CleartextMockServer::upkeep_result() const { return upkeep_result_; }

std::size_t H2CleartextMockServer::observed_request_count() const { return plan_driver_.observed_request_count(); }

}  // namespace proto_fuzzer
