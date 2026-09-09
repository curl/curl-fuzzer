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

namespace proto_fuzzer {

namespace {

// Header accessor work is independently bounded even if a future script
// raises the HTTP/2 decoder's current PUSH_PROMISE header limit.
constexpr std::size_t kMaxInspectedPushHeaders = 16;

}  // namespace

H2OriginMockServer::H2OriginMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain)
    : TlsMockServer(TlsApplicationProtocol::kHttp2, certificate_chain),
      push_callback_count_(0),
      push_header_count_(0),
      saw_push_path_(false),
      upkeep_result_(CURLE_FAILED_INIT) {}

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

/// Inspect both public push-header accessor families, then reject the pushed
/// transfer. Rejecting still exercises curl's cloned-handle and RST_STREAM
/// paths while leaving DriveScenario's single-handle ownership unchanged.
int H2OriginMockServer::PushCallback(CURL* parent, CURL* pushed, std::size_t header_count,
                                     struct curl_pushheaders* headers, void* userdata) {
  (void)parent;
  (void)pushed;
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
  return CURL_PUSH_DENY;
}

/// Configure shared-multi HTTP/2 behavior before its first perform, then use
/// the inherited raw response driver. One upkeep call after completion sends
/// an HTTP/2 PING through the still-live connection cache; draining once lets
/// the in-process TLS peer consume it without introducing another event loop.
void H2OriginMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  (void)curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  (void)curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, &H2OriginMockServer::PushCallback);
  (void)curl_multi_setopt(multi, CURLMOPT_PUSHDATA, this);

  MockServer::RunLoop(multi, easy, scenario);

  upkeep_result_ = curl_easy_upkeep(easy);
  if (connection() != nullptr) {
    (void)connection()->DrainIncoming();
  }
}

std::size_t H2OriginMockServer::push_callback_count() const { return push_callback_count_; }

std::size_t H2OriginMockServer::push_header_count() const { return push_header_count_; }

bool H2OriginMockServer::saw_push_path() const { return saw_push_path_; }

CURLcode H2OriginMockServer::upkeep_result() const { return upkeep_result_; }

}  // namespace proto_fuzzer
