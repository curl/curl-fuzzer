/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared HTTP/2 origin behavior independent of the transport carrier.

#include "proto_fuzzer/h2_runtime.h"

#include <curl/multi.h>

#include <algorithm>
#include <limits>
#include <utility>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

namespace {

// Bound header inspection independently of curl's PUSH_PROMISE limits.
constexpr std::size_t kMaxInspectedPushHeaders = 16;
// One extra easy handle exercises accepted push without multiplying work.
constexpr std::size_t kMaxAcceptedPushes = 1;

}  // namespace

/// Install the bounded push policy before curl emits its initial SETTINGS.
/// The runtime must outlive the multi and any accepted pushed handles.
/// @param multi Caller-owned multi handle receiving the push callbacks.
/// @param accept_push Whether to accept one push and reject further pushes.
void H2Runtime::PrepareMulti(CURLM* multi, bool accept_push) {
  accept_push_ = accept_push;
  accepted_push_count_ = 0;
  pushed_body_bytes_ = 0;
  (void)curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  (void)curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, &H2Runtime::PushCallback);
  (void)curl_multi_setopt(multi, CURLMOPT_PUSHDATA, this);
}

/// Observe application bytes after the carrier has decoded its transport.
/// A null connection is harmless; an attached connection borrows this runtime.
/// @param connection Transport to observe, or nullptr when creation failed.
void H2Runtime::AttachConnection(MockConnection* connection) {
  if (connection != nullptr) {
    connection->SetIncomingDataObserver(&plan_driver_);
  }
}

/// Borrow a structured plan for the ensuing synchronous drive.
/// @param plan Stable plan that remains alive and unmodified during the drive.
/// @param scheme Scheme used in generated push-request pseudo-headers.
/// @param authority Authority used in generated push-request pseudo-headers.
void H2Runtime::ResetPlan(const curl::fuzzer::proto::Http2Plan& plan, std::string scheme, std::string authority) {
  plan_driver_.Reset(plan, std::move(scheme), std::move(authority));
}

/// Alternate curl and one bounded H2 plan boundary. Carrier observation and
/// response-resume work run after each successful perform through the hook.
/// Idle and operation limits remain selected by the owning driver.
/// @param multi Caller-owned multi handle containing the transfer to drive.
/// @param server Carrier exposing the currently active connection.
/// @param max_idle_iterations Consecutive no-progress turns allowed.
/// @param max_drive_iterations Total state-machine turns allowed.
/// @param after_perform Carrier hook invoked after each successful perform.
void H2Runtime::DrivePlan(CURLM* multi, MockServer& server, int max_idle_iterations, int max_drive_iterations,
                          const std::function<void()>& after_perform) {
  int still_running = 1;
  int idle_iterations = 0;
  int drive_iterations = 0;
  while (still_running && idle_iterations < max_idle_iterations && drive_iterations++ < max_drive_iterations) {
    const int running_before = still_running;
    if (curl_multi_perform(multi, &still_running) != CURLM_OK) {
      break;
    }
    after_perform();
    if (!still_running) {
      break;
    }

    bool made_progress = still_running != running_before;
    if (MockConnection* connection = server.connection(); connection != nullptr) {
      made_progress = connection->DrainIncoming() != 0 || made_progress;
      std::string chunk;
      if (plan_driver_.NextChunk(&chunk)) {
        made_progress = true;
        if (!chunk.empty()) {
          (void)connection->WriteAll(reinterpret_cast<const unsigned char*>(chunk.data()), chunk.size());
        }
        made_progress = connection->DrainIncoming() != 0 || made_progress;
      }
    }
    if (made_progress) {
      idle_iterations = 0;
    } else {
      ++idle_iterations;
    }
  }
}

/// Probe upkeep while curl's connection cache and the peer are still live.
/// @param easy Caller-owned easy handle whose upkeep API is probed.
/// @param connection Peer to drain after upkeep, or nullptr when none opened.
void H2Runtime::FinishTransfer(CURL* easy, MockConnection* connection) {
  upkeep_result_ = curl_easy_upkeep(easy);
  if (connection != nullptr) {
    (void)connection->DrainIncoming();
  }
}

int H2Runtime::PushCallback(CURL* /*parent*/, CURL* pushed, std::size_t header_count, struct curl_pushheaders* headers,
                            void* userdata) {
  auto* self = static_cast<H2Runtime*>(userdata);
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

  if (!self->accept_push_ || self->accepted_push_count_ >= kMaxAcceptedPushes) {
    return CURL_PUSH_DENY;
  }
  // The new pushed handle needs an application-owned sink before acceptance.
  if (curl_easy_setopt(pushed, CURLOPT_WRITEFUNCTION, &H2Runtime::PushedWriteCallback) != CURLE_OK ||
      curl_easy_setopt(pushed, CURLOPT_WRITEDATA, self) != CURLE_OK) {
    return CURL_PUSH_DENY;
  }
  ++self->accepted_push_count_;
  return CURL_PUSH_OK;
}

std::size_t H2Runtime::PushedWriteCallback(char* /*contents*/, std::size_t size, std::size_t nmemb, void* userdata) {
  auto* self = static_cast<H2Runtime*>(userdata);
  const std::size_t maximum = std::numeric_limits<std::size_t>::max();
  if (self == nullptr || (size != 0 && nmemb > maximum / size)) {
    return 0;
  }
  const std::size_t bytes = size * nmemb;
  self->pushed_body_bytes_ += std::min(bytes, maximum - self->pushed_body_bytes_);
  return bytes;
}

}  // namespace proto_fuzzer
