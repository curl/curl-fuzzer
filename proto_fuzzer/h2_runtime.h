/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared HTTP/2 plan, push, and upkeep behavior for origin peers.

#ifndef PROTO_FUZZER_H2_RUNTIME_H_
#define PROTO_FUZZER_H2_RUNTIME_H_

#include <curl/curl.h>

#include <cstddef>
#include <functional>
#include <string>

#include "proto_fuzzer/h2_plan.h"

struct curl_pushheaders;

namespace proto_fuzzer {

class MockConnection;
class MockServer;

/// Protocol state shared by TLS and plaintext HTTP/2 origin peers. This object
/// owns the client-frame observer and push callback userdata, but borrows the
/// transport and curl handles. The carrier must destroy its retained multi and
/// observed connections before destroying this runtime.
class H2Runtime {
 public:
  /// Construct detached protocol state without observing a connection.
  H2Runtime() = default;

  /// Callback userdata and incoming observers require a stable owner.
  /// @param other Runtime whose callback identity cannot be copied.
  H2Runtime(const H2Runtime& other) = delete;
  /// Callback userdata and incoming observers require a stable owner.
  /// @param other Runtime whose callback identity cannot be copied.
  /// @return Copy assignment is unavailable.
  H2Runtime& operator=(const H2Runtime& other) = delete;

  void PrepareMulti(CURLM* multi, bool accept_push);

  void AttachConnection(MockConnection* connection);

  void ResetPlan(const curl::fuzzer::proto::Http2Plan& plan, std::string scheme, std::string authority = "tls.test");

  /// Reject temporary plans whose storage would expire before servicing.
  /// @param plan Temporary plan that cannot provide borrowed storage.
  /// @param scheme Scheme used in generated push-request pseudo-headers.
  /// @param authority Authority used in generated push-request pseudo-headers.
  void ResetPlan(curl::fuzzer::proto::Http2Plan&& plan, std::string scheme,
                 std::string authority = "tls.test") = delete;
  /// Reject const temporary plans whose storage would expire before servicing.
  /// @param plan Temporary plan that cannot provide borrowed storage.
  /// @param scheme Scheme used in generated push-request pseudo-headers.
  /// @param authority Authority used in generated push-request pseudo-headers.
  void ResetPlan(const curl::fuzzer::proto::Http2Plan&& plan, std::string scheme,
                 std::string authority = "tls.test") = delete;

  void DrivePlan(CURLM* multi, MockServer& server, int max_idle_iterations, int max_drive_iterations,
                 const std::function<void()>& after_perform);

  void FinishTransfer(CURL* easy, MockConnection* connection);

  /// @return Number of syntactically valid pushes offered to this runtime.
  std::size_t push_callback_count() const { return push_callback_count_; }
  /// @return Number of PUSH_PROMISE headers advertised to the push callback.
  std::size_t push_header_count() const { return push_header_count_; }
  /// @return True when the latest push callback found the promised :path.
  bool saw_push_path() const { return saw_push_path_; }
  /// @return Number of pushed transfers accepted in the most recent drive.
  std::size_t accepted_push_count() const { return accepted_push_count_; }
  /// @return Body bytes consumed from accepted pushes in the latest drive.
  std::size_t pushed_body_bytes() const { return pushed_body_bytes_; }
  /// @return Result of the most recent upkeep probe, or CURLE_FAILED_INIT.
  CURLcode upkeep_result() const { return upkeep_result_; }
  /// @return Number of request streams observed since the latest plan reset.
  std::size_t observed_request_count() const { return plan_driver_.observed_request_count(); }
  /// @return Non-ACK client SETTINGS frames observed since the latest plan reset.
  std::size_t observed_client_settings_count() const { return plan_driver_.observed_client_settings_count(); }

 private:
  static int PushCallback(CURL* parent, CURL* pushed, std::size_t header_count, struct curl_pushheaders* headers,
                          void* userdata);
  static std::size_t PushedWriteCallback(char* contents, std::size_t size, std::size_t nmemb, void* userdata);

  H2PlanDriver plan_driver_;
  std::size_t push_callback_count_ = 0;
  std::size_t push_header_count_ = 0;
  bool saw_push_path_ = false;
  bool accept_push_ = false;
  std::size_t accepted_push_count_ = 0;
  std::size_t pushed_body_bytes_ = 0;
  CURLcode upkeep_result_ = CURLE_FAILED_INIT;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_H2_RUNTIME_H_
