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
  H2Runtime();

  H2Runtime(const H2Runtime&) = delete;
  H2Runtime& operator=(const H2Runtime&) = delete;

  void PrepareMulti(CURLM* multi, bool accept_push);

  void AttachConnection(MockConnection* connection);

  void ResetPlan(const curl::fuzzer::proto::Http2Plan& plan, std::string scheme, std::string authority = "tls.test");

  void ResetPlan(curl::fuzzer::proto::Http2Plan&&, std::string, std::string = "tls.test") = delete;
  void ResetPlan(const curl::fuzzer::proto::Http2Plan&&, std::string, std::string = "tls.test") = delete;

  void DrivePlan(CURLM* multi, MockServer& server, int max_idle_iterations, int max_drive_iterations,
                 const std::function<void()>& after_perform);

  void FinishTransfer(CURL* easy, MockConnection* connection);

  std::size_t push_callback_count() const;
  std::size_t push_header_count() const;
  bool saw_push_path() const;
  std::size_t accepted_push_count() const;
  std::size_t pushed_body_bytes() const;
  CURLcode upkeep_result() const;
  std::size_t observed_request_count() const;
  std::size_t observed_client_settings_count() const;

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
