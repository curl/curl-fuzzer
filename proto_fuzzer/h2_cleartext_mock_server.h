/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Plaintext HTTP/2 prior-knowledge origin peer.

#ifndef PROTO_FUZZER_H2_CLEARTEXT_MOCK_SERVER_H_
#define PROTO_FUZZER_H2_CLEARTEXT_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>

#include "proto_fuzzer/h2_plan.h"
#include "proto_fuzzer/mock_server.h"

struct curl_pushheaders;

namespace proto_fuzzer {

/// Drives raw or structured HTTP/2 frames over a local plaintext socketpair.
/// Prior-knowledge mode enters curl's HTTP/2 state machine without paying for
/// a TLS handshake, while retaining the same multi/easy cleanup ordering as
/// the HTTPS/HTTP2 origin lane.
class H2CleartextMockServer final : public MockServer {
 public:
  H2CleartextMockServer();
  ~H2CleartextMockServer() override;

  /// Install the socketpair peer and force HTTP/2 prior-knowledge mode.
  /// @param easy Easy handle to configure.
  void Install(CURL* easy) override;

  /// @return number of syntactically valid pushes offered to the callback.
  std::size_t push_callback_count() const;

  /// @return number of pushed transfers accepted by the bounded callback.
  std::size_t accepted_push_count() const;

  /// @return number of accepted pushed handles explicitly cleaned up.
  std::size_t cleaned_push_count() const;

  /// @return result of the bounded post-transfer curl_easy_upkeep call.
  CURLcode upkeep_result() const;

  /// @return number of client request streams observed by a structured plan.
  std::size_t observed_request_count() const;

 protected:
  /// Attach the reusable H2 client-frame tracker to the plaintext connection.
  /// @return newly allocated plaintext connection with the tracker attached.
  std::unique_ptr<MockConnection> CreateConnection() override;

  /// Drive raw or structured H2 peer work and probe server push and upkeep.
  /// @param multi Multi handle containing `easy`.
  /// @param easy Easy handle attached to this mock.
  /// @param scenario Source of bounded HTTP/2 response work.
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

  /// Retain the detached connection cache until after caller-owned easy cleanup.
  /// @param multi Detached multi handle and its live connection cache.
  void HandleDetachedMulti(CurlMultiPtr multi) override;

 private:
  static int PushCallback(CURL* parent, CURL* pushed, std::size_t header_count, struct curl_pushheaders* headers,
                          void* userdata);
  static std::size_t PushedWriteCallback(char* contents, std::size_t size, std::size_t nmemb, void* userdata);

  std::size_t push_callback_count_;
  bool accept_h2_push_;
  std::size_t accepted_push_count_;
  std::size_t pushed_body_bytes_;
  CURLcode upkeep_result_;
  H2PlanDriver plan_driver_;
  CurlMultiPtr retained_multi_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_H2_CLEARTEXT_MOCK_SERVER_H_
