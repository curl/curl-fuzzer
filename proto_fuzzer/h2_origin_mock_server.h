/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief HTTPS origin peer with a fixed HTTP/2 application protocol.

#ifndef PROTO_FUZZER_H2_ORIGIN_MOCK_SERVER_H_
#define PROTO_FUZZER_H2_ORIGIN_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>

#include "proto_fuzzer/tls_mock_server.h"

struct curl_pushheaders;

namespace proto_fuzzer {

/// Runs Connection's bounded raw-byte scripts as HTTP/2 frames over the real
/// in-process TLS transport. The lane fixes protocol selection rather than
/// relying on a mutable CURLOPT_HTTP_VERSION, and installs the public server-
/// push callback before curl emits its initial SETTINGS frame.
class H2OriginMockServer final : public TlsMockServer {
 public:
  /// Construct an HTTP/2 TLS peer with the selected certificate chain.
  /// @param certificate_chain Fixed certificate-chain profile to present.
  explicit H2OriginMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain =
                                  curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC);

  /// Install TLS routing plus fixed HTTP/2 and immediate upkeep policy.
  /// @param easy Easy handle to configure.
  void Install(CURL* easy) override;

  /// @return number of syntactically valid pushes offered to the callback.
  std::size_t push_callback_count() const;

  /// @return number of PUSH_PROMISE headers advertised to the callback.
  std::size_t push_header_count() const;

  /// @return true when the callback found the promised :path header.
  bool saw_push_path() const;

  /// @return result of the bounded post-transfer curl_easy_upkeep call.
  CURLcode upkeep_result() const;

 protected:
  /// Run the raw HTTP/2 response driver and probe server push and upkeep APIs.
  /// @param multi Multi handle containing `easy`.
  /// @param easy Easy handle attached to this mock.
  /// @param scenario Source of bounded HTTP/2 response bytes.
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  static int PushCallback(CURL* parent, CURL* pushed, std::size_t header_count, struct curl_pushheaders* headers,
                          void* userdata);

  std::size_t push_callback_count_;
  std::size_t push_header_count_;
  bool saw_push_path_;
  CURLcode upkeep_result_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_H2_ORIGIN_MOCK_SERVER_H_
