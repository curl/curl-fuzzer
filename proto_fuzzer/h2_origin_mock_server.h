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
#include <memory>

#include "proto_fuzzer/h2_runtime.h"
#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// Runs Connection's bounded raw-byte scripts as HTTP/2 frames over the real
/// in-process TLS transport. The lane fixes protocol selection rather than
/// relying on a mutable CURLOPT_HTTP_VERSION, and installs the public server-
/// push callback before curl emits its initial SETTINGS frame.
class H2OriginMockServer final : public TlsMockServer {
 public:
  explicit H2OriginMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain =
                                  curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC);
  ~H2OriginMockServer() override;

  void Install(CURL* easy) override;

  const H2Runtime& runtime() const;
  std::size_t cleaned_push_count() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

  void HandleDetachedMulti(CurlMultiPtr multi) override;

 private:
  H2Runtime runtime_;
  CurlMultiPtr retained_multi_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_H2_ORIGIN_MOCK_SERVER_H_
