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

#include "proto_fuzzer/h2_runtime.h"
#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Drives raw or structured HTTP/2 frames over a local plaintext socketpair.
/// Prior-knowledge mode enters curl's HTTP/2 state machine without paying for
/// a TLS handshake, while retaining the same multi/easy cleanup ordering as
/// the HTTPS/HTTP2 origin lane.
class H2CleartextMockServer final : public MockServer {
 public:
  H2CleartextMockServer();
  ~H2CleartextMockServer() override;

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

#endif  // PROTO_FUZZER_H2_CLEARTEXT_MOCK_SERVER_H_
