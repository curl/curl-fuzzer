/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded transport probes for curl's synchronous Gopher selector.

#ifndef PROTO_FUZZER_GOPHER_MOCK_SERVER_H_
#define PROTO_FUZZER_GOPHER_MOCK_SERVER_H_

#include <memory>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// The ordinary Gopher peer plus two closed selector-write probes. No mode
/// accepts arbitrary timing or environment values from the protobuf.
class GopherMockServer final : public MockServer {
 public:
  explicit GopherMockServer(curl::fuzzer::proto::GopherProbeMode mode);
  ~GopherMockServer() override;

  GopherMockServer(const GopherMockServer&) = delete;
  GopherMockServer& operator=(const GopherMockServer&) = delete;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  const curl::fuzzer::proto::GopherProbeMode mode_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_GOPHER_MOCK_SERVER_H_
