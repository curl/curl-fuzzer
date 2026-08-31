/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Non-blocking in-process peer for curl's blocking TELNET driver.

#ifndef PROTO_FUZZER_TELNET_MOCK_SERVER_H_
#define PROTO_FUZZER_TELNET_MOCK_SERVER_H_

#include <curl/curl.h>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/mock_server_base.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::TelnetMockServer
/// @brief Preloads a complete bounded TELNET response before curl enters its
///        protocol loop.
///
/// Unlike curl's event-driven HTTP path, telnet_do() polls the network and the
/// caller's input source inside one curl_multi_perform() call. An incremental
/// mock cannot regain control to provide its next chunk. This peer writes the
/// whole runtime-visible script and half-closes first, making even an empty or
/// malformed scenario immediately readable and preventing a fuzz iteration
/// from waiting for terminal input or a wall-clock timeout.
class TelnetMockServer final : public MockServerBase {
 public:
  TelnetMockServer();
  ~TelnetMockServer() override;

  /// Attach the synchronous peer drain to TELNET's upload callback. curl's
  /// TELNET driver does not yield to RunLoop between network parsing and
  /// callback writes, so this is the only cheap point at which the harness can
  /// keep the outbound socket empty.
  /// @param request_data Callback state retained through the transfer.
  void ConfigureRequestData(ScenarioRequestData* request_data) override;

 protected:
  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// C-compatible UploadScriptState hook forwarding to DrainIncoming().
  static void DrainBeforeUploadRead(void* userdata);

  const curl::fuzzer::proto::Scenario* scenario_;
  bool socket_opened_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TELNET_MOCK_SERVER_H_
