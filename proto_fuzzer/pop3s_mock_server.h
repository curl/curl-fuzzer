/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implicit-TLS in-process peer for curl's POP3S state machine.

#ifndef PROTO_FUZZER_POP3S_MOCK_SERVER_H_
#define PROTO_FUZZER_POP3S_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/pop3_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::Pop3sMockServer
/// @brief Runs the status-line POP3 command/reply exchange over implicit TLS.
///
/// POP3S differs from POP3 only in transport setup: curl establishes TLS
/// immediately after CONNECT and then executes the same greeting, CAPA,
/// USER/PASS or APOP, LIST, RETR, and QUIT sequence. This peer therefore
/// inherits the command-aware parser and replaces only the connection factory
/// and trust installation.
///
/// POP3 handshakes carry no ALPN extension. The carrier is constructed with
/// its closed HTTP/1.1 default, but OpenSSL only invokes the selector when the
/// client offers ALPN, so curl negotiates no application protocol here.
class Pop3sMockServer final : public Pop3MockServer {
 public:
  Pop3sMockServer();

  ~Pop3sMockServer() override;

  Pop3sMockServer(const Pop3sMockServer&) = delete;
  Pop3sMockServer& operator=(const Pop3sMockServer&) = delete;

  void Install(CURL* easy) override;

  int negotiated_tls_version() const;

  std::size_t completed_handshake_count() const;

  std::string negotiated_alpn() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

 private:
  TlsMockTransport transport_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_POP3S_MOCK_SERVER_H_
