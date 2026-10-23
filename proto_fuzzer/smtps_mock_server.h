/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implicit-TLS in-process peer for curl's SMTPS state machine.

#ifndef PROTO_FUZZER_SMTPS_MOCK_SERVER_H_
#define PROTO_FUZZER_SMTPS_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/smtp_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::SmtpsMockServer
/// @brief Runs the SMTP command/reply and DATA-body exchange over implicit TLS.
///
/// SMTPS differs from SMTP only in transport setup: curl establishes TLS
/// immediately after CONNECT and then executes the same greeting, EHLO/HELO,
/// envelope, DATA, and QUIT sequence. This peer therefore inherits the
/// command-aware parser and replaces only the connection factory and trust
/// installation.
///
/// SMTP handshakes carry no ALPN extension. The carrier is constructed with
/// its closed HTTP/1.1 default, but OpenSSL only invokes the selector when the
/// client offers ALPN, so curl negotiates no application protocol here.
class SmtpsMockServer final : public SmtpMockServer {
 public:
  SmtpsMockServer();

  ~SmtpsMockServer() override;

  SmtpsMockServer(const SmtpsMockServer&) = delete;
  SmtpsMockServer& operator=(const SmtpsMockServer&) = delete;

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

#endif  // PROTO_FUZZER_SMTPS_MOCK_SERVER_H_
