/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implicit-TLS in-process peer for curl's FTPS state machine.

#ifndef PROTO_FUZZER_FTPS_MOCK_SERVER_H_
#define PROTO_FUZZER_FTPS_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/ftp_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::FtpsMockServer
/// @brief Runs FTP's control and passive data exchanges over implicit TLS.
///
/// FTPS differs from FTP only in transport setup: curl establishes TLS
/// immediately after the control TCP connection and, after PBSZ/PROT, wraps
/// each passive data connection as well. This peer inherits the command-aware
/// parser, channel bookkeeping, and bounded drive loop, replacing only the
/// connection factory and trust installation. Both the control connection and
/// every passive data channel are therefore real OpenSSL carriers.
///
/// Active mode (PORT/EPRT) is deliberately unsupported. Its data connection is
/// a real TCP socket that the FTP server dials into curl's listener, while this
/// harness only knows how to wrap socketpairs. The target policy removes
/// CURLOPT_FTPPORT from FTPS scenarios, and SupportsActiveMode() makes any
/// direct caller fail the data socket request boundedly rather than silently
/// downgrade to plaintext.
///
/// FTPS handshakes carry no ALPN extension. The carrier is constructed with
/// its closed HTTP/1.1 default, but OpenSSL only invokes the selector when the
/// client offers ALPN, so curl negotiates no application protocol here.
class FtpsMockServer final : public FtpMockServer {
 public:
  FtpsMockServer();

  ~FtpsMockServer() override;

  FtpsMockServer(const FtpsMockServer&) = delete;
  FtpsMockServer& operator=(const FtpsMockServer&) = delete;

  void Install(CURL* easy) override;

  int negotiated_tls_version() const;

  std::size_t completed_handshake_count() const;

  std::string negotiated_alpn() const;

 protected:
  std::unique_ptr<MockConnection> CreateConnection() override;

  bool SupportsActiveMode() const override;

 private:
  TlsMockTransport transport_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_FTPS_MOCK_SERVER_H_
