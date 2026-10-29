/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implicit-TLS in-process peer for curl's IMAPS state machine.

#ifndef PROTO_FUZZER_IMAPS_MOCK_SERVER_H_
#define PROTO_FUZZER_IMAPS_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/imap_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::ImapsMockServer
/// @brief Runs the tagged IMAP command/reply exchange over implicit TLS.
///
/// IMAPS differs from IMAP only in transport setup: curl establishes TLS
/// immediately after CONNECT and then executes the same greeting, CAPABILITY,
/// LOGIN/AUTHENTICATE, SELECT, FETCH, and APPEND sequence. This peer therefore
/// inherits the tag-aware parser and replaces only the connection factory and
/// trust installation.
///
/// IMAP handshakes carry no ALPN extension. The carrier is constructed with
/// its closed HTTP/1.1 default, but OpenSSL only invokes the selector when the
/// client offers ALPN, so curl negotiates no application protocol here.
class ImapsMockServer final : public ImapMockServer {
 public:
  ImapsMockServer();

  ~ImapsMockServer() override;

  void ObserveState() override;

  ImapsMockServer(const ImapsMockServer&) = delete;
  ImapsMockServer& operator=(const ImapsMockServer&) = delete;

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

#endif  // PROTO_FUZZER_IMAPS_MOCK_SERVER_H_
