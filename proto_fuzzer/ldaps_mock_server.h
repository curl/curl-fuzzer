/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implicit-TLS in-process peer for curl's OpenLDAP-backed LDAPS
///        exchange.

#ifndef PROTO_FUZZER_LDAPS_MOCK_SERVER_H_
#define PROTO_FUZZER_LDAPS_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/ldap_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::LdapsMockServer
/// @brief Runs the LDAP bind/search exchange over implicit TLS.
///
/// LDAPS differs from LDAP only in transport setup: curl establishes TLS
/// immediately after CONNECT and then executes the same bindRequest and
/// searchRequest exchange. This peer therefore inherits the BER-aware parser
/// and replaces only the connection factory and trust installation.
///
/// OpenLDAP does not terminate this TLS itself in the bundled curl revision.
/// lib/openldap.c drives curl's own SSL connection filter in oldap_ssl_connect()
/// and then installs a Sockbuf_IO layer that routes OpenLDAP's BER reads and
/// writes through conn->recv/conn->send. The socketpair therefore carries
/// ordinary TLS records, and a plain server-side OpenSSL acceptor can terminate
/// them even though libldap itself was configured --without-tls.
///
/// LDAP handshakes carry no ALPN extension. The carrier is constructed with its
/// closed HTTP/1.1 default, but OpenSSL only invokes the selector when the
/// client offers ALPN, so curl negotiates no application protocol here.
class LdapsMockServer final : public LdapMockServer {
 public:
  LdapsMockServer();

  ~LdapsMockServer() override;

  LdapsMockServer(const LdapsMockServer&) = delete;
  LdapsMockServer& operator=(const LdapsMockServer&) = delete;

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

#endif  // PROTO_FUZZER_LDAPS_MOCK_SERVER_H_
