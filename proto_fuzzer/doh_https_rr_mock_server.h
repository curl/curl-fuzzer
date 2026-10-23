/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief DoH responder that feeds a synthesized HTTPS resource record to
///        curl's HTTPS-connect ALPN filter.

#ifndef PROTO_FUZZER_DOH_HTTPS_RR_MOCK_SERVER_H_
#define PROTO_FUZZER_DOH_HTTPS_RR_MOCK_SERVER_H_

#include <curl/curl.h>

#include <array>
#include <cstddef>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/h2_origin_mock_server.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::DohHttpsRrMockServer
/// @brief Resolver-lane peer that answers curl's internal DoH queries from a
///        loopback HTTP listener and completes the selected HTTPS/ALPN h2
///        exchange through the in-process TLS transport.
///
/// curl creates and drives the DoH easy handle itself, so the harness socket
/// callbacks do not reach it. A real 127.0.0.1 listener is therefore the only
/// way to answer the HTTPS resource-record query that `cf-https-connect` reads.
/// The synthesized answer advertises `alpn=h2,h3`; this peer owns the fixed
/// h2 application protocol, so the selected transfer can complete when the
/// build supports HTTP/2.
class DohHttpsRrMockServer : public H2OriginMockServer {
 public:
  explicit DohHttpsRrMockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain =
                                    curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC);
  ~DohHttpsRrMockServer() override;

  DohHttpsRrMockServer(const DohHttpsRrMockServer&) = delete;
  DohHttpsRrMockServer& operator=(const DohHttpsRrMockServer&) = delete;

  void Install(CURL* easy) override;

  void ConfigureRequestData(ScenarioRequestData* request_data) override;

  /// @return Number of complete DoH requests served by the loopback listener.
  std::size_t doh_request_count() const { return doh_request_count_; }

  /// @return Number of HTTPS resource-record answers synthesized.
  std::size_t httpsrr_answer_count() const { return httpsrr_answer_count_; }

  /// @return Ephemeral DoH listener URL, or an empty string when setup failed.
  const std::string& doh_url() const { return doh_url_; }

 protected:
  void ObserveActiveTransfer(CURL* easy) override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// One accepted DoH TCP connection and its buffered request/response state.
  struct DohConnection {
    int fd = -1;
    std::string request;
    std::string response;
    std::size_t response_offset = 0;
    bool writing = false;
  };

  /// Bound accepted probes independently of curl's internal DoH concurrency.
  static constexpr std::size_t kMaxConnections = 8;
  /// Bound each HTTP request and DNS answer so a malformed probe cannot grow
  /// harness memory in proportion to the fuzz input.
  static constexpr std::size_t kMaxRequestBytes = 4096;
  static constexpr std::size_t kMaxResponseBytes = 4096;

  virtual bool StartListener();
  void StopListener();
  bool BeginProxyBypass();
  void EndProxyBypass();

  void ServiceDohConnections();
  void AcceptConnections();
  void CloseConnection(DohConnection* connection);
  bool CompleteRequest(DohConnection* connection);

  CURL* easy_;
  int listener_;
  std::string doh_url_;

  std::array<DohConnection, kMaxConnections> connections_;
  std::size_t doh_request_count_;
  std::size_t httpsrr_answer_count_;

  /// True only after every resolver endpoint and proxy-bypass step has been
  /// installed. RunLoop refuses to perform when setup is partial so curl
  /// cannot fall back to the process's native resolver.
  bool setup_ok_;

  /// Saved process proxy bypass so the internal DoH handle cannot consult an
  /// ambient proxy configuration that does not apply to the parent transfer.
  bool proxy_bypass_active_;
  bool lower_no_proxy_was_set_;
  bool upper_no_proxy_was_set_;
  std::string saved_no_proxy_lower_;
  std::string saved_no_proxy_upper_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_DOH_HTTPS_RR_MOCK_SERVER_H_
