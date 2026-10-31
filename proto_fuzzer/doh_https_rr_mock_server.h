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
#include <cstdio>
#include <memory>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/h2_origin_mock_server.h"

namespace proto_fuzzer {

class BoundedAnonymousInputFile;

/// @class proto_fuzzer::DohHttpsRrMockServer
/// @brief Resolver-lane peer that answers curl's internal DoH queries from a
///        loopback HTTP or HTTPS listener and completes the selected outer
///        HTTPS/ALPN h2 exchange through a separate in-process TLS transport.
///
/// curl creates and drives the DoH easy handle itself, so the harness socket
/// callbacks do not reach it. A real 127.0.0.1 listener is therefore the only
/// way to answer the HTTPS resource-record query that `cf-https-connect` reads.
/// The synthesized answer advertises `alpn=h2,h3`; this peer owns the fixed
/// h2 application protocol, so the selected transfer can complete when the
/// build supports HTTP/2.
class DohHttpsRrMockServer : public H2OriginMockServer {
 public:
  explicit DohHttpsRrMockServer(const curl::fuzzer::proto::Scenario& scenario);
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

  /// @return Number of TLS handshakes completed by the DoH listener itself.
  std::size_t doh_tls_handshake_count() const {
    return doh_tls_transport_ == nullptr ? 0 : doh_tls_transport_->completed_handshake_count();
  }

  /// @return ALPN selected by the most recent DoH TLS handshake.
  std::string doh_tls_alpn() const {
    return doh_tls_transport_ == nullptr ? std::string() : doh_tls_transport_->negotiated_alpn();
  }

  std::string custom_stderr_contents();

  bool tls_path_fixture_ready() const;

  /// @return SSL context callbacks observed on curl-created internal handles.
  std::size_t internal_ssl_ctx_callback_count() const { return internal_ssl_ctx_callback_count_; }

 protected:
  void ObserveActiveTransfer(CURL* easy) override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// Bound accepted probes independently of curl's internal DoH concurrency.
  static constexpr std::size_t kMaxConnections = 8;
  /// Bound each HTTP request and DNS answer so a malformed probe cannot grow
  /// harness memory in proportion to the fuzz input.
  static constexpr std::size_t kMaxRequestBytes = 4096;
  static constexpr std::size_t kMaxResponseBytes = 4096;
  static constexpr std::size_t kMaxDiagnosticBytes = 4096;

  /// One accepted DoH TCP connection and its buffered request/response state.
  struct DohConnection final : public IncomingDataObserver {
    bool active() const { return fd >= 0 || tls != nullptr; }
    void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

    int fd = -1;
    std::unique_ptr<MockConnection> tls;
    std::string request;
    std::string response;
    std::size_t response_offset = 0;
    std::size_t deferred_write_turns = 0;
    bool writing = false;
    bool request_overflow = false;
  };

  virtual bool StartListener();
  void StopListener();
  bool ConfigureHttpsOptions();
  static CURLcode ObserveSslContext(CURL* easy, void* ssl_context, void* user_data);
  bool BeginProxyBypass();
  void EndProxyBypass();

  void ServiceDohConnections();
  void AcceptConnections();
  void CloseConnection(DohConnection* connection);
  bool CompleteRequest(DohConnection* connection);

  CURL* easy_;
  int listener_;
  std::string doh_url_;

  /// Closed parent-option probe copied onto curl-created HTTPS DoH handles.
  curl::fuzzer::proto::DohOptionProbeMode option_probe_mode_;

  /// Fixed scheme used by the listener for every internal probe.
  curl::fuzzer::proto::DohTransportMode transport_mode_;

  /// Non-global diagnostic stream retained by CURLOPT_STDERR.
  std::FILE* diagnostic_stream_;

  /// Procfs-backed certificate bytes reused as CAINFO, CAPATH, and CRLFILE.
  std::unique_ptr<BoundedAnonymousInputFile> tls_path_fixture_;

  /// Callback hits from internal DoH handles rather than the parent easy.
  std::size_t internal_ssl_ctx_callback_count_;

  /// Dedicated HTTP/1.1 TLS context for accepted DoH connections. The outer
  /// origin keeps the separate HTTP/2 transport owned by the base class.
  std::unique_ptr<TlsMockTransport> doh_tls_transport_;

  std::array<DohConnection, kMaxConnections> connections_;
  std::size_t doh_request_count_;
  std::size_t httpsrr_answer_count_;

  /// Fixed HTTP/DNS terminal for every complete request in this drive.
  curl::fuzzer::proto::DohResponseMode response_mode_;

  /// Hold a valid HTTPS answer for one outer drive turn. Address resolution
  /// can then create the TLS filter while ECH's HTTPS-RR lookup is pending.
  bool defer_httpsrr_;

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
