/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <csignal>
#include <cstddef>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/ftps_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct FtpsRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  std::string uploaded;
  std::size_t data_connections = 0;
  int tls_version = 0;
  std::size_t handshakes = 0;
  std::string alpn;
  std::size_t active_pollset_probes = 0;
};

FtpsRunResult RunScenario(const Scenario &scenario, const char *url) {
  FtpsRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_FTPS));
  Expect(connect_to != nullptr,
         "FTPS baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "FTPS URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "FTPS write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "FTPS write data setup failed");

  proto_fuzzer::FtpsMockServer server;
  server.Install(easy.get());
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.uploaded = server.uploaded_data();
  result.data_connections = server.opened_data_connection_count();
  result.tls_version = server.negotiated_tls_version();
  result.handshakes = server.completed_handshake_count();
  result.alpn = server.negotiated_alpn();
  result.active_pollset_probes = server.active_pollset_probe_count();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void AddLoginAndProtectionReplies(Scenario *scenario) {
  auto *connection = scenario->mutable_connection();
  connection->set_initial_response("220 ftps fuzz peer ready\r\n");
  connection->add_on_readable("331 password required\r\n");
  connection->add_on_readable("230 logged in\r\n");
  connection->add_on_readable("200 PBSZ accepted\r\n");
  connection->add_on_readable("200 PROT accepted\r\n");
  connection->add_on_readable("257 \"/\" is current directory\r\n");
}

void TestEpsvDownloadOverImplicitTls() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_FTPS);
  scenario.set_probe_multi_pollset(true);
  AddLoginAndProtectionReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable(
      "229 Entering Extended Passive Mode (|||12345|)\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("213 15\r\n");
  control->add_on_readable("150 opening secure data\r\n");
  control->add_on_readable("226 complete\r\n");
  scenario.add_subsequent_connections()->set_initial_response(
      "secret over tls");

  const FtpsRunResult result =
      RunScenario(scenario, "ftps://tls.test/file.bin");
  Expect(result.code == CURLE_OK, "FTPS EPSV download did not complete");
  Expect(result.body == "secret over tls",
         "FTPS EPSV download produced the wrong body");
  Expect(result.data_connections == 1,
         "FTPS download did not open exactly one data socket");
  Expect(result.handshakes == 2,
         "FTPS download did not complete control and data TLS handshakes");
  Expect(result.tls_version != 0,
         "FTPS peer did not record a negotiated TLS version");
  Expect(result.alpn.empty(),
         "FTPS handshake unexpectedly negotiated an ALPN protocol");
  Expect(result.transcript.find("PBSZ 0\r\n") != std::string::npos,
         "FTPS download did not negotiate the protection buffer size");
  Expect(result.transcript.find("PROT P\r\n") != std::string::npos,
         "FTPS download did not request private data-channel protection");
  Expect(result.transcript.find("EPSV\r\n") != std::string::npos,
         "FTPS download did not issue EPSV");
  Expect(result.transcript.find("RETR file.bin\r\n") != std::string::npos,
         "FTPS download did not issue RETR");
  Expect(result.active_pollset_probes != 0,
         "FTPS opt-in did not probe a live protocol pollset");
}

void TestUploadOverImplicitTls() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_FTPS);
  auto *upload_option = scenario.add_options();
  upload_option->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload_option->set_bool_value(true);
  auto *size_option = scenario.add_options();
  size_option->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  size_option->set_uint_value(12);
  scenario.mutable_upload()->set_data("upload-bytes");
  scenario.mutable_upload()->add_read_sizes(3);
  scenario.mutable_upload()->add_read_sizes(4);
  AddLoginAndProtectionReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable(
      "229 Entering Extended Passive Mode (|||12345|)\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("150 send data\r\n");
  control->add_on_readable("226 stored\r\n");
  scenario.add_subsequent_connections();

  const FtpsRunResult result =
      RunScenario(scenario, "ftps://tls.test/upload.bin");
  Expect(result.code == CURLE_OK, "FTPS upload did not complete");
  Expect(result.uploaded == "upload-bytes",
         "FTPS peer did not drain the complete decrypted upload body");
  Expect(result.data_connections == 1,
         "FTPS upload did not open exactly one data socket");
  Expect(result.handshakes == 2,
         "FTPS upload did not complete control and data TLS handshakes");
  Expect(result.transcript.find("STOR upload.bin\r\n") != std::string::npos,
         "FTPS upload did not issue STOR");
  Expect(result.active_pollset_probes == 0,
         "FTPS default path unexpectedly issued a pollset probe");
}

void TestActiveModeIsRejectedBoundedly() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_FTPS);
  auto *ftp_port = scenario.add_options();
  ftp_port->set_option_id(curl::fuzzer::proto::CURLOPT_FTPPORT);
  ftp_port->set_string_value("127.0.0.1");
  AddLoginAndProtectionReplies(&scenario);
  scenario.mutable_connection()->add_on_readable("257 \"/\"\r\n");
  scenario.add_subsequent_connections()->set_initial_response("unused");

  const FtpsRunResult result =
      RunScenario(scenario, "ftps://tls.test/active.bin");
  Expect(result.code != CURLE_OK,
         "FTPS active mode unexpectedly completed without a TLS data peer");
  Expect(result.data_connections == 0,
         "FTPS active mode allocated a passive data channel");
  Expect(result.handshakes == 1,
         "FTPS active mode completed more than the control handshake");
  Expect(result.transcript.find("EPRT ") == std::string::npos &&
             result.transcript.find("PORT ") == std::string::npos,
         "FTPS active mode sent a plaintext active-mode setup command");
}

} // namespace

int main() {
  // The proto fuzz runtime ignores SIGPIPE because mock-peer teardown can race
  // curl's TLS close. Match it here so OpenSSL's fatal-alert write reports a
  // socket error instead of terminating the focused peer test.
  std::signal(SIGPIPE, SIG_IGN);
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestEpsvDownloadOverImplicitTls();
  TestUploadOverImplicitTls();
  TestActiveModeIsRejectedBoundedly();
  curl_global_cleanup();
  return 0;
}
