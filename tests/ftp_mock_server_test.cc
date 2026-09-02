/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdlib>
#include <iostream>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/ftp_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct FtpRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  std::string uploaded;
  std::size_t data_connections = 0;
};

FtpRunResult RunScenario(const Scenario &scenario, const char *url) {
  FtpRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_FTP));
  Expect(connect_to != nullptr, "FTP baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "FTP URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "FTP write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "FTP write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::FtpMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.uploaded = server.uploaded_data();
  result.data_connections = server.opened_data_connection_count();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void AddLoginAndPwdReplies(Scenario *scenario) {
  auto *connection = scenario->mutable_connection();
  connection->set_initial_response("220 ready\r\n");
  connection->add_on_readable("331 password required\r\n");
  connection->add_on_readable("230 logged in\r\n");
  connection->add_on_readable("257 \"/\" is current directory\r\n");
}

void TestEpsvDownloadAndFinalReply() {
  Scenario scenario;
  AddLoginAndPwdReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable(
      "229 Entering Extended Passive Mode (|||12345|)\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("213 11\r\n");
  control->add_on_readable("150 opening data\r\n");
  control->add_on_readable("226 complete\r\n");
  scenario.add_subsequent_connections()->set_initial_response("hello world");

  const FtpRunResult result = RunScenario(scenario, "ftp://ftp.test/file.bin");
  Expect(result.code == CURLE_OK, "EPSV FTP download did not complete");
  Expect(result.body == "hello world",
         "EPSV FTP download produced the wrong body");
  Expect(result.data_connections == 1,
         "EPSV FTP download did not open exactly one data socket");
  Expect(result.transcript.find("EPSV\r\n") != std::string::npos,
         "FTP download did not issue EPSV");
  Expect(result.transcript.find("RETR file.bin\r\n") != std::string::npos,
         "FTP download did not issue RETR");
}

void TestEpsvFailureFallsBackToPasv() {
  Scenario scenario;
  AddLoginAndPwdReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable("500 no EPSV\r\n");
  control->add_on_readable("227 Entering Passive Mode (127,0,0,1,48,57)\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("213 8\r\n");
  control->add_on_readable("150 opening data\r\n");
  control->add_on_readable("226 complete\r\n");
  scenario.add_subsequent_connections()->set_initial_response("fallback");

  const FtpRunResult result = RunScenario(scenario, "ftp://ftp.test/fallback");
  Expect(result.code == CURLE_OK, "FTP PASV fallback did not complete");
  Expect(result.body == "fallback",
         "FTP PASV fallback produced the wrong body");
  Expect(result.transcript.find("EPSV\r\n") != std::string::npos,
         "FTP PASV fallback skipped EPSV attempt");
  Expect(result.transcript.find("PASV\r\n") != std::string::npos,
         "FTP EPSV rejection did not issue PASV");
}

void TestUploadIsDrainedWithoutLosingControlChannel() {
  Scenario scenario;
  auto *upload_option = scenario.add_options();
  upload_option->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload_option->set_bool_value(true);
  auto *size_option = scenario.add_options();
  size_option->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  size_option->set_uint_value(12);
  scenario.mutable_upload()->set_data("upload-bytes");
  scenario.mutable_upload()->add_read_sizes(3);
  scenario.mutable_upload()->add_read_sizes(4);
  AddLoginAndPwdReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable(
      "229 Entering Extended Passive Mode (|||12345|)\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("150 send data\r\n");
  control->add_on_readable("226 stored\r\n");
  scenario.add_subsequent_connections();

  const FtpRunResult result =
      RunScenario(scenario, "ftp://ftp.test/upload.bin");
  Expect(result.code == CURLE_OK, "FTP upload did not complete");
  Expect(result.uploaded == "upload-bytes",
         "FTP peer did not drain the exact upload body");
  Expect(result.transcript.find("STOR upload.bin\r\n") != std::string::npos,
         "FTP upload did not issue STOR");
  Expect(result.data_connections == 1,
         "FTP upload did not open exactly one passive socket");
}

void TestCustomListingCommandReceivesPassiveData() {
  Scenario scenario;
  auto *list_only = scenario.add_options();
  list_only->set_option_id(curl::fuzzer::proto::CURLOPT_DIRLISTONLY);
  list_only->set_bool_value(true);
  auto *custom_request = scenario.add_options();
  custom_request->set_option_id(curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST);
  custom_request->set_string_value("X-LIST");
  AddLoginAndPwdReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable(
      "229 Entering Extended Passive Mode (|||12345|)\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("150 custom listing\r\n");
  control->add_on_readable("226 listed\r\n");
  scenario.add_subsequent_connections()->set_initial_response(
      "custom-entry\r\n");

  const FtpRunResult result = RunScenario(scenario, "ftp://ftp.test/");
  Expect(result.code == CURLE_OK, "custom FTP listing did not complete");
  Expect(result.body == "custom-entry\n",
         "custom FTP listing did not receive its passive payload");
  Expect(result.transcript.find("X-LIST\r\n") != std::string::npos,
         "CURLOPT_CUSTOMREQUEST did not replace the listing command");
}

void TestExplicitEmptyCompletionExposesControlEof() {
  Scenario scenario;
  AddLoginAndPwdReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable(
      "229 Entering Extended Passive Mode (|||12345|)\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("213 4\r\n");
  control->add_on_readable("150 opening data\r\n");
  control->add_on_readable("");
  scenario.add_subsequent_connections()->set_initial_response("body");

  const FtpRunResult result = RunScenario(scenario, "ftp://ftp.test/file");
  Expect(result.code != CURLE_OK,
         "empty FTP completion was replaced by synthetic success");
  Expect(result.body == "body",
         "control EOF prevented the passive body from being delivered");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestEpsvDownloadAndFinalReply();
  TestEpsvFailureFallsBackToPasv();
  TestUploadIsDrainedWithoutLosingControlChannel();
  TestCustomListingCommandReceivesPassiveData();
  TestExplicitEmptyCompletionExposesControlEof();
  curl_global_cleanup();
  return 0;
}
