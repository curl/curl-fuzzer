/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/ftp_mock_server.h"
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

struct FtpRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  std::string uploaded;
  std::size_t data_connections = 0;
  std::size_t active_pollset_probes = 0;
};

void ExpectTranscript(const FtpRunResult &result, std::string_view expected,
                      const char *message) {
  if (result.transcript != expected) {
    std::cerr << message << "\nExpected:\n"
              << expected << "Actual:\n"
              << result.transcript;
    std::exit(1);
  }
}

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
  result.active_pollset_probes = server.active_pollset_probe_count();

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
  Expect(result.active_pollset_probes == 0,
         "FTP default path unexpectedly issued a pollset probe");
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

void TestMalformedEpsvFallsBackToPasv() {
  Scenario scenario;
  AddLoginAndPwdReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable("200 EPSV reply missing port tuple\r\n");
  control->add_on_readable("227 Entering Passive Mode (127,0,0,1,48,57)\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("213 13\r\n");
  control->add_on_readable("150 opening data\r\n");
  control->add_on_readable("226 complete\r\n");
  scenario.add_subsequent_connections()->set_initial_response("pasv-fallback");

  const FtpRunResult result =
      RunScenario(scenario, "ftp://ftp.test/malformed-epsv.bin");
  Expect(result.code == CURLE_OK, "malformed EPSV fallback did not complete");
  Expect(result.body == "pasv-fallback",
         "malformed EPSV fallback produced the wrong body");
  const std::size_t epsv = result.transcript.find("EPSV\r\n");
  const std::size_t pasv = result.transcript.find("PASV\r\n");
  Expect(epsv != std::string::npos && pasv != std::string::npos && epsv < pasv,
         "malformed EPSV response did not lead to a PASV retry");
}

void TestMalformed229EpsvIsTerminal() {
  Scenario scenario;
  AddLoginAndPwdReplies(&scenario);
  scenario.mutable_connection()->add_on_readable(
      "229 Entering Extended Passive Mode (||1025|)\r\n");

  const FtpRunResult result =
      RunScenario(scenario, "ftp://ftp.test/malformed-epsv-tuple.bin");
  Expect(result.code == CURLE_FTP_WEIRD_PASV_REPLY,
         "malformed EPSV tuple did not produce a malformed-reply error");
  Expect(result.transcript.find("EPSV\r\n") != std::string::npos,
         "malformed EPSV tuple scenario did not issue EPSV");
  Expect(
      result.transcript.find("PASV\r\n") == std::string::npos,
      "curl unexpectedly retried PASV after a malformed positive EPSV reply");
  Expect(result.data_connections == 0,
         "malformed EPSV tuple unexpectedly opened a data connection");
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

void AddWildcardListingReplies(Scenario *scenario) {
  AddLoginAndPwdReplies(scenario);
  auto *control = scenario->mutable_connection();
  control->add_on_readable("250 changed to pub\r\n");
  control->add_on_readable(
      "229 Entering Extended Passive Mode (|||12345|)\r\n");
  control->add_on_readable("200 ASCII type selected\r\n");
  control->add_on_readable("150 opening listing\r\n");
  control->add_on_readable("226 listing complete\r\n");
  control->add_on_readable(
      "229 Entering Extended Passive Mode (|||12346|)\r\n");
  control->add_on_readable("200 binary type selected\r\n");
  control->add_on_readable("150 opening match.txt\r\n");
  control->add_on_readable("226 file complete\r\n");

  auto *wildcard = scenario->add_options();
  wildcard->set_option_id(curl::fuzzer::proto::CURLOPT_WILDCARDMATCH);
  wildcard->set_bool_value(true);
}

void TestWildcardUnixSymlinkIsSkippedBeforeRegularMatch() {
  Scenario scenario;
  scenario.set_probe_multi_pollset(true);
  AddWildcardListingReplies(&scenario);
  scenario.add_subsequent_connections()->set_initial_response(
      "lrwxrwxrwx 1 ftp ftp 9 Apr 27 11:01 link.txt -> match.txt\r\n"
      "-rw-r--r-- 1 ftp ftp 5 Apr 27 11:01 match.txt\r\n");
  scenario.add_subsequent_connections()->set_initial_response("match");

  const FtpRunResult result = RunScenario(scenario, "ftp://ftp.test/pub/*.txt");
  Expect(result.code == CURLE_OK,
         "UNIX symlink wildcard listing did not complete");
  Expect(result.body == "match",
         "UNIX symlink listing did not retrieve the regular match");
  ExpectTranscript(result,
                   "USER anonymous\r\n"
                   "PASS ftp@example.com\r\n"
                   "PWD\r\n"
                   "CWD pub\r\n"
                   "EPSV\r\n"
                   "TYPE A\r\n"
                   "LIST\r\n"
                   "EPSV\r\n"
                   "TYPE I\r\n"
                   "RETR match.txt\r\n",
                   "UNIX symlink parser did not skip only the symlink");
  Expect(result.active_pollset_probes != 0,
         "FTP opt-in did not probe a live protocol pollset");
}

void TestWildcardWindowsListingRetrievesMatch() {
  Scenario scenario;
  AddWildcardListingReplies(&scenario);
  scenario.add_subsequent_connections()->set_initial_response(
      "04-27-26  11:01AM                  5 match.txt\r\n");
  scenario.add_subsequent_connections()->set_initial_response("match");

  const FtpRunResult result = RunScenario(scenario, "ftp://ftp.test/pub/*.txt");
  Expect(result.code == CURLE_OK, "Windows wildcard listing did not complete");
  Expect(result.body == "match",
         "Windows listing did not retrieve the matching file");
  ExpectTranscript(result,
                   "USER anonymous\r\n"
                   "PASS ftp@example.com\r\n"
                   "PWD\r\n"
                   "CWD pub\r\n"
                   "EPSV\r\n"
                   "TYPE A\r\n"
                   "LIST\r\n"
                   "EPSV\r\n"
                   "TYPE I\r\n"
                   "RETR match.txt\r\n",
                   "Windows parser did not drive the exact LIST/RETR flow");
  Expect(result.active_pollset_probes == 0,
         "FTP default wildcard path unexpectedly issued a pollset probe");
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

void AddActiveModeOptions(Scenario *scenario, bool use_eprt) {
  auto *ftp_port = scenario->add_options();
  ftp_port->set_option_id(curl::fuzzer::proto::CURLOPT_FTPPORT);
  ftp_port->set_string_value("127.0.0.1");
  auto *eprt = scenario->add_options();
  eprt->set_option_id(curl::fuzzer::proto::CURLOPT_FTP_USE_EPRT);
  eprt->set_bool_value(use_eprt);
}

void TestActiveDownload(bool use_eprt) {
  Scenario scenario;
  AddActiveModeOptions(&scenario, use_eprt);
  AddLoginAndPwdReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable(use_eprt ? "200 EPRT accepted\r\n"
                                    : "200 PORT accepted\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("213 11\r\n");
  control->add_on_readable("150 opening data\r\n");
  control->add_on_readable("226 complete\r\n");
  scenario.add_subsequent_connections()->set_initial_response("active-data");

  const FtpRunResult result =
      RunScenario(scenario, "ftp://ftp.test/active.bin");
  Expect(result.code == CURLE_OK, "active FTP download did not complete");
  Expect(result.body == "active-data",
         "active FTP download produced the wrong body");
  Expect(result.data_connections == 1,
         "active FTP download did not allocate one data channel");
  const char *verb = use_eprt ? "EPRT " : "PORT ";
  Expect(result.transcript.find(verb) != std::string::npos,
         "active FTP download used the wrong setup command");
}

void TestEprtFailureFallsBackToPort() {
  Scenario scenario;
  AddActiveModeOptions(&scenario, true);
  AddLoginAndPwdReplies(&scenario);
  auto *control = scenario.mutable_connection();
  control->add_on_readable("500 EPRT unsupported\r\n");
  control->add_on_readable("200 PORT accepted\r\n");
  control->add_on_readable("200 type set\r\n");
  control->add_on_readable("213 15\r\n");
  control->add_on_readable("150 opening data\r\n");
  control->add_on_readable("226 complete\r\n");
  scenario.add_subsequent_connections()->set_initial_response(
      "active-fallback");

  const FtpRunResult result =
      RunScenario(scenario, "ftp://ftp.test/eprt-port-fallback.bin");
  Expect(result.code == CURLE_OK, "EPRT-to-PORT fallback did not complete");
  Expect(result.body == "active-fallback",
         "EPRT-to-PORT fallback produced the wrong body");
  Expect(result.data_connections == 1,
         "EPRT-to-PORT fallback allocated the wrong number of data channels");
  const std::size_t eprt = result.transcript.find("EPRT ");
  const std::size_t port = result.transcript.find("PORT ");
  Expect(eprt != std::string::npos && port != std::string::npos && eprt < port,
         "EPRT rejection did not lead to a PORT retry");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestEpsvDownloadAndFinalReply();
  TestEpsvFailureFallsBackToPasv();
  TestMalformedEpsvFallsBackToPasv();
  TestMalformed229EpsvIsTerminal();
  TestUploadIsDrainedWithoutLosingControlChannel();
  TestCustomListingCommandReceivesPassiveData();
  TestWildcardUnixSymlinkIsSkippedBeforeRegularMatch();
  TestWildcardWindowsListingRetrievesMatch();
  TestExplicitEmptyCompletionExposesControlEof();
  TestActiveDownload(true);
  TestActiveDownload(false);
  TestEprtFailureFallsBackToPort();
  curl_global_cleanup();
  return 0;
}
