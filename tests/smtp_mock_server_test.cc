/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/smtp_mock_server.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kMailBody[] =
    "Subject: fuzz\r\n\r\nfirst line\r\n.leading dot\r\nlast line\r\n";
constexpr char kEscapedMailBody[] =
    "Subject: fuzz\r\n\r\nfirst line\r\n..leading dot\r\nlast line\r\n.\r\n";

struct SmtpRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string transcript;
  std::string uploaded;
};

SmtpRunResult RunScenario(const Scenario &scenario, const char *url) {
  SmtpRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_SMTP));
  Expect(connect_to != nullptr,
         "SMTP baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "SMTP URL setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::SmtpMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.uploaded = server.uploaded_data();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void AddMailEnvelope(Scenario *scenario) {
  scenario->set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  auto *upload = scenario->add_options();
  upload->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload->set_bool_value(true);
  auto *size = scenario->add_options();
  size->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  size->set_uint_value(sizeof(kMailBody) - 1);
  auto *from = scenario->add_options();
  from->set_option_id(curl::fuzzer::proto::CURLOPT_MAIL_FROM);
  from->set_string_value("sender@example.test");
  scenario->add_mail_rcpt("recipient@example.test");
  scenario->mutable_upload()->set_data(kMailBody);
  scenario->mutable_upload()->add_read_sizes(7);
  scenario->mutable_upload()->add_read_sizes(11);
  scenario->mutable_upload()->add_read_sizes(9);
}

void AddSuccessfulReplies(Scenario *scenario) {
  auto *connection = scenario->mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250-smtp.test\r\n250 8BITMIME\r\n");
  connection->add_on_readable("250 sender accepted\r\n");
  connection->add_on_readable("250 recipient accepted\r\n");
  connection->add_on_readable("354 send the message\r\n");
  connection->add_on_readable("250 message queued\r\n");
  connection->add_on_readable("221 bye\r\n");
}

void TestMailUploadDrainsBody() {
  Scenario scenario;
  AddMailEnvelope(&scenario);
  AddSuccessfulReplies(&scenario);

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/fuzz.test");
  Expect(result.code == CURLE_OK, "SMTP mail upload did not complete");
  Expect(result.transcript.find("EHLO fuzz.test\r\n") != std::string::npos,
         "SMTP transfer did not announce the URL path as its EHLO domain");
  Expect(result.transcript.find("MAIL FROM:<sender@example.test>\r\n") !=
             std::string::npos,
         "SMTP transfer did not issue the configured MAIL FROM envelope");
  Expect(result.transcript.find("RCPT TO:<recipient@example.test>\r\n") !=
             std::string::npos,
         "SMTP transfer did not issue the schema-native RCPT TO envelope");
  Expect(result.transcript.find("DATA\r\n") != std::string::npos,
         "SMTP transfer did not enter the DATA phase");
  Expect(result.uploaded == kEscapedMailBody,
         "SMTP peer did not drain the complete dot-stuffed body and EOB");
}

void TestDataRejectionDoesNotEnterBodyMode() {
  Scenario scenario;
  AddMailEnvelope(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250 smtp.test\r\n");
  connection->add_on_readable("250 sender accepted\r\n");
  connection->add_on_readable("250 recipient accepted\r\n");
  connection->add_on_readable("550 data rejected\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/rejected.test");
  Expect(result.code != CURLE_OK,
         "rejected SMTP DATA unexpectedly completed the transfer");
  Expect(result.transcript.find("DATA\r\n") != std::string::npos,
         "rejected SMTP DATA was never issued");
  Expect(result.transcript.find("QUIT\r\n") != std::string::npos,
         "SMTP error teardown did not issue QUIT");
  Expect(result.uploaded.empty(),
         "SMTP peer treated command bytes as message body after DATA failed");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestMailUploadDrainsBody();
  TestDataRejectionDoesNotEnterBodyMode();
  curl_global_cleanup();
  return 0;
}
