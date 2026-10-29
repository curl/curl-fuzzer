/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <string>
#include <string_view>

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
  std::string body;
  std::string transcript;
  std::string uploaded;
  std::size_t active_pollset_probes = 0;
};

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

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
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "SMTP write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "SMTP write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::SmtpMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.uploaded = server.uploaded_data();
  result.active_pollset_probes = server.active_pollset_probe_count();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void AddLoginOptions(Scenario *scenario) {
  auto *username = scenario->add_options();
  username->set_option_id(curl::fuzzer::proto::CURLOPT_USERNAME);
  username->set_string_value("fuzz");
  auto *password = scenario->add_options();
  password->set_option_id(curl::fuzzer::proto::CURLOPT_PASSWORD);
  password->set_string_value("secret");
}

void AddStringOption(Scenario *scenario,
                     curl::fuzzer::proto::CurlOptionId option_id,
                     std::string_view value) {
  auto *option = scenario->add_options();
  option->set_option_id(option_id);
  option->set_string_value(std::string(value));
}

void AddBoolOption(Scenario *scenario,
                   curl::fuzzer::proto::CurlOptionId option_id, bool value) {
  auto *option = scenario->add_options();
  option->set_option_id(option_id);
  option->set_bool_value(value);
}

void ExpectTranscript(const SmtpRunResult &result, std::string_view expected,
                      const char *message) {
  Expect(result.transcript == expected, message);
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
  scenario.set_probe_multi_pollset(true);

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
  Expect(result.active_pollset_probes != 0,
         "SMTP opt-in did not probe a live protocol pollset");
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

void TestCramMd5AuthenticationAndMailUpload() {
  Scenario scenario;
  AddMailEnvelope(&scenario);
  AddLoginOptions(&scenario);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=CRAM-MD5");
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable(
      "250-smtp.test\r\n250-AUTH CRAM-MD5\r\n250 8BITMIME\r\n");
  connection->add_on_readable(
      "334 PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UuZXhhbXBsZS5uZXQ+\r\n");
  connection->add_on_readable("235 2.7.0 authentication succeeded\r\n");
  connection->add_on_readable("250 sender accepted\r\n");
  connection->add_on_readable("250 recipient accepted\r\n");
  connection->add_on_readable("354 send the message\r\n");
  connection->add_on_readable("250 message queued\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/cram.test");
  Expect(result.code == CURLE_OK, "SMTP CRAM-MD5 mail upload did not complete");
  ExpectTranscript(
      result,
      "EHLO cram.test\r\n"
      "AUTH CRAM-MD5\r\n"
      "ZnV6eiBhYmI3ZGU0OWM1OGRhMTQxNjg2NmJiYzU2NmI3ZTU4NQ==\r\n"
      "MAIL FROM:<sender@example.test>\r\n"
      "RCPT TO:<recipient@example.test>\r\n"
      "DATA\r\n"
      "QUIT\r\n",
      "SMTP CRAM-MD5 transcript differed from the complete auth and mail "
      "exchange");
  Expect(result.uploaded == kEscapedMailBody,
         "SMTP CRAM-MD5 transfer did not upload the complete message");
}

void TestInvalidCramChallengeFallsBackToPlain() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  AddLoginOptions(&scenario);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable(
      "250-smtp.test\r\n250-AUTH CRAM-MD5 PLAIN\r\n250 8BITMIME\r\n");
  connection->add_on_readable("334 !\r\n");
  connection->add_on_readable("501 authentication exchange cancelled\r\n");
  connection->add_on_readable("334 \r\n");
  connection->add_on_readable("235 2.7.0 authentication succeeded\r\n");
  connection->add_on_readable("214 smtp.test help\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/fallback.test");
  Expect(result.code == CURLE_OK,
         "SMTP did not fall back from malformed CRAM-MD5 to PLAIN");
  ExpectTranscript(
      result,
      "EHLO fallback.test\r\n"
      "AUTH CRAM-MD5\r\n"
      "*\r\n"
      "AUTH PLAIN\r\n"
      "AGZ1enoAc2VjcmV0\r\n"
      "HELP\r\n"
      "QUIT\r\n",
      "SMTP CRAM-MD5 fallback transcript was incomplete or out of order");
  Expect(result.body == "214 smtp.test help\r\n",
         "SMTP command after CRAM-MD5 fallback returned the wrong body");
}

void TestPlainAuthenticationUsesSaslInitialResponse() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  AddLoginOptions(&scenario);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=PLAIN");
  AddBoolOption(&scenario, curl::fuzzer::proto::CURLOPT_SASL_IR, true);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable(
      "250-smtp.test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n");
  connection->add_on_readable("235 2.7.0 authentication succeeded\r\n");
  connection->add_on_readable("214 smtp.test help\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/initial.test");
  Expect(result.code == CURLE_OK,
         "SMTP AUTH PLAIN with SASL-IR did not complete");
  ExpectTranscript(result,
                   "EHLO initial.test\r\n"
                   "AUTH PLAIN AGZ1enoAc2VjcmV0\r\n"
                   "HELP\r\n"
                   "QUIT\r\n",
                   "SMTP SASL-IR transcript did not keep the PLAIN payload "
                   "on the AUTH command");
}

void TestEhloRejectionFallsBackToHelo() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("500 EHLO unavailable\r\n");
  connection->add_on_readable("250 smtp.test greets client\r\n");
  connection->add_on_readable("214 smtp.test help\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/legacy.test");
  Expect(result.code == CURLE_OK,
         "SMTP did not recover from EHLO rejection with HELO");
  ExpectTranscript(result,
                   "EHLO legacy.test\r\n"
                   "HELO legacy.test\r\n"
                   "HELP\r\n"
                   "QUIT\r\n",
                   "SMTP EHLO fallback transcript was incomplete or out of "
                   "order");
  Expect(result.active_pollset_probes == 0,
         "SMTP default path unexpectedly issued a pollset probe");
}

void TestNoUploadCustomExpnCommand() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST,
                  "EXPN");
  scenario.add_mail_rcpt("list@example.test");
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250 smtp.test\r\n");
  connection->add_on_readable("250 member@example.test\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/command.test");
  Expect(result.code == CURLE_OK,
         "SMTP no-upload EXPN command did not complete");
  ExpectTranscript(result,
                   "EHLO command.test\r\n"
                   "EXPN list@example.test\r\n"
                   "QUIT\r\n",
                   "SMTP EXPN transcript was incomplete or out of order");
  Expect(result.body == "250 member@example.test\r\n",
         "SMTP EXPN response body was not delivered");
  Expect(result.uploaded.empty(),
         "SMTP no-upload EXPN command unexpectedly entered body mode");
}

void TestUnavailableScramMechanismIsRejected() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  AddLoginOptions(&scenario);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS,
                  "AUTH=SCRAM-SHA-256");
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable(
      "250-smtp.test\r\n250-AUTH SCRAM-SHA-256\r\n250 8BITMIME\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/unavailable.test");
  Expect(result.code == CURLE_LOGIN_DENIED,
         "SMTP unavailable SCRAM mechanism was not rejected");
  ExpectTranscript(result, "EHLO unavailable.test\r\n",
                   "SMTP unavailable-mechanism path issued an unexpected "
                   "AUTH or command");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestMailUploadDrainsBody();
  TestDataRejectionDoesNotEnterBodyMode();
  TestCramMd5AuthenticationAndMailUpload();
  TestInvalidCramChallengeFallsBackToPlain();
  TestPlainAuthenticationUsesSaslInitialResponse();
  TestEhloRejectionFallsBackToHelo();
  TestNoUploadCustomExpnCommand();
  TestUnavailableScramMechanismIsRejected();
  curl_global_cleanup();
  return 0;
}
