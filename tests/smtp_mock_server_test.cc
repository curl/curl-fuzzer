/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/allocation_fault_injection.h"
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
  std::size_t writable_pollset_probes = 0;
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

  proto_fuzzer::SmtpMockServer server(scenario.smtp_probe_mode());
  server.Install(easy.get());
  server.ConfigureClient(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.control_transcript();
  result.uploaded = server.uploaded_data();
  result.active_pollset_probes = server.active_pollset_probe_count();
  result.writable_pollset_probes = server.writable_pollset_probe_count();

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
  Expect(result.writable_pollset_probes == 0,
         "ordinary SMTP upload looked like a pending control-command send");
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

void TestRecipientFailureCanReachRejectedPostBodyReply() {
  Scenario scenario;
  AddMailEnvelope(&scenario);
  scenario.add_mail_rcpt("accepted@example.test");
  AddBoolOption(&scenario, curl::fuzzer::proto::CURLOPT_MAIL_RCPT_ALLOWFAILS,
                true);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250 smtp.test\r\n");
  connection->add_on_readable("250 sender accepted\r\n");
  connection->add_on_readable("550 first recipient rejected\r\n");
  connection->add_on_readable("250 second recipient accepted\r\n");
  connection->add_on_readable("354 send the message\r\n");
  connection->add_on_readable("550 message rejected after body\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/allowfails.test");
  Expect(result.code == CURLE_WEIRD_SERVER_REPLY,
         "SMTP post-body rejection returned the wrong transfer error");
  Expect(result.transcript.find("RCPT TO:<recipient@example.test>\r\n") !=
                 std::string::npos &&
             result.transcript.find("RCPT TO:<accepted@example.test>\r\n") !=
                 std::string::npos &&
             result.transcript.find("DATA\r\n") != std::string::npos,
         "SMTP recipient-failure scenario did not reach DATA");
  Expect(result.uploaded == kEscapedMailBody,
         "SMTP post-body rejection did not drain the complete message");
  Expect(result.transcript.find("QUIT\r\n") != std::string::npos,
         "SMTP post-body rejection did not tear down with QUIT");
}

Scenario StartTlsScenario(curl::fuzzer::proto::SmtpProbeMode mode,
                          std::string_view reply) {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  scenario.set_host_path("smtp.test/starttls.test");
  scenario.set_smtp_probe_mode(mode);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250-smtp.test\r\n250 STARTTLS\r\n");
  connection->add_on_readable(std::string(reply));
  return scenario;
}

void TestRequiredStartTlsReachesBoundedHandshakeEof() {
  Scenario scenario = StartTlsScenario(
      curl::fuzzer::proto::SMTP_PROBE_STARTTLS_REQUIRE, "220 begin TLS\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/starttls.test");
  Expect(result.code != CURLE_OK,
         "bounded SMTP STARTTLS EOF unexpectedly completed a handshake");
  ExpectTranscript(result, "EHLO starttls.test\r\nSTARTTLS\r\n",
                   "SMTP STARTTLS acceptance did not stop plaintext parsing");
}

void TestTryStartTlsDenialFallsBackToPlaintext() {
  Scenario scenario =
      StartTlsScenario(curl::fuzzer::proto::SMTP_PROBE_STARTTLS_TRY,
                       "454 TLS temporarily unavailable\r\n");
  scenario.mutable_connection()->add_on_readable("214 smtp.test help\r\n");
  scenario.mutable_connection()->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/starttls.test");
  Expect(result.code == CURLE_OK,
         "optional SMTP STARTTLS denial did not fall back to plaintext");
  ExpectTranscript(result,
                   "EHLO starttls.test\r\n"
                   "STARTTLS\r\n"
                   "HELP\r\n"
                   "QUIT\r\n",
                   "optional SMTP STARTTLS fallback transcript was wrong");
}

void TestTryStartTlsWithoutCapabilityFallsBackToPlaintext() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  scenario.set_smtp_probe_mode(curl::fuzzer::proto::SMTP_PROBE_STARTTLS_TRY);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250 smtp.test\r\n");
  connection->add_on_readable("214 smtp.test help\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/starttls-unsupported.test");
  Expect(result.code == CURLE_OK,
         "optional SMTP without STARTTLS did not continue in plaintext");
  ExpectTranscript(result,
                   "EHLO starttls-unsupported.test\r\n"
                   "HELP\r\n"
                   "QUIT\r\n",
                   "SMTP without a STARTTLS capability issued the wrong "
                   "commands");
}

void TestRequiredStartTlsDenialFailsTransfer() {
  Scenario scenario =
      StartTlsScenario(curl::fuzzer::proto::SMTP_PROBE_STARTTLS_REQUIRE,
                       "454 TLS unavailable\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/starttls.test");
  Expect(result.code == CURLE_USE_SSL_FAILED,
         "required SMTP STARTTLS denial returned the wrong error");
  Expect(result.transcript.find("STARTTLS\r\n") != std::string::npos,
         "required SMTP STARTTLS denial never issued STARTTLS");
}

void TestRequiredStartTlsDoesNotFallBackToHelo() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  scenario.set_smtp_probe_mode(
      curl::fuzzer::proto::SMTP_PROBE_STARTTLS_REQUIRE);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("500 EHLO unavailable\r\n");

  const SmtpRunResult result = RunScenario(
      scenario, "smtp://smtp.test/starttls-required-ehlo-denied.test");
  Expect(result.code == CURLE_REMOTE_ACCESS_DENIED,
         "required SMTP STARTTLS EHLO rejection returned the wrong error");
  Expect(result.transcript.find(
             "EHLO starttls-required-ehlo-denied.test\r\n") !=
             std::string::npos,
         "required SMTP STARTTLS never issued EHLO");
  Expect(result.transcript.find("HELO ") == std::string::npos &&
             result.transcript.find("STARTTLS\r\n") == std::string::npos,
         "required SMTP STARTTLS incorrectly fell back after EHLO rejection");
}

void TestRequiredStartTlsWithoutCapabilityFailsTransfer() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  scenario.set_smtp_probe_mode(
      curl::fuzzer::proto::SMTP_PROBE_STARTTLS_REQUIRE);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250 smtp.test\r\n");

  const SmtpRunResult result = RunScenario(
      scenario, "smtp://smtp.test/starttls-required-unsupported.test");
  Expect(result.code == CURLE_USE_SSL_FAILED,
         "required SMTP without STARTTLS returned the wrong error");
  Expect(result.transcript.find(
             "EHLO starttls-required-unsupported.test\r\n") !=
             std::string::npos,
         "required SMTP without STARTTLS never issued EHLO");
  Expect(result.transcript.find("STARTTLS\r\n") == std::string::npos &&
             result.transcript.find("HELP\r\n") == std::string::npos,
         "required SMTP without STARTTLS continued in plaintext");
}

void TestStartTlsResponseOverflowIsRejected() {
  Scenario scenario =
      StartTlsScenario(curl::fuzzer::proto::SMTP_PROBE_STARTTLS_REQUIRE,
                       "220 begin TLS\r\n250 pipelined reply\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/starttls.test");
  Expect(result.code == CURLE_WEIRD_SERVER_REPLY,
         "pipelined SMTP STARTTLS reply was not rejected");
}

void TestStartTlsArmsAdjacentFilterAllocationFailure() {
  proto_fuzzer::allocation_fault_injection::Reset();
  Scenario scenario = StartTlsScenario(
      curl::fuzzer::proto::SMTP_PROBE_STARTTLS_FILTER_ALLOCATION_FAILURE,
      "220 begin TLS\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/starttls.test");
  const auto statistics =
      proto_fuzzer::allocation_fault_injection::GetStatistics();
  Expect(result.code == CURLE_OUT_OF_MEMORY,
         "SMTP STARTTLS filter allocation failure did not reach curl");
  Expect(statistics.configured_failures == 1 &&
             statistics.injected_failures == 1 &&
             statistics.allocation_attempts >= 1,
         "SMTP STARTTLS semantic arm did not reject exactly one allocation");
  proto_fuzzer::allocation_fault_injection::Reset();
}

void TestSmtpUtf8AndSizeEnvelope() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  auto *upload = scenario.add_options();
  upload->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload->set_bool_value(true);
  auto *size = scenario.add_options();
  size->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  size->set_uint_value(sizeof(kMailBody) - 1);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_MAIL_FROM, "sender");
  scenario.add_mail_rcpt("r\xc3\xa9"
                         "cipient@example.test");
  scenario.mutable_upload()->set_data(kMailBody);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250-SIZE 4096\r\n250 SMTPUTF8\r\n");
  connection->add_on_readable("250 sender accepted\r\n");
  connection->add_on_readable("250 recipient accepted\r\n");
  connection->add_on_readable("354 send the message\r\n");
  connection->add_on_readable("250 message queued\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/utf8.test");
  Expect(result.code == CURLE_OK, "SMTPUTF8 upload did not complete");
  const std::size_t mail = result.transcript.find("MAIL FROM:<sender> SIZE=");
  Expect(mail != std::string::npos &&
             result.transcript.find(" SMTPUTF8\r\n", mail) != std::string::npos,
         "SMTPUTF8 upload omitted SIZE or SMTPUTF8 from MAIL FROM");
}

void TestLocalOnlyVrfyMailbox() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  scenario.add_mail_rcpt("local");
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250-SIZE 4096\r\n250 SMTPUTF8\r\n");
  connection->add_on_readable("250 local mailbox exists\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/vrfy.test");
  Expect(result.code == CURLE_OK, "local-only SMTP VRFY did not complete");
  ExpectTranscript(result, "EHLO vrfy.test\r\nVRFY local\r\nQUIT\r\n",
                   "local-only SMTP VRFY transcript was wrong");
}

void TestSendBackpressureFlushesFixedCommand() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_SMTP);
  scenario.set_smtp_probe_mode(
      curl::fuzzer::proto::SMTP_PROBE_SEND_BACKPRESSURE);
  scenario.set_probe_multi_pollset(true);
  auto *backpressure = scenario.mutable_connection()->mutable_backpressure();
  backpressure->set_recv_buf_bytes(2048);
  backpressure->set_drain_limit(1024);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("220 smtp.test ESMTP fuzz peer\r\n");
  connection->add_on_readable("250 smtp.test\r\n");
  connection->add_on_readable("250 command accepted\r\n");
  connection->add_on_readable("221 bye\r\n");

  const SmtpRunResult result =
      RunScenario(scenario, "smtp://smtp.test/pressure.test");
  Expect(result.code == CURLE_OK,
         "SMTP send-backpressure probe did not complete");
  Expect(result.transcript.size() >= 16 * 1024 &&
             result.transcript.find("NOOP ") != std::string::npos,
         "SMTP send-backpressure probe lost the fixed command");
  Expect(result.writable_pollset_probes != 0,
         "SMTP send-backpressure probe never left a protocol write pending");
  Expect(result.active_pollset_probes > 1,
         "SMTP send-backpressure probe did not span writable pollsets");
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
  Expect(proto_fuzzer::allocation_fault_injection::InitializeCurl(),
         "SMTP tests could not install allocation callbacks");
  TestMailUploadDrainsBody();
  TestDataRejectionDoesNotEnterBodyMode();
  TestRecipientFailureCanReachRejectedPostBodyReply();
  TestRequiredStartTlsReachesBoundedHandshakeEof();
  TestTryStartTlsDenialFallsBackToPlaintext();
  TestTryStartTlsWithoutCapabilityFallsBackToPlaintext();
  TestRequiredStartTlsDenialFailsTransfer();
  TestRequiredStartTlsDoesNotFallBackToHelo();
  TestRequiredStartTlsWithoutCapabilityFailsTransfer();
  TestStartTlsResponseOverflowIsRejected();
  TestStartTlsArmsAdjacentFilterAllocationFailure();
  TestSmtpUtf8AndSizeEnvelope();
  TestLocalOnlyVrfyMailbox();
  TestSendBackpressureFlushesFixedCommand();
  TestCramMd5AuthenticationAndMailUpload();
  TestInvalidCramChallengeFallsBackToPlain();
  TestPlainAuthenticationUsesSaslInitialResponse();
  TestEhloRejectionFallsBackToHelo();
  TestNoUploadCustomExpnCommand();
  TestUnavailableScramMechanismIsRejected();
  proto_fuzzer::allocation_fault_injection::Reset();
  curl_global_cleanup();
  return 0;
}
