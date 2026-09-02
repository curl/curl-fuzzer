/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <string>
#include <vector>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/tftp_mock_server.h"

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

std::string Packet(std::uint16_t opcode, std::uint16_t value,
                   const std::string &payload = {}) {
  std::string packet;
  packet.push_back(static_cast<char>(opcode >> 8));
  packet.push_back(static_cast<char>(opcode));
  packet.push_back(static_cast<char>(value >> 8));
  packet.push_back(static_cast<char>(value));
  packet += payload;
  return packet;
}

std::string OptionAck(std::initializer_list<const char *> values) {
  std::string packet("\0\x06", 2);
  for (const char *value : values) {
    packet += value;
    packet.push_back('\0');
  }
  return packet;
}

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

struct TftpRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::vector<proto_fuzzer::TftpReceivedDatagram> received;
  std::uint16_t request_port = 0;
  std::uint16_t transfer_port = 0;
};

TftpRunResult RunScenario(const Scenario &scenario) {
  TftpRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_TFTP));
  Expect(connect_to != nullptr,
         "TFTP baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, "tftp://tftp.test/file") ==
             CURLE_OK,
         "TFTP URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "TFTP write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "TFTP write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::TftpMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.received = server.received_datagrams();
  result.request_port = server.request_port();
  result.transfer_port = server.transfer_port();

  // Pointer-valued baseline options must outlive easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void TestOackDownloadUsesTransferId() {
  Scenario scenario;
  auto *blksize = scenario.add_options();
  blksize->set_option_id(curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE);
  blksize->set_uint_value(8);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response(OptionAck({"blksize", "8"}));
  connection->add_on_readable(Packet(3, 1, "abcdefgh"));
  connection->add_on_readable(Packet(3, 2, "ijk"));

  const TftpRunResult result = RunScenario(scenario);
  Expect(result.code == CURLE_OK, "OACK TFTP download did not complete");
  Expect(result.body == "abcdefghijk",
         "OACK TFTP download produced the wrong body");
  Expect(result.request_port != 0 && result.transfer_port != 0 &&
             result.request_port != result.transfer_port,
         "TFTP request and transfer endpoints did not use distinct IDs");
  Expect(result.received.size() >= 3,
         "TFTP peer did not capture RRQ and acknowledgements");
  Expect(result.received[0].received_on ==
             proto_fuzzer::TftpSocketRole::kRequest,
         "initial RRQ did not reach the request endpoint");
  Expect(result.received[1].received_on ==
             proto_fuzzer::TftpSocketRole::kTransfer,
         "ACK0 did not follow the response transfer ID");
  Expect(result.received[1].bytes == Packet(4, 0),
         "curl did not acknowledge the OACK with ACK0");
  Expect(result.received[2].bytes == Packet(4, 1),
         "curl did not acknowledge DATA1");
}

void TestNoOptionsRequestAndErrorMapping() {
  Scenario request;
  auto *no_options = request.add_options();
  no_options->set_option_id(curl::fuzzer::proto::CURLOPT_TFTP_NO_OPTIONS);
  no_options->set_bool_value(true);
  request.mutable_connection()->set_initial_response(Packet(3, 1, "ok"));

  const TftpRunResult success = RunScenario(request);
  Expect(success.code == CURLE_OK, "no-options TFTP download did not complete");
  Expect(!success.received.empty(), "no-options TFTP peer did not capture RRQ");
  Expect(success.received[0].bytes.find("blksize") == std::string::npos,
         "CURLOPT_TFTP_NO_OPTIONS still emitted blksize");
  Expect(success.received[0].bytes.find("tsize") == std::string::npos,
         "CURLOPT_TFTP_NO_OPTIONS still emitted tsize");

  Scenario error;
  error.mutable_connection()->set_initial_response(
      Packet(5, 1, std::string("missing\0", 8)));
  const TftpRunResult missing = RunScenario(error);
  Expect(missing.code == CURLE_TFTP_NOTFOUND,
         "TFTP ERROR 1 did not map to CURLE_TFTP_NOTFOUND");
}

void TestExactBlockUploadSendsTerminalPacket() {
  Scenario scenario;
  auto *upload = scenario.add_options();
  upload->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload->set_bool_value(true);
  auto *size = scenario.add_options();
  size->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  size->set_uint_value(8);
  auto *blksize = scenario.add_options();
  blksize->set_option_id(curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE);
  blksize->set_uint_value(8);
  scenario.mutable_upload()->set_data("12345678");
  scenario.mutable_connection()->set_initial_response(
      OptionAck({"blksize", "8", "tsize", "8"}));
  scenario.mutable_connection()->add_on_readable(Packet(4, 1));
  scenario.mutable_connection()->add_on_readable(Packet(4, 2));

  const TftpRunResult result = RunScenario(scenario);
  Expect(result.code == CURLE_OK, "exact-block TFTP upload did not complete");
  Expect(result.received.size() >= 3,
         "TFTP peer did not capture WRQ and both DATA packets");
  Expect(result.received[1].bytes == Packet(3, 1, "12345678"),
         "TFTP DATA1 did not contain the upload body");
  Expect(result.received[2].bytes == Packet(3, 2),
         "TFTP exact-block upload omitted terminal DATA2");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestOackDownloadUsesTransferId();
  TestNoOptionsRequestAndErrorMapping();
  TestExactBlockUploadSendsTerminalPacket();
  curl_global_cleanup();
  return 0;
}
