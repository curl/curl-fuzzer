/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/h2_plan.h"

namespace {

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

std::uint32_t FrameStream(const std::string &frame) {
  if (frame.size() < 9) {
    return 0;
  }
  const auto *bytes = reinterpret_cast<const unsigned char *>(frame.data());
  return ((static_cast<std::uint32_t>(bytes[5]) << 24U) |
          (static_cast<std::uint32_t>(bytes[6]) << 16U) |
          (static_cast<std::uint32_t>(bytes[7]) << 8U) |
          static_cast<std::uint32_t>(bytes[8])) &
         0x7fffffffU;
}

void TestStructuredFramesFollowObservedRequest() {
  curl::fuzzer::proto::Http2Plan plan;
  auto *setting = plan.mutable_initial_settings()->add_entries();
  setting->set_identifier(4);
  setting->set_value(0);

  auto *wait = plan.add_actions()->mutable_wait();
  wait->set_event(curl::fuzzer::proto::HTTP2_CLIENT_EVENT_HEADERS);
  wait->mutable_stream()->set_request_index(0);

  auto *headers = plan.add_actions()->mutable_headers();
  headers->mutable_stream()->set_request_index(0);
  headers->set_status_code(204);

  auto *data = plan.add_actions()->mutable_data();
  data->mutable_stream()->set_request_index(0);
  data->set_data("body");
  data->set_end_stream(true);

  auto *wire = plan.add_actions()->mutable_wire_frame();
  wire->set_type(255);
  wire->set_flags(255);
  wire->set_stream_id(7);
  wire->set_payload("abc");
  wire->set_declared_length(1);
  wire->set_use_declared_length(true);

  proto_fuzzer::H2PlanDriver driver;
  driver.Reset(plan, "http", "h2.test");
  std::string output;
  Expect(driver.NextChunk(&output) && output.size() == 15 &&
             static_cast<unsigned char>(output[2]) == 6 &&
             static_cast<unsigned char>(output[3]) == 4 &&
             static_cast<unsigned char>(output[10]) == 4,
         "initial SETTINGS did not preserve the configured upload window");

  const std::string client =
      std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) +
      std::string("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9) +
      std::string("\x00\x00\x00\x01\x04\x00\x00\x00\x03", 9);
  driver.ObserveIncomingData(
      reinterpret_cast<const unsigned char *>(client.data()), client.size());
  Expect(driver.observed_client_settings_count() == 1 &&
             driver.observed_request_count() == 1,
         "client frame tracker missed SETTINGS or request HEADERS");

  Expect(driver.NextChunk(&output) && output.size() == 9 &&
             static_cast<unsigned char>(output[3]) == 4 &&
             static_cast<unsigned char>(output[4]) == 1,
         "client SETTINGS did not release the automatic ACK");
  Expect(driver.NextChunk(&output) && output.empty(),
         "satisfied request barrier did not advance exactly one action");
  Expect(driver.NextChunk(&output) && output.size() >= 10 &&
             static_cast<unsigned char>(output[3]) == 1 &&
             FrameStream(output) == 3,
         "symbolic response HEADERS did not follow observed stream 3");
  Expect(driver.NextChunk(&output) && output.size() == 13 &&
             static_cast<unsigned char>(output[3]) == 0 &&
             static_cast<unsigned char>(output[4]) == 1 &&
             FrameStream(output) == 3 && output.substr(9) == "body",
         "symbolic DATA did not end observed stream 3");
  Expect(driver.NextChunk(&output) && output.size() == 12 &&
             static_cast<unsigned char>(output[2]) == 1 &&
             static_cast<unsigned char>(output[3]) == 255 &&
             static_cast<unsigned char>(output[4]) == 255 &&
             FrameStream(output) == 7 && output.substr(9) == "abc",
         "wire-frame escape did not retain its declared-length mismatch");
  Expect(!driver.has_pending_work(),
         "completed structured plan still reported pending work");
}

void TestYieldCountIsBoundedByDriver() {
  curl::fuzzer::proto::Http2Plan plan;
  plan.add_actions()->set_yield_turns(1000);
  proto_fuzzer::H2PlanDriver driver;
  driver.Reset(plan);
  std::string output;
  Expect(driver.NextChunk(&output), "driver did not emit initial SETTINGS");
  const std::string client =
      std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) +
      std::string("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9);
  driver.ObserveIncomingData(
      reinterpret_cast<const unsigned char *>(client.data()), client.size());
  Expect(driver.NextChunk(&output), "driver did not ACK client SETTINGS");
  std::size_t turns = 0;
  while (driver.has_pending_work() && turns < 100) {
    Expect(driver.NextChunk(&output), "yield action unexpectedly stalled");
    ++turns;
  }
  Expect(turns == 16, "runtime did not cap an excessive H2 yield count");
}

} // namespace

int main() {
  TestStructuredFramesFollowObservedRequest();
  TestYieldCountIsBoundedByDriver();
  return 0;
}
