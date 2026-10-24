/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/mqtt_mock_server.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::CurlEasyPtr;
using proto_fuzzer::CurlSlistPtr;
using test_support::Expect;
using test_support::Fail;

constexpr char kTopic[] = "sensors/kitchen";
constexpr char kPayload[] = "hello mqtt";

// CONNACK: fixed header 0x20, remaining length 2, session-present 0, rc 0.
// Keep the explicit length: an embedded NUL would truncate a C-string copy.
const std::string kAcceptedConnack("\x20\x02\x00\x00", 4);

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

std::string ServerPublish(const std::string &topic, const std::string &payload) {
  std::string body;
  body.push_back(static_cast<char>((topic.size() >> 8U) & 0xffU));
  body.push_back(static_cast<char>(topic.size() & 0xffU));
  body.append(topic);
  body.append(payload);

  std::string packet;
  packet.push_back(static_cast<char>(0x30));
  // Both seed-sized topics and payloads keep the remaining length below the
  // one-byte base-128 limit.
  Expect(body.size() < 128, "test server PUBLISH needs a longer encoding");
  packet.push_back(static_cast<char>(body.size()));
  packet.append(body);
  return packet;
}

struct MqttRunResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string body;
  std::string transcript;
  std::string topic;
  std::string payload;
  std::size_t packets = 0;
  std::size_t connects = 0;
  std::size_t publishes = 0;
  std::size_t subscribes = 0;
  std::size_t qos1_publishes = 0;
  std::size_t active_pollset_probes = 0;
};

MqttRunResult RunScenario(const Scenario &scenario, const char *url) {
  MqttRunResult result;
  CurlEasyPtr easy(curl_easy_init());
  Expect(easy != nullptr, "curl_easy_init failed");
  CurlSlistPtr connect_to(proto_fuzzer::ApplyBaselineOptions(
      easy.get(), curl::fuzzer::proto::SCHEME_MQTT));
  Expect(connect_to != nullptr,
         "MQTT baseline did not create CONNECT_TO state");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_URL, url) == CURLE_OK,
         "MQTT URL setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEFUNCTION,
                          &CollectResponse) == CURLE_OK,
         "MQTT write callback setup failed");
  Expect(curl_easy_setopt(easy.get(), CURLOPT_WRITEDATA, &result.body) ==
             CURLE_OK,
         "MQTT write data setup failed");
  (void)proto_fuzzer::ApplyScenarioOptions(easy.get(), scenario);

  proto_fuzzer::MqttMockServer server;
  server.Install(easy.get());
  {
    proto_fuzzer::ScenarioRequestData request_data(easy.get(), scenario);
    result.code = server.DriveScenario(easy.get(), scenario);
  }
  result.transcript = server.packet_transcript();
  result.topic = server.published_topic();
  result.payload = server.published_payload();
  result.packets = server.packet_count();
  result.connects = server.connect_count();
  result.publishes = server.publish_count();
  result.subscribes = server.subscribe_count();
  result.qos1_publishes = server.qos1_publish_count();
  result.active_pollset_probes = server.active_pollset_probe_count();

  // CONNECT_TO storage must remain valid through easy cleanup.
  easy.reset();
  connect_to.reset();
  return result;
}

void TestPublishSendsConnectAndDisconnect() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_MQTT);
  auto *fields = scenario.add_options();
  fields->set_option_id(curl::fuzzer::proto::CURLOPT_POSTFIELDS);
  fields->set_string_value(kPayload);
  auto *username = scenario.add_options();
  username->set_option_id(curl::fuzzer::proto::CURLOPT_USERNAME);
  username->set_string_value("fuzz");
  auto *password = scenario.add_options();
  password->set_option_id(curl::fuzzer::proto::CURLOPT_PASSWORD);
  password->set_string_value("secret");
  scenario.mutable_connection()->set_initial_response(kAcceptedConnack);

  const MqttRunResult result =
      RunScenario(scenario, "mqtt://mqtt.test/sensors/kitchen");
  Expect(result.code == CURLE_OK, "MQTT publish did not complete");
  Expect(result.connects == 1 && result.publishes == 1 &&
             result.subscribes == 0,
         "MQTT publish sent the wrong packet sequence");
  Expect(result.qos1_publishes == 0,
         "current curl unexpectedly emitted a QoS 1 PUBLISH");
  Expect(result.packets == 3,
         "MQTT publish did not send CONNECT, PUBLISH, and DISCONNECT");
  Expect(result.topic == kTopic,
         "MQTT peer parsed the wrong publish topic");
  Expect(result.payload == kPayload,
         "MQTT peer parsed the wrong publish payload");
  Expect(result.transcript.find(kTopic) != std::string::npos,
         "MQTT packet transcript lost the topic bytes");
}

void TestPublishProbesLivePollsetWhenRequested() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_MQTT);
  scenario.set_probe_multi_pollset(true);
  auto *fields = scenario.add_options();
  fields->set_option_id(curl::fuzzer::proto::CURLOPT_POSTFIELDS);
  fields->set_string_value(kPayload);
  scenario.mutable_connection()->set_initial_response(kAcceptedConnack);

  const MqttRunResult result =
      RunScenario(scenario, "mqtt://mqtt.test/sensors/kitchen");
  Expect(result.code == CURLE_OK, "MQTT pollset scenario did not complete");
  Expect(result.active_pollset_probes != 0,
         "MQTT opt-in did not probe a live protocol pollset");
}

void TestSubscribeDeliversServerPublish() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_MQTT);
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response(kAcceptedConnack);
  connection->add_on_readable(ServerPublish(kTopic, kPayload));
  // A server DISCONNECT ends curl's subscribe wait successfully instead of
  // letting the final half-close look like a truncated packet.
  connection->add_on_readable(std::string("\xe0\x00", 2));

  const MqttRunResult result = RunScenario(
      scenario, "mqtt://mqtt.test/sensors/kitchen");
  Expect(result.code == CURLE_OK,
         "MQTT subscribe did not complete after server DISCONNECT");
  Expect(result.connects == 1 && result.subscribes == 1 &&
             result.publishes == 0,
         "MQTT subscribe sent the wrong packet sequence");
  Expect(result.packets == 2,
         "MQTT subscribe unexpectedly sent a client DISCONNECT");
  // curl's MQTT reader forwards the complete PUBLISH remaining-length body,
  // including the two-byte topic length and topic, to the write callback.
  const std::string expected_body =
      std::string("\x00\x0f", 2) + std::string(kTopic) + std::string(kPayload);
  Expect(result.body == expected_body,
         "MQTT subscribe forwarded the wrong PUBLISH body");
  Expect(result.transcript.find("sensors/kitchen") != std::string::npos,
         "MQTT subscribe transcript lost the SUBSCRIBE topic");
  Expect(result.active_pollset_probes == 0,
         "MQTT default path unexpectedly issued a pollset probe");
}

void TestRejectedConnackStopsBeforePublish() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_MQTT);
  auto *fields = scenario.add_options();
  fields->set_option_id(curl::fuzzer::proto::CURLOPT_POSTFIELDS);
  fields->set_string_value("never sent");
  // CONNACK: fixed header 0x20, remaining length 2, session-present 0,
  // return code 5 ("not authorized").
  scenario.mutable_connection()->set_initial_response(
      std::string("\x20\x02\x00\x05", 4));

  const MqttRunResult result =
      RunScenario(scenario, "mqtt://mqtt.test/sensors/rejected");
  Expect(result.code != CURLE_OK,
         "rejected MQTT CONNACK unexpectedly completed the transfer");
  Expect(result.connects == 1 && result.publishes == 0 &&
             result.subscribes == 0,
         "MQTT transfer continued after a rejected CONNACK");
  Expect(result.packets == 1,
         "MQTT transfer sent packets after a rejected CONNACK");
}

} // namespace

int main() {
  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    Fail("curl_global_init failed");
  }
  TestPublishSendsConnectAndDisconnect();
  TestPublishProbesLivePollsetWhenRequested();
  TestSubscribeDeliversServerPublish();
  TestRejectedConnackStopsBeforePublish();
  curl_global_cleanup();
  return 0;
}
