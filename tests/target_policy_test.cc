/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/target_policy.h"

#include "proto_fuzzer/scenario_limits.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>

namespace {

using curl::fuzzer::proto::Scenario;
using curl::fuzzer::proto::SCHEME_HTTP;
using curl::fuzzer::proto::SCHEME_HTTPS;
using curl::fuzzer::proto::SCHEME_UNSPECIFIED;
using curl::fuzzer::proto::SCHEME_WS;
using curl::fuzzer::proto::SCHEME_WSS;
using proto_fuzzer::ApplyTargetPolicy;
using proto_fuzzer::TargetPolicy;

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

Scenario ScenarioWithBackpressure(curl::fuzzer::proto::Scheme scheme,
                                  std::uint32_t recv_buf_bytes,
                                  std::uint32_t drain_limit) {
  Scenario scenario;
  scenario.set_scheme(scheme);
  scenario.mutable_connection()->set_initial_response("response sentinel");
  auto *backpressure = scenario.mutable_connection()->mutable_backpressure();
  backpressure->set_recv_buf_bytes(recv_buf_bytes);
  backpressure->set_drain_limit(drain_limit);
  return scenario;
}

void ExpectFixedPolicy(TargetPolicy policy,
                       curl::fuzzer::proto::Scheme expected_scheme,
                       const char *scheme_message,
                       const char *backpressure_message,
                       bool websocket_policy) {
  Scenario scenario = ScenarioWithBackpressure(
      SCHEME_UNSPECIFIED, std::numeric_limits<std::uint32_t>::max(), 17);
  auto *follow_on = scenario.add_subsequent_connections();
  follow_on->set_initial_response("follow-on sentinel");
  follow_on->mutable_backpressure()->set_recv_buf_bytes(2048);
  follow_on->mutable_backpressure()->set_drain_limit(1);
  scenario.mutable_mime_post()->add_parts()->set_data("mime sentinel");

  ApplyTargetPolicy(&scenario, policy);

  Expect(scenario.scheme() == expected_scheme, scheme_message);
  Expect(!scenario.connection().has_backpressure(), backpressure_message);
  Expect(scenario.connection().initial_response() == "response sentinel",
         "fixed policy changed fuzz-controlled connection data");
  if (websocket_policy) {
    Expect(scenario.subsequent_connections_size() == 0,
           "WebSocket policy retained ignored follow-on connections");
    Expect(!scenario.has_mime_post(),
           "WebSocket policy retained MIME that prevents a useful upgrade");
  } else {
    Expect(!scenario.subsequent_connections(0).has_backpressure(),
           "fixed policy retained follow-on backpressure");
    Expect(scenario.subsequent_connections(0).initial_response() ==
               "follow-on sentinel",
           "fixed policy changed a follow-on response script");
    Expect(scenario.has_mime_post(),
           "HTTP policy removed a request body curl can consume");
  }
}

void TestFastHttpPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_UNSPECIFIED, 4096, 17);
  scenario.add_request_headers("X-Fast: retained");
  scenario.mutable_connection()->add_on_readable("raw response sentinel");
  scenario.mutable_connection()->add_server_frames()->set_payload(
      "structured frame sentinel");
  scenario.mutable_connection()->mutable_manual_probes()->set_flag_matrix(true);
  scenario.add_subsequent_connections()->set_initial_response(
      "follow-on sentinel");
  scenario.mutable_mime_post()->add_parts()->set_data("mime sentinel");
  scenario.mutable_upload()->set_data("upload sentinel");

  ApplyTargetPolicy(&scenario, TargetPolicy::kFastHttp);

  Expect(scenario.scheme() == SCHEME_HTTP,
         "fast HTTP policy did not force HTTP");
  Expect(!scenario.connection().has_backpressure(),
         "fast HTTP policy retained backpressure");
  Expect(scenario.connection().server_frames_size() == 0,
         "fast HTTP policy retained structured server frames");
  Expect(!scenario.connection().has_manual_probes(),
         "fast HTTP policy retained WebSocket manual probes");
  Expect(scenario.subsequent_connections_size() == 0,
         "fast HTTP policy retained follow-on connections");
  Expect(!scenario.has_mime_post(),
         "fast HTTP policy retained a MIME request body");
  Expect(!scenario.has_upload(), "fast HTTP policy retained an upload script");
  Expect(scenario.connection().on_readable(0) == "raw response sentinel",
         "fast HTTP policy removed a cheap raw response chunk");
  Expect(scenario.request_headers(0) == "X-Fast: retained",
         "fast HTTP policy removed a cheap request header");
}

void TestDeepHttpPolicy() {
  ExpectFixedPolicy(TargetPolicy::kDeepHttp, SCHEME_HTTP,
                    "deep HTTP policy did not force HTTP",
                    "deep HTTP policy retained backpressure", false);

  Scenario scenario = ScenarioWithBackpressure(SCHEME_UNSPECIFIED, 4096, 17);
  scenario.add_request_headers("X-Deep: retained");
  scenario.mutable_connection()->add_on_readable("raw response sentinel");
  scenario.mutable_connection()->add_server_frames()->set_payload(
      "structured frame sentinel");
  scenario.mutable_connection()->mutable_manual_probes()->set_flag_matrix(true);
  scenario.add_subsequent_connections()->set_initial_response(
      "follow-on sentinel");
  scenario.mutable_mime_post()->add_parts()->set_data("mime sentinel");
  scenario.mutable_upload()->set_data("upload sentinel");
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);

  ApplyTargetPolicy(&scenario, TargetPolicy::kDeepHttp);

  Expect(scenario.connection().server_frames_size() == 1,
         "deep HTTP policy removed structured response frames");
  Expect(scenario.connection().has_manual_probes(),
         "deep HTTP policy removed manual probes");
  Expect(scenario.subsequent_connections_size() == 1,
         "deep HTTP policy removed follow-on connections");
  Expect(scenario.has_mime_post(),
         "deep HTTP policy removed a MIME request body");
  Expect(scenario.has_upload(), "deep HTTP policy removed an upload script");
  Expect(scenario.request_headers_size() == 1,
         "deep HTTP policy removed request headers");
  Expect(scenario.options_size() == 1 && scenario.options(0).option_id() ==
                                             curl::fuzzer::proto::CURLOPT_POST,
         "deep HTTP policy filtered a coverage option");
}

void TestFastHttpsPolicy() {
  ExpectFixedPolicy(TargetPolicy::kFastHttps, SCHEME_HTTPS,
                    "fast HTTPS policy did not force HTTPS",
                    "fast HTTPS policy retained backpressure", false);
}

void TestFastWebSocketPolicy() {
  ExpectFixedPolicy(TargetPolicy::kFastWebSocket, SCHEME_WS,
                    "fast WebSocket policy did not force WS",
                    "fast WebSocket policy retained backpressure", true);
}

void TestFastSecureWebSocketPolicy() {
  ExpectFixedPolicy(TargetPolicy::kFastSecureWebSocket, SCHEME_WSS,
                    "fast secure WebSocket policy did not force WSS",
                    "fast secure WebSocket policy retained backpressure", true);
}

void TestTimingPolicyMapsSecureSchemesToPlaintext() {
  Scenario https = ScenarioWithBackpressure(SCHEME_HTTPS, 2048, 1);
  ApplyTargetPolicy(&https, TargetPolicy::kTiming);
  Expect(https.scheme() == SCHEME_HTTP,
         "timing policy did not map HTTPS to HTTP");

  Scenario wss = ScenarioWithBackpressure(SCHEME_WSS, 2048, 1);
  ApplyTargetPolicy(&wss, TargetPolicy::kTiming);
  Expect(wss.scheme() == SCHEME_WS, "timing policy did not map WSS to WS");
}

void TestTimingPolicySuppliesBackpressureForZeroConfig() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 0, 0);

  ApplyTargetPolicy(&scenario, TargetPolicy::kTiming);

  Expect(scenario.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy did not supply the minimum receive buffer");
  Expect(scenario.connection().backpressure().drain_limit() == 0,
         "timing policy changed the unlimited-drain sentinel");
}

void TestTimingPolicyPreservesMeaningfulBoundaries() {
  Scenario minimum = ScenarioWithBackpressure(SCHEME_HTTP, 2048, 1);
  ApplyTargetPolicy(&minimum, TargetPolicy::kTiming);
  Expect(minimum.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy changed the minimum effective receive buffer");
  Expect(minimum.connection().backpressure().drain_limit() == 1,
         "timing policy changed the minimum drain limit");

  Scenario maximum = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 1024);
  ApplyTargetPolicy(&maximum, TargetPolicy::kTiming);
  Expect(maximum.connection().backpressure().recv_buf_bytes() == 4096,
         "timing policy changed the maximum receive buffer");
  Expect(maximum.connection().backpressure().drain_limit() == 1024,
         "timing policy changed the maximum drain limit");

  Scenario drain_only = ScenarioWithBackpressure(SCHEME_HTTP, 0, 512);
  ApplyTargetPolicy(&drain_only, TargetPolicy::kTiming);
  Expect(drain_only.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy did not make a drain-only config exert pressure");
  Expect(drain_only.connection().backpressure().drain_limit() == 512,
         "timing policy changed an in-range drain limit");
}

void TestTimingPolicyClampsIneffectiveValues() {
  Scenario too_small = ScenarioWithBackpressure(SCHEME_HTTP, 1, 0);
  ApplyTargetPolicy(&too_small, TargetPolicy::kTiming);
  Expect(too_small.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy retained a receive buffer below the platform floor");
  Expect(too_small.connection().backpressure().drain_limit() == 0,
         "timing policy changed the unlimited-drain sentinel");

  constexpr std::uint32_t kAboveIntMax =
      static_cast<std::uint32_t>(std::numeric_limits<int>::max()) + 1U;
  Scenario too_large = ScenarioWithBackpressure(
      SCHEME_HTTP, kAboveIntMax, std::numeric_limits<std::uint32_t>::max());
  ApplyTargetPolicy(&too_large, TargetPolicy::kTiming);
  Expect(too_large.connection().backpressure().recv_buf_bytes() == 4096,
         "timing policy retained a receive buffer that overflows int");
  Expect(too_large.connection().backpressure().drain_limit() == 1024,
         "timing policy retained an effectively unlimited drain limit");
}

void TestTimingPolicyCanonicalizesOnlyConfiguredFollowOns() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 2048, 0);
  auto *configured = scenario.add_subsequent_connections();
  configured->mutable_backpressure()->set_drain_limit(
      std::numeric_limits<std::uint32_t>::max());
  scenario.add_subsequent_connections()->set_initial_response(
      "ordinary redirect response");

  ApplyTargetPolicy(&scenario, TargetPolicy::kTiming);

  Expect(scenario.subsequent_connections(0).backpressure().recv_buf_bytes() ==
             2048,
         "timing policy left drain-only follow-on pressure ineffective");
  Expect(scenario.subsequent_connections(0).backpressure().drain_limit() ==
             1024,
         "timing policy did not clamp follow-on drain pressure");
  Expect(!scenario.subsequent_connections(1).has_backpressure(),
         "timing policy added waits to an ordinary follow-on script");
}

void TestDeepPoliciesRemoveRuntimeInvisibleSuffixes() {
  Scenario scenario;
  for (std::size_t i = 0; i < proto_fuzzer::scenario_limits::kMaxOptions + 5;
       ++i) {
    auto *option = scenario.add_options();
    option->set_string_value(std::string(
        proto_fuzzer::scenario_limits::kMaxMetadataBytes + 17, 'o'));
  }
  for (std::size_t i = 0;
       i < proto_fuzzer::scenario_limits::kMaxRequestHeaders + 5; ++i) {
    scenario.add_request_headers(std::string(
        proto_fuzzer::scenario_limits::kMaxMetadataBytes + 17, 'h'));
  }

  auto *primary = scenario.mutable_connection();
  for (std::size_t i = 0;
       i < proto_fuzzer::scenario_limits::kMaxResponseChunks + 5; ++i) {
    primary->add_on_readable("raw");
    primary->add_server_frames()->set_payload("frame");
  }
  for (std::size_t i = 0;
       i < proto_fuzzer::scenario_limits::kMaxConnections + 5; ++i) {
    scenario.add_subsequent_connections()->set_initial_response("follow-on");
  }

  auto *mime = scenario.mutable_mime_post();
  for (std::size_t i = 0;
       i < proto_fuzzer::scenario_limits::kMaxTopLevelMimeParts + 5; ++i) {
    auto *part = mime->add_parts();
    for (std::size_t header = 0;
         header < proto_fuzzer::scenario_limits::kMaxMimeHeadersPerPart + 5;
         ++header) {
      part->add_headers("X-Part: value");
    }
    auto *children = part->mutable_subparts();
    for (std::size_t child = 0;
         child < proto_fuzzer::scenario_limits::kMaxNestedMimeParts + 5;
         ++child) {
      children->add_parts()->set_data("child");
    }
  }

  auto *upload = scenario.mutable_upload();
  upload->set_data(
      std::string(proto_fuzzer::scenario_limits::kMaxUploadBytes + 17, 'u'));
  for (std::size_t i = 0;
       i < proto_fuzzer::scenario_limits::kMaxUploadReadSteps + 5; ++i) {
    upload->add_read_sizes(std::numeric_limits<std::uint32_t>::max());
  }

  ApplyTargetPolicy(&scenario, TargetPolicy::kDeepHttp);

  Expect(static_cast<std::size_t>(scenario.options_size()) ==
             proto_fuzzer::scenario_limits::kMaxOptions,
         "fixed policy retained options beyond the runtime budget");
  Expect(scenario.options(0).string_value().size() ==
             proto_fuzzer::scenario_limits::kMaxMetadataBytes,
         "fixed policy retained an invisible option-string suffix");
  Expect(static_cast<std::size_t>(scenario.request_headers_size()) ==
             proto_fuzzer::scenario_limits::kMaxRequestHeaders,
         "fixed policy retained request headers beyond the runtime budget");
  Expect(scenario.request_headers(0).size() ==
             proto_fuzzer::scenario_limits::kMaxMetadataBytes,
         "fixed policy retained an invisible request-header suffix");
  Expect(static_cast<std::size_t>(scenario.connection().on_readable_size()) ==
             proto_fuzzer::scenario_limits::kMaxResponseChunks,
         "fixed policy retained raw chunks beyond the shared response budget");
  Expect(scenario.connection().server_frames_size() == 0,
         "fixed policy retained frames after raw chunks spent the budget");
  Expect(
      static_cast<std::size_t>(scenario.subsequent_connections_size()) ==
          proto_fuzzer::scenario_limits::kMaxConnections - 1,
      "fixed policy retained follow-on connections beyond the runtime budget");

  std::size_t mime_parts = 0;
  for (const auto &part : scenario.mime_post().parts()) {
    ++mime_parts;
    Expect(static_cast<std::size_t>(part.headers_size()) <=
               proto_fuzzer::scenario_limits::kMaxMimeHeadersPerPart,
           "fixed policy retained MIME headers beyond the runtime budget");
    if (part.has_subparts()) {
      mime_parts += static_cast<std::size_t>(part.subparts().parts_size());
    }
  }
  Expect(mime_parts == proto_fuzzer::scenario_limits::kMaxTotalMimeParts,
         "fixed policy did not mirror the shared MIME-part budget");
  Expect(scenario.upload().data().size() ==
             proto_fuzzer::scenario_limits::kMaxUploadBytes,
         "fixed policy retained upload bytes beyond the runtime budget");
  Expect(static_cast<std::size_t>(scenario.upload().read_sizes_size()) ==
             proto_fuzzer::scenario_limits::kMaxUploadReadSteps,
         "fixed policy retained upload steps beyond the runtime budget");
  Expect(scenario.upload().read_sizes(0) ==
             proto_fuzzer::scenario_limits::kMaxUploadReadSize,
         "fixed policy retained an ineffective upload read size");
}

void TestFastHttpOptionAllowlist() {
  constexpr curl::fuzzer::proto::CurlOptionId kCheapOptions[] = {
      curl::fuzzer::proto::CURLOPT_ACCEPT_ENCODING,
      curl::fuzzer::proto::CURLOPT_BUFFERSIZE,
      curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST,
      curl::fuzzer::proto::CURLOPT_DISALLOW_USERNAME_IN_URL,
      curl::fuzzer::proto::CURLOPT_FAILONERROR,
      curl::fuzzer::proto::CURLOPT_FILETIME,
      curl::fuzzer::proto::CURLOPT_HEADER,
      curl::fuzzer::proto::CURLOPT_HTTP09_ALLOWED,
      curl::fuzzer::proto::CURLOPT_HTTP_CONTENT_DECODING,
      curl::fuzzer::proto::CURLOPT_HTTP_TRANSFER_DECODING,
      curl::fuzzer::proto::CURLOPT_HTTP_VERSION,
      curl::fuzzer::proto::CURLOPT_HTTPGET,
      curl::fuzzer::proto::CURLOPT_IGNORE_CONTENT_LENGTH,
      curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE,
      curl::fuzzer::proto::CURLOPT_NOBODY,
      curl::fuzzer::proto::CURLOPT_PATH_AS_IS,
      curl::fuzzer::proto::CURLOPT_RANGE,
      curl::fuzzer::proto::CURLOPT_REQUEST_TARGET,
      curl::fuzzer::proto::CURLOPT_RESUME_FROM_LARGE,
      curl::fuzzer::proto::CURLOPT_TRANSFER_ENCODING,
      curl::fuzzer::proto::CURLOPT_USERAGENT,
  };

  Scenario scenario;
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  for (auto option_id : kCheapOptions) {
    scenario.add_options()->set_option_id(option_id);
  }
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION);
  scenario.add_options()->set_option_id(
      static_cast<curl::fuzzer::proto::CurlOptionId>(123456789));

  Scenario deep = scenario;
  ApplyTargetPolicy(&scenario, TargetPolicy::kFastHttp);
  ApplyTargetPolicy(&deep, TargetPolicy::kDeepHttp);

  Expect(scenario.options_size() ==
             static_cast<int>(sizeof(kCheapOptions) / sizeof(kCheapOptions[0])),
         "fast HTTP policy retained an option outside its cheap allowlist");
  for (int index = 0; index < scenario.options_size(); ++index) {
    Expect(scenario.options(index).option_id() == kCheapOptions[index],
           "fast HTTP policy changed the order of retained options");
  }
  Expect(deep.options_size() == static_cast<int>(sizeof(kCheapOptions) /
                                                 sizeof(kCheapOptions[0])) +
                                    3,
         "deep HTTP policy filtered an option intended for full coverage");
}

void TestFastHttpFiltersBeforeApplyingOptionBound() {
  Scenario scenario;
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxOptions + 5; ++index) {
    scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  }
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_USERAGENT);

  ApplyTargetPolicy(&scenario, TargetPolicy::kFastHttp);

  Expect(scenario.options_size() == 1,
         "fast HTTP bounded options before removing deep-only entries");
  Expect(scenario.options(0).option_id() ==
             curl::fuzzer::proto::CURLOPT_USERAGENT,
         "fast HTTP lost a cheap option behind a rejected prefix");
}

} // namespace

int main() {
  TestFastHttpPolicy();
  TestDeepHttpPolicy();
  TestFastHttpsPolicy();
  TestFastWebSocketPolicy();
  TestFastSecureWebSocketPolicy();
  TestTimingPolicyMapsSecureSchemesToPlaintext();
  TestTimingPolicySuppliesBackpressureForZeroConfig();
  TestTimingPolicyPreservesMeaningfulBoundaries();
  TestTimingPolicyClampsIneffectiveValues();
  TestTimingPolicyCanonicalizesOnlyConfiguredFollowOns();
  TestDeepPoliciesRemoveRuntimeInvisibleSuffixes();
  TestFastHttpOptionAllowlist();
  TestFastHttpFiltersBeforeApplyingOptionBound();
  return 0;
}
