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
#include <string>

namespace {

using curl::fuzzer::proto::Scenario;
using curl::fuzzer::proto::SCHEME_FTP;
using curl::fuzzer::proto::SCHEME_HTTP;
using curl::fuzzer::proto::SCHEME_HTTPS;
using curl::fuzzer::proto::SCHEME_TELNET;
using curl::fuzzer::proto::SCHEME_TFTP;
using curl::fuzzer::proto::SCHEME_UNSPECIFIED;
using curl::fuzzer::proto::SCHEME_WS;
using curl::fuzzer::proto::SCHEME_WSS;
using proto_fuzzer::ApplyTargetPolicy;
using proto_fuzzer::RunModeFor;
using proto_fuzzer::ScenarioRunMode;
using proto_fuzzer::TargetProfile;

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

void ExpectFixedPolicy(TargetProfile profile,
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

  ApplyTargetPolicy(&scenario, profile);

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

  ApplyTargetPolicy(&scenario, TargetProfile::kFastHttp);

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
  ExpectFixedPolicy(TargetProfile::kDeepHttp, SCHEME_HTTP,
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

  ApplyTargetPolicy(&scenario, TargetProfile::kDeepHttp);

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
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("mutated.example:8443/a/path?query#fragment");

  ApplyTargetPolicy(&scenario, TargetProfile::kFastHttps);

  Expect(scenario.scheme() == SCHEME_HTTPS,
         "fast HTTPS policy did not force HTTPS");
  Expect(!scenario.connection().has_backpressure(),
         "fast HTTPS policy retained backpressure");
  Expect(scenario.host_path() == "tls.test/a/path?query#fragment",
         "fast HTTPS policy did not retain URL suffix under the trusted host");
}

void TestH2ProxyPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("mutated.invalid:8443/path?query#fragment");
  scenario.add_request_headers("X-Origin: retained");
  scenario.mutable_connection()->add_on_readable("raw HTTP/2 frames");
  scenario.mutable_connection()->add_server_frames()->set_payload(
      "WebSocket-only frame");
  scenario.mutable_connection()->mutable_manual_probes()->set_flag_matrix(true);
  scenario.add_subsequent_connections()->set_initial_response(
      "unrepresentable second proxy stream");
  scenario.mutable_mime_post()->add_parts()->set_data("MIME body");
  scenario.mutable_upload()->set_data("upload body");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);

  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_CONNECT_ONLY);
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION);

  ApplyTargetPolicy(&scenario, TargetProfile::kH2Proxy);

  Expect(scenario.scheme() == SCHEME_HTTP,
         "HTTP/2 proxy policy did not force a plaintext origin");
  Expect(scenario.host_path() == "origin.test/path?query#fragment",
         "HTTP/2 proxy policy did not isolate the origin authority");
  Expect(!scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0 &&
             !scenario.connection().has_manual_probes() &&
             scenario.subsequent_connections_size() == 0,
         "HTTP/2 proxy policy retained transport shapes its peer cannot use");
  Expect(scenario.connection().on_readable(0) == "raw HTTP/2 frames",
         "HTTP/2 proxy policy removed the raw outer frame stream");
  Expect(scenario.request_headers(0) == "X-Origin: retained" &&
             scenario.has_mime_post() && scenario.has_upload(),
         "HTTP/2 proxy policy removed state visible to the tunneled request");
  Expect(scenario.telnet_options_size() == 0 && !scenario.has_api_plan(),
         "HTTP/2 proxy policy retained another target's work");
  Expect(scenario.options_size() == 2 &&
             scenario.options(0).option_id() ==
                 curl::fuzzer::proto::CURLOPT_POST &&
             scenario.options(1).option_id() ==
                 curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION,
         "HTTP/2 proxy policy retained an option that can bypass its fixed "
         "transport");
}

void TestFastWebSocketPolicy() {
  ExpectFixedPolicy(TargetProfile::kFastWebSocket, SCHEME_WS,
                    "fast WebSocket policy did not force WS",
                    "fast WebSocket policy retained backpressure", true);
}

void TestFastSecureWebSocketPolicy() {
  ExpectFixedPolicy(TargetProfile::kFastSecureWebSocket, SCHEME_WSS,
                    "fast secure WebSocket policy did not force WSS",
                    "fast secure WebSocket policy retained backpressure", true);
}

void TestFastTelnetPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.mutable_connection()->set_initial_response("peer sentinel");
  scenario.mutable_connection()->add_on_readable("raw sentinel");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.mutable_connection()->mutable_manual_probes()->set_flag_matrix(true);
  scenario.add_subsequent_connections()->set_initial_response("follow-on");
  scenario.add_request_headers("X-Ignored: telnet");
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.mutable_upload()->set_data(std::string(
      proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes + 17, 'u'));
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxTelnetUploadReadSteps + 3;
       ++index) {
    scenario.mutable_upload()->add_read_sizes(
        std::numeric_limits<std::uint32_t>::max());
  }
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxTelnetOptions + 3; ++index) {
    scenario.add_telnet_options(std::string(
        proto_fuzzer::scenario_limits::kMaxTelnetOptionBytes + 17, 't'));
  }
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_HTTPGET);
  constexpr curl::fuzzer::proto::CurlOptionId kRetained[] = {
      curl::fuzzer::proto::CURLOPT_CRLF,
      curl::fuzzer::proto::CURLOPT_USERNAME,
      curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE,
  };
  for (const auto option : kRetained) {
    scenario.add_options()->set_option_id(option);
  }

  ApplyTargetPolicy(&scenario, TargetProfile::kFastTelnet);

  Expect(scenario.scheme() == SCHEME_TELNET,
         "fast TELNET policy did not force TELNET");
  Expect(!scenario.connection().has_backpressure(),
         "fast TELNET policy retained unserviceable backpressure");
  Expect(scenario.connection().server_frames_size() == 0,
         "fast TELNET policy retained structured WebSocket frames");
  Expect(!scenario.connection().has_manual_probes(),
         "fast TELNET policy retained WebSocket manual probes");
  Expect(scenario.connection().initial_response() == "peer sentinel" &&
             scenario.connection().on_readable(0) == "raw sentinel",
         "fast TELNET policy removed preloaded raw peer bytes");
  Expect(scenario.subsequent_connections_size() == 0,
         "fast TELNET policy retained follow-on sockets");
  Expect(scenario.request_headers_size() == 0,
         "fast TELNET policy retained HTTP request headers");
  Expect(!scenario.has_mime_post(),
         "fast TELNET policy retained an HTTP MIME body");
  Expect(scenario.upload().data().size() ==
             proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes,
         "fast TELNET policy retained upload bytes beyond its work budget");
  Expect(scenario.upload().read_sizes(0) ==
             proto_fuzzer::scenario_limits::kMaxTelnetUploadReadSize,
         "fast TELNET policy retained an unsafe callback write size");
  Expect(static_cast<std::size_t>(scenario.upload().read_sizes_size()) ==
             proto_fuzzer::scenario_limits::kMaxTelnetUploadReadSteps,
         "fast TELNET policy exceeded its fragmentation-step budget");
  Expect(static_cast<std::size_t>(scenario.telnet_options_size()) ==
             proto_fuzzer::scenario_limits::kMaxTelnetOptions,
         "fast TELNET policy retained options beyond its list budget");
  Expect(scenario.telnet_options(0).size() ==
             proto_fuzzer::scenario_limits::kMaxTelnetOptionBytes,
         "fast TELNET policy retained an invisible option suffix");
  Expect(scenario.options_size() ==
             static_cast<int>(sizeof(kRetained) / sizeof(kRetained[0])),
         "fast TELNET policy retained an unrelated scalar option");
  for (int index = 0; index < scenario.options_size(); ++index) {
    Expect(scenario.options(index).option_id() == kRetained[index],
           "fast TELNET policy changed retained option order");
  }
}

void TestFastFtpPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("mutated.invalid:9999/a/b/file");
  scenario.add_request_headers("X-Ignored: ftp");
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_upload()->set_data("upload sentinel");
  scenario.mutable_connection()->add_on_readable("control reply");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxConnections + 2; ++index) {
    auto *data = scenario.add_subsequent_connections();
    data->set_initial_response("data-" + std::to_string(index));
    data->mutable_backpressure()->set_drain_limit(1);
    data->add_server_frames()->set_payload("ignored frame");
  }

  auto *rejected = scenario.add_options();
  rejected->set_option_id(curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
  auto *create_dirs = scenario.add_options();
  create_dirs->set_option_id(
      curl::fuzzer::proto::CURLOPT_FTP_CREATE_MISSING_DIRS);
  create_dirs->set_uint_value(std::numeric_limits<std::uint64_t>::max());
  auto *file_method = scenario.add_options();
  file_method->set_option_id(curl::fuzzer::proto::CURLOPT_FTP_FILEMETHOD);
  file_method->set_uint_value(99);
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);

  ApplyTargetPolicy(&scenario, TargetProfile::kFastFtp);

  Expect(scenario.scheme() == SCHEME_FTP, "fast FTP policy did not force FTP");
  Expect(scenario.host_path() == "ftp.test/a/b/file",
         "fast FTP policy did not retain only the URL path");
  Expect(scenario.request_headers_size() == 0 && !scenario.has_mime_post() &&
             scenario.telnet_options_size() == 0 && !scenario.has_api_plan(),
         "fast FTP policy retained another protocol's shape");
  Expect(scenario.has_upload() && scenario.upload().data() == "upload sentinel",
         "fast FTP policy removed callback-backed upload data");
  Expect(scenario.connection().on_readable(0) == "control reply" &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast FTP policy changed raw control data or retained stream-only "
         "controls");
  Expect(static_cast<std::size_t>(scenario.subsequent_connections_size()) ==
             proto_fuzzer::scenario_limits::kMaxConnections - 1,
         "fast FTP policy exceeded its passive data-channel budget");
  Expect(!scenario.subsequent_connections(0).has_backpressure() &&
             scenario.subsequent_connections(0).server_frames_size() == 0,
         "fast FTP policy retained ignored data-channel controls");
  Expect(scenario.options_size() == 3,
         "fast FTP policy retained a non-FTP option");
  Expect(scenario.options(0).uint_value() < 3 &&
             scenario.options(1).uint_value() < 4,
         "fast FTP policy left small enums outside curl's valid domains");
}

void TestFastTftpPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("untrusted.invalid:1234/path;mode=netascii?query");
  scenario.mutable_connection()->add_on_readable("packet one");
  scenario.mutable_connection()->add_on_readable("");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("stream-only");
  scenario.add_request_headers("X-Ignored: tftp");
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_upload()->set_data("upload sentinel");

  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  auto *block_size = scenario.add_options();
  block_size->set_option_id(curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE);
  block_size->set_uint_value(std::numeric_limits<std::uint64_t>::max());
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_TFTP_NO_OPTIONS);

  ApplyTargetPolicy(&scenario, TargetProfile::kFastTftp);

  Expect(scenario.scheme() == SCHEME_TFTP,
         "fast TFTP policy did not force TFTP");
  Expect(scenario.host_path() == "tftp.test/path;mode=netascii?query",
         "fast TFTP policy did not retain the filename/mode suffix");
  Expect(scenario.subsequent_connections_size() == 0 &&
             scenario.request_headers_size() == 0 &&
             !scenario.has_mime_post() && scenario.telnet_options_size() == 0 &&
             !scenario.has_api_plan(),
         "fast TFTP policy retained stream or another protocol's shape");
  Expect(scenario.has_upload() && scenario.upload().data() == "upload sentinel",
         "fast TFTP policy removed WRQ upload data");
  Expect(scenario.connection().on_readable_size() == 2 &&
             scenario.connection().on_readable(1).empty(),
         "fast TFTP policy lost a UDP packet boundary");
  Expect(!scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast TFTP policy retained stream-only connection controls");
  Expect(scenario.options_size() == 2,
         "fast TFTP policy retained a non-TFTP option");
  Expect(scenario.options(0).uint_value() == 65464,
         "fast TFTP policy did not clamp block size to curl's upper boundary");
}

void TestPauseTerminalIsTelnetOnly() {
  Scenario telnet;
  telnet.mutable_upload()->set_terminal(
      curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE);
  ApplyTargetPolicy(&telnet, TargetProfile::kFastTelnet);
  Expect(telnet.upload().terminal() ==
             curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE,
         "TELNET policy removed its synchronous pause outcome");

  Scenario http;
  http.mutable_upload()->set_terminal(
      curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE);
  http.add_telnet_options("TTYPE=must-be-discarded");
  ApplyTargetPolicy(&http, TargetProfile::kDeepHttp);
  Expect(http.upload().terminal() == curl::fuzzer::proto::UPLOAD_TERMINAL_EOF,
         "non-TELNET policy retained a callback pause without a resume source");
  Expect(http.telnet_options_size() == 0,
         "non-TELNET policy retained TELNET-only options");
}

void TestNonTelnetPolicySelectsUploadBudgetBeforeBounding() {
  Scenario scenario;
  // The incoming scheme is fuzz-controlled and must not select the budget of
  // a different protocol before the fixed lane restores its own invariant.
  scenario.set_scheme(SCHEME_TELNET);
  scenario.mutable_upload()->set_data(std::string(
      proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes + 1, 'u'));

  ApplyTargetPolicy(&scenario, TargetProfile::kDeepHttp);

  Expect(scenario.scheme() == SCHEME_HTTP,
         "deep HTTP policy did not restore its fixed scheme");
  Expect(scenario.upload().data().size() ==
             proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes + 1,
         "input TELNET scheme incorrectly selected TELNET's upload budget");
}

void TestFastTelnetResponseBudgets() {
  Scenario byte_budget;
  byte_budget.mutable_connection()->set_initial_response(std::string(
      proto_fuzzer::scenario_limits::kMaxTelnetResponseBytes - 1, 'a'));
  byte_budget.mutable_connection()->add_on_readable("bc");
  byte_budget.mutable_connection()->add_on_readable("invisible");
  ApplyTargetPolicy(&byte_budget, TargetProfile::kFastTelnet);
  Expect(byte_budget.connection().initial_response().size() +
                 byte_budget.connection().on_readable(0).size() ==
             proto_fuzzer::scenario_limits::kMaxTelnetResponseBytes,
         "fast TELNET policy did not enforce its total peer-byte budget");
  Expect(byte_budget.connection().on_readable_size() == 1,
         "fast TELNET policy retained chunks after a truncated response");

  Scenario exact_budget;
  exact_budget.mutable_connection()->set_initial_response(
      std::string(proto_fuzzer::scenario_limits::kMaxTelnetResponseBytes, 'a'));
  exact_budget.mutable_connection()->add_on_readable("invisible");
  ApplyTargetPolicy(&exact_budget, TargetProfile::kFastTelnet);
  Expect(exact_budget.connection().on_readable_size() == 0,
         "fast TELNET policy retained an empty budget-exhausted chunk");

  Scenario control_budget;
  control_budget.mutable_connection()->set_initial_response(
      std::string(proto_fuzzer::scenario_limits::kMaxTelnetControlBytes,
                  '\xff') +
      "prefix");
  control_budget.mutable_connection()->add_on_readable("\xffsuffix");
  ApplyTargetPolicy(&control_budget, TargetProfile::kFastTelnet);
  Expect(control_budget.connection().initial_response().size() ==
             proto_fuzzer::scenario_limits::kMaxTelnetControlBytes + 6,
         "fast TELNET policy retained reply-amplifying control bytes");
  Expect(control_budget.connection().on_readable_size() == 0,
         "fast TELNET policy retained bytes after the control budget");
}

void TestTimingPolicyMapsSecureSchemesToPlaintext() {
  Scenario https = ScenarioWithBackpressure(SCHEME_HTTPS, 2048, 1);
  ApplyTargetPolicy(&https, TargetProfile::kTiming);
  Expect(https.scheme() == SCHEME_HTTP,
         "timing policy did not map HTTPS to HTTP");

  Scenario wss = ScenarioWithBackpressure(SCHEME_WSS, 2048, 1);
  ApplyTargetPolicy(&wss, TargetProfile::kTiming);
  Expect(wss.scheme() == SCHEME_WS, "timing policy did not map WSS to WS");
}

void TestTimingPolicySuppliesBackpressureForZeroConfig() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 0, 0);

  ApplyTargetPolicy(&scenario, TargetProfile::kTiming);

  Expect(scenario.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy did not supply the minimum receive buffer");
  Expect(scenario.connection().backpressure().drain_limit() == 0,
         "timing policy changed the unlimited-drain sentinel");
}

void TestTimingPolicyPreservesMeaningfulBoundaries() {
  Scenario minimum = ScenarioWithBackpressure(SCHEME_HTTP, 2048, 1);
  ApplyTargetPolicy(&minimum, TargetProfile::kTiming);
  Expect(minimum.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy changed the minimum effective receive buffer");
  Expect(minimum.connection().backpressure().drain_limit() == 1,
         "timing policy changed the minimum drain limit");

  Scenario maximum = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 1024);
  ApplyTargetPolicy(&maximum, TargetProfile::kTiming);
  Expect(maximum.connection().backpressure().recv_buf_bytes() == 4096,
         "timing policy changed the maximum receive buffer");
  Expect(maximum.connection().backpressure().drain_limit() == 1024,
         "timing policy changed the maximum drain limit");

  Scenario drain_only = ScenarioWithBackpressure(SCHEME_HTTP, 0, 512);
  ApplyTargetPolicy(&drain_only, TargetProfile::kTiming);
  Expect(drain_only.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy did not make a drain-only config exert pressure");
  Expect(drain_only.connection().backpressure().drain_limit() == 512,
         "timing policy changed an in-range drain limit");
}

void TestTimingPolicyClampsIneffectiveValues() {
  Scenario too_small = ScenarioWithBackpressure(SCHEME_HTTP, 1, 0);
  ApplyTargetPolicy(&too_small, TargetProfile::kTiming);
  Expect(too_small.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy retained a receive buffer below the platform floor");
  Expect(too_small.connection().backpressure().drain_limit() == 0,
         "timing policy changed the unlimited-drain sentinel");

  constexpr std::uint32_t kAboveIntMax =
      static_cast<std::uint32_t>(std::numeric_limits<int>::max()) + 1U;
  Scenario too_large = ScenarioWithBackpressure(
      SCHEME_HTTP, kAboveIntMax, std::numeric_limits<std::uint32_t>::max());
  ApplyTargetPolicy(&too_large, TargetProfile::kTiming);
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

  ApplyTargetPolicy(&scenario, TargetProfile::kTiming);

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

  ApplyTargetPolicy(&scenario, TargetProfile::kDeepHttp);

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
  ApplyTargetPolicy(&scenario, TargetProfile::kFastHttp);
  ApplyTargetPolicy(&deep, TargetProfile::kDeepHttp);

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

  ApplyTargetPolicy(&scenario, TargetProfile::kFastHttp);

  Expect(scenario.options_size() == 1,
         "fast HTTP bounded options before removing deep-only entries");
  Expect(scenario.options(0).option_id() ==
             curl::fuzzer::proto::CURLOPT_USERAGENT,
         "fast HTTP lost a cheap option behind a rejected prefix");
}

void TestApiPolicyRetainsAndBoundsItsPlan() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path(
      std::string(proto_fuzzer::scenario_limits::kMaxApiStringBytes + 7, 'u'));
  scenario.mutable_mime_post()->add_parts()->set_data("deep HTTP sentinel");
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);

  auto *plan = scenario.mutable_api_plan();
  plan->set_duplicate_easy(true);
  plan->set_reset_easy(true);
  plan->set_attach_share(true);
  plan->set_drive_mode(curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET);
  plan->set_wake_multi(true);
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxApiShareDataSelectors + 3;
       ++index) {
    plan->add_share_data_selectors(static_cast<std::uint32_t>(index + 100));
  }
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxApiInfoSelectors + 3;
       ++index) {
    plan->add_easy_info_selectors(static_cast<std::uint32_t>(index + 200));
  }
  ApplyTargetPolicy(&scenario, TargetProfile::kApi);

  Expect(scenario.scheme() == SCHEME_HTTP,
         "API policy did not force plaintext HTTP");
  Expect(scenario.host_path().size() ==
             proto_fuzzer::scenario_limits::kMaxApiStringBytes,
         "API policy retained URL bytes its convenience probes cannot use");
  Expect(!scenario.connection().has_backpressure(),
         "API policy retained timed backpressure");
  Expect(scenario.has_mime_post() && scenario.options_size() == 1,
         "API policy discarded the HTTP state used to populate query results");
  Expect(scenario.has_api_plan(), "API policy discarded its lifecycle plan");
  Expect(scenario.api_plan().duplicate_easy() &&
             scenario.api_plan().reset_easy() &&
             scenario.api_plan().attach_share() &&
             scenario.api_plan().drive_mode() ==
                 curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET &&
             scenario.api_plan().wake_multi(),
         "API policy changed mutation-controlled lifecycle choices");
  Expect(static_cast<std::size_t>(
             scenario.api_plan().share_data_selectors_size()) ==
             proto_fuzzer::scenario_limits::kMaxApiShareDataSelectors,
         "API policy retained too many share-data selectors");
  Expect(static_cast<std::size_t>(
             scenario.api_plan().easy_info_selectors_size()) ==
             proto_fuzzer::scenario_limits::kMaxApiInfoSelectors,
         "API policy retained too many typed getinfo selectors");
  Expect(scenario.api_plan().share_data_selectors(0) == 100 &&
             scenario.api_plan().easy_info_selectors(0) == 200,
         "API policy changed the retained selector prefix");
}

void TestProtocolPoliciesDiscardApiPlans() {
  constexpr TargetProfile kProtocolPolicies[] = {
      TargetProfile::kFastHttp,      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,     TargetProfile::kH2Proxy,
      TargetProfile::kFastWebSocket, TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,    TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,      TargetProfile::kMulti,
      TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kProtocolPolicies) {
    Scenario scenario;
    scenario.set_host_path("example.test/");
    scenario.mutable_api_plan()->set_duplicate_easy(true);
    scenario.mutable_api_plan()->add_easy_info_selectors(7);

    ApplyTargetPolicy(&scenario, profile);

    Expect(!scenario.has_api_plan(),
           "a protocol-focused policy retained API-only lifecycle work");
  }
}

void TestMultiPolicyRetainsAndBoundsItsPlan() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("mutated.invalid/a/path?query#fragment");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxConnections + 2; ++index) {
    scenario.add_subsequent_connections()->set_initial_response("response");
  }

  auto *plan = scenario.mutable_multi_plan();
  plan->set_transfer_count(99);
  plan->set_drive_mode(curl::fuzzer::proto::MULTI_DRIVE_SOCKET);
  plan->set_max_host_connections(99);
  plan->set_max_total_connections(99);
  plan->set_connection_cache_size(99);
  plan->set_keep_connections_open(true);
  plan->set_multiplex(true);
  plan->set_wake_multi(true);
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxMultiActions + 3; ++index) {
    auto *action = plan->add_actions();
    action->set_transfer_selector(99);
    action->set_kind(curl::fuzzer::proto::MULTI_ACTION_REMOVE);
  }

  ApplyTargetPolicy(&scenario, TargetProfile::kMulti);

  Expect(scenario.scheme() == SCHEME_HTTP,
         "multi policy did not force plaintext HTTP");
  Expect(scenario.host_path() == "multi.test/a/path?query#fragment",
         "multi policy did not put all handles on one origin");
  Expect(!scenario.connection().has_backpressure(),
         "multi policy retained timed backpressure");
  Expect(!scenario.has_api_plan(),
         "multi policy retained API-only lifecycle work");
  Expect(scenario.has_multi_plan(),
         "multi policy discarded its shared-multi plan");
  Expect(scenario.multi_plan().transfer_count() ==
             proto_fuzzer::scenario_limits::kMaxMultiTransfers,
         "multi policy did not cap the easy-handle count");
  Expect(scenario.multi_plan().max_host_connections() ==
                 proto_fuzzer::scenario_limits::kMaxMultiTransfers &&
             scenario.multi_plan().max_total_connections() ==
                 proto_fuzzer::scenario_limits::kMaxMultiTransfers &&
             scenario.multi_plan().connection_cache_size() ==
                 proto_fuzzer::scenario_limits::kMaxMultiTransfers * 2,
         "multi policy did not cap connection limits");
  Expect(static_cast<std::size_t>(scenario.multi_plan().actions_size()) ==
             proto_fuzzer::scenario_limits::kMaxMultiActions,
         "multi policy retained actions beyond its operation budget");
  Expect(scenario.multi_plan().actions(0).transfer_selector() <
             scenario.multi_plan().transfer_count(),
         "multi policy retained an out-of-range handle selector");
  Expect(static_cast<std::size_t>(scenario.subsequent_connections_size()) ==
             proto_fuzzer::scenario_limits::kMaxMultiTransfers - 1,
         "multi policy retained response scripts beyond its handle count");
}

void TestOtherPoliciesDiscardMultiPlans() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp,      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,     TargetProfile::kH2Proxy,
      TargetProfile::kFastWebSocket, TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,    TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,      TargetProfile::kApi,
      TargetProfile::kTiming,
  };
  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path("example.test/");
    scenario.mutable_multi_plan()->set_transfer_count(4);
    ApplyTargetPolicy(&scenario, profile);
    Expect(!scenario.has_multi_plan(),
           "a non-multi policy retained concurrent-handle work");
  }
}

void TestApiEasyDriveDropsMultiOnlyWakeup() {
  Scenario scenario;
  scenario.mutable_api_plan()->set_drive_mode(
      curl::fuzzer::proto::API_DRIVE_EASY_PERFORM);
  scenario.mutable_api_plan()->set_wake_multi(true);

  ApplyTargetPolicy(&scenario, TargetProfile::kApi);

  Expect(scenario.api_plan().drive_mode() ==
             curl::fuzzer::proto::API_DRIVE_EASY_PERFORM,
         "API policy changed the selected easy entrypoint");
  Expect(!scenario.api_plan().wake_multi(),
         "easy drive retained a multi-only wakeup mutation");
}

void TestProfileRunModes() {
  Expect(RunModeFor(TargetProfile::kCompatibility) ==
             ScenarioRunMode::kProtocolCoverage,
         "compatibility profile lost its ordinary result probes");
  Expect(RunModeFor(TargetProfile::kFastHttp) == ScenarioRunMode::kFastProtocol,
         "fast HTTP profile gained coverage-probe overhead");
  Expect(RunModeFor(TargetProfile::kFastTelnet) ==
             ScenarioRunMode::kFastProtocol,
         "fast TELNET profile gained coverage-probe overhead");
  Expect(RunModeFor(TargetProfile::kApi) == ScenarioRunMode::kApiLifecycle,
         "API profile does not authorize its lifecycle plan");
  Expect(RunModeFor(TargetProfile::kMulti) == ScenarioRunMode::kMultiTransfer,
         "multi profile does not authorize concurrent transfers");
  Expect(RunModeFor(TargetProfile::kFastHttps) == ScenarioRunMode::kTlsCoverage,
         "fast HTTPS profile does not authorize the real TLS peer");
  Expect(RunModeFor(TargetProfile::kH2Proxy) ==
             ScenarioRunMode::kH2ProxyCoverage,
         "HTTP/2 proxy profile does not authorize its CONNECT peer");
  Expect(RunModeFor(TargetProfile::kFastFtp) == ScenarioRunMode::kFtpCoverage,
         "fast FTP profile does not authorize the two-channel peer");
  Expect(RunModeFor(TargetProfile::kFastTftp) == ScenarioRunMode::kTftpCoverage,
         "fast TFTP profile does not authorize the UDP peer");

  constexpr TargetProfile kCoverageProfiles[] = {
      TargetProfile::kDeepHttp,
      TargetProfile::kFastWebSocket,
      TargetProfile::kFastSecureWebSocket,
      TargetProfile::kTiming,
  };
  for (const TargetProfile profile : kCoverageProfiles) {
    Expect(RunModeFor(profile) == ScenarioRunMode::kProtocolCoverage,
           "coverage profile does not retain ordinary result probes");
  }
}

void TestCompatibilityProfileIsNoOp() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("compatibility.example/");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.add_request_headers("X-Compatibility: retained");
  const std::string before = scenario.SerializeAsString();

  ApplyTargetPolicy(&scenario, TargetProfile::kCompatibility);

  Expect(scenario.SerializeAsString() == before,
         "compatibility profile changed an accumulated-corpus input");
}

} // namespace

int main() {
  TestFastHttpPolicy();
  TestDeepHttpPolicy();
  TestFastHttpsPolicy();
  TestH2ProxyPolicy();
  TestFastWebSocketPolicy();
  TestFastSecureWebSocketPolicy();
  TestFastTelnetPolicy();
  TestFastFtpPolicy();
  TestFastTftpPolicy();
  TestPauseTerminalIsTelnetOnly();
  TestNonTelnetPolicySelectsUploadBudgetBeforeBounding();
  TestFastTelnetResponseBudgets();
  TestTimingPolicyMapsSecureSchemesToPlaintext();
  TestTimingPolicySuppliesBackpressureForZeroConfig();
  TestTimingPolicyPreservesMeaningfulBoundaries();
  TestTimingPolicyClampsIneffectiveValues();
  TestTimingPolicyCanonicalizesOnlyConfiguredFollowOns();
  TestDeepPoliciesRemoveRuntimeInvisibleSuffixes();
  TestFastHttpOptionAllowlist();
  TestFastHttpFiltersBeforeApplyingOptionBound();
  TestApiPolicyRetainsAndBoundsItsPlan();
  TestProtocolPoliciesDiscardApiPlans();
  TestMultiPolicyRetainsAndBoundsItsPlan();
  TestOtherPoliciesDiscardMultiPlans();
  TestApiEasyDriveDropsMultiOnlyWakeup();
  TestProfileRunModes();
  TestCompatibilityProfileIsNoOp();
  return 0;
}
