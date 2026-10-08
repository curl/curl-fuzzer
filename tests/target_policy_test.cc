/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/target_policy.h"

#include "proto_fuzzer/scenario_limits.h"

#include <curl/curl.h>
#include <google/protobuf/text_format.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
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
using proto_fuzzer::NormalizeScenarioForTarget;
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

  NormalizeScenarioForTarget(&scenario, profile);

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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp);

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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kDeepHttp);

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

void TestDeepHttpBoundsFileInputs() {
  Scenario scenario;
  scenario.set_cookie_file(
      std::string(proto_fuzzer::scenario_limits::kMaxFileInputBytes + 1, 'c'));
  scenario.set_altsvc_file(
      std::string(proto_fuzzer::scenario_limits::kMaxFileInputBytes + 1, 'a'));
  scenario.set_hsts_file("must be removed by the shared budget");
  scenario.set_netrc_file("must also be removed by the shared budget");
  scenario.set_crl_file("TLS-only input");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kDeepHttp);

  Expect(scenario.cookie_file().size() ==
             proto_fuzzer::scenario_limits::kMaxFileInputBytes,
         "deep HTTP policy did not cap the cookie-file input");
  Expect(scenario.altsvc_file().size() ==
             proto_fuzzer::scenario_limits::kMaxFileInputBytes,
         "deep HTTP policy did not cap the Alt-Svc-file input");
  Expect(scenario.hsts_file().empty(),
         "deep HTTP policy exceeded the shared file-input byte budget");
  Expect(scenario.netrc_file().empty(),
         "deep HTTP policy exceeded the shared budget with netrc input");
  Expect(scenario.crl_file().empty(),
         "deep HTTP policy retained TLS-only CRL input");

  Scenario fast;
  fast.set_cookie_file("cookie");
  fast.set_altsvc_file("alt-svc");
  fast.set_hsts_file("hsts");
  fast.set_netrc_file("netrc");
  fast.set_crl_file("crl");
  NormalizeScenarioForTarget(&fast, TargetProfile::kFastHttp);
  Expect(fast.cookie_file().empty() && fast.altsvc_file().empty() &&
             fast.hsts_file().empty() && fast.netrc_file().empty() &&
             fast.crl_file().empty(),
         "fast HTTP policy retained deep filename-parser inputs");
}

void TestDeepHttpAltSvcCanonicalAuthority() {
  Scenario scenario;
  scenario.set_host_path("mutated.example:8443/a/path?query#fragment");
  scenario.set_altsvc_file("h1 altsvc-origin.test 80 h1 alternate.test 80");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kDeepHttp);

  Expect(scenario.host_path() == "altsvc-origin.test/a/path?query#fragment",
         "deep HTTP Alt-Svc policy did not select its cache-backed authority");

  Scenario ordinary;
  ordinary.set_host_path("mutated.example:8443/a/path?query#fragment");
  NormalizeScenarioForTarget(&ordinary, TargetProfile::kDeepHttp);
  Expect(ordinary.host_path() == "mutated.example:8443/a/path?query#fragment",
         "deep HTTP policy canonicalized an authority without Alt-Svc input");
}

void TestFastHttpsPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("mutated.example:8443/a/path?query#fragment");
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);
  scenario.set_cookie_file("HTTP-only input");
  scenario.set_crl_file("TLS CRL input");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttps);

  Expect(scenario.scheme() == SCHEME_HTTPS,
         "fast HTTPS policy did not force HTTPS");
  Expect(!scenario.connection().has_backpressure(),
         "fast HTTPS policy retained backpressure");
  Expect(scenario.host_path() == "tls.test/a/path?query#fragment",
         "fast HTTPS policy did not retain URL suffix under the trusted host");
  Expect(scenario.tls_certificate_chain() ==
             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES,
         "fast HTTPS policy discarded its certificate-chain selector");
  Expect(scenario.cookie_file().empty(),
         "fast HTTPS policy retained deep HTTP filename input");
  Expect(scenario.crl_file() == "TLS CRL input",
         "fast HTTPS policy discarded its CRL input");
}

void TestHttpsH2Policy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("mutated.invalid:8443/path?query#fragment");
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);
  scenario.add_request_headers("X-H2: retained");
  scenario.mutable_connection()->add_on_readable("raw HTTP/2 frames");
  scenario.mutable_connection()->add_server_frames()->set_payload(
      "WebSocket-only frame");
  scenario.mutable_connection()->mutable_manual_probes()->set_flag_matrix(true);
  scenario.add_subsequent_connections()->set_initial_response(
      "unrepresentable second HTTP/2 connection");
  scenario.mutable_mime_post()->add_parts()->set_data("MIME body");
  scenario.mutable_upload()->set_data("upload body");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.set_accept_h2_push(true);

  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_SSL_ENABLE_ALPN);
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kHttpsH2);

  Expect(scenario.scheme() == SCHEME_HTTPS,
         "HTTPS/H2 policy did not force HTTPS");
  Expect(scenario.host_path() == "tls.test/path?query#fragment",
         "HTTPS/H2 policy did not isolate the verified TLS authority");
  Expect(scenario.tls_certificate_chain() ==
             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES,
         "HTTPS/H2 policy discarded its certificate-chain selector");
  Expect(!scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0 &&
             !scenario.connection().has_manual_probes() &&
             scenario.subsequent_connections_size() == 0,
         "HTTPS/H2 policy retained shapes its raw-frame peer cannot use");
  Expect(scenario.connection().on_readable(0) == "raw HTTP/2 frames",
         "HTTPS/H2 policy removed its raw frame stream");
  Expect(scenario.request_headers(0) == "X-H2: retained" &&
             scenario.has_mime_post() && scenario.has_upload(),
         "HTTPS/H2 policy removed request-side HTTP state");
  Expect(scenario.telnet_options_size() == 0 && !scenario.has_api_plan() &&
             !scenario.has_multi_plan(),
         "HTTPS/H2 policy retained another target's work");
  Expect(scenario.accept_h2_push(),
         "HTTPS/H2 policy discarded its accepted-push mode");
  Expect(scenario.options_size() == 2 &&
             scenario.options(0).option_id() ==
                 curl::fuzzer::proto::CURLOPT_POST &&
             scenario.options(1).option_id() ==
                 curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION,
         "HTTPS/H2 policy retained an option that can bypass fixed ALPN h2");
}

void TestFastHttp2Policy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTPS, 4096, 17);
  scenario.set_host_path("mutated.invalid:8443/path?query#fragment");
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);
  scenario.set_crl_file("TLS-only input");
  scenario.set_accept_h2_push(true);
  scenario.mutable_connection()->set_initial_response("competing raw frames");
  scenario.mutable_http2_plan()
      ->add_actions()
      ->mutable_headers()
      ->set_status_code(200);
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_SSL_ENABLE_ALPN);
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp2);

  Expect(scenario.scheme() == SCHEME_HTTP,
         "fast HTTP/2 policy did not force plaintext HTTP");
  Expect(scenario.host_path() == "tls.test/path?query#fragment",
         "fast HTTP/2 policy did not isolate its socketpair authority");
  Expect(scenario.tls_certificate_chain() ==
                 curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC &&
             scenario.crl_file().empty(),
         "fast HTTP/2 policy retained TLS-only server or file state");
  Expect(scenario.accept_h2_push() && scenario.has_http2_plan(),
         "fast HTTP/2 policy discarded H2 origin work");
  Expect(scenario.connection().initial_response().empty() &&
             !scenario.connection().has_backpressure(),
         "fast HTTP/2 policy retained competing raw or timed response work");
  Expect(scenario.options_size() == 1 && scenario.options(0).option_id() ==
                                             curl::fuzzer::proto::CURLOPT_POST,
         "fast HTTP/2 policy retained an option that can bypass "
         "prior-knowledge H2");
}

void TestTlsPoliciesRejectUnknownCertificateChain() {
  constexpr TargetProfile kTlsPolicies[] = {
      TargetProfile::kFastHttps,
      TargetProfile::kHttpsH2,
      TargetProfile::kFastHttp3,
  };
  for (const TargetProfile profile : kTlsPolicies) {
    Scenario scenario;
    scenario.set_tls_certificate_chain(
        static_cast<curl::fuzzer::proto::TlsCertificateChainProfile>(99));

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.tls_certificate_chain() ==
               curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC,
           "a TLS policy retained an unknown certificate-chain selector");
  }
}

void TestFastHttp3PolicyMaterializesUsefulPlan() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("mutated.example:8443/a/path?query#fragment");
  scenario.add_request_headers("X-H3: retained");
  scenario.add_subsequent_connections()->set_initial_response(
      "ignored stream response");
  scenario.mutable_mime_post()->add_parts()->set_data("mime sentinel");
  scenario.mutable_upload()->set_data("upload sentinel");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);
  scenario.mutable_http3_plan();

  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_CONNECT_ONLY);
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp3);

  Expect(scenario.scheme() == SCHEME_HTTPS,
         "fast HTTP/3 policy did not force HTTPS");
  Expect(scenario.host_path() == "tls.test/a/path?query#fragment",
         "fast HTTP/3 policy did not retain the URL suffix");
  Expect(!scenario.has_connection() &&
             scenario.subsequent_connections_size() == 0,
         "fast HTTP/3 policy retained stream-socket response scripts");
  Expect(scenario.request_headers_size() == 1 && scenario.has_mime_post() &&
             scenario.has_upload(),
         "fast HTTP/3 policy removed request-side HTTP state");
  Expect(scenario.telnet_options_size() == 0 && !scenario.has_api_plan() &&
             !scenario.has_multi_plan(),
         "fast HTTP/3 policy retained another target's work");
  Expect(scenario.tls_certificate_chain() ==
             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES,
         "fast HTTP/3 policy discarded its certificate-chain selector");
  Expect(scenario.options_size() == 1 && scenario.options(0).option_id() ==
                                             curl::fuzzer::proto::CURLOPT_POST,
         "fast HTTP/3 policy retained transport-breaking options");
  Expect(scenario.has_http3_plan() && scenario.http3_plan().actions_size() == 1,
         "fast HTTP/3 policy did not materialize a default peer action");
  const auto &response = scenario.http3_plan().actions(0).structured_response();
  Expect(response.status_code() == 200 && response.finish_stream(),
         "fast HTTP/3 default action is not a finished 200 response");
}

void TestFastHttp3ProxyPolicyRetainsStreamScript() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.mutable_connection()->set_initial_response("proxy response");
  scenario.add_subsequent_connections()->set_initial_response("ignored");
  auto *plan = scenario.mutable_http3_plan();
  plan->set_use_h1_connect_udp_proxy(true);
  plan->add_actions()->mutable_structured_response();

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp3);

  Expect(scenario.scheme() == SCHEME_HTTPS && scenario.has_connection(),
         "HTTP/3 proxy policy discarded its stream response");
  Expect(scenario.connection().initial_response() == "proxy response" &&
             scenario.subsequent_connections_size() == 0,
         "HTTP/3 proxy policy did not bound its one proxy connection");
  Expect(scenario.http3_plan().use_h1_connect_udp_proxy() &&
             scenario.http3_plan().actions_size() == 0,
         "HTTP/3 proxy policy retained direct-peer actions");
}

void TestFastHttp3PolicyBoundsOrderedActions() {
  Scenario scenario;
  auto *plan = scenario.mutable_http3_plan();

  auto *response = plan->add_actions()->mutable_structured_response();
  response->set_status_code(700);
  auto *first_header = response->add_response_headers();
  first_header->set_name(":Bad NAME");
  first_header->set_value(std::string("ok\r\n\0bad\x7f", 9));
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxHttp3Headers + 4; ++index) {
    auto *header = response->add_response_headers();
    header->set_name(std::string(
        proto_fuzzer::scenario_limits::kMaxHttp3HeaderNameBytes + 8, 'N'));
    header->set_value(std::string(
        proto_fuzzer::scenario_limits::kMaxHttp3HeaderValueBytes + 8, 'v'));
  }
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxHttp3Trailers + 4; ++index) {
    auto *trailer = response->add_response_trailers();
    trailer->set_name("X-Trailer");
    trailer->set_value("value");
  }
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxHttp3BodyChunks + 4;
       ++index) {
    response->add_body_chunks(std::string(
        proto_fuzzer::scenario_limits::kMaxHttp3BodyBytes + 8, 'b'));
  }

  auto *write = plan->add_actions()->mutable_stream_write();
  write->set_role(static_cast<curl::fuzzer::proto::Http3StreamRole>(99));
  write->set_data(std::string(
      proto_fuzzer::scenario_limits::kMaxHttp3RawWriteBytes + 8, 'r'));
  write->set_finish_stream(true);

  auto *opened_stream =
      plan->add_actions()->mutable_open_unidirectional_stream();
  opened_stream->set_data(std::string(
      proto_fuzzer::scenario_limits::kMaxHttp3RawWriteBytes + 8, 'u'));
  opened_stream->set_finish_stream(true);

  auto *reset = plan->add_actions()->mutable_stream_reset();
  reset->set_role(static_cast<curl::fuzzer::proto::Http3StreamRole>(99));
  reset->set_application_error_code(std::numeric_limits<std::uint64_t>::max());
  plan->add_actions()->mutable_goaway()->set_id(
      std::numeric_limits<std::uint64_t>::max());
  plan->add_actions();
  while (static_cast<std::size_t>(plan->actions_size()) <
         proto_fuzzer::scenario_limits::kMaxHttp3Actions - 1) {
    plan->add_actions()->mutable_stream_write()->set_data("suffix");
  }
  plan->add_actions()->mutable_connection_close()->set_application_error_code(
      std::numeric_limits<std::uint64_t>::max());
  for (int index = 0; index < 4; ++index) {
    plan->add_actions()->mutable_stream_write()->set_data("ignored suffix");
  }

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp3);

  Expect(static_cast<std::size_t>(scenario.http3_plan().actions_size()) ==
             proto_fuzzer::scenario_limits::kMaxHttp3Actions,
         "fast HTTP/3 policy retained actions beyond its operation budget");
  const auto &bounded_response =
      scenario.http3_plan().actions(0).structured_response();
  Expect(bounded_response.status_code() == 300,
         "fast HTTP/3 policy did not fold status into 100..599");
  Expect(bounded_response.response_headers(0).name() == "-bad-name",
         "fast HTTP/3 policy did not canonicalize a field name");
  Expect(bounded_response.response_headers(0).value() ==
             std::string("ok   bad ", 9),
         "fast HTTP/3 policy retained controls in a field value");
  Expect(
      static_cast<std::size_t>(bounded_response.response_headers_size()) <=
              proto_fuzzer::scenario_limits::kMaxHttp3Headers &&
          static_cast<std::size_t>(bounded_response.response_trailers_size()) <=
              proto_fuzzer::scenario_limits::kMaxHttp3Trailers,
      "fast HTTP/3 policy retained too many fields");

  std::size_t body_bytes = 0;
  for (const std::string &chunk : bounded_response.body_chunks()) {
    body_bytes += chunk.size();
  }
  Expect(static_cast<std::size_t>(bounded_response.body_chunks_size()) ==
                 proto_fuzzer::scenario_limits::kMaxHttp3BodyChunks &&
             body_bytes == proto_fuzzer::scenario_limits::kMaxHttp3BodyBytes,
         "fast HTTP/3 policy did not apply its body budgets");

  const auto &bounded_write = scenario.http3_plan().actions(1).stream_write();
  Expect(bounded_write.role() == curl::fuzzer::proto::HTTP3_STREAM_RESPONSE &&
             bounded_write.data().size() ==
                 proto_fuzzer::scenario_limits::kMaxHttp3RawWriteBytes &&
             bounded_write.finish_stream(),
         "fast HTTP/3 policy did not bound a raw write in place");
  const auto &bounded_open =
      scenario.http3_plan().actions(2).open_unidirectional_stream();
  Expect(bounded_open.data().size() ==
                 proto_fuzzer::scenario_limits::kMaxHttp3RawWriteBytes &&
             bounded_open.finish_stream(),
         "fast HTTP/3 policy did not bound a fresh raw stream in place");
  const std::uint64_t max_quic_varint =
      proto_fuzzer::scenario_limits::kMaxQuicVarint;
  const auto &bounded_reset = scenario.http3_plan().actions(3).stream_reset();
  Expect(bounded_reset.role() == curl::fuzzer::proto::HTTP3_STREAM_RESPONSE &&
             bounded_reset.application_error_code() == max_quic_varint,
         "fast HTTP/3 policy did not canonicalize a stream reset");
  Expect(scenario.http3_plan().actions(4).goaway().id() ==
             (max_quic_varint & ~std::uint64_t{3}),
         "fast HTTP/3 policy did not canonicalize a GOAWAY stream ID");
  Expect(scenario.http3_plan()
                 .actions(static_cast<int>(
                     proto_fuzzer::scenario_limits::kMaxHttp3Actions - 1))
                 .connection_close()
                 .application_error_code() == max_quic_varint,
         "fast HTTP/3 policy did not bound a connection-close error");
  const auto &defaulted =
      scenario.http3_plan().actions(5).structured_response();
  Expect(defaulted.status_code() == 200 && defaulted.finish_stream(),
         "fast HTTP/3 policy left an empty ordered action inert");
}

void TestNonHttp3PoliciesDiscardPlans() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp,      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,     TargetProfile::kHttpsH2,
      TargetProfile::kFastHttp2,     TargetProfile::kH2Proxy,
      TargetProfile::kFastWebSocket, TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,    TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,      TargetProfile::kApi,
      TargetProfile::kMulti,         TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.mutable_http3_plan()
        ->add_actions()
        ->mutable_structured_response()
        ->set_status_code(204);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(!scenario.has_http3_plan(),
           "a non-HTTP/3 policy retained QUIC-peer work");
  }
}

void TestNonHttpsPoliciesDiscardTlsCertificateChains() {
  constexpr TargetProfile kNonHttpsPolicies[] = {
      TargetProfile::kFastHttp,      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttp2,     TargetProfile::kH2Proxy,
      TargetProfile::kFastWebSocket, TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,    TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,      TargetProfile::kApi,
      TargetProfile::kMulti,         TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kNonHttpsPolicies) {
    Scenario scenario;
    scenario.set_host_path("example.test/");
    scenario.set_tls_certificate_chain(
        curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.tls_certificate_chain() ==
               curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC,
           "a non-HTTPS policy retained TLS certificate-chain work");
  }
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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kH2Proxy);

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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastTelnet);

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
  auto *ftp_port = scenario.add_options();
  ftp_port->set_option_id(curl::fuzzer::proto::CURLOPT_FTPPORT);
  ftp_port->set_string_value("untrusted.invalid");
  auto *use_eprt = scenario.add_options();
  use_eprt->set_option_id(curl::fuzzer::proto::CURLOPT_FTP_USE_EPRT);
  use_eprt->set_uint_value(7);
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastFtp);

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
         "fast FTP policy exceeded its data-channel budget");
  Expect(!scenario.subsequent_connections(0).has_backpressure() &&
             scenario.subsequent_connections(0).server_frames_size() == 0,
         "fast FTP policy retained ignored data-channel controls");
  Expect(scenario.options_size() == 5,
         "fast FTP policy retained a non-FTP option");
  Expect(scenario.options(0).uint_value() < 3 &&
             scenario.options(1).uint_value() < 4,
         "fast FTP policy left small enums outside curl's valid domains");
  Expect(scenario.options(2).string_value() == "127.0.0.1",
         "fast FTP policy retained a resolving active-mode address");
  Expect(scenario.options(3).uint_value() == 1,
         "fast FTP policy did not canonicalize the EPRT selector");
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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastTftp);

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

void TestResolverPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("untrusted.invalid:8080/path?query#fragment");
  scenario.set_socks_proxy_mode(curl::fuzzer::proto::SOCKS_PROXY_SOCKS4A);
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.mutable_mime_post()->add_parts()->set_data("ignored");
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxResolveEntries + 3; ++index) {
    scenario.add_resolve_entries(std::string(
        proto_fuzzer::scenario_limits::kMaxResolveEntryBytes + 11, 'r'));
  }

  NormalizeScenarioForTarget(&scenario, TargetProfile::kResolver);

  Expect(scenario.scheme() == SCHEME_HTTP,
         "resolver policy did not force plaintext HTTP");
  Expect(scenario.host_path() == "resolve.test/path?query#fragment",
         "resolver policy did not select the cache-backed authority");
  Expect(static_cast<std::size_t>(scenario.resolve_entries_size()) ==
             proto_fuzzer::scenario_limits::kMaxResolveEntries,
         "resolver policy retained entries beyond its slist budget");
  Expect(scenario.resolve_entries(0).size() ==
             proto_fuzzer::scenario_limits::kMaxResolveEntryBytes,
         "resolver policy retained an invisible entry suffix");
  Expect(!scenario.has_api_plan() && !scenario.has_multi_plan() &&
             !scenario.has_mime_post() &&
             scenario.socks_proxy_mode() ==
                 curl::fuzzer::proto::SOCKS_PROXY_SOCKS4,
         "resolver policy retained another dedicated lane's shape");

  Scenario localhost;
  localhost.set_host_path("untrusted.invalid/no-cache");
  NormalizeScenarioForTarget(&localhost, TargetProfile::kResolver);
  Expect(localhost.host_path() == "localhost/no-cache",
         "empty resolver policy did not retain the localhost path");

  Scenario ordinary;
  ordinary.add_resolve_entries("example.test:80:127.0.0.1");
  NormalizeScenarioForTarget(&ordinary, TargetProfile::kFastHttp);
  Expect(ordinary.resolve_entries_size() == 0,
         "non-resolver policy retained structured DNS work");
}

void TestPauseTerminalIsTelnetOnly() {
  Scenario telnet;
  telnet.mutable_upload()->set_terminal(
      curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE);
  NormalizeScenarioForTarget(&telnet, TargetProfile::kFastTelnet);
  Expect(telnet.upload().terminal() ==
             curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE,
         "TELNET policy removed its synchronous pause outcome");

  Scenario http;
  http.mutable_upload()->set_terminal(
      curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE);
  http.add_telnet_options("TTYPE=must-be-discarded");
  NormalizeScenarioForTarget(&http, TargetProfile::kDeepHttp);
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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kDeepHttp);

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
  NormalizeScenarioForTarget(&byte_budget, TargetProfile::kFastTelnet);
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
  NormalizeScenarioForTarget(&exact_budget, TargetProfile::kFastTelnet);
  Expect(exact_budget.connection().on_readable_size() == 0,
         "fast TELNET policy retained an empty budget-exhausted chunk");

  Scenario control_budget;
  control_budget.mutable_connection()->set_initial_response(
      std::string(proto_fuzzer::scenario_limits::kMaxTelnetControlBytes,
                  '\xff') +
      "prefix");
  control_budget.mutable_connection()->add_on_readable("\xffsuffix");
  NormalizeScenarioForTarget(&control_budget, TargetProfile::kFastTelnet);
  Expect(control_budget.connection().initial_response().size() ==
             proto_fuzzer::scenario_limits::kMaxTelnetControlBytes + 6,
         "fast TELNET policy retained reply-amplifying control bytes");
  Expect(control_budget.connection().on_readable_size() == 0,
         "fast TELNET policy retained bytes after the control budget");
}

void TestTimingPolicyMapsSecureSchemesToPlaintext() {
  Scenario https = ScenarioWithBackpressure(SCHEME_HTTPS, 2048, 1);
  NormalizeScenarioForTarget(&https, TargetProfile::kTiming);
  Expect(https.scheme() == SCHEME_HTTP,
         "timing policy did not map HTTPS to HTTP");

  Scenario wss = ScenarioWithBackpressure(SCHEME_WSS, 2048, 1);
  NormalizeScenarioForTarget(&wss, TargetProfile::kTiming);
  Expect(wss.scheme() == SCHEME_WS, "timing policy did not map WSS to WS");
}

void TestTimingPolicySuppliesBackpressureForZeroConfig() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 0, 0);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kTiming);

  Expect(scenario.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy did not supply the minimum receive buffer");
  Expect(scenario.connection().backpressure().drain_limit() == 0,
         "timing policy changed the unlimited-drain sentinel");
}

void TestTimingPolicyPreservesMeaningfulBoundaries() {
  Scenario minimum = ScenarioWithBackpressure(SCHEME_HTTP, 2048, 1);
  NormalizeScenarioForTarget(&minimum, TargetProfile::kTiming);
  Expect(minimum.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy changed the minimum effective receive buffer");
  Expect(minimum.connection().backpressure().drain_limit() == 1,
         "timing policy changed the minimum drain limit");

  Scenario maximum = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 1024);
  NormalizeScenarioForTarget(&maximum, TargetProfile::kTiming);
  Expect(maximum.connection().backpressure().recv_buf_bytes() == 4096,
         "timing policy changed the maximum receive buffer");
  Expect(maximum.connection().backpressure().drain_limit() == 1024,
         "timing policy changed the maximum drain limit");

  Scenario drain_only = ScenarioWithBackpressure(SCHEME_HTTP, 0, 512);
  NormalizeScenarioForTarget(&drain_only, TargetProfile::kTiming);
  Expect(drain_only.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy did not make a drain-only config exert pressure");
  Expect(drain_only.connection().backpressure().drain_limit() == 512,
         "timing policy changed an in-range drain limit");
}

void TestTimingPolicyClampsIneffectiveValues() {
  Scenario too_small = ScenarioWithBackpressure(SCHEME_HTTP, 1, 0);
  NormalizeScenarioForTarget(&too_small, TargetProfile::kTiming);
  Expect(too_small.connection().backpressure().recv_buf_bytes() == 2048,
         "timing policy retained a receive buffer below the platform floor");
  Expect(too_small.connection().backpressure().drain_limit() == 0,
         "timing policy changed the unlimited-drain sentinel");

  constexpr std::uint32_t kAboveIntMax =
      static_cast<std::uint32_t>(std::numeric_limits<int>::max()) + 1U;
  Scenario too_large = ScenarioWithBackpressure(
      SCHEME_HTTP, kAboveIntMax, std::numeric_limits<std::uint32_t>::max());
  NormalizeScenarioForTarget(&too_large, TargetProfile::kTiming);
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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kTiming);

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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kDeepHttp);

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
  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp);
  NormalizeScenarioForTarget(&deep, TargetProfile::kDeepHttp);

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

void TestFastHttpKeepsOnlyOwnedHttpVersions() {
  struct VersionCase {
    std::uint64_t input;
    std::uint64_t expected;
  };
  constexpr VersionCase kCases[] = {
      {CURL_HTTP_VERSION_NONE, CURL_HTTP_VERSION_NONE},
      {CURL_HTTP_VERSION_1_0, CURL_HTTP_VERSION_1_0},
      {CURL_HTTP_VERSION_1_1, CURL_HTTP_VERSION_1_1},
      {CURL_HTTP_VERSION_2_0, CURL_HTTP_VERSION_2_0},
      {CURL_HTTP_VERSION_2TLS, CURL_HTTP_VERSION_2TLS},
      {CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE, CURL_HTTP_VERSION_NONE},
      {CURL_HTTP_VERSION_3, CURL_HTTP_VERSION_NONE},
      {CURL_HTTP_VERSION_3ONLY, CURL_HTTP_VERSION_NONE},
      {CURL_HTTP_VERSION_LAST, CURL_HTTP_VERSION_NONE},
      {std::numeric_limits<std::uint64_t>::max(), CURL_HTTP_VERSION_NONE},
  };

  Scenario scenario;
  for (const auto &test_case : kCases) {
    auto *option = scenario.add_options();
    option->set_option_id(curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
    option->set_uint_value(test_case.input);
  }
  auto *bool_value = scenario.add_options();
  bool_value->set_option_id(curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
  bool_value->set_bool_value(true);
  auto *false_value = scenario.add_options();
  false_value->set_option_id(curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
  false_value->set_bool_value(false);
  auto *string_value = scenario.add_options();
  string_value->set_option_id(curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
  string_value->set_string_value("invalid");
  scenario.add_options()->set_option_id(
      curl::fuzzer::proto::CURLOPT_HTTP_VERSION);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp);

  for (std::size_t index = 0; index < sizeof(kCases) / sizeof(kCases[0]);
       ++index) {
    Expect(scenario.options(static_cast<int>(index)).uint_value() ==
               kCases[index].expected,
           "fast HTTP policy retained an unowned HTTP version");
  }
  const int malformed_start =
      static_cast<int>(sizeof(kCases) / sizeof(kCases[0]));
  Expect(scenario.options(malformed_start).uint_value() ==
             CURL_HTTP_VERSION_1_0,
         "fast HTTP policy did not canonicalize a boolean HTTP version");
  Expect(scenario.options(malformed_start + 1).uint_value() ==
             CURL_HTTP_VERSION_NONE,
         "fast HTTP policy did not canonicalize a false HTTP version");
  Expect(scenario.options(malformed_start + 2).uint_value() ==
             CURL_HTTP_VERSION_NONE,
         "fast HTTP policy did not canonicalize a string HTTP version");
  Expect(scenario.options(malformed_start + 3).uint_value() ==
             CURL_HTTP_VERSION_NONE,
         "fast HTTP policy did not canonicalize an unset HTTP version");
  const std::string normalized = scenario.SerializeAsString();
  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp);
  Expect(scenario.SerializeAsString() == normalized,
         "fast HTTP version normalization was not idempotent");
}

void TestFastHttpFiltersBeforeApplyingOptionBound() {
  Scenario scenario;
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxOptions + 5; ++index) {
    scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  }
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_USERAGENT);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp);

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
  plan->set_pause_response_once(true);
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
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxApiReentrantSelectors + 3;
       ++index) {
    plan->add_reentrant_probe_selectors(static_cast<std::uint32_t>(index + 300));
  }
  NormalizeScenarioForTarget(&scenario, TargetProfile::kApi);

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
             scenario.api_plan().wake_multi() &&
             scenario.api_plan().pause_response_once(),
         "API policy changed mutation-controlled lifecycle choices");
  Expect(static_cast<std::size_t>(
             scenario.api_plan().share_data_selectors_size()) ==
             proto_fuzzer::scenario_limits::kMaxApiShareDataSelectors,
         "API policy retained too many share-data selectors");
  Expect(static_cast<std::size_t>(
             scenario.api_plan().easy_info_selectors_size()) ==
             proto_fuzzer::scenario_limits::kMaxApiInfoSelectors,
         "API policy retained too many typed getinfo selectors");
  Expect(static_cast<std::size_t>(
             scenario.api_plan().reentrant_probe_selectors_size()) ==
             proto_fuzzer::scenario_limits::kMaxApiReentrantSelectors,
         "API policy retained too many reentrancy probes");
  Expect(scenario.api_plan().share_data_selectors(0) == 100 &&
             scenario.api_plan().easy_info_selectors(0) == 200 &&
             scenario.api_plan().reentrant_probe_selectors(0) == 300,
         "API policy changed the retained selector prefix");
}

void TestProtocolPoliciesDiscardApiPlans() {
  constexpr TargetProfile kProtocolPolicies[] = {
      TargetProfile::kFastHttp,
      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,
      TargetProfile::kHttpsH2,
      TargetProfile::kFastHttp2,
      TargetProfile::kFastHttp3,
      TargetProfile::kH2Proxy,
      TargetProfile::kFastWebSocket,
      TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,
      TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,
      TargetProfile::kMulti,
      TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kProtocolPolicies) {
    Scenario scenario;
    scenario.set_host_path("example.test/");
    scenario.mutable_api_plan()->set_duplicate_easy(true);
    scenario.mutable_api_plan()->add_easy_info_selectors(7);

    NormalizeScenarioForTarget(&scenario, profile);

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

  NormalizeScenarioForTarget(&scenario, TargetProfile::kMulti);

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
      TargetProfile::kFastHttp,
      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,
      TargetProfile::kHttpsH2,
      TargetProfile::kFastHttp2,
      TargetProfile::kFastHttp3,
      TargetProfile::kH2Proxy,
      TargetProfile::kFastWebSocket,
      TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,
      TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,
      TargetProfile::kApi,
      TargetProfile::kTiming,
  };
  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path("example.test/");
    scenario.mutable_multi_plan()->set_transfer_count(4);
    NormalizeScenarioForTarget(&scenario, profile);
    Expect(!scenario.has_multi_plan(),
           "a non-multi policy retained concurrent-handle work");
  }
}

void TestApiEasyDrivesDropMultiOnlyWork() {
  constexpr curl::fuzzer::proto::ApiDriveMode kEasyModes[] = {
      curl::fuzzer::proto::API_DRIVE_EASY_PERFORM,
      curl::fuzzer::proto::API_DRIVE_EASY_EVENTS,
      curl::fuzzer::proto::API_DRIVE_CONNECT_ONLY,
  };
  for (const auto drive_mode : kEasyModes) {
    Scenario scenario;
    scenario.mutable_api_plan()->set_drive_mode(drive_mode);
    scenario.mutable_api_plan()->set_wake_multi(true);
    scenario.mutable_api_plan()->set_pause_response_once(true);

    NormalizeScenarioForTarget(&scenario, TargetProfile::kApi);

    Expect(scenario.api_plan().drive_mode() == drive_mode,
           "API policy changed the selected easy entrypoint");
    Expect(!scenario.api_plan().wake_multi(),
           "easy drive retained a multi-only wakeup mutation");
    Expect(!scenario.api_plan().pause_response_once(),
           "blocking easy drive retained an unresumable output pause");
  }
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
  Expect(RunModeFor(TargetProfile::kHttpsH2) ==
             ScenarioRunMode::kTlsHttp2Coverage,
         "HTTPS/H2 profile does not authorize its fixed-ALPN origin peer");
  Expect(
      RunModeFor(TargetProfile::kFastHttp2) == ScenarioRunMode::kHttp2Coverage,
      "fast HTTP/2 profile does not authorize its prior-knowledge origin peer");
  Expect(RunModeFor(TargetProfile::kFastHttp3) ==
             ScenarioRunMode::kHttp3Coverage,
         "fast HTTP/3 profile does not authorize the QUIC peer");
  Expect(RunModeFor(TargetProfile::kH2Proxy) ==
             ScenarioRunMode::kH2ProxyCoverage,
         "HTTP/2 proxy profile does not authorize its CONNECT peer");
  Expect(RunModeFor(TargetProfile::kSocks4) == ScenarioRunMode::kSocks4Coverage,
         "SOCKS4 profile does not authorize its proxy peer");
  Expect(RunModeFor(TargetProfile::kResolver) ==
             ScenarioRunMode::kResolverCoverage,
         "resolver profile does not authorize DNS/cache work");
  Expect(RunModeFor(TargetProfile::kFastFtp) == ScenarioRunMode::kFtpCoverage,
         "fast FTP profile does not authorize the two-channel peer");
  Expect(RunModeFor(TargetProfile::kFastTftp) == ScenarioRunMode::kTftpCoverage,
         "fast TFTP profile does not authorize the UDP peer");
  Expect(RunModeFor(TargetProfile::kDeepHttp) ==
             ScenarioRunMode::kDeepHttpCoverage,
         "deep HTTP profile does not authorize filename-parser inputs");

  constexpr TargetProfile kCoverageProfiles[] = {
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
  scenario.set_accept_h2_push(true);
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);
  scenario.mutable_http3_plan()
      ->add_actions()
      ->mutable_stream_write()
      ->set_data("compatibility H3 bytes");
  scenario.add_request_headers("X-Compatibility: retained");
  auto *mismatched = scenario.add_options();
  mismatched->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  mismatched->set_uint_value(7);
  auto *pin = scenario.add_options();
  pin->set_option_id(curl::fuzzer::proto::CURLOPT_PINNEDPUBLICKEY);
  pin->set_string_value(
      std::string(proto_fuzzer::scenario_limits::kMaxMetadataBytes + 17, 'p'));
  const std::string before = scenario.SerializeAsString();

  NormalizeScenarioForTarget(&scenario, TargetProfile::kCompatibility);

  Expect(scenario.SerializeAsString() == before,
         "compatibility profile changed an accumulated-corpus input");
}

void TestNonH2OriginPoliciesDiscardAcceptedPushMode() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp,
      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,
      TargetProfile::kFastHttp3,
      TargetProfile::kH2Proxy,
      TargetProfile::kFastWebSocket,
      TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,
      TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,
      TargetProfile::kFastGopher,
      TargetProfile::kSocks4,
      TargetProfile::kResolver,
      TargetProfile::kApi,
      TargetProfile::kMulti,
      TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_accept_h2_push(true);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(!scenario.accept_h2_push(),
           "a non-H2-origin policy retained accepted-push work");
  }
}

void TestGeneratedMimePolicyPreservesBoundariesAndSharesBudget() {
  constexpr std::uint32_t kBoundarySizes[] = {
      16 * 1024 - 1,
      16 * 1024,
      16 * 1024 + 1,
      // Quoted printable expands an '=' pattern by three, putting these
      // values around the same 64 KiB encoded-output boundary.
      21845 - 1,
      21845,
      21845 + 1,
      32 * 1024 - 1,
      32 * 1024,
      32 * 1024 + 1,
      64 * 1024 - 1,
      64 * 1024,
      64 * 1024 + 1,
  };
  for (const std::uint32_t size : kBoundarySizes) {
    Scenario scenario;
    auto *generated =
        scenario.mutable_mime_post()->add_parts()->mutable_generated_data();
    generated->set_pattern("=");
    generated->set_repeat_count(size);

    NormalizeScenarioForTarget(&scenario, TargetProfile::kDeepHttp);

    Expect(scenario.mime_post().parts(0).generated_data().repeat_count() ==
               size,
           "generated MIME policy folded an observable buffer boundary");
  }

  Scenario shared;
  auto *first =
      shared.mutable_mime_post()->add_parts()->mutable_generated_data();
  first->set_pattern(std::string(
      proto_fuzzer::scenario_limits::kMaxGeneratedMimePatternBytes + 23, 'a'));
  first->set_repeat_count(std::numeric_limits<std::uint32_t>::max());
  auto *parent = shared.mutable_mime_post()->add_parts();
  auto *second =
      parent->mutable_subparts()->add_parts()->mutable_generated_data();
  second->set_pattern("b");
  second->set_repeat_count(std::numeric_limits<std::uint32_t>::max());
  auto *third =
      parent->mutable_subparts()->add_parts()->mutable_generated_data();
  third->set_pattern("c");
  third->set_repeat_count(std::numeric_limits<std::uint32_t>::max());

  NormalizeScenarioForTarget(&shared, TargetProfile::kDeepHttp);

  const auto &bounded_first = shared.mime_post().parts(0).generated_data();
  const auto &bounded_second =
      shared.mime_post().parts(1).subparts().parts(0).generated_data();
  const auto &bounded_third =
      shared.mime_post().parts(1).subparts().parts(1).generated_data();
  Expect(bounded_first.pattern().size() ==
             proto_fuzzer::scenario_limits::kMaxGeneratedMimePatternBytes,
         "generated MIME policy retained an oversized pattern");
  const std::size_t total =
      bounded_first.pattern().size() * bounded_first.repeat_count() +
      bounded_second.pattern().size() * bounded_second.repeat_count() +
      bounded_third.pattern().size() * bounded_third.repeat_count();
  Expect(total <= proto_fuzzer::scenario_limits::kMaxGeneratedMimeDataBytes,
         "generated MIME policy exceeded its shared materialization budget");
  Expect(
      total == proto_fuzzer::scenario_limits::kMaxGeneratedMimeDataBytes,
      "generated MIME policy discarded a usable byte inside its shared budget");
  Expect(
      bounded_third.repeat_count() == 0,
      "generated MIME policy retained work after exhausting its shared budget");

  Scenario empty_pattern;
  auto *empty =
      empty_pattern.mutable_mime_post()->add_parts()->mutable_generated_data();
  empty->set_repeat_count(std::numeric_limits<std::uint32_t>::max());
  NormalizeScenarioForTarget(&empty_pattern, TargetProfile::kDeepHttp);
  Expect(empty_pattern.mime_post().parts(0).generated_data().repeat_count() ==
             0,
         "empty generated MIME pattern retained an ineffective repeat count");
}

void TestHttpsH2PolicyBoundsStructuredPlan() {
  Scenario scenario;
  scenario.mutable_connection()->set_initial_response("raw");
  scenario.mutable_connection()->add_on_readable("raw chunk");
  auto *plan = scenario.mutable_http2_plan();
  auto *enable_push = plan->mutable_initial_settings()->add_entries();
  enable_push->set_identifier(2);
  enable_push->set_value(8);
  auto *initial_window = plan->mutable_initial_settings()->add_entries();
  initial_window->set_identifier(4);
  initial_window->set_value(std::numeric_limits<std::uint32_t>::max());
  auto *frame_size = plan->mutable_initial_settings()->add_entries();
  frame_size->set_identifier(5);
  frame_size->set_value(0);

  auto *headers = plan->add_actions()->mutable_headers();
  headers->set_status_code(std::numeric_limits<std::uint32_t>::max());
  headers->mutable_stream()->set_request_index(99);
  auto *field = headers->add_fields();
  field->set_name("X Bad\r\n");
  field->set_value("value\0control", 13);
  plan->add_actions()->set_yield_turns(1000);
  for (std::size_t index = plan->actions_size();
       index < proto_fuzzer::scenario_limits::kMaxHttp2Actions + 8; ++index) {
    plan->add_actions()->mutable_ping()->set_opaque_data("0123456789abcdef");
  }

  NormalizeScenarioForTarget(&scenario, TargetProfile::kHttpsH2);

  Expect(scenario.connection().initial_response().empty() &&
             scenario.connection().on_readable().empty(),
         "structured H2 policy retained competing raw response bytes");
  Expect(static_cast<std::size_t>(scenario.http2_plan().actions_size()) ==
             proto_fuzzer::scenario_limits::kMaxHttp2Actions,
         "structured H2 policy retained an oversized action suffix");
  Expect(scenario.http2_plan().initial_settings().entries(0).identifier() ==
                 2 &&
             scenario.http2_plan().initial_settings().entries(0).value() <= 1,
         "structured H2 policy retained an invalid ENABLE_PUSH setting");
  Expect(scenario.http2_plan().initial_settings().entries(1).identifier() ==
                 4 &&
             scenario.http2_plan().initial_settings().entries(1).value() <=
                 0x7fffffffU,
         "structured H2 policy retained an invalid initial window");
  Expect(
      scenario.http2_plan().initial_settings().entries(2).identifier() == 5 &&
          scenario.http2_plan().initial_settings().entries(2).value() >= 16384U,
      "structured H2 policy retained an invalid maximum frame size");
  Expect(scenario.http2_plan().actions(0).headers().stream().request_index() <
                 16 &&
             scenario.http2_plan().actions(0).headers().status_code() >= 100 &&
             scenario.http2_plan().actions(0).headers().status_code() <= 599 &&
             scenario.http2_plan().actions(0).headers().fields(0).name() ==
                 "x-bad--",
         "structured H2 policy did not canonicalize a response header");
  Expect(scenario.http2_plan().actions(1).yield_turns() ==
             proto_fuzzer::scenario_limits::kMaxHttp2YieldTurns,
         "structured H2 policy retained an excessive yield count");

  Scenario other;
  other.mutable_http2_plan()->add_actions()->mutable_headers();
  NormalizeScenarioForTarget(&other, TargetProfile::kFastHttp);
  Expect(!other.has_http2_plan(),
         "non-H2 profile retained a structured H2 plan");
}

void TestH2NormalizationPreservesValidSettings() {
  constexpr TargetProfile kH2Profiles[] = {TargetProfile::kHttpsH2,
                                         TargetProfile::kFastHttp2};
  for (const TargetProfile profile : kH2Profiles) {
    Scenario scenario;
    auto *settings = scenario.mutable_http2_plan()->mutable_initial_settings();
    for (const auto identifier : {1U, 2U, 3U, 4U, 6U, 8U, 9U}) {
      auto *entry = settings->add_entries();
      entry->set_identifier(identifier);
      entry->set_value(
          identifier == 2U || identifier == 8U || identifier == 9U ? 1U : 0U);
    }
    for (const auto frame_size : {16384U, 16385U, 65535U, 0x00ffffffU}) {
      auto *entry = settings->add_entries();
      entry->set_identifier(5U);
      entry->set_value(frame_size);
    }
    for (const auto identifier : {7U, 0xffffU}) {
      auto *entry = settings->add_entries();
      entry->set_identifier(identifier);
      entry->set_value(std::numeric_limits<std::uint32_t>::max());
    }
    const std::string initial_settings = settings->SerializeAsString();
    auto *action_settings =
        scenario.mutable_http2_plan()->add_actions()->mutable_settings();
    *action_settings = *settings;

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.http2_plan().initial_settings().SerializeAsString() ==
               initial_settings,
           "H2 normalization changed valid initial SETTINGS");
    Expect(scenario.http2_plan().actions(0).settings().SerializeAsString() ==
               initial_settings,
           "H2 normalization changed valid action SETTINGS");
  }
}

void TestH2NormalizationCanonicalizesSettingsWireWidth() {
  constexpr TargetProfile kH2Profiles[] = {TargetProfile::kHttpsH2,
                                           TargetProfile::kFastHttp2};
  for (const TargetProfile profile : kH2Profiles) {
    Scenario scenario;
    auto *extension = scenario.mutable_http2_plan()
                          ->mutable_initial_settings()
                          ->add_entries();
    extension->set_identifier(0x10007U);
    extension->set_value(std::numeric_limits<std::uint32_t>::max());
    auto *enable_connect = scenario.mutable_http2_plan()
                               ->mutable_initial_settings()
                               ->add_entries();
    enable_connect->set_identifier(0x10008U);
    enable_connect->set_value(8U);

    NormalizeScenarioForTarget(&scenario, profile);

    const auto &settings = scenario.http2_plan().initial_settings();
    Expect(settings.entries(0).identifier() == 7U &&
               settings.entries(0).value() ==
                   std::numeric_limits<std::uint32_t>::max(),
           "H2 normalization rewrote an extension SETTINGS value");
    Expect(settings.entries(1).identifier() == 8U &&
               settings.entries(1).value() == 0U,
           "H2 normalization did not constrain a masked known setting");
  }
}

void TestH2FlowControlSeedPreservesInitialWindow() {
  const std::string path =
      std::string(PROTO_FUZZER_SCENARIO_DIR) +
      "/https_h2/https_h2_push_flow_control.textproto";
  std::ifstream input(path);
  Expect(input.is_open(), "could not read the H2 flow-control seed");
  const std::string text((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
  Scenario seed;
  Expect(google::protobuf::TextFormat::ParseFromString(text, &seed),
         "could not parse the H2 flow-control seed");
  Expect(seed.http2_plan().initial_settings().entries_size() == 1 &&
             seed.http2_plan().initial_settings().entries(0).identifier() ==
                 4U &&
             seed.http2_plan().initial_settings().entries(0).value() == 0U,
         "H2 flow-control seed no longer requests an initial zero window");
  for (const TargetProfile profile : {TargetProfile::kHttpsH2,
                                     TargetProfile::kFastHttp2}) {
    Scenario scenario = seed;
    NormalizeScenarioForTarget(&scenario, profile);
    const auto &settings = scenario.http2_plan().initial_settings();
    Expect(settings.entries(0).identifier() == 4U &&
               settings.entries(0).value() == 0U,
           "normalization removed the flow-control seed's zero stream window");
    Expect(scenario.accept_h2_push(),
           "normalization disabled accepted push in the flow-control seed");
  }
}

void TestRawHttp2SeedsFitDedicatedTarget() {
  constexpr const char *kSeedNames[] = {
      "http2_control_frames.textproto",
      "http2_invalid_preface.textproto",
      "http2_prior_knowledge.textproto",
      "http2_truncated_headers_frame.textproto",
  };

  for (const char *name : kSeedNames) {
    const std::string path = std::string(PROTO_FUZZER_SCENARIO_DIR) +
                             "/http/" + name;
    std::ifstream input(path);
    Expect(input.is_open(), "could not read a raw HTTP/2 seed");
    const std::string text((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
    Scenario scenario;
    Expect(google::protobuf::TextFormat::ParseFromString(text, &scenario),
           "could not parse a raw HTTP/2 seed");
    const auto connection = scenario.connection();
    bool selects_prior_knowledge = false;
    for (const auto &option : scenario.options()) {
      if (option.option_id() ==
              curl::fuzzer::proto::CURLOPT_HTTP_VERSION &&
          option.uint_value() == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE) {
        selects_prior_knowledge = true;
      }
    }
    Expect(selects_prior_knowledge,
           "raw HTTP/2 seed does not select prior knowledge");
    Expect(!connection.initial_response().empty() ||
               connection.on_readable_size() != 0,
           "raw HTTP/2 seed has no response frames");

    NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp2);

    Expect(scenario.scheme() == SCHEME_HTTP,
           "HTTP/2 target changed a raw seed's scheme");
    Expect(!scenario.has_http2_plan(),
           "HTTP/2 target materialized a structured plan for a raw seed");
    Expect(scenario.connection().SerializeAsString() ==
               connection.SerializeAsString(),
           "HTTP/2 target changed a raw seed's response bytes");
    for (const auto &option : scenario.options()) {
      Expect(option.option_id() !=
                 curl::fuzzer::proto::CURLOPT_HTTP_VERSION,
             "HTTP/2 target retained a seed's transport selection option");
    }
  }
}

void TestNormalizationBoundsCanonicalOptionStrings() {
  Scenario scenario;
  auto *pin = scenario.add_options();
  pin->set_option_id(curl::fuzzer::proto::CURLOPT_PINNEDPUBLICKEY);
  pin->set_string_value(
      std::string(proto_fuzzer::scenario_limits::kMaxMetadataBytes + 17, 'p'));
  auto *post = scenario.add_options();
  post->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  post->set_uint_value(7);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttps);

  Expect(scenario.options(0).string_value().size() ==
             proto_fuzzer::scenario_limits::kMaxMetadataBytes &&
             scenario.options(0).string_value().rfind("sha256//", 0) == 0,
         "pin canonicalization escaped the final option-string budget");
  Expect(scenario.options(1).value_case() ==
                 curl::fuzzer::proto::SetOption::kBoolValue &&
             scenario.options(1).bool_value(),
         "complete normalization did not canonicalize option oneofs");
  const std::string normalized = scenario.SerializeAsString();
  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttps);
  Expect(scenario.SerializeAsString() == normalized,
         "repeated normalization changed a canonical public-key pin");
}

void TestNormalizationPipelineIsIdempotent() {
  constexpr TargetProfile kProfiles[] = {
      TargetProfile::kCompatibility,
      TargetProfile::kFastHttp,
      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,
      TargetProfile::kHttpsH2,
      TargetProfile::kFastHttp2,
      TargetProfile::kFastHttp3,
      TargetProfile::kH2Proxy,
      TargetProfile::kSocks4,
      TargetProfile::kResolver,
      TargetProfile::kFastWebSocket,
      TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,
      TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,
      TargetProfile::kFastGopher,
      TargetProfile::kApi,
      TargetProfile::kMulti,
      TargetProfile::kTiming,
  };
  // Check the composition with competing shapes and both direct/proxy H3.
  // These are serialization-only checks; no peer or curl handle is driven.
  for (const TargetProfile profile : kProfiles) {
    for (const bool proxy : {false, true}) {
      Scenario scenario = ScenarioWithBackpressure(
          proxy ? SCHEME_TELNET : SCHEME_WSS,
          std::numeric_limits<std::uint32_t>::max(), 4096);
      scenario.set_host_path("input.invalid/path?query#fragment");
      scenario.set_accept_h2_push(true);
      scenario.add_resolve_entries("resolve.test:80:127.0.0.1");
      scenario.add_telnet_options("TTYPE=fuzz");
      scenario.add_request_headers("X-Fuzz: value");
      scenario.set_cookie_file("cookie data");
      scenario.set_altsvc_file("altsvc data");
      scenario.mutable_upload()->set_data("upload");
      scenario.mutable_upload()->add_read_sizes(999999);
      scenario.mutable_upload()->set_terminal(
          curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE);
      scenario.mutable_api_plan()->set_drive_mode(
          curl::fuzzer::proto::API_DRIVE_EASY_PERFORM);
      scenario.mutable_api_plan()->set_pause_response_once(true);
      scenario.mutable_multi_plan()->set_transfer_count(999999);
      auto *mime = scenario.mutable_mime_post()->add_parts()->mutable_generated_data();
      mime->set_pattern("abc");
      mime->set_repeat_count(999999);
      scenario.add_subsequent_connections()->mutable_backpressure()->set_drain_limit(1);

      auto *pin = scenario.add_options();
      pin->set_option_id(curl::fuzzer::proto::CURLOPT_PINNEDPUBLICKEY);
      pin->set_string_value(std::string(
          proto_fuzzer::scenario_limits::kMaxMetadataBytes + 17, 'p'));
      auto *post = scenario.add_options();
      post->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
      post->set_uint_value(7);

      auto *settings = scenario.mutable_http2_plan()->mutable_initial_settings();
      auto *window = settings->add_entries();
      window->set_identifier(4);
      window->set_value(0);
      auto *frame_size = settings->add_entries();
      frame_size->set_identifier(5);
      frame_size->set_value(16385);
      auto *invalid = settings->add_entries();
      invalid->set_identifier(0);
      invalid->set_value(999999);
      scenario.mutable_http2_plan()->add_actions()->mutable_headers()->set_end_stream(true);

      scenario.mutable_http3_plan()->set_use_h1_connect_udp_proxy(proxy);
      auto *response = scenario.mutable_http3_plan()->add_actions()->mutable_structured_response();
      response->add_response_headers()->set_name("X Bad");
      response->set_finish_stream(true);

      NormalizeScenarioForTarget(&scenario, profile);
      const std::string normalized = scenario.SerializeAsString();
      NormalizeScenarioForTarget(&scenario, profile);
      if (scenario.SerializeAsString() != normalized) {
        Fail(("normalization was not idempotent for profile " +
              std::to_string(static_cast<int>(profile)))
                 .c_str());
      }
    }
  }
}

} // namespace

int main() {
  TestFastHttpPolicy();
  TestDeepHttpPolicy();
  TestDeepHttpBoundsFileInputs();
  TestDeepHttpAltSvcCanonicalAuthority();
  TestFastHttpsPolicy();
  TestHttpsH2Policy();
  TestFastHttp2Policy();
  TestTlsPoliciesRejectUnknownCertificateChain();
  TestFastHttp3PolicyMaterializesUsefulPlan();
  TestFastHttp3ProxyPolicyRetainsStreamScript();
  TestFastHttp3PolicyBoundsOrderedActions();
  TestNonHttp3PoliciesDiscardPlans();
  TestNonHttpsPoliciesDiscardTlsCertificateChains();
  TestH2ProxyPolicy();
  TestFastWebSocketPolicy();
  TestFastSecureWebSocketPolicy();
  TestFastTelnetPolicy();
  TestFastFtpPolicy();
  TestFastTftpPolicy();
  TestResolverPolicy();
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
  TestFastHttpKeepsOnlyOwnedHttpVersions();
  TestFastHttpFiltersBeforeApplyingOptionBound();
  TestApiPolicyRetainsAndBoundsItsPlan();
  TestProtocolPoliciesDiscardApiPlans();
  TestMultiPolicyRetainsAndBoundsItsPlan();
  TestOtherPoliciesDiscardMultiPlans();
  TestApiEasyDrivesDropMultiOnlyWork();
  TestProfileRunModes();
  TestCompatibilityProfileIsNoOp();
  TestNonH2OriginPoliciesDiscardAcceptedPushMode();
  TestGeneratedMimePolicyPreservesBoundariesAndSharesBudget();
  TestHttpsH2PolicyBoundsStructuredPlan();
  TestH2NormalizationPreservesValidSettings();
  TestH2NormalizationCanonicalizesSettingsWireWidth();
  TestH2FlowControlSeedPreservesInitialWindow();
  TestRawHttp2SeedsFitDedicatedTarget();
  TestNormalizationBoundsCanonicalOptionStrings();
  TestNormalizationPipelineIsIdempotent();
  return 0;
}
