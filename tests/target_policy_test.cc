/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/target_policy.h"

#include "proto_fuzzer/scenario_limits.h"
#include "test_assertions.h"

#include <curl/curl.h>

#include <cstdint>
#include <limits>
#include <string>

namespace {

using curl::fuzzer::proto::Scenario;
using curl::fuzzer::proto::SCHEME_DICT;
using curl::fuzzer::proto::SCHEME_FILE;
using curl::fuzzer::proto::SCHEME_FTP;
using curl::fuzzer::proto::SCHEME_FTPS;
using curl::fuzzer::proto::SCHEME_HTTP;
using curl::fuzzer::proto::SCHEME_HTTPS;
using curl::fuzzer::proto::SCHEME_IMAP;
using curl::fuzzer::proto::SCHEME_IMAPS;
using curl::fuzzer::proto::SCHEME_IPFS;
using curl::fuzzer::proto::SCHEME_IPNS;
using curl::fuzzer::proto::SCHEME_LDAP;
using curl::fuzzer::proto::SCHEME_LDAPS;
using curl::fuzzer::proto::SCHEME_MQTT;
using curl::fuzzer::proto::SCHEME_MQTTS;
using curl::fuzzer::proto::SCHEME_POP3;
using curl::fuzzer::proto::SCHEME_POP3S;
using curl::fuzzer::proto::SCHEME_RTSP;
using curl::fuzzer::proto::SCHEME_SMTP;
using curl::fuzzer::proto::SCHEME_SMTPS;
using curl::fuzzer::proto::SCHEME_TELNET;
using curl::fuzzer::proto::SCHEME_TFTP;
using curl::fuzzer::proto::SCHEME_UNSPECIFIED;
using curl::fuzzer::proto::SCHEME_WS;
using curl::fuzzer::proto::SCHEME_WSS;
using curl::fuzzer::proto::SetOption;
using proto_fuzzer::NormalizeScenarioForExecution;
using proto_fuzzer::NormalizeScenarioForTarget;
using proto_fuzzer::RunModeFor;
using proto_fuzzer::ScenarioRunMode;
using proto_fuzzer::TargetProfile;
using test_support::Expect;
using test_support::Fail;

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

const SetOption &RequireOption(const Scenario &scenario,
                               curl::fuzzer::proto::CurlOptionId option_id,
                               const char *message) {
  for (const auto &option : scenario.options()) {
    if (option.option_id() == option_id) {
      return option;
    }
  }
  Fail(message);
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

void TestDeepHttpTransportPolicy() {
  Scenario connect;
  connect.set_host_path("mutated.example:8443/path?query#fragment");
  connect.set_http_transport_mode(
      curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY);
  connect.set_probe_multi_pollset(true);

  NormalizeScenarioForTarget(&connect, TargetProfile::kDeepHttp);

  Expect(connect.scheme() == SCHEME_HTTP &&
             connect.host_path() == "transport.test/path?query#fragment",
         "deep HTTP transport policy did not isolate its origin authority");
  Expect(connect.http_transport_mode() ==
                 curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY &&
             connect.probe_multi_pollset(),
         "deep HTTP transport policy discarded CONNECT poll work");

  Scenario haproxy = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 1024);
  haproxy.set_http_transport_mode(
      curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY);
  haproxy.set_haproxy_protocol(true);
  haproxy.set_probe_multi_pollset(true);
  haproxy.add_subsequent_connections()->mutable_backpressure()->set_drain_limit(
      1);
  NormalizeScenarioForTarget(&haproxy, TargetProfile::kDeepHttp);
  Expect(haproxy.haproxy_protocol() && haproxy.probe_multi_pollset() &&
             haproxy.connection().backpressure().recv_buf_bytes() == 2048 &&
             haproxy.connection().backpressure().drain_limit() == 48 &&
             !haproxy.subsequent_connections(0).has_backpressure(),
         "deep CONNECT policy did not install bounded HAProxy pressure");

  Scenario forward;
  forward.set_http_transport_mode(
      curl::fuzzer::proto::HTTP_TRANSPORT_FORWARD_PROXY);
  forward.set_haproxy_protocol(true);
  forward.mutable_connection()->mutable_backpressure()->set_drain_limit(1);
  forward.set_probe_multi_pollset(true);
  forward.set_altsvc_file("must not replace the fixed route");
  forward.set_hsts_file("must not upgrade the plaintext proxy route");
  NormalizeScenarioForTarget(&forward, TargetProfile::kDeepHttp);
  Expect(forward.http_transport_mode() ==
                 curl::fuzzer::proto::HTTP_TRANSPORT_FORWARD_PROXY &&
             !forward.haproxy_protocol() &&
             !forward.connection().has_backpressure() &&
             !forward.probe_multi_pollset(),
         "forward-proxy policy retained unrelated HAProxy timing work");
  Expect(forward.altsvc_file().empty() && forward.hsts_file().empty(),
         "forward-proxy policy retained a conflicting routing file");

  Scenario unknown;
  unknown.set_http_transport_mode(
      static_cast<curl::fuzzer::proto::HttpTransportMode>(99));
  NormalizeScenarioForTarget(&unknown, TargetProfile::kDeepHttp);
  Expect(unknown.http_transport_mode() ==
             curl::fuzzer::proto::HTTP_TRANSPORT_DIRECT,
         "deep HTTP policy retained an unknown transport mode");

  Scenario other;
  other.set_http_transport_mode(
      curl::fuzzer::proto::HTTP_TRANSPORT_UNIX_SOCKET);
  NormalizeScenarioForTarget(&other, TargetProfile::kFastHttp);
  Expect(other.http_transport_mode() ==
             curl::fuzzer::proto::HTTP_TRANSPORT_DIRECT,
         "a non-deep policy retained the HTTP transport selector");
}

void TestDeepHttpProxySocketOptionPolicy() {
  struct Case {
    curl::fuzzer::proto::ProxySocketOptionMode mode;
    const char *host_path;
  };
  constexpr Case kCases[] = {
      {curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_HOSTNAME,
       "service.proxy.test/path?query#fragment"},
      {curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_IPV4_CIDR,
       "127.0.0.2/path?query#fragment"},
      {curl::fuzzer::proto::PROXY_SOCKET_OPTION_NOPROXY_IPV6_CIDR,
       "[::1]/path?query#fragment"},
      {curl::fuzzer::proto::PROXY_SOCKET_OPTION_ENV_HTTP_PROXY,
       "proxy-origin.test/path?query#fragment"},
      {curl::fuzzer::proto::PROXY_SOCKET_OPTION_LOOPBACK_INTERFACE_KEEPALIVE,
       "resolve.test/path?query#fragment"},
  };

  for (const auto &test_case : kCases) {
    Scenario scenario;
    scenario.set_host_path("mutated.example:8443/path?query#fragment");
    scenario.set_proxy_socket_option_mode(test_case.mode);
    scenario.set_http_transport_mode(
        curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY);
    scenario.set_altsvc_file("must not replace the fixed route");
    scenario.set_hsts_file("must not upgrade the plaintext option route");

    NormalizeScenarioForTarget(&scenario, TargetProfile::kDeepHttp);

    Expect(scenario.scheme() == SCHEME_HTTP &&
               scenario.proxy_socket_option_mode() == test_case.mode &&
               scenario.host_path() == test_case.host_path,
           "deep HTTP policy did not canonicalize a proxy/socket mode");
    Expect(scenario.altsvc_file().empty() && scenario.hsts_file().empty(),
           "proxy/socket mode retained a conflicting routing file");
    Expect(scenario.http_transport_mode() ==
               curl::fuzzer::proto::HTTP_TRANSPORT_DIRECT,
           "proxy/socket mode retained a competing HTTP transport");
  }

  Scenario unknown;
  unknown.set_proxy_socket_option_mode(
      static_cast<curl::fuzzer::proto::ProxySocketOptionMode>(99));
  NormalizeScenarioForTarget(&unknown, TargetProfile::kDeepHttp);
  Expect(unknown.proxy_socket_option_mode() ==
             curl::fuzzer::proto::PROXY_SOCKET_OPTION_DEFAULT,
         "deep HTTP policy retained an unknown proxy/socket mode");

  Scenario other;
  other.set_proxy_socket_option_mode(
      curl::fuzzer::proto::PROXY_SOCKET_OPTION_ENV_HTTP_PROXY);
  NormalizeScenarioForTarget(&other, TargetProfile::kFastHttp);
  Expect(other.proxy_socket_option_mode() ==
             curl::fuzzer::proto::PROXY_SOCKET_OPTION_DEFAULT,
         "a non-deep policy retained the proxy/socket mode");
}

void TestFastHttpsPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("mutated.example:8443/a/path?query#fragment");
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);
  scenario.set_tls_group_profile(
      curl::fuzzer::proto::TLS_GROUP_PROVIDER_DEFAULT);
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
  Expect(scenario.tls_group_profile() == curl::fuzzer::proto::TLS_GROUP_X25519,
         "fast HTTPS policy retained HTTPS/H2 group work");
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
  scenario.set_tls_group_profile(
      curl::fuzzer::proto::TLS_GROUP_PROVIDER_DEFAULT);
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
  scenario.set_h2_forward_proxy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.set_accept_h2_push(true);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kHttpsH2);

  Expect(scenario.scheme() == SCHEME_HTTPS,
         "HTTPS/H2 policy did not force HTTPS");
  Expect(scenario.host_path() == "tls.test/path?query#fragment",
         "HTTPS/H2 policy did not isolate the verified TLS authority");
  Expect(scenario.tls_certificate_chain() ==
             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES,
         "HTTPS/H2 policy discarded its certificate-chain selector");
  Expect(scenario.tls_group_profile() ==
             curl::fuzzer::proto::TLS_GROUP_PROVIDER_DEFAULT,
         "HTTPS/H2 policy discarded its TLS group selector");
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
  Expect(!scenario.h2_forward_proxy(),
         "HTTPS/H2 policy retained forward-proxy-only work");
  Expect(scenario.accept_h2_push(),
         "HTTPS/H2 policy discarded its accepted-push mode");
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
}

void TestTlsPoliciesRejectUnknownCertificateChain() {
  constexpr TargetProfile kTlsPolicies[] = {
      TargetProfile::kFastHttps,
      TargetProfile::kHttpsH2,
      TargetProfile::kFastHttp3,
      TargetProfile::kFastSecureWebSocket,
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

void TestTlsClientCredentialProfilePolicy() {
  Scenario https;
  https.set_tls_client_credential_profile(
      curl::fuzzer::proto::TLS_CLIENT_CREDENTIAL_MALFORMED_PKCS12);
  NormalizeScenarioForTarget(&https, TargetProfile::kFastHttps);
  Expect(https.tls_client_credential_profile() ==
             curl::fuzzer::proto::TLS_CLIENT_CREDENTIAL_MALFORMED_PKCS12,
         "HTTPS policy discarded a bounded client-credential profile");

  Scenario unknown;
  unknown.set_tls_client_credential_profile(
      static_cast<curl::fuzzer::proto::TlsClientCredentialProfile>(99));
  NormalizeScenarioForTarget(&unknown, TargetProfile::kFastHttps);
  Expect(unknown.tls_client_credential_profile() ==
             curl::fuzzer::proto::TLS_CLIENT_CREDENTIAL_NONE,
         "HTTPS policy retained an unknown client-credential profile");

  Scenario plaintext;
  plaintext.set_tls_client_credential_profile(
      curl::fuzzer::proto::TLS_CLIENT_CREDENTIAL_ENGINE_DEV_NULL);
  NormalizeScenarioForTarget(&plaintext, TargetProfile::kDeepHttp);
  Expect(plaintext.tls_client_credential_profile() ==
             curl::fuzzer::proto::TLS_CLIENT_CREDENTIAL_NONE,
         "non-HTTPS policy retained client-credential setup work");
}

void TestTlsHandshakeProfilePolicy() {
  Scenario https;
  https.set_tls_handshake_profile(
      curl::fuzzer::proto::TLS_HANDSHAKE_OPENSSL_CLOSE_NOTIFY);
  NormalizeScenarioForTarget(&https, TargetProfile::kFastHttps);
  Expect(https.tls_handshake_profile() ==
             curl::fuzzer::proto::TLS_HANDSHAKE_OPENSSL_CLOSE_NOTIFY,
         "HTTPS policy discarded its OpenSSL handshake terminal");

  Scenario hello_request;
  hello_request.set_tls_handshake_profile(
      curl::fuzzer::proto::TLS_HANDSHAKE_OPENSSL_HELLO_REQUEST);
  NormalizeScenarioForTarget(&hello_request, TargetProfile::kFastHttps);
  Expect(hello_request.tls_handshake_profile() ==
             curl::fuzzer::proto::TLS_HANDSHAKE_OPENSSL_HELLO_REQUEST,
         "HTTPS policy discarded its fixed HelloRequest terminal");

  Scenario unknown;
  unknown.set_tls_handshake_profile(
      static_cast<curl::fuzzer::proto::TlsHandshakeProfile>(99));
  NormalizeScenarioForTarget(&unknown, TargetProfile::kFastHttps);
  Expect(unknown.tls_handshake_profile() ==
             curl::fuzzer::proto::TLS_HANDSHAKE_DEFAULT,
         "HTTPS policy retained an unknown handshake profile");

  Scenario plaintext;
  plaintext.set_tls_handshake_profile(
      curl::fuzzer::proto::TLS_HANDSHAKE_OPENSSL_CLOSE_NOTIFY);
  NormalizeScenarioForTarget(&plaintext, TargetProfile::kDeepHttp);
  Expect(plaintext.tls_handshake_profile() ==
             curl::fuzzer::proto::TLS_HANDSHAKE_DEFAULT,
         "non-HTTPS policy retained a TLS handshake terminal");
}

void TestHttpsH2PolicyRejectsUnknownTlsGroupProfile() {
  Scenario scenario;
  scenario.set_tls_group_profile(
      static_cast<curl::fuzzer::proto::TlsGroupProfile>(99));

  NormalizeScenarioForTarget(&scenario, TargetProfile::kHttpsH2);

  Expect(scenario.tls_group_profile() == curl::fuzzer::proto::TLS_GROUP_X25519,
         "HTTPS/H2 policy retained an unknown TLS group selector");
}

void TestOtherPoliciesDiscardTlsGroupProfiles() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp,       TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,      TargetProfile::kFastHttp2,
      TargetProfile::kFastHttp3,      TargetProfile::kH2Proxy,
      TargetProfile::kProxyTransport, TargetProfile::kResolver,
      TargetProfile::kFastWebSocket,  TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,     TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,       TargetProfile::kFastSmtp,
      TargetProfile::kFastFile,       TargetProfile::kFastGopher,
      TargetProfile::kFastTftp,       TargetProfile::kFastImap,
      TargetProfile::kFastPop3,       TargetProfile::kFastGopher,
      TargetProfile::kFastMqtt,       TargetProfile::kFastDict,
      TargetProfile::kFastLdap,       TargetProfile::kFastRtsp,
      TargetProfile::kFastIpfs,       TargetProfile::kApi,
      TargetProfile::kMulti,          TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_tls_group_profile(
        curl::fuzzer::proto::TLS_GROUP_PROVIDER_DEFAULT);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.tls_group_profile() ==
               curl::fuzzer::proto::TLS_GROUP_X25519,
           "a non-HTTPS/H2 policy retained TLS group work");
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
      TargetProfile::kFastTftp,      TargetProfile::kFastSmtp,
      TargetProfile::kFastFile,      TargetProfile::kApi,
      TargetProfile::kFastTftp,      TargetProfile::kFastImap,
      TargetProfile::kFastPop3,      TargetProfile::kApi,
      TargetProfile::kFastMqtt,      TargetProfile::kFastDict,
      TargetProfile::kFastLdap,      TargetProfile::kFastRtsp,
      TargetProfile::kFastIpfs,      TargetProfile::kMulti,
      TargetProfile::kTiming,
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

void TestNonTlsPoliciesDiscardTlsCertificateChains() {
  constexpr TargetProfile kNonHttpsPolicies[] = {
      TargetProfile::kFastHttp,      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttp2,     TargetProfile::kH2Proxy,
      TargetProfile::kFastWebSocket, TargetProfile::kFastTelnet,
      TargetProfile::kFastFtp,       TargetProfile::kFastTftp,
      TargetProfile::kFastSmtp,      TargetProfile::kFastFile,
      TargetProfile::kFastImap,      TargetProfile::kFastPop3,
      TargetProfile::kFastMqtt,      TargetProfile::kFastDict,
      TargetProfile::kFastLdap,      TargetProfile::kFastRtsp,
      TargetProfile::kFastIpfs,      TargetProfile::kApi,
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
  scenario.mutable_connection()->set_proxy_protocol(
      curl::fuzzer::proto::PROXY_PROTOCOL_HTTP1);
  scenario.add_subsequent_connections()->set_initial_response(
      "unrepresentable second proxy stream");
  scenario.mutable_mime_post()->add_parts()->set_data("MIME body");
  scenario.mutable_upload()->set_data("upload body");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.set_h2_forward_proxy(true);

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
  Expect(scenario.connection().proxy_protocol() ==
             curl::fuzzer::proto::PROXY_PROTOCOL_HTTP1,
         "HTTPS proxy policy discarded its H1 protocol profile");
  Expect(scenario.request_headers(0) == "X-Origin: retained" &&
             scenario.has_mime_post() && scenario.has_upload(),
         "HTTP/2 proxy policy removed state visible to the origin request");
  Expect(scenario.telnet_options_size() == 0 && !scenario.has_api_plan(),
         "HTTP/2 proxy policy retained another target's work");
  Expect(!scenario.h2_forward_proxy(),
         "HTTP/1 proxy policy retained unsupported direct-forwarding mode");
  Scenario h2_forward;
  h2_forward.set_h2_forward_proxy(true);
  NormalizeScenarioForTarget(&h2_forward, TargetProfile::kH2Proxy);
  Expect(h2_forward.h2_forward_proxy() &&
             h2_forward.connection().proxy_protocol() ==
                 curl::fuzzer::proto::PROXY_PROTOCOL_HTTP2,
         "HTTP/2 proxy policy discarded direct-forwarding mode");

  Scenario other;
  other.mutable_connection()->set_proxy_protocol(
      curl::fuzzer::proto::PROXY_PROTOCOL_HTTP1);
  NormalizeScenarioForTarget(&other, TargetProfile::kFastHttp);
  Expect(other.connection().proxy_protocol() ==
             curl::fuzzer::proto::PROXY_PROTOCOL_HTTP2,
         "non-proxy policy retained the nested proxy protocol selector");
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

  Scenario scenario;
  scenario.set_host_path("mutated.example:8443/chat?room=fuzz#tail");
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastSecureWebSocket);

  Expect(scenario.host_path() == "tls.test/chat?room=fuzz#tail",
         "secure WebSocket policy did not canonicalize its TLS authority");
  Expect(scenario.tls_certificate_chain() ==
             curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES,
         "secure WebSocket policy discarded its TLS certificate chain");
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
}

void TestFastFtpPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_probe_multi_pollset(true);
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
  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastFtp);

  Expect(scenario.scheme() == SCHEME_FTP, "fast FTP policy did not force FTP");
  Expect(scenario.probe_multi_pollset(),
         "fast FTP policy removed the pollset-probe opt-in");
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
  const auto &normalized_create_dirs = RequireOption(
      scenario, curl::fuzzer::proto::CURLOPT_FTP_CREATE_MISSING_DIRS,
      "fast FTP policy lost its create-directory selector");
  const auto &normalized_file_method =
      RequireOption(scenario, curl::fuzzer::proto::CURLOPT_FTP_FILEMETHOD,
                    "fast FTP policy lost its file-method selector");
  const auto &normalized_ftp_port =
      RequireOption(scenario, curl::fuzzer::proto::CURLOPT_FTPPORT,
                    "fast FTP policy lost its active-mode address");
  const auto &normalized_use_eprt =
      RequireOption(scenario, curl::fuzzer::proto::CURLOPT_FTP_USE_EPRT,
                    "fast FTP policy lost its EPRT selector");
  Expect(normalized_create_dirs.uint_value() < 3 &&
             normalized_file_method.uint_value() < 4,
         "fast FTP policy left small enums outside curl's valid domains");
  Expect(normalized_ftp_port.string_value() == "127.0.0.1",
         "fast FTP policy retained a resolving active-mode address");
  Expect(normalized_use_eprt.uint_value() == 1,
         "fast FTP policy did not canonicalize the EPRT selector");
}

void TestFastFtpsPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_scheme(SCHEME_FTPS);
  scenario.set_probe_multi_pollset(true);
  scenario.set_host_path("untrusted.invalid:990/secure.bin?query#fragment");
  scenario.add_request_headers("X-Ignored: ftps");
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_connection()->add_on_readable("control reply");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("data");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastFtp);

  Expect(scenario.scheme() == SCHEME_FTPS,
         "fast FTP lane did not preserve an explicit FTPS scheme");
  Expect(scenario.probe_multi_pollset(),
         "fast FTP lane removed the FTPS pollset-probe opt-in");
  Expect(scenario.host_path() == "tls.test/secure.bin?query#fragment",
         "fast FTP lane did not give FTPS the certifiable authority");
  Expect(scenario.request_headers_size() == 0 && !scenario.has_mime_post() &&
             scenario.telnet_options_size() == 0 && !scenario.has_api_plan(),
         "fast FTP lane retained another protocol's shape in FTPS");
  Expect(scenario.connection().on_readable(0) == "control reply" &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast FTP lane changed the FTPS control script");
}

void TestNonFtpPoliciesClearFtpsScheme() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp, TargetProfile::kDeepHttp,
      TargetProfile::kFastSmtp, TargetProfile::kFastRtsp,
      TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path("tls.test/secure.bin");
    scenario.set_scheme(SCHEME_FTPS);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.scheme() != SCHEME_FTPS,
           "a non-FTP policy retained the FTPS scheme");
  }

  Scenario compatibility;
  compatibility.set_host_path("tls.test/secure.bin");
  compatibility.set_scheme(SCHEME_FTPS);
  NormalizeScenarioForTarget(&compatibility, TargetProfile::kCompatibility);
  Expect(compatibility.scheme() == SCHEME_FTPS,
         "compatibility unexpectedly rewrote the FTPS input");
}

void TestFastFilePolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path(
      "filehost.test:8080/%2e%2e/etc/passwd?download=1#fragment");
  scenario.add_request_headers("X-Ignored: file");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.mutable_upload()->set_data("bounded upload bytes");
  scenario.mutable_connection()->set_initial_response("ignored peer script");
  scenario.add_subsequent_connections()->set_initial_response("ignored");
  scenario.set_cookie_file("ignored parser input");
  scenario.add_resolve_entries("filehost.test:80:127.0.0.1");
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastFile);

  Expect(scenario.scheme() == SCHEME_FILE,
         "fast FILE policy did not force the local-file scheme");
  Expect(scenario.host_path() ==
             "filehost.test:8080/dev/null?download=1#fragment",
         "fast FILE policy did not pin the path while retaining the URL "
         "authority and suffix");
  Expect(scenario.connection().initial_response().empty() &&
             scenario.connection().on_readable_size() == 0 &&
             scenario.connection().server_frames_size() == 0 &&
             !scenario.connection().has_backpressure() &&
             scenario.has_upload() &&
             scenario.upload().data() == "bounded upload bytes" &&
             !scenario.has_mime_post() && !scenario.has_api_plan() &&
             !scenario.has_multi_plan() &&
             scenario.subsequent_connections_size() == 0 &&
             scenario.request_headers_size() == 0 &&
             scenario.telnet_options_size() == 0 &&
             scenario.resolve_entries_size() == 0 &&
             scenario.cookie_file().empty(),
         "fast FILE policy retained an inert shape or dropped upload data");
  Scenario bare;
  bare.set_host_path("localhost");
  NormalizeScenarioForTarget(&bare, TargetProfile::kFastFile);
  Expect(bare.host_path() == "localhost/dev/null",
         "fast FILE policy did not append the fixed path to a bare authority");

  Scenario traversal;
  traversal.set_host_path("//etc/passwd");
  NormalizeScenarioForTarget(&traversal, TargetProfile::kFastFile);
  Expect(traversal.host_path() == "/dev/null",
         "fast FILE policy retained a traversal path or authority");
}

void TestNonFilePoliciesClearFileScheme() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp, TargetProfile::kDeepHttp,
      TargetProfile::kFastFtp,  TargetProfile::kTiming,
      TargetProfile::kApi,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path("localhost/etc/passwd");
    scenario.set_scheme(SCHEME_FILE);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.scheme() != SCHEME_FILE,
           "a non-FILE policy retained the local-file scheme");
  }

  Scenario compatibility;
  compatibility.set_host_path("localhost/etc/passwd");
  compatibility.set_scheme(SCHEME_FILE);
  NormalizeScenarioForTarget(&compatibility, TargetProfile::kCompatibility);
  Expect(compatibility.scheme() == SCHEME_FILE,
         "compatibility unexpectedly rewrote the FILE scheme");
}

void TestFastSmtpPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("untrusted.invalid:2525/client.test?query#fragment");
  scenario.set_probe_multi_pollset(true);
  scenario.add_request_headers("X-Ignored: smtp");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_upload()->set_data("mail body sentinel");
  scenario.mutable_connection()->add_on_readable("250 reply");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("stream-only");
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxMailRecipients + 2; ++index) {
    scenario.add_mail_rcpt("recipient-" + std::to_string(index) +
                           "@example.test");
  }
  scenario.set_mail_rcpt(
      0, std::string(proto_fuzzer::scenario_limits::kMaxMailRecipientBytes + 32,
                     'r'));

  auto *allow_fails = scenario.add_options();
  allow_fails->set_option_id(curl::fuzzer::proto::CURLOPT_MAIL_RCPT_ALLOWFAILS);
  allow_fails->set_uint_value(7);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastSmtp);

  Expect(scenario.scheme() == SCHEME_SMTP,
         "fast SMTP policy did not force SMTP");
  Expect(scenario.probe_multi_pollset(),
         "fast SMTP policy removed its pollset-probe opt-in");
  Expect(scenario.host_path() == "smtp.test/client.test?query#fragment",
         "fast SMTP policy did not preserve the EHLO path suffix");
  Expect(scenario.request_headers_size() == 0 &&
             scenario.telnet_options_size() == 0 && !scenario.has_api_plan() &&
             scenario.subsequent_connections_size() == 0,
         "fast SMTP policy retained another protocol's shape");
  Expect(scenario.has_upload() &&
             scenario.upload().data() == "mail body sentinel",
         "fast SMTP policy removed the callback-backed message body");
  Expect(scenario.connection().on_readable(0) == "250 reply" &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast SMTP policy changed replies or retained stream-only controls");
  Expect(static_cast<std::size_t>(scenario.mail_rcpt_size()) ==
             proto_fuzzer::scenario_limits::kMaxMailRecipients,
         "fast SMTP policy exceeded its recipient budget");
  Expect(scenario.mail_rcpt(0).size() ==
             proto_fuzzer::scenario_limits::kMaxMailRecipientBytes,
         "fast SMTP policy left an oversized recipient");
  Expect(RequireOption(scenario,
                       curl::fuzzer::proto::CURLOPT_MAIL_RCPT_ALLOWFAILS,
                       "fast SMTP policy lost its recipient-failure selector")
             .bool_value(),
         "fast SMTP policy did not canonicalize the recipient-failure flag");
}

void TestFastSmtpsPolicy() {
  Scenario scenario;
  scenario.set_scheme(SCHEME_SMTPS);
  scenario.set_host_path("untrusted.invalid:2465/client.test?query#fragment");
  scenario.mutable_upload()->set_data("implicit tls mail body");
  scenario.mutable_connection()->set_initial_response("220 smtps.test\r\n");
  scenario.mutable_connection()->add_on_readable("250 reply");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastSmtp);

  Expect(scenario.scheme() == SCHEME_SMTPS,
         "fast SMTP lane did not preserve an explicit SMTPS scheme");
  Expect(scenario.host_path() == "tls.test/client.test?query#fragment",
         "fast SMTP lane did not give SMTPS the certifiable authority");
  Expect(scenario.has_upload() &&
             scenario.upload().data() == "implicit tls mail body",
         "fast SMTP lane removed the SMTPS message body");
}

void TestFastImapsPolicy() {
  Scenario scenario;
  scenario.set_scheme(SCHEME_IMAPS);
  scenario.set_host_path("untrusted.invalid:993/INBOX;UID=1?query#fragment");
  scenario.mutable_upload()->set_data("implicit tls append body");
  scenario.mutable_connection()->set_initial_response("* OK imaps.test\r\n");
  scenario.mutable_connection()->add_on_readable("OK reply");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastImap);

  Expect(scenario.scheme() == SCHEME_IMAPS,
         "fast IMAP lane did not preserve an explicit IMAPS scheme");
  Expect(scenario.host_path() == "tls.test/INBOX;UID=1?query#fragment",
         "fast IMAP lane did not give IMAPS the certifiable authority");
  Expect(scenario.has_upload() &&
             scenario.upload().data() == "implicit tls append body",
         "fast IMAP lane removed the IMAPS APPEND body");
}

void TestFastPop3sPolicy() {
  Scenario scenario;
  scenario.set_scheme(SCHEME_POP3S);
  scenario.set_host_path("untrusted.invalid:995/2?query");
  scenario.mutable_connection()->set_initial_response("+OK pop3s.test\r\n");
  scenario.mutable_connection()->add_on_readable("+OK reply");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastPop3);

  Expect(scenario.scheme() == SCHEME_POP3S,
         "fast POP3 lane did not preserve an explicit POP3S scheme");
  Expect(scenario.host_path() == "tls.test/2?query",
         "fast POP3 lane did not give POP3S the certifiable authority");
  Expect(
      !scenario.has_upload() && !scenario.has_mime_post(),
      "fast POP3 lane retained upload state its download-only peer cannot use");
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

  auto *block_size = scenario.add_options();
  block_size->set_option_id(curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE);
  block_size->set_uint_value(std::numeric_limits<std::uint64_t>::max());

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
  Expect(RequireOption(scenario, curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE,
                       "fast TFTP policy lost its block-size selector")
                 .uint_value() == 65464,
         "fast TFTP policy did not clamp block size to curl's upper boundary");
}

void TestFastImapPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("untrusted.invalid:143/INBOX;UID=1?query#fragment");
  scenario.set_probe_multi_pollset(true);
  scenario.add_request_headers("X-Ignored: imap");
  scenario.mutable_mime_post()->add_parts()->set_data("mime sentinel");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_upload()->set_data("append sentinel");
  scenario.mutable_connection()->add_on_readable("control reply");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("stream-only");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastImap);

  Expect(scenario.scheme() == curl::fuzzer::proto::SCHEME_IMAP,
         "fast IMAP policy did not force IMAP");
  Expect(scenario.probe_multi_pollset(),
         "fast IMAP policy removed its pollset-probe opt-in");
  Expect(scenario.host_path() == "imap.test/INBOX;UID=1?query#fragment",
         "fast IMAP policy did not retain the mailbox selectors");
  Expect(scenario.request_headers_size() == 0 &&
             scenario.telnet_options_size() == 0 && !scenario.has_api_plan() &&
             scenario.subsequent_connections_size() == 0,
         "fast IMAP policy retained another protocol's shape");
  Expect(scenario.has_mime_post() && scenario.has_upload() &&
             scenario.upload().data() == "append sentinel",
         "fast IMAP policy removed the APPEND inputs curl can consume");
  Expect(scenario.connection().on_readable(0) == "control reply" &&
             scenario.connection().has_backpressure() &&
             scenario.connection().backpressure().recv_buf_bytes() == 4096 &&
             scenario.connection().backpressure().drain_limit() == 0 &&
             scenario.connection().server_frames_size() == 0,
         "fast IMAP policy changed replies or mail pressure controls");
}

void TestFastPop3Policy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("untrusted.invalid:110/2?query");
  scenario.set_probe_multi_pollset(true);
  scenario.add_request_headers("X-Ignored: pop3");
  scenario.mutable_mime_post()->add_parts()->set_data("mime sentinel");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_upload()->set_data("ignored upload");
  scenario.mutable_connection()->add_on_readable("control reply");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("stream-only");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastPop3);

  Expect(scenario.scheme() == curl::fuzzer::proto::SCHEME_POP3,
         "fast POP3 policy did not force POP3");
  Expect(scenario.probe_multi_pollset(),
         "fast POP3 policy removed its pollset-probe opt-in");
  Expect(scenario.host_path() == "pop3.test/2?query",
         "fast POP3 policy did not retain the message-id path");
  Expect(scenario.request_headers_size() == 0 && !scenario.has_mime_post() &&
             !scenario.has_upload() && scenario.telnet_options_size() == 0 &&
             !scenario.has_api_plan() &&
             scenario.subsequent_connections_size() == 0,
         "fast POP3 policy retained work its download-only peer cannot use");
  Expect(scenario.connection().on_readable(0) == "control reply" &&
             scenario.connection().has_backpressure() &&
             scenario.connection().backpressure().recv_buf_bytes() == 4096 &&
             scenario.connection().backpressure().drain_limit() == 0 &&
             scenario.connection().server_frames_size() == 0,
         "fast POP3 policy changed replies or mail pressure controls");

  Scenario starttls;
  starttls.set_scheme(SCHEME_POP3);
  starttls.set_pop3_starttls_filter_allocation_failure(true);
  starttls.add_fail_allocations(7);
  NormalizeScenarioForTarget(&starttls, TargetProfile::kFastPop3);
  Expect(starttls.pop3_starttls_filter_allocation_failure() &&
             starttls.fail_allocations().empty(),
         "fast POP3 policy combined semantic and ordinal failures");

  Scenario implicit_tls;
  implicit_tls.set_scheme(SCHEME_POP3S);
  implicit_tls.set_pop3_starttls_filter_allocation_failure(true);
  NormalizeScenarioForTarget(&implicit_tls, TargetProfile::kFastPop3);
  Expect(!implicit_tls.pop3_starttls_filter_allocation_failure(),
         "implicit POP3S retained the plaintext STLS selector");

  Scenario drain_only = ScenarioWithBackpressure(SCHEME_POP3, 0, 17);
  NormalizeScenarioForTarget(&drain_only, TargetProfile::kFastPop3);
  Expect(!drain_only.connection().has_backpressure(),
         "fast POP3 policy retained drain-only timing work");
}

void TestFastMqttPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_probe_multi_pollset(true);
  scenario.set_host_path(
      "untrusted.invalid:1883/sensors/kitchen?query#fragment");
  scenario.add_request_headers("X-Ignored: mqtt");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.mutable_upload()->set_data("callback upload");
  scenario.mutable_connection()->add_on_readable("server packet");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("stream-only");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastMqtt);

  Expect(scenario.scheme() == SCHEME_MQTT,
         "fast MQTT policy did not force MQTT");
  Expect(scenario.probe_multi_pollset(),
         "fast MQTT policy removed its pollset-probe opt-in");
  Expect(scenario.host_path() == "mqtt.test/sensors/kitchen?query#fragment",
         "fast MQTT policy did not retain the publish topic suffix");
  Expect(scenario.subsequent_connections_size() == 0 &&
             scenario.request_headers_size() == 0 &&
             !scenario.has_mime_post() && scenario.telnet_options_size() == 0 &&
             !scenario.has_api_plan() && !scenario.has_upload(),
         "fast MQTT policy retained another protocol's shape");
  Expect(scenario.connection().on_readable(0) == "server packet" &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast MQTT policy changed server packets or retained stream-only "
         "controls");
}

void TestFastMqttsPolicy() {
  Scenario scenario;
  scenario.set_scheme(SCHEME_MQTTS);
  scenario.set_probe_multi_pollset(true);
  scenario.set_host_path(
      "untrusted.invalid:8883/sensors/kitchen?query#fragment");
  scenario.mutable_connection()->set_initial_response(
      std::string("\x20\x02\x00\x00", 4));

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastMqtt);

  Expect(scenario.scheme() == SCHEME_MQTTS,
         "fast MQTT lane did not preserve an explicit MQTTS scheme");
  Expect(scenario.probe_multi_pollset(),
         "fast MQTT lane removed the MQTTS pollset-probe opt-in");
  Expect(scenario.host_path() == "tls.test/sensors/kitchen?query#fragment",
         "fast MQTT lane did not give MQTTS the certifiable authority");
  Expect(scenario.connection().initial_response() ==
             std::string("\x20\x02\x00\x00", 4),
         "fast MQTT lane removed the MQTTS CONNACK");
}

void TestNonMqttPoliciesClearMqttScheme() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp, TargetProfile::kDeepHttp,
      TargetProfile::kFastFtp,  TargetProfile::kTiming,
      TargetProfile::kApi,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path("mqtt.test/topic");
    scenario.set_scheme(SCHEME_MQTT);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.scheme() != SCHEME_MQTT,
           "a non-MQTT policy retained the MQTT scheme");
  }

  Scenario compatibility;
  compatibility.set_host_path("mqtt.test/topic");
  compatibility.set_scheme(SCHEME_MQTT);
  NormalizeScenarioForTarget(&compatibility, TargetProfile::kCompatibility);
  Expect(compatibility.scheme() == SCHEME_MQTT,
         "compatibility unexpectedly rewrote the MQTT scheme");
}

void TestFastDictPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("untrusted.invalid:2628/d:word?query#fragment");
  scenario.add_request_headers("X-Ignored: dict");
  scenario.mutable_mime_post()->add_parts()->set_data("mime sentinel");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_upload()->set_data("ignored upload");
  scenario.mutable_connection()->add_on_readable("150 dict reply");
  scenario.mutable_connection()->add_on_readable("250 ok");
  scenario.mutable_connection()->add_on_readable("221 bye");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("stream-only");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastDict);

  Expect(scenario.scheme() == SCHEME_DICT,
         "fast DICT policy did not force DICT");
  Expect(scenario.host_path() == "dict.test/d:word?query#fragment",
         "fast DICT policy did not retain the lookup path suffix");
  Expect(scenario.request_headers_size() == 0 && !scenario.has_mime_post() &&
             !scenario.has_upload() && scenario.telnet_options_size() == 0 &&
             !scenario.has_api_plan() &&
             scenario.subsequent_connections_size() == 0,
         "fast DICT policy retained work its download-only peer cannot use");
  Expect(scenario.connection().on_readable_size() == 1 &&
             scenario.connection().on_readable(0) == "150 dict reply" &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast DICT policy changed replies, kept unreachable chunks, or "
         "retained stream-only controls");

  Scenario oversized;
  oversized.set_host_path(
      "untrusted.invalid/d:" +
      std::string(proto_fuzzer::scenario_limits::kMaxDictHostPathBytes * 2,
                  'x'));
  NormalizeScenarioForTarget(&oversized, TargetProfile::kFastDict);
  Expect(oversized.host_path().size() ==
                 proto_fuzzer::scenario_limits::kMaxDictHostPathBytes &&
             oversized.host_path().rfind("dict.test/d:", 0) == 0,
         "fast DICT policy did not bound the synchronous request path");
}

void TestNonDictPoliciesClearDictScheme() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp, TargetProfile::kDeepHttp,
      TargetProfile::kFastFtp,  TargetProfile::kTiming,
      TargetProfile::kApi,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path("dict.test/d:word");
    scenario.set_scheme(SCHEME_DICT);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.scheme() != SCHEME_DICT,
           "a non-DICT policy retained the DICT scheme");
  }

  Scenario compatibility;
  compatibility.set_host_path("dict.test/d:word");
  compatibility.set_scheme(SCHEME_DICT);
  NormalizeScenarioForTarget(&compatibility, TargetProfile::kCompatibility);
  Expect(compatibility.scheme() == SCHEME_DICT,
         "compatibility unexpectedly rewrote the DICT scheme");
}

void TestFastLdapPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path(
      "untrusted.invalid:1389/dc=example,dc=com?cn?sub?(objectclass=*)#frag");
  scenario.add_request_headers("X-Ignored: ldap");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.mutable_upload()->set_data("callback upload");
  scenario.mutable_connection()->add_on_readable("search entry");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("stream-only");
  scenario.add_mail_rcpt("recipient@example.test");
  scenario.set_ldap_starttls(true);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastLdap);

  Expect(scenario.scheme() == SCHEME_LDAP,
         "fast LDAP policy did not force LDAP");
  Expect(scenario.host_path() ==
             "ldap.test/dc=example,dc=com?cn?sub?(objectclass=*)#frag",
         "fast LDAP policy did not retain the base-DN and filter suffix");
  Expect(scenario.subsequent_connections_size() == 0 &&
             scenario.request_headers_size() == 0 &&
             !scenario.has_mime_post() && scenario.telnet_options_size() == 0 &&
             !scenario.has_api_plan() && !scenario.has_upload() &&
             scenario.mail_rcpt_size() == 0,
         "fast LDAP policy retained another protocol's shape");
  Expect(scenario.connection().initial_response() == "response sentinel" &&
             scenario.connection().on_readable(0) == "search entry" &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast LDAP policy changed the scripted bind/search bytes or retained "
         "stream-only controls");
  Expect(scenario.ldap_starttls(),
         "fast LDAP policy discarded the bounded StartTLS mode");
}

void TestNonLdapPoliciesClearLdapScheme() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp,
      TargetProfile::kFastMqtt,
      TargetProfile::kTiming,
      TargetProfile::kApi,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path("ldap.test/dc=example,dc=com");
    scenario.set_scheme(SCHEME_LDAP);
    scenario.set_ldap_starttls(true);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.scheme() != SCHEME_LDAP,
           "a non-LDAP policy retained the LDAP scheme");
    Expect(!scenario.ldap_starttls(),
           "a non-LDAP policy retained the StartTLS mode");

    Scenario secure;
    secure.set_host_path("tls.test/dc=example,dc=com");
    secure.set_scheme(SCHEME_LDAPS);

    NormalizeScenarioForTarget(&secure, profile);

    Expect(secure.scheme() != SCHEME_LDAPS,
           "a non-LDAP policy retained the LDAPS scheme");
  }

  Scenario compatibility;
  compatibility.set_host_path("ldap.test/dc=example,dc=com");
  compatibility.set_scheme(SCHEME_LDAP);
  compatibility.set_ldap_starttls(true);
  NormalizeScenarioForTarget(&compatibility, TargetProfile::kCompatibility);
  Expect(compatibility.scheme() == SCHEME_LDAP && compatibility.ldap_starttls(),
         "compatibility unexpectedly rewrote the LDAP StartTLS shape");

  Scenario secure_compatibility;
  secure_compatibility.set_host_path("tls.test/dc=example,dc=com");
  secure_compatibility.set_scheme(SCHEME_LDAPS);
  NormalizeScenarioForTarget(&secure_compatibility,
                             TargetProfile::kCompatibility);
  Expect(secure_compatibility.scheme() == SCHEME_LDAPS,
         "compatibility unexpectedly rewrote the LDAPS scheme");
}

void TestFastLdapsPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_scheme(SCHEME_LDAPS);
  scenario.set_host_path(
      "untrusted.invalid:636/dc=example,dc=com?cn?sub?(objectclass=*)#frag");
  scenario.set_ldap_starttls(true);
  scenario.add_request_headers("X-Ignored: ldaps");
  scenario.mutable_connection()->add_on_readable("search entry");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastLdap);

  Expect(scenario.scheme() == SCHEME_LDAPS,
         "fast LDAP lane did not preserve an explicit LDAPS scheme");
  Expect(scenario.host_path() ==
             "tls.test/dc=example,dc=com?cn?sub?(objectclass=*)#frag",
         "fast LDAP lane did not give LDAPS the certifiable authority");
  Expect(scenario.request_headers_size() == 0 && !scenario.has_mime_post() &&
             !scenario.has_upload() && !scenario.has_api_plan(),
         "fast LDAP lane retained another protocol's shape for LDAPS");
  Expect(scenario.connection().on_readable(0) == "search entry" &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast LDAP lane changed the LDAPS script or retained stream-only "
         "controls");
  Expect(!scenario.ldap_starttls(),
         "fast LDAP lane retained StartTLS for implicit LDAPS");
}

void TestFastRtspPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("untrusted.invalid:554/twister/video?query#fragment");
  scenario.add_request_headers("Require: gzip");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.mutable_upload()->set_data("descriptor body");
  scenario.mutable_upload()->set_terminal(
      curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE);
  scenario.mutable_connection()->add_on_readable("control reply");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("stream-only");

  auto *request = scenario.add_options();
  request->set_option_id(curl::fuzzer::proto::CURLOPT_RTSP_REQUEST);
  request->set_uint_value(0);
  auto *cseq = scenario.add_options();
  cseq->set_option_id(curl::fuzzer::proto::CURLOPT_RTSP_CLIENT_CSEQ);
  cseq->set_uint_value(std::numeric_limits<std::uint64_t>::max());

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastRtsp);

  Expect(scenario.scheme() == SCHEME_RTSP,
         "fast RTSP policy did not force RTSP");
  Expect(scenario.host_path() == "rtsp.test/twister/video?query#fragment",
         "fast RTSP policy did not pin the authority and retain the path");
  Expect(scenario.subsequent_connections_size() == 0 &&
             !scenario.has_mime_post() && scenario.telnet_options_size() == 0 &&
             !scenario.has_api_plan() && !scenario.has_multi_plan(),
         "fast RTSP policy retained another protocol's shape");
  Expect(scenario.request_headers_size() == 1 &&
             scenario.request_headers(0) == "Require: gzip",
         "fast RTSP policy discarded a usable custom request header");
  Expect(scenario.has_upload() && scenario.upload().terminal() ==
                                      curl::fuzzer::proto::UPLOAD_TERMINAL_EOF,
         "fast RTSP policy changed the bounded request body state");
  Expect(scenario.connection().on_readable(0) == "control reply" &&
             scenario.connection().initial_response().empty() &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast RTSP policy changed the request-aligned reply script");
  Expect(RequireOption(scenario, curl::fuzzer::proto::CURLOPT_RTSP_REQUEST,
                       "fast RTSP policy lost its method selector")
                 .uint_value() == CURL_RTSPREQ_OPTIONS,
         "fast RTSP policy did not fold an invalid method onto OPTIONS");
  Expect(RequireOption(scenario, curl::fuzzer::proto::CURLOPT_RTSP_CLIENT_CSEQ,
                       "fast RTSP policy lost its client sequence selector")
                 .uint_value() ==
             static_cast<std::uint64_t>(std::numeric_limits<int>::max()),
         "fast RTSP policy did not clamp the client sequence override");
}

void TestFastRtspPolicyFoldsReceiveOntoOptions() {
  // RECEIVE issues no request and cannot reach the request-aligned peer's
  // FinishRequest() reply path, so it must fold onto OPTIONS rather than
  // leave a mutation that stalls before any scripted exchange.
  Scenario scenario;
  scenario.set_scheme(SCHEME_RTSP);
  scenario.set_host_path("rtsp.test/stream");
  auto *request = scenario.add_options();
  request->set_option_id(curl::fuzzer::proto::CURLOPT_RTSP_REQUEST);
  request->set_uint_value(CURL_RTSPREQ_RECEIVE);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastRtsp);

  Expect(scenario.options_size() == 1 &&
             scenario.options(0).option_id() ==
                 curl::fuzzer::proto::CURLOPT_RTSP_REQUEST &&
             scenario.options(0).uint_value() == CURL_RTSPREQ_OPTIONS,
         "fast RTSP policy retained CURL_RTSPREQ_RECEIVE instead of folding "
         "it onto OPTIONS");
}

void TestNonRtspPoliciesClearRtspScheme() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp, TargetProfile::kDeepHttp,
      TargetProfile::kFastFtp,  TargetProfile::kFastSmtp,
      TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path("rtsp.test/stream");
    scenario.set_scheme(SCHEME_RTSP);
    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.scheme() != SCHEME_RTSP,
           "a non-RTSP policy retained the RTSP scheme");
  }

  Scenario compatibility;
  compatibility.set_host_path("rtsp.test/stream");
  compatibility.set_scheme(SCHEME_RTSP);
  NormalizeScenarioForTarget(&compatibility, TargetProfile::kCompatibility);
  Expect(compatibility.scheme() == SCHEME_RTSP,
         "compatibility unexpectedly rewrote the RTSP input");
}

void TestFastIpfsPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_HTTP, 4096, 17);
  scenario.set_host_path("untrusted.invalid:8080/ignored/path?query#fragment");
  scenario.add_request_headers("X-Gateway: retained");
  scenario.add_telnet_options("TTYPE=ignored");
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.mutable_mime_post()->add_parts()->set_data("mime");
  scenario.mutable_upload()->set_data("upload");
  scenario.mutable_connection()->add_on_readable("gateway response");
  scenario.mutable_connection()->add_server_frames()->set_payload("frame");
  scenario.add_subsequent_connections()->set_initial_response("redirect");

  auto *http_version = scenario.add_options();
  http_version->set_option_id(curl::fuzzer::proto::CURLOPT_HTTP_VERSION);
  http_version->set_uint_value(CURL_HTTP_VERSION_1_1);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastIpfs);

  Expect(scenario.scheme() == SCHEME_IPFS,
         "fast IPFS policy did not select IPFS by default");
  Expect(scenario.host_path().rfind(
             "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
             "/ignored/path?query#fragment",
             0) == 0,
         "fast IPFS policy did not pin the CID and retain the gateway suffix");
  Expect(scenario.subsequent_connections_size() == 0 &&
             !scenario.has_mime_post() && !scenario.has_upload() &&
             scenario.telnet_options_size() == 0 && !scenario.has_api_plan() &&
             !scenario.has_multi_plan(),
         "fast IPFS policy retained another protocol's shape");
  Expect(scenario.request_headers_size() == 1 &&
             scenario.request_headers(0) == "X-Gateway: retained",
         "fast IPFS policy discarded a usable request header");
  Expect(scenario.connection().on_readable(0) == "gateway response" &&
             !scenario.connection().has_backpressure() &&
             scenario.connection().server_frames_size() == 0,
         "fast IPFS policy changed the gateway response script");
  Expect(RequireOption(scenario, curl::fuzzer::proto::CURLOPT_HTTP_VERSION,
                       "fast IPFS policy lost its HTTP version selector")
                 .uint_value() <= CURL_HTTP_VERSION_2TLS,
         "fast IPFS policy retained an unusable HTTP version");

  Scenario ipns;
  ipns.set_scheme(SCHEME_IPNS);
  ipns.set_host_path("untrusted.invalid/site/");
  NormalizeScenarioForTarget(&ipns, TargetProfile::kFastIpfs);
  Expect(
      ipns.scheme() == SCHEME_IPNS &&
          ipns.host_path().rfind(
              "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8"
              "/site/",
              0) == 0,
      "fast IPFS policy did not preserve the IPNS namespace and suffix");
}

void TestNonIpfsPoliciesClearIpfsScheme() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp, TargetProfile::kDeepHttp,
      TargetProfile::kFastFtp,  TargetProfile::kFastSmtp,
      TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_host_path(
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/path");
    scenario.set_scheme(SCHEME_IPFS);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.scheme() != SCHEME_IPFS,
           "a non-IPFS policy retained the IPFS scheme");
  }

  Scenario compatibility;
  compatibility.set_host_path(
      "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/path");
  compatibility.set_scheme(SCHEME_IPNS);
  NormalizeScenarioForTarget(&compatibility, TargetProfile::kCompatibility);
  Expect(compatibility.scheme() == SCHEME_IPNS,
         "compatibility unexpectedly rewrote the IPNS input");
}

void TestProxyTransportPolicy() {
  Scenario remote = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  remote.set_host_path("untrusted.invalid:8443/path?query#fragment");
  remote.set_socks_proxy_mode(curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME);
  remote.set_haproxy_protocol(true);
  remote.set_probe_multi_pollset(true);
  remote.mutable_api_plan()->set_duplicate_easy(true);
  remote.mutable_multi_plan()->set_transfer_count(4);
  remote.mutable_connection()->add_on_readable("reply");

  NormalizeScenarioForTarget(&remote, TargetProfile::kProxyTransport);

  Expect(remote.scheme() == SCHEME_HTTP,
         "proxy-transport policy did not force plaintext HTTP");
  Expect(remote.host_path() == "socks.test/path?query#fragment",
         "proxy-transport policy did not pin the remote-resolution host");
  Expect(remote.socks_proxy_mode() ==
                 curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME &&
             remote.haproxy_protocol() && remote.probe_multi_pollset(),
         "proxy-transport policy discarded an owned mode or poll probe");
  Expect(remote.connection().initial_response().empty() &&
             remote.connection().on_readable_size() == 1,
         "proxy-transport policy did not enforce request-triggered replies");
  Expect(!remote.has_api_plan() && !remote.has_multi_plan(),
         "proxy-transport policy retained unrelated lifecycle work");

  Scenario local;
  local.set_host_path("untrusted.invalid/local");
  local.set_socks_proxy_mode(curl::fuzzer::proto::SOCKS_PROXY_SOCKS5);
  NormalizeScenarioForTarget(&local, TargetProfile::kProxyTransport);
  Expect(local.host_path() == "localhost/local" &&
             local.socks_proxy_mode() ==
                 curl::fuzzer::proto::SOCKS_PROXY_SOCKS5,
         "proxy-transport policy changed the local SOCKS5 mode");

  Scenario unknown;
  unknown.set_host_path("untrusted.invalid/unknown");
  unknown.set_socks_proxy_mode(
      static_cast<curl::fuzzer::proto::SocksProxyMode>(99));
  NormalizeScenarioForTarget(&unknown, TargetProfile::kProxyTransport);
  Expect(unknown.socks_proxy_mode() ==
                 curl::fuzzer::proto::SOCKS_PROXY_SOCKS4 &&
             unknown.host_path() == "localhost/unknown",
         "proxy-transport policy retained an unknown wire mode");

  Scenario other;
  other.set_socks_proxy_mode(curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME);
  other.set_haproxy_protocol(true);
  NormalizeScenarioForTarget(&other, TargetProfile::kFastHttp);
  Expect(other.socks_proxy_mode() == curl::fuzzer::proto::SOCKS_PROXY_SOCKS4 &&
             !other.haproxy_protocol(),
         "a non-proxy policy retained proxy-transport selectors");
}

void TestResolverPolicy() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path("untrusted.invalid:8080/path?query#fragment");
  scenario.set_socks_proxy_mode(curl::fuzzer::proto::SOCKS_PROXY_SOCKS4A);
  scenario.set_haproxy_protocol(true);
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
                 curl::fuzzer::proto::SOCKS_PROXY_SOCKS4 &&
             !scenario.haproxy_protocol(),
         "resolver policy retained another dedicated lane's shape");
  Scenario localhost;
  localhost.set_host_path("untrusted.invalid/no-cache");
  NormalizeScenarioForTarget(&localhost, TargetProfile::kResolver);
  Expect(localhost.host_path() == "localhost/no-cache",
         "empty resolver policy did not retain the localhost path");

  Scenario happy;
  happy.set_host_path("untrusted.invalid/race");
  happy.set_happy_eyeballs(true);
  NormalizeScenarioForTarget(&happy, TargetProfile::kResolver);
  Expect(happy.host_path() == "resolve.test/race",
         "happy-eyeballs policy did not select the cache-backed authority");
  Expect(happy.happy_eyeballs(),
         "resolver policy discarded its happy-eyeballs selector");

  Scenario doh;
  doh.set_host_path("untrusted.invalid/doh");
  doh.set_doh_https_rr(true);
  doh.add_resolve_entries("example.test:443:127.0.0.1");
  doh.set_happy_eyeballs(true);
  doh.mutable_http2_plan();
  NormalizeScenarioForTarget(&doh, TargetProfile::kResolver);
  Expect(doh.scheme() == SCHEME_HTTPS,
         "DoH resolver policy did not select its HTTPS transport");
  Expect(doh.host_path() == "tls.test/doh",
         "DoH resolver policy did not select the TLS authority");
  Expect(doh.resolve_entries_size() == 0 && !doh.happy_eyeballs(),
         "DoH resolver policy retained contradictory address-resolution state");
  Expect(doh.has_http2_plan(),
         "DoH resolver policy discarded the selected ALPN h2 response plan");
  Scenario threaded;
  threaded.set_host_path("untrusted.invalid/threaded");
  threaded.set_resolver_mode(
      curl::fuzzer::proto::RESOLVER_MODE_THREADED_POSITIVE);
  threaded.add_resolve_entries("*:80:203.0.113.1");
  threaded.set_happy_eyeballs(true);
  threaded.set_doh_https_rr(true);
  NormalizeScenarioForTarget(&threaded, TargetProfile::kResolver);
  Expect(threaded.scheme() == SCHEME_HTTP &&
             threaded.host_path() == "resolver-positive.test/threaded",
         "threaded resolver policy did not select its fixed authority");
  Expect(threaded.resolve_entries_size() == 0 && !threaded.happy_eyeballs() &&
             !threaded.doh_https_rr(),
         "threaded resolver policy retained a bypassing resolver source");
  Expect(
      threaded.connection().backpressure().drain_limit() == 1,
      "threaded resolver policy did not install its fixed timed-drive marker");

  Scenario link_local;
  link_local.set_host_path("untrusted.invalid/scope");
  link_local.set_resolver_mode(
      curl::fuzzer::proto::RESOLVER_MODE_THREADED_LINK_LOCAL);
  NormalizeScenarioForTarget(&link_local, TargetProfile::kResolver);
  Expect(link_local.host_path() == "resolver-link-local.test/scope",
         "link-local resolver policy did not select its shim authority");
  Expect(link_local.connection().backpressure().drain_limit() == 1,
         "link-local resolver policy did not install its fixed timed-drive "
         "marker");

  Scenario partial;
  partial.set_host_path("untrusted.invalid/partial");
  partial.set_resolver_mode(
      curl::fuzzer::proto::RESOLVER_MODE_THREADED_PARTIAL);
  NormalizeScenarioForTarget(&partial, TargetProfile::kResolver);
  Expect(partial.host_path() == "resolver-partial.test/partial" &&
             partial.connection().backpressure().drain_limit() == 1,
         "partial resolver policy did not select its deterministic drive");

  Scenario queued_cancel;
  queued_cancel.set_host_path("untrusted.invalid/queued-cancel");
  queued_cancel.set_resolver_mode(
      curl::fuzzer::proto::RESOLVER_MODE_THREADED_QUEUED_CANCEL);
  NormalizeScenarioForTarget(&queued_cancel, TargetProfile::kResolver);
  Expect(queued_cancel.host_path() ==
                 "resolver-queued-cancel.test/queued-cancel" &&
             queued_cancel.connection().backpressure().drain_limit() == 1 &&
             queued_cancel.trace_config() == "+THREADS",
         "queued-cancellation resolver policy did not select its deterministic "
         "drive");

  Scenario unix_socket;
  unix_socket.set_host_path("untrusted.invalid/unix");
  unix_socket.set_resolver_mode(curl::fuzzer::proto::RESOLVER_MODE_UNIX_SOCKET);
  NormalizeScenarioForTarget(&unix_socket, TargetProfile::kResolver);
  Expect(unix_socket.host_path() == "resolver-unix.test/unix",
         "Unix resolver policy did not select its fixed authority");

  Scenario doh_error;
  doh_error.set_host_path("untrusted.invalid/doh-error");
  doh_error.set_resolver_mode(curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR);
  doh_error.mutable_http2_plan()
      ->add_actions()
      ->mutable_headers()
      ->set_status_code(200);
  NormalizeScenarioForTarget(&doh_error, TargetProfile::kResolver);
  Expect(doh_error.scheme() == SCHEME_HTTPS &&
             doh_error.host_path() == "tls.test/doh-error" &&
             doh_error.doh_https_rr() && doh_error.has_http2_plan() &&
             doh_error.http2_plan().actions_size() == 1,
         "DoH error policy did not retain the confined DoH transport");

  Scenario global_lifecycle;
  global_lifecycle.set_host_path("untrusted.invalid/global");
  global_lifecycle.set_resolver_mode(
      curl::fuzzer::proto::RESOLVER_MODE_GLOBAL_LIFECYCLE);
  NormalizeScenarioForTarget(&global_lifecycle, TargetProfile::kResolver);
  Expect(global_lifecycle.host_path() == "localhost/global" &&
             global_lifecycle.scheme() == SCHEME_HTTP,
         "global resolver lifecycle policy did not select localhost");

  Scenario ordinary;
  ordinary.add_resolve_entries("example.test:80:127.0.0.1");
  ordinary.set_happy_eyeballs(true);
  ordinary.set_doh_https_rr(true);
  ordinary.set_resolver_mode(
      curl::fuzzer::proto::RESOLVER_MODE_THREADED_NEGATIVE);
  NormalizeScenarioForTarget(&ordinary, TargetProfile::kFastHttp);
  Expect(ordinary.resolve_entries_size() == 0,
         "non-resolver policy retained structured DNS work");
  Expect(!ordinary.happy_eyeballs(),
         "non-resolver policy retained happy-eyeballs state");
  Expect(!ordinary.doh_https_rr(),
         "non-resolver policy retained the DoH responder selector");
  Expect(ordinary.resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_DEFAULT,
         "non-resolver policy retained the target-local resolver selector");
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

  Scenario smtps = ScenarioWithBackpressure(SCHEME_SMTPS, 2048, 1);
  NormalizeScenarioForTarget(&smtps, TargetProfile::kTiming);
  Expect(smtps.scheme() == SCHEME_HTTP,
         "timing policy left SMTPS on a peerless scheme instead of the "
         "reachable HTTP fallback");

  Scenario imaps = ScenarioWithBackpressure(SCHEME_IMAPS, 2048, 1);
  NormalizeScenarioForTarget(&imaps, TargetProfile::kTiming);
  Expect(imaps.scheme() == SCHEME_HTTP,
         "timing policy left IMAPS on a peerless scheme instead of the "
         "reachable HTTP fallback");

  Scenario pop3s = ScenarioWithBackpressure(SCHEME_POP3S, 2048, 1);
  NormalizeScenarioForTarget(&pop3s, TargetProfile::kTiming);
  Expect(pop3s.scheme() == SCHEME_HTTP,
         "timing policy left POP3S on a peerless scheme instead of the "
         "reachable HTTP fallback");

  Scenario mqtts = ScenarioWithBackpressure(SCHEME_MQTTS, 2048, 1);
  NormalizeScenarioForTarget(&mqtts, TargetProfile::kTiming);
  Expect(mqtts.scheme() == SCHEME_HTTP,
         "timing policy left MQTTS on a peerless scheme instead of the "
         "reachable HTTP fallback");
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

void TestFastHttpCanonicalizesSupportedHttpVersions() {
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
           "fast HTTP policy retained an unsupported HTTP version");
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

int conditional_pruner_calls = 0;
TargetProfile conditional_pruner_profile = TargetProfile::kCompatibility;
bool conditional_pruner_saw_fixed_scheme = false;
std::size_t conditional_pruner_unbounded_size = 0;

void GeneratedConditionalPrunerFixture(Scenario *scenario,
                                       TargetProfile profile) {
  ++conditional_pruner_calls;
  conditional_pruner_profile = profile;
  conditional_pruner_saw_fixed_scheme = scenario->scheme() == SCHEME_HTTP;
  conditional_pruner_unbounded_size =
      static_cast<std::size_t>(scenario->options_size());
  scenario->mutable_options()->DeleteSubrange(0, 1);
}

void TestGeneratedConditionalPrunerRunsBeforeOptionBound() {
  conditional_pruner_calls = 0;
  conditional_pruner_profile = TargetProfile::kCompatibility;
  conditional_pruner_saw_fixed_scheme = false;
  conditional_pruner_unbounded_size = 0;

  Scenario scenario;
  scenario.set_scheme(SCHEME_TFTP);
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  for (std::size_t index = 0;
       index + 1 < proto_fuzzer::scenario_limits::kMaxOptions; ++index) {
    scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  }
  scenario.add_options()->set_option_id(curl::fuzzer::proto::CURLOPT_USERAGENT);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kFastHttp,
                             &GeneratedConditionalPrunerFixture);

  Expect(conditional_pruner_calls == 1 &&
             conditional_pruner_profile == TargetProfile::kFastHttp,
         "target policy did not invoke the generated conditional pruner once");
  Expect(conditional_pruner_saw_fixed_scheme,
         "conditional pruning ran before selector normalization");
  Expect(conditional_pruner_unbounded_size ==
             proto_fuzzer::scenario_limits::kMaxOptions + 1,
         "conditional pruning ran after the shared option bound");
  Expect(static_cast<std::size_t>(scenario.options_size()) ==
                 proto_fuzzer::scenario_limits::kMaxOptions &&
             scenario.options(scenario.options_size() - 1).option_id() ==
                 curl::fuzzer::proto::CURLOPT_USERAGENT,
         "shared bounds did not run after conditional option pruning");
}

bool selector_pruner_saw_canonical_deep_http = false;
bool selector_pruner_saw_canonical_api_drive = false;

void GeneratedSelectorPrunerFixture(Scenario *scenario, TargetProfile profile) {
  if (profile == TargetProfile::kDeepHttp) {
    selector_pruner_saw_canonical_deep_http =
        scenario->proxy_socket_option_mode() ==
            curl::fuzzer::proto::PROXY_SOCKET_OPTION_DEFAULT &&
        scenario->http_transport_mode() ==
            curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY;
  }
  if (profile == TargetProfile::kApi && scenario->has_api_plan()) {
    selector_pruner_saw_canonical_api_drive =
        scenario->api_plan().drive_mode() ==
            curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM &&
        scenario->api_plan().wake_multi() &&
        scenario->api_plan().pause_response_once();
  }
}

void TestGeneratedConditionalPrunerSeesCanonicalSelectors() {
  selector_pruner_saw_canonical_deep_http = false;
  selector_pruner_saw_canonical_api_drive = false;

  Scenario deep_http;
  deep_http.set_http_transport_mode(
      curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY);
  deep_http.set_proxy_socket_option_mode(
      static_cast<curl::fuzzer::proto::ProxySocketOptionMode>(99));
  deep_http.set_haproxy_protocol(true);
  NormalizeScenarioForTarget(&deep_http, TargetProfile::kDeepHttp,
                             &GeneratedSelectorPrunerFixture);
  Expect(selector_pruner_saw_canonical_deep_http,
         "conditional pruning saw malformed deep HTTP route selectors");

  Scenario api;
  auto *plan = api.mutable_api_plan();
  plan->set_drive_mode(static_cast<curl::fuzzer::proto::ApiDriveMode>(99));
  plan->set_wake_multi(true);
  plan->set_pause_response_once(true);
  NormalizeScenarioForTarget(&api, TargetProfile::kApi,
                             &GeneratedSelectorPrunerFixture);
  Expect(selector_pruner_saw_canonical_api_drive,
         "conditional pruning saw a malformed API drive selector");
  Expect(plan->drive_mode() == curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM &&
             plan->wake_multi() && plan->pause_response_once(),
         "API fallback drive lost eligible multi-only work");
}

void TestApiPolicyRetainsAndBoundsItsPlan() {
  Scenario scenario = ScenarioWithBackpressure(SCHEME_WSS, 4096, 17);
  scenario.set_host_path(
      std::string(proto_fuzzer::scenario_limits::kMaxApiStringBytes + 7, 'u'));
  scenario.mutable_mime_post()->add_parts()->set_data("deep HTTP sentinel");
  auto *plan = scenario.mutable_api_plan();
  plan->set_duplicate_easy(true);
  plan->set_reset_easy(true);
  plan->set_attach_share(true);
  plan->set_drive_mode(curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET);
  plan->set_wake_multi(true);
  plan->set_pause_response_once(true);
  plan->set_guess_scheme_url(true);
  plan->set_probe_version_info(true);
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
    plan->add_reentrant_probe_selectors(
        static_cast<std::uint32_t>(index + 300));
  }
  NormalizeScenarioForTarget(&scenario, TargetProfile::kApi);

  Expect(scenario.scheme() == SCHEME_HTTP,
         "API policy did not force plaintext HTTP");
  Expect(scenario.host_path().size() ==
             proto_fuzzer::scenario_limits::kMaxApiStringBytes,
         "API policy retained URL bytes its convenience probes cannot use");
  Expect(!scenario.connection().has_backpressure(),
         "API policy retained timed backpressure");
  Expect(scenario.has_mime_post(),
         "API policy discarded the HTTP state used to populate query results");
  Expect(scenario.has_api_plan(), "API policy discarded its lifecycle plan");
  Expect(scenario.api_plan().duplicate_easy() &&
             scenario.api_plan().reset_easy() &&
             scenario.api_plan().attach_share() &&
             scenario.api_plan().drive_mode() ==
                 curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET &&
             scenario.api_plan().wake_multi() &&
             scenario.api_plan().pause_response_once() &&
             scenario.api_plan().guess_scheme_url() &&
             scenario.api_plan().probe_version_info(),
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

void TestApiMimeRepeatRequiresCallbackShape() {
  Scenario valid;
  valid.set_scheme(SCHEME_HTTP);
  valid.set_host_path("api.test/mime-repeat");
  valid.mutable_upload()->set_data("callback body");
  valid.mutable_mime_post()->add_parts()->set_upload_callback(true);
  auto *plan = valid.mutable_api_plan();
  plan->set_drive_mode(curl::fuzzer::proto::API_DRIVE_CONNECT_ONLY);
  plan->set_wake_multi(true);
  plan->set_pause_response_once(true);
  plan->set_repeat_mime_post(true);

  Scenario missing_upload = valid;
  missing_upload.clear_upload();
  NormalizeScenarioForTarget(&missing_upload, TargetProfile::kApi);
  Expect(!missing_upload.api_plan().repeat_mime_post(),
         "API policy retained MIME reuse without callback bytes");

  Scenario missing_callback = valid;
  missing_callback.mutable_mime_post()->mutable_parts(0)->set_data("memory");
  NormalizeScenarioForTarget(&missing_callback, TargetProfile::kApi);
  Expect(!missing_callback.api_plan().repeat_mime_post(),
         "API policy retained MIME reuse without a callback part");

  NormalizeScenarioForTarget(&valid, TargetProfile::kApi);
  Expect(valid.api_plan().repeat_mime_post() &&
             valid.api_plan().drive_mode() ==
                 curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM &&
             !valid.api_plan().wake_multi() &&
             !valid.api_plan().pause_response_once(),
         "API policy did not isolate the same-easy MIME repeat lifecycle");
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
      TargetProfile::kFastSmtp,
      TargetProfile::kFastFile,
      TargetProfile::kFastImap,
      TargetProfile::kFastPop3,
      TargetProfile::kFastMqtt,
      TargetProfile::kFastDict,
      TargetProfile::kFastLdap,
      TargetProfile::kFastRtsp,
      TargetProfile::kFastIpfs,
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
  plan->set_state_probe_profile(
      curl::fuzzer::proto::MULTI_STATE_PROBE_PROGRESS_RATE_LIMIT);
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
  Expect(scenario.multi_plan().state_probe_profile() ==
             curl::fuzzer::proto::MULTI_STATE_PROBE_PROGRESS_RATE_LIMIT,
         "multi policy discarded its closed state-probe profile");
  Expect(scenario.multi_plan().actions(0).transfer_selector() <
             scenario.multi_plan().transfer_count(),
         "multi policy retained an out-of-range handle selector");
  Expect(static_cast<std::size_t>(scenario.subsequent_connections_size()) ==
             proto_fuzzer::scenario_limits::kMaxMultiTransfers - 1,
         "multi policy retained response scripts beyond its handle count");

  scenario.mutable_multi_plan()->set_state_probe_profile(
      static_cast<curl::fuzzer::proto::MultiStateProbeProfile>(99));
  NormalizeScenarioForTarget(&scenario, TargetProfile::kMulti);
  Expect(scenario.multi_plan().state_probe_profile() ==
             curl::fuzzer::proto::MULTI_STATE_PROBE_NONE,
         "multi policy retained an unknown state-probe profile");
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
      TargetProfile::kFastSmtp,
      TargetProfile::kFastFile,
      TargetProfile::kFastImap,
      TargetProfile::kFastPop3,
      TargetProfile::kFastMqtt,
      TargetProfile::kFastDict,
      TargetProfile::kFastLdap,
      TargetProfile::kFastRtsp,
      TargetProfile::kFastIpfs,
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

void TestApiAllocationFailuresAvoidDebugEventAdapter() {
  Scenario scenario;
  scenario.mutable_api_plan()->set_drive_mode(
      curl::fuzzer::proto::API_DRIVE_EASY_EVENTS);
  scenario.add_fail_allocations(76);

  NormalizeScenarioForTarget(&scenario, TargetProfile::kApi);

  Expect(scenario.api_plan().drive_mode() ==
             curl::fuzzer::proto::API_DRIVE_EASY_PERFORM,
         "API allocation plan retained the debug event adapter");
  Expect(scenario.fail_allocations_size() == 1 &&
             scenario.fail_allocations(0) == 76,
         "API drive normalization changed the allocation plan");
}

void TestAllocationFailuresRetainMimeConversion() {
  for (const auto scheme :
       {SCHEME_HTTP, SCHEME_HTTPS, SCHEME_WS, SCHEME_WSS, SCHEME_IPFS,
        SCHEME_IPNS, SCHEME_IMAP, SCHEME_IMAPS, SCHEME_SMTP, SCHEME_SMTPS}) {
    Scenario scenario;
    scenario.set_scheme(scheme);
    scenario.mutable_mime_post()->add_parts()->set_data("mime body");
    scenario.add_fail_allocations(91);
    auto *crlf = scenario.add_options();
    crlf->set_option_id(curl::fuzzer::proto::CURLOPT_CRLF);
    crlf->set_bool_value(true);
    auto *transfer_text = scenario.add_options();
    transfer_text->set_option_id(curl::fuzzer::proto::CURLOPT_TRANSFERTEXT);
    transfer_text->set_bool_value(true);

    NormalizeScenarioForExecution(&scenario);

    Expect(scenario.has_mime_post() && scenario.fail_allocations_size() == 1 &&
               scenario.fail_allocations(0) == 91,
           "execution normalization changed the MIME allocation plan");
    Expect(scenario.options_size() == 2 &&
               scenario.options(0).option_id() ==
                   curl::fuzzer::proto::CURLOPT_CRLF &&
               scenario.options(1).option_id() ==
                   curl::fuzzer::proto::CURLOPT_TRANSFERTEXT,
           "execution normalization removed MIME conversion coverage");
  }
}

void TestExecutionBoundsLocalPortRange() {
  Scenario scenario;
  auto *large = scenario.add_options();
  large->set_option_id(curl::fuzzer::proto::CURLOPT_LOCALPORTRANGE);
  large->set_uint_value(std::numeric_limits<std::uint64_t>::max());
  auto *boolean = scenario.add_options();
  boolean->set_option_id(curl::fuzzer::proto::CURLOPT_LOCALPORTRANGE);
  boolean->set_bool_value(true);
  auto *mismatched = scenario.add_options();
  mismatched->set_option_id(curl::fuzzer::proto::CURLOPT_LOCALPORTRANGE);
  mismatched->set_string_value("ignored");

  NormalizeScenarioForExecution(&scenario);

  Expect(scenario.options(0).uint_value() == 16 &&
             scenario.options(1).uint_value() == 1 &&
             scenario.options(2).uint_value() == 0,
         "execution policy did not bound the local-port retry range");
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
  Expect(RunModeFor(TargetProfile::kFastSecureWebSocket) ==
             ScenarioRunMode::kTlsWebSocketCoverage,
         "secure WebSocket profile does not authorize its TLS peer");
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
  Expect(RunModeFor(TargetProfile::kProxyTransport) ==
             ScenarioRunMode::kProxyTransportCoverage,
         "proxy-transport profile does not authorize its fixed peer");
  Expect(RunModeFor(TargetProfile::kResolver) ==
             ScenarioRunMode::kResolverCoverage,
         "resolver profile does not authorize DNS/cache work");
  Expect(RunModeFor(TargetProfile::kFastFtp) == ScenarioRunMode::kFtpCoverage,
         "fast FTP profile does not authorize the two-channel peer");
  Expect(RunModeFor(TargetProfile::kFastTftp) == ScenarioRunMode::kTftpCoverage,
         "fast TFTP profile does not authorize the UDP peer");
  Expect(RunModeFor(TargetProfile::kFastSmtp) == ScenarioRunMode::kSmtpCoverage,
         "fast SMTP profile does not authorize the single-connection peer");
  Expect(RunModeFor(TargetProfile::kFastImap) == ScenarioRunMode::kImapCoverage,
         "fast IMAP profile does not authorize the tagged control peer");
  Expect(RunModeFor(TargetProfile::kFastPop3) == ScenarioRunMode::kPop3Coverage,
         "fast POP3 profile does not authorize the control peer");
  Expect(RunModeFor(TargetProfile::kFastMqtt) == ScenarioRunMode::kMqttCoverage,
         "fast MQTT profile does not authorize the packet-aware peer");
  Expect(RunModeFor(TargetProfile::kFastDict) == ScenarioRunMode::kDictCoverage,
         "fast DICT profile does not authorize the command-aware peer");
  Expect(RunModeFor(TargetProfile::kFastFile) == ScenarioRunMode::kFileCoverage,
         "fast FILE profile does not authorize its peerless local reader");
  Expect(RunModeFor(TargetProfile::kFastLdap) == ScenarioRunMode::kLdapCoverage,
         "fast LDAP profile does not authorize the BER-aware peer");
  Expect(RunModeFor(TargetProfile::kFastRtsp) == ScenarioRunMode::kRtspCoverage,
         "fast RTSP profile does not authorize the request-aligned peer");
  Expect(RunModeFor(TargetProfile::kFastIpfs) == ScenarioRunMode::kFastProtocol,
         "fast IPFS profile does not use the in-process HTTP peer");
  Expect(RunModeFor(TargetProfile::kDeepHttp) ==
             ScenarioRunMode::kDeepHttpCoverage,
         "deep HTTP profile does not authorize filename-parser inputs");

  constexpr TargetProfile kCoverageProfiles[] = {
      TargetProfile::kFastWebSocket,
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
  scenario.set_probe_multi_pollset(true);
  scenario.set_socks_proxy_mode(
      curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME);
  scenario.set_haproxy_protocol(true);
  scenario.set_h2_forward_proxy(true);
  scenario.mutable_api_plan()->set_duplicate_easy(true);
  scenario.mutable_multi_plan()->set_transfer_count(4);
  scenario.set_accept_h2_push(true);
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);
  scenario.set_tls_group_profile(
      curl::fuzzer::proto::TLS_GROUP_PROVIDER_DEFAULT);
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
  scenario.add_fail_allocations(9);
  scenario.add_fail_allocations(0);
  scenario.add_fail_allocations(9);
  const std::string before = scenario.SerializeAsString();

  NormalizeScenarioForTarget(&scenario, TargetProfile::kCompatibility);

  Expect(scenario.SerializeAsString() == before,
         "compatibility profile changed an accumulated-corpus input");
}

void TestOnlySupportedPoliciesRetainPollsetProbe() {
  constexpr TargetProfile kOtherPolicies[] = {
      TargetProfile::kFastHttp,
      TargetProfile::kFastHttps,
      TargetProfile::kHttpsH2,
      TargetProfile::kFastHttp2,
      TargetProfile::kFastHttp3,
      TargetProfile::kH2Proxy,
      TargetProfile::kResolver,
      TargetProfile::kFastWebSocket,
      TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,
      TargetProfile::kFastTftp,
      TargetProfile::kFastDict,
      TargetProfile::kFastGopher,
      TargetProfile::kFastFile,
      TargetProfile::kFastLdap,
      TargetProfile::kFastRtsp,
      TargetProfile::kFastIpfs,
      TargetProfile::kApi,
      TargetProfile::kMulti,
      TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kOtherPolicies) {
    Scenario scenario;
    scenario.set_probe_multi_pollset(true);

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(!scenario.probe_multi_pollset(),
           "an unsupported fixed policy retained pollset-probe work");
  }

  Scenario proxy_transport;
  proxy_transport.set_probe_multi_pollset(true);
  NormalizeScenarioForTarget(&proxy_transport, TargetProfile::kProxyTransport);
  Expect(proxy_transport.probe_multi_pollset(),
         "proxy-transport policy discarded its pollset probe");

  Scenario deep_connect;
  deep_connect.set_http_transport_mode(
      curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY);
  deep_connect.set_probe_multi_pollset(true);
  NormalizeScenarioForTarget(&deep_connect, TargetProfile::kDeepHttp);
  Expect(deep_connect.probe_multi_pollset(),
         "deep CONNECT policy discarded its pollset probe");

  Scenario compatibility;
  compatibility.set_probe_multi_pollset(true);
  NormalizeScenarioForTarget(&compatibility, TargetProfile::kCompatibility);
  Expect(compatibility.probe_multi_pollset(),
         "compatibility policy changed an append-only scenario field");
}

void TestAllocationFailurePlansAreCanonicalized() {
  constexpr TargetProfile kFixedProfiles[] = {
      TargetProfile::kFastHttp,
      TargetProfile::kDeepHttp,
      TargetProfile::kFastHttps,
      TargetProfile::kHttpsH2,
      TargetProfile::kFastHttp2,
      TargetProfile::kFastHttp3,
      TargetProfile::kH2Proxy,
      TargetProfile::kProxyTransport,
      TargetProfile::kResolver,
      TargetProfile::kFastWebSocket,
      TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,
      TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,
      TargetProfile::kFastSmtp,
      TargetProfile::kFastFile,
      TargetProfile::kFastImap,
      TargetProfile::kFastPop3,
      TargetProfile::kFastMqtt,
      TargetProfile::kFastDict,
      TargetProfile::kFastLdap,
      TargetProfile::kFastRtsp,
      TargetProfile::kFastIpfs,
      TargetProfile::kFastGopher,
      TargetProfile::kApi,
      TargetProfile::kMulti,
      TargetProfile::kTiming,
  };

  for (const TargetProfile profile : kFixedProfiles) {
    Scenario scenario;
    for (const std::uint32_t ordinal : {9U, 0U, 3U, 9U, 1U, 7U, 2U}) {
      scenario.add_fail_allocations(ordinal);
    }

    NormalizeScenarioForTarget(&scenario, profile);

    Expect(scenario.fail_allocations_size() == 4 &&
               scenario.fail_allocations(0) == 1 &&
               scenario.fail_allocations(1) == 2 &&
               scenario.fail_allocations(2) == 3 &&
               scenario.fail_allocations(3) == 7,
           "fixed policy did not sort, deduplicate, and bound allocation "
           "failures");
    const std::string normalized = scenario.SerializeAsString();
    NormalizeScenarioForTarget(&scenario, profile);
    Expect(scenario.SerializeAsString() == normalized,
           "allocation failure normalization was not idempotent");
  }

  Scenario folded;
  folded.add_fail_allocations(static_cast<std::uint32_t>(
      proto_fuzzer::scenario_limits::kMaxAllocationOrdinal + 1));
  NormalizeScenarioForTarget(&folded, TargetProfile::kFastHttp);
  Expect(folded.fail_allocations_size() == 1 && folded.fail_allocations(0) == 1,
         "allocation failure ordinal was not folded into the runtime range");
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
      TargetProfile::kFastSmtp,
      TargetProfile::kFastFile,
      TargetProfile::kFastImap,
      TargetProfile::kFastPop3,
      TargetProfile::kFastMqtt,
      TargetProfile::kFastDict,
      TargetProfile::kFastLdap,
      TargetProfile::kFastRtsp,
      TargetProfile::kFastIpfs,
      TargetProfile::kFastGopher,
      TargetProfile::kProxyTransport,
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
  plan->set_stream_weight_after_headers(
      std::numeric_limits<std::uint32_t>::max());
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
  Expect(scenario.http2_plan().stream_weight_after_headers() >= 1 &&
             scenario.http2_plan().stream_weight_after_headers() <= 256,
         "structured H2 policy did not bound its post-header transition");

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

void TestH2FlowControlWindowIsPreserved() {
  Scenario seed;
  seed.set_accept_h2_push(true);
  auto *initial_window =
      seed.mutable_http2_plan()->mutable_initial_settings()->add_entries();
  initial_window->set_identifier(4U);
  initial_window->set_value(0U);
  Expect(seed.http2_plan().initial_settings().entries_size() == 1 &&
             seed.http2_plan().initial_settings().entries(0).identifier() ==
                 4U &&
             seed.http2_plan().initial_settings().entries(0).value() == 0U,
         "H2 flow-control fixture does not request an initial zero window");
  for (const TargetProfile profile :
       {TargetProfile::kHttpsH2, TargetProfile::kFastHttp2}) {
    Scenario scenario = seed;
    NormalizeScenarioForTarget(&scenario, profile);
    const auto &settings = scenario.http2_plan().initial_settings();
    Expect(
        settings.entries(0).identifier() == 4U &&
            settings.entries(0).value() == 0U,
        "normalization removed the flow-control fixture's zero stream window");
    Expect(scenario.accept_h2_push(),
           "normalization disabled accepted push in the flow-control fixture");
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
      TargetProfile::kCompatibility,  TargetProfile::kFastHttp,
      TargetProfile::kDeepHttp,       TargetProfile::kFastHttps,
      TargetProfile::kHttpsH2,        TargetProfile::kFastHttp2,
      TargetProfile::kFastHttp3,      TargetProfile::kH2Proxy,
      TargetProfile::kProxyTransport, TargetProfile::kResolver,
      TargetProfile::kFastWebSocket,  TargetProfile::kFastSecureWebSocket,
      TargetProfile::kFastTelnet,     TargetProfile::kFastFtp,
      TargetProfile::kFastTftp,       TargetProfile::kFastSmtp,
      TargetProfile::kFastFile,       TargetProfile::kFastImap,
      TargetProfile::kFastPop3,       TargetProfile::kFastMqtt,
      TargetProfile::kFastDict,       TargetProfile::kFastLdap,
      TargetProfile::kFastRtsp,       TargetProfile::kFastIpfs,
      TargetProfile::kFastGopher,     TargetProfile::kApi,
      TargetProfile::kMulti,          TargetProfile::kTiming,
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
      scenario.add_fail_allocations(9);
      scenario.add_fail_allocations(0);
      scenario.add_fail_allocations(3);
      scenario.add_fail_allocations(9);
      scenario.mutable_api_plan()->set_drive_mode(
          curl::fuzzer::proto::API_DRIVE_EASY_PERFORM);
      scenario.mutable_api_plan()->set_pause_response_once(true);
      scenario.mutable_multi_plan()->set_transfer_count(999999);
      auto *mime =
          scenario.mutable_mime_post()->add_parts()->mutable_generated_data();
      mime->set_pattern("abc");
      mime->set_repeat_count(999999);
      scenario.add_subsequent_connections()
          ->mutable_backpressure()
          ->set_drain_limit(1);

      auto *pin = scenario.add_options();
      pin->set_option_id(curl::fuzzer::proto::CURLOPT_PINNEDPUBLICKEY);
      pin->set_string_value(std::string(
          proto_fuzzer::scenario_limits::kMaxMetadataBytes + 17, 'p'));
      auto *post = scenario.add_options();
      post->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
      post->set_uint_value(7);

      auto *settings =
          scenario.mutable_http2_plan()->mutable_initial_settings();
      auto *window = settings->add_entries();
      window->set_identifier(4);
      window->set_value(0);
      auto *frame_size = settings->add_entries();
      frame_size->set_identifier(5);
      frame_size->set_value(16385);
      auto *invalid = settings->add_entries();
      invalid->set_identifier(0);
      invalid->set_value(999999);
      scenario.mutable_http2_plan()
          ->add_actions()
          ->mutable_headers()
          ->set_end_stream(true);

      scenario.mutable_http3_plan()->set_use_h1_connect_udp_proxy(proxy);
      auto *response = scenario.mutable_http3_plan()
                           ->add_actions()
                           ->mutable_structured_response();
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
  TestDeepHttpTransportPolicy();
  TestDeepHttpProxySocketOptionPolicy();
  TestFastHttpsPolicy();
  TestHttpsH2Policy();
  TestFastHttp2Policy();
  TestTlsPoliciesRejectUnknownCertificateChain();
  TestTlsClientCredentialProfilePolicy();
  TestTlsHandshakeProfilePolicy();
  TestHttpsH2PolicyRejectsUnknownTlsGroupProfile();
  TestOtherPoliciesDiscardTlsGroupProfiles();
  TestFastHttp3PolicyMaterializesUsefulPlan();
  TestFastHttp3ProxyPolicyRetainsStreamScript();
  TestFastHttp3PolicyBoundsOrderedActions();
  TestNonHttp3PoliciesDiscardPlans();
  TestNonTlsPoliciesDiscardTlsCertificateChains();
  TestH2ProxyPolicy();
  TestFastWebSocketPolicy();
  TestFastSecureWebSocketPolicy();
  TestFastTelnetPolicy();
  TestFastFtpPolicy();
  TestFastFtpsPolicy();
  TestNonFtpPoliciesClearFtpsScheme();
  TestFastFilePolicy();
  TestNonFilePoliciesClearFileScheme();
  TestFastTftpPolicy();
  TestFastSmtpPolicy();
  TestFastImapPolicy();
  TestFastPop3Policy();
  TestFastMqttPolicy();
  TestFastMqttsPolicy();
  TestNonMqttPoliciesClearMqttScheme();
  TestFastDictPolicy();
  TestNonDictPoliciesClearDictScheme();
  TestFastLdapPolicy();
  TestNonLdapPoliciesClearLdapScheme();
  TestFastLdapsPolicy();
  TestFastRtspPolicy();
  TestFastRtspPolicyFoldsReceiveOntoOptions();
  TestNonRtspPoliciesClearRtspScheme();
  TestFastIpfsPolicy();
  TestNonIpfsPoliciesClearIpfsScheme();
  TestProxyTransportPolicy();
  TestFastSmtpsPolicy();
  TestFastImapsPolicy();
  TestFastPop3sPolicy();
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
  TestFastHttpCanonicalizesSupportedHttpVersions();
  TestGeneratedConditionalPrunerRunsBeforeOptionBound();
  TestGeneratedConditionalPrunerSeesCanonicalSelectors();
  TestApiPolicyRetainsAndBoundsItsPlan();
  TestApiMimeRepeatRequiresCallbackShape();
  TestProtocolPoliciesDiscardApiPlans();
  TestMultiPolicyRetainsAndBoundsItsPlan();
  TestOtherPoliciesDiscardMultiPlans();
  TestApiEasyDrivesDropMultiOnlyWork();
  TestApiAllocationFailuresAvoidDebugEventAdapter();
  TestAllocationFailuresRetainMimeConversion();
  TestExecutionBoundsLocalPortRange();
  TestProfileRunModes();
  TestCompatibilityProfileIsNoOp();
  TestOnlySupportedPoliciesRetainPollsetProbe();
  TestAllocationFailurePlansAreCanonicalized();
  TestNonH2OriginPoliciesDiscardAcceptedPushMode();
  TestGeneratedMimePolicyPreservesBoundariesAndSharesBudget();
  TestHttpsH2PolicyBoundsStructuredPlan();
  TestH2NormalizationPreservesValidSettings();
  TestH2NormalizationCanonicalizesSettingsWireWidth();
  TestH2FlowControlWindowIsPreserved();
  TestNormalizationBoundsCanonicalOptionStrings();
  TestNormalizationPipelineIsIdempotent();
  return 0;
}
