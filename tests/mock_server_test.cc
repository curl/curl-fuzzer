/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/mock_server.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "proto_fuzzer/api_lifecycle.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/scenario_limits.h"
#include "proto_fuzzer/telnet_mock_server.h"
#include "proto_fuzzer/websocket_mock_server.h"
#include "proto_fuzzer/ws_frame.h"

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
#include <openssl/ech.h>
#include <openssl/ssl.h>

#include "proto_fuzzer/h2_proxy_mock_server.h"
#include "proto_fuzzer/tls_mock_server.h"
#include "proto_fuzzer/tls_test_credentials.h"
#endif

namespace {

using curl::fuzzer::proto::Scenario;

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

size_t CollectResponse(char *contents, size_t size, size_t nmemb,
                       void *userdata) {
  const size_t bytes = size * nmemb;
  static_cast<std::string *>(userdata)->append(contents, bytes);
  return bytes;
}

/// Expose only the protected socket callback for deterministic unit tests. The
/// production path reaches exactly the same method through curl's trampoline.
class TestMockServer : public proto_fuzzer::MockServer {
public:
  using proto_fuzzer::MockServer::HandleOpenSocket;
};

/// Read a fully half-closed scripted response. Every test script either has no
/// chunks or explicitly delivers its final chunk before calling this helper,
/// so a blocking read is deterministic and avoids polling in the test itself.
std::string ReadResponse(curl_socket_t fd) {
  std::string response;
  char buffer[128];
  while (true) {
    const ssize_t count = ::read(fd, buffer, sizeof(buffer));
    if (count <= 0) {
      break;
    }
    response.append(buffer, static_cast<std::size_t>(count));
  }
  return response;
}

/// Count the negotiation bytes waiting immediately before TELNET returns an
/// upload callback result. This mirrors the production pre-read drain while
/// letting the amplification test prove that curl produced the large replies
/// it was designed to exercise.
struct TelnetDrainCounter {
  proto_fuzzer::TelnetMockServer *server;
  std::size_t bytes = 0;
};

void CountTelnetDrain(void *userdata) {
  auto *counter = static_cast<TelnetDrainCounter *>(userdata);
  if (counter != nullptr && counter->server != nullptr &&
      counter->server->connection() != nullptr) {
    counter->bytes += counter->server->connection()->DrainIncoming();
  }
}

void TestFollowOnScriptsAndOldConnectionLifetime() {
  Scenario scenario;
  scenario.mutable_connection()->set_initial_response("first-");
  scenario.mutable_connection()->add_on_readable("tail");
  scenario.add_subsequent_connections()->set_initial_response("second");

  TestMockServer server;
  server.SetScripts(scenario);

  const curl_socket_t first = server.HandleOpenSocket();
  Expect(first != CURL_SOCKET_BAD, "primary scripted socket did not open");
  Expect(server.DeliverNextChunk(), "primary response chunk was not delivered");
  Expect(ReadResponse(first) == "first-tail",
         "primary socket received the wrong response script");

  const curl_socket_t second = server.HandleOpenSocket();
  Expect(second != CURL_SOCKET_BAD, "follow-on scripted socket did not open");
  Expect(ReadResponse(second) == "second",
         "follow-on socket received the wrong response script");

  // Opening `second` must not destroy the server half paired with `first`.
  // curl can finish or tear down an old request after its redirect target is
  // already active; an eager destruction would inject an artificial EPIPE.
  const char late_request_byte = 'x';
  Expect(::send(first, &late_request_byte, 1, MSG_NOSIGNAL) == 1,
         "opening a follow-on socket destroyed the previous peer");

  ::close(first);
  ::close(second);
}

void TestConnectionBudgetIncludesPrimarySocket() {
  Scenario scenario;
  scenario.mutable_connection()->set_initial_response("0");
  for (int i = 1; i <= 7; ++i) {
    scenario.add_subsequent_connections()->set_initial_response(
        std::to_string(i));
  }

  TestMockServer server;
  server.SetScripts(scenario);

  std::vector<curl_socket_t> sockets;
  for (int i = 0; i < 4; ++i) {
    const curl_socket_t fd = server.HandleOpenSocket();
    Expect(fd != CURL_SOCKET_BAD,
           "a socket inside the four-connection budget failed");
    Expect(ReadResponse(fd) == std::to_string(i),
           "connection budget changed script ordering");
    sockets.push_back(fd);
  }
  Expect(server.HandleOpenSocket() == CURL_SOCKET_BAD,
         "mock accepted a fifth socket beyond the runtime budget");

  for (curl_socket_t fd : sockets) {
    ::close(fd);
  }
}

void TestRawChunksPrecedeFramesWithinSharedBudget() {
  Scenario scenario;
  auto *connection = scenario.mutable_connection();
  connection->set_initial_response("initial-");

  std::string expected = "initial-";
  constexpr std::size_t kRawChunks =
      proto_fuzzer::scenario_limits::kMaxResponseChunks - 1;
  for (std::size_t i = 0; i < kRawChunks; ++i) {
    const std::string chunk = "raw" + std::to_string(i) + ";";
    connection->add_on_readable(chunk);
    expected += chunk;
  }

  auto *included_frame = connection->add_server_frames();
  included_frame->set_fin(true);
  included_frame->set_opcode(1);
  included_frame->set_payload("included");
  expected += proto_fuzzer::SerializeWebSocketFrame(*included_frame);

  // The raw chunks consume all but one slot, so this suffix frame must remain
  // invisible even though it is present in the compatibility input.
  auto *capped_frame = connection->add_server_frames();
  capped_frame->set_fin(true);
  capped_frame->set_opcode(2);
  capped_frame->set_payload("excluded");

  TestMockServer server;
  server.SetScripts(scenario);
  const curl_socket_t fd = server.HandleOpenSocket();
  Expect(fd != CURL_SOCKET_BAD, "mixed raw/frame scripted socket did not open");
  for (std::size_t i = 0; i < proto_fuzzer::scenario_limits::kMaxResponseChunks;
       ++i) {
    Expect(server.DeliverNextChunk(),
           "mixed raw/frame script ended before the shared chunk cap");
  }
  Expect(!server.DeliverNextChunk(),
         "mixed raw/frame script exceeded the shared chunk cap");
  Expect(ReadResponse(fd) == expected,
         "raw chunks did not precede the one retained structured frame");
  ::close(fd);
}

void TestEachBorrowedConnectionKeepsItsBackpressure() {
  Scenario scenario;
  scenario.mutable_connection()->mutable_backpressure()->set_drain_limit(2);
  scenario.add_subsequent_connections()
      ->mutable_backpressure()
      ->set_drain_limit(3);

  TestMockServer server;
  server.SetScripts(scenario);

  constexpr char kRequestBytes[] = "request";
  const curl_socket_t first = server.HandleOpenSocket();
  Expect(first != CURL_SOCKET_BAD, "primary pressure socket did not open");
  Expect(::send(first, kRequestBytes, sizeof(kRequestBytes), MSG_NOSIGNAL) ==
             static_cast<ssize_t>(sizeof(kRequestBytes)),
         "primary pressure socket did not accept request bytes");
  Expect(server.connection()->DrainIncoming() == 2,
         "primary script lost its per-connection drain limit");

  const curl_socket_t second = server.HandleOpenSocket();
  Expect(second != CURL_SOCKET_BAD, "follow-on pressure socket did not open");
  Expect(::send(second, kRequestBytes, sizeof(kRequestBytes), MSG_NOSIGNAL) ==
             static_cast<ssize_t>(sizeof(kRequestBytes)),
         "follow-on pressure socket did not accept request bytes");
  Expect(server.connection()->DrainIncoming() == 3,
         "follow-on script did not use its own drain limit");

  ::close(first);
  ::close(second);
}

void TestClosedPeerIsAnOrdinaryWriteFailure() {
  proto_fuzzer::MockConnection connection;
  Expect(connection.ok(), "socketpair for closed-peer test did not open");

  const curl_socket_t peer = connection.take_client_fd();
  Expect(peer != CURL_SOCKET_BAD, "closed-peer test did not obtain client fd");
  ::close(peer);

  const unsigned char byte = 'x';
  // This test process deliberately leaves SIGPIPE at its default disposition.
  // If WriteAll regresses to write(2), the test terminates before this
  // assertion instead of returning a normal socket failure.
  Expect(!connection.WriteAll(&byte, 1),
         "write unexpectedly succeeded after the peer was closed");
}

void TestManualWebSocketDriveUsesBoundedLastOption() {
  Scenario suffix;
  for (std::size_t i = 0; i < proto_fuzzer::scenario_limits::kMaxOptions; ++i) {
    auto *option = suffix.add_options();
    option->set_option_id(curl::fuzzer::proto::CURLOPT_HTTPGET);
    option->set_bool_value(true);
  }
  auto *ignored_manual = suffix.add_options();
  ignored_manual->set_option_id(curl::fuzzer::proto::CURLOPT_CONNECT_ONLY);
  ignored_manual->set_uint_value(2);
  Expect(!proto_fuzzer::ScenarioRequestsManualWsDrive(suffix),
         "option suffix enabled manual WebSocket delivery");

  Scenario overridden;
  auto *manual = overridden.add_options();
  manual->set_option_id(curl::fuzzer::proto::CURLOPT_CONNECT_ONLY);
  manual->set_uint_value(2);
  auto *ordinary = overridden.add_options();
  ordinary->set_option_id(curl::fuzzer::proto::CURLOPT_CONNECT_ONLY);
  ordinary->set_uint_value(0);
  Expect(!proto_fuzzer::ScenarioRequestsManualWsDrive(overridden),
         "earlier CONNECT_ONLY value overrode the final retained value");

  ordinary->set_uint_value(2);
  Expect(proto_fuzzer::ScenarioRequestsManualWsDrive(overridden),
         "final CONNECT_ONLY=2 did not enable manual WebSocket delivery");

  ordinary->set_uint_value(3);
  Expect(proto_fuzzer::ScenarioRequestsManualWsDrive(overridden),
         "rejected CONNECT_ONLY value replaced the last accepted setting");
}

void TestBrotliResponseExpandsAcrossWriteBufferBoundary() {
  // Keep this wire payload synchronized with http_brotli_decode.textproto.
  // Its unusually high expansion ratio lets a small seed exercise curl's
  // decoder loop after the fixed-size output buffer fills.
  constexpr char kCompressed[] =
      "\x1b\x7f\x40\x00\x64\xf1\x98\xcf\x28\x1a\xeb\xaf\xc7\x12\xac\x41"
      "\xab\x42\x62\x51\xf3\xc8\xea\xd9\x7b\x9f\xdc\x1b\x00\x48\x00";
  static_assert(sizeof(kCompressed) - 1 == 31,
                "Brotli payload and Content-Length must stay synchronized");

  Scenario scenario;
  scenario.mutable_connection()->set_initial_response(
      std::string("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                  "Content-Length: 31\r\nContent-Encoding: br\r\n\r\n") +
      std::string(kCompressed, sizeof(kCompressed) - 1));

  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "Brotli test could not allocate an easy handle");
  struct curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_HTTP);
  curl_easy_setopt(easy, CURLOPT_URL, "http://127.0.0.1/brotli");
  curl_easy_setopt(easy, CURLOPT_ACCEPT_ENCODING, "");

  std::string decoded;
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &decoded);

  TestMockServer server;
  server.SetScripts(scenario);
  server.Install(easy);
  server.DriveScenario(easy, scenario);

  const std::string line =
      "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
      "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n";
  std::string expected;
  for (int i = 0; i < 128; ++i) {
    expected += line;
  }
  Expect(decoded == expected,
         "Brotli response did not decode across CURL_MAX_WRITE_SIZE");

  curl_easy_cleanup(easy);
  curl_slist_free_all(connect_to);
}

#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
/// Values retained from a completed TLS drive after its easy handle and peer
/// have been safely dismantled. Tests assert these public/client and
/// server-side views together so a successful HTTP body cannot mask the TLS
/// behavior the corresponding seed promises to cover.
struct TlsTransferResult {
  CURLcode code = CURLE_FAILED_INIT;
  std::string response;
  long verify_result = -1;
  int certificate_count = 0;
  std::vector<std::string> certificate_info;
  bool saw_live_tls_session = false;
  int negotiated_version = 0;
  std::size_t handshake_count = 0;
  std::size_t reused_session_count = 0;
  std::size_t write_retry_count = 0;
  int ech_status = -1;
  std::string ech_inner_name;
  std::string ech_outer_name;
};

/// Add a typed option without spelling protobuf oneof plumbing in each TLS
/// regression. The runtime still consumes it through ApplySetOption.
void AddBoolOption(Scenario *scenario,
                   curl::fuzzer::proto::CurlOptionId option_id, bool value) {
  auto *option = scenario->add_options();
  option->set_option_id(option_id);
  option->set_bool_value(value);
}

void AddUintOption(Scenario *scenario,
                   curl::fuzzer::proto::CurlOptionId option_id,
                   std::uint64_t value) {
  auto *option = scenario->add_options();
  option->set_option_id(option_id);
  option->set_uint_value(value);
}

void AddStringOption(Scenario *scenario,
                     curl::fuzzer::proto::CurlOptionId option_id,
                     const std::string &value) {
  auto *option = scenario->add_options();
  option->set_option_id(option_id);
  option->set_string_value(value);
}

/// Retain request bytes that the production mock normally discards while
/// making room for curl's next write. This test-only transport still uses the
/// same socketpair and drive loop as the fuzzer.
class RequestCapturingConnection final : public proto_fuzzer::MockConnection {
public:
  explicit RequestCapturingConnection(std::string *request)
      : request_(request) {}

  std::size_t DrainIncoming() override {
    const std::size_t previous_size = request_->size();
    ReadAvailable(request_);
    return request_->size() - previous_size;
  }

private:
  std::string *request_;
};

/// Substitute the request-retaining connection without changing MockServer's
/// response scripting or multi-perform behavior.
class RequestCapturingServer final : public proto_fuzzer::MockServer {
public:
  ~RequestCapturingServer() override { ResetConnections(); }

  const std::string &request() const { return request_; }

protected:
  std::unique_ptr<proto_fuzzer::MockConnection> CreateConnection() override {
    return std::make_unique<RequestCapturingConnection>(&request_);
  }

private:
  std::string request_;
};

/// Drive one signing algorithm through the same generated SetOption manifest,
/// request-header owner, and in-process HTTP peer used by deep fuzz inputs.
std::string CaptureHttpsigRequest(std::uint64_t algorithm,
                                  const std::string &key,
                                  const std::string &key_id,
                                  const std::string &components) {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("httpsig.test/signed?view=full");
  scenario.mutable_connection()->add_on_readable(
      "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
  scenario.add_request_headers("Date: Tue, 20 Apr 2021 02:07:55 GMT");
  scenario.add_request_headers("X-Fuzz-Meta: first");
  scenario.add_request_headers("X-Fuzz-Meta: second");
  AddUintOption(&scenario, curl::fuzzer::proto::CURLOPT_HTTPSIG_ALGORITHM,
                algorithm);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_HTTPSIG_KEY, key);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_HTTPSIG_KEYID,
                  key_id);
  if (!components.empty()) {
    AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_HTTPSIG_HEADERS,
                    components);
  }

  CURL *easy = curl_easy_init();
  Expect(easy != nullptr,
         "HTTP Message Signature test could not allocate an easy handle");
  struct curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_HTTP);
  curl_easy_setopt(easy, CURLOPT_URL, "http://httpsig.test/signed?view=full");

  RequestCapturingServer server;
  server.Install(easy);
  for (const auto &option : scenario.options()) {
    Expect(proto_fuzzer::ApplySetOption(easy, option) == CURLE_OK,
           "HTTP Message Signature option was rejected by curl");
  }
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, scenario);
    server.ConfigureRequestData(&request_data);
    Expect(server.DriveScenario(easy, scenario) == CURLE_OK,
           "HTTP Message Signature transfer did not complete");
  }
  const std::string request = server.request();

  curl_easy_cleanup(easy);
  curl_slist_free_all(connect_to);
  return request;
}

void TestHttpsigAlgorithmsEmitSignatureHeaders() {
  // curl's debug-time hook makes the structural header assertions stable
  // without baking a wall-clock-dependent timestamp into this regression.
  const char *const old_force_time = std::getenv("CURL_FORCETIME");
  const bool had_force_time = old_force_time != nullptr;
  const std::string saved_force_time = had_force_time ? old_force_time : "";
  const char *const old_created = std::getenv("CURL_HTTPSIG_CREATED");
  const bool had_created = old_created != nullptr;
  const std::string saved_created = had_created ? old_created : "";
  (void)setenv("CURL_FORCETIME", "1", 1);
  (void)setenv("CURL_HTTPSIG_CREATED", "1618884473", 1);

  const std::string ed25519_request = CaptureHttpsigRequest(
      1,
      "9f8362f87a484a954e6e740c5b4c0e84"
      "229139a20aa8ab56ff66586f6a7d29c5",
      "fuzz-ed25519", "date: method path authority query x-fuzz-meta:");
  Expect(ed25519_request.find(
             "Signature-Input: sig1=(\"date\" \"@method\" \"@path\" "
             "\"@authority\" \"@query\" \"x-fuzz-meta\");created=1618884473;"
             "keyid=\"fuzz-ed25519\";alg=\"ed25519\"\r\n") != std::string::npos,
         "Ed25519 signing did not emit its correlated Signature-Input");
  Expect(ed25519_request.find("Signature: sig1=:") != std::string::npos,
         "Ed25519 signing did not emit a Signature field");

  const std::string hmac_request = CaptureHttpsigRequest(
      2, "7365637265742d66757a7a2d6b6579", "fuzz-hmac-sha256", "");
  Expect(hmac_request.find(
             "Signature-Input: sig1=(\"@method\" \"@authority\" \"@path\" "
             "\"@query\");created=1618884473;keyid=\"fuzz-hmac-sha256\";"
             "alg=\"hmac-sha256\"\r\n") != std::string::npos,
         "HMAC signing did not emit its default Signature-Input components");
  Expect(hmac_request.find("Signature: sig1=:") != std::string::npos,
         "HMAC signing did not emit a Signature field");

  if (had_created) {
    (void)setenv("CURL_HTTPSIG_CREATED", saved_created.c_str(), 1);
  } else {
    (void)unsetenv("CURL_HTTPSIG_CREATED");
  }
  if (had_force_time) {
    (void)setenv("CURL_FORCETIME", saved_force_time.c_str(), 1);
  } else {
    (void)unsetenv("CURL_FORCETIME");
  }
}

/// Construct the common complete-response shape used by TLS behavior tests.
Scenario MakeTlsScenario(const std::string &path, const std::string &body) {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
  scenario.set_host_path("tls.test/" + path);
  scenario.mutable_connection()->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
      "\r\n\r\n" + body);
  return scenario;
}

/// Apply options in ScenarioRunner's production order and retain the exact
/// completion result. This keeps the tests on the same socketpair/multi path
/// as fuzz inputs while making failure-path assertions deterministic.
TlsTransferResult DriveTlsScenario(const Scenario &scenario) {
  TlsTransferResult result;
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "TLS test could not allocate an easy handle");
  struct curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_HTTPS);
  const std::string url = "https://" + scenario.host_path();
  curl_easy_setopt(easy, CURLOPT_URL, url.c_str());

  proto_fuzzer::TlsMockServer server(scenario.tls_certificate_chain());
  server.Install(easy);
  for (const auto &option : scenario.options()) {
    Expect(proto_fuzzer::ApplySetOption(easy, option) == CURLE_OK,
           "TLS scenario option was rejected by curl");
  }
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &result.response);

  result.code = server.DriveScenario(easy, scenario);
  struct curl_certinfo *certificate_info = nullptr;
  (void)curl_easy_getinfo(easy, CURLINFO_SSL_VERIFYRESULT,
                          &result.verify_result);
  if (curl_easy_getinfo(easy, CURLINFO_CERTINFO, &certificate_info) ==
          CURLE_OK &&
      certificate_info != nullptr) {
    result.certificate_count = certificate_info->num_of_certs;
    for (int certificate_index = 0;
         certificate_index < certificate_info->num_of_certs;
         ++certificate_index) {
      for (const curl_slist *entry =
               certificate_info->certinfo[certificate_index];
           entry != nullptr; entry = entry->next) {
        if (entry->data != nullptr) {
          result.certificate_info.emplace_back(entry->data);
        }
      }
    }
  }
  result.saw_live_tls_session = server.saw_live_tls_session();
  result.negotiated_version = server.negotiated_tls_version();
  result.handshake_count = server.completed_handshake_count();
  result.reused_session_count = server.reused_session_count();
  result.write_retry_count = server.write_retry_count();
  result.ech_status = server.ech_status();
  result.ech_inner_name = server.ech_inner_name();
  result.ech_outer_name = server.ech_outer_name();

  curl_easy_cleanup(easy);
  curl_slist_free_all(connect_to);
  return result;
}

bool HasCertificateInfoPrefix(const TlsTransferResult &result,
                              const std::string &prefix) {
  for (const std::string &entry : result.certificate_info) {
    if (entry.compare(0, prefix.size(), prefix) == 0) {
      return true;
    }
  }
  return false;
}

void TestTlsServerCompletesVerifiedTransfer() {
  Scenario scenario = MakeTlsScenario("tls13", "tls");
  AddBoolOption(&scenario, curl::fuzzer::proto::CURLOPT_CERTINFO, true);

  const TlsTransferResult result = DriveTlsScenario(scenario);
  Expect(result.code == CURLE_OK, "verified TLS transfer did not complete");
  Expect(result.response == "tls",
         "verified TLS peer did not deliver decrypted HTTP data");
  Expect(result.verify_result == 0,
         "TLS peer certificate did not verify against the in-memory CA");
  Expect(result.certificate_count >= 1,
         "TLS transfer did not materialize certificate-chain information");
  Expect(result.saw_live_tls_session,
         "TLS transfer did not expose its backend session through getinfo");
  Expect(result.negotiated_version == TLS1_3_VERSION,
         "default TLS seed no longer negotiates TLS 1.3");
  Expect(result.handshake_count == 1,
         "single TLS transfer completed an unexpected number of handshakes");
}

void TestTlsAllKeyTypesReachCertificateInfo() {
  Scenario scenario = MakeTlsScenario("certinfo-all-key-types", "keys");
  scenario.set_tls_certificate_chain(
      curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES);
  AddBoolOption(&scenario, curl::fuzzer::proto::CURLOPT_CERTINFO, true);

  const TlsTransferResult result = DriveTlsScenario(scenario);
  Expect(result.code == CURLE_OK && result.response == "keys",
         "all-key-types TLS chain did not complete a verified transfer");
  Expect(result.verify_result == 0,
         "auxiliary certificate types changed leaf verification");
  Expect(result.certificate_count == 4,
         "all-key-types TLS peer did not send every selected certificate");
  Expect(HasCertificateInfoPrefix(result, "RSA Public Key:"),
         "RSA certificate did not reach ossl_certchain's key formatter");
#ifndef OPENSSL_NO_DSA
  Expect(HasCertificateInfoPrefix(result, "dsa(p):"),
         "DSA certificate did not reach ossl_certchain's key formatter");
#endif
  Expect(HasCertificateInfoPrefix(result, "dh(p):"),
         "DH certificate did not reach ossl_certchain's key formatter");
  Expect(HasCertificateInfoPrefix(result, "Serial Number:-"),
         "negative certificate serial did not reach ossl_certchain");
}

void TestTls12OptionsForceNegotiatedVersion() {
  Scenario scenario = MakeTlsScenario("tls12", "tls12");
  AddUintOption(&scenario, curl::fuzzer::proto::CURLOPT_SSLVERSION,
                CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_2);
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_SSL_CIPHER_LIST,
                  "ECDHE-ECDSA-AES128-GCM-SHA256");
  AddStringOption(&scenario, curl::fuzzer::proto::CURLOPT_SSL_EC_CURVES,
                  "P-256");
  AddStringOption(&scenario,
                  curl::fuzzer::proto::CURLOPT_SSL_SIGNATURE_ALGORITHMS,
                  "ecdsa_secp256r1_sha256");

  const TlsTransferResult result = DriveTlsScenario(scenario);
  Expect(result.code == CURLE_OK && result.response == "tls12",
         "forced TLS 1.2 seed did not complete");
  Expect(result.negotiated_version == TLS1_2_VERSION,
         "SSLVERSION limits did not force TLS 1.2");
  Expect(result.handshake_count == 1,
         "TLS 1.2 transfer completed an unexpected number of handshakes");
}

void TestTlsPublicKeyPins() {
  Scenario matching = MakeTlsScenario("matching-pin", "pinned");
  AddStringOption(&matching, curl::fuzzer::proto::CURLOPT_PINNEDPUBLICKEY,
                  proto_fuzzer::tls_test_credentials::kPublicKeyPin);
  const TlsTransferResult matching_result = DriveTlsScenario(matching);
  Expect(matching_result.code == CURLE_OK &&
             matching_result.response == "pinned",
         "matching in-memory public-key pin was rejected");

  Scenario mismatch = MakeTlsScenario("mismatched-pin", "unreachable");
  AddStringOption(&mismatch, curl::fuzzer::proto::CURLOPT_PINNEDPUBLICKEY,
                  "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
  const TlsTransferResult mismatch_result = DriveTlsScenario(mismatch);
  Expect(
      mismatch_result.code == CURLE_SSL_PINNEDPUBKEYNOTMATCH,
      "mismatched in-memory public-key pin did not reach curl's pin failure");
  Expect(mismatch_result.response.empty(),
         "curl delivered HTTP data after rejecting the peer's public key");
  Expect(mismatch_result.verify_result == 0,
         "ordinary certificate verification failed before the pin comparison");
}

void TestTlsRedirectReusesSession() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
  scenario.set_host_path("tls.test/start");
  AddUintOption(&scenario, curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION, 1);
  AddUintOption(&scenario, curl::fuzzer::proto::CURLOPT_MAXREDIRS, 2);
  AddBoolOption(&scenario, curl::fuzzer::proto::CURLOPT_SSL_SESSIONID_CACHE,
                true);
  scenario.mutable_connection()->set_initial_response(
      "HTTP/1.1 302 Found\r\nLocation: https://tls.test/final\r\nConnection: "
      "close\r\nContent-Length: 0\r\n\r\n");
  scenario.add_subsequent_connections()->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nresumed");

  const TlsTransferResult result = DriveTlsScenario(scenario);
  Expect(result.code == CURLE_OK && result.response == "resumed",
         "TLS redirect did not reach its final response");
  Expect(result.handshake_count == 2,
         "TLS redirect did not complete exactly two handshakes");
  Expect(result.reused_session_count == 1,
         "TLS redirect's second connection did not resume its session");
}

void TestTlsWriteRetryKeepsItsOriginalBoundary() {
  constexpr std::size_t kInitialBodySize = 1024 * 1024;
  constexpr std::size_t kChunkCount =
      proto_fuzzer::scenario_limits::kMaxResponseChunks;
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
  scenario.set_host_path("tls.test/write-retry");
  std::string expected(kInitialBodySize, 'a');
  for (std::size_t index = 0; index < kChunkCount; ++index) {
    scenario.mutable_connection()->add_on_readable("b");
    expected.push_back('b');
  }
  scenario.mutable_connection()->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(expected.size()) +
      "\r\n\r\n" + std::string(kInitialBodySize, 'a'));

  const TlsTransferResult result = DriveTlsScenario(scenario);
  Expect(result.write_retry_count > 0,
         "large TLS response did not exercise SSL_write_ex retry handling");
  Expect(result.code == CURLE_OK && result.response == expected,
         "appending a response chunk corrupted an outstanding TLS write retry");
}

#ifndef OPENSSL_NO_ECH
void TestTlsEchCompletesEncryptedClientHello() {
  Scenario scenario = MakeTlsScenario("ech-success", "ech");
  AddStringOption(
      &scenario, curl::fuzzer::proto::CURLOPT_ECH,
      std::string("ecl:") +
          proto_fuzzer::tls_test_credentials::kEchConfigListBase64);

  const TlsTransferResult result = DriveTlsScenario(scenario);
  Expect(result.code == CURLE_OK && result.response == "ech",
         "ECH transfer did not complete over the encrypted ClientHello");
  Expect(result.handshake_count == 1,
         "ECH transfer completed an unexpected number of handshakes");
  Expect(result.ech_status == SSL_ECH_STATUS_SUCCESS,
         "OpenSSL server did not report successful ECH decryption");
  Expect(result.ech_inner_name == "tls.test",
         "ECH server did not recover tls.test from the inner ClientHello");
  Expect(result.ech_outer_name == "public.test",
         "ECH ClientHello did not retain the configured public outer name");
}
#endif

void TestH2ProxyCarriesAnHttpOriginResponse() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("origin.test/h2-proxy");
  auto *connection = scenario.mutable_connection();
  // An empty SETTINGS frame establishes the server side of the HTTP/2
  // session before curl submits CONNECT on stream 1.
  connection->set_initial_response(
      std::string("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9));
  // Acknowledge curl's settings and accept CONNECT with indexed :status=200.
  connection->add_on_readable(
      std::string("\x00\x00\x00\x04\x01\x00\x00\x00\x00"
                  "\x00\x00\x01\x01\x04\x00\x00\x00\x01\x88",
                  19));
  // The DATA payload is the byte stream seen by curl's inner HTTP/1.1
  // filter. END_STREAM also proves the proxy maps stream closure to EOF.
  connection->add_on_readable(
      std::string("\x00\x00\x28\x00\x01\x00\x00\x00\x01", 9) +
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");

  CURL *easy = curl_easy_init();
  Expect(easy != nullptr,
         "HTTP/2 proxy test could not allocate an easy handle");
  struct curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_HTTP);
  curl_easy_setopt(easy, CURLOPT_URL, "http://origin.test/h2-proxy");

  std::string response;
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &response);

  proto_fuzzer::H2ProxyMockServer server;
  server.Install(easy);
  const CURLcode code = server.DriveScenario(easy, scenario);

  Expect(code == CURLE_OK, "HTTP/2 CONNECT proxy transfer did not complete");
  Expect(server.negotiated_alpn() == "h2",
         "HTTP/2 proxy TLS handshake did not negotiate h2");
  Expect(server.completed_handshake_count() == 1,
         "HTTP/2 proxy completed an unexpected number of TLS handshakes");
  Expect(response == "OK",
         "HTTP/2 proxy did not preserve the tunneled HTTP response");

  curl_easy_cleanup(easy);
  curl_slist_free_all(connect_to);
}
#endif

void TestApiLifecycleCompletesSocketActionTransfer() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("api.test/");
  scenario.mutable_connection()->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
      "6\r\n\r\n");
  scenario.mutable_connection()->add_on_readable("socket");

  auto *plan = scenario.mutable_api_plan();
  plan->set_duplicate_easy(true);
  plan->set_attach_share(true);
  plan->set_drive_mode(curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET);
  plan->set_wake_multi(true);
  for (std::uint32_t selector = 0; selector < 9; ++selector) {
    plan->add_share_data_selectors(selector);
  }
  for (std::uint32_t selector = 0;
       selector < proto_fuzzer::scenario_limits::kMaxApiInfoSelectors;
       ++selector) {
    plan->add_easy_info_selectors(selector);
  }
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr,
         "API lifecycle test could not allocate an easy handle");
  struct curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_HTTP);
  curl_easy_setopt(easy, CURLOPT_URL, "http://api.test/");

  std::string response;
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &response);

  TestMockServer server;
  server.Install(easy);
  auto lifecycle = std::make_unique<proto_fuzzer::ApiLifecycle>(
      easy, *plan, "http://api.test/");
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, scenario);
    server.ConfigureRequestData(&request_data);
    server.DriveScenario(easy, scenario,
                         plan->drive_mode() ==
                             curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET,
                         plan->wake_multi());
    lifecycle->ProbeTransferResults(false);
    lifecycle->ProbeEasyDuplication();
  }

  Expect(response == "socket",
         "socket-action API drive did not complete the scripted HTTP response");

  curl_easy_cleanup(easy);
  lifecycle.reset();
  curl_slist_free_all(connect_to);
}

void TestEasyPerformPreloadsIncrementalResponse() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("api.test/easy");
  scenario.mutable_connection()->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n");
  scenario.mutable_connection()->add_on_readable("easy");

  CURL *easy = curl_easy_init();
  Expect(easy != nullptr,
         "easy-perform test could not allocate an easy handle");
  struct curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_HTTP);
  curl_easy_setopt(easy, CURLOPT_URL, "http://api.test/easy");

  std::string response;
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &response);

  TestMockServer server;
  server.Install(easy);
  server.DriveEasyScenario(easy, scenario);

  Expect(
      response == "easy",
      "curl_easy_perform did not consume the preloaded incremental response");

  curl_easy_cleanup(easy);
  curl_slist_free_all(connect_to);
}

void TestTelnetPreloadsChunksAndNeverReadsStdin() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_TELNET);
  scenario.set_host_path("127.0.0.1/");
  scenario.add_telnet_options("WS=255x65535");

  auto *connection = scenario.mutable_connection();
  // Putting CR-NUL and an IAC negotiation before a separate tail field
  // verifies that the synchronous mock presents one ordered byte stream before
  // curl enters telnet_do(), rather than relying on an outer loop that cannot
  // run then.
  connection->set_initial_response(std::string("banner\r\0", 8) +
                                   std::string("\xff\xfd\x1f", 3));
  connection->add_on_readable("tail\r\n");

  // These knobs are useful for event-driven protocol lanes, but applying
  // either to TELNET can deadlock its blocking send path. Keep them tiny so
  // this test fails by timeout if the TELNET mock ever starts honoring them.
  connection->mutable_backpressure()->set_recv_buf_bytes(1);
  connection->mutable_backpressure()->set_drain_limit(1);

  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "TELNET test could not allocate an easy handle");
  struct curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_TELNET);
  curl_easy_setopt(easy, CURLOPT_URL, "telnet://127.0.0.1/");

  std::string response;
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &response);

  proto_fuzzer::TelnetMockServer server;
  server.Install(easy);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, scenario);
    // An absent TELNET upload must be an immediate in-memory EOF. Installing
    // the callback even here is what prevents curl from falling back to stdin.
    Expect(request_data.upload_callbacks_installed(),
           "TELNET did not replace stdin with an upload callback");
    Expect(!request_data.upload_state().scripted() &&
               request_data.upload_state().data_size() == 0,
           "absent TELNET upload did not become immediate EOF");
    server.ConfigureRequestData(&request_data);
    server.DriveScenario(easy, scenario);
  }

  Expect(response == "banner\rtail\r\n",
         "TELNET did not flatten chunks or normalize CR-NUL data");

  curl_easy_cleanup(easy);
  curl_slist_free_all(connect_to);
}

void TestTelnetMaximumAmplificationCannotBlock() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_TELNET);
  scenario.set_host_path("127.0.0.1/");

  // Two of these variables nearly fill curl's 2048-byte NEW_ENV response;
  // the third reaches the capacity check on every repeated SEND request.
  scenario.add_telnet_options("NEW_ENV=A," + std::string(990, 'a'));
  scenario.add_telnet_options("NEW_ENV=B," + std::string(990, 'b'));
  scenario.add_telnet_options("NEW_ENV=C," + std::string(990, 'c'));

  constexpr char kNewEnvSend[] = "\xff\xfa\x27\x01\xff\xf0";
  std::string peer_response = "x";
  const std::size_t request_count =
      proto_fuzzer::scenario_limits::kMaxTelnetControlBytes / 2;
  for (std::size_t index = 0; index < request_count; ++index) {
    peer_response.append(kNewEnvSend, sizeof(kNewEnvSend) - 1);
  }
  scenario.mutable_connection()->set_initial_response(peer_response);

  // send_telnet_data doubles every IAC, making this the largest upload the
  // TELNET runtime permits between peer drains.
  scenario.mutable_upload()->set_data(std::string(
      proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes, '\xff'));

  CURL *easy = curl_easy_init();
  Expect(easy != nullptr,
         "TELNET amplification test could not allocate an easy handle");
  struct curl_slist *connect_to = proto_fuzzer::ApplyBaselineOptions(
      easy, curl::fuzzer::proto::SCHEME_TELNET);
  curl_easy_setopt(easy, CURLOPT_URL, "telnet://127.0.0.1/");

  std::string response;
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &CollectResponse);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, &response);

  proto_fuzzer::TelnetMockServer server;
  server.Install(easy);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, scenario);
    server.ConfigureRequestData(&request_data);
    TelnetDrainCounter counter{&server};
    request_data.SetBeforeUploadReadCallback(&CountTelnetDrain, &counter);
    server.DriveScenario(easy, scenario);

    // Each response is about 1992 bytes. Keep the lower bound independent of
    // curl's exact formatting while proving all repeated large replies ran.
    Expect(counter.bytes >= request_count * 1900,
           "TELNET did not produce every amplified NEW_ENV reply");
    Expect(request_data.upload_state().offset() ==
               proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes,
           "TELNET did not consume the maximum all-IAC upload");
    curl_off_t uploaded = 0;
    Expect(curl_easy_getinfo(easy, CURLINFO_SIZE_UPLOAD_T, &uploaded) ==
                   CURLE_OK &&
               uploaded ==
                   static_cast<curl_off_t>(
                       proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes),
           "TELNET did not finish sending the doubled-IAC upload");
  }

  Expect(response == "x",
         "TELNET amplification controls leaked into response data");

  curl_easy_cleanup(easy);
  curl_slist_free_all(connect_to);
}

} // namespace

int main() {
  TestFollowOnScriptsAndOldConnectionLifetime();
  TestConnectionBudgetIncludesPrimarySocket();
  TestRawChunksPrecedeFramesWithinSharedBudget();
  TestEachBorrowedConnectionKeepsItsBackpressure();
  TestClosedPeerIsAnOrdinaryWriteFailure();
  TestManualWebSocketDriveUsesBoundedLastOption();
  TestBrotliResponseExpandsAcrossWriteBufferBoundary();
#if defined(PROTO_FUZZER_HAS_TLS_MOCK_SERVER)
  TestHttpsigAlgorithmsEmitSignatureHeaders();
  TestTlsServerCompletesVerifiedTransfer();
  TestTlsAllKeyTypesReachCertificateInfo();
  TestTls12OptionsForceNegotiatedVersion();
  TestTlsPublicKeyPins();
  TestTlsRedirectReusesSession();
  TestTlsWriteRetryKeepsItsOriginalBoundary();
#ifndef OPENSSL_NO_ECH
  TestTlsEchCompletesEncryptedClientHello();
#endif
  TestH2ProxyCarriesAnHttpOriginResponse();
#endif
  TestApiLifecycleCompletesSocketActionTransfer();
  TestEasyPerformPreloadsIncrementalResponse();
  TestTelnetPreloadsChunksAndNeverReadsStdin();
  TestTelnetMaximumAmplificationCannotBlock();
  return 0;
}
