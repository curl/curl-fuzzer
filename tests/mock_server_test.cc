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
  TestApiLifecycleCompletesSocketActionTransfer();
  TestEasyPerformPreloadsIncrementalResponse();
  TestTelnetPreloadsChunksAndNeverReadsStdin();
  TestTelnetMaximumAmplificationCannotBlock();
  return 0;
}
