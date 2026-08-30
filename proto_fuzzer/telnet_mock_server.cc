/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the preloaded TELNET mock peer.

#include "proto_fuzzer/telnet_mock_server.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/scenario_limits.h"
#include "proto_fuzzer/telnet_scenario.h"

namespace proto_fuzzer {

namespace {

// BoundTelnetResponse limits worst-case negotiation output to well below this
// floor. Rejecting a surprising platform socket configuration is preferable
// to letting curl's blocking POLLOUT path become a fuzzer timeout.
constexpr std::size_t kMinClientSendBufferBytes = 64 * 1024;

// curl currently builds each TTYPE, XDISPLOC, or NEW_ENV reply in a fixed
// 2048-byte buffer. Charging that whole buffer to every retained IAC is more
// conservative than curl's protocol grammar, while doubled upload bytes and a
// generous allowance for initial/small negotiation frames cover the remaining
// writes that can accumulate before the pre-read drain runs.
constexpr std::size_t kCurlTelnetSuboptionReplyBytes = 2048;
constexpr std::size_t kSmallNegotiationHeadroomBytes = 4 * 1024;
constexpr std::size_t kMaxBufferedClientBytes =
    scenario_limits::kMaxTelnetControlBytes * kCurlTelnetSuboptionReplyBytes +
    2 * scenario_limits::kMaxTelnetUploadBytes + kSmallNegotiationHeadroomBytes;
static_assert(kMaxBufferedClientBytes <= kMinClientSendBufferBytes,
              "TELNET mutation caps exceed the verified client send buffer");

/// Copy only the byte prefix the runtime can preload before applying the
/// control-byte budget. Compatibility inputs bypass the LPM postprocessor, so
/// copying each complete protobuf field and trimming afterwards would briefly
/// duplicate mutation-sized response strings that curl can never observe.
void CopyTelnetResponsePrefix(const curl::fuzzer::proto::Connection& source,
                              curl::fuzzer::proto::Connection* destination) {
  std::size_t bytes_left = scenario_limits::kMaxTelnetResponseBytes;
  const auto copy_fragment = [&bytes_left](const std::string& fragment, std::string* output) {
    const std::size_t retained = std::min(fragment.size(), bytes_left);
    output->assign(fragment.data(), retained);
    bytes_left -= retained;
    return retained == fragment.size();
  };

  if (!copy_fragment(source.initial_response(), destination->mutable_initial_response())) {
    return;
  }

  const std::size_t chunk_count =
      std::min<std::size_t>(scenario_limits::kMaxTelnetResponseChunks, source.on_readable_size());
  for (std::size_t index = 0; index < chunk_count && bytes_left != 0; ++index) {
    if (!copy_fragment(source.on_readable(static_cast<int>(index)), destination->add_on_readable())) {
      break;
    }
  }
}

}  // namespace

/// Start without a borrowed scenario. RunLoop installs the pointer only for
/// the synchronous multi drive in which curl may invoke HandleOpenSocket.
TelnetMockServer::TelnetMockServer() : scenario_(nullptr), socket_opened_(false) {}

/// The base owns and closes the server half after curl releases its client fd.
TelnetMockServer::~TelnetMockServer() = default;

void TelnetMockServer::ConfigureRequestData(ScenarioRequestData* request_data) {
  if (request_data != nullptr) {
    request_data->SetBeforeUploadReadCallback(&DrainBeforeUploadRead, this);
  }
}

void TelnetMockServer::DrainBeforeUploadRead(void* userdata) {
  auto* server = static_cast<TelnetMockServer*>(userdata);
  if (server != nullptr && server->connection_) {
    (void)server->connection_->DrainIncoming();
  }
}

/// Create one socketpair, preload every raw response fragment curl can observe,
/// then half-close the peer before returning the client fd. TELNET's transfer
/// function does not yield to the outer multi loop while it polls, so deferred
/// delivery would turn an ordinary mutation into a timeout. WriteAll uses a
/// non-blocking server fd; if a compatibility input exceeds the socket buffer,
/// the retained prefix is still useful and the half-close still guarantees
/// termination.
/// @return The preloaded client socket, or CURL_SOCKET_BAD on setup failure.
curl_socket_t TelnetMockServer::HandleOpenSocket() {
  if (scenario_ == nullptr || socket_opened_) {
    return CURL_SOCKET_BAD;
  }
  socket_opened_ = true;

  connection_ = std::make_unique<MockConnection>();
  if (!connection_->ok()) {
    connection_.reset();
    return CURL_SOCKET_BAD;
  }

  if (!connection_->EnsureClientSendBufferSize(kMinClientSendBufferBytes)) {
    connection_.reset();
    return CURL_SOCKET_BAD;
  }

  const auto write_bytes = [this](const std::string& bytes) {
    return bytes.empty() || connection_->WriteAll(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
  };

  // Compatibility corpus entries bypass the LPM postprocessor. Copy only the
  // raw prefix TELNET can consume, then normalize it so direct replay gets the
  // same byte/control budgets without traversing HTTP/WS-only fields.
  const auto& source = scenario_->connection();
  curl::fuzzer::proto::Connection script;
  CopyTelnetResponsePrefix(source, &script);
  BoundTelnetResponse(&script);
  bool complete = write_bytes(script.initial_response());
  const std::size_t chunk_count = static_cast<std::size_t>(script.on_readable_size());
  for (std::size_t index = 0; complete && index < chunk_count; ++index) {
    complete = write_bytes(script.on_readable(static_cast<int>(index)));
  }
  (void)complete;

  // Do not apply BackpressureConfig here. curl's TELNET driver sends from
  // inside its blocking protocol loop; tightening the socket would invalidate
  // the minimum-capacity invariant used by the pre-read drain.
  connection_->ShutdownWrite();
  return connection_->take_client_fd();
}

/// Drive a small number of non-waiting multi transitions. The first call that
/// enters telnet_do() sees a preloaded, half-closed peer and therefore returns
/// without relying on the outer loop to deliver bytes. Subsequent calls only
/// settle curl's completion bookkeeping.
/// @param multi Multi handle whose sole easy handle runs the TELNET transfer.
/// @param easy Easy handle already installed on this mock.
/// @param scenario Bounded script to preload when curl opens its socket.
void TelnetMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  (void)easy;
  scenario_ = &scenario;
  socket_opened_ = false;
  connection_.reset();

  int still_running = 1;
  for (int iteration = 0; still_running && iteration < kMaxIdleIterations; ++iteration) {
    const CURLMcode result = curl_multi_perform(multi, &still_running);
    if (result != CURLM_OK) {
      break;
    }
    if (connection_) {
      (void)connection_->DrainIncoming();
    }
  }

  scenario_ = nullptr;
}

}  // namespace proto_fuzzer
