/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the command-aware in-process DICT peer.

#include "proto_fuzzer/dict_mock_server.h"

#include <string_view>

#include "proto_fuzzer/mock_server.h"

namespace proto_fuzzer {

/// Begin without a borrowed protobuf or open socketpair. RunLoop borrows a
/// Scenario only for the synchronous DriveScenario call in which socket
/// callbacks can run.
DictMockServer::DictMockServer() : reply_sent_(false), write_closed_(false) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
DictMockServer::~DictMockServer() = default;

/// Reset DICT's response bookkeeping for a new drive. The shared base has
/// already cleared the transport, reply cursor, transcript, upload capture,
/// and any in-flight body phase.
void DictMockServer::ResetProtocolState() {
  reply_sent_ = false;
  write_closed_ = false;
}

/// Queue end-of-response and half-close exactly once per drive.
void DictMockServer::FinishResponse() {
  if (write_closed_) {
    return;
  }
  write_closed_ = true;
  if (connection_ != nullptr) {
    connection_->ShutdownWrite();
  }
}

/// Answer the first lookup command in the request and ignore CLIENT, which is
/// a bare identification line. curl normally writes CLIENT, the lookup, and
/// QUIT together and then waits for the response body; QUIT is therefore only
/// answered when it arrives without a preceding lookup command (for example a
/// URL with no path).
/// @param line One newline-terminated command from curl.
void DictMockServer::HandleLine(std::string_view line) {
  const std::string_view verb = FirstToken(line);
  if (verb.empty()) {
    return;
  }

  if (TokenEquals(verb, "CLIENT")) {
    return;
  }

  if (reply_sent_ || TokenEquals(verb, "QUIT")) {
    if (!reply_sent_) {
      (void)WriteNextReply();
      reply_sent_ = true;
    }
    FinishResponse();
    return;
  }

  // The first lookup command consumes the scripted body. A script without a
  // reply still closes the response so curl cannot wait for a body forever.
  (void)WriteNextReply();
  reply_sent_ = true;
  FinishResponse();
}

}  // namespace proto_fuzzer
