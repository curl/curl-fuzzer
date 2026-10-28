/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the command-aware in-process POP3 peer.

#include "proto_fuzzer/pop3_mock_server.h"

#include <string>
#include <string_view>

#include "proto_fuzzer/allocation_fault_injection.h"

namespace proto_fuzzer {

/// Begin without a borrowed protobuf or open socketpair. RunLoop borrows a
/// Scenario only for the synchronous DriveScenario call in which socket
/// callbacks can run.
Pop3MockServer::Pop3MockServer() = default;

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps MockConnection's complete type
/// local to this translation unit.
Pop3MockServer::~Pop3MockServer() = default;

/// Advance one reply for every complete command. POP3's status lines are
/// self-describing, so the scripted bytes are written unchanged; curl chooses
/// multi-line handling from the command it sent, not from the reply.
/// @param line One newline-terminated command from curl.
void Pop3MockServer::HandleLine(std::string_view line) {
  if (scenario() == nullptr) {
    return;
  }
  const std::string* response = NextControlReply();
  if (response == nullptr || !WriteControlBytes(*response)) {
    return;
  }
  if (!scenario()->pop3_starttls_filter_allocation_failure()) {
    return;
  }
  const bool starttls_accepted = TokenEquals(FirstToken(line), "STLS") && TokenEquals(FirstToken(*response), "+OK");
  if (starttls_accepted) {
    allocation_fault_injection::ArmNextAllocationFailure();
  }
}

/// Queue a +OK for the blocking QUIT that follows easy cleanup, then let the
/// shared transport half-close so an unfinished transfer cannot wait on a
/// reply that will never arrive.
void Pop3MockServer::QueueShutdownReply() { (void)WriteControlBytes(kShutdownReply); }

}  // namespace proto_fuzzer
