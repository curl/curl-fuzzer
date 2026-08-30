/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of shared TELNET response normalization.

#include "proto_fuzzer/telnet_scenario.h"

#include <cstddef>
#include <string>

#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

namespace {

/// Remove a repeated-field suffix that the TELNET runtime cannot observe.
template <typename RepeatedField>
void TrimRepeated(RepeatedField* field, std::size_t limit) {
  const std::size_t size = static_cast<std::size_t>(field->size());
  if (size > limit) {
    field->DeleteSubrange(static_cast<int>(limit), static_cast<int>(size - limit));
  }
}

/// Retain one contiguous fragment without crossing either shared budget.
/// Counting IAC bytes conservatively covers negotiation and subnegotiation
/// replies without duplicating curl's state machine in the harness.
bool BoundTelnetFragment(std::string* fragment, std::size_t* bytes_left, std::size_t* controls_left) {
  std::size_t retained = 0;
  while (retained < fragment->size() && retained < *bytes_left) {
    if (static_cast<unsigned char>((*fragment)[retained]) == 0xff) {
      if (*controls_left == 0) {
        break;
      }
      --*controls_left;
    }
    ++retained;
  }

  const bool complete = retained == fragment->size();
  fragment->resize(retained);
  *bytes_left -= retained;
  return complete;
}

}  // namespace

void BoundTelnetResponse(curl::fuzzer::proto::Connection* connection) {
  if (connection == nullptr) {
    return;
  }

  TrimRepeated(connection->mutable_on_readable(), scenario_limits::kMaxTelnetResponseChunks);

  std::size_t bytes_left = scenario_limits::kMaxTelnetResponseBytes;
  std::size_t controls_left = scenario_limits::kMaxTelnetControlBytes;
  if (!BoundTelnetFragment(connection->mutable_initial_response(), &bytes_left, &controls_left)) {
    connection->clear_on_readable();
    return;
  }

  int retained_chunks = 0;
  for (; retained_chunks < connection->on_readable_size(); ++retained_chunks) {
    std::string* fragment = connection->mutable_on_readable(retained_chunks);
    if (!BoundTelnetFragment(fragment, &bytes_left, &controls_left)) {
      // A genuinely partial prefix is observable and worth retaining. When a
      // previous fragment exhausted the budget, however, keeping the empty
      // truncation would give LPM a field curl can never distinguish.
      if (!fragment->empty()) {
        ++retained_chunks;
      }
      break;
    }
  }

  auto* chunks = connection->mutable_on_readable();
  if (retained_chunks < chunks->size()) {
    chunks->DeleteSubrange(retained_chunks, chunks->size() - retained_chunks);
  }
}

}  // namespace proto_fuzzer
