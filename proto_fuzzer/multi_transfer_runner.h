/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Bounded shared-multi orchestration for concurrent HTTP transfers.

#ifndef PROTO_FUZZER_MULTI_TRANSFER_RUNNER_H_
#define PROTO_FUZZER_MULTI_TRANSFER_RUNNER_H_

#include <cstddef>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

/// Observable lifecycle counts returned to focused unit tests. Fuzz targets
/// ignore these values; crashes and sanitizer findings remain their signal.
struct MultiTransferRunStats {
  /// Easy handles requested after runtime bounds are applied.
  std::size_t configured_handles = 0;
  /// Easy handles successfully added to the shared multi handle.
  std::size_t added_handles = 0;
  /// CURLMSG_DONE records consumed across all configured handles.
  std::size_t completion_messages = 0;
  /// Ordered plan actions consumed, including intentional no-ops.
  std::size_t actions_consumed = 0;
  /// Peer sockets opened while serving the concurrent transfers.
  std::size_t opened_connections = 0;
};

/// @class proto_fuzzer::MultiTransferRunner
/// @brief Drives two to four easy handles through one CURLM and one bounded
///        in-process HTTP peer.
class MultiTransferRunner {
 public:
  MultiTransferRunner();
  ~MultiTransferRunner();

  MultiTransferRunner(const MultiTransferRunner&) = delete;
  MultiTransferRunner& operator=(const MultiTransferRunner&) = delete;

  /// Configure and run the containing Scenario according to its MultiPlan.
  /// Runtime bounds repeat the mutation policy's limits so direct unit-test
  /// and standalone calls cannot make work proportional to unchecked input.
  /// @param scenario HTTP transfer shape and concurrent lifecycle plan.
  /// @return Bounded setup, action, and completion counts.
  MultiTransferRunStats Run(const curl::fuzzer::proto::Scenario& scenario);
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_MULTI_TRANSFER_RUNNER_H_
