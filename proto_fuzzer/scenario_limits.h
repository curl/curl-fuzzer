/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Shared complexity limits for structured scenarios.

#ifndef PROTO_FUZZER_SCENARIO_LIMITS_H_
#define PROTO_FUZZER_SCENARIO_LIMITS_H_

#include <cstddef>

namespace proto_fuzzer::scenario_limits {

// Keep these limits in one place because the target postprocessor and runtime
// must agree about which protobuf suffixes can affect curl. If runtime alone
// ignored an oversized suffix, LPM would still spend mutation and allocation
// work on bytes that can never add coverage.
/// Four sockets cover redirect/auth flows without permitting mutation-sized
/// connection chains to dominate a case.
inline constexpr std::size_t kMaxConnections = 4;
/// Enough response boundaries to exercise incremental parsers while keeping
/// per-perform delivery work fixed.
inline constexpr std::size_t kMaxResponseChunks = 16;
/// Scalar options are cheap, but a finite list prevents protobuf allocation
/// from growing independently of curl work.
inline constexpr std::size_t kMaxOptions = 64;
/// Request headers retain useful combinatorial interactions at this size.
inline constexpr std::size_t kMaxRequestHeaders = 16;
/// Bound top-level MIME traversal before curl recursively serializes it.
inline constexpr std::size_t kMaxTopLevelMimeParts = 16;
/// One bounded child layer is sufficient to enter recursive MIME code.
inline constexpr std::size_t kMaxNestedMimeParts = 8;
/// Share a total budget so many parents cannot multiply their child caps.
inline constexpr std::size_t kMaxTotalMimeParts = 32;
/// Per-part headers are bounded separately from the part count.
inline constexpr std::size_t kMaxMimeHeadersPerPart = 8;
/// Metadata reaches NUL-terminated APIs, where giant suffixes add no coverage.
inline constexpr std::size_t kMaxMetadataBytes = 4096;
/// MIME payloads remain large enough to cross encoder buffer boundaries.
inline constexpr std::size_t kMaxMimeDataBytes = 16384;
// Match the legacy callback's 16 KiB stream: it is large enough to fill the
// deliberately tightened timing-lane socket while remaining cheap per case.
/// Maximum callback-backed body bytes visible in one scenario.
inline constexpr std::size_t kMaxUploadBytes = 16 * 1024;
/// Short-read scripts need several transitions, not mutation-sized sequences.
inline constexpr std::size_t kMaxUploadReadSteps = 32;
/// Larger read requests are indistinguishable once the whole body fits.
inline constexpr std::size_t kMaxUploadReadSize = kMaxUploadBytes;

}  // namespace proto_fuzzer::scenario_limits

#endif  // PROTO_FUZZER_SCENARIO_LIMITS_H_
