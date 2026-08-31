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
/// TELNET has only a handful of meaningful negotiated preferences. A short
/// list reaches their combinations without letting response-triggered
/// subnegotiation multiply client output inside curl's blocking driver.
inline constexpr std::size_t kMaxTelnetOptions = 8;
/// Preserve curl's explicit over-1000-byte TTYPE/XDISPLOC rejection paths
/// without giving arbitrary option strings the general metadata budget.
inline constexpr std::size_t kMaxTelnetOptionBytes = 1024;
/// TELNET consumes the peer synchronously, so only this bounded prefix can be
/// preloaded before curl enters its protocol loop.
inline constexpr std::size_t kMaxTelnetResponseBytes = 8 * 1024;
/// Bound reply amplification as well as input bytes. Sixteen IAC markers are
/// enough for every supported negotiation in one seed; stopping before a
/// seventeenth prevents duplicate commands from filling curl's send buffer
/// before the upload callback can drain the peer.
inline constexpr std::size_t kMaxTelnetControlBytes = 16;
/// Raw fragments are all preloaded before TELNET starts. More write-call
/// boundaries add protobuf and syscall work without reliably creating socket-
/// read boundaries on a stream socket.
inline constexpr std::size_t kMaxTelnetResponseChunks = 8;
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
/// TELNET writes upload bytes while its blocking driver owns the thread, so
/// keep total callback work small while retaining payload and IAC coverage.
inline constexpr std::size_t kMaxTelnetUploadBytes = 2048;
/// The TELNET peer drains immediately before each callback result. Keeping one
/// result within the total payload budget means even an all-IAC payload
/// expands to only 4096 bytes, safely below TelnetMockServer's socket-buffer
/// floor. Letting the whole payload through at once also avoids retaining bytes
/// that TELNET's bounded receive loop would never request from the callback.
inline constexpr std::size_t kMaxTelnetUploadReadSize = kMaxTelnetUploadBytes;
/// OSS-Fuzz's local AF_UNIX peer normally fills curl's 4 KiB TELNET reads, so
/// the bounded 8 KiB response gives two useful fragmentation decisions. POSIX
/// permits shorter reads; later callbacks remain safe but use the default cap
/// instead of retaining mostly-dead mutation steps in the throughput lane.
inline constexpr std::size_t kMaxTelnetUploadReadSteps = 2;
/// Short-read scripts need several transitions, not mutation-sized sequences.
inline constexpr std::size_t kMaxUploadReadSteps = 32;
/// Larger read requests are indistinguishable once the whole body fits.
inline constexpr std::size_t kMaxUploadReadSize = kMaxUploadBytes;
/// A share handle has only a small fixed set of shareable data families. The
/// extra slots retain duplicate/unshare transitions without allowing a list
/// of identical selectors to dominate a lifecycle iteration.
inline constexpr std::size_t kMaxApiShareDataSelectors = 16;
/// One API iteration can cheaply inspect several result families, but an
/// unbounded list would repeatedly query identical handle-owned state.
inline constexpr std::size_t kMaxApiInfoSelectors = 32;
/// URL escaping can expand input threefold. Four KiB crosses parser buffer
/// boundaries without letting one convenience-API probe dominate a transfer.
inline constexpr std::size_t kMaxApiStringBytes = 4 * 1024;

}  // namespace proto_fuzzer::scenario_limits

#endif  // PROTO_FUZZER_SCENARIO_LIMITS_H_
