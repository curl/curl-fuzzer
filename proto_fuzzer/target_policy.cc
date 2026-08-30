/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the per-binary proto mutation policies.

#include "proto_fuzzer/target_policy.h"

#include <algorithm>
#include <cstdint>
#include <string>

#include "proto_fuzzer/scenario_limits.h"
#include "proto_fuzzer/telnet_scenario.h"

namespace proto_fuzzer {

namespace {

// Linux raises smaller socket-buffer requests to an implementation minimum,
// so 2048 is both cheap and reliably small enough to exercise short writes.
constexpr std::uint32_t kDefaultBackpressureBufferBytes = 2048;

// Values outside these ranges do not create useful new socket behavior for
// the harness's bounded 4-16 KiB writes. Keeping them small also prevents a
// mutated uint32 recv size from overflowing the int accepted by setsockopt.
constexpr std::uint32_t kMinBackpressureBufferBytes = 2048;
constexpr std::uint32_t kMaxBackpressureBufferBytes = 4096;
constexpr std::uint32_t kMaxDrainBytesPerIteration = 1024;

/// Remove a repeated-field suffix that the runtime would ignore. Doing this
/// in LPM's postprocessor matters for speed as well as memory: otherwise later
/// mutations keep rediscovering and editing objects that cannot reach curl.
template <typename RepeatedField>
void TrimRepeated(RepeatedField* field, std::size_t limit) {
  const std::size_t size = static_cast<std::size_t>(field->size());
  if (size > limit) {
    field->DeleteSubrange(static_cast<int>(limit), static_cast<int>(size - limit));
  }
}

/// Bound strings passed to NUL-terminated metadata APIs. The runtime applies
/// the same prefix, so deleting the invisible suffix increases useful
/// mutation density without removing any behavior curl could observe.
void TrimMetadata(std::string* value) {
  if (value->size() > scenario_limits::kMaxMetadataBytes) {
    value->resize(scenario_limits::kMaxMetadataBytes);
  }
}

template <typename RepeatedBytes>
void BoundStringValues(RepeatedBytes* values, std::size_t count_limit, std::size_t value_limit) {
  TrimRepeated(values, count_limit);
  for (std::string& value : *values) {
    if (value.size() > value_limit) {
      value.resize(value_limit);
    }
  }
}

template <typename RepeatedBytes>
void BoundHeaderValues(RepeatedBytes* headers, std::size_t limit) {
  BoundStringValues(headers, limit, scenario_limits::kMaxMetadataBytes);
}

/// Keep one response script identical to the prefix MockServer and
/// WebSocketMockServer can deliver. Raw chunks take precedence over structured
/// frames, matching both runtime serializers.
void BoundConnectionShape(curl::fuzzer::proto::Connection* connection) {
  TrimRepeated(connection->mutable_on_readable(), scenario_limits::kMaxResponseChunks);
  const std::size_t raw_count = static_cast<std::size_t>(connection->on_readable_size());
  TrimRepeated(connection->mutable_server_frames(), scenario_limits::kMaxResponseChunks - raw_count);
}

/// Apply the metadata/header limits shared by both MIME part message types.
template <typename Part>
void BoundMimePartMetadata(Part* part) {
  TrimMetadata(part->mutable_name());
  TrimMetadata(part->mutable_filename());
  TrimMetadata(part->mutable_content_type());
  BoundHeaderValues(part->mutable_headers(), scenario_limits::kMaxMimeHeadersPerPart);
}

void BoundMimeLeaf(curl::fuzzer::proto::MimeDataPart* part) {
  BoundMimePartMetadata(part);
  if (part->data().size() > scenario_limits::kMaxMimeDataBytes) {
    part->mutable_data()->resize(scenario_limits::kMaxMimeDataBytes);
  }
}

/// Mirror the runtime's shared top-level/nested part budget in the protobuf
/// itself. A simple per-list cap is insufficient because many bounded child
/// lists could still leave most of the message semantically dead.
void BoundMimeShape(curl::fuzzer::proto::MimePost* post) {
  TrimRepeated(post->mutable_parts(), scenario_limits::kMaxTopLevelMimeParts);
  std::size_t remaining = scenario_limits::kMaxTotalMimeParts;
  std::size_t retained_top_parts = 0;

  while (retained_top_parts < static_cast<std::size_t>(post->parts_size()) && remaining != 0) {
    auto* part = post->mutable_parts(static_cast<int>(retained_top_parts));
    ++retained_top_parts;
    --remaining;
    BoundMimePartMetadata(part);

    if (part->content_case() == curl::fuzzer::proto::MimePart::kData) {
      if (part->data().size() > scenario_limits::kMaxMimeDataBytes) {
        part->mutable_data()->resize(scenario_limits::kMaxMimeDataBytes);
      }
      continue;
    }
    if (part->content_case() != curl::fuzzer::proto::MimePart::kSubparts) {
      continue;
    }

    auto* children = part->mutable_subparts()->mutable_parts();
    TrimRepeated(children, std::min(scenario_limits::kMaxNestedMimeParts, remaining));
    for (auto& child : *children) {
      BoundMimeLeaf(&child);
      --remaining;
    }
  }

  TrimRepeated(post->mutable_parts(), retained_top_parts);
}

/// Remove upload bytes and read steps the callback cannot observe. Clamping
/// individual limits also keeps mutations concentrated on short reads instead
/// of many distinct uint32 values that all collapse to the same 16 KiB cap.
void BoundUploadShape(curl::fuzzer::proto::UploadScript* upload, std::size_t data_limit, std::size_t read_step_limit,
                      std::size_t read_size_limit) {
  if (upload->data().size() > data_limit) {
    upload->mutable_data()->resize(data_limit);
  }
  // RepeatedField<uint32_t> lacks RepeatedPtrField's DeleteSubrange helper;
  // removing the ignored suffix from the end is constant-time per element and
  // preserves the mutation-significant prefix exactly.
  while (static_cast<std::size_t>(upload->read_sizes_size()) > read_step_limit) {
    upload->mutable_read_sizes()->RemoveLast();
  }
  for (int i = 0; i < upload->read_sizes_size(); ++i) {
    if (upload->read_sizes(i) > read_size_limit) {
      upload->set_read_sizes(i, static_cast<std::uint32_t>(read_size_limit));
    }
  }
}

/// Canonicalize all shape limits enforced by the runtime. This runs only in
/// fixed policy targets; the compatibility binary deliberately retains its
/// historical no-postprocessor semantics for existing OSS-Fuzz reproducers.
void BoundScenarioShape(curl::fuzzer::proto::Scenario* scenario) {
  TrimRepeated(scenario->mutable_options(), scenario_limits::kMaxOptions);
  for (auto& option : *scenario->mutable_options()) {
    if (option.value_case() == curl::fuzzer::proto::SetOption::kStringValue) {
      TrimMetadata(option.mutable_string_value());
    }
  }

  BoundHeaderValues(scenario->mutable_request_headers(), scenario_limits::kMaxRequestHeaders);
  BoundStringValues(scenario->mutable_telnet_options(), scenario_limits::kMaxTelnetOptions,
                    scenario_limits::kMaxTelnetOptionBytes);
  if (scenario->has_mime_post()) {
    BoundMimeShape(scenario->mutable_mime_post());
  }
  if (scenario->has_upload()) {
    const bool telnet = scenario->scheme() == curl::fuzzer::proto::SCHEME_TELNET;
    const std::size_t data_limit = telnet ? scenario_limits::kMaxTelnetUploadBytes : scenario_limits::kMaxUploadBytes;
    const std::size_t read_step_limit =
        telnet ? scenario_limits::kMaxTelnetUploadReadSteps : scenario_limits::kMaxUploadReadSteps;
    const std::size_t read_size_limit =
        telnet ? scenario_limits::kMaxTelnetUploadReadSize : scenario_limits::kMaxUploadReadSize;
    BoundUploadShape(scenario->mutable_upload(), data_limit, read_step_limit, read_size_limit);
  }

  BoundConnectionShape(scenario->mutable_connection());
  TrimRepeated(scenario->mutable_subsequent_connections(), scenario_limits::kMaxConnections - 1);
  for (auto& connection : *scenario->mutable_subsequent_connections()) {
    BoundConnectionShape(&connection);
  }
}

/// Return whether an option belongs in the high-throughput HTTP lane. This is
/// deliberately an allowlist rather than a denylist: adding a new structured
/// option should expand deep coverage first, not silently make the fast lane
/// slower before its cost has been measured.
bool IsCheapHttpOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_ACCEPT_ENCODING:
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST:
    case curl::fuzzer::proto::CURLOPT_DISALLOW_USERNAME_IN_URL:
    case curl::fuzzer::proto::CURLOPT_FAILONERROR:
    case curl::fuzzer::proto::CURLOPT_FILETIME:
    case curl::fuzzer::proto::CURLOPT_HEADER:
    case curl::fuzzer::proto::CURLOPT_HTTP09_ALLOWED:
    case curl::fuzzer::proto::CURLOPT_HTTP_CONTENT_DECODING:
    case curl::fuzzer::proto::CURLOPT_HTTP_TRANSFER_DECODING:
    case curl::fuzzer::proto::CURLOPT_HTTP_VERSION:
    case curl::fuzzer::proto::CURLOPT_HTTPGET:
    case curl::fuzzer::proto::CURLOPT_IGNORE_CONTENT_LENGTH:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PATH_AS_IS:
    case curl::fuzzer::proto::CURLOPT_RANGE:
    case curl::fuzzer::proto::CURLOPT_REQUEST_TARGET:
    case curl::fuzzer::proto::CURLOPT_RESUME_FROM_LARGE:
    case curl::fuzzer::proto::CURLOPT_TRANSFER_ENCODING:
    case curl::fuzzer::proto::CURLOPT_USERAGENT:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Compact the option list before applying the general option-count bound.
/// Keeping an allowed option that appears after a long rejected prefix is
/// important for mutation density: bounding first would let expensive options
/// crowd cheap ones out of the only lane intended to approach legacy speed.
void RetainCheapHttpOptions(curl::fuzzer::proto::Scenario* scenario) {
  auto* options = scenario->mutable_options();
  int retained = 0;
  for (int index = 0; index < options->size(); ++index) {
    if (!IsCheapHttpOption(options->Get(index).option_id())) {
      continue;
    }
    if (retained != index) {
      options->SwapElements(retained, index);
    }
    ++retained;
  }
  options->DeleteSubrange(retained, options->size() - retained);
}

/// Return whether a scalar option can influence TELNET without selecting an
/// incompatible transfer mode or introducing external state. Protocol-
/// specific negotiation preferences use Scenario.telnet_options instead.
bool IsCheapTelnetOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_CRLF:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Compact the TELNET option prefix so unrelated HTTP mutations cannot crowd
/// useful credentials, CRLF handling, and transfer-size controls out of the
/// fixed target's general option budget.
void RetainCheapTelnetOptions(curl::fuzzer::proto::Scenario* scenario) {
  auto* options = scenario->mutable_options();
  int retained = 0;
  for (int index = 0; index < options->size(); ++index) {
    if (!IsCheapTelnetOption(options->Get(index).option_id())) {
      continue;
    }
    if (retained != index) {
      options->SwapElements(retained, index);
    }
    ++retained;
  }
  options->DeleteSubrange(retained, options->size() - retained);
}

/// Remove the stateful shapes assigned to the deep HTTP target. This happens
/// before BoundScenarioShape so a fast iteration never walks or normalizes a
/// MIME tree, upload script, or follow-on connection that it will discard.
/// Raw response chunks and request headers stay intact because they reach the
/// core HTTP parser cheaply and provide much of the legacy fuzzer's coverage.
void RemoveDeepHttpShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_mime_post();
  scenario->clear_upload();
  scenario->clear_subsequent_connections();

  auto* connection = scenario->mutable_connection();
  connection->clear_server_frames();
  connection->clear_manual_probes();
  connection->clear_backpressure();
}

/// Remove fields the single-socket WebSocket driver cannot consume. MIME also
/// changes the HTTP request away from a useful Upgrade handshake, so retaining
/// either shape in fixed WS lanes gives LPM mutation work with no WS coverage
/// payoff. The mixed compatibility target has no postprocessor and keeps its
/// historical behavior.
void RemoveIgnoredWebSocketShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_mime_post();
}

/// Remove fields whose only effect in a TELNET lane would be protobuf work or
/// unsafe socket timing. TELNET's curl driver owns the thread until the peer
/// closes, so response backpressure and follow-on sockets cannot be serviced
/// by the outer event loop. Raw response fragments and the bounded upload stay
/// mutation-controlled because the dedicated mock can preload and drain them.
void RemoveNonTelnetShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  scenario->clear_mime_post();

  auto* connection = scenario->mutable_connection();
  connection->clear_server_frames();
  connection->clear_manual_probes();
  connection->clear_backpressure();
}

/// Remove the TELNET-only list and pause outcome from fixed event-driven
/// targets. The compatibility target skips postprocessing, so the runtime
/// repeats the pause-to-EOF guard before installing callbacks.
void RemoveTelnetOnlyShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_telnet_options();
  if (scenario->has_upload() && scenario->upload().terminal() == curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE) {
    scenario->mutable_upload()->set_terminal(curl::fuzzer::proto::UPLOAD_TERMINAL_EOF);
  }
}

/// Preserve useful in-range mutations while folding ineffective extremes onto
/// meaningful boundaries. Zero remains special: it disables that individual
/// control and lets the other control provide the timing target's pressure.
std::uint32_t CanonicalizeNonZero(std::uint32_t value, std::uint32_t minimum, std::uint32_t maximum) {
  if (value == 0) {
    return 0;
  }
  return std::max(minimum, std::min(value, maximum));
}

/// Keep the timing target on the plaintext member of the protocol family.
/// TLS setup has its own cost profile and would obscure whether backpressure
/// mutations are exploring curl's send/receive state machines effectively.
curl::fuzzer::proto::Scheme PlaintextScheme(curl::fuzzer::proto::Scheme scheme) {
  switch (scheme) {
    case curl::fuzzer::proto::SCHEME_WS:
    case curl::fuzzer::proto::SCHEME_WSS:
      return curl::fuzzer::proto::SCHEME_WS;
    case curl::fuzzer::proto::SCHEME_HTTP:
    case curl::fuzzer::proto::SCHEME_HTTPS:
    case curl::fuzzer::proto::SCHEME_TELNET:
    case curl::fuzzer::proto::SCHEME_UNSPECIFIED:
    default:
      return curl::fuzzer::proto::SCHEME_HTTP;
  }
}

/// Remove timing controls from every connection the structured message can
/// carry. Clearing only the primary script would let a mutated redirect turn a
/// fixed fast lane into the timed drive loop after its second socket opens.
void ClearAllBackpressure(curl::fuzzer::proto::Scenario* scenario) {
  if (scenario->has_connection()) {
    scenario->mutable_connection()->clear_backpressure();
  }
  for (auto& connection : *scenario->mutable_subsequent_connections()) {
    connection.clear_backpressure();
  }
}

/// Clamp one explicitly pressure-bearing follow-on script to the same useful
/// ranges as the timing lane's primary connection. An absent configuration is
/// left absent so merely adding a redirect response does not add waits.
void CanonicalizeOptionalBackpressure(curl::fuzzer::proto::Connection* connection) {
  if (!connection->has_backpressure()) {
    return;
  }
  auto* backpressure = connection->mutable_backpressure();
  if (backpressure->recv_buf_bytes() == 0 && backpressure->drain_limit() != 0) {
    backpressure->set_recv_buf_bytes(kDefaultBackpressureBufferBytes);
  } else {
    backpressure->set_recv_buf_bytes(
        CanonicalizeNonZero(backpressure->recv_buf_bytes(), kMinBackpressureBufferBytes, kMaxBackpressureBufferBytes));
  }
  backpressure->set_drain_limit(CanonicalizeNonZero(backpressure->drain_limit(), 1, kMaxDrainBytesPerIteration));
}

}  // namespace

/// Canonicalize the fields that determine which server and drive-loop policy
/// execute. Fast targets discard backpressure because one mutated non-zero
/// scalar otherwise opts an ordinary input into hundreds of timed waits. The
/// timing target does the inverse: it guarantees a non-default buffer setting
/// so its CPU allocation remains focused on the intentionally slower paths.
void ApplyTargetPolicy(curl::fuzzer::proto::Scenario* scenario, TargetPolicy policy) {
  if (scenario == nullptr) {
    return;
  }

  if (policy == TargetPolicy::kFastTelnet) {
    // Set the scheme before general bounds so the TELNET-specific upload and
    // PAUSE budgets are selected rather than event-driven compatibility ones.
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_TELNET);
    RemoveNonTelnetShape(scenario);
    RetainCheapTelnetOptions(scenario);
    BoundScenarioShape(scenario);
    BoundTelnetResponse(scenario->mutable_connection());
    return;
  }

  if (policy == TargetPolicy::kFastHttp) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
    RemoveTelnetOnlyShape(scenario);
    RemoveDeepHttpShape(scenario);
    RetainCheapHttpOptions(scenario);
    BoundScenarioShape(scenario);
    return;
  }

  // Select the lane's scheme before applying scheme-sensitive upload bounds.
  // The scheme field is itself mutable, so bounding first could accidentally
  // give an HTTP/WS case TELNET's smaller payload budget merely because that
  // was the input's pre-policy value.
  switch (policy) {
    case TargetPolicy::kDeepHttp:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
      break;
    case TargetPolicy::kFastHttps:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
      break;
    case TargetPolicy::kFastWebSocket:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_WS);
      break;
    case TargetPolicy::kFastSecureWebSocket:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_WSS);
      break;
    case TargetPolicy::kTiming:
      scenario->set_scheme(PlaintextScheme(scenario->scheme()));
      break;
    case TargetPolicy::kFastHttp:
    case TargetPolicy::kFastTelnet:
      // Both early-return paths selected their scheme above.
      return;
  }

  // TELNET's retained slist and synchronous pause have no observable, safe
  // meaning in the fixed event-driven lanes. Clear them before walking the
  // general shape so only the compatibility and TELNET targets can retain
  // those values.
  RemoveTelnetOnlyShape(scenario);
  BoundScenarioShape(scenario);

  switch (policy) {
    case TargetPolicy::kFastHttp:
      // Handled before the general bounds so discarded deep shapes are never
      // traversed on the fast path.
      return;

    case TargetPolicy::kDeepHttp:
      ClearAllBackpressure(scenario);
      return;

    case TargetPolicy::kFastHttps:
      ClearAllBackpressure(scenario);
      return;

    case TargetPolicy::kFastWebSocket:
      ClearAllBackpressure(scenario);
      RemoveIgnoredWebSocketShape(scenario);
      return;

    case TargetPolicy::kFastSecureWebSocket:
      ClearAllBackpressure(scenario);
      RemoveIgnoredWebSocketShape(scenario);
      return;

    case TargetPolicy::kFastTelnet:
      // Handled before the general bounds so its protocol-specific limits are
      // selected from the start.
      return;

    case TargetPolicy::kTiming: {
      if (scenario->scheme() == curl::fuzzer::proto::SCHEME_WS) {
        RemoveIgnoredWebSocketShape(scenario);
      }
      auto* backpressure = scenario->mutable_connection()->mutable_backpressure();
      if (backpressure->recv_buf_bytes() == 0) {
        // A drain limit alone cannot fill the default AF_UNIX buffer with the
        // harness's bounded upload. Always tighten the socket so this lane
        // represents real pressure, not merely selection of the timed loop.
        backpressure->set_recv_buf_bytes(kDefaultBackpressureBufferBytes);
      } else {
        backpressure->set_recv_buf_bytes(CanonicalizeNonZero(backpressure->recv_buf_bytes(),
                                                             kMinBackpressureBufferBytes, kMaxBackpressureBufferBytes));
      }
      backpressure->set_drain_limit(CanonicalizeNonZero(backpressure->drain_limit(), 1, kMaxDrainBytesPerIteration));
      for (auto& connection : *scenario->mutable_subsequent_connections()) {
        CanonicalizeOptionalBackpressure(&connection);
      }
      return;
    }
  }
}

}  // namespace proto_fuzzer
