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

/// Give the successful-TLS lane a hostname its fixed certificate can verify
/// while retaining the fuzz-controlled path, query, and fragment. Arbitrary
/// authorities remain covered by the compatibility and legacy HTTPS lanes;
/// spending this lane's mutations on URL failures would keep curl's peer-cert
/// and encrypted application-data paths dark.
void CanonicalizeTlsAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("tls.test/");
    return;
  }
  scenario->set_host_path("tls.test" + host_path.substr(suffix_start));
}

/// Both fixed TLS peers support the same closed set of checked-in certificate
/// bundles. Unknown proto3 enum values fall back to the historical EC chain.
void CanonicalizeTlsCertificateChain(curl::fuzzer::proto::Scenario* scenario) {
  switch (scenario->tls_certificate_chain()) {
    case curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC:
    case curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES:
      return;
    default:
      scenario->clear_tls_certificate_chain();
      return;
  }
}

/// Keep the tunneled origin parseable while retaining every path, query, and
/// fragment byte. The fixed numeric proxy endpoint handles routing separately;
/// mutating the origin authority would therefore buy only early URL failures,
/// not additional HTTP/2 proxy behavior.
void CanonicalizeH2ProxyOriginAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("origin.test/");
    return;
  }
  scenario->set_host_path("origin.test" + host_path.substr(suffix_start));
}

/// Give the TFTP lane a parseable filename-bearing URL while retaining the
/// fuzz-controlled path, query, and fragment. The UDP peer rewrites curl's
/// destination after URL parsing, so authority mutations cannot reach another
/// host; canonicalizing them here avoids spending most iterations on failures
/// before curl constructs a TFTP request. An explicit slash is preserved so
/// the missing-filename error remains reachable.
void CanonicalizeTftpAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("tftp.test/file");
    return;
  }
  scenario->set_host_path("tftp.test" + host_path.substr(suffix_start));
}

/// Keep the FTP lane inside the same parseable authority while leaving every
/// path segment and wildcard under mutation control. CONNECT_TO already
/// confines networking, but rejecting malformed authorities before USER/PWD
/// would waste the control/data peer this target uniquely provides.
void CanonicalizeFtpAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("ftp.test/file");
    return;
  }
  scenario->set_host_path("ftp.test" + host_path.substr(suffix_start));
}

/// Put every handle in the multi lane on one origin so connection limits,
/// queueing, and reuse affect real transfers instead of independent hosts.
/// Path/query/fragment bytes remain mutation-controlled.
void CanonicalizeMultiAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("multi.test/");
    return;
  }
  scenario->set_host_path("multi.test" + host_path.substr(suffix_start));
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

/// Trim a protobuf repeated scalar without depending on the container's
/// pointer-field-only DeleteSubrange API. Keeping the mutation-significant
/// prefix matches every runtime selector loop.
template <typename RepeatedScalar>
void TrimRepeatedScalar(RepeatedScalar* values, std::size_t limit) {
  while (static_cast<std::size_t>(values->size()) > limit) {
    values->RemoveLast();
  }
}

/// Keep API work proportional to the fixed descriptor tables used by the
/// runtime. Selector magnitudes stay mutation-controlled because the runtime
/// folds them into the relevant typed table; only suffixes it cannot execute
/// are dead and therefore removed here.
void BoundApiPlanShape(curl::fuzzer::proto::ApiPlan* plan) {
  TrimRepeatedScalar(plan->mutable_share_data_selectors(), scenario_limits::kMaxApiShareDataSelectors);
  TrimRepeatedScalar(plan->mutable_easy_info_selectors(), scenario_limits::kMaxApiInfoSelectors);

  switch (plan->drive_mode()) {
    case curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM:
    case curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET:
      break;
    case curl::fuzzer::proto::API_DRIVE_EASY_PERFORM:
      // Wakeup is a multi-handle API and has no live object in easy mode.
      // Clearing it keeps every retained mutation observable.
      plan->set_wake_multi(false);
      break;
    default:
      plan->set_drive_mode(curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM);
      break;
  }
}

/// Keep concurrent-handle work within the mock's fixed socket and operation
/// budgets. Values are canonicalized here rather than only at runtime so LPM
/// mutates state that the target can actually distinguish.
void BoundMultiPlanShape(curl::fuzzer::proto::MultiPlan* plan) {
  const std::uint32_t minimum = static_cast<std::uint32_t>(scenario_limits::kMinMultiTransfers);
  const std::uint32_t maximum = static_cast<std::uint32_t>(scenario_limits::kMaxMultiTransfers);
  const std::uint32_t transfer_count = std::max(minimum, std::min(plan->transfer_count(), maximum));
  plan->set_transfer_count(transfer_count);
  plan->set_max_host_connections(std::min(plan->max_host_connections(), transfer_count));
  plan->set_max_total_connections(std::min(plan->max_total_connections(), transfer_count));
  plan->set_connection_cache_size(std::min(plan->connection_cache_size(), maximum * 2U));
  TrimRepeated(plan->mutable_actions(), scenario_limits::kMaxMultiActions);

  switch (plan->drive_mode()) {
    case curl::fuzzer::proto::MULTI_DRIVE_PERFORM:
    case curl::fuzzer::proto::MULTI_DRIVE_SOCKET:
      break;
    default:
      plan->set_drive_mode(curl::fuzzer::proto::MULTI_DRIVE_PERFORM);
      break;
  }

  for (auto& action : *plan->mutable_actions()) {
    action.set_transfer_selector(action.transfer_selector() % transfer_count);
    switch (action.kind()) {
      case curl::fuzzer::proto::MULTI_ACTION_NONE:
      case curl::fuzzer::proto::MULTI_ACTION_PAUSE_RECV:
      case curl::fuzzer::proto::MULTI_ACTION_PAUSE_SEND:
      case curl::fuzzer::proto::MULTI_ACTION_PAUSE_ALL:
      case curl::fuzzer::proto::MULTI_ACTION_RESUME:
      case curl::fuzzer::proto::MULTI_ACTION_REMOVE:
      case curl::fuzzer::proto::MULTI_ACTION_READD:
        break;
      default:
        action.set_kind(curl::fuzzer::proto::MULTI_ACTION_NONE);
        break;
    }
  }
}

/// HTTP field names are lowercase RFC token bytes in the structured lane.
/// Replacing (rather than deleting) invalid bytes retains mutation-significant
/// positions while preventing accidental pseudo-headers and encoder failures.
void CanonicalizeHttp3HeaderName(std::string* name) {
  if (name->size() > scenario_limits::kMaxHttp3HeaderNameBytes) {
    name->resize(scenario_limits::kMaxHttp3HeaderNameBytes);
  }
  if (name->empty()) {
    *name = "x-fuzz";
    return;
  }

  for (char& byte : *name) {
    const unsigned char value = static_cast<unsigned char>(byte);
    const bool alpha = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
    const bool digit = value >= '0' && value <= '9';
    const bool punctuation = value == '!' || value == '#' || value == '$' || value == '%' || value == '&' ||
                             value == '\'' || value == '*' || value == '+' || value == '-' || value == '.' ||
                             value == '^' || value == '_' || value == '`' || value == '|' || value == '~';
    if (value >= 'A' && value <= 'Z') {
      byte = static_cast<char>(value - 'A' + 'a');
    } else if (!alpha && !digit && !punctuation) {
      byte = '-';
    }
  }
}

/// Structured field values must not inject another HTTP field or carry NUL
/// into the encoder. Observable malformed bytes remain available in raw stream
/// actions, while this path stays suitable for valid QPACK generation.
void CanonicalizeHttp3HeaderValue(std::string* value) {
  if (value->size() > scenario_limits::kMaxHttp3HeaderValueBytes) {
    value->resize(scenario_limits::kMaxHttp3HeaderValueBytes);
  }
  for (char& byte : *value) {
    const unsigned char character = static_cast<unsigned char>(byte);
    if ((character < 0x20U && character != '\t') || character == 0x7fU) {
      byte = ' ';
    }
  }
}

/// Retain only a prefix of encodable fields within both a count and a shared
/// byte budget. A missing name is materialized as x-fuzz while budget remains,
/// making default-initialized structured headers useful to the peer.
template <typename RepeatedHeaders>
void BoundHttp3Headers(RepeatedHeaders* headers, std::size_t count_limit, std::size_t* remaining_bytes) {
  TrimRepeated(headers, count_limit);
  std::size_t retained = 0;
  while (retained < static_cast<std::size_t>(headers->size()) && *remaining_bytes != 0) {
    auto* header = headers->Mutable(static_cast<int>(retained));
    CanonicalizeHttp3HeaderName(header->mutable_name());
    CanonicalizeHttp3HeaderValue(header->mutable_value());

    if (header->name().size() > *remaining_bytes) {
      header->mutable_name()->resize(*remaining_bytes);
      header->clear_value();
    } else if (header->value().size() > *remaining_bytes - header->name().size()) {
      header->mutable_value()->resize(*remaining_bytes - header->name().size());
    }
    *remaining_bytes -= header->name().size() + header->value().size();
    ++retained;
  }
  TrimRepeated(headers, retained);
}

void CanonicalizeHttp3StreamRole(curl::fuzzer::proto::Http3StreamRole* role) {
  switch (*role) {
    case curl::fuzzer::proto::HTTP3_STREAM_RESPONSE:
    case curl::fuzzer::proto::HTTP3_STREAM_CONTROL:
    case curl::fuzzer::proto::HTTP3_STREAM_QPACK_ENCODER:
    case curl::fuzzer::proto::HTTP3_STREAM_QPACK_DECODER:
      return;
    default:
      *role = curl::fuzzer::proto::HTTP3_STREAM_RESPONSE;
      return;
  }
}

void BoundHttp3RawData(std::string* data, std::size_t* remaining_raw_bytes) {
  const std::size_t limit = std::min(scenario_limits::kMaxHttp3RawWriteBytes, *remaining_raw_bytes);
  if (data->size() > limit) {
    data->resize(limit);
  }
  *remaining_raw_bytes -= data->size();
}

/// Canonicalize one ordered H3 script to the exact bounded prefix that the
/// QUIC peer can execute. Transport setup remains peer-owned; only plaintext
/// HTTP/3 operations are mutation-controlled here.
void BoundHttp3PlanShape(curl::fuzzer::proto::Http3Plan* plan) {
  TrimRepeated(plan->mutable_actions(), scenario_limits::kMaxHttp3Actions);
  if (plan->actions().empty()) {
    auto* response = plan->add_actions()->mutable_structured_response();
    response->set_status_code(200);
    response->set_finish_stream(true);
  }

  std::size_t remaining_header_bytes = scenario_limits::kMaxHttp3HeaderBytes;
  std::size_t remaining_body_bytes = scenario_limits::kMaxHttp3BodyBytes;
  std::size_t remaining_raw_bytes = scenario_limits::kMaxHttp3RawBytes;
  std::size_t retained_actions = 0;
  bool connection_closed = false;
  for (auto& action : *plan->mutable_actions()) {
    if (connection_closed) {
      break;
    }
    ++retained_actions;
    switch (action.action_case()) {
      case curl::fuzzer::proto::Http3Action::kStructuredResponse: {
        auto* response = action.mutable_structured_response();
        if (response->status_code() == 0U) {
          response->set_status_code(200U);
        } else if (response->status_code() < 100U || response->status_code() > 599U) {
          response->set_status_code(100U + response->status_code() % 500U);
        }
        BoundHttp3Headers(response->mutable_response_headers(), scenario_limits::kMaxHttp3Headers,
                          &remaining_header_bytes);
        BoundHttp3Headers(response->mutable_response_trailers(), scenario_limits::kMaxHttp3Trailers,
                          &remaining_header_bytes);
        TrimRepeated(response->mutable_body_chunks(), scenario_limits::kMaxHttp3BodyChunks);
        for (std::string& chunk : *response->mutable_body_chunks()) {
          if (chunk.size() > remaining_body_bytes) {
            chunk.resize(remaining_body_bytes);
          }
          remaining_body_bytes -= chunk.size();
        }
        break;
      }

      case curl::fuzzer::proto::Http3Action::kStreamWrite: {
        auto* write = action.mutable_stream_write();
        auto role = write->role();
        CanonicalizeHttp3StreamRole(&role);
        write->set_role(role);
        BoundHttp3RawData(write->mutable_data(), &remaining_raw_bytes);
        break;
      }

      case curl::fuzzer::proto::Http3Action::kOpenUnidirectionalStream: {
        auto* stream = action.mutable_open_unidirectional_stream();
        BoundHttp3RawData(stream->mutable_data(), &remaining_raw_bytes);
        break;
      }

      case curl::fuzzer::proto::Http3Action::kStreamReset: {
        auto* reset = action.mutable_stream_reset();
        auto role = reset->role();
        CanonicalizeHttp3StreamRole(&role);
        reset->set_role(role);
        reset->set_application_error_code(reset->application_error_code() & scenario_limits::kMaxQuicVarint);
        break;
      }

      case curl::fuzzer::proto::Http3Action::kGoaway:
        action.mutable_goaway()->set_id(action.goaway().id() & scenario_limits::kMaxQuicVarint & ~std::uint64_t{3});
        break;

      case curl::fuzzer::proto::Http3Action::kConnectionClose:
        action.mutable_connection_close()->set_application_error_code(
            action.connection_close().application_error_code() & scenario_limits::kMaxQuicVarint);
        connection_closed = true;
        break;

      case curl::fuzzer::proto::Http3Action::ACTION_NOT_SET: {
        auto* response = action.mutable_structured_response();
        response->set_status_code(200);
        response->set_finish_stream(true);
        break;
      }
    }
  }
  TrimRepeated(plan->mutable_actions(), retained_actions);
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

/// Return whether an option can affect the HTTP/1.1 request carried inside the
/// fixed HTTP/2 CONNECT tunnel. Proxy routing, ALPN, and TLS verification are
/// owned by H2ProxyMockServer and must not be mutation-controlled; HTTP/2 as an
/// inner origin protocol is also excluded because it would require a second
/// frame script and obscure coverage of the outer proxy filter. Stateful HTTP
/// options remain useful here because their wire effects traverse cf-h2-proxy.
bool IsH2ProxyOriginOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_ACCEPT_ENCODING:
    case curl::fuzzer::proto::CURLOPT_ALTSVC_CTRL:
    case curl::fuzzer::proto::CURLOPT_AUTOREFERER:
    case curl::fuzzer::proto::CURLOPT_AWS_SIGV4:
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_COOKIE:
    case curl::fuzzer::proto::CURLOPT_COOKIELIST:
    case curl::fuzzer::proto::CURLOPT_COOKIESESSION:
    case curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST:
    case curl::fuzzer::proto::CURLOPT_DISALLOW_USERNAME_IN_URL:
    case curl::fuzzer::proto::CURLOPT_EXPECT_100_TIMEOUT_MS:
    case curl::fuzzer::proto::CURLOPT_FAILONERROR:
    case curl::fuzzer::proto::CURLOPT_FILETIME:
    case curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION:
    case curl::fuzzer::proto::CURLOPT_FORBID_REUSE:
    case curl::fuzzer::proto::CURLOPT_FRESH_CONNECT:
    case curl::fuzzer::proto::CURLOPT_HEADER:
    case curl::fuzzer::proto::CURLOPT_HSTS_CTRL:
    case curl::fuzzer::proto::CURLOPT_HTTP09_ALLOWED:
    case curl::fuzzer::proto::CURLOPT_HTTPAUTH:
    case curl::fuzzer::proto::CURLOPT_HTTPGET:
    case curl::fuzzer::proto::CURLOPT_HTTP_CONTENT_DECODING:
    case curl::fuzzer::proto::CURLOPT_HTTP_TRANSFER_DECODING:
    case curl::fuzzer::proto::CURLOPT_IGNORE_CONTENT_LENGTH:
    case curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_KEEP_SENDING_ON_ERROR:
    case curl::fuzzer::proto::CURLOPT_MAXAGE_CONN:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_MAXLIFETIME_CONN:
    case curl::fuzzer::proto::CURLOPT_MAXREDIRS:
    case curl::fuzzer::proto::CURLOPT_MIME_OPTIONS:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_PATH_AS_IS:
    case curl::fuzzer::proto::CURLOPT_POST:
    case curl::fuzzer::proto::CURLOPT_POSTFIELDS:
    case curl::fuzzer::proto::CURLOPT_POSTREDIR:
    case curl::fuzzer::proto::CURLOPT_RANGE:
    case curl::fuzzer::proto::CURLOPT_REFERER:
    case curl::fuzzer::proto::CURLOPT_REQUEST_TARGET:
    case curl::fuzzer::proto::CURLOPT_RESUME_FROM_LARGE:
    case curl::fuzzer::proto::CURLOPT_TIMECONDITION:
    case curl::fuzzer::proto::CURLOPT_TIMEVALUE_LARGE:
    case curl::fuzzer::proto::CURLOPT_TRANSFER_ENCODING:
    case curl::fuzzer::proto::CURLOPT_UNRESTRICTED_AUTH:
    case curl::fuzzer::proto::CURLOPT_UPLOAD:
    case curl::fuzzer::proto::CURLOPT_UPLOAD_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_USERAGENT:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
    case curl::fuzzer::proto::CURLOPT_XOAUTH2_BEARER:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Compact an option list before applying the general option-count bound.
/// Keeping a relevant option that appears after a long rejected prefix is
/// important for mutation density: bounding first would let unrelated options
/// crowd useful ones out of a protocol-specific lane.
template <typename Predicate>
void RetainMatchingOptions(curl::fuzzer::proto::Scenario* scenario, Predicate predicate) {
  auto* options = scenario->mutable_options();
  int retained = 0;
  for (int index = 0; index < options->size(); ++index) {
    if (!predicate(options->Get(index).option_id())) {
      continue;
    }
    if (retained != index) {
      options->SwapElements(retained, index);
    }
    ++retained;
  }
  options->DeleteSubrange(retained, options->size() - retained);
}

/// Keep the high-throughput HTTP lane free of options whose setup or state is
/// assigned to a deeper or protocol-specific target.
void RetainCheapHttpOptions(curl::fuzzer::proto::Scenario* scenario) {
  RetainMatchingOptions(scenario, &IsCheapHttpOption);
}

/// Compact the option list before its shared cap so irrelevant TLS, WebSocket,
/// and file-transfer entries cannot crowd out origin traffic mutations.
void RetainH2ProxyOriginOptions(curl::fuzzer::proto::Scenario* scenario) {
  RetainMatchingOptions(scenario, &IsH2ProxyOriginOption);
}

/// HTTP/3 owns QUIC selection, ALPN, routing, and certificate verification in
/// its peer. The tunneled-origin allowlist is deliberately the same set of
/// request-level HTTP controls, and notably excludes CURLOPT_HTTP_VERSION and
/// CURLOPT_CONNECT_ONLY, which could bypass the dedicated transport.
void RetainHttp3RequestOptions(curl::fuzzer::proto::Scenario* scenario) {
  RetainMatchingOptions(scenario, &IsH2ProxyOriginOption);
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
  RetainMatchingOptions(scenario, &IsCheapTelnetOption);
}

/// Return whether an option can change a plaintext FTP transfer serviced by
/// the bounded control/data peer. Active mode and FTPS settings are omitted:
/// retaining them would select socket and TLS behavior this target does not
/// provide, turning otherwise-useful mutations into early setup failures.
bool IsFtpOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_APPEND:
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_CRLF:
    case curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST:
    case curl::fuzzer::proto::CURLOPT_DIRLISTONLY:
    case curl::fuzzer::proto::CURLOPT_FILETIME:
    case curl::fuzzer::proto::CURLOPT_FTP_ACCOUNT:
    case curl::fuzzer::proto::CURLOPT_FTP_ALTERNATIVE_TO_USER:
    case curl::fuzzer::proto::CURLOPT_FTP_CREATE_MISSING_DIRS:
    case curl::fuzzer::proto::CURLOPT_FTP_FILEMETHOD:
    case curl::fuzzer::proto::CURLOPT_FTP_SKIP_PASV_IP:
    case curl::fuzzer::proto::CURLOPT_FTP_USE_EPSV:
    case curl::fuzzer::proto::CURLOPT_FTP_USE_PRET:
    case curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_RANGE:
    case curl::fuzzer::proto::CURLOPT_RESUME_FROM_LARGE:
    case curl::fuzzer::proto::CURLOPT_TIMECONDITION:
    case curl::fuzzer::proto::CURLOPT_TIMEVALUE_LARGE:
    case curl::fuzzer::proto::CURLOPT_TRANSFERTEXT:
    case curl::fuzzer::proto::CURLOPT_UPLOAD:
    case curl::fuzzer::proto::CURLOPT_UPLOAD_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
    case curl::fuzzer::proto::CURLOPT_WILDCARDMATCH:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the FTP target's general option budget focused on states its passive
/// peer can actually advance.
void RetainFtpOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsFtpOption); }

/// Return whether an option affects TFTP request construction, option
/// negotiation, transfer direction, or bounded body delivery. TFTP has no
/// connection reuse or stream-level controls, so retaining those settings
/// would add protobuf work without another state-machine edge in curl.
bool IsTftpOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_CRLF:
    case curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE:
    case curl::fuzzer::proto::CURLOPT_TFTP_NO_OPTIONS:
    case curl::fuzzer::proto::CURLOPT_TRANSFERTEXT:
    case curl::fuzzer::proto::CURLOPT_UPLOAD:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the datagram lane from spending mutations on stream-only options.
void RetainTftpOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsTftpOption); }

/// Decode an integral oneof locally before the generated option canonicalizer
/// runs. Protocol mode bounds are policy, not setopt mechanics: folding them
/// here keeps nearly every mutation on a real FTP/TFTP state while the shared
/// option layer remains unaware of protocol-specific numeric ranges.
std::uint64_t IntegralMutationValue(const curl::fuzzer::proto::SetOption& option) {
  switch (option.value_case()) {
    case curl::fuzzer::proto::SetOption::kUintValue:
      return option.uint_value();
    case curl::fuzzer::proto::SetOption::kBoolValue:
      return option.bool_value() ? 1U : 0U;
    case curl::fuzzer::proto::SetOption::kStringValue:
    case curl::fuzzer::proto::SetOption::VALUE_NOT_SET:
      return 0;
  }
  return 0;
}

/// Fold small FTP enums onto curl's documented domains so random uint64 values
/// do not overwhelmingly stop at setopt validation before issuing a command.
void CanonicalizeFtpOptionModes(curl::fuzzer::proto::Scenario* scenario) {
  for (auto& option : *scenario->mutable_options()) {
    switch (option.option_id()) {
      case curl::fuzzer::proto::CURLOPT_FTP_CREATE_MISSING_DIRS:
        option.set_uint_value(IntegralMutationValue(option) % 3U);
        break;
      case curl::fuzzer::proto::CURLOPT_FTP_FILEMETHOD:
        option.set_uint_value(IntegralMutationValue(option) % 4U);
        break;
      default:
        break;
    }
  }
}

/// TFTP accepts block sizes from 8 through 65464. Mapping zero or a mismatched
/// oneof to the default 512 preserves a common valid request, while saturating
/// other values retains both lower/upper parser boundaries under mutation.
void CanonicalizeTftpOptionModes(curl::fuzzer::proto::Scenario* scenario) {
  for (auto& option : *scenario->mutable_options()) {
    if (option.option_id() != curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE) {
      continue;
    }
    std::uint64_t value = IntegralMutationValue(option);
    if (value == 0) {
      value = 512;
    }
    option.set_uint_value(std::max<std::uint64_t>(8, std::min<std::uint64_t>(value, 65464)));
  }
}

/// Identify options introduced for FTP/TFTP so existing fixed lanes do not
/// silently inherit dead mutations when the shared generated manifest grows.
/// Generic options retained by the FTP/TFTP allowlists are deliberately absent
/// here because they remain useful to HTTP, WebSocket, API, or timing targets.
bool IsFileTransferOnlyOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_APPEND:
    case curl::fuzzer::proto::CURLOPT_DIRLISTONLY:
    case curl::fuzzer::proto::CURLOPT_FTP_ACCOUNT:
    case curl::fuzzer::proto::CURLOPT_FTP_ALTERNATIVE_TO_USER:
    case curl::fuzzer::proto::CURLOPT_FTP_CREATE_MISSING_DIRS:
    case curl::fuzzer::proto::CURLOPT_FTP_FILEMETHOD:
    case curl::fuzzer::proto::CURLOPT_FTP_SKIP_PASV_IP:
    case curl::fuzzer::proto::CURLOPT_FTP_USE_EPSV:
    case curl::fuzzer::proto::CURLOPT_FTP_USE_PRET:
    case curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE:
    case curl::fuzzer::proto::CURLOPT_TFTP_NO_OPTIONS:
    case curl::fuzzer::proto::CURLOPT_TRANSFERTEXT:
    case curl::fuzzer::proto::CURLOPT_WILDCARDMATCH:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Remove FTP/TFTP-only options while preserving the relative order of every
/// generic option an existing fixed target already consumed.
void RemoveFileTransferOnlyOptions(curl::fuzzer::proto::Scenario* scenario) {
  RetainMatchingOptions(
      scenario, [](curl::fuzzer::proto::CurlOptionId option_id) { return !IsFileTransferOnlyOption(option_id); });
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

/// Remove response forms the proxy peer cannot interpret. Raw chunks are the
/// HTTP/2 frame stream; WebSocket frames would merely add a second unrelated
/// binary grammar, and follow-on Connection messages cannot describe later
/// streams multiplexed on the already-open proxy socket.
void RemoveIgnoredH2ProxyShape(curl::fuzzer::proto::Scenario* scenario) {
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

/// Keep lifecycle work out of protocol-focused lanes. The API binary retains
/// this message explicitly; compatibility inputs have no postprocessor so
/// existing reproducers keep their historical serialized meaning.
void RemoveApiOnlyShape(curl::fuzzer::proto::Scenario* scenario) { scenario->clear_api_plan(); }

/// Keep concurrent multi-handle work out of every other fixed lane. The
/// compatibility binary deliberately preserves newly-added unknown fields.
void RemoveMultiOnlyShape(curl::fuzzer::proto::Scenario* scenario) { scenario->clear_multi_plan(); }

/// The QUIC peer consumes Http3Plan rather than the stream-socket response
/// script. Request headers, MIME, upload state, and HTTP options remain useful
/// because curl serializes those onto its client-initiated request stream.
void RemoveIgnoredHttp3Shape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_connection();
  scenario->clear_subsequent_connections();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
}

/// Remove stream-driver controls that neither file-transfer peer interprets.
/// FTP consumes raw byte chunks as control/data replies, while TFTP preserves
/// them as individual datagrams; structured WebSocket frames, manual probes,
/// and event-loop backpressure therefore cannot affect either curl protocol.
void RemoveUnusedFileTransferConnectionShape(curl::fuzzer::proto::Connection* connection) {
  connection->clear_server_frames();
  connection->clear_manual_probes();
  connection->clear_backpressure();
}

/// Retain only the reusable shapes consumed by the FTP peer: one raw control
/// script, a bounded sequence of passive-data scripts, and optional upload
/// input. HTTP, TELNET, WebSocket, and public-API fields would otherwise absorb
/// mutations despite having no representation in an FTP exchange.
void RemoveIgnoredFtpShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_request_headers();
  scenario->clear_mime_post();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);

  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
  TrimRepeated(scenario->mutable_subsequent_connections(), scenario_limits::kMaxConnections - 1);
  for (auto& connection : *scenario->mutable_subsequent_connections()) {
    RemoveUnusedFileTransferConnectionShape(&connection);
  }
}

/// Retain the primary raw response script because its entries are the ordered
/// UDP datagrams seen by curl, plus optional upload input for WRQ. TFTP cannot
/// consume follow-on stream connections or any higher-level protocol shape.
void RemoveIgnoredTftpShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  scenario->clear_mime_post();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
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
    case curl::fuzzer::proto::SCHEME_FTP:
    case curl::fuzzer::proto::SCHEME_TFTP:
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
void ApplyTargetPolicy(curl::fuzzer::proto::Scenario* scenario, TargetProfile profile) {
  if (scenario == nullptr) {
    return;
  }

  if (profile == TargetProfile::kCompatibility) {
    // The original target's existing corpus predates profile splitting. A
    // no-op here makes the type safe to pass around while its binary continues
    // to omit postprocessor registration altogether. The append-only FTP/TFTP
    // scheme values do not justify rewriting historical mixed-lane inputs.
    return;
  }

  // Only the dedicated TLS and QUIC peers consume a certificate-chain
  // selector. Remove it before protocol-specific early returns so other fixed
  // targets do not spend mutations on inert TLS server state.
  if (profile != TargetProfile::kFastHttps && profile != TargetProfile::kFastHttp3) {
    scenario->clear_tls_certificate_chain();
  }

  // Field 13 is append-only so the compatibility target can round-trip it,
  // but every other fixed lane must discard work its peer cannot consume.
  if (profile != TargetProfile::kFastHttp3) {
    scenario->clear_http3_plan();
  }

  if (profile == TargetProfile::kFastHttp3) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
    RemoveIgnoredHttp3Shape(scenario);
    RetainHttp3RequestOptions(scenario);
    BoundScenarioShape(scenario);
    // BoundScenarioShape materializes an empty primary Connection while
    // sharing request-side limits. Do not retain that protocol-inert message.
    scenario->clear_connection();
    BoundHttp3PlanShape(scenario->mutable_http3_plan());
    CanonicalizeTlsAuthority(scenario);
    CanonicalizeTlsCertificateChain(scenario);
    return;
  }

  if (profile == TargetProfile::kFastTelnet) {
    // Set the scheme before general bounds so the TELNET-specific upload and
    // PAUSE budgets are selected rather than event-driven compatibility ones.
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_TELNET);
    RemoveApiOnlyShape(scenario);
    RemoveMultiOnlyShape(scenario);
    RemoveNonTelnetShape(scenario);
    RetainCheapTelnetOptions(scenario);
    BoundScenarioShape(scenario);
    BoundTelnetResponse(scenario->mutable_connection());
    return;
  }

  if (profile == TargetProfile::kFastHttp) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
    RemoveApiOnlyShape(scenario);
    RemoveMultiOnlyShape(scenario);
    RemoveTelnetOnlyShape(scenario);
    RemoveDeepHttpShape(scenario);
    RetainCheapHttpOptions(scenario);
    BoundScenarioShape(scenario);
    return;
  }

  if (profile == TargetProfile::kH2Proxy) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
    RemoveApiOnlyShape(scenario);
    RemoveMultiOnlyShape(scenario);
    RemoveTelnetOnlyShape(scenario);
    RemoveIgnoredH2ProxyShape(scenario);
    RetainH2ProxyOriginOptions(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeH2ProxyOriginAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastFtp) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_FTP);
    RemoveIgnoredFtpShape(scenario);
    RetainFtpOptions(scenario);
    CanonicalizeFtpOptionModes(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeFtpAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastTftp) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_TFTP);
    RemoveIgnoredTftpShape(scenario);
    RetainTftpOptions(scenario);
    CanonicalizeTftpOptionModes(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeTftpAuthority(scenario);
    return;
  }

  // Select the lane's scheme before applying scheme-sensitive upload bounds.
  // The scheme field is itself mutable, so bounding first could accidentally
  // give an HTTP/WS case TELNET's smaller payload budget merely because that
  // was the input's pre-policy value.
  switch (profile) {
    case TargetProfile::kCompatibility:
      return;
    case TargetProfile::kDeepHttp:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
      break;
    case TargetProfile::kApi:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
      break;
    case TargetProfile::kMulti:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
      break;
    case TargetProfile::kFastHttps:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
      break;
    case TargetProfile::kFastHttp3:
      // The protocol-specific early path owns the QUIC response plan.
      return;
    case TargetProfile::kH2Proxy:
      // The early path removes proxy-incompatible fields before general
      // bounds, keeping raw frame mutation dense.
      return;
    case TargetProfile::kFastWebSocket:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_WS);
      break;
    case TargetProfile::kFastSecureWebSocket:
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_WSS);
      break;
    case TargetProfile::kTiming:
      scenario->set_scheme(PlaintextScheme(scenario->scheme()));
      break;
    case TargetProfile::kFastHttp:
    case TargetProfile::kFastTelnet:
    case TargetProfile::kFastFtp:
    case TargetProfile::kFastTftp:
      // Protocol-specific early-return paths selected their scheme above.
      return;
  }

  // TELNET's retained slist and synchronous pause have no observable, safe
  // meaning in the fixed event-driven lanes. Clear them before walking the
  // general shape so only the compatibility and TELNET targets can retain
  // those values.
  RemoveTelnetOnlyShape(scenario);
  if (profile != TargetProfile::kApi) {
    RemoveApiOnlyShape(scenario);
  }
  if (profile != TargetProfile::kMulti) {
    RemoveMultiOnlyShape(scenario);
  }
  RemoveFileTransferOnlyOptions(scenario);
  BoundScenarioShape(scenario);

  switch (profile) {
    case TargetProfile::kCompatibility:
      return;
    case TargetProfile::kFastHttp:
      // Handled before the general bounds so discarded deep shapes are never
      // traversed on the fast path.
      return;

    case TargetProfile::kDeepHttp:
      ClearAllBackpressure(scenario);
      return;

    case TargetProfile::kApi:
      ClearAllBackpressure(scenario);
      if (scenario->host_path().size() > scenario_limits::kMaxApiStringBytes) {
        scenario->mutable_host_path()->resize(scenario_limits::kMaxApiStringBytes);
      }
      if (scenario->has_api_plan()) {
        BoundApiPlanShape(scenario->mutable_api_plan());
      }
      return;

    case TargetProfile::kMulti: {
      ClearAllBackpressure(scenario);
      CanonicalizeMultiAuthority(scenario);
      auto* plan = scenario->mutable_multi_plan();
      BoundMultiPlanShape(plan);
      TrimRepeated(scenario->mutable_subsequent_connections(), plan->transfer_count() - 1U);
      return;
    }

    case TargetProfile::kFastHttps:
      ClearAllBackpressure(scenario);
      CanonicalizeTlsAuthority(scenario);
      CanonicalizeTlsCertificateChain(scenario);
      return;

    case TargetProfile::kFastHttp3:
      // Handled before generic connection bounding because Http3Plan replaces
      // the stream-socket response script.
      return;

    case TargetProfile::kH2Proxy:
      // Handled by the protocol-specific early path above.
      return;

    case TargetProfile::kFastWebSocket:
      ClearAllBackpressure(scenario);
      RemoveIgnoredWebSocketShape(scenario);
      return;

    case TargetProfile::kFastSecureWebSocket:
      ClearAllBackpressure(scenario);
      RemoveIgnoredWebSocketShape(scenario);
      return;

    case TargetProfile::kFastTelnet:
      // Handled before the general bounds so its protocol-specific limits are
      // selected from the start.
      return;

    case TargetProfile::kFastFtp:
    case TargetProfile::kFastTftp:
      // Their peers consume narrower raw-script shapes, pruned before general
      // bounds so ignored fields never tax these fast paths.
      return;

    case TargetProfile::kTiming: {
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
