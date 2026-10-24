/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the per-binary proto mutation policies.

#include "proto_fuzzer/target_policy.h"

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

#include "proto_fuzzer/option_model.h"
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

// A default, bounded identifier keeps newly generated inputs on the gateway's
// /ipfs/ or /ipns/ namespace. The path, query, and fragment after it stay
// mutation-controlled.
constexpr char kDefaultIpfsCid[] = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
constexpr char kDefaultIpnsName[] = "k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8";

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

/// Bound fixed-target metadata. Compatibility inputs preserve their original
/// option strings; consumers of bounded request metadata cap their own views.
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

/// Alt-Svc lookup cannot run while the harness's wildcard CONNECT_TO route is
/// active. Give file-backed Alt-Svc inputs one fixed origin whose port can be
/// populated in curl's DNS cache before that override is safely detached,
/// while preserving all mutation-controlled path, query, and fragment bytes.
void CanonicalizeAltSvcAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("altsvc-origin.test/");
    return;
  }
  scenario->set_host_path("altsvc-origin.test" + host_path.substr(suffix_start));
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

/// Keep the HTTPS/HTTP2 group selector inside its closed, useful set. Unknown
/// proto3 enum values take the inexpensive historical-input path.
void CanonicalizeTlsGroupProfile(curl::fuzzer::proto::Scenario* scenario) {
  switch (scenario->tls_group_profile()) {
    case curl::fuzzer::proto::TLS_GROUP_X25519:
    case curl::fuzzer::proto::TLS_GROUP_PROVIDER_DEFAULT:
      return;
    default:
      scenario->clear_tls_group_profile();
      return;
  }
}

/// Keep the proxied origin parseable while retaining every path, query, and
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

/// Local-resolution SOCKS modes use libc/curl's deterministic localhost path,
/// while SOCKS4A and SOCKS5-hostname deliberately carry a fixed hostname to
/// the proxy. The path/query/fragment stays mutation-controlled.
void CanonicalizeSocksAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  const auto mode = scenario->socks_proxy_mode();
  const bool resolve_at_proxy =
      mode == curl::fuzzer::proto::SOCKS_PROXY_SOCKS4A || mode == curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME;
  const char* host = resolve_at_proxy ? "socks.test" : "localhost";
  if (suffix_start == std::string::npos) {
    scenario->set_host_path(std::string(host) + "/");
    return;
  }
  scenario->set_host_path(std::string(host) + host_path.substr(suffix_start));
}

/// Keep proxy and Unix-domain HTTP transfers on one parseable origin while
/// preserving the mutation-controlled path, query, and fragment. Routing is
/// selected independently by a fixed numeric proxy or abstract socket name,
/// so authority mutation would add early URL failures without new transport
/// behavior.
void CanonicalizeHttpTransportAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("transport.test/");
    return;
  }
  scenario->set_host_path("transport.test" + host_path.substr(suffix_start));
}

/// Use libc/curl's localhost path when there are no structured entries, and a
/// fixed cache-backed name when entries are present. The DoH lane uses the
/// certificate's tls.test authority because its outer transfer completes a
/// verified TLS/ALPN h2 handshake. In every case the path, query, and fragment
/// remain mutation-controlled.
void CanonicalizeResolverAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  const char* host = "localhost";
  switch (scenario->resolver_mode()) {
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_POSITIVE:
      host = "resolver-positive.test";
      break;
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_NEGATIVE:
      host = "resolver-negative.test";
      break;
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_LINK_LOCAL:
      host = "resolver-link-local.test";
      break;
    case curl::fuzzer::proto::RESOLVER_MODE_THREADED_PARTIAL:
      host = "resolver-partial.test";
      break;
    case curl::fuzzer::proto::RESOLVER_MODE_UNIX_SOCKET:
      host = "resolver-unix.test";
      break;
    case curl::fuzzer::proto::RESOLVER_MODE_GLOBAL_LIFECYCLE:
      host = "localhost";
      break;
    case curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR:
      host = "tls.test";
      break;
    case curl::fuzzer::proto::RESOLVER_MODE_DEFAULT:
    default:
      host =
          scenario->doh_https_rr()
              ? "tls.test"
              : ((scenario->happy_eyeballs() || !scenario->resolve_entries().empty()) ? "resolve.test" : "localhost");
      break;
  }
  if (suffix_start == std::string::npos) {
    scenario->set_host_path(std::string(host) + "/");
    return;
  }
  scenario->set_host_path(std::string(host) + host_path.substr(suffix_start));
}

bool IsThreadedResolverMode(curl::fuzzer::proto::ResolverMode mode) {
  return mode == curl::fuzzer::proto::RESOLVER_MODE_THREADED_POSITIVE ||
         mode == curl::fuzzer::proto::RESOLVER_MODE_THREADED_NEGATIVE ||
         mode == curl::fuzzer::proto::RESOLVER_MODE_THREADED_LINK_LOCAL ||
         mode == curl::fuzzer::proto::RESOLVER_MODE_THREADED_PARTIAL;
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
/// Implicit-TLS inputs use the checked-in certificate's tls.test name so every
/// control and data handshake can be verified before the same exchange runs.
void CanonicalizeFtpAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  const char* host = scenario->scheme() == curl::fuzzer::proto::SCHEME_FTPS ? "tls.test" : "ftp.test";
  if (suffix_start == std::string::npos) {
    scenario->set_host_path(std::string(host) + "/file");
    return;
  }
  scenario->set_host_path(std::string(host) + host_path.substr(suffix_start));
}

/// Keep the SMTP lane inside a parseable authority while leaving the URL path
/// mutation-controlled. In this curl revision the path is the EHLO argument
/// (the client's announced domain), not the envelope recipient; recipients
/// arrive through Scenario.mail_rcpt. Preserving the suffix still exercises
/// EHLO parsing, while a fixed host avoids spending iterations on URL failures
/// before curl sends its first command. Implicit-TLS inputs use the checked-in
/// certificate's tls.test name so the verified handshake can complete before
/// the same command exchange runs.
void CanonicalizeSmtpAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  const char* host = scenario->scheme() == curl::fuzzer::proto::SCHEME_SMTPS ? "tls.test" : "smtp.test";
  if (suffix_start == std::string::npos) {
    scenario->set_host_path(std::string(host) + "/client.test");
    return;
  }
  scenario->set_host_path(std::string(host) + host_path.substr(suffix_start));
}

/// Keep the IMAP lane inside a parseable authority while retaining every URL
/// path parameter, query, and fragment byte. The path carries the mailbox and
/// the `;UID=`, `;MAILINDEX=`, `;SECTION=`, and `;PARTIAL=` selectors that
/// choose FETCH, SEARCH, and LIST states; canonicalizing only the host avoids
/// spending iterations on failures before curl sends its first command.
/// Implicit-TLS inputs use the checked-in certificate's tls.test name so the
/// verified handshake can complete before the same tagged exchange runs.
void CanonicalizeImapAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  const char* host = scenario->scheme() == curl::fuzzer::proto::SCHEME_IMAPS ? "tls.test" : "imap.test";
  if (suffix_start == std::string::npos) {
    scenario->set_host_path(std::string(host) + "/INBOX");
    return;
  }
  scenario->set_host_path(std::string(host) + host_path.substr(suffix_start));
}

/// Give POP3 a mailbox with a message id by default so the lane reaches RETR
/// rather than only LIST. The id remains mutation-controlled, and an explicit
/// trailing slash or query continues to select the listing and error states.
/// Implicit-TLS inputs use the checked-in certificate's tls.test name so the
/// verified handshake can complete before the same status-line exchange runs.
void CanonicalizePop3Authority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  const char* host = scenario->scheme() == curl::fuzzer::proto::SCHEME_POP3S ? "tls.test" : "pop3.test";
  if (suffix_start == std::string::npos) {
    scenario->set_host_path(std::string(host) + "/1");
    return;
  }
  scenario->set_host_path(std::string(host) + host_path.substr(suffix_start));
}

/// Pin the MQTT broker authority while leaving the URL path mutation-
/// controlled: curl percent-decodes that path into the PUBLISH/SUBSCRIBE topic.
/// A missing path is a legitimate "No MQTT topic found" error, but a default
/// topic makes most newly generated inputs reach the packet peer instead of
/// stopping at URL validation. Implicit-TLS inputs use the checked-in
/// certificate's tls.test name so the verified handshake can complete before
/// the same packet exchange runs.
void CanonicalizeMqttAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  const char* host = scenario->scheme() == curl::fuzzer::proto::SCHEME_MQTTS ? "tls.test" : "mqtt.test";
  if (suffix_start == std::string::npos) {
    scenario->set_host_path(std::string(host) + "/topic");
    return;
  }
  scenario->set_host_path(std::string(host) + host_path.substr(suffix_start));
}

/// Pin the DICT server authority while retaining every lookup selector in the
/// URL path. In curl's DICT handler the path after the leading slash is the
/// complete command: `/d:word`, `/match:word:db`, `/show:db`, or a raw command
/// with colons becoming spaces. A default DEFINE keeps newly generated inputs
/// reaching the command peer instead of stopping at URL validation, while an
/// explicit path (including a bare `/`) continues to select the other states.
void CanonicalizeDictAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("dict.test/d:word");
    return;
  }
  scenario->set_host_path("dict.test" + host_path.substr(suffix_start));
}

/// Pin a file:// URL to a fixed local source/sink. The path component is what
/// libcurl opens, so retaining a fuzzed path would let a mutated input read or
/// write any file visible to the fuzzer process. Keep the fuzz-controlled
/// authority and any query/fragment so URL parsing still sees mutated bytes,
/// but always replace the path with /dev/null. An input with no path keeps its
/// authority and gains /dev/null, so the canonical empty-authority form is
/// `file:///dev/null`.
void CanonicalizeFileAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t path_start = host_path.find('/');
  const std::size_t query_start = host_path.find_first_of("?#");
  std::size_t authority_end = host_path.size();
  if (path_start != std::string::npos) {
    authority_end = std::min(authority_end, path_start);
  }
  if (query_start != std::string::npos) {
    authority_end = std::min(authority_end, query_start);
  }

  std::string canonical = host_path.substr(0, authority_end);
  canonical += "/dev/null";
  if (query_start != std::string::npos) {
    canonical += host_path.substr(query_start);
  }
  scenario->set_host_path(canonical);
}

/// Pin the LDAP directory authority while retaining the complete URL suffix.
/// In this curl revision OpenLDAP parses the base DN, attributes, scope, and
/// filter from the URL path (`/dn?attrs?scope?filter`); CURLOPT_CUSTOMREQUEST
/// is not consulted. A default base DN makes newly generated inputs reach the
/// bind/search peer, and dropping any userinfo component keeps OpenLDAP's
/// strict URL parser from rejecting credentials it only accepts separately.
/// Implicit-TLS inputs use the checked-in certificate's tls.test name so the
/// verified handshake can complete before the same BER exchange runs.
void CanonicalizeLdapAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  const char* host = scenario->scheme() == curl::fuzzer::proto::SCHEME_LDAPS ? "tls.test" : "ldap.test";
  if (suffix_start == std::string::npos) {
    scenario->set_host_path(std::string(host) + "/dc=example,dc=com");
    return;
  }
  scenario->set_host_path(std::string(host) + host_path.substr(suffix_start));
}

/// Pin the RTSP peer's authority while preserving the path, query, and
/// fragment. curl builds its request stream URI from CURLOPT_RTSP_STREAM_URI
/// (defaulting to "*"), but the URL still has to parse before the dedicated
/// request/response peer can be reached. A default stream path keeps newly
/// generated scenarios representative rather than spending them on URL errors.
void CanonicalizeRtspAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string::npos) {
    scenario->set_host_path("rtsp.test/stream");
    return;
  }
  scenario->set_host_path("rtsp.test" + host_path.substr(suffix_start));
}

/// Pin the IPFS/IPNS identifier while preserving the gateway path, query, and
/// fragment. curl's command-line tool rewrites these schemes to an HTTP
/// gateway request; the structured lane performs that same rewrite inside the
/// runner, so the identifier has no local meaning beyond selecting the
/// /ipfs/<cid> or /ipns/<name> namespace. A default identifier makes newly
/// generated inputs reach the HTTP peer, while the bounded suffix retains the
/// fuzz-controlled request target.
void CanonicalizeIpfsAuthority(curl::fuzzer::proto::Scenario* scenario) {
  const std::string& host_path = scenario->host_path();
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  std::string canonical = scenario->scheme() == curl::fuzzer::proto::SCHEME_IPNS ? kDefaultIpnsName : kDefaultIpfsCid;
  if (suffix_start != std::string::npos) {
    canonical += host_path.substr(suffix_start);
  }
  if (canonical.size() > scenario_limits::kMaxIpfsHostPathBytes) {
    canonical.resize(scenario_limits::kMaxIpfsHostPathBytes);
  }
  scenario->set_host_path(canonical);
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

/// Retain the observable prefix of one filename-backed parser input while
/// debiting the shared per-scenario file-byte budget.
void BoundFileInput(std::string* input, std::size_t* remaining_bytes) {
  const std::size_t limit = std::min(scenario_limits::kMaxFileInputBytes, *remaining_bytes);
  if (input->size() > limit) {
    input->resize(limit);
  }
  *remaining_bytes -= input->size();
}

void BoundFileInputs(curl::fuzzer::proto::Scenario* scenario) {
  std::size_t remaining_bytes = scenario_limits::kMaxFileInputTotalBytes;
  BoundFileInput(scenario->mutable_cookie_file(), &remaining_bytes);
  BoundFileInput(scenario->mutable_altsvc_file(), &remaining_bytes);
  BoundFileInput(scenario->mutable_hsts_file(), &remaining_bytes);
  BoundFileInput(scenario->mutable_netrc_file(), &remaining_bytes);
  BoundFileInput(scenario->mutable_crl_file(), &remaining_bytes);
}

/// Apply the metadata/header limits shared by both MIME part message types.
template <typename Part>
void BoundMimePartMetadata(Part* part) {
  TrimMetadata(part->mutable_name());
  TrimMetadata(part->mutable_filename());
  TrimMetadata(part->mutable_content_type());
  BoundHeaderValues(part->mutable_headers(), scenario_limits::kMaxMimeHeadersPerPart);
}

void BoundGeneratedMimeData(curl::fuzzer::proto::GeneratedBytes* generated, std::size_t* remaining_bytes) {
  if (generated->pattern().size() > scenario_limits::kMaxGeneratedMimePatternBytes) {
    generated->mutable_pattern()->resize(scenario_limits::kMaxGeneratedMimePatternBytes);
  }

  const std::size_t pattern_size = generated->pattern().size();
  if (pattern_size == 0 || *remaining_bytes == 0) {
    generated->clear_repeat_count();
    return;
  }

  // Keep every exact in-range size, including 16/32/64 KiB and their +/-1
  // neighborhoods. Counts beyond the shared budget all have identical runtime
  // behavior, so fold them onto the largest observable repetition count.
  const std::size_t max_repeat_count = *remaining_bytes / pattern_size;
  const std::size_t repeat_count =
      std::min<std::size_t>(static_cast<std::size_t>(generated->repeat_count()), max_repeat_count);
  generated->set_repeat_count(static_cast<std::uint32_t>(repeat_count));
  *remaining_bytes -= repeat_count * pattern_size;
}

void BoundMimeLeaf(curl::fuzzer::proto::MimeDataPart* part, std::size_t* remaining_generated_bytes) {
  BoundMimePartMetadata(part);
  if (part->content_case() == curl::fuzzer::proto::MimeDataPart::kGeneratedData) {
    BoundGeneratedMimeData(part->mutable_generated_data(), remaining_generated_bytes);
  } else if (part->data().size() > scenario_limits::kMaxMimeDataBytes) {
    part->mutable_data()->resize(scenario_limits::kMaxMimeDataBytes);
  }
}

/// Mirror the runtime's shared top-level/nested part budget in the protobuf
/// itself. A simple per-list cap is insufficient because many bounded child
/// lists could still leave most of the message semantically dead.
void BoundMimeShape(curl::fuzzer::proto::MimePost* post) {
  TrimRepeated(post->mutable_parts(), scenario_limits::kMaxTopLevelMimeParts);
  std::size_t remaining = scenario_limits::kMaxTotalMimeParts;
  std::size_t remaining_generated_bytes = scenario_limits::kMaxGeneratedMimeDataBytes;
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
    if (part->content_case() == curl::fuzzer::proto::MimePart::kGeneratedData) {
      BoundGeneratedMimeData(part->mutable_generated_data(), &remaining_generated_bytes);
      continue;
    }
    if (part->content_case() != curl::fuzzer::proto::MimePart::kSubparts) {
      continue;
    }

    auto* children = part->mutable_subparts()->mutable_parts();
    TrimRepeated(children, std::min(scenario_limits::kMaxNestedMimeParts, remaining));
    for (auto& child : *children) {
      BoundMimeLeaf(&child, &remaining_generated_bytes);
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

/// Canonicalize the allocation failure plan to the same fixed-size sequence
/// consumed by the runtime controller. Sorting lets its hot callback compare
/// only the next ordinal, while retaining the lowest distinct values keeps
/// an oversized mutation focused on reachable work.
void CanonicalizeAllocationFailures(curl::fuzzer::proto::Scenario* scenario) {
  std::array<std::uint32_t, scenario_limits::kMaxAllocationFailures> retained{};
  std::size_t retained_count = 0;
  const std::uint32_t maximum = static_cast<std::uint32_t>(scenario_limits::kMaxAllocationOrdinal);

  for (const std::uint32_t raw : scenario->fail_allocations()) {
    if (raw == 0) {
      continue;
    }
    const std::uint32_t ordinal = 1U + ((raw - 1U) % maximum);
    const auto begin = retained.begin();
    const auto end = begin + static_cast<std::ptrdiff_t>(retained_count);
    const auto position = std::lower_bound(begin, end, ordinal);
    if (position != end && *position == ordinal) {
      continue;
    }
    const std::size_t index = static_cast<std::size_t>(position - begin);
    if (index >= retained.size()) {
      continue;
    }
    if (retained_count < retained.size()) {
      ++retained_count;
    }
    for (std::size_t destination = retained_count - 1; destination > index; --destination) {
      retained[destination] = retained[destination - 1];
    }
    retained[index] = ordinal;
  }

  auto* values = scenario->mutable_fail_allocations();
  values->Clear();
  for (std::size_t index = 0; index < retained_count; ++index) {
    values->Add(retained[index]);
  }
}

/// Keep injected failures out of curl's debug event adapter. Its socket
/// monitor is heap-backed, and rejecting the allocation that records a newly
/// announced socket leaves a later CURL_POLL_REMOVE with no matching entry.
/// Ordinary inputs still cover curl_easy_perform_ev; allocation plans use the
/// equivalent blocking easy entrypoint and retain a stable allocation trace.
void CanonicalizeAllocationFailureDrive(curl::fuzzer::proto::Scenario* scenario) {
  if (!scenario->fail_allocations().empty() && scenario->has_api_plan() &&
      scenario->api_plan().drive_mode() == curl::fuzzer::proto::API_DRIVE_EASY_EVENTS) {
    scenario->mutable_api_plan()->set_drive_mode(curl::fuzzer::proto::API_DRIVE_EASY_PERFORM);
  }
}

/// Return whether a scenario can install MIME through curl's HTTP reader path.
bool UsesHttpMimeReader(const curl::fuzzer::proto::Scenario& scenario) {
  switch (scenario.scheme()) {
    case curl::fuzzer::proto::SCHEME_HTTP:
    case curl::fuzzer::proto::SCHEME_HTTPS:
    case curl::fuzzer::proto::SCHEME_WS:
    case curl::fuzzer::proto::SCHEME_WSS:
    case curl::fuzzer::proto::SCHEME_IPFS:
    case curl::fuzzer::proto::SCHEME_IPNS:
      return true;

    case curl::fuzzer::proto::SCHEME_UNSPECIFIED:
    case curl::fuzzer::proto::SCHEME_TELNET:
    case curl::fuzzer::proto::SCHEME_FTP:
    case curl::fuzzer::proto::SCHEME_FTPS:
    case curl::fuzzer::proto::SCHEME_TFTP:
    case curl::fuzzer::proto::SCHEME_IMAP:
    case curl::fuzzer::proto::SCHEME_IMAPS:
    case curl::fuzzer::proto::SCHEME_POP3:
    case curl::fuzzer::proto::SCHEME_POP3S:
    case curl::fuzzer::proto::SCHEME_MQTT:
    case curl::fuzzer::proto::SCHEME_MQTTS:
    case curl::fuzzer::proto::SCHEME_GOPHER:
    case curl::fuzzer::proto::SCHEME_GOPHERS:
    case curl::fuzzer::proto::SCHEME_SMTP:
    case curl::fuzzer::proto::SCHEME_SMTPS:
    case curl::fuzzer::proto::SCHEME_DICT:
    case curl::fuzzer::proto::SCHEME_FILE:
    default:
      return false;
  }
}

/// Keep an injected failure from leaving curl's MIME client-reader stack
/// dangling. With line-ending conversion enabled, curl installs the MIME
/// reader before allocating the conversion reader. If that second allocation
/// fails, the current error path frees the MIME reader without clearing the
/// installed stack pointer. Ordinary inputs still cover MIME plus conversion;
/// failure plans retain MIME processing and use curl's unconverted reader
/// path. Non-HTTP schemes do not install this reader, so their conversion
/// options remain useful and safe even if a compatibility input carries MIME.
void CanonicalizeAllocationFailureOptions(curl::fuzzer::proto::Scenario* scenario) {
  if (scenario->fail_allocations().empty() || !scenario->has_mime_post() || !UsesHttpMimeReader(*scenario)) {
    return;
  }

  auto* options = scenario->mutable_options();
  int retained = 0;
  for (int index = 0; index < options->size(); ++index) {
    const auto option_id = options->Get(index).option_id();
    if (option_id == curl::fuzzer::proto::CURLOPT_CRLF || option_id == curl::fuzzer::proto::CURLOPT_TRANSFERTEXT) {
      continue;
    }
    if (retained != index) {
      options->SwapElements(retained, index);
    }
    ++retained;
  }
  options->DeleteSubrange(retained, options->size() - retained);
}

/// Keep API work proportional to the fixed descriptor tables used by the
/// runtime. Selector magnitudes stay mutation-controlled because the runtime
/// folds them into the relevant typed table; only suffixes it cannot execute
/// are dead and therefore removed here.
void BoundApiPlanShape(curl::fuzzer::proto::ApiPlan* plan) {
  TrimRepeatedScalar(plan->mutable_share_data_selectors(), scenario_limits::kMaxApiShareDataSelectors);
  TrimRepeatedScalar(plan->mutable_easy_info_selectors(), scenario_limits::kMaxApiInfoSelectors);
  TrimRepeatedScalar(plan->mutable_reentrant_probe_selectors(), scenario_limits::kMaxApiReentrantSelectors);

  switch (plan->drive_mode()) {
    case curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM:
    case curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET:
      break;
    case curl::fuzzer::proto::API_DRIVE_EASY_PERFORM:
    case curl::fuzzer::proto::API_DRIVE_EASY_EVENTS:
    case curl::fuzzer::proto::API_DRIVE_CONNECT_ONLY:
      // Wakeup is a multi-handle API and has no live object in easy mode.
      // Likewise, a body callback cannot be resumed while one of these
      // blocking entrypoints owns the thread. Clearing both mutations keeps
      // every retained API-plan value observable and bounded.
      plan->set_wake_multi(false);
      plan->set_pause_response_once(false);
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

void BoundHttp2StreamRef(curl::fuzzer::proto::Http2StreamRef* stream) {
  switch (stream->target_case()) {
    case curl::fuzzer::proto::Http2StreamRef::kRequestIndex:
      stream->set_request_index(stream->request_index() % 16U);
      break;
    case curl::fuzzer::proto::Http2StreamRef::kPushIndex:
      stream->set_push_index(stream->push_index() % 16U);
      break;
    case curl::fuzzer::proto::Http2StreamRef::kExplicitId:
      stream->set_explicit_id(stream->explicit_id() & 0x7fffffffU);
      break;
    case curl::fuzzer::proto::Http2StreamRef::kConnection:
    case curl::fuzzer::proto::Http2StreamRef::kLatestRequest:
    case curl::fuzzer::proto::Http2StreamRef::TARGET_NOT_SET:
    default:
      break;
  }
}

void BoundHttp2Settings(curl::fuzzer::proto::Http2Settings* settings) {
  TrimRepeated(settings->mutable_entries(), scenario_limits::kMaxHttp2Settings);
  for (auto& entry : *settings->mutable_entries()) {
    // SETTINGS identifiers occupy 16 bits. Preserve unknown extensions,
    // which receivers ignore when they do not understand them.
    entry.set_identifier(entry.identifier() & 0xffffU);
    switch (entry.identifier()) {
      case 2U:  // SETTINGS_ENABLE_PUSH
      case 8U:  // SETTINGS_ENABLE_CONNECT_PROTOCOL
      case 9U:  // SETTINGS_NO_RFC7540_PRIORITIES
        entry.set_value(entry.value() & 1U);
        break;
      case 4U:  // SETTINGS_INITIAL_WINDOW_SIZE
        entry.set_value(entry.value() & 0x7fffffffU);
        break;
      case 5U:  // SETTINGS_MAX_FRAME_SIZE
        if (entry.value() < 16384U || entry.value() > 0x00ffffffU) {
          entry.set_value(16384U + entry.value() % (0x00ffffffU - 16384U + 1U));
        }
        break;
      case 1U:  // SETTINGS_HEADER_TABLE_SIZE
      case 3U:  // SETTINGS_MAX_CONCURRENT_STREAMS
      case 6U:  // SETTINGS_MAX_HEADER_LIST_SIZE
      default:
        break;
    }
  }
}

void BoundHttp2RawData(std::string* data, std::size_t* remaining_raw_bytes) {
  const std::size_t limit = std::min(scenario_limits::kMaxHttp2RawFrameBytes, *remaining_raw_bytes);
  if (data->size() > limit) {
    data->resize(limit);
  }
  *remaining_raw_bytes -= data->size();
}

/// Bound the structured HTTP/2 sequence to the exact prefix interpreted by
/// H2PlanDriver. The raw escapes retain malformed frame behavior while every
/// ordinary header action remains HPACK and HTTP-field valid.
void BoundHttp2PlanShape(curl::fuzzer::proto::Http2Plan* plan) {
  TrimRepeated(plan->mutable_actions(), scenario_limits::kMaxHttp2Actions);
  BoundHttp2Settings(plan->mutable_initial_settings());
  plan->mutable_initial_settings()->set_ack(false);
  if (plan->actions().empty()) {
    auto* response = plan->add_actions()->mutable_headers();
    response->set_status_code(200);
    response->set_end_stream(true);
  }

  std::size_t remaining_header_bytes = scenario_limits::kMaxHttp2HeaderBytes;
  std::size_t remaining_data_bytes = scenario_limits::kMaxHttp2DataBytes;
  std::size_t remaining_raw_bytes = scenario_limits::kMaxHttp2RawBytes;
  for (auto& action : *plan->mutable_actions()) {
    switch (action.action_case()) {
      case curl::fuzzer::proto::Http2Action::kSettings:
        BoundHttp2Settings(action.mutable_settings());
        break;
      case curl::fuzzer::proto::Http2Action::kHeaders: {
        auto* headers = action.mutable_headers();
        BoundHttp2StreamRef(headers->mutable_stream());
        if (!headers->trailers()) {
          if (headers->status_code() == 0U) {
            headers->set_status_code(200U);
          } else if (headers->status_code() < 100U || headers->status_code() > 599U) {
            headers->set_status_code(100U + headers->status_code() % 500U);
          }
        }
        BoundHttp3Headers(headers->mutable_fields(), scenario_limits::kMaxHttp2Headers, &remaining_header_bytes);
        break;
      }
      case curl::fuzzer::proto::Http2Action::kData: {
        auto* data = action.mutable_data();
        BoundHttp2StreamRef(data->mutable_stream());
        if (data->data().size() > remaining_data_bytes) {
          data->mutable_data()->resize(remaining_data_bytes);
        }
        remaining_data_bytes -= data->data().size();
        break;
      }
      case curl::fuzzer::proto::Http2Action::kWindowUpdate: {
        auto* update = action.mutable_window_update();
        BoundHttp2StreamRef(update->mutable_stream());
        update->set_increment(std::max(1U, update->increment() & 0x7fffffffU));
        break;
      }
      case curl::fuzzer::proto::Http2Action::kRstStream:
        BoundHttp2StreamRef(action.mutable_rst_stream()->mutable_stream());
        break;
      case curl::fuzzer::proto::Http2Action::kPing:
        if (action.ping().opaque_data().size() > 8U) {
          action.mutable_ping()->mutable_opaque_data()->resize(8U);
        }
        break;
      case curl::fuzzer::proto::Http2Action::kGoaway:
        BoundHttp2StreamRef(action.mutable_goaway()->mutable_last_stream());
        BoundHttp2RawData(action.mutable_goaway()->mutable_debug_data(), &remaining_raw_bytes);
        break;
      case curl::fuzzer::proto::Http2Action::kPushPromise:
        BoundHttp2StreamRef(action.mutable_push_promise()->mutable_parent_stream());
        BoundHttp2StreamRef(action.mutable_push_promise()->mutable_promised_stream());
        BoundHttp3Headers(action.mutable_push_promise()->mutable_request_headers(), scenario_limits::kMaxHttp2Headers,
                          &remaining_header_bytes);
        break;
      case curl::fuzzer::proto::Http2Action::kWait: {
        auto* wait = action.mutable_wait();
        BoundHttp2StreamRef(wait->mutable_stream());
        if (wait->event() < curl::fuzzer::proto::HTTP2_CLIENT_EVENT_SETTINGS ||
            wait->event() > curl::fuzzer::proto::HTTP2_CLIENT_EVENT_END_STREAM) {
          wait->set_event(curl::fuzzer::proto::HTTP2_CLIENT_EVENT_SETTINGS);
        }
        wait->set_count(std::max(1U, std::min(wait->count(), 16U)));
        break;
      }
      case curl::fuzzer::proto::Http2Action::kYieldTurns:
        action.set_yield_turns(std::min<std::uint32_t>(action.yield_turns(), scenario_limits::kMaxHttp2YieldTurns));
        break;
      case curl::fuzzer::proto::Http2Action::kWireFrame:
        action.mutable_wire_frame()->set_type(action.wire_frame().type() & 0xffU);
        action.mutable_wire_frame()->set_flags(action.wire_frame().flags() & 0xffU);
        action.mutable_wire_frame()->set_stream_id(action.wire_frame().stream_id() & 0x7fffffffU);
        action.mutable_wire_frame()->set_declared_length(action.wire_frame().declared_length() & 0x00ffffffU);
        BoundHttp2RawData(action.mutable_wire_frame()->mutable_payload(), &remaining_raw_bytes);
        break;
      case curl::fuzzer::proto::Http2Action::kRawBytes:
        BoundHttp2RawData(action.mutable_raw_bytes(), &remaining_raw_bytes);
        break;
      case curl::fuzzer::proto::Http2Action::ACTION_NOT_SET: {
        auto* response = action.mutable_headers();
        response->set_status_code(200);
        response->set_end_stream(true);
        break;
      }
    }
  }
}

/// Canonicalize one ordered H3 script to the exact bounded prefix that the
/// QUIC peer can execute. Transport setup remains peer-owned; only plaintext
/// HTTP/3 operations are mutation-controlled here.
void BoundHttp3PlanShape(curl::fuzzer::proto::Http3Plan* plan) {
  if (plan->use_h1_connect_udp_proxy()) {
    plan->clear_actions();
    return;
  }
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
  BoundStringValues(scenario->mutable_mail_rcpt(), scenario_limits::kMaxMailRecipients,
                    scenario_limits::kMaxMailRecipientBytes);
  BoundFileInputs(scenario);
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

/// Return whether an option can affect the origin request carried through the
/// fixed HTTP/2 proxy. Proxy routing, ALPN, and TLS verification are owned by
/// H2ProxyMockServer and must not be mutation-controlled; HTTP/2 as an inner
/// tunneled origin protocol is also excluded because it would require a second
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

/// Keep request-level HTTP mutations while preserving the resolver lane's
/// fixed HTTP/2 transport. Scenario options run after the H2 peer installs
/// CURL_HTTP_VERSION_2TLS, so retaining CURLOPT_HTTP_VERSION here would let a
/// mutation disable the HTTPS-RR ALPN path this lane exists to exercise.
void RetainDohHttpsRrOptions(curl::fuzzer::proto::Scenario* scenario) {
  RetainMatchingOptions(scenario, [](curl::fuzzer::proto::CurlOptionId option_id) {
    return IsCheapHttpOption(option_id) && option_id != curl::fuzzer::proto::CURLOPT_HTTP_VERSION;
  });
}

/// IPFS and IPNS are rewritten to an ordinary gateway GET before curl runs, so
/// the gateway lane can consume the same cheap HTTP request controls as the
/// fast HTTP lane. Gateway selection and TLS policy remain harness-owned.
bool IsIpfsOption(curl::fuzzer::proto::CurlOptionId option_id) { return IsCheapHttpOption(option_id); }

/// Keep the gateway lane's option budget on request-level HTTP behavior.
void RetainIpfsOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsIpfsOption); }

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

/// Return whether an option can change an FTP transfer serviced by the
/// bounded control/data peer. Active mode is confined to the mock's loopback
/// listener; the implicit-TLS lane removes those selectors because its data
/// channels are wrapped socketpairs rather than dialable TCP listeners.
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
    case curl::fuzzer::proto::CURLOPT_FTPPORT:
    case curl::fuzzer::proto::CURLOPT_FTP_USE_EPRT:
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

/// Remove active-mode selectors from the implicit-TLS FTP lane. FTPS data
/// channels must carry TLS, but curl's PORT/EPRT path expects a real loopback
/// TCP listener that the socketpair-wrapped TLS peer cannot provide, so those
/// scenarios stay on EPSV/PASV. Removing the options here keeps LPM from
/// spending mutations on a transfer mode this lane deliberately rejects.
void RemoveFtpActiveModeOptions(curl::fuzzer::proto::Scenario* scenario) {
  RetainMatchingOptions(scenario, [](curl::fuzzer::proto::CurlOptionId option_id) {
    return option_id != curl::fuzzer::proto::CURLOPT_FTPPORT && option_id != curl::fuzzer::proto::CURLOPT_FTP_USE_EPRT;
  });
}

/// Return whether an option can change a local file:// transfer against the
/// fixed /dev/null target. Upload controls are safe only because
/// CanonicalizeFileAuthority replaces every mutation-controlled path before
/// execution; they let the lane cover file.c's write path without creating or
/// changing a named host file. Range, resume, size, metadata, and conversion
/// controls remain useful because curl implements them directly in file.c.
bool IsFileOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_CRLF:
    case curl::fuzzer::proto::CURLOPT_DIRLISTONLY:
    case curl::fuzzer::proto::CURLOPT_DISALLOW_USERNAME_IN_URL:
    case curl::fuzzer::proto::CURLOPT_FAILONERROR:
    case curl::fuzzer::proto::CURLOPT_FILETIME:
    case curl::fuzzer::proto::CURLOPT_HEADER:
    case curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PATH_AS_IS:
    case curl::fuzzer::proto::CURLOPT_RANGE:
    case curl::fuzzer::proto::CURLOPT_RESUME_FROM_LARGE:
    case curl::fuzzer::proto::CURLOPT_TIMECONDITION:
    case curl::fuzzer::proto::CURLOPT_TIMEVALUE_LARGE:
    case curl::fuzzer::proto::CURLOPT_TRANSFERTEXT:
    case curl::fuzzer::proto::CURLOPT_UPLOAD:
    case curl::fuzzer::proto::CURLOPT_UPLOAD_BUFFERSIZE:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the FILE target's option budget on local-transfer semantics. The URL
/// canonicalizer, rather than this allowlist, is the write barrier: every
/// retained upload option can target only /dev/null.
void RetainFileOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsFileOption); }

/// Return whether an option can change the single-connection SMTP exchange.
/// The peer owns routing and timeouts; this list retains the mail envelope,
/// authentication, and upload shape. STARTTLS remains exclusive to TLS lanes,
/// and CURLOPT_FORBID_REUSE is excluded because its graceful-shutdown path
/// spends up to a second waiting for QUIT on every fuzzed error.
bool IsSmtpOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_CRLF:
    case curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST:
    case curl::fuzzer::proto::CURLOPT_FRESH_CONNECT:
    case curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS:
    case curl::fuzzer::proto::CURLOPT_MAIL_AUTH:
    case curl::fuzzer::proto::CURLOPT_MAIL_FROM:
    case curl::fuzzer::proto::CURLOPT_MAIL_RCPT_ALLOWFAILS:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_SASL_AUTHZID:
    case curl::fuzzer::proto::CURLOPT_SASL_IR:
    case curl::fuzzer::proto::CURLOPT_UPLOAD:
    case curl::fuzzer::proto::CURLOPT_UPLOAD_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
    case curl::fuzzer::proto::CURLOPT_XOAUTH2_BEARER:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the SMTP target's general option budget focused on mail-envelope and
/// authentication states its command-aware peer can advance.
void RetainSmtpOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsSmtpOption); }

/// Return whether an option affects IMAP authentication, command selection, or
/// APPEND upload state. IMAP has no envelope recipient list; STARTTLS belongs
/// to a future TLS lane and is deliberately excluded here.
bool IsImapOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_CRLF:
    case curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST:
    case curl::fuzzer::proto::CURLOPT_FRESH_CONNECT:
    case curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_SASL_AUTHZID:
    case curl::fuzzer::proto::CURLOPT_SASL_IR:
    case curl::fuzzer::proto::CURLOPT_UPLOAD:
    case curl::fuzzer::proto::CURLOPT_UPLOAD_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
    case curl::fuzzer::proto::CURLOPT_XOAUTH2_BEARER:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the IMAP target's general option budget focused on command selection,
/// authentication, and the bounded APPEND upload.
void RetainImapOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsImapOption); }

/// Return whether an option affects POP3 authentication or command selection.
/// POP3 is download-only, so upload and file-size controls would add callback
/// work that its state machine never consumes.
bool IsPop3Option(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST:
    case curl::fuzzer::proto::CURLOPT_DIRLISTONLY:
    case curl::fuzzer::proto::CURLOPT_FRESH_CONNECT:
    case curl::fuzzer::proto::CURLOPT_LOGIN_OPTIONS:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_SASL_AUTHZID:
    case curl::fuzzer::proto::CURLOPT_SASL_IR:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
    case curl::fuzzer::proto::CURLOPT_XOAUTH2_BEARER:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the POP3 target's general option budget focused on authentication and
/// LIST/RETR command selection.
void RetainPop3Options(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsPop3Option); }

/// Return whether an option affects DICT request construction. DICT is
/// download-only and takes its command from the URL path; authentication,
/// response sizing, and the handful of transfer-mode controls are the only
/// meaningful scalar inputs.
bool IsDictOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_CRLF:
    case curl::fuzzer::proto::CURLOPT_FRESH_CONNECT:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the DICT target's general option budget focused on command and
/// credential state its stream peer can advance.
void RetainDictOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsDictOption); }

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

/// Return whether an option can change the single-connection MQTT exchange.
/// The topic comes from the URL path and the publish body from POSTFIELDS, so
/// authentication, publish/subscribe mode, receive sizing, and the publish
/// size ceiling are the meaningful scalar controls. Transport and connection-
/// reuse options stay with the peer.
bool IsMqttOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_COPYPOSTFIELDS:
    case curl::fuzzer::proto::CURLOPT_HTTPGET:
    case curl::fuzzer::proto::CURLOPT_KEEP_SENDING_ON_ERROR:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_NOBODY:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_POST:
    case curl::fuzzer::proto::CURLOPT_POSTFIELDS:
    case curl::fuzzer::proto::CURLOPT_UPLOAD:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the MQTT target's general option budget focused on credential and
/// publish-mode states its packet-aware peer can advance.
void RetainMqttOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsMqttOption); }

/// Return whether an option can change the single-connection LDAP exchange.
/// The base DN, attributes, scope, and filter come from the URL path, and
/// OpenLDAP's simple bind takes its DN/password from the credential options.
/// CURLOPT_CUSTOMREQUEST is deliberately absent: this curl revision's
/// OpenLDAP handler ignores it. Upload, HTTP, and transfer-shape controls would
/// add option work that the LDAP state machine never consumes.
bool IsLdapOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_FRESH_CONNECT:
    case curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_USERNAME:
    case curl::fuzzer::proto::CURLOPT_USERPWD:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Keep the LDAP target's option budget focused on bind credentials and the
/// bounded download path its BER-aware peer can advance.
void RetainLdapOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsLdapOption); }

/// Return whether an option can change curl's RTSP request construction,
/// response handling, authentication, or bounded entity body. Redirect and
/// connection-reuse controls are deliberately excluded: the peer services one
/// request at a time and refuses follow-on sockets.
bool IsRtspOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_ACCEPT_ENCODING:
    case curl::fuzzer::proto::CURLOPT_BUFFERSIZE:
    case curl::fuzzer::proto::CURLOPT_COPYPOSTFIELDS:
    case curl::fuzzer::proto::CURLOPT_FAILONERROR:
    case curl::fuzzer::proto::CURLOPT_HTTPAUTH:
    case curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE:
    case curl::fuzzer::proto::CURLOPT_PASSWORD:
    case curl::fuzzer::proto::CURLOPT_POSTFIELDS:
    case curl::fuzzer::proto::CURLOPT_RANGE:
    case curl::fuzzer::proto::CURLOPT_REFERER:
    case curl::fuzzer::proto::CURLOPT_RTSP_CLIENT_CSEQ:
    case curl::fuzzer::proto::CURLOPT_RTSP_REQUEST:
    case curl::fuzzer::proto::CURLOPT_RTSP_SERVER_CSEQ:
    case curl::fuzzer::proto::CURLOPT_RTSP_SESSION_ID:
    case curl::fuzzer::proto::CURLOPT_RTSP_STREAM_URI:
    case curl::fuzzer::proto::CURLOPT_RTSP_TRANSPORT:
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

/// Compact the RTSP option prefix so unrelated HTTP/TLS controls cannot crowd
/// method selection, stream metadata, credentials, and the bounded body out of
/// the shared option budget.
void RetainRtspOptions(curl::fuzzer::proto::Scenario* scenario) { RetainMatchingOptions(scenario, &IsRtspOption); }

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

/// Keep prior-knowledge HTTP/2 and HTTP/3 out of the throughput-oriented HTTP
/// lane. HTTP/1 modes and cleartext HTTP/2 upgrade remain here because h2c's
/// HTTP/1 request and 101 transition are distinct from the dedicated target's
/// prior-knowledge transport.
void CanonicalizeFastHttpVersion(curl::fuzzer::proto::Scenario* scenario) {
  for (auto& option : *scenario->mutable_options()) {
    if (option.option_id() != curl::fuzzer::proto::CURLOPT_HTTP_VERSION) {
      continue;
    }
    const std::uint64_t version = IntegralMutationValue(option);
    // 2TLS remains HTTP/1.1 because this target fixes the scheme to HTTP.
    if (version <= CURL_HTTP_VERSION_2TLS) {
      option.set_uint_value(version);
    } else {
      option.set_uint_value(CURL_HTTP_VERSION_NONE);
    }
  }
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
      case curl::fuzzer::proto::CURLOPT_FTPPORT:
        // Never let a mutated active-mode address resolve or bind outside the
        // process. Empty remains reachable only by omitting the option.
        option.set_string_value("127.0.0.1");
        break;
      case curl::fuzzer::proto::CURLOPT_FTP_USE_EPRT:
        option.set_bool_value(IntegralMutationValue(option) != 0U);
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

/// Fold the RTSP request selector onto curl's documented 1..11 domain so
/// random uint64 mutations still issue a method instead of failing setopt
/// validation. A zero or out-of-range value becomes the default OPTIONS.
/// Sequence overrides are clamped to curl's int range; zero remains meaningful
/// because curl rewrites it to its default on connect.
void CanonicalizeRtspOptionModes(curl::fuzzer::proto::Scenario* scenario) {
  for (auto& option : *scenario->mutable_options()) {
    switch (option.option_id()) {
      case curl::fuzzer::proto::CURLOPT_RTSP_REQUEST: {
        const std::uint64_t value = IntegralMutationValue(option);
        // RECEIVE sends no request and instead waits for server-initiated
        // stream data, which the request-aligned peer never emits. Fold it
        // onto the default OPTIONS like zero and out-of-range values so every
        // retained request still issues a scripted exchange.
        const bool supported =
            value >= CURL_RTSPREQ_OPTIONS && value < CURL_RTSPREQ_LAST && value != CURL_RTSPREQ_RECEIVE;
        option.set_uint_value(supported ? value : CURL_RTSPREQ_OPTIONS);
        break;
      }
      case curl::fuzzer::proto::CURLOPT_RTSP_CLIENT_CSEQ:
      case curl::fuzzer::proto::CURLOPT_RTSP_SERVER_CSEQ:
        option.set_uint_value(std::min<std::uint64_t>(IntegralMutationValue(option),
                                                      static_cast<std::uint64_t>(std::numeric_limits<int>::max())));
        break;
      default:
        break;
    }
  }
}

/// Identify options introduced for FTP/TFTP/SMTP so existing fixed lanes do
/// not silently inherit dead mutations when the shared generated manifest
/// grows. Generic options retained by those protocol allowlists are
/// deliberately absent here because they remain useful to HTTP, WebSocket,
/// API, or timing targets.
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
    case curl::fuzzer::proto::CURLOPT_FTPPORT:
    case curl::fuzzer::proto::CURLOPT_FTP_USE_EPRT:
    case curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE:
    case curl::fuzzer::proto::CURLOPT_TFTP_NO_OPTIONS:
    case curl::fuzzer::proto::CURLOPT_MAIL_FROM:
    case curl::fuzzer::proto::CURLOPT_MAIL_RCPT_ALLOWFAILS:
    case curl::fuzzer::proto::CURLOPT_TRANSFERTEXT:
    case curl::fuzzer::proto::CURLOPT_WILDCARDMATCH:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Remove FTP/TFTP/SMTP-only options while preserving the relative order of
/// every generic option an existing fixed target already consumed.
void RemoveFileTransferOnlyOptions(curl::fuzzer::proto::Scenario* scenario) {
  RetainMatchingOptions(
      scenario, [](curl::fuzzer::proto::CurlOptionId option_id) { return !IsFileTransferOnlyOption(option_id); });
}

/// Identify options that only the RTSP peer interprets. Other fixed lanes
/// would apply them to handles whose protocol driver never reads the values, so
/// keeping them would spend mutation and setopt work without changing a
/// transfer.
bool IsRtspOnlyOption(curl::fuzzer::proto::CurlOptionId option_id) {
  switch (option_id) {
    case curl::fuzzer::proto::CURLOPT_RTSP_CLIENT_CSEQ:
    case curl::fuzzer::proto::CURLOPT_RTSP_REQUEST:
    case curl::fuzzer::proto::CURLOPT_RTSP_SERVER_CSEQ:
    case curl::fuzzer::proto::CURLOPT_RTSP_SESSION_ID:
    case curl::fuzzer::proto::CURLOPT_RTSP_STREAM_URI:
    case curl::fuzzer::proto::CURLOPT_RTSP_TRANSPORT:
      return true;

    case curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED:
    default:
      return false;
  }
}

/// Remove RTSP-only options from lanes that cannot reach curl's RTSP request
/// builder. The compatibility target returns before this helper so historical
/// unknown-field semantics stay unchanged.
void RemoveRtspOnlyOptions(curl::fuzzer::proto::Scenario* scenario) {
  RetainMatchingOptions(scenario,
                        [](curl::fuzzer::proto::CurlOptionId option_id) { return !IsRtspOnlyOption(option_id); });
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
  if (!scenario->http3_plan().use_h1_connect_udp_proxy()) {
    scenario->clear_connection();
  }
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

/// Retain the single command-aligned control script and optional upload body
/// consumed by the SMTP peer. SMTP cannot open follow-on sockets, and HTTP
/// headers, TELNET negotiation, API plans, and stream-only connection controls
/// have no representation in its exchange. MIME remains meaningful because
/// curl can serialize it as the DATA body.
void RemoveIgnoredSmtpShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
}

/// Retain the one command-aligned control script and optional APPEND body
/// consumed by the IMAP peer. IMAP cannot open follow-on sockets, and HTTP
/// headers and structured stream controls have no representation in its
/// exchange. MIME remains meaningful because curl serializes it as an APPEND
/// literal.
void RemoveIgnoredImapShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
}

/// Retain only the command-aligned control script. POP3 is a download-only
/// protocol: upload state, MIME bodies, HTTP headers, and follow-on sockets
/// cannot reach its state machine.
void RemoveIgnoredPop3Shape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  scenario->clear_mime_post();
  scenario->clear_upload();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
}

void RemoveIgnoredGopherShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  scenario->clear_mime_post();
  scenario->clear_upload();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
}

/// Retain only the command-aligned control script. DICT is a download-only
/// protocol: upload state, MIME bodies, HTTP headers, and follow-on sockets
/// cannot reach its state machine.
void RemoveIgnoredDictShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  scenario->clear_mime_post();
  scenario->clear_upload();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
  // curl writes CLIENT, one lookup command, and QUIT in a single send, then
  // reads an EOF-framed body. The peer consumes only the first non-CLIENT
  // reply chunk and half-closes, so any later chunk is permanently dead work
  // the mutator keeps rediscovering.
  TrimRepeated(scenario->mutable_connection()->mutable_on_readable(), 1);
}

/// Retain the one binary server script and the scalar publish payload. MQTT
/// cannot open follow-on sockets, does not use HTTP headers or MIME, and takes
/// its publish body from CURLOPT_POSTFIELDS rather than curl's read callback.
/// The remaining connection fields (initial CONNACK plus server packets) are
/// exactly what the packet-aware peer consumes.
void RemoveIgnoredMqttShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  scenario->clear_mime_post();
  scenario->clear_upload();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
}

/// FILE has no peer, so response scripts, connection controls, MIME, and
/// HTTP/TELNET/API state are inert. Retain the bounded upload script because
/// the fixed /dev/null URL makes curl's local write path safe to exercise.
void RemoveIgnoredFileShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_connection();
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  scenario->clear_mime_post();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
}

/// Retain the scripted bind reply and BER search-result messages consumed by
/// the LDAP peer. LDAP cannot open follow-on sockets, and HTTP headers, MIME,
/// upload state, and TELNET negotiation have no representation in its
/// exchange. The primary connection's initial_response is the bind reply, so
/// unlike the file-transfer and mail lanes it must survive pruning.
void RemoveIgnoredLdapShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_request_headers();
  scenario->clear_mime_post();
  scenario->clear_upload();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveUnusedFileTransferConnectionShape(scenario->mutable_connection());
}

/// Retain the request-aligned control script and the fields curl serializes
/// into an RTSP request. Custom request headers, upload/postfields bodies for
/// ANNOUNCE and SET_PARAMETER, and MIME-free options stay meaningful. RTSP has
/// no server greeting, cannot consume follow-on stream scripts, and does not
/// use MIME bodies, so those shapes are removed before general bounds.
void RemoveIgnoredRtspShape(curl::fuzzer::proto::Scenario* scenario) {
  scenario->clear_subsequent_connections();
  scenario->clear_mime_post();
  RemoveTelnetOnlyShape(scenario);
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);

  auto* connection = scenario->mutable_connection();
  connection->clear_initial_response();
  RemoveUnusedFileTransferConnectionShape(connection);
}

/// Retain the shapes an ordinary gateway GET can consume. The IPFS/IPNS lane
/// runs through the same HTTP mock as the fast HTTP lane, so raw response
/// chunks, request headers, and HTTP options stay meaningful while MIME,
/// uploads, structured frames, and follow-on sockets are removed.
void RemoveIgnoredIpfsShape(curl::fuzzer::proto::Scenario* scenario) {
  RemoveApiOnlyShape(scenario);
  RemoveMultiOnlyShape(scenario);
  RemoveTelnetOnlyShape(scenario);
  RemoveDeepHttpShape(scenario);
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

/// Keep the timing target on a protocol the timing run mode can actually
/// drive. TLS setup has its own cost profile and would obscure whether
/// backpressure mutations are exploring curl's send/receive state machines
/// effectively. Only WebSocket has a plaintext peer in kProtocolCoverage mode,
/// so WSS folds onto WS; every other scheme — including the mail, MQTT, and
/// file-transfer families whose peers are gated on their dedicated run modes —
/// falls back to the always-served HTTP peer rather than leaving the runner
/// without a transport.
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
    case curl::fuzzer::proto::SCHEME_DICT:
    case curl::fuzzer::proto::SCHEME_FILE:
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

/// Canonicalize the fields that determine which server and drive-loop policy
/// execute. Fast targets discard backpressure because one mutated non-zero
/// scalar otherwise opts an ordinary input into hundreds of timed waits. The
/// timing target does the inverse: it guarantees a non-default buffer setting
/// so its CPU allocation remains focused on the intentionally slower paths.
void ApplyLanePolicy(curl::fuzzer::proto::Scenario* scenario, TargetProfile profile) {
  if (scenario == nullptr) {
    return;
  }

  if (profile == TargetProfile::kCompatibility) {
    // The original target's existing corpus predates profile splitting. A
    // no-op here makes the type safe to pass around while its binary continues
    // to omit postprocessor registration altogether. The append-only FTP/FTPS
    // and TFTP scheme values do not justify rewriting historical mixed-lane
    // inputs.
    return;
  }

  // MQTT is append-only as well. No other fixed lane may reinterpret one of
  // its packet scripts, so clear the selector before the lane-specific early
  // paths install their own scheme. Compatibility returned above and keeps
  // historical unknown-field semantics.
  if (profile != TargetProfile::kFastMqtt && scenario->scheme() == curl::fuzzer::proto::SCHEME_MQTT) {
    scenario->clear_scheme();
  }

  // DICT is append-only too. Only the dedicated lane may reinterpret a lookup
  // script; every other fixed lane clears the selector before installing its
  // own scheme.
  if (profile != TargetProfile::kFastDict && scenario->scheme() == curl::fuzzer::proto::SCHEME_DICT) {
    scenario->clear_scheme();
  }

  // FILE is append-only as well. Other fixed lanes must not inherit a local
  // filesystem selector from a corpus input; only the dedicated lane may run
  // the peerless file:// path.
  if (profile != TargetProfile::kFastFile && scenario->scheme() == curl::fuzzer::proto::SCHEME_FILE) {
    scenario->clear_scheme();
  }

  // LDAP and LDAPS are append-only too. Only the fixed BER lane may turn one
  // of their scripted bind/search exchanges into a live OpenLDAP session.
  if (profile != TargetProfile::kFastLdap && (scenario->scheme() == curl::fuzzer::proto::SCHEME_LDAP ||
                                              scenario->scheme() == curl::fuzzer::proto::SCHEME_LDAPS)) {
    scenario->clear_scheme();
  }

  // RTSP is append-only too. Keep its selector away from every fixed lane
  // that cannot service a request-aligned RTSP exchange, and drop its
  // protocol-only options before those lanes compact their own allowlists.
  if (profile != TargetProfile::kFastRtsp && scenario->scheme() == curl::fuzzer::proto::SCHEME_RTSP) {
    scenario->clear_scheme();
  }
  if (profile != TargetProfile::kFastRtsp) {
    RemoveRtspOnlyOptions(scenario);
  }

  // FTPS is append-only too. Only the fixed FTP lane may turn one of its
  // scenarios into a TLS-wrapped control/data exchange.
  if (profile != TargetProfile::kFastFtp && scenario->scheme() == curl::fuzzer::proto::SCHEME_FTPS) {
    scenario->clear_scheme();
  }

  // IPFS/IPNS are append-only as well. Their identifiers and gateway paths
  // would be inert in every other fixed lane, so clear the selector before
  // the lane-specific early paths install their own scheme.
  if (profile != TargetProfile::kFastIpfs && (scenario->scheme() == curl::fuzzer::proto::SCHEME_IPFS ||
                                              scenario->scheme() == curl::fuzzer::proto::SCHEME_IPNS)) {
    scenario->clear_scheme();
  }

  // Accepted server push adds a harness-owned easy handle and therefore
  // belongs only in the fixed H2 origin lanes. Compatibility remains a no-op
  // above so accumulated mixed corpus entries keep their wire meaning.
  if (profile != TargetProfile::kHttpsH2 && profile != TargetProfile::kFastHttp2) {
    scenario->clear_accept_h2_push();
  }

  // Only the dedicated TLS and QUIC peers consume a certificate-chain
  // selector. Remove it before protocol-specific early returns so other fixed
  // targets do not spend mutations on inert TLS server state.
  if (profile != TargetProfile::kFastHttps && profile != TargetProfile::kHttpsH2 &&
      profile != TargetProfile::kFastHttp3 && profile != TargetProfile::kFastSecureWebSocket) {
    scenario->clear_tls_certificate_chain();
  }

  // Only the dedicated TLS HTTP/2 origin consumes the group selector. The
  // compatibility profile returned above so unknown fields remain stable.
  if (profile != TargetProfile::kHttpsH2) {
    scenario->clear_tls_group_profile();
  }

  // Field 13 is append-only so the compatibility target can round-trip it,
  // but every other fixed lane must discard work its peer cannot consume.
  if (profile != TargetProfile::kFastHttp3) {
    scenario->clear_http3_plan();
  }

  const bool resolver_uses_doh =
      profile == TargetProfile::kResolver &&
      (scenario->doh_https_rr() || scenario->resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR);
  if (profile != TargetProfile::kHttpsH2 && profile != TargetProfile::kFastHttp2 && !resolver_uses_doh) {
    scenario->clear_http2_plan();
  }

  if (profile != TargetProfile::kProxyTransport) {
    scenario->clear_socks_proxy_mode();
    scenario->clear_haproxy_protocol();
  }

  if (profile != TargetProfile::kDeepHttp) {
    scenario->clear_http_transport_mode();
  }

  if (profile != TargetProfile::kResolver) {
    scenario->clear_resolve_entries();
    scenario->clear_happy_eyeballs();
    scenario->clear_doh_https_rr();
    scenario->clear_resolver_mode();
  }

  // SMTP's schema-native recipient list has no meaning in another protocol's
  // exchange. Clearing it before early returns keeps other fixed lanes from
  // carrying inert envelope work.
  if (profile != TargetProfile::kFastSmtp) {
    scenario->clear_mail_rcpt();
  }

  // Only these protocol peers currently interleave zero-timeout public multi
  // polling with immediate service of their live connection.
  // Keep the opt-in out of fixed lanes whose driver cannot honor that timing
  // contract; compatibility returned above and preserves its wire input.
  if (profile != TargetProfile::kFastSmtp && profile != TargetProfile::kFastImap &&
      profile != TargetProfile::kFastPop3 && profile != TargetProfile::kFastFtp &&
      profile != TargetProfile::kFastMqtt && profile != TargetProfile::kProxyTransport &&
      profile != TargetProfile::kDeepHttp) {
    scenario->clear_probe_multi_pollset();
  }

  // Direct forwarding changes the H2 proxy stream from CONNECT authority-form
  // to an absolute-form origin request. No other peer implements that shape.
  if (profile != TargetProfile::kH2Proxy) {
    scenario->clear_h2_forward_proxy();
  }

  // Anonymous parser files add syscalls and line parsing that belong only in
  // the deep HTTP lane. Clear them before every protocol-specific early path
  // so fast targets never pay to normalize content they cannot consume.
  if (profile != TargetProfile::kDeepHttp) {
    scenario->clear_cookie_file();
    scenario->clear_altsvc_file();
    scenario->clear_hsts_file();
    scenario->clear_netrc_file();
  }

  // A CRL is useful only when the target completes a real origin TLS setup.
  // Keep malformed or oversized CRLs from turning every other lane into an
  // early TLS-option failure.
  if (profile != TargetProfile::kFastHttps) {
    scenario->clear_crl_file();
  }

  if (profile == TargetProfile::kFastHttp3) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTPS);
    RemoveIgnoredHttp3Shape(scenario);
    RetainHttp3RequestOptions(scenario);
    BoundScenarioShape(scenario);
    // The ordinary QUIC peer consumes Http3Plan and has no use for a stream
    // response. CONNECT-UDP proxy mode instead feeds the retained Connection
    // bytes to curl's HTTP/1.1 proxy state machine and capsule filter.
    if (!scenario->http3_plan().use_h1_connect_udp_proxy()) {
      scenario->clear_connection();
    }
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
    CanonicalizeFastHttpVersion(scenario);
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

  if (profile == TargetProfile::kHttpsH2 || profile == TargetProfile::kFastHttp2) {
    scenario->set_scheme(profile == TargetProfile::kHttpsH2 ? curl::fuzzer::proto::SCHEME_HTTPS
                                                            : curl::fuzzer::proto::SCHEME_HTTP);
    RemoveApiOnlyShape(scenario);
    RemoveMultiOnlyShape(scenario);
    RemoveTelnetOnlyShape(scenario);
    RemoveIgnoredH2ProxyShape(scenario);
    RetainH2ProxyOriginOptions(scenario);
    BoundScenarioShape(scenario);
    if (scenario->has_http2_plan()) {
      auto* connection = scenario->mutable_connection();
      connection->clear_initial_response();
      connection->clear_on_readable();
      connection->clear_server_frames();
      BoundHttp2PlanShape(scenario->mutable_http2_plan());
    }
    CanonicalizeTlsAuthority(scenario);
    if (profile == TargetProfile::kHttpsH2) {
      CanonicalizeTlsCertificateChain(scenario);
      CanonicalizeTlsGroupProfile(scenario);
    }
    return;
  }

  if (profile == TargetProfile::kProxyTransport) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
    switch (scenario->socks_proxy_mode()) {
      case curl::fuzzer::proto::SOCKS_PROXY_SOCKS4:
      case curl::fuzzer::proto::SOCKS_PROXY_SOCKS4A:
      case curl::fuzzer::proto::SOCKS_PROXY_SOCKS5:
      case curl::fuzzer::proto::SOCKS_PROXY_SOCKS5_HOSTNAME:
        break;
      default:
        scenario->set_socks_proxy_mode(curl::fuzzer::proto::SOCKS_PROXY_SOCKS4);
        break;
    }
    RemoveApiOnlyShape(scenario);
    RemoveMultiOnlyShape(scenario);
    RemoveTelnetOnlyShape(scenario);
    RemoveDeepHttpShape(scenario);
    RetainCheapHttpOptions(scenario);
    scenario->mutable_connection()->clear_initial_response();
    BoundScenarioShape(scenario);
    CanonicalizeSocksAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kResolver) {
    // The DoH variant owns the outer HTTPS exchange through a verified
    // TLS/ALPN h2 peer, so its response is an Http2Plan rather than a raw
    // stream script. The ordinary resolver lanes keep plaintext HTTP.
    switch (scenario->resolver_mode()) {
      case curl::fuzzer::proto::RESOLVER_MODE_DEFAULT:
      case curl::fuzzer::proto::RESOLVER_MODE_THREADED_POSITIVE:
      case curl::fuzzer::proto::RESOLVER_MODE_THREADED_NEGATIVE:
      case curl::fuzzer::proto::RESOLVER_MODE_THREADED_LINK_LOCAL:
      case curl::fuzzer::proto::RESOLVER_MODE_UNIX_SOCKET:
      case curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR:
      case curl::fuzzer::proto::RESOLVER_MODE_THREADED_PARTIAL:
      case curl::fuzzer::proto::RESOLVER_MODE_GLOBAL_LIFECYCLE:
        break;
      default:
        scenario->clear_resolver_mode();
        break;
    }
    const bool fixed_resolver_mode = scenario->resolver_mode() != curl::fuzzer::proto::RESOLVER_MODE_DEFAULT;
    if (fixed_resolver_mode) {
      scenario->clear_resolve_entries();
      scenario->clear_happy_eyeballs();
    }
    if (scenario->resolver_mode() == curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR) {
      scenario->set_doh_https_rr(true);
    } else if (fixed_resolver_mode) {
      scenario->clear_doh_https_rr();
    }
    const bool doh_https_rr = scenario->doh_https_rr();
    scenario->set_scheme(doh_https_rr ? curl::fuzzer::proto::SCHEME_HTTPS : curl::fuzzer::proto::SCHEME_HTTP);
    RemoveApiOnlyShape(scenario);
    RemoveMultiOnlyShape(scenario);
    RemoveTelnetOnlyShape(scenario);
    RemoveDeepHttpShape(scenario);
    // The generic fast-lane pruning above removes fuzz-controlled timing
    // knobs. Threaded resolver modes add back one fixed marker so their
    // bounded drive performs a pollset probe and short fdset waits while the
    // target-local resolver work is outstanding.
    if (IsThreadedResolverMode(scenario->resolver_mode())) {
      scenario->mutable_connection()->mutable_backpressure()->set_drain_limit(1);
    }
    if (doh_https_rr) {
      RetainDohHttpsRrOptions(scenario);
    } else {
      RetainCheapHttpOptions(scenario);
    }
    if (doh_https_rr) {
      // CURLOPT_RESOLVE cannot carry an HTTPS record, and the responder owns
      // both the address and HTTPS answers. Clearing the address entries keeps
      // the DoH query on the only path that can reach the ALPN selector.
      scenario->clear_resolve_entries();
      scenario->clear_happy_eyeballs();
      if (scenario->has_http2_plan()) {
        auto* connection = scenario->mutable_connection();
        connection->clear_initial_response();
        connection->clear_on_readable();
        connection->clear_server_frames();
        BoundHttp2PlanShape(scenario->mutable_http2_plan());
      }
    } else {
      scenario->clear_http2_plan();
      BoundStringValues(scenario->mutable_resolve_entries(), scenario_limits::kMaxResolveEntries,
                        scenario_limits::kMaxResolveEntryBytes);
    }
    BoundScenarioShape(scenario);
    CanonicalizeResolverAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastFtp) {
    // The same lane services plaintext FTP and implicit-TLS FTPS through one
    // command/data parser. Preserve an explicitly supplied FTPS scheme so the
    // seed and mutations can select the TLS peer; every other scheme falls
    // back to the historical plaintext lane.
    const auto scheme = scenario->scheme();
    const bool implicit_tls = scheme == curl::fuzzer::proto::SCHEME_FTPS;
    scenario->set_scheme(implicit_tls ? curl::fuzzer::proto::SCHEME_FTPS : curl::fuzzer::proto::SCHEME_FTP);
    RemoveIgnoredFtpShape(scenario);
    RetainFtpOptions(scenario);
    if (implicit_tls) {
      RemoveFtpActiveModeOptions(scenario);
    }
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

  if (profile == TargetProfile::kFastSmtp) {
    // The legacy target and its structured replacement both service plaintext
    // SMTP and implicit-TLS SMTPS through one command/reply parser. Preserve an
    // explicitly supplied SMTPS scheme so the seed and mutations can select the
    // TLS peer; every other scheme falls back to the historical plaintext lane.
    const auto scheme = scenario->scheme();
    scenario->set_scheme(scheme == curl::fuzzer::proto::SCHEME_SMTPS ? curl::fuzzer::proto::SCHEME_SMTPS
                                                                     : curl::fuzzer::proto::SCHEME_SMTP);
    RemoveIgnoredSmtpShape(scenario);
    RetainSmtpOptions(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeSmtpAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastImap) {
    // Preserve an explicitly supplied IMAPS scheme so seeds and mutations can
    // select the implicit-TLS peer; every other scheme falls back to the
    // historical plaintext lane. Both values reuse this tag-aware parser.
    const auto scheme = scenario->scheme();
    scenario->set_scheme(scheme == curl::fuzzer::proto::SCHEME_IMAPS ? curl::fuzzer::proto::SCHEME_IMAPS
                                                                     : curl::fuzzer::proto::SCHEME_IMAP);
    RemoveIgnoredImapShape(scenario);
    RetainImapOptions(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeImapAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastPop3) {
    // Preserve an explicitly supplied POP3S scheme so seeds and mutations can
    // select the implicit-TLS peer; every other scheme falls back to the
    // historical plaintext lane. Both values reuse this status-line parser.
    const auto scheme = scenario->scheme();
    scenario->set_scheme(scheme == curl::fuzzer::proto::SCHEME_POP3S ? curl::fuzzer::proto::SCHEME_POP3S
                                                                     : curl::fuzzer::proto::SCHEME_POP3);
    RemoveIgnoredPop3Shape(scenario);
    RetainPop3Options(scenario);
    BoundScenarioShape(scenario);
    CanonicalizePop3Authority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastMqtt) {
    // The dedicated MQTT lane services both the plaintext and implicit-TLS
    // variants through one packet-aware parser. Preserve an explicitly
    // supplied MQTTS scheme so the seed and mutations can select the TLS peer;
    // every other scheme falls back to the historical plaintext lane.
    const auto scheme = scenario->scheme();
    scenario->set_scheme(scheme == curl::fuzzer::proto::SCHEME_MQTTS ? curl::fuzzer::proto::SCHEME_MQTTS
                                                                     : curl::fuzzer::proto::SCHEME_MQTT);
    RemoveIgnoredMqttShape(scenario);
    RetainMqttOptions(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeMqttAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastDict) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_DICT);
    RemoveIgnoredDictShape(scenario);
    RetainDictOptions(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeDictAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastGopher) {
    scenario->set_scheme(scenario->scheme() == curl::fuzzer::proto::SCHEME_GOPHERS
                             ? curl::fuzzer::proto::SCHEME_GOPHERS
                             : curl::fuzzer::proto::SCHEME_GOPHER);
    RemoveIgnoredGopherShape(scenario);
    RemoveFileTransferOnlyOptions(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeTlsAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastFile) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_FILE);
    RemoveIgnoredFileShape(scenario);
    RetainFileOptions(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeFileAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastLdap) {
    // The single LDAP target services plaintext LDAP and implicit-TLS LDAPS
    // through one BER parser. Preserve an explicitly supplied LDAPS scheme so
    // the seed and mutations can select the TLS peer; every other scheme falls
    // back to the historical plaintext lane.
    const auto scheme = scenario->scheme();
    scenario->set_scheme(scheme == curl::fuzzer::proto::SCHEME_LDAPS ? curl::fuzzer::proto::SCHEME_LDAPS
                                                                     : curl::fuzzer::proto::SCHEME_LDAP);
    RemoveIgnoredLdapShape(scenario);
    RetainLdapOptions(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeLdapAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastRtsp) {
    scenario->set_scheme(curl::fuzzer::proto::SCHEME_RTSP);
    RemoveIgnoredRtspShape(scenario);
    RetainRtspOptions(scenario);
    CanonicalizeRtspOptionModes(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeRtspAuthority(scenario);
    return;
  }

  if (profile == TargetProfile::kFastIpfs) {
    // Preserve an explicitly selected IPNS name; every other pre-policy value
    // falls back to the historical IPFS lane so one binary covers both.
    scenario->set_scheme(scenario->scheme() == curl::fuzzer::proto::SCHEME_IPNS ? curl::fuzzer::proto::SCHEME_IPNS
                                                                                : curl::fuzzer::proto::SCHEME_IPFS);
    RemoveIgnoredIpfsShape(scenario);
    RetainIpfsOptions(scenario);
    CanonicalizeFastHttpVersion(scenario);
    BoundScenarioShape(scenario);
    CanonicalizeIpfsAuthority(scenario);
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
    case TargetProfile::kHttpsH2:
      // The protocol-specific early path fixes ALPN and prunes incompatible
      // response shapes while retaining the raw frame script.
      return;
    case TargetProfile::kFastHttp2:
      // The protocol-specific early path fixes prior-knowledge H2 and prunes
      // incompatible response shapes while retaining its frame script.
      return;
    case TargetProfile::kFastHttp3:
      // The protocol-specific early path owns the QUIC response plan.
      return;
    case TargetProfile::kH2Proxy:
      // The early path removes proxy-incompatible fields before general
      // bounds, keeping raw frame mutation dense.
      return;
    case TargetProfile::kProxyTransport:
      // The early path fixes proxy routing and request-triggered replies.
      return;
    case TargetProfile::kResolver:
      // The early path fixes safe DNS/cache routing and bounds its slist.
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
    case TargetProfile::kFastSmtp:
    case TargetProfile::kFastImap:
    case TargetProfile::kFastPop3:
    case TargetProfile::kFastMqtt:
    case TargetProfile::kFastDict:
    case TargetProfile::kFastGopher:
    case TargetProfile::kFastFile:
    case TargetProfile::kFastLdap:
    case TargetProfile::kFastRtsp:
    case TargetProfile::kFastIpfs:
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
      switch (scenario->http_transport_mode()) {
        case curl::fuzzer::proto::HTTP_TRANSPORT_DIRECT:
        case curl::fuzzer::proto::HTTP_TRANSPORT_FORWARD_PROXY:
        case curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY:
        case curl::fuzzer::proto::HTTP_TRANSPORT_UNIX_SOCKET:
          break;
        default:
          scenario->clear_http_transport_mode();
          break;
      }
      if (scenario->http_transport_mode() != curl::fuzzer::proto::HTTP_TRANSPORT_DIRECT) {
        CanonicalizeHttpTransportAuthority(scenario);
      } else if (!scenario->altsvc_file().empty()) {
        CanonicalizeAltSvcAuthority(scenario);
      }
      if (scenario->http_transport_mode() != curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY) {
        scenario->clear_probe_multi_pollset();
      }
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
      // The multi runner is HTTP-only (it drives every handle through one
      // plaintext HTTP peer), so pin the scheme instead of letting a mutation
      // select a protocol the runner cannot service.
      scenario->set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
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

    case TargetProfile::kHttpsH2:
      // Handled by the raw HTTP/2 protocol-specific early path above.
      return;

    case TargetProfile::kFastHttp2:
      // Handled by the plaintext HTTP/2 protocol-specific early path above.
      return;

    case TargetProfile::kFastHttp3:
      // Handled before generic connection bounding because Http3Plan replaces
      // the stream-socket response script.
      return;

    case TargetProfile::kH2Proxy:
      // Handled by the protocol-specific early path above.
      return;

    case TargetProfile::kProxyTransport:
      // Handled by the protocol-specific early path above.
      return;

    case TargetProfile::kResolver:
      // Handled by the resolver-specific early path above.
      return;

    case TargetProfile::kFastWebSocket:
      ClearAllBackpressure(scenario);
      RemoveIgnoredWebSocketShape(scenario);
      return;

    case TargetProfile::kFastSecureWebSocket:
      ClearAllBackpressure(scenario);
      RemoveIgnoredWebSocketShape(scenario);
      CanonicalizeTlsAuthority(scenario);
      CanonicalizeTlsCertificateChain(scenario);
      return;

    case TargetProfile::kFastTelnet:
      // Handled before the general bounds so its protocol-specific limits are
      // selected from the start.
      return;

    case TargetProfile::kFastFtp:
    case TargetProfile::kFastTftp:
    case TargetProfile::kFastSmtp:
    case TargetProfile::kFastImap:
    case TargetProfile::kFastPop3:
    case TargetProfile::kFastMqtt:
    case TargetProfile::kFastDict:
    case TargetProfile::kFastGopher:
    case TargetProfile::kFastFile:
    case TargetProfile::kFastLdap:
    case TargetProfile::kFastRtsp:
    case TargetProfile::kFastIpfs:
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

}  // namespace

/// Apply execution-only allocation-failure safety rules. Fixed target
/// postprocessors call this while serializing mutations; the shared runtime
/// repeats it so the compatibility target keeps its persistent wire format
/// while executing the same bounded, safe plan.
/// @param scenario Parsed scenario to canonicalize in place.
void NormalizeScenarioForExecution(curl::fuzzer::proto::Scenario* scenario) {
  if (scenario == nullptr) {
    return;
  }
  CanonicalizeAllocationFailures(scenario);
  CanonicalizeAllocationFailureDrive(scenario);
  CanonicalizeAllocationFailureOptions(scenario);
}

/// Complete normalization for a loaded or mutated fixed-target Scenario.
/// Besides dispatch and timing controls, fixed lanes trim repeated-field and
/// metadata suffixes that the runtime cannot consume. WebSocket lanes also
/// remove follow-on sockets and MIME bodies their single-upgrade driver cannot
/// use; all remaining observable bytes, options, frames, and probes stay
/// fuzz-controlled. Option oneofs are canonicalized before final string bounds,
/// so repeated normalization preserves the same serialized message. The
/// compatibility profile leaves the entire input unchanged.
/// @param scenario Scenario to canonicalize in place.
/// @param profile Target lane whose invariants must be restored.
void NormalizeScenarioForTarget(curl::fuzzer::proto::Scenario* scenario, TargetProfile profile) {
  // Compatibility has no LPM postprocessor. Preserve the complete wire input,
  // including mismatched option oneofs and newly added, otherwise inert fields.
  if (scenario == nullptr || profile == TargetProfile::kCompatibility) {
    return;
  }

  ApplyLanePolicy(scenario, profile);
  NormalizeScenarioForExecution(scenario);
  CanonicalizeOptionValueCases(scenario);
  // Canonicalization can materialize string values or prepend pin syntax.
  // Charge the final representation so normalization remains a fixed point.
  for (auto& option : *scenario->mutable_options()) {
    if (option.value_case() == curl::fuzzer::proto::SetOption::kStringValue) {
      TrimMetadata(option.mutable_string_value());
    }
  }
}

}  // namespace proto_fuzzer
