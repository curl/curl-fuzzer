/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the option-translation helpers declared in
///        option_apply.h.

#include "proto_fuzzer/option_apply.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// How a SetOption oneof should be decoded before calling curl_easy_setopt.
enum class OptionValueKind {
  kString,  ///< string_value → const char* option.
  kUint,    ///< uint_value → long or curl_off_t option.
  kBool     ///< bool_value → 0/1 long option.
};

/// One row in the build-time-generated option manifest: binds a proto enum
/// value to the matching curl_easy_setopt option id and value kind.
struct OptionDescriptor {
  /// Proto enum identifier for this option.
  curl::fuzzer::proto::CurlOptionId id;
  /// How the oneof value should be decoded.
  OptionValueKind kind;
  /// Human-readable option name (e.g. "CURLOPT_URL") for diagnostics.
  const char* name;
  /// The native CURLoption to pass to curl_easy_setopt.
  CURLoption curlopt;
};

// Pulls in kOptionManifest[] and its generated switch-based lookup.
#include "curl_fuzzer_option_manifest.inc"

namespace {

constexpr char kEventDrivenProtocolsAllowed[] = "http,https,ws,wss";
constexpr char kTelnetProtocolAllowed[] = "telnet";
constexpr char kConnectToOverride[] = "::127.0.1.127:";
constexpr char kDevNull[] = "/dev/null";
constexpr char kVerboseEnvVar[] = "FUZZ_VERBOSE";
constexpr char kAltSvcHttpEnvVar[] = "CURL_ALTSVC_HTTP";
constexpr char kHstsHttpEnvVar[] = "CURL_HSTS_HTTP";
constexpr long kConnectTimeoutMs = 200;
constexpr long kTimeoutMs = 200;

/// Baseline write callback for both CURLOPT_WRITEFUNCTION and
/// CURLOPT_HEADERFUNCTION. Consumes every byte so transfers don't stall on
/// backpressure and emits nothing. Protocol-specific mocks may install their
/// own WRITEFUNCTION afterwards if they need to poke protocol APIs while
/// inside a curl callback.
size_t SilentWriteCallback(void* /*contents*/, size_t size, size_t nmemb, void* /*userdata*/) { return size * nmemb; }

/// Consume libcurl's verbose records without emitting per-input diagnostics.
/// TELNET's debug build keeps its negotiation/suboption formatters behind the
/// verbose switch, so the protocol lane uses this sink to make that reachable
/// code fuzzable without turning millions of iterations into log traffic.
int SilentDebugCallback(CURL* /*handle*/, curl_infotype /*type*/, char* /*data*/, size_t /*size*/, void* /*userdata*/) {
  return 0;
}

/// Let curl's debug build accept transport-security response headers over the
/// plaintext HTTP mock. The structured secure lane currently covers TLS setup
/// and failure handling, not a successful TLS peer, so this curl-provided test
/// hook is what lets the high-throughput HTTP lane reach the HSTS and Alt-Svc
/// parsers today.
void EnableDebugHttpTransportMetadata() {
  static const bool configured = [] {
    // CMake builds the fuzzing copy of curl with ENABLE_DEBUG specifically so
    // these curl-provided test hooks are available. Do not overwrite values a
    // reproducer deliberately supplied in its environment.
    (void)setenv(kAltSvcHttpEnvVar, "1", 0);
    (void)setenv(kHstsHttpEnvVar, "1", 0);
    return true;
  }();
  (void)configured;
}

/// Decode protobuf's two integral oneof members according to the semantic
/// kind in the generated option descriptor. The schema cannot couple an
/// option id to one particular oneof member, so both retained corpus entries
/// and ordinary mutations can represent a flag as uint_value or a numeric
/// mode as bool_value. Preserving magnitude for numeric options and reducing
/// flags to truthiness keeps either representation useful without embedding
/// option-specific history in the runtime. String or unset members map to the
/// same zero default protobuf's inactive scalar accessors historically gave.
std::uint64_t DecodeIntegralValue(const OptionDescriptor& descriptor, const curl::fuzzer::proto::SetOption& option) {
  if (descriptor.kind == OptionValueKind::kString) {
    return 0;
  }
  switch (option.value_case()) {
    case curl::fuzzer::proto::SetOption::kBoolValue:
      return option.bool_value() ? 1U : 0U;
    case curl::fuzzer::proto::SetOption::kUintValue:
      if (descriptor.kind == OptionValueKind::kBool) {
        return option.uint_value() != 0 ? 1U : 0U;
      }
      return option.uint_value();
    case curl::fuzzer::proto::SetOption::kStringValue:
    case curl::fuzzer::proto::SetOption::VALUE_NOT_SET:
      return 0;
  }
  return 0;
}

}  // namespace

/// Decode a recognized integral option using its generated semantic kind.
/// Unknown and string-valued options have no integral interpretation and
/// therefore return zero.
std::uint64_t DecodeIntegralOptionValue(const curl::fuzzer::proto::SetOption& option) {
  const OptionDescriptor* descriptor = LookupOptionDescriptor(option.option_id());
  if (descriptor == nullptr || descriptor->kind == OptionValueKind::kString) {
    return 0;
  }
  return DecodeIntegralValue(*descriptor, option);
}

/// Make every supported option's expected oneof member explicit. Boolean and
/// integer representations retain their scalar meaning when crossing between
/// those families; string or unset mismatches become the destination family's
/// zero value. This focuses later mutations on a value ApplySetOption consumes
/// without requiring option-specific compatibility rules.
void CanonicalizeOptionValueCases(curl::fuzzer::proto::Scenario* scenario) {
  if (scenario == nullptr) {
    return;
  }
  for (auto& option : *scenario->mutable_options()) {
    const OptionDescriptor* desc = LookupOptionDescriptor(option.option_id());
    if (desc == nullptr) {
      continue;
    }

    switch (desc->kind) {
      case OptionValueKind::kString:
        if (option.value_case() != curl::fuzzer::proto::SetOption::kStringValue) {
          option.set_string_value("");
        }
        break;
      case OptionValueKind::kUint:
        if (option.value_case() != curl::fuzzer::proto::SetOption::kUintValue) {
          option.set_uint_value(DecodeIntegralValue(*desc, option));
        }
        break;
      case OptionValueKind::kBool:
        if (option.value_case() != curl::fuzzer::proto::SetOption::kBoolValue) {
          option.set_bool_value(DecodeIntegralValue(*desc, option) != 0);
        }
        break;
    }
  }
}

/// Apply the fixed baseline options the harness always wants: output sinks,
/// protocol restrictions, DNS overrides, timeouts. Call before applying any
/// scenario options.
/// @param easy The curl easy handle to configure.
/// @param scheme Protocol whose dedicated in-process mock will service it.
/// @return the curl_slist owned by the caller (for CURLOPT_CONNECT_TO), which
///         must be freed with curl_slist_free_all after curl_easy_cleanup.
struct curl_slist* ApplyBaselineOptions(CURL* easy, curl::fuzzer::proto::Scheme scheme) {
  EnableDebugHttpTransportMetadata();

  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &SilentWriteCallback);
  curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, &SilentWriteCallback);

  const bool user_requested_verbose = std::getenv(kVerboseEnvVar) != nullptr;
  if (scheme == curl::fuzzer::proto::SCHEME_TELNET && !user_requested_verbose) {
    // printoption() and printsub() contain a substantial part of curl's TELNET
    // parser diagnostics but run only in verbose mode. Keep those paths in the
    // ordinary TELNET coverage lane while suppressing their high-volume text.
    // An explicit FUZZ_VERBOSE still skips the sink so reproductions remain
    // inspectable from the terminal.
    curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, &SilentDebugCallback);
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  }

  // A TELNET transfer must use TelnetMockServer's preload/drain invariants.
  // Keep it out of the redirect allowlist so an HTTP mock can never redirect
  // into curl's synchronous TELNET driver with event-driven peer semantics.
  // CURLOPT_PROTOCOLS_STR arrived in 7.85.0.
  const char* direct_protocols =
      scheme == curl::fuzzer::proto::SCHEME_TELNET ? kTelnetProtocolAllowed : kEventDrivenProtocolsAllowed;
  curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, direct_protocols);
  curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, kEventDrivenProtocolsAllowed);

  // CONNECT_TO confines direct connections, but an ambient http_proxy or
  // ALL_PROXY can select a proxy before curl asks the harness for a socket.
  // An explicit empty proxy keeps every transfer inside the socketpair and
  // makes replay independent of the machine running the fuzzer.
  curl_easy_setopt(easy, CURLOPT_PROXY, "");

  // Keep ordinary secure-scheme mutations independent of host trust-store
  // state, matching the legacy harness. An explicit scenario option is applied
  // later and can restore verification to exercise that deliberate path.
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);

  // Force every name lookup to the fuzzer's in-process mock peer. The caller
  // owns the returned slist and must free it after curl_easy_cleanup.
  struct curl_slist* connect_to = curl_slist_append(nullptr, kConnectToOverride);
  curl_easy_setopt(easy, CURLOPT_CONNECT_TO, connect_to);

  // Short bounds: fuzzing should never sit waiting on real I/O. Response
  // volume is already bounded by libFuzzer's input-size limit, so do not rate
  // limit receive traffic here: a global bytes-per-second throttle turns every
  // otherwise-complete large response into wall-clock sleep.
  curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, kConnectTimeoutMs);
  curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, kTimeoutMs);

  // Keep every persistence/read path deterministic and prevent scenarios from
  // leaking state onto the filesystem. COOKIEFILE also makes the in-memory
  // engine's RELOAD command traverse its loader against a harmless empty
  // source. These path options deliberately remain absent from the generated
  // mutation manifest, so a proto cannot replace /dev/null.
  curl_easy_setopt(easy, CURLOPT_COOKIEJAR, kDevNull);
  curl_easy_setopt(easy, CURLOPT_COOKIEFILE, kDevNull);
  curl_easy_setopt(easy, CURLOPT_ALTSVC, kDevNull);
  curl_easy_setopt(easy, CURLOPT_HSTS, kDevNull);
  curl_easy_setopt(easy, CURLOPT_NETRC_FILE, kDevNull);
  // Do not set CRLFILE merely to mirror the legacy harness. An empty CRL is
  // not a harmless sink: when a scenario restores certificate verification,
  // OpenSSL rejects /dev/null before it can exercise useful handshake and
  // verification paths. The option is absent from the mutation manifest, so
  // leaving it unset introduces neither filesystem writes nor external input.

  // Match the legacy TLV fuzzer: FUZZ_VERBOSE in the environment flips curl's
  // own verbose logging on. Useful when reproducing a crashing corpus entry.
  if (user_requested_verbose) {
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  }
  return connect_to;
}

/// Apply one SetOption to the easy handle. The Scenario passed to the runner
/// owns every SetOption for the whole transfer, so pointer-valued options can
/// borrow string_value directly instead of allocating a duplicate backing
/// store on every iteration. This lifetime is especially important for
/// CURLOPT_POSTFIELDS, which curl deliberately does not copy.
/// @param easy   The curl easy handle to configure.
/// @param option The SetOption proto describing which option and value to set;
///               its containing Scenario must remain stable through cleanup.
/// @return CURLE_OK on success, an error code if the option is unsupported or
///         the setopt call itself failed.
CURLcode ApplySetOption(CURL* easy, const curl::fuzzer::proto::SetOption& option) {
  const OptionDescriptor* desc = LookupOptionDescriptor(option.option_id());
  if (desc == nullptr) {
    return CURLE_UNKNOWN_OPTION;
  }

  switch (desc->kind) {
    case OptionValueKind::kString: {
      const std::string& value = option.string_value();

      // POSTFIELDS borrows its pointer and accepts embedded NULs only when its
      // size is explicit. Apply the size first so curl never observes the
      // protobuf bytes with strlen semantics, even transiently.
      if (desc->curlopt == CURLOPT_POSTFIELDS) {
        CURLcode result = curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(value.size()));
        if (result != CURLE_OK) {
          return result;
        }
      }

      return curl_easy_setopt(easy, desc->curlopt, value.c_str());
    }

    // Decode the uint_value and pass it as either a long or a curl_off_t depending on the option.
    case OptionValueKind::kUint: {
      const std::uint64_t raw = DecodeIntegralValue(*desc, option);
      // CURLOPTTYPE_OFF_T options start at 30000. Everything below takes a
      // long; everything at/above takes a curl_off_t.
      if (static_cast<int>(desc->curlopt) >= 30000) {
        return curl_easy_setopt(easy, desc->curlopt, static_cast<curl_off_t>(raw));
      }
      return curl_easy_setopt(easy, desc->curlopt, static_cast<long>(raw));
    }

    // Decode the bool_value and pass it as a long flag (0 or 1).
    case OptionValueKind::kBool: {
      const long flag = static_cast<long>(DecodeIntegralValue(*desc, option));
      return curl_easy_setopt(easy, desc->curlopt, flag);
    }
  }
  return CURLE_UNKNOWN_OPTION;
}

/// Keep compatibility inputs immutable while enforcing the same observable
/// option prefix as postprocessed fixed lanes.
std::size_t RuntimeOptionCount(const curl::fuzzer::proto::Scenario& scenario) {
  return std::min<std::size_t>(static_cast<std::size_t>(scenario.options_size()), scenario_limits::kMaxOptions);
}

/// Apply only the prefix curl can observe in every target lane. Bounding here,
/// rather than relying solely on LPM's postprocessor, is important because
/// standalone compatibility seeds reach ScenarioRunner without normalization.
std::size_t ApplyScenarioOptions(CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  const std::size_t option_count = RuntimeOptionCount(scenario);
  for (std::size_t index = 0; index < option_count; ++index) {
    (void)ApplySetOption(easy, scenario.options(static_cast<int>(index)));
  }
  return option_count;
}

}  // namespace proto_fuzzer
