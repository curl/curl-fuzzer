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

namespace {

constexpr char kEventDrivenProtocolsAllowed[] = "http,https,ws,wss";
constexpr char kTelnetProtocolAllowed[] = "telnet";
constexpr char kFtpProtocolAllowed[] = "ftp";
constexpr char kTftpProtocolAllowed[] = "tftp";
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
/// plaintext HTTP mock. The HTTPS lane now provides a verified peer, but making
/// HSTS and Alt-Svc parser coverage depend on a cryptographic handshake would
/// needlessly remove those parsers from the high-throughput HTTP lane.
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

void EnableTraceIds() {
  static const bool enabled = curl_global_trace("+LIB-IDS") == CURLE_OK;
  (void)enabled;
}

}  // namespace

/// Apply deterministic routing, timeout, output, and persistence defaults.
/// Call before applying scenario options. `scheme` identifies the dedicated
/// in-process mock that will service the transfer and selects the safe direct-
/// protocol allowlist.
/// @param easy The curl easy handle to configure.
/// @param scheme Protocol whose dedicated in-process mock will service it.
/// @param trace_ids Enable verbose LIB-IDS tracing for this scenario.
/// @return Caller-owned CURLOPT_CONNECT_TO list, which must outlive the easy
///         handle and be freed with curl_slist_free_all after curl_easy_cleanup.
struct curl_slist* ApplyBaselineOptions(CURL* easy, curl::fuzzer::proto::Scheme scheme, bool trace_ids) {
  EnableDebugHttpTransportMetadata();

  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, &SilentWriteCallback);
  curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, &SilentWriteCallback);

  const bool user_requested_verbose = std::getenv(kVerboseEnvVar) != nullptr;
  if (trace_ids) {
    EnableTraceIds();
    // Keep trace-ID coverage enabled during fuzzing without flooding the
    // process log. The callback still executes curl_trc.c's formatting path.
    curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, &SilentDebugCallback);
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  } else if (scheme == curl::fuzzer::proto::SCHEME_TELNET && !user_requested_verbose) {
    // printoption() and printsub() contain a substantial part of curl's TELNET
    // parser diagnostics but run only in verbose mode. Keep those paths in the
    // ordinary TELNET coverage lane while suppressing their high-volume text.
    // An explicit FUZZ_VERBOSE still skips the sink so reproductions remain
    // inspectable from the terminal.
    curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, &SilentDebugCallback);
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  }

  // Each non-HTTP protocol must use its dedicated peer invariants. Keep them
  // out of the redirect allowlist so an HTTP response cannot switch a stream
  // mock into synchronous TELNET, two-channel FTP, or datagram TFTP semantics.
  // CURLOPT_PROTOCOLS_STR arrived in 7.85.0.
  const char* direct_protocols = kEventDrivenProtocolsAllowed;
  switch (scheme) {
    case curl::fuzzer::proto::SCHEME_TELNET:
      direct_protocols = kTelnetProtocolAllowed;
      break;
    case curl::fuzzer::proto::SCHEME_FTP:
      direct_protocols = kFtpProtocolAllowed;
      break;
    case curl::fuzzer::proto::SCHEME_TFTP:
      direct_protocols = kTftpProtocolAllowed;
      break;
    case curl::fuzzer::proto::SCHEME_GOPHER:
      direct_protocols = "gopher";
      break;
    case curl::fuzzer::proto::SCHEME_GOPHERS:
      direct_protocols = "gophers";
      break;
    case curl::fuzzer::proto::SCHEME_HTTP:
    case curl::fuzzer::proto::SCHEME_HTTPS:
    case curl::fuzzer::proto::SCHEME_WS:
    case curl::fuzzer::proto::SCHEME_WSS:
    case curl::fuzzer::proto::SCHEME_UNSPECIFIED:
    default:
      break;
  }
  curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, direct_protocols);
  curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, kEventDrivenProtocolsAllowed);

  // CONNECT_TO confines direct connections, but an ambient http_proxy or
  // ALL_PROXY can select a proxy before curl asks the harness for a socket.
  // An explicit empty proxy keeps every transfer inside the socketpair and
  // makes replay independent of the machine running the fuzzer.
  curl_easy_setopt(easy, CURLOPT_PROXY, "");

  // Keep raw secure-scheme inputs independent of the host trust store,
  // matching the legacy harness. The dedicated TLS mock installs its own
  // in-memory trust anchor after this baseline; scenario options still run
  // last and can deliberately select verification failures.
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

/// Translate and apply one generated scalar/string SetOption to the easy handle.
/// Pointer-valued options borrow the SetOption's protobuf-owned string storage,
/// so its containing Scenario must remain alive and unmodified until the
/// transfer has stopped and the easy handle has been cleaned up. Borrowing
/// avoids a duplicate backing allocation on every iteration; the lifetime is
/// especially important for CURLOPT_POSTFIELDS, which curl does not copy.
/// @param easy The curl easy handle to configure.
/// @param option The SetOption proto describing which option and value to set.
/// @return curl's setopt result, or CURLE_UNKNOWN_OPTION for an unknown id.
CURLcode ApplySetOption(CURL* easy, const curl::fuzzer::proto::SetOption& option) {
  const OptionDescriptor* desc = LookupOptionDescriptor(option.option_id());
  if (desc == nullptr) {
    return CURLE_UNKNOWN_OPTION;
  }
  const CURLoption curlopt = static_cast<CURLoption>(desc->curlopt);

  switch (desc->kind) {
    case OptionValueKind::kString: {
      const std::string& value = option.string_value();

      // POSTFIELDS borrows its pointer and COPYPOSTFIELDS copies exactly the
      // previously configured size. Apply the correlated byte length first so
      // either option accepts embedded NULs without strlen semantics and the
      // copying variant can never read beyond the protobuf-owned buffer.
      if (desc->curlopt == CURLOPT_POSTFIELDS || desc->curlopt == CURLOPT_COPYPOSTFIELDS) {
        CURLcode result = curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(value.size()));
        if (result != CURLE_OK) {
          return result;
        }
      }

      // Curl otherwise treats this option as a filename during the TLS
      // handshake. Fixed-policy inputs normally arrive pre-constrained by the
      // postprocessor; this runtime check also protects compatibility inputs,
      // which intentionally bypass it. Curl copies this option in setopt, so
      // the temporary remains valid for the call's full ownership contract.
      if (desc->curlopt == CURLOPT_PINNEDPUBLICKEY && !UsesInMemoryPublicKeyPin(value)) {
        std::string constrained = value;
        ConstrainPinnedPublicKeyValue(&constrained);
        return curl_easy_setopt(easy, curlopt, constrained.c_str());
      }

      return curl_easy_setopt(easy, curlopt, value.c_str());
    }

    // Decode the uint_value and pass it as either a long or a curl_off_t depending on the option.
    case OptionValueKind::kUint: {
      const std::uint64_t raw = DecodeIntegralOptionValue(*desc, option);
      // CURLOPTTYPE_OFF_T options start at 30000. Everything below takes a
      // long; everything at/above takes a curl_off_t.
      if (static_cast<int>(desc->curlopt) >= 30000) {
        return curl_easy_setopt(easy, curlopt, static_cast<curl_off_t>(raw));
      }
      return curl_easy_setopt(easy, curlopt, static_cast<long>(raw));
    }

    // Decode the bool_value and pass it as a long flag (0 or 1).
    case OptionValueKind::kBool: {
      const long flag = static_cast<long>(DecodeIntegralOptionValue(*desc, option));
      return curl_easy_setopt(easy, curlopt, flag);
    }
  }
  return CURLE_UNKNOWN_OPTION;
}

/// Return the runtime-visible option prefix length. Fixed targets normally
/// trim the protobuf in their postprocessor, but the compatibility target must
/// preserve its historical message unchanged; applying the same bound here
/// prevents that lane from doing mutation-sized setopt work while exposing the
/// same option prefix as postprocessed fixed lanes.
/// @param scenario Structured input whose option prefix will be consumed.
/// @return Number of options visible to the runtime.
std::size_t RuntimeOptionCount(const curl::fuzzer::proto::Scenario& scenario) {
  return std::min<std::size_t>(static_cast<std::size_t>(scenario.options_size()), scenario_limits::kMaxOptions);
}

/// Apply the bounded runtime-visible prefix of Scenario.options. Individual
/// CURLcode values remain intentionally ignored, matching the fuzzer runner's
/// historical behavior. Bounding here also covers standalone compatibility
/// seeds that reach RunScenario without normalization.
/// @param easy Easy handle receiving each supported option.
/// @param scenario Structured input that owns all borrowed option strings.
/// @return Number of option entries attempted.
std::size_t ApplyScenarioOptions(CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  const std::size_t option_count = RuntimeOptionCount(scenario);
  for (std::size_t index = 0; index < option_count; ++index) {
    (void)ApplySetOption(easy, scenario.options(static_cast<int>(index)));
  }
  return option_count;
}

}  // namespace proto_fuzzer
