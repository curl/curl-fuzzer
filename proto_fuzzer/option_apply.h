/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Translates Scenario SetOption messages into curl_easy_setopt calls,
///        plus the fixed baseline setopts the harness always applies.

#ifndef PROTO_FUZZER_OPTION_APPLY_H_
#define PROTO_FUZZER_OPTION_APPLY_H_

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

/// Decode a recognized boolean or integer option according to the generated
/// descriptor. Integer options preserve uint values and map bools to 0/1;
/// boolean options normalize either representation to 0/1. Unknown, string,
/// unset, or otherwise non-integral values return zero.
/// @param option Structured option whose descriptor and value will be read.
/// @return Descriptor-aware integral value suitable for runtime decisions.
std::uint64_t DecodeIntegralOptionValue(const curl::fuzzer::proto::SetOption& option);

/// Restore each recognized SetOption's oneof to the value family its native
/// CURLOPT expects. Boolean and integer arms are converted without losing
/// their scalar meaning; incompatible arms become that family's default.
/// Making the consumed member explicit lets later LPM mutations edit useful
/// bytes instead of repeatedly changing fields ApplySetOption cannot observe.
/// Unrecognized option ids are retained so mutation can still turn them into
/// supported ids.
/// @param scenario Structured input to canonicalize in place.
void CanonicalizeOptionValueCases(curl::fuzzer::proto::Scenario* scenario);

/// Apply deterministic routing, timeout, output, and persistence defaults.
/// Returns a caller-owned CONNECT_TO list that must outlive the easy handle.
/// `scheme` identifies the dedicated in-process mock that will service the
/// transfer and therefore selects the safe direct-protocol allowlist.
struct curl_slist* ApplyBaselineOptions(CURL* easy, curl::fuzzer::proto::Scheme scheme);

/// Translate and apply one generated scalar/string option. String pointers
/// borrow the SetOption's protobuf-owned storage, so the containing Scenario
/// must remain alive and unmodified until the transfer has stopped and the
/// easy handle has been cleaned up.
/// Returns curl's setopt result, or CURLE_UNKNOWN_OPTION for an unknown id.
CURLcode ApplySetOption(CURL* easy, const curl::fuzzer::proto::SetOption& option);

/// Return the runtime-visible option prefix length. Fixed targets normally
/// trim the protobuf in their postprocessor, but the compatibility target must
/// preserve its historical message unchanged; applying the same bound here
/// prevents that lane from doing mutation-sized setopt work.
/// @param scenario Structured input whose option prefix will be consumed.
/// @return Number of options visible to the runtime.
std::size_t RuntimeOptionCount(const curl::fuzzer::proto::Scenario& scenario);

/// Apply the bounded runtime-visible prefix of Scenario.options. Individual
/// CURLcode values remain intentionally ignored, matching the fuzzer runner's
/// historical behavior.
/// @param easy Easy handle receiving each supported option.
/// @param scenario Structured input that owns all borrowed option strings.
/// @return Number of option entries attempted.
std::size_t ApplyScenarioOptions(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_OPTION_APPLY_H_
