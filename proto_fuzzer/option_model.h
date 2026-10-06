/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Pure interpretation and normalization of structured curl options.

#ifndef PROTO_FUZZER_OPTION_MODEL_H_
#define PROTO_FUZZER_OPTION_MODEL_H_

#include <cstdint>
#include <string>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

/// Value family selected by the build-time-generated option manifest.
enum class OptionValueKind {
  kString,  ///< string_value passed to a string or byte-data option.
  kUint,    ///< uint_value passed to a long or curl_off_t option.
  kBool     ///< bool_value passed as a zero-or-one long flag.
};

/// A generated option description. The native option is stored as its integer
/// identifier so interpreting protobuf values does not require a curl handle.
struct OptionDescriptor {
  /// Stable protobuf identifier for this option.
  curl::fuzzer::proto::CurlOptionId id;
  /// Value family consumed by the native option.
  OptionValueKind kind;
  /// Human-readable CURLOPT name from the generated manifest.
  const char* name;
  /// Native CURLoption value, stored without exposing curl handle types.
  int curlopt;
};

const OptionDescriptor* LookupOptionDescriptor(curl::fuzzer::proto::CurlOptionId id);

std::uint64_t DecodeIntegralOptionValue(const curl::fuzzer::proto::SetOption& option);

std::uint64_t DecodeIntegralOptionValue(const OptionDescriptor& descriptor,
                                        const curl::fuzzer::proto::SetOption& option);

void CanonicalizeOptionValueCases(curl::fuzzer::proto::Scenario* scenario);

bool UsesInMemoryPublicKeyPin(const std::string& value);

void ConstrainPinnedPublicKeyValue(std::string* value);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_OPTION_MODEL_H_
