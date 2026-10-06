/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Generated option semantics without curl execution or handle state.

#include "proto_fuzzer/option_model.h"

#include <curl/curl.h>

namespace proto_fuzzer {

namespace {

// Only the generated constants require curl headers. This translation unit
// makes no libcurl calls and can be linked into normalization-only tests.
namespace generated {
#include "curl_fuzzer_option_manifest.inc"
}  // namespace generated

}  // namespace

/// Decode using an already-resolved descriptor, avoiding another lookup when
/// the runtime has selected the option's application path.
/// @param descriptor Generated description of the option being decoded.
/// @param option Structured option supplying the integral value.
/// @return Integral value interpreted according to the descriptor's family.
std::uint64_t DecodeIntegralOptionValue(const OptionDescriptor& descriptor,
                                        const curl::fuzzer::proto::SetOption& option) {
  if (descriptor.kind == OptionValueKind::kString) {
    return 0;
  }
  switch (option.value_case()) {
    case curl::fuzzer::proto::SetOption::kBoolValue:
      return option.bool_value() ? 1U : 0U;
    case curl::fuzzer::proto::SetOption::kUintValue:
      return descriptor.kind == OptionValueKind::kBool ? (option.uint_value() != 0 ? 1U : 0U) : option.uint_value();
    case curl::fuzzer::proto::SetOption::kStringValue:
    case curl::fuzzer::proto::SetOption::VALUE_NOT_SET:
      return 0;
  }
  return 0;
}

/// Return the generated description, or nullptr for an unsupported option.
/// @param id Protobuf option identifier to look up.
/// @return Immutable generated descriptor, or nullptr when unsupported.
const OptionDescriptor* LookupOptionDescriptor(curl::fuzzer::proto::CurlOptionId id) {
  return generated::LookupOptionDescriptor(id);
}

/// Whether curl will interpret this pin as an in-memory digest expression.
/// @param value Public-key pin expression to inspect.
/// @return True when the value begins with curl's in-memory digest prefix.
bool UsesInMemoryPublicKeyPin(const std::string& value) { return value.rfind("sha256//", 0) == 0; }

/// Prefix filename-like pins with in-memory digest syntax. This helper does
/// not trim bytes; fixed-target normalization applies its final budget after
/// canonicalization, while compatibility execution preserves its input size.
/// @param value Pin expression to constrain in place; nullptr is harmless.
void ConstrainPinnedPublicKeyValue(std::string* value) {
  if (value != nullptr && !UsesInMemoryPublicKeyPin(*value)) {
    value->insert(0, "sha256//");
  }
}

/// Decode a recognized integral option. Numeric options preserve magnitude;
/// boolean options use truthiness. Incompatible or unknown values yield zero.
/// @param option Structured option whose descriptor and value will be read.
/// @return Descriptor-aware integral value, or zero for incompatible values.
std::uint64_t DecodeIntegralOptionValue(const curl::fuzzer::proto::SetOption& option) {
  const OptionDescriptor* descriptor = LookupOptionDescriptor(option.option_id());
  return descriptor == nullptr ? 0 : DecodeIntegralOptionValue(*descriptor, option);
}

/// Restore each recognized option's consumed oneof member without calling
/// libcurl. Public-key pins are constrained to curl's in-memory digest syntax.
/// Unknown ids remain available for later mutation into a supported option.
/// @param scenario Scenario to canonicalize in place; nullptr is harmless.
void CanonicalizeOptionValueCases(curl::fuzzer::proto::Scenario* scenario) {
  if (scenario == nullptr) {
    return;
  }
  for (auto& option : *scenario->mutable_options()) {
    const OptionDescriptor* descriptor = LookupOptionDescriptor(option.option_id());
    if (descriptor == nullptr) {
      continue;
    }
    switch (descriptor->kind) {
      case OptionValueKind::kString:
        if (option.value_case() != curl::fuzzer::proto::SetOption::kStringValue) {
          option.set_string_value("");
        }
        if (descriptor->id == curl::fuzzer::proto::CURLOPT_PINNEDPUBLICKEY) {
          ConstrainPinnedPublicKeyValue(option.mutable_string_value());
        }
        break;
      case OptionValueKind::kUint:
        if (option.value_case() != curl::fuzzer::proto::SetOption::kUintValue) {
          option.set_uint_value(DecodeIntegralOptionValue(*descriptor, option));
        }
        break;
      case OptionValueKind::kBool:
        if (option.value_case() != curl::fuzzer::proto::SetOption::kBoolValue) {
          option.set_bool_value(DecodeIntegralOptionValue(*descriptor, option) != 0);
        }
        break;
    }
  }
}

}  // namespace proto_fuzzer
