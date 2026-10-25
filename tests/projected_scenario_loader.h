/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef CURL_FUZZER_TESTS_PROJECTED_SCENARIO_LOADER_H_
#define CURL_FUZZER_TESTS_PROJECTED_SCENARIO_LOADER_H_

#include <string>

#include <google/protobuf/text_format.h>

#include "generated/compatibility/compatibility_traits.h"

namespace test_support {

/// Strictly parse an authoring-schema textproto, project its wire form into a
/// generated target root, and lower that root to the internal runtime schema.
/// This mirrors the ordinary protoc --encode plus target-projection path used
/// for checked-in corpus inputs.
template <typename Traits>
bool ParseAndLowerProjectedScenario(
    const std::string &text, ::curl::fuzzer::proto::Scenario *destination) {
  proto_fuzzer::generated::CompatibilityTraits::Message authoring;
  if (!google::protobuf::TextFormat::ParseFromString(text, &authoring)) {
    return false;
  }

  typename Traits::Message projected;
  if (!projected.ParseFromString(authoring.SerializeAsString())) {
    return false;
  }
  projected.DiscardUnknownFields();
  Traits::Lower(&projected, destination);
  return true;
}

} // namespace test_support

#endif // CURL_FUZZER_TESTS_PROJECTED_SCENARIO_LOADER_H_
