/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/profile_fuzzer.h"

#include "test_assertions.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace {

using curl::fuzzer::proto::Scenario;
using proto_fuzzer::BindProfileFuzzer;
using proto_fuzzer::ProfileFuzzerHooks;
using proto_fuzzer::TargetProfile;
using test_support::Expect;

/// Exercise the bridge used by live generated profile roots without coupling
/// this unit test to one generated schema. Swap is valid because both sides
/// deliberately use the generic runtime type; generated traits instead move
/// matching fields between their restricted root and that runtime type.
struct IdentityFtpTraits {
  using Message = Scenario;
  static constexpr TargetProfile kProfile = TargetProfile::kFastFtp;
  static inline int prune_calls = 0;
  static inline bool saw_fixed_scheme = false;

  static void Lower(Message *source, Scenario *destination) {
    destination->Swap(source);
  }
  static void Lift(Scenario *source, Message *destination) {
    destination->Swap(source);
  }
  static void PruneConditionalEligibility(Scenario *scenario,
                                          TargetProfile profile) {
    ++prune_calls;
    saw_fixed_scheme = profile == TargetProfile::kFastFtp &&
                       scenario->scheme() == curl::fuzzer::proto::SCHEME_FTP;
  }
};

using Hooks = ProfileFuzzerHooks<IdentityFtpTraits>;
constexpr auto kFtpProfile = BindProfileFuzzer<IdentityFtpTraits>();

struct IdentityTimingTraits : IdentityFtpTraits {
  static constexpr TargetProfile kProfile = TargetProfile::kTiming;
  static inline int lift_calls = 0;

  static void Lift(Scenario *source, Message *destination) {
    ++lift_calls;
    IdentityFtpTraits::Lift(source, destination);
  }
};

constexpr auto kTimingProfile = BindProfileFuzzer<IdentityTimingTraits>();
static_assert(kFtpProfile.profile == TargetProfile::kFastFtp);
static_assert(kFtpProfile.custom_mutator != nullptr);
static_assert(kFtpProfile.custom_crossover != nullptr);
static_assert(kFtpProfile.load_input != nullptr);
static_assert(kFtpProfile.probe_mutation_helpers == nullptr);
static_assert(kTimingProfile.probe_mutation_helpers != nullptr);

/// Stand in for a generated restricted root which has no scheme field. Its
/// postprocessor can lift the normalized connection back, but cannot encode
/// the fixed FTP scheme for a later load.
struct ConnectionOnlyFtpTraits {
  using Message = curl::fuzzer::proto::Connection;
  static constexpr TargetProfile kProfile = TargetProfile::kFastFtp;

  static void Lower(Message *source, Scenario *destination) {
    destination->mutable_connection()->Swap(source);
  }
  static void Lift(Scenario *source, Message *destination) {
    destination->Swap(source->mutable_connection());
  }
  static void PruneConditionalEligibility(Scenario *, TargetProfile) {}
};

using ConnectionOnlyHooks = ProfileFuzzerHooks<ConnectionOnlyFtpTraits>;

Scenario MakeScenario() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("profile.test/file");

  auto *empty = scenario.add_options();
  empty->set_option_id(curl::fuzzer::proto::CURLOPT_USERNAME);
  empty->set_string_value("");

  auto *false_value = scenario.add_options();
  false_value->set_option_id(curl::fuzzer::proto::CURLOPT_NOBODY);
  false_value->set_bool_value(false);

  auto *zero = scenario.add_options();
  zero->set_option_id(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  zero->set_uint_value(0);

  auto *duplicate = scenario.add_options();
  duplicate->set_option_id(curl::fuzzer::proto::CURLOPT_USERNAME);
  duplicate->set_string_value("second");
  return scenario;
}

void AppendUnknownVarint(std::string *wire) {
  // Field 127, wire type 0, value 1. This field is outside Scenario's schema.
  wire->append("\xf8\x07\x01", 3);
}

void ExpectOrderedValues(const Scenario &scenario) {
  Expect(scenario.options_size() == 4,
         "profile adapter changed the option count");
  Expect(scenario.options(0).option_id() ==
                 curl::fuzzer::proto::CURLOPT_USERNAME &&
             scenario.options(0).value_case() ==
                 curl::fuzzer::proto::SetOption::kStringValue &&
             scenario.options(0).string_value().empty(),
         "profile adapter lost an explicitly empty value");
  Expect(scenario.options(1).option_id() ==
                 curl::fuzzer::proto::CURLOPT_NOBODY &&
             scenario.options(1).value_case() ==
                 curl::fuzzer::proto::SetOption::kBoolValue &&
             !scenario.options(1).bool_value(),
         "profile adapter lost an explicit false value");
  Expect(scenario.options(2).option_id() ==
                 curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE &&
             scenario.options(2).value_case() ==
                 curl::fuzzer::proto::SetOption::kUintValue &&
             scenario.options(2).uint_value() == 0,
         "profile adapter lost an explicit zero value");
  Expect(scenario.options(3).option_id() ==
                 curl::fuzzer::proto::CURLOPT_USERNAME &&
             scenario.options(3).string_value() == "second",
         "profile adapter reordered duplicate options");
}

void TestDirectNormalization() {
  IdentityFtpTraits::prune_calls = 0;
  IdentityFtpTraits::saw_fixed_scheme = false;
  std::string wire = MakeScenario().SerializeAsString();
  AppendUnknownVarint(&wire);

  Scenario scenario;
  Expect(scenario.ParseFromString(wire),
         "failed to parse unknown-field fixture");
  Expect(scenario.GetReflection()->GetUnknownFields(scenario).field_count() ==
             1,
         "unknown-field fixture did not contain its sentinel");

  Hooks::NormalizeMessage(&scenario);

  Expect(scenario.scheme() == curl::fuzzer::proto::SCHEME_FTP,
         "profile adapter skipped fixed-target normalization");
  Expect(scenario.GetReflection()->GetUnknownFields(scenario).empty(),
         "profile adapter retained unknown wire data");
  Expect(IdentityFtpTraits::prune_calls == 1 &&
             IdentityFtpTraits::saw_fixed_scheme,
         "profile adapter did not prune after selector normalization");
  ExpectOrderedValues(scenario);
}

void TestLoadRestoresPolicyOwnedFieldsOmittedByRoot() {
  curl::fuzzer::proto::Connection restricted;
  restricted.set_initial_response("220 ready\r\n");
  const std::string wire = restricted.SerializeAsString();

  Scenario runtime;
  Expect(ConnectionOnlyHooks::LoadAndLower(
             reinterpret_cast<const std::uint8_t *>(wire.data()), wire.size(),
             &runtime),
         "restricted profile root did not load");
  Expect(runtime.scheme() == curl::fuzzer::proto::SCHEME_FTP,
         "final lowering did not restore the policy-owned FTP scheme");
  Expect(runtime.connection().initial_response() == "220 ready\r\n",
         "restricted profile root lost its represented connection data");
}

std::size_t SerializeInto(const Scenario &scenario,
                          std::array<std::uint8_t, 4096> *storage) {
  const std::size_t size = scenario.ByteSizeLong();
  Expect(size <= storage->size(), "profile test fixture exceeded its buffer");
  Expect(scenario.SerializeToArray(storage->data(), static_cast<int>(size)),
         "failed to serialize profile test fixture");
  return size;
}

void TestMutationCacheAndLoad() {
  std::array<std::uint8_t, 4096> storage = {};
  const std::size_t original_size = SerializeInto(MakeScenario(), &storage);
  const std::size_t mutated_size = kFtpProfile.custom_mutator(
      storage.data(), original_size, storage.size(), 0x465450U);
  Expect(mutated_size > 0 && mutated_size <= storage.size(),
         "profile mutation did not produce bounded output");

  // This load consumes LPM's last-mutation cache. A different Message type
  // would make its reflection Swap unsafe before protobuf could parse bytes.
  Scenario runtime;
  Expect(kFtpProfile.load_input(storage.data(), mutated_size, &runtime),
         "cached profile mutation did not load");
  Expect(runtime.scheme() == curl::fuzzer::proto::SCHEME_FTP,
         "cached profile mutation was not normalized before lowering");

  std::array<std::uint8_t, 1> invalid = {0x80};
  Expect(!kFtpProfile.load_input(invalid.data(), invalid.size(), &runtime),
         "invalid protobuf unexpectedly loaded");
  Expect(!kFtpProfile.load_input(storage.data(), mutated_size, nullptr),
         "null runtime destination was accepted");
}

void TestCrossOverCacheAndLoad() {
  Scenario second = MakeScenario();
  second.set_host_path("profile.test/other");
  second.mutable_options(3)->set_string_value("other duplicate");

  std::array<std::uint8_t, 4096> first_bytes = {};
  std::array<std::uint8_t, 4096> second_bytes = {};
  std::array<std::uint8_t, 4096> child = {};
  const std::size_t first_size = SerializeInto(MakeScenario(), &first_bytes);
  const std::size_t second_size = SerializeInto(second, &second_bytes);
  const std::size_t child_size = kFtpProfile.custom_crossover(
      first_bytes.data(), first_size, second_bytes.data(), second_size,
      child.data(), child.size(), 0x43524f53U);
  Expect(child_size > 0 && child_size <= child.size(),
         "profile crossover did not produce bounded output");

  Scenario runtime;
  Expect(kFtpProfile.load_input(child.data(), child_size, &runtime),
         "cached profile crossover did not load");
  Expect(runtime.scheme() == curl::fuzzer::proto::SCHEME_FTP,
         "cached profile crossover was not normalized before lowering");
}

void TestEmptyInputAndSizeFailure() {
  std::array<std::uint8_t, 1> empty = {};
  Scenario runtime;
  Expect(kFtpProfile.load_input(empty.data(), 0, &runtime),
         "empty protobuf input did not load");
  Expect(runtime.scheme() == curl::fuzzer::proto::SCHEME_FTP,
         "empty protobuf input did not pass through the profile policy");

  Expect(kFtpProfile.custom_mutator(empty.data(), 0, 0, 1) == 0,
         "zero-capacity mutation unexpectedly produced output");
}

void TestTimingMutationProbeRunsOnce() {
  IdentityTimingTraits::lift_calls = 0;
  kTimingProfile.probe_mutation_helpers();
  const int first_probe_lifts = IdentityTimingTraits::lift_calls;
  Expect(first_probe_lifts > 0,
         "timing profile descriptor did not exercise typed mutation helpers");
  kTimingProfile.probe_mutation_helpers();
  Expect(IdentityTimingTraits::lift_calls == first_probe_lifts,
         "timing profile descriptor repeated its process-once probe");
}

} // namespace

int main() {
  TestLoadRestoresPolicyOwnedFieldsOmittedByRoot();
  TestDirectNormalization();
  TestMutationCacheAndLoad();
  TestCrossOverCacheAndLoad();
  TestEmptyInputAndSizeFailure();
  TestTimingMutationProbeRunsOnce();
  return 0;
}
