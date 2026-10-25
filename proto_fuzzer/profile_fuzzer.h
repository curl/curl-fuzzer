/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Type-safe libprotobuf-mutator hooks for one generated target profile.

#ifndef PROTO_FUZZER_PROFILE_FUZZER_H_
#define PROTO_FUZZER_PROFILE_FUZZER_H_

#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include <cstddef>
#include <cstdint>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/target_policy.h"
#include "proto_fuzzer/target_profile.h"

namespace proto_fuzzer {

/// Bind all LPM operations for one process to one protobuf message type.
///
/// Traits must provide:
///
/// - `using Message` for the generated profile root;
/// - `static constexpr TargetProfile kProfile`;
/// - `Lower(Message*, curl::fuzzer::proto::Scenario*)`; and
/// - `Lift(curl::fuzzer::proto::Scenario*, Message*)`; and
/// - `PruneConditionalEligibility(curl::fuzzer::proto::Scenario*,
///   TargetProfile)`.
///
/// Lower and Lift transfer fields directly. They must not serialize, reparse,
/// reflection-swap unlike message types, or retain pointers into the source.
/// Keeping the same Message in mutation, crossover, and loading is required by
/// LPM's process-wide last-mutation cache.
template <typename Traits>
class ProfileFuzzerHooks {
 public:
  using Message = typename Traits::Message;
  using RuntimeScenario = curl::fuzzer::proto::Scenario;

  /// Register the profile postprocessor before the first LPM operation.
  static void EnsurePostProcessor() {
    static const protobuf_mutator::libfuzzer::PostProcessorRegistration<Message> registration(
        [](Message* message, unsigned int /*seed*/) { NormalizeMessage(message); });
    (void)registration;
  }

  /// Remove unknown wire data, normalize through the common runtime model,
  /// and lift back into the same generated profile type.
  static void NormalizeMessage(Message* message) {
    if (message == nullptr) {
      return;
    }

    message->DiscardUnknownFields();
    RuntimeScenario runtime;
    Traits::Lower(message, &runtime);
    if constexpr (Traits::kProfile != TargetProfile::kCompatibility) {
      NormalizeScenarioForTarget(&runtime, Traits::kProfile, &Traits::PruneConditionalEligibility);
    }
    message->Clear();
    Traits::Lift(&runtime, message);
  }

  /// Mutate a binary profile message and retain its exact type in LPM's cache.
  static std::size_t CustomMutator(std::uint8_t* data, std::size_t size, std::size_t max_size, unsigned int seed) {
    EnsurePostProcessor();
    Message message;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(true, data, size, max_size, seed, &message);
  }

  /// Cross two binary profile messages using the same type as mutation/load.
  static std::size_t CustomCrossOver(const std::uint8_t* data1, std::size_t size1, const std::uint8_t* data2,
                                     std::size_t size2, std::uint8_t* out, std::size_t max_out_size,
                                     unsigned int seed) {
    EnsurePostProcessor();
    Message message1;
    Message message2;
    return protobuf_mutator::libfuzzer::CustomProtoCrossOver(true, data1, size1, data2, size2, out, max_out_size, seed,
                                                             &message1, &message2);
  }

  /// Load one binary profile message and transfer it into owned runtime state.
  ///
  /// This deliberately uses LPM's ordinary input unchanged. On a cache hit,
  /// the cached Message is the same concrete type used above; on a parse path,
  /// LPM invokes the registered postprocessor before this direct lowering.
  static bool LoadAndLower(const std::uint8_t* data, std::size_t size, RuntimeScenario* runtime) {
    if (runtime == nullptr) {
      return false;
    }

    EnsurePostProcessor();
    Message message;
    if (!protobuf_mutator::libfuzzer::LoadProtoInput(true, data, size, &message)) {
      return false;
    }

    // Mutated inputs have already passed the postprocessor before entering
    // LPM's cache. Parsed inputs pass it in Fix(). Discarding once more is
    // harmless and makes the lowering boundary fail closed for either path.
    message.DiscardUnknownFields();
    runtime->Clear();
    Traits::Lower(&message, runtime);
    // A projected profile root intentionally cannot carry policy-owned state
    // such as a fixed scheme. The postprocessor normalized that state before
    // Lift, but Lift necessarily omitted it; restore it at the final lowering
    // boundary instead of assuming the serialized root can round-trip it.
    if constexpr (Traits::kProfile != TargetProfile::kCompatibility) {
      NormalizeScenarioForTarget(runtime, Traits::kProfile, &Traits::PruneConditionalEligibility);
    }
    return true;
  }
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_PROFILE_FUZZER_H_
