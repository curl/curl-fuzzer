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

#include <array>
#include <cstddef>
#include <cstdint>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/target_policy.h"
#include "proto_fuzzer/target_profile.h"

namespace proto_fuzzer {

/// Ordinary runtime binding for one generated protobuf profile.
///
/// A single binding owns the target profile and every typed LPM callback. This
/// keeps libFuzzer entrypoints non-template while guaranteeing mutation,
/// crossover, and loading all use the same concrete protobuf message type.
struct ProfileFuzzerTraits {
  /// libFuzzer custom-mutator callback for the bound message type.
  using CustomMutator = std::size_t (*)(std::uint8_t*, std::size_t, std::size_t, unsigned int);
  /// libFuzzer custom-crossover callback for the bound message type.
  using CustomCrossOver = std::size_t (*)(const std::uint8_t*, std::size_t, const std::uint8_t*, std::size_t,
                                          std::uint8_t*, std::size_t, unsigned int);
  /// Parse and lower one input using the bound message type.
  using InputLoader = bool (*)(const std::uint8_t*, std::size_t, curl::fuzzer::proto::Scenario*);
  /// Optional profiling-only callback that exercises typed mutation helpers.
  using MutationProbe = void (*)();

  /// Runtime policy permanently associated with all callbacks.
  TargetProfile profile;
  /// Typed mutation callback.
  CustomMutator custom_mutator;
  /// Typed crossover callback.
  CustomCrossOver custom_crossover;
  /// Typed parse-and-lower callback.
  InputLoader load_input;
  /// Timing-profile probe, or nullptr for ordinary profiles.
  MutationProbe probe_mutation_helpers;
};

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
  /// Concrete generated protobuf root for this target profile.
  using Message = typename Traits::Message;
  /// Shared internal Scenario consumed by the runtime.
  using RuntimeScenario = curl::fuzzer::proto::Scenario;

  /// Register the profile postprocessor before the first LPM operation.
  static void EnsurePostProcessor() {
    static const protobuf_mutator::libfuzzer::PostProcessorRegistration<Message> registration(
        [](Message* message, unsigned int /*seed*/) { NormalizeMessage(message); });
    (void)registration;
  }

  /// Remove unknown wire data, normalize through the common runtime model,
  /// and lift back into the same generated profile type.
  /// @param message Generated profile message to normalize in place.
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
  /// @param data Serialized profile message buffer to mutate in place.
  /// @param size Number of input bytes currently stored in `data`.
  /// @param max_size Capacity of `data` available for the mutated message.
  /// @param seed Deterministic mutation seed supplied by libFuzzer.
  /// @return Number of serialized bytes in the mutated message.
  static std::size_t CustomMutator(std::uint8_t* data, std::size_t size, std::size_t max_size, unsigned int seed) {
    EnsurePostProcessor();
    Message message;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(true, data, size, max_size, seed, &message);
  }

  /// Cross two binary profile messages using the same type as mutation/load.
  /// @param data1 Serialized first parent message.
  /// @param size1 Number of bytes in `data1`.
  /// @param data2 Serialized second parent message.
  /// @param size2 Number of bytes in `data2`.
  /// @param out Destination buffer for the crossed message.
  /// @param max_out_size Capacity of `out`.
  /// @param seed Deterministic crossover seed supplied by libFuzzer.
  /// @return Number of serialized bytes written to `out`.
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
  /// @param data Serialized profile message bytes.
  /// @param size Number of bytes available at `data`.
  /// @param runtime Destination for the owned, lowered runtime Scenario.
  /// @return Whether the input loaded and lowered successfully.
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

/// Load one generated profile message and lower it into runtime state.
/// @tparam Traits Generated adapter defining the concrete message type.
/// @param data Serialized generated-profile bytes.
/// @param size Number of bytes available at `data`.
/// @param runtime Destination for the owned runtime Scenario.
/// @return Whether parsing and lowering succeeded.
template <typename Traits>
bool LoadProfileInput(const std::uint8_t* data, std::size_t size, curl::fuzzer::proto::Scenario* runtime) {
  return ProfileFuzzerHooks<Traits>::LoadAndLower(data, size, runtime);
}

/// Exercise the typed mutation ABI once for the profiling timing target.
/// @tparam Traits Generated adapter defining the concrete message type.
template <typename Traits>
void ProbeTimingMutationHelpers() {
  static const bool mutation_helpers_probed = [] {
    constexpr std::size_t kBufferSize = 1024;
    constexpr unsigned int kMutationSeed = 0x4355524cU;

    curl::fuzzer::proto::Scenario runtime;
    NormalizeScenarioForTarget(&runtime, Traits::kProfile, &Traits::PruneConditionalEligibility);

    typename Traits::Message message;
    Traits::Lift(&runtime, &message);
    std::array<std::uint8_t, kBufferSize> first = {};
    const std::size_t original_size = message.ByteSizeLong();
    if (original_size > first.size()) {
      return true;
    }
    (void)message.SerializeWithCachedSizesToArray(first.data());

    using Hooks = ProfileFuzzerHooks<Traits>;
    std::array<std::uint8_t, kBufferSize> second = first;
    std::array<std::uint8_t, kBufferSize> child = {};
    const std::size_t mutated_size = Hooks::CustomMutator(first.data(), original_size, first.size(), kMutationSeed);
    const std::size_t crossed_size = Hooks::CustomCrossOver(first.data(), mutated_size, second.data(), original_size,
                                                            child.data(), child.size(), kMutationSeed);
    const volatile std::size_t result_sizes[] = {mutated_size, crossed_size};
    (void)result_sizes;
    return true;
  }();
  (void)mutation_helpers_probed;
}

/// Bind one generated adapter to the ordinary entrypoint helper interface.
/// @tparam Traits Generated adapter defining the concrete message type.
/// @return Immutable runtime descriptor binding all callbacks to `Traits`.
template <typename Traits>
constexpr ProfileFuzzerTraits BindProfileFuzzer() {
  using Hooks = ProfileFuzzerHooks<Traits>;
  if constexpr (Traits::kProfile == TargetProfile::kTiming) {
    return {Traits::kProfile, &Hooks::CustomMutator, &Hooks::CustomCrossOver, &LoadProfileInput<Traits>,
            &ProbeTimingMutationHelpers<Traits>};
  }
  return {Traits::kProfile, &Hooks::CustomMutator, &Hooks::CustomCrossOver, &LoadProfileInput<Traits>, nullptr};
}

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_PROFILE_FUZZER_H_
