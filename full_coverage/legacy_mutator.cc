/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "full_coverage/legacy_mutator.h"

#include "legacy_tlv_mutator.h"

#include <stdint.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t max_size,
                                          unsigned int seed);
extern "C" size_t LLVMFuzzerCustomCrossOver(
    const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2,
    uint8_t *out, size_t max_out_size, unsigned int seed);

namespace full_coverage {
namespace {

constexpr size_t kCapacity = 8192;
constexpr unsigned int kSeedCount = 64;
using Input = std::vector<uint8_t>;

void AppendRecord(Input *input, uint16_t type, const uint8_t *value,
                  size_t size) {
  const uint32_t length = static_cast<uint32_t>(size);
  input->push_back(static_cast<uint8_t>(type >> 8));
  input->push_back(static_cast<uint8_t>(type));
  input->push_back(static_cast<uint8_t>(length >> 24));
  input->push_back(static_cast<uint8_t>(length >> 16));
  input->push_back(static_cast<uint8_t>(length >> 8));
  input->push_back(static_cast<uint8_t>(length));
  if(size)
    input->insert(input->end(), value, value + size);
}

void AppendString(Input *input, uint16_t type, const char *value) {
  AppendRecord(input, type, reinterpret_cast<const uint8_t *>(value),
               std::strlen(value));
}

std::vector<Input> MakeInputs() {
  Input transfer;
  AppendString(&transfer, 1, "http://127.0.0.1/");
  const Input url = transfer;
  AppendString(&transfer, 2,
               "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

  // One ordinary record from every value class, plus repeatable records and
  // canonical routing strings. These remain data for the mutator only.
  Input options = transfer;
  AppendString(&options, 6, "X-Coverage: 1");
  AppendString(&options, 6, "X-Coverage: 2");
  AppendString(&options, 8, "upload");
  AppendString(&options, 11, "coverage@example.test");
  Input mime;
  AppendString(&mime, 14, "field");
  AppendString(&mime, 15, "value");
  AppendRecord(&options, 13, mime.data(), mime.size());
  const uint8_t numeric[] = {0, 0, 0, 80};
  AppendRecord(&options, 200, numeric, sizeof(numeric));
  for(const uint16_t type : {53, 102, 105, 149})
    AppendString(&options, type,
                 legacy_tlv_mutator::CanonicalRoutingValue(type));

  Input header;
  AppendString(&header, 6, "X-Only: 1");
  Input response;
  AppendString(&response, 2, "HTTP/1.1 204 OK\r\n\r\n");

  // Short values exercise canonicalization with and without growth space.
  Input routing = transfer;
  for(const uint16_t type : {53, 102, 105, 149})
    AppendString(&routing, type, "");

  Input trailing = options;
  trailing.push_back(0);

  // Known framing and semantic rejection paths also enter prefix repair and
  // byte crossover. All storage is local; none of these records reaches curl.
  Input truncated = options;
  truncated.pop_back();
  Input duplicate = transfer;
  AppendString(&duplicate, 1, "http://127.0.0.1/");
  Input short_numeric = transfer;
  AppendRecord(&short_numeric, 200, numeric, 1);
  Input unknown = transfer;
  AppendString(&unknown, 0xffff, "");
  Input invalid_mime = transfer;
  AppendRecord(&invalid_mime, 13, header.data(), header.size());
  Input truncated_mime = transfer;
  const uint8_t short_part[] = {0, 15, 0, 0, 0, 2, 'v'};
  AppendRecord(&truncated_mime, 13, short_part, sizeof(short_part));

  // The parser has a 512-record work limit. Repeated empty headers exercise
  // acceptance at that limit and the bounded repair path immediately above it.
  Input at_record_limit;
  for(size_t index = 0; index < 512; ++index)
    AppendString(&at_record_limit, 6, "");
  Input above_record_limit = at_record_limit;
  AppendString(&above_record_limit, 6, "");

  return {{}, transfer, options, url, header, response, routing, trailing,
          truncated, duplicate, short_numeric, unknown, invalid_mime,
          truncated_mime, at_record_limit, above_record_limit};
}

// A volatile result keeps validation and immutable routing queries visible
// even when link-time optimization can see that this is a coverage exercise.
void ObserveValidation(const uint8_t *data, size_t size) {
  volatile bool valid = legacy_tlv_mutator::IsStructurallyValid(data, size);
  (void)valid;
}

}  // namespace

void ExerciseLegacyMutatorCoverage() {
  const std::vector<Input> inputs = MakeInputs();
  std::array<uint8_t, kCapacity> scratch = {};
  std::array<uint8_t, kCapacity> child = {};

  // Replay does not call libFuzzer's ABI adapters. Cover them explicitly as
  // well as their ordinary namespaced implementations below.
  const Input &first = inputs[1];
  const Input &second = inputs[2];
  std::copy(first.begin(), first.end(), scratch.begin());
  const size_t mutated_size = LLVMFuzzerCustomMutator(
      scratch.data(), first.size(), scratch.size(), 1);
  ObserveValidation(scratch.data(), mutated_size);
  const size_t crossed_size = LLVMFuzzerCustomCrossOver(
      first.data(), first.size(), second.data(), second.size(), child.data(),
      child.size(), 1);
  ObserveValidation(child.data(), crossed_size);

  // Empty parents still use real storage. Reversing the existing empty-first
  // case exercises the one-byte fallback from the first parent; two empty
  // parents have no byte to inherit even when output capacity is available.
  const Input &header = inputs[4];
  const size_t reversed_size = LLVMFuzzerCustomCrossOver(
      header.data(), header.size(), scratch.data(), 0, child.data(), 1, 7);
  ObserveValidation(child.data(), reversed_size);
  const size_t empty_size = LLVMFuzzerCustomCrossOver(
      scratch.data(), 0, scratch.data(), 0, child.data(), 1, 7);
  ObserveValidation(child.data(), empty_size);

  // These framed IDs are explicitly excluded by the top-level type policy.
  for(const uint16_t type : {15, 51, 212, 322}) {
    Input rejected;
    AppendRecord(&rejected, type, scratch.data(), 0);
    ObserveValidation(rejected.data(), rejected.size());
  }

  // With exact capacity, a nonempty short routing value must shrink to the
  // disabled empty value when its canonical spelling cannot fit. Seed 8
  // selects duplication; scalar-only records leave no room for insertion.
  Input short_routing = first;
  AppendString(&short_routing, 53, "1");
  std::copy(short_routing.begin(), short_routing.end(), scratch.begin());
  const size_t routing_size = legacy_tlv_mutator::Mutate(
      scratch.data(), short_routing.size(), short_routing.size(), 8);
  ObserveValidation(scratch.data(), routing_size);

  for(const uint16_t type : {53, 102, 105, 129, 149, 0xffff}) {
    const char *volatile routing =
        legacy_tlv_mutator::CanonicalRoutingValue(type);
    (void)routing;
  }

  for(size_t index = 0; index < inputs.size(); ++index) {
    const Input &input = inputs[index];
    const Input &other = inputs[(index + 1) % inputs.size()];
    ObserveValidation(input.data(), input.size());

    // Zero/tiny capacities exercise the documented no-op/fallback behavior;
    // exact capacity and spare capacity distinguish replacement from growth.
    const size_t capacities[] = {0, 1, 6, 96, input.size(), kCapacity};
    for(const size_t capacity : capacities) {
      for(unsigned int seed = 0; seed < kSeedCount; ++seed) {
        std::copy(input.begin(), input.end(), scratch.begin());
        const size_t size = legacy_tlv_mutator::Mutate(
            scratch.data(), input.size(), capacity, seed);
        ObserveValidation(scratch.data(), size);

        const size_t child_size = legacy_tlv_mutator::CrossOver(
            input.data(), input.size(), other.data(), other.size(),
            child.data(), capacity, seed);
        ObserveValidation(child.data(), child_size);
      }
    }
  }
}

}  // namespace full_coverage
