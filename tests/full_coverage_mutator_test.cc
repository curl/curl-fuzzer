/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "full_coverage/legacy_mutator.h"
#include "test_assertions.h"

#include <stddef.h>
#include <stdint.h>

namespace {

using test_support::Expect;

struct Observations {
  size_t calls = 0;
  size_t empty_inputs = 0;
  size_t growth_capacity = 0;
  size_t exact_capacity = 0;
  uint64_t fingerprint = UINT64_C(14695981039346656037);
};

Observations observed;

void Hash(uint64_t value) {
  observed.fingerprint ^= value;
  observed.fingerprint *= UINT64_C(1099511628211);
}

}  // namespace

// Emulate only the byte-mutator contract, with observable deterministic edits.
// Linking no curl library keeps this test confined to local mutation helpers.
extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size,
                                   size_t max_size) {
  Expect(data != nullptr, "byte mutation received no storage");
  Expect(size <= max_size && max_size > 0 && max_size <= 8192,
         "coverage helper exceeded its byte-mutation budget");
  ++observed.calls;
  observed.empty_inputs += size == 0;
  observed.growth_capacity += size < max_size;
  observed.exact_capacity += size == max_size;
  Hash(size);
  Hash(max_size);
  for(size_t index = 0; index < size; ++index)
    Hash(data[index]);

  if(size == 0) {
    data[0] = 'A';
    return 1;
  }
  data[0] ^= 1;
  return size;
}

int main() {
  full_coverage::ExerciseLegacyMutatorCoverage();
  const Observations first = observed;
  Expect(first.calls > 0, "coverage helper skipped engine byte mutation");
  Expect(first.empty_inputs > 0 && first.growth_capacity > 0 &&
             first.exact_capacity > 0,
         "coverage helper skipped a byte-mutation capacity transition");

  observed = Observations{};
  full_coverage::ExerciseLegacyMutatorCoverage();
  Expect(observed.calls == first.calls &&
             observed.empty_inputs == first.empty_inputs &&
             observed.growth_capacity == first.growth_capacity &&
             observed.exact_capacity == first.exact_capacity &&
             observed.fingerprint == first.fingerprint,
         "coverage helper's fixed exercise was not reproducible");
  return 0;
}
