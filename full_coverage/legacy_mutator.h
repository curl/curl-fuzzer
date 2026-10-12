/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef FULL_COVERAGE_LEGACY_MUTATOR_H_
#define FULL_COVERAGE_LEGACY_MUTATOR_H_

namespace full_coverage {

// Exercise the legacy mutator's replay-independent helpers using a fixed,
// bounded set of inputs. No resulting input is passed to a transfer harness.
void ExerciseLegacyMutatorCoverage();

}  // namespace full_coverage

#endif  // FULL_COVERAGE_LEGACY_MUTATOR_H_
