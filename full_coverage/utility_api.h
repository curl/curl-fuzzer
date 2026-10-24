/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef FULL_COVERAGE_UTILITY_API_H_
#define FULL_COVERAGE_UTILITY_API_H_

namespace full_coverage {

/** Exercise bounded version, date, and escaping APIs without a transfer. */
void ExerciseUtilityApiCoverage();

/** Exercise the same APIs while a caller-owned curl runtime is active. */
void ExerciseUtilityApiCoverageWithInitializedCurl();

}  // namespace full_coverage

#endif  // FULL_COVERAGE_UTILITY_API_H_
