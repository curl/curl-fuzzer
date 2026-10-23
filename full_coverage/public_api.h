/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef FULL_COVERAGE_PUBLIC_API_H_
#define FULL_COVERAGE_PUBLIC_API_H_

namespace full_coverage {

/** Exercise public compatibility helpers without performing a transfer. */
void ExercisePublicApiCoverage();

/** Exercise the same helpers while a caller-owned curl runtime is active. */
void ExercisePublicApiCoverageWithInitializedCurl();

}  // namespace full_coverage

#endif  // FULL_COVERAGE_PUBLIC_API_H_
