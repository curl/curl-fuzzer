/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef FUZZ_PRIVATE_H_
#define FUZZ_PRIVATE_H_

#include <cstddef>
#include <cstdint>

namespace private_fuzzer {

/** Interpret one bounded operation stream against curl's private helpers. */
int TestOneInput(const std::uint8_t *data, std::size_t size);

}  // namespace private_fuzzer

#endif  // FUZZ_PRIVATE_H_
