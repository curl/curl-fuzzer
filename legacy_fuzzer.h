/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef LEGACY_FUZZER_H_
#define LEGACY_FUZZER_H_

#include <stddef.h>
#include <stdint.h>

/**
 * Execute one legacy TLV testcase without owning the exported libFuzzer
 * symbol. Protocol binaries delegate here from uniquely named entrypoint
 * sources so coverage attribution remains per binary.
 */
int LegacyFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif  /* LEGACY_FUZZER_H_ */
