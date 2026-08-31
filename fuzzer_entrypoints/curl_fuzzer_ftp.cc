/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "legacy_fuzzer.h"

// Fuzz Introspector pairs a static profile with runtime coverage by target
// basename. This literal, same-named entrypoint keeps that pairing precise
// while all protocol binaries continue to share the TLV implementation.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  return LegacyFuzzerTestOneInput(data, size);
}
