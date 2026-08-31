/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/fuzzer_main.h"

// Fuzz Introspector pairs a static profile with runtime coverage by target
// basename. This literal, same-named entrypoint keeps that pairing precise
// while all lanes continue to share protobuf mutation and scenario execution.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  return proto_fuzzer::ProtoFuzzerTestOneInput(data, size);
}
