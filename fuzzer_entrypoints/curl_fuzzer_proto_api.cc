/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/fuzzer_main.h"

// Keep this entrypoint in a same-named source so Fuzz Introspector attributes
// the API lifecycle lane independently from the protocol-focused proto lanes.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
  return proto_fuzzer::ProtoFuzzerTestOneInput(data, size);
}
