/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "generated/fast_https/fast_https_traits.h"
#include "proto_fuzzer/fuzzer_main.h"

namespace {

// Bind the GnuTLS client binary to the same focused HTTPS policy as the
// original OpenSSL-backed lane. The linked libcurl variant, rather than fuzz
// input, selects the client TLS backend for the lifetime of the process.
using Traits = proto_fuzzer::generated::FastHttpsTraits;
constexpr auto kProfile = proto_fuzzer::BindProfileFuzzer<Traits>();

} // namespace

// Keep all three libFuzzer ABI hooks in the same-named source so OSS-Fuzz and
// Fuzz Introspector give this backend its own target identity and corpus.
extern "C" std::size_t LLVMFuzzerCustomMutator(std::uint8_t *data,
                                               std::size_t size,
                                               std::size_t max_size,
                                               unsigned int seed) {
  return proto_fuzzer::ProtoFuzzerCustomMutator(data, size, max_size, seed,
                                                kProfile);
}

extern "C" std::size_t
LLVMFuzzerCustomCrossOver(const std::uint8_t *data1, std::size_t size1,
                          const std::uint8_t *data2, std::size_t size2,
                          std::uint8_t *out, std::size_t max_out_size,
                          unsigned int seed) {
  return proto_fuzzer::ProtoFuzzerCustomCrossOver(
      data1, size1, data2, size2, out, max_out_size, seed, kProfile);
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  return proto_fuzzer::ProtoFuzzerTestOneInput(data, size, kProfile);
}
