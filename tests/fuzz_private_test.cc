/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "fuzz_private.h"

#include <cstdint>
#include <string_view>

int main() {
  constexpr std::string_view inputs[] = {
      "P+a+b+c+d+e+f+g+h+i#?4-z-b0C",
      "DP@A!!xvA!!yzC! xN! xn! xS!!xwr! xX  A!!qzN! q",
      "U+0000+1000N0000",
      "MS0A0D0R0",
      "H0PQS",
  };

  // A second pass makes stale per-input state observable.
  for (int pass = 0; pass < 2; ++pass) {
    for (std::string_view input : inputs) {
      if (private_fuzzer::TestOneInput(
              reinterpret_cast<const std::uint8_t *>(input.data()),
              input.size()) != 0)
        return 1;
    }
  }
  return 0;
}
