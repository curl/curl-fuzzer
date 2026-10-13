/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef CURL_FUZZER_TEST_ASSERTIONS_H_
#define CURL_FUZZER_TEST_ASSERTIONS_H_

#include <cstdlib>
#include <iostream>

namespace test_support {

[[noreturn]] inline void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

inline void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

}  // namespace test_support

#endif  // CURL_FUZZER_TEST_ASSERTIONS_H_
