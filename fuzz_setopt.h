/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef FUZZ_SETOPT_H_
#define FUZZ_SETOPT_H_

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace setopt_fuzzer {

inline constexpr std::size_t kRecordSize = 11;
inline constexpr std::size_t kMaxRecords = 64;
inline constexpr std::size_t kMaxInputSize = kRecordSize * kMaxRecords;

enum class ValueMode : std::uint8_t {
  kRaw = 0,
  kZero,
  kOne,
  kMinusOne,
  kNativeMinimum,
  kNativeMaximum,
  kOneBit,
  kInvertedOneBit,
};

struct EligibleOption {
  CURLoption id;
  curl_easytype type;
};

struct DecodedRecord {
  EligibleOption option;
  ValueMode mode;
  std::uint64_t payload;
};

/** Return the sorted, alias-free catalog of numeric easy options. */
const std::vector<EligibleOption> &EligibleOptions();

/** Decode complete, fixed-size records up to the per-input limit. */
std::vector<DecodedRecord> DecodeRecords(const std::uint8_t *data,
                                         std::size_t size);

/** Apply one bounded option stream to a fresh easy handle. */
int TestOneInput(const std::uint8_t *data, std::size_t size);

} // namespace setopt_fuzzer

#endif // FUZZ_SETOPT_H_
