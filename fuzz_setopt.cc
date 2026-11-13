/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

// Direct fuzzing for numeric curl_easy_setopt paths. Each fixed-size input
// record selects one option from libcurl's runtime catalog and supplies one
// value. The target does not perform a transfer, so mutations can concentrate
// on option validation and state changes.

#include "fuzz_setopt.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <type_traits>

namespace setopt_fuzzer {
namespace {

struct CurlBootstrap {
  CurlBootstrap() { (void)curl_global_init(CURL_GLOBAL_ALL); }
  ~CurlBootstrap() { curl_global_cleanup(); }
};

CurlBootstrap kCurlBootstrap;

bool IsNumericType(curl_easytype type) {
  return type == CURLOT_LONG || type == CURLOT_VALUES || type == CURLOT_OFF_T;
}

std::uint16_t ReadSelector(const std::uint8_t *record) {
  return static_cast<std::uint16_t>(record[0]) |
         static_cast<std::uint16_t>(record[1]) << 8;
}

std::uint64_t ReadPayload(const std::uint8_t *record) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < sizeof(value); ++index)
    value |= static_cast<std::uint64_t>(record[3 + index]) << (index * 8);
  return value;
}

template <typename T> T FromBits(typename std::make_unsigned<T>::type bits) {
  static_assert(std::is_integral<T>::value, "setopt value must be integral");
  T value;
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

template <typename T> T ValueFor(const DecodedRecord &record) {
  using Unsigned = typename std::make_unsigned<T>::type;
  constexpr std::size_t kValueBits = std::numeric_limits<Unsigned>::digits;
  const Unsigned payload = static_cast<Unsigned>(record.payload);
  const Unsigned one_bit = static_cast<Unsigned>(1)
                           << (record.payload % kValueBits);

  switch (record.mode) {
  case ValueMode::kRaw:
    return FromBits<T>(payload);
  case ValueMode::kZero:
    return static_cast<T>(0);
  case ValueMode::kOne:
    return static_cast<T>(1);
  case ValueMode::kMinusOne:
    return static_cast<T>(-1);
  case ValueMode::kNativeMinimum:
    return std::numeric_limits<T>::min();
  case ValueMode::kNativeMaximum:
    return std::numeric_limits<T>::max();
  case ValueMode::kOneBit:
    return FromBits<T>(one_bit);
  case ValueMode::kInvertedOneBit:
    return FromBits<T>(static_cast<Unsigned>(~one_bit));
  }
  return static_cast<T>(0);
}

void ApplyRecord(CURL *easy, const DecodedRecord &record) {
  switch (record.option.type) {
  case CURLOT_LONG:
  case CURLOT_VALUES:
    (void)curl_easy_setopt(easy, record.option.id, ValueFor<long>(record));
    break;
  case CURLOT_OFF_T:
    (void)curl_easy_setopt(easy, record.option.id,
                           ValueFor<curl_off_t>(record));
    break;
  default:
    break;
  }
}

} // namespace

const std::vector<EligibleOption> &EligibleOptions() {
  static const std::vector<EligibleOption> options = [] {
    std::vector<EligibleOption> result;
    const struct curl_easyoption *option = nullptr;
    while ((option = curl_easy_option_next(option)) != nullptr) {
      if ((option->flags & CURLOT_FLAG_ALIAS) == 0 &&
          IsNumericType(option->type)) {
        result.push_back({option->id, option->type});
      }
    }

    std::sort(result.begin(), result.end(),
              [](const EligibleOption &left, const EligibleOption &right) {
                return left.id < right.id;
              });
    result.erase(std::unique(result.begin(), result.end(),
                             [](const EligibleOption &left,
                                const EligibleOption &right) {
                               return left.id == right.id;
                             }),
                 result.end());
    return result;
  }();
  return options;
}

std::vector<DecodedRecord> DecodeRecords(const std::uint8_t *data,
                                         std::size_t size) {
  std::vector<DecodedRecord> records;
  const std::vector<EligibleOption> &options = EligibleOptions();
  if (data == nullptr || options.empty())
    return records;

  const std::size_t count = std::min(size / kRecordSize, kMaxRecords);
  records.reserve(count);
  for (std::size_t index = 0; index < count; ++index) {
    const std::uint8_t *record = data + index * kRecordSize;
    const std::size_t option_index = ReadSelector(record) % options.size();
    records.push_back({options[option_index],
                       static_cast<ValueMode>(record[2] & 7U),
                       ReadPayload(record)});
  }
  return records;
}

int TestOneInput(const std::uint8_t *data, std::size_t size) {
  CURL *easy = curl_easy_init();
  if (easy == nullptr)
    return 0;

  for (const DecodedRecord &record : DecodeRecords(data, size))
    ApplyRecord(easy, record);

  curl_easy_cleanup(easy);
  return 0;
}

} // namespace setopt_fuzzer

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  return setopt_fuzzer::TestOneInput(data, size);
}
