/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "fuzz_setopt.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <string>
#include <vector>

#ifndef FUZZ_SETOPT_CORPUS_DIR
#define FUZZ_SETOPT_CORPUS_DIR "corpora/fuzz_setopt"
#endif

namespace {

bool Expect(bool condition, const char *message) {
  if (!condition)
    std::cerr << message << '\n';
  return condition;
}

std::array<std::uint8_t, setopt_fuzzer::kRecordSize>
MakeRecord(std::uint16_t selector, std::uint8_t mode, std::uint64_t payload) {
  std::array<std::uint8_t, setopt_fuzzer::kRecordSize> record = {};
  record[0] = static_cast<std::uint8_t>(selector);
  record[1] = static_cast<std::uint8_t>(selector >> 8);
  record[2] = mode;
  for (std::size_t index = 0; index < sizeof(payload); ++index)
    record[3 + index] = static_cast<std::uint8_t>(payload >> (index * 8));
  return record;
}

bool CatalogIsSortedAndAliasFree() {
  const auto &options = setopt_fuzzer::EligibleOptions();
  if (!Expect(!options.empty(), "the numeric option catalog is empty"))
    return false;
  if (!Expect(options.size() <= 65536,
              "the option selector cannot address the complete catalog"))
    return false;

  std::set<CURLoption> expected_ids;
  const struct curl_easyoption *option = nullptr;
  while ((option = curl_easy_option_next(option)) != nullptr) {
    if ((option->flags & CURLOT_FLAG_ALIAS) == 0 &&
        (option->type == CURLOT_LONG || option->type == CURLOT_VALUES ||
         option->type == CURLOT_OFF_T)) {
      expected_ids.insert(option->id);
    }
  }

  if (!Expect(options.size() == expected_ids.size(),
              "the option catalog did not remove aliases"))
    return false;
  for (std::size_t index = 0; index < options.size(); ++index) {
    if (!Expect(expected_ids.count(options[index].id) == 1,
                "the option catalog contains an ineligible ID"))
      return false;
    if (!Expect(options[index].type == CURLOT_LONG ||
                    options[index].type == CURLOT_VALUES ||
                    options[index].type == CURLOT_OFF_T,
                "the option catalog contains a non-numeric type"))
      return false;
    if (index != 0 && !Expect(options[index - 1].id < options[index].id,
                              "the option catalog is not strictly sorted"))
      return false;
  }
  return true;
}

bool EveryCatalogEntryIsSelectable() {
  const auto &options = setopt_fuzzer::EligibleOptions();
  for (std::size_t index = 0; index < options.size(); ++index) {
    const auto input = MakeRecord(static_cast<std::uint16_t>(index),
                                  static_cast<std::uint8_t>(index), index);
    const auto records =
        setopt_fuzzer::DecodeRecords(input.data(), input.size());
    if (!Expect(records.size() == 1, "one record did not decode"))
      return false;
    if (!Expect(records[0].option.id == options[index].id,
                "the selector chose the wrong option"))
      return false;
    if (!Expect(records[0].option.type == options[index].type,
                "the selector lost the native option type"))
      return false;
    if (!Expect(records[0].mode ==
                    static_cast<setopt_fuzzer::ValueMode>(index & 7U),
                "the record chose the wrong value mode"))
      return false;
    if (!Expect(records[0].payload == index,
                "the record changed the value payload"))
      return false;
    if (!Expect(setopt_fuzzer::TestOneInput(input.data(), input.size()) == 0,
                "the selected option failed to execute"))
      return false;
  }
  return true;
}

bool SeedCorpusCoversCatalog() {
  constexpr const char *kSeedNames[] = {
      "ordinals_000_062",
      "ordinals_063_125",
      "ordinals_126_140",
  };
  const auto &options = setopt_fuzzer::EligibleOptions();
  std::size_t ordinal = 0;

  for (const char *seed_name : kSeedNames) {
    const std::string path =
        std::string(FUZZ_SETOPT_CORPUS_DIR) + "/" + seed_name;
    std::ifstream input(path, std::ios::binary);
    if (!Expect(input.is_open(), "a checked-in setopt seed is missing"))
      return false;
    const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(input),
                                          std::istreambuf_iterator<char>()};
    if (!Expect(bytes.size() <= setopt_fuzzer::kMaxInputSize,
                "a setopt seed exceeds the input limit"))
      return false;

    const auto records =
        setopt_fuzzer::DecodeRecords(bytes.data(), bytes.size());
    if (!Expect(records.size() <= setopt_fuzzer::kMaxRecords,
                "a setopt seed exceeds the record limit"))
      return false;
    for (const auto &record : records) {
      if (!Expect(ordinal < options.size(),
                  "the setopt corpus contains an extra record"))
        return false;
      if (!Expect(record.option.id == options[ordinal].id,
                  "the setopt corpus skipped a catalog ordinal"))
        return false;
      if (!Expect(record.option.type == options[ordinal].type,
                  "the setopt corpus changed a catalog type"))
        return false;
      if (!Expect(record.mode ==
                      static_cast<setopt_fuzzer::ValueMode>(ordinal & 7U),
                  "the setopt corpus did not rotate value modes"))
        return false;
      ++ordinal;
    }
  }

  return Expect(ordinal == options.size(),
                "the setopt corpus does not cover the complete catalog");
}

bool DecoderIsBounded() {
  std::vector<std::uint8_t> input(
      setopt_fuzzer::kRecordSize * (setopt_fuzzer::kMaxRecords + 1), 0);
  const auto records = setopt_fuzzer::DecodeRecords(input.data(), input.size());
  if (!Expect(records.size() == setopt_fuzzer::kMaxRecords,
              "the decoder exceeded the record limit"))
    return false;

  input.resize(setopt_fuzzer::kRecordSize - 1);
  if (!Expect(setopt_fuzzer::DecodeRecords(input.data(), input.size()).empty(),
              "the decoder accepted an incomplete record"))
    return false;
  return Expect(setopt_fuzzer::kMaxInputSize == 704,
                "the input limit no longer matches OSS-Fuzz");
}

} // namespace

int main() {
  if (!CatalogIsSortedAndAliasFree() || !EveryCatalogEntryIsSelectable() ||
      !SeedCorpusCoversCatalog() || !DecoderIsBounded())
    return 1;
  return 0;
}
