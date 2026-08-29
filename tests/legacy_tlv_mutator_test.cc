/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "legacy_tlv_mutator.h"

#include <stdint.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

namespace {

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if(!condition)
    Fail(message);
}

void AppendTlv(std::vector<uint8_t> *out, uint16_t type,
               const std::vector<uint8_t> &value) {
  out->push_back(static_cast<uint8_t>(type >> 8));
  out->push_back(static_cast<uint8_t>(type));
  const uint32_t length = static_cast<uint32_t>(value.size());
  out->push_back(static_cast<uint8_t>(length >> 24));
  out->push_back(static_cast<uint8_t>(length >> 16));
  out->push_back(static_cast<uint8_t>(length >> 8));
  out->push_back(static_cast<uint8_t>(length));
  out->insert(out->end(), value.begin(), value.end());
}

std::vector<uint8_t> Bytes(const char *text) {
  return std::vector<uint8_t>(text, text + std::strlen(text));
}

uint16_t ReadU16(const uint8_t *data) {
  return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                               static_cast<uint16_t>(data[1]));
}

uint32_t ReadU32(const uint8_t *data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         static_cast<uint32_t>(data[3]);
}

bool FindTlv(const uint8_t *data, size_t size, uint16_t wanted_type,
             const uint8_t **value, size_t *value_size) {
  size_t offset = 0;
  while(offset + 6 <= size) {
    const uint16_t type = ReadU16(data + offset);
    const uint32_t length = ReadU32(data + offset + 2);
    if(static_cast<size_t>(length) > size - offset - 6)
      return false;
    if(type == wanted_type) {
      if(value)
        *value = data + offset + 6;
      if(value_size)
        *value_size = length;
      return true;
    }
    offset += 6 + length;
  }
  return false;
}

bool HasTlv(const uint8_t *data, size_t size, uint16_t type) {
  return FindTlv(data, size, type, nullptr, nullptr);
}

bool TlvValueEquals(const uint8_t *data, size_t size, uint16_t type,
                    const char *expected) {
  const uint8_t *value = nullptr;
  size_t value_size = 0;
  if(!FindTlv(data, size, type, &value, &value_size))
    return false;
  const size_t expected_size = std::strlen(expected);
  return value_size == expected_size &&
         std::memcmp(value, expected, expected_size) == 0;
}

/**
 * Accepts the safe postconditions used when a routing value is present.
 * Loopback preserves option-parser coverage when capacity permits; a zero
 * length is the capacity fallback, while an initial NUL neutralizes a record in
 * a malformed stream without changing its framing.
 */
bool TlvRoutingValueIsSafe(const uint8_t *data, size_t size, uint16_t type,
                           const char *canonical) {
  const uint8_t *value = nullptr;
  size_t value_size = 0;
  if(!FindTlv(data, size, type, &value, &value_size))
    return true;
  if(!value_size)
    return true;
  if(value[0] == 0)
    return true;
  const size_t canonical_size = std::strlen(canonical);
  return value_size == canonical_size &&
         std::memcmp(value, canonical, canonical_size) == 0;
}

/**
 * Checks every option whose value can bypass CONNECT_TO and reach a resolver.
 * Keeping this assertion shared makes mutation and crossover tests enforce the
 * complete safety policy rather than whichever option happened to regress.
 */
bool RoutingValuesAreSafe(const uint8_t *data, size_t size) {
  return TlvRoutingValueIsSafe(data, size, 53, "http://127.0.0.1") &&
         TlvRoutingValueIsSafe(data, size, 102, "127.0.0.1") &&
         TlvRoutingValueIsSafe(data, size, 105, "127.0.0.1") &&
         TlvRoutingValueIsSafe(data, size, 149, "socks5://127.0.0.1");
}

std::vector<uint8_t> MakeParentOne() {
  std::vector<uint8_t> input;
  AppendTlv(&input, 1, Bytes("http://127.0.0.1/"));
  AppendTlv(&input, 2, Bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
  AppendTlv(&input, 6, Bytes("X-One: 1"));
  AppendTlv(&input, 200, {0, 0, 0, 80});
  return input;
}

std::vector<uint8_t> MakeParentTwo() {
  std::vector<uint8_t> input;
  AppendTlv(&input, 2, Bytes("HTTP/1.1 204 OK\r\n\r\n"));
  AppendTlv(&input, 8, Bytes("upload"));
  AppendTlv(&input, 11, Bytes("a@example.test"));
  return input;
}

/**
 * Builds a valid ancestor containing the resolver-bound values that can arrive
 * from an old OSS-Fuzz corpus. DNS_INTERFACE is included as an audit sentinel:
 * unlike these endpoints it names a c-ares device and should remain fuzzable.
 */
std::vector<uint8_t> MakeUnsafeRoutingInput() {
  std::vector<uint8_t> input = MakeParentOne();
  AppendTlv(&input, 53, Bytes("http://proxy.resolver.invalid:8080"));
  AppendTlv(&input, 102, Bytes("ftp-active.resolver.invalid:2000-2010"));
  AppendTlv(&input, 105, Bytes("host!interface.resolver.invalid"));
  AppendTlv(&input, 129, Bytes("dns-interface-audit-sentinel"));
  AppendTlv(&input, 149, Bytes("socks5://preproxy.resolver.invalid:1080"));
  return input;
}

void TestValidation() {
  const std::vector<uint8_t> valid = MakeParentOne();
  Expect(legacy_tlv_mutator::IsStructurallyValid(valid.data(), valid.size()),
         "valid TLV input was rejected");

  std::vector<uint8_t> with_short_tail = valid;
  with_short_tail.push_back(0xaa);
  with_short_tail.push_back(0xbb);
  Expect(legacy_tlv_mutator::IsStructurallyValid(with_short_tail.data(),
                                                  with_short_tail.size()),
         "wire-compatible short trailing bytes were rejected");

  std::vector<uint8_t> unknown;
  AppendTlv(&unknown, 0xffff, Bytes("x"));
  Expect(!legacy_tlv_mutator::IsStructurallyValid(unknown.data(),
                                                   unknown.size()),
         "unknown top-level type was accepted");

  std::vector<uint8_t> wrong_numeric;
  AppendTlv(&wrong_numeric, 200, {0, 1});
  Expect(!legacy_tlv_mutator::IsStructurallyValid(wrong_numeric.data(),
                                                   wrong_numeric.size()),
         "non-four-byte numeric TLV was accepted");

  std::vector<uint8_t> duplicate;
  AppendTlv(&duplicate, 1, Bytes("http://one/"));
  AppendTlv(&duplicate, 1, Bytes("http://two/"));
  Expect(!legacy_tlv_mutator::IsStructurallyValid(duplicate.data(),
                                                   duplicate.size()),
         "duplicate singleton TLV was accepted");

  std::vector<uint8_t> bad_mime;
  std::vector<uint8_t> nested;
  AppendTlv(&nested, 99, Bytes("bad"));
  AppendTlv(&bad_mime, 13, nested);
  Expect(!legacy_tlv_mutator::IsStructurallyValid(bad_mime.data(),
                                                   bad_mime.size()),
         "invalid nested MIME TLV was accepted");
}

void TestCanonicalRoutingValuePolicy() {
  struct ExpectedValue {
    uint16_t type;
    const char *value;
  };
  const ExpectedValue expected[] = {
      {53, "http://127.0.0.1"},
      {102, "127.0.0.1"},
      {105, "127.0.0.1"},
      {149, "socks5://127.0.0.1"},
  };

  for(const ExpectedValue &entry : expected) {
    const char *actual =
        legacy_tlv_mutator::CanonicalRoutingValue(entry.type);
    Expect(actual != nullptr && std::strcmp(actual, entry.value) == 0,
           "public routing policy returned the wrong canonical value");
  }
  Expect(legacy_tlv_mutator::CanonicalRoutingValue(129) == nullptr,
         "DNS_INTERFACE was incorrectly classified as a hostname");
  Expect(legacy_tlv_mutator::CanonicalRoutingValue(128) == nullptr,
         "DNS_SERVERS was incorrectly classified as a routing hostname");
}

void TestStructuredMutationsStayValidAndBounded() {
  const std::vector<uint8_t> original = MakeParentOne();
  for(unsigned int seed = 1; seed < 512; ++seed) {
    if(seed % legacy_tlv_mutator::kRawMutationPeriod == 0)
      continue;
    std::array<uint8_t, 1056> storage = {};
    std::copy(original.begin(), original.end(), storage.begin());
    std::fill(storage.begin() + 1024, storage.end(), 0xcd);
    const size_t result = legacy_tlv_mutator::Mutate(
        storage.data(), original.size(), 1024, seed);
    Expect(result <= 1024, "structured mutation exceeded max_size");
    Expect(legacy_tlv_mutator::IsStructurallyValid(storage.data(), result),
           "structured mutation produced an invalid TLV stream");
    Expect(HasTlv(storage.data(), result, 1),
           "structured mutation removed the URL scaffold");
    Expect(HasTlv(storage.data(), result, 2),
           "structured mutation removed the initial-response scaffold");
    for(size_t i = 1024; i < storage.size(); ++i)
      Expect(storage[i] == 0xcd, "structured mutation overwrote its capacity");
  }
}

void TestStructuredMutationRepairsTransferScaffold() {
  std::vector<uint8_t> input;
  AppendTlv(&input, 6, Bytes("X-Only: 1"));
  std::array<uint8_t, 512> storage = {};
  std::copy(input.begin(), input.end(), storage.begin());

  size_t size = legacy_tlv_mutator::Mutate(
      storage.data(), input.size(), storage.size(), 1);
  Expect(HasTlv(storage.data(), size, 1),
         "structured mutation did not restore a missing URL");
  size = legacy_tlv_mutator::Mutate(storage.data(), size, storage.size(), 2);
  Expect(HasTlv(storage.data(), size, 2),
         "structured mutation did not restore a missing initial response");
}

void TestGeneratedRoutingValuesStayOnLoopback() {
  const std::vector<uint8_t> original = MakeParentOne();
  bool saw_proxy = false;
  bool saw_ftp_port = false;
  bool saw_interface = false;
  bool saw_pre_proxy = false;
  for(unsigned int seed = 1; seed < 20000; ++seed) {
    if(seed % legacy_tlv_mutator::kRawMutationPeriod == 0)
      continue;
    std::array<uint8_t, 1024> storage = {};
    std::copy(original.begin(), original.end(), storage.begin());
    const size_t result = legacy_tlv_mutator::Mutate(
        storage.data(), original.size(), storage.size(), seed);
    if(HasTlv(storage.data(), result, 53)) {
      saw_proxy = true;
      Expect(TlvValueEquals(storage.data(), result, 53,
                            "http://127.0.0.1"),
             "structured mutation generated a resolving proxy host");
    }
    if(HasTlv(storage.data(), result, 149)) {
      saw_pre_proxy = true;
      Expect(TlvValueEquals(storage.data(), result, 149,
                            "socks5://127.0.0.1"),
             "structured mutation generated a resolving pre-proxy host");
    }
    if(HasTlv(storage.data(), result, 102)) {
      saw_ftp_port = true;
      Expect(TlvValueEquals(storage.data(), result, 102, "127.0.0.1"),
             "structured mutation generated a resolving FTPPORT host");
    }
    if(HasTlv(storage.data(), result, 105)) {
      saw_interface = true;
      Expect(TlvValueEquals(storage.data(), result, 105, "127.0.0.1"),
             "structured mutation generated a resolving interface host");
    }
  }
  Expect(saw_proxy, "proxy safety test did not exercise proxy insertion");
  Expect(saw_ftp_port, "routing safety test did not exercise FTPPORT insertion");
  Expect(saw_interface,
         "routing safety test did not exercise interface insertion");
  Expect(saw_pre_proxy,
         "routing safety test did not exercise pre-proxy insertion");
}

/**
 * Proves that structured edits repair dangerous values inherited from corpus
 * entries, not merely values created by insertion. One local edit may remove a
 * record, so the test checks every surviving endpoint over many edit choices.
 * The DNS_INTERFACE sentinel must also survive at least one unrelated edit;
 * this guards the deliberate decision not to confuse a device name with a
 * resolver hostname.
 */
void TestInheritedRoutingValuesAreCanonicalized() {
  const std::vector<uint8_t> original = MakeUnsafeRoutingInput();
  bool saw_dns_interface_unchanged = false;
  bool saw_proxy = false;
  bool saw_ftp_port = false;
  bool saw_interface = false;
  bool saw_pre_proxy = false;

  for(unsigned int seed = 1; seed < 1024; ++seed) {
    if(seed % legacy_tlv_mutator::kRawMutationPeriod == 0)
      continue;
    std::array<uint8_t, 4096> storage = {};
    std::copy(original.begin(), original.end(), storage.begin());
    const size_t result = legacy_tlv_mutator::Mutate(
        storage.data(), original.size(), storage.size(), seed);

    Expect(legacy_tlv_mutator::IsStructurallyValid(storage.data(), result),
           "routing repair made a structured mutation invalid");
    Expect(RoutingValuesAreSafe(storage.data(), result),
           "structured mutation retained a resolver-bound routing value");

    if(HasTlv(storage.data(), result, 53)) {
      saw_proxy = true;
      Expect(TlvValueEquals(storage.data(), result, 53,
                            "http://127.0.0.1"),
             "inherited proxy did not use the preferred loopback value");
    }
    if(HasTlv(storage.data(), result, 102)) {
      saw_ftp_port = true;
      Expect(TlvValueEquals(storage.data(), result, 102, "127.0.0.1"),
             "inherited FTPPORT did not use the preferred loopback value");
    }
    if(HasTlv(storage.data(), result, 105)) {
      saw_interface = true;
      Expect(TlvValueEquals(storage.data(), result, 105, "127.0.0.1"),
             "inherited interface did not use the preferred loopback value");
    }
    if(HasTlv(storage.data(), result, 149)) {
      saw_pre_proxy = true;
      Expect(TlvValueEquals(storage.data(), result, 149,
                            "socks5://127.0.0.1"),
             "inherited pre-proxy did not use the preferred loopback value");
    }
    if(TlvValueEquals(storage.data(), result, 129,
                      "dns-interface-audit-sentinel"))
      saw_dns_interface_unchanged = true;
  }

  Expect(saw_proxy && saw_ftp_port && saw_interface && saw_pre_proxy,
         "inherited routing test did not retain every protected option");
  Expect(saw_dns_interface_unchanged,
         "DNS_INTERFACE was incorrectly canonicalized as a hostname");
}

/**
 * Exercises the post-raw finalizer. Raw byte edits that stay structurally valid
 * must be safe to execute, while edits that corrupt TLV framing must remain
 * malformed so the parser-coverage escape hatch is not accidentally repaired.
 */
void TestRawRoutingRepairPreservesMalformedCoverage() {
  const std::vector<uint8_t> original = MakeUnsafeRoutingInput();
  bool saw_valid = false;
  bool saw_invalid = false;

  for(unsigned int seed = legacy_tlv_mutator::kRawMutationPeriod;
      seed < 8192; seed += legacy_tlv_mutator::kRawMutationPeriod) {
    std::array<uint8_t, 4096> storage = {};
    std::copy(original.begin(), original.end(), storage.begin());
    const size_t result = legacy_tlv_mutator::Mutate(
        storage.data(), original.size(), storage.size(), seed);
    if(legacy_tlv_mutator::IsStructurallyValid(storage.data(), result)) {
      saw_valid = true;
      Expect(RoutingValuesAreSafe(storage.data(), result),
             "valid raw mutation retained a resolver-bound routing value");
    }
    else {
      saw_invalid = true;
      Expect(RoutingValuesAreSafe(storage.data(), result),
             "malformed raw mutation retained a reachable routing hostname");
    }
  }

  Expect(saw_valid, "raw routing test never produced an executable TLV stream");
  Expect(saw_invalid,
         "routing finalization erased malformed raw-mutation coverage");
}

/**
 * Forces the repair pass to run without growth capacity. Empty strings are the
 * safe fallback in that case, so the mutator must neither overflow max_size nor
 * retain a one-byte hostname that curl could resolve.
 */
void TestRoutingRepairWithoutGrowthCapacity() {
  std::vector<uint8_t> original = MakeParentOne();
  AppendTlv(&original, 53, Bytes("x"));
  AppendTlv(&original, 102, Bytes("x"));
  AppendTlv(&original, 105, Bytes("x"));
  AppendTlv(&original, 149, Bytes("x"));
  bool saw_empty_fallback = false;

  for(unsigned int seed = 1; seed < 256; ++seed) {
    if(seed % legacy_tlv_mutator::kRawMutationPeriod == 0)
      continue;
    std::vector<uint8_t> storage = original;
    const size_t result = legacy_tlv_mutator::Mutate(
        storage.data(), storage.size(), storage.size(), seed);
    Expect(result <= storage.size(),
           "routing repair grew past an exact max_size buffer");
    Expect(RoutingValuesAreSafe(storage.data(), result),
           "capacity fallback retained a resolver-bound routing value");

    const uint16_t types[] = {53, 102, 105, 149};
    for(uint16_t type : types) {
      const uint8_t *value = nullptr;
      size_t value_size = 0;
      if(FindTlv(storage.data(), result, type, &value, &value_size) &&
         value_size == 0)
        saw_empty_fallback = true;
    }
  }

  Expect(saw_empty_fallback,
         "exact-capacity routing repair did not exercise its empty fallback");
}

void TestInvalidInputRepairAndEmptyInput() {
  std::array<uint8_t, 256> invalid = {};
  invalid[0] = 0xff;
  invalid[1] = 0xff;
  invalid[5] = 1;
  invalid[6] = 'x';
  const size_t repaired =
      legacy_tlv_mutator::Mutate(invalid.data(), 7, invalid.size(), 1);
  Expect(repaired > 0, "invalid input repair produced no seed");
  Expect(legacy_tlv_mutator::IsStructurallyValid(invalid.data(), repaired),
         "invalid input was not repaired to a valid TLV stream");

  std::array<uint8_t, 256> empty = {};
  const size_t inserted =
      legacy_tlv_mutator::Mutate(empty.data(), 0, empty.size(), 2);
  Expect(inserted > 6, "empty input did not gain a complete TLV");
  Expect(legacy_tlv_mutator::IsStructurallyValid(empty.data(), inserted),
         "empty input mutation was invalid");
}

void TestRawMutationIsControlledAndDeterministicWithoutLibFuzzer() {
  const std::vector<uint8_t> original = MakeParentOne();
  std::array<uint8_t, 512> first = {};
  std::array<uint8_t, 512> second = {};
  std::copy(original.begin(), original.end(), first.begin());
  std::copy(original.begin(), original.end(), second.begin());
  const unsigned int seed = legacy_tlv_mutator::kRawMutationPeriod;
  const size_t first_size = legacy_tlv_mutator::Mutate(
      first.data(), original.size(), first.size(), seed);
  const size_t second_size = legacy_tlv_mutator::Mutate(
      second.data(), original.size(), second.size(), seed);
  Expect(first_size == second_size, "raw fallback size was not deterministic");
  Expect(std::equal(first.begin(), first.begin() + first_size, second.begin()),
         "raw fallback bytes were not deterministic");
  Expect(first_size != original.size() ||
             !std::equal(first.begin(), first.begin() + first_size,
                         original.begin()),
         "raw fallback did not mutate the input");
}

void TestRecordCrossOver() {
  const std::vector<uint8_t> first = MakeParentOne();
  const std::vector<uint8_t> second = MakeParentTwo();
  for(unsigned int seed = 0; seed < 128; ++seed) {
    std::array<uint8_t, 1024> out = {};
    const size_t size = legacy_tlv_mutator::CrossOver(
        first.data(), first.size(), second.data(), second.size(), out.data(),
        out.size(), seed);
    Expect(size <= out.size(), "crossover exceeded max_out_size");
    Expect(legacy_tlv_mutator::IsStructurallyValid(out.data(), size),
           "record crossover produced an invalid TLV stream");
    Expect(HasTlv(out.data(), size, 1),
           "record crossover omitted the URL scaffold");
    Expect(HasTlv(out.data(), size, 2),
           "record crossover omitted the initial-response scaffold");
  }
}

/**
 * Verifies that record-aware crossover cannot reintroduce a hostname from an
 * old parent. Crossover copies payloads verbatim, so this specifically protects
 * the finalization step that runs after genetic selection.
 */
void TestCrossOverCanonicalizesInheritedRoutingValues() {
  const std::vector<uint8_t> first = MakeUnsafeRoutingInput();
  std::vector<uint8_t> second = MakeParentTwo();
  AppendTlv(&second, 53, Bytes("http://second.resolver.invalid"));
  AppendTlv(&second, 102, Bytes("second-ftp.resolver.invalid"));
  AppendTlv(&second, 105, Bytes("host!second-interface.resolver.invalid"));
  AppendTlv(&second, 149, Bytes("socks5://second.resolver.invalid"));
  bool saw_routing_record = false;

  for(unsigned int seed = 0; seed < 512; ++seed) {
    std::array<uint8_t, 4096> out = {};
    const size_t size = legacy_tlv_mutator::CrossOver(
        first.data(), first.size(), second.data(), second.size(), out.data(),
        out.size(), seed);
    Expect(legacy_tlv_mutator::IsStructurallyValid(out.data(), size),
           "routing crossover produced an invalid TLV stream");
    Expect(RoutingValuesAreSafe(out.data(), size),
           "crossover inherited a resolver-bound routing value");
    if(HasTlv(out.data(), size, 53) || HasTlv(out.data(), size, 102) ||
       HasTlv(out.data(), size, 105) || HasTlv(out.data(), size, 149))
      saw_routing_record = true;
  }

  Expect(saw_routing_record,
         "routing crossover test did not inherit a protected option");
}

void TestCrossOverSynthesizesMissingTransferScaffold() {
  std::vector<uint8_t> first;
  std::vector<uint8_t> second;
  AppendTlv(&first, 6, Bytes("X-Only: 1"));
  AppendTlv(&second, 200, {0, 0, 0, 80});
  std::array<uint8_t, 512> out = {};
  const size_t size = legacy_tlv_mutator::CrossOver(
      first.data(), first.size(), second.data(), second.size(), out.data(),
      out.size(), 7);
  Expect(legacy_tlv_mutator::IsStructurallyValid(out.data(), size),
         "scaffold crossover result was invalid");
  Expect(HasTlv(out.data(), size, 1),
         "crossover did not synthesize a missing URL");
  Expect(HasTlv(out.data(), size, 2),
         "crossover did not synthesize a missing initial response");
}

}  // namespace

int main() {
  TestValidation();
  TestCanonicalRoutingValuePolicy();
  TestStructuredMutationsStayValidAndBounded();
  TestStructuredMutationRepairsTransferScaffold();
  TestGeneratedRoutingValuesStayOnLoopback();
  TestInheritedRoutingValuesAreCanonicalized();
  TestRawRoutingRepairPreservesMalformedCoverage();
  TestRoutingRepairWithoutGrowthCapacity();
  TestInvalidInputRepairAndEmptyInput();
  TestRawMutationIsControlledAndDeterministicWithoutLibFuzzer();
  TestRecordCrossOver();
  TestCrossOverCanonicalizesInheritedRoutingValues();
  TestCrossOverSynthesizesMissingTransferScaffold();
  return 0;
}
