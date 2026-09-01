/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "legacy_tlv_mutator.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define LEGACY_TLV_MUTATOR_MEMORY_SANITIZER 1
#endif
#endif

#ifndef LEGACY_TLV_MUTATOR_MEMORY_SANITIZER
#define LEGACY_TLV_MUTATOR_MEMORY_SANITIZER 0
#endif

#ifdef LEGACY_TLV_MUTATOR_CHECK_HARNESS_CONSTANTS
#include "curl_fuzzer.h"

static_assert(TLV_TYPE_URL == 1, "legacy TLV URL ID changed");
static_assert(TLV_TYPE_MIME_PART_NAME == 14, "legacy MIME TLV IDs changed");
static_assert(TLV_TYPE_MIME_PART_DATA == 15, "legacy MIME TLV IDs changed");
static_assert(TLV_TYPE_HSTS == 51, "legacy disabled TLV IDs changed");
static_assert(TLV_TYPE_PROXY == 53, "legacy routing TLV IDs changed");
static_assert(TLV_TYPE_FTPPORT == 102, "legacy routing TLV IDs changed");
static_assert(TLV_TYPE_INTERFACE == 105, "legacy routing TLV IDs changed");
static_assert(TLV_TYPE_DNS_INTERFACE == 129,
              "legacy routing audit TLV IDs changed");
static_assert(TLV_TYPE_PRE_PROXY == 149,
              "legacy routing TLV IDs changed");
static_assert(TLV_TYPE_ECH == 161, "legacy string TLV range changed");
static_assert(TLV_TYPE_PORT == 200, "legacy integer TLV range changed");
static_assert(TLV_TYPE_TCP_KEEPCNT == 293,
              "legacy integer TLV range changed");
static_assert(TLV_TYPE_SSLVERSION == 300,
              "legacy enum TLV range changed");
static_assert(TLV_TYPE_PROXY_SSLVERSION == 312,
              "legacy enum TLV range changed");
static_assert(TLV_TYPE_RESUME_FROM_LARGE == 320,
              "legacy large-value TLV range changed");
static_assert(TLV_TYPE_TIMEVALUE_LARGE == 325,
              "legacy large-value TLV range changed");
#endif

#if defined(__clang__) || defined(__GNUC__)
/**
 * Optional libFuzzer byte mutator supplied by the fuzzing runtime.
 *
 * Weak linkage keeps standalone replay and unit-test binaries linkable. The
 * wrapper below selects a small deterministic fallback when the symbol is not
 * present, so both build modes exercise the same higher-level policy.
 */
extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size,
                                    size_t max_size) __attribute__((weak));
#endif

namespace legacy_tlv_mutator {
namespace {

/* The fast path is a policy pipeline: consult one ID policy, build a bounded
 * index over valid wire records, then perform one local edit. Mutate chooses
 * between structure preservation and a rare raw escape before parsing;
 * CrossOver uses the same index to splice only whole records. The shared parse
 * contract keeps repair, mutation, validation, and crossover from drifting
 * apart. */

/* All parser state is fixed-size and stack-resident. The record bound makes
 * work predictable for adversarial corpora, while the field/growth bounds
 * keep one large payload from dominating a mutation or one execution. */
constexpr size_t kTlvHeaderSize = 6;
constexpr size_t kMaxParsedRecords = 512;
constexpr size_t kMaxValueGrowth = 4096;
constexpr size_t kMaxFieldToMutate = 64 * 1024;
constexpr uint16_t kMaximumKnownType = 325;

/**
 * Semantic representation classes that are safe to mutate interchangeably.
 *
 * In particular, numeric options must remain four bytes and MIME values need
 * nested framing; classifying them here prevents a type mutation from silently
 * producing a record that the harness rejects before curl is called.
 */
enum class ValueKind {
  kUnknown,
  kBytes,
  kString,
  kU32,
  kMime,
};

/**
 * Mutation policy for one legacy option type.
 *
 * `kind` protects the value-shape invariant. `repeatable` is mutation policy:
 * list-like entries can contribute independently, whereas duplicate scalar or
 * last-write-wins records mostly bloat a child and obscure which value won.
 */
struct TypeInfo {
  ValueKind kind;
  bool repeatable;
};

/**
 * Non-owning index for a validated top-level record.
 *
 * Storing offsets instead of pointers keeps the descriptor valid across array
 * relocation and avoids per-record allocation. A descriptor is intentionally
 * used for only one edit because an edit can invalidate later offsets.
 */
struct Record {
  size_t offset;
  uint32_t length;
  uint16_t type;

  /** Returns the payload boundary used by value-only mutations. */
  size_t value_offset() const { return offset + kTlvHeaderSize; }
  /** Returns the first byte after this record for bounded tail moves. */
  size_t end_offset() const { return value_offset() + length; }
  /** Returns the wire footprint used by insert, erase, and crossover. */
  size_t total_size() const { return kTlvHeaderSize + length; }
};

/**
 * Allocation-free parse result shared by all structured operations.
 *
 * `records_size` always marks the end of the validated prefix, even on error;
 * that invariant lets mutation cheaply repair corrupt inputs. `valid` means
 * the whole input has acceptable legacy trailing-byte semantics, while the
 * limit flag distinguishes bounded-parser exhaustion for diagnostics/policy.
 */
struct ParsedInput {
  /** Fixed storage makes parse cost independent of allocator behavior. */
  std::array<Record, kMaxParsedRecords> records;
  /** Descriptors in `[0, count)` are validated and safe to index. */
  size_t count;
  /** Boundary after the last validated record, including on failure. */
  size_t records_size;
  /** Bytes not represented by records; short tails are wire-compatible. */
  size_t trailing_size;
  /** True only when the complete input satisfies structured preconditions. */
  bool valid;
  /** Records resource-bound rejection separately from malformed framing. */
  bool hit_record_limit;
};

/**
 * Small deterministic generator isolated from the C library's global state.
 *
 * Reproducibility from libFuzzer's seed is required for minimizing failures,
 * and local state makes mutation safe when several fuzzing jobs share a
 * process.
 */
class Random {
 public:
  /** Decorrelates low-entropy seeds before the first SplitMix64 choice. */
  explicit Random(uint64_t seed)
      : state_(seed + UINT64_C(0x9e3779b97f4a7c15)) {}

  /** Advances a stable full-width stream used for all policy choices. */
  uint64_t Next() {
    uint64_t z = (state_ += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
  }

  /** Selects a bounded index; zero keeps empty-case callers simple. */
  size_t Index(size_t count) {
    return count ? static_cast<size_t>(Next() % count) : 0;
  }

  /** Makes deliberately rare policy branches explicit and reproducible. */
  bool OneIn(unsigned int count) {
    return count && (Next() % count) == 0;
  }

 private:
  uint64_t state_;
};

/** Reads a big-endian type without host alignment assumptions. */
uint16_t ReadU16(const uint8_t *data) {
  return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                               static_cast<uint16_t>(data[1]));
}

/** Reads a length/value without host endianness or alignment assumptions. */
uint32_t ReadU32(const uint8_t *data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         static_cast<uint32_t>(data[3]);
}

/** Writes a type in the exact byte order consumed by the legacy harness. */
void WriteU16(uint8_t *data, uint16_t value) {
  data[0] = static_cast<uint8_t>(value >> 8);
  data[1] = static_cast<uint8_t>(value);
}

/** Writes a length/value in the byte order consumed by the legacy harness. */
void WriteU32(uint8_t *data, uint32_t value) {
  data[0] = static_cast<uint8_t>(value >> 24);
  data[1] = static_cast<uint8_t>(value >> 16);
  data[2] = static_cast<uint8_t>(value >> 8);
  data[3] = static_cast<uint8_t>(value);
}

/** Identifies payloads interpreted as server bytes rather than C strings. */
bool IsResponseType(uint16_t type) {
  return type == 2 || (type >= 17 && type <= 26) || type == 31 ||
         type == 32;
}

/**
 * Returns the non-resolving endpoint used for a routing option.
 *
 * These four options can reinterpret an arbitrary string as a hostname outside
 * the harness's CONNECT_TO wildcard. Keeping the canonical spellings in one
 * function makes insertion and post-mutation repair enforce the same safety
 * policy. PRE_PROXY deliberately uses a SOCKS scheme so repair still reaches
 * its option parser instead of converting the option into an ordinary proxy.
 *
 * CURLOPT_DNS_INTERFACE (type 129) is intentionally absent. With c-ares it is
 * passed to ares_set_local_dev as a device name; it is not resolved as a host,
 * and builds without c-ares reject it at setopt time. Canonicalizing it would
 * therefore discard interface-binding coverage without removing a synchronous
 * resolver stall.
 */
const char *CanonicalRoutingValueImpl(uint16_t type) {
  switch(type) {
    case 53:  // CURLOPT_PROXY
      return "http://127.0.0.1";
    case 102:  // CURLOPT_FTPPORT
    case 105:  // CURLOPT_INTERFACE
      return "127.0.0.1";
    case 149:  // CURLOPT_PRE_PROXY
      return "socks5://127.0.0.1";
    default:
      return nullptr;
  }
}

/**
 * Identifies strings whose arbitrary values can escape the in-process peer.
 * Centralizing the predicate through CanonicalRoutingValue prevents the
 * mutation exclusions from drifting away from final output repair.
 */
bool IsLatencySensitiveStringType(uint16_t type) {
  return CanonicalRoutingValueImpl(type) != nullptr;
}

/** Identifies non-range-based options whose payload is exactly one u32. */
bool IsTopLevelU32Type(uint16_t type) {
  switch(type) {
    case 16:
    case 27:
    case 28:
    case 29:
    case 33:
    case 34:
    case 38:
    case 40:
    case 46:
    case 48:
    case 49:
    case 50:
    case 54:
      return true;
    default:
      return false;
  }
}

/**
 * Centralizes the declarative legacy ID policy used by parsing and mutation.
 * Keeping disabled IDs and wire kinds in one mapping prevents generators from
 * drifting away from the harness switch table.
 */
TypeInfo GetTypeInfo(uint16_t type) {
  /* IDs 14 and 15 are valid only inside a type-13 MIME record. ID 51 is
   * declared for corpus compatibility but intentionally disabled by the
   * harness. */
  if(type == 14 || type == 15 || type == 51)
    return {ValueKind::kUnknown, false};

  if(type >= 1 && type <= 54) {
    if(type == 13)
      return {ValueKind::kMime, true};
    if(IsResponseType(type) || type == 8)
      return {ValueKind::kBytes, false};
    if(IsTopLevelU32Type(type))
      return {ValueKind::kU32, false};
    return {ValueKind::kString, type == 6 || type == 11};
  }

  /* The legacy ID layout deliberately groups string and integer options.
   * Keep the two API-misuse-prone POSTFIELDSIZE IDs out of the mutator because
   * their parser cases are disabled. */
  if(type >= 100 && type <= 161)
    return {ValueKind::kString, false};
  if(type >= 200 && type <= 293 && type != 212)
    return {ValueKind::kU32, false};
  if(type >= 300 && type <= 312)
    return {ValueKind::kU32, false};
  if(type >= 320 && type <= 325 && type != 322)
    return {ValueKind::kU32, false};

  return {ValueKind::kUnknown, false};
}

/**
 * Validates the nested subset accepted inside a MIME record.
 *
 * MIME values are intentionally treated as atomic by mutation, so this one
 * linear check is enough to guarantee later top-level edits cannot expose a
 * malformed nested length or an illegal top-level/nested ID mix.
 */
bool ValidateMimeValue(const uint8_t *data, size_t size) {
  size_t offset = 0;
  while(offset + kTlvHeaderSize <= size) {
    const uint16_t type = ReadU16(data + offset);
    const uint32_t length = ReadU32(data + offset + 2);
    if(type != 14 && type != 15)
      return false;
    if(static_cast<size_t>(length) > size - offset - kTlvHeaderSize)
      return false;
    offset += kTlvHeaderSize + length;
  }
  /* The harness treats fewer than six leftover bytes as an exhausted nested
   * TLV stream, so preserve that wire-compatible behavior. */
  return size - offset < kTlvHeaderSize;
}

/**
 * Scans a legacy TLV stream into bounded, non-owning record descriptors.
 *
 * Parsing stops at the first semantic or framing failure and always publishes
 * the end of the valid prefix. The structured path can therefore repair an
 * input by truncation without rescanning or allocating. A fixed descriptor
 * array bounds latency for very large/adversarial inputs. Fewer than six final
 * bytes remain valid because the harness itself treats that suffix as EOF.
 */
ParsedInput Parse(const uint8_t *data, size_t size) {
  ParsedInput parsed = {};
  std::array<uint8_t, kMaximumKnownType + 1> seen = {};
  size_t offset = 0;

  while(offset + kTlvHeaderSize <= size) {
    if(parsed.count == parsed.records.size()) {
      parsed.records_size = offset;
      parsed.trailing_size = size - offset;
      parsed.hit_record_limit = true;
      return parsed;
    }

    const uint16_t type = ReadU16(data + offset);
    const uint32_t length = ReadU32(data + offset + 2);
    const TypeInfo info = GetTypeInfo(type);
    if(info.kind == ValueKind::kUnknown ||
       static_cast<size_t>(length) > size - offset - kTlvHeaderSize) {
      parsed.records_size = offset;
      parsed.trailing_size = size - offset;
      return parsed;
    }
    if(info.kind == ValueKind::kU32 && length != 4) {
      parsed.records_size = offset;
      parsed.trailing_size = size - offset;
      return parsed;
    }
    if(info.kind == ValueKind::kMime &&
       !ValidateMimeValue(data + offset + kTlvHeaderSize, length)) {
      parsed.records_size = offset;
      parsed.trailing_size = size - offset;
      return parsed;
    }
    if(!info.repeatable && seen[type]) {
      parsed.records_size = offset;
      parsed.trailing_size = size - offset;
      return parsed;
    }

    seen[type] = 1;
    parsed.records[parsed.count++] = {offset, length, type};
    offset += kTlvHeaderSize + length;
    parsed.records_size = offset;
  }

  parsed.trailing_size = size - offset;
  parsed.valid = true;
  return parsed;
}

/** Tests singleton presence when choosing insertions or replacement types. */
bool HasType(const ParsedInput &parsed, uint16_t type) {
  for(size_t i = 0; i < parsed.count; ++i) {
    if(parsed.records[i].type == type)
      return true;
  }
  return false;
}

/* The supported top-level IDs form compact ranges with five intentional
 * holes. Mapping an ordinal avoids a 224-entry table while keeping selection
 * uniform and O(1). */
constexpr size_t kKnownTopLevelTypeCount = 224;

/**
 * Maps a dense selection ordinal to a legal top-level legacy type ID.
 * The arithmetic encoding excludes nested and disabled holes without a large
 * lookup table, keeping the hot selection path cache-small and uniform.
 */
uint16_t TypeFromOrdinal(size_t ordinal) {
  if(ordinal < 51) {
    uint16_t type = static_cast<uint16_t>(ordinal + 1);
    if(type >= 14)
      type = static_cast<uint16_t>(type + 2);
    if(type >= 51)
      ++type;
    return type;
  }
  ordinal -= 51;

  if(ordinal < 62)
    return static_cast<uint16_t>(100 + ordinal);
  ordinal -= 62;

  if(ordinal < 93) {
    uint16_t type = static_cast<uint16_t>(200 + ordinal);
    if(type >= 212)
      ++type;
    return type;
  }
  ordinal -= 93;

  if(ordinal < 13)
    return static_cast<uint16_t>(300 + ordinal);
  ordinal -= 13;

  uint16_t type = static_cast<uint16_t>(320 + ordinal);
  if(type >= 322)
    ++type;
  return type;
}

/** Selects uniformly from the legal top-level IDs encoded above. */
uint16_t RandomKnownType(Random *random) {
  return TypeFromOrdinal(random->Index(kKnownTopLevelTypeCount));
}

/**
 * Supplies a protocol-specific URL that reaches the selected legacy target.
 * Seed records must use the compiled harness's scheme or otherwise-valid
 * structured mutations still exit before exercising the intended protocol.
 */
const char *DefaultUrl() {
#if defined(FUZZ_PROTOCOLS_DICT)
  return "dict://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_FILE)
  return "file:///dev/null";
#elif defined(FUZZ_PROTOCOLS_FTP)
  return "ftp://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_GOPHER)
  return "gopher://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_HTTPS)
  return "https://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_IMAP)
  return "imap://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_LDAP)
  return "ldap://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_MQTT)
  return "mqtt://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_POP3)
  return "pop3://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_RTMP)
  return "rtmp://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_RTSP)
  return "rtsp://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_SCP)
  return "scp://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_SFTP)
  return "sftp://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_SMB)
  return "smb://127.0.0.1/share";
#elif defined(FUZZ_PROTOCOLS_SMTP)
  return "smtp://127.0.0.1/";
#elif defined(FUZZ_PROTOCOLS_TFTP)
  return "tftp://127.0.0.1/file";
#elif defined(FUZZ_PROTOCOLS_WS)
  return "ws://127.0.0.1/";
#else
  return "http://127.0.0.1/";
#endif
}

/**
 * Supplies a small, coverage-oriented response placeholder for the target.
 * It is not universally parseable, but a plausible greeting/status advances
 * common state machines farther than an arbitrary byte on first insertion.
 */
const char *DefaultResponse() {
#if defined(FUZZ_PROTOCOLS_FTP) || defined(FUZZ_PROTOCOLS_SMTP)
  return "220 fuzz ready\r\n";
#elif defined(FUZZ_PROTOCOLS_IMAP)
  return "* OK fuzz ready\r\n";
#elif defined(FUZZ_PROTOCOLS_POP3)
  return "+OK fuzz ready\r\n";
#elif defined(FUZZ_PROTOCOLS_RTSP)
  return "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
#elif defined(FUZZ_PROTOCOLS_HTTP) || defined(FUZZ_PROTOCOLS_HTTPS) || \
    defined(FUZZ_PROTOCOLS_WS) || defined(FUZZ_PROTOCOLS_ALL)
  return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
#else
  return "fuzz\r\n";
#endif
}

/**
 * Distinguishes the file harness, where injecting a network response is dead
 * corpus weight, from targets whose transfer path needs peer input.
 */
bool TargetNeedsResponse() {
#if defined(FUZZ_PROTOCOLS_FILE)
  return false;
#else
  return true;
#endif
}

/**
 * Marks the minimal records that keep structured network children executable.
 * Raw mutation may still remove or corrupt them to retain framing coverage.
 */
bool IsRequiredType(uint16_t type) {
  return type == 1 || (TargetNeedsResponse() && type == 2);
}

/**
 * Provides a bounded deterministic byte mutator outside a libFuzzer binary.
 * It keeps unit tests, replay tools, and alternate fuzzing engines functional
 * without pretending to match libFuzzer's richer mutation distribution.
 */
size_t LocalByteMutate(uint8_t *data, size_t size, size_t max_size,
                       Random *random) {
  size = std::min(size, max_size);
  if(!max_size)
    return 0;
  if(!size) {
    data[0] = static_cast<uint8_t>(random->Next());
    return 1;
  }

  switch(random->Index(4)) {
    case 0: {
      const size_t pos = random->Index(size);
      data[pos] ^= static_cast<uint8_t>(1u << random->Index(8));
      break;
    }
    case 1: {
      const size_t pos = random->Index(size);
      data[pos] = static_cast<uint8_t>(random->Next());
      break;
    }
    case 2:
      if(size < max_size) {
        const size_t pos = random->Index(size + 1);
        std::memmove(data + pos + 1, data + pos, size - pos);
        data[pos] = static_cast<uint8_t>(random->Next());
        ++size;
      }
      else {
        data[random->Index(size)] ^= 0x80;
      }
      break;
    default: {
      const size_t pos = random->Index(size);
      std::memmove(data + pos, data + pos + 1, size - pos - 1);
      --size;
      break;
    }
  }
  return size;
}

/**
 * Uses libFuzzer's tuned byte mutations when available, with a local fallback.
 * Centralizing this choice gives both the periodic raw path and field mutation
 * identical size bounds and standalone behavior.
 */
size_t ByteMutate(uint8_t *data, size_t size, size_t max_size,
                  Random *random) {
  if(!max_size)
    return 0;
#if defined(__clang__) || defined(__GNUC__)
  if(LLVMFuzzerMutate) {
    const size_t result =
        std::min(LLVMFuzzerMutate(data, size, max_size), max_size);
#if LEGACY_TLV_MUTATOR_MEMORY_SANITIZER
    /* libFuzzer clears stale MSan shadow before the target callback, but a
     * nested LLVMFuzzerMutate() returns before that boundary. Its result is
     * logically initialized, so unpoison it before the finalizer parses it. */
    __msan_unpoison(data, result);
#endif
    return result;
  }
#endif
  return LocalByteMutate(data, size, max_size, random);
}

/**
 * Generates numeric payloads biased toward API and conversion boundaries.
 * Occasional random values retain breadth, while common powers, signed edges,
 * and maxima reach more useful curl branches than uniformly random u32s alone.
 */
void WriteBoundaryU32(uint8_t *out, Random *random) {
  static constexpr uint32_t kBoundaries[] = {
      0, 1, 2, 3, 4, 7, 8, 15, 16, 255, 256, 1024,
      UINT32_C(0x7fffffff), UINT32_C(0x80000000), UINT32_MAX};
  uint32_t value;
  if(random->OneIn(4))
    value = static_cast<uint32_t>(random->Next());
  else
    value = kBoundaries[random->Index(sizeof(kBoundaries) /
                                      sizeof(kBoundaries[0]))];
  WriteU32(out, value);
}

/**
 * Lightweight immutable payload view used for synthetic record defaults.
 * Static backing avoids allocation and copying until insertion is committed.
 */
struct ByteView {
  const uint8_t *data;
  size_t size;
};

/**
 * Chooses a small payload that satisfies each value class's framing needs.
 * These are coverage-oriented starting points, not fixed corpus templates.
 * Ordinary fields can evolve freely; latency-sensitive routing fields stay on
 * loopback because even valid raw mutations are repaired before execution.
 * Malformed routing records remain available through the raw framing lane.
 */
ByteView DefaultValue(uint16_t type, ValueKind kind) {
  static const uint8_t kOneByte[] = {'A'};
  static const uint8_t kHeader[] = "X-Fuzz: 1";
  static const uint8_t kRecipient[] = "a@b";
  static const uint8_t kMime[] = {
      0, 14, 0, 0, 0, 1, 'n',
      0, 15, 0, 0, 0, 1, 'v'};

  if(type == 1) {
    const char *url = DefaultUrl();
    return {reinterpret_cast<const uint8_t *>(url), std::strlen(url)};
  }
  if(IsResponseType(type)) {
    const char *response = DefaultResponse();
    return {reinterpret_cast<const uint8_t *>(response),
            std::strlen(response)};
  }
  if(type == 6)
    return {kHeader, sizeof(kHeader) - 1};
  if(type == 11)
    return {kRecipient, sizeof(kRecipient) - 1};
  const char *routing_value = CanonicalRoutingValueImpl(type);
  if(routing_value)
    return {reinterpret_cast<const uint8_t *>(routing_value),
            std::strlen(routing_value)};
  if(kind == ValueKind::kMime)
    return {kMime, sizeof(kMime)};
  return {kOneByte, sizeof(kOneByte)};
}

/**
 * Rewrites resolver-sensitive records after mutation or crossover.
 *
 * A valid raw edit can change only a proxy hostname and otherwise look
 * executable; canonicalizing that case closes the resolver-stall lane.
 * Structured edits and crossover also pass here because they can inherit an
 * unsafe value from an older corpus entry even though they never mutate that
 * value directly. Semantically malformed streams take the length-preserving
 * neutralization path below so their parser shape remains available.
 *
 * Records are processed from the end so resizing a value never invalidates an
 * offset that remains to be visited. If the preferred loopback spelling cannot
 * fit, an empty string is used as the safe fallback: curl treats it as disabled
 * proxy/interface/FTPPORT configuration, and shrinking always fits. Short
 * wire-compatible trailing bytes move with the tail and remain intact.
 */
size_t CanonicalizeRoutingValues(uint8_t *data, size_t size,
                                 size_t max_size) {
  const ParsedInput parsed = Parse(data, size);
  if(!parsed.valid) {
    /* The legacy harness rejects most malformed streams before transfer, but
     * malformed MIME records are tolerated and an oversized record list can
     * exceed this mutator's descriptor bound. Scan only independently framed
     * top-level records and NUL their first routing byte. This preserves every
     * type, length, offset, and malformed suffix while making curl observe an
     * empty C string if the harness does continue to a transfer. A broken
     * length stops the scan at the same boundary that stops the harness. */
    size_t offset = 0;
    while(offset + kTlvHeaderSize <= size) {
      const uint32_t length = ReadU32(data + offset + 2);
      if(static_cast<size_t>(length) > size - offset - kTlvHeaderSize)
        break;
      if(length &&
         IsLatencySensitiveStringType(ReadU16(data + offset)))
        data[offset + kTlvHeaderSize] = 0;
      offset += kTlvHeaderSize + length;
    }
    return size;
  }

  for(size_t index = parsed.count; index > 0; --index) {
    const Record &record = parsed.records[index - 1];
    const char *canonical = CanonicalRoutingValueImpl(record.type);
    if(!canonical)
      continue;

    size_t canonical_size = std::strlen(canonical);
    const size_t fixed_size = size - record.length;
    if(canonical_size > max_size - fixed_size)
      canonical_size = 0;

    const uint8_t *value = data + record.value_offset();
    if(record.length == canonical_size &&
       (!canonical_size ||
        std::memcmp(value, canonical, canonical_size) == 0))
      continue;

    const size_t tail_size = size - record.end_offset();
    std::memmove(data + record.value_offset() + canonical_size,
                 data + record.end_offset(), tail_size);
    WriteU32(data + record.offset + 2,
             static_cast<uint32_t>(canonical_size));
    if(canonical_size)
      std::memcpy(data + record.value_offset(), canonical, canonical_size);
    size = fixed_size + canonical_size;
  }
  return size;
}

/**
 * Chooses an insertable type while prioritizing transfer-enabling core records.
 * URL and response prerequisites are filled first; later choices mix a focused
 * high-value set with the complete ID space. Bounded retries enforce singleton
 * cardinality without turning mutation time into corpus-dependent searching.
 */
uint16_t PickInsertType(const ParsedInput &parsed, Random *random) {
  if(!HasType(parsed, 1))
    return 1;
  if(TargetNeedsResponse() && !HasType(parsed, 2))
    return 2;

  static constexpr uint16_t kCoreTypes[] = {
      1, 2, 17, 6, 8, 11, 13, 16, 27, 28, 29, 30, 40, 48, 49,
      52, 53, 54, 200, 214, 222, 227, 240, 258, 262, 280};

  for(size_t attempt = 0; attempt < 64; ++attempt) {
    const uint16_t type = random->OneIn(2)
                              ? RandomKnownType(random)
                              : kCoreTypes[random->Index(
                                    sizeof(kCoreTypes) /
                                    sizeof(kCoreTypes[0]))];
    const TypeInfo info = GetTypeInfo(type);
    if(info.repeatable || !HasType(parsed, type))
      return type;
  }
  return 6;  // Headers are repeatable and useful for every network protocol.
}

/**
 * Inserts one self-consistent record at an existing record boundary.
 *
 * Choosing the type and default before moving bytes makes capacity failure a
 * no-op. Boundary insertion and big-endian header repair preserve every
 * existing record while introducing a new curl option in one mutation step.
 */
size_t InsertRecord(uint8_t *data, size_t size, size_t max_size,
                    const ParsedInput &parsed, Random *random) {
  const uint16_t type = PickInsertType(parsed, random);
  const TypeInfo info = GetTypeInfo(type);
  uint8_t numeric_value[4];
  ByteView value = DefaultValue(type, info.kind);
  if(info.kind == ValueKind::kU32) {
    WriteBoundaryU32(numeric_value, random);
    value = {numeric_value, sizeof(numeric_value)};
  }

  if(value.size > std::numeric_limits<uint32_t>::max() ||
     kTlvHeaderSize + value.size > max_size - std::min(size, max_size))
    return size;

  const size_t boundary_index = random->Index(parsed.count + 1);
  const size_t insert_at = boundary_index == parsed.count
                               ? parsed.records_size
                               : parsed.records[boundary_index].offset;
  const size_t added = kTlvHeaderSize + value.size;
  std::memmove(data + insert_at + added, data + insert_at, size - insert_at);
  WriteU16(data + insert_at, type);
  WriteU32(data + insert_at + 2, static_cast<uint32_t>(value.size));
  if(value.size)
    std::memcpy(data + insert_at + kTlvHeaderSize, value.data, value.size);
  return size + added;
}

/**
 * Erases one optional record while preserving framing and transfer scaffolding.
 * Whole-record deletion explores option interactions without producing broken
 * lengths; retaining URL/initial-response records avoids systematic fast-path
 * loss and socket stalls in otherwise-structured children.
 */
size_t EraseRecord(uint8_t *data, size_t size, const ParsedInput &parsed,
                   Random *random) {
  if(!parsed.count)
    return size;
  const size_t start = random->Index(parsed.count);
  for(size_t n = 0; n < parsed.count; ++n) {
    const Record &record = parsed.records[(start + n) % parsed.count];
    if(IsRequiredType(record.type))
      continue;
    std::memmove(data + record.offset, data + record.end_offset(),
                 size - record.end_offset());
    return size - record.total_size();
  }
  return size;
}

/**
 * Duplicates only records whose harness semantics permit repetition.
 * This targets lists such as headers/MIME parts while avoiding inert duplicate
 * singletons and performs no edit when capacity cannot hold the whole record.
 */
size_t DuplicateRecord(uint8_t *data, size_t size, size_t max_size,
                       const ParsedInput &parsed, Random *random) {
  if(!parsed.count)
    return size;
  const size_t start = random->Index(parsed.count);
  for(size_t n = 0; n < parsed.count; ++n) {
    const Record &record = parsed.records[(start + n) % parsed.count];
    if(!GetTypeInfo(record.type).repeatable)
      continue;
    if(record.total_size() > max_size - size)
      return size;
    const size_t at = record.end_offset();
    std::memmove(data + at + record.total_size(), data + at, size - at);
    /* memmove above can move the source only when it is after `at`; this
     * record ends exactly at `at`, so its bytes remain available. */
    std::memmove(data + at, data + record.offset, record.total_size());
    return size + record.total_size();
  }
  return size;
}

/**
 * Swaps neighboring complete records to explore order-sensitive option setup.
 * Restricting the permutation to one adjacent pair keeps evolutionary locality
 * and preserves every record's bytes and framing.
 */
size_t SwapAdjacentRecords(uint8_t *data, size_t size,
                           const ParsedInput &parsed, Random *random) {
  if(parsed.count < 2)
    return size;
  const size_t index = random->Index(parsed.count - 1);
  const Record &first = parsed.records[index];
  const Record &second = parsed.records[index + 1];
  std::rotate(data + first.offset, data + second.offset,
              data + second.end_offset());
  return size;
}

/**
 * Rebinds an optional record to another option with the same representation.
 * Required transfer records are retained. Matching kinds protect u32/MIME
 * shapes, and routing fields are never created from arbitrary string payloads;
 * their loopback defaults remain available through direct insertion.
 */
size_t ChangeRecordType(uint8_t *data, size_t size,
                        const ParsedInput &parsed, Random *random) {
  if(!parsed.count)
    return size;
  const size_t start = random->Index(parsed.count);
  for(size_t n = 0; n < parsed.count; ++n) {
    const Record &record = parsed.records[(start + n) % parsed.count];
    if(IsRequiredType(record.type))
      continue;
    const TypeInfo original = GetTypeInfo(record.type);

    for(size_t attempt = 0; attempt < kKnownTopLevelTypeCount; ++attempt) {
      const uint16_t replacement = RandomKnownType(random);
      const TypeInfo candidate = GetTypeInfo(replacement);
      if(replacement != record.type && candidate.kind == original.kind &&
         !IsLatencySensitiveStringType(replacement) &&
         (candidate.repeatable || !HasType(parsed, replacement))) {
        WriteU16(data + record.offset, replacement);
        return size;
      }
    }
  }
  return size;
}

/**
 * Mutates one payload while shielding the rest of the TLV stream.
 *
 * Numeric fields use boundary values; nested MIME and connection-routing
 * fields remain atomic so an ordinary field edit cannot manufacture a routing
 * endpoint. The raw lane still explores surrounding type/length corruption,
 * but its independently framed routing strings are canonicalized before curl
 * can resolve them. For other byte/string fields, the untouched suffix is
 * temporarily parked at the high end of the selected field's capacity. This
 * gives LLVMFuzzerMutate a contiguous resizable buffer without letting it
 * consume following headers; the suffix is then relocated behind the new value
 * and the length repaired. Per-field size/growth caps keep this hot operation
 * bounded.
 */
size_t MutateRecordValue(uint8_t *data, size_t size, size_t max_size,
                         const ParsedInput &parsed, Random *random) {
  if(!parsed.count)
    return size;
  const size_t start = random->Index(parsed.count);

  for(size_t n = 0; n < parsed.count; ++n) {
    const Record &record = parsed.records[(start + n) % parsed.count];
    const TypeInfo info = GetTypeInfo(record.type);
    if(info.kind == ValueKind::kMime ||
       IsLatencySensitiveStringType(record.type) ||
       record.length > kMaxFieldToMutate)
      continue;

    if(info.kind == ValueKind::kU32) {
      WriteBoundaryU32(data + record.value_offset(), random);
      return size;
    }

    const size_t fixed_size = size - record.length;
    if(fixed_size > max_size)
      return size;
    size_t capacity = max_size - fixed_size;
    capacity = std::min(capacity,
                        static_cast<size_t>(std::numeric_limits<uint32_t>::max()));
    if(capacity > record.length + kMaxValueGrowth)
      capacity = record.length + kMaxValueGrowth;

    /* Relocate the tail before exposing the value to a general byte mutator.
     * `capacity` is bounded above and at least the old length, so the temporary
     * destination cannot overlap the active value or exceed `max_size`. */
    const size_t tail_size = size - record.end_offset();
    uint8_t *value = data + record.value_offset();
    std::memmove(value + capacity, data + record.end_offset(), tail_size);
    const size_t new_length =
        ByteMutate(value, record.length, capacity, random);
    std::memmove(value + new_length, value + capacity, tail_size);
    WriteU32(data + record.offset + 2, static_cast<uint32_t>(new_length));
    return fixed_size + new_length;
  }
  return size;
}

/**
 * Bounded byte-level crossover for parents that cannot support record splicing.
 * Keeping malformed parents alive is important for framing coverage, while
 * limiting both slices guarantees the libFuzzer output contract.
 */
size_t LocalByteCrossOver(const uint8_t *data1, size_t size1,
                          const uint8_t *data2, size_t size2,
                          uint8_t *out, size_t max_out_size,
                          Random *random) {
  if(!max_out_size)
    return 0;

  const size_t first_take =
      std::min(random->Index(size1 + 1), max_out_size);
  if(first_take)
    std::memcpy(out, data1, first_take);

  const size_t second_start = random->Index(size2 + 1);
  const size_t second_take =
      std::min(size2 - second_start, max_out_size - first_take);
  if(second_take)
    std::memcpy(out + first_take, data2 + second_start, second_take);

  size_t out_size = first_take + second_take;
  if(!out_size) {
    if(size1)
      out[out_size++] = data1[random->Index(size1)];
    else if(size2)
      out[out_size++] = data2[random->Index(size2)];
  }
  return out_size;
}

/**
 * Appends one complete record under the mutator's duplicate policy.
 * Returning false only for capacity exhaustion lets crossover stop cleanly;
 * skipped last-write-wins duplicates do not prevent useful later records from
 * being inherited.
 */
bool AppendRecord(const uint8_t *source, const Record &record,
                  uint8_t *out, size_t max_out_size, size_t *out_size,
                  std::array<uint8_t, kMaximumKnownType + 1> *seen) {
  const TypeInfo info = GetTypeInfo(record.type);
  if(!info.repeatable && (*seen)[record.type])
    return true;
  if(record.total_size() > max_out_size - *out_size)
    return false;

  std::memcpy(out + *out_size, source + record.offset, record.total_size());
  *out_size += record.total_size();
  (*seen)[record.type] = 1;
  return true;
}

/** Finds a validated record without reparsing or allocating. */
const Record *FindRecord(const ParsedInput &parsed, uint16_t type) {
  for(size_t i = 0; i < parsed.count; ++i) {
    if(parsed.records[i].type == type)
      return &parsed.records[i];
  }
  return nullptr;
}

/**
 * Appends a coverage-oriented default when neither parent has a prerequisite.
 * This makes a structured child executable without weakening invalid-parent
 * fallback or manufacturing arbitrary connection endpoints.
 */
bool AppendDefaultRecord(uint16_t type, uint8_t *out, size_t max_out_size,
                         size_t *out_size,
                         std::array<uint8_t, kMaximumKnownType + 1> *seen) {
  const TypeInfo info = GetTypeInfo(type);
  const ByteView value = DefaultValue(type, info.kind);
  if(value.size > std::numeric_limits<uint32_t>::max() ||
     kTlvHeaderSize + value.size > max_out_size - *out_size)
    return false;

  WriteU16(out + *out_size, type);
  WriteU32(out + *out_size + 2, static_cast<uint32_t>(value.size));
  if(value.size)
    std::memcpy(out + *out_size + kTlvHeaderSize, value.data, value.size);
  *out_size += kTlvHeaderSize + value.size;
  (*seen)[type] = 1;
  return true;
}

/**
 * Inherits a required record from either parent, or synthesizes its default.
 * Random parent choice retains genetic diversity when both provide the record;
 * appending prerequisites first ensures optional records cannot consume their
 * output capacity.
 */
bool AppendRequiredRecord(
    uint16_t type, const uint8_t *data1, const ParsedInput &first,
    const uint8_t *data2, const ParsedInput &second, uint8_t *out,
    size_t max_out_size, size_t *out_size,
    std::array<uint8_t, kMaximumKnownType + 1> *seen, Random *random) {
  const Record *first_record = FindRecord(first, type);
  const Record *second_record = FindRecord(second, type);
  if(first_record && second_record && random->OneIn(2)) {
    std::swap(first_record, second_record);
    std::swap(data1, data2);
  }
  if(first_record)
    return AppendRecord(data1, *first_record, out, max_out_size, out_size,
                        seen);
  if(second_record)
    return AppendRecord(data2, *second_record, out, max_out_size, out_size,
                        seen);
  return AppendDefaultRecord(type, out, max_out_size, out_size, seen);
}

}  // namespace

/** Shares the routing policy with the execution-time legacy harness guard. */
const char *CanonicalRoutingValue(uint16_t type) {
  return CanonicalRoutingValueImpl(type);
}

/**
 * Applies one reproducible mutation under the public structural/raw policy.
 * One record-aware edit per structured call preserves locality for libFuzzer's
 * evolutionary search while repairing malformed ancestors back into inputs
 * that reach curl quickly.
 */
size_t Mutate(uint8_t *data, size_t size, size_t max_size,
              unsigned int seed) {
  size = std::min(size, max_size);
  Random random(static_cast<uint64_t>(seed) ^
                (static_cast<uint64_t>(size) << 32));
  size_t result = size;

  /* Structure-aware edits dominate because valid options drive curl coverage.
   * A scheduled raw escape hatch still explores unknown IDs, corrupt lengths,
   * and trailing-byte states that a validity-preserving mutator cannot make.
   * Every lane rejoins below so a raw edit that happens to remain executable
   * cannot smuggle a blocking hostname past routing repair. */
  if(seed % kRawMutationPeriod == 0) {
    result = ByteMutate(data, size, max_size, &random);
  }
  else {
    ParsedInput parsed = Parse(data, size);
    if(!parsed.valid) {
      /* Parse exposes the last trustworthy boundary. Retain that prefix,
       * discard the corrupt record/tail, then insert a valid option so repair
       * is itself a productive mutation. Oversized record lists are compacted
       * as well; the periodic raw path separately preserves stress-input
       * exploration. */
      size = parsed.records_size;
      parsed = Parse(data, size);
      result = InsertRecord(data, size, max_size, parsed, &random);
    }
    else if(!HasType(parsed, 1) ||
            (TargetNeedsResponse() && !HasType(parsed, 2)) ||
            !parsed.count) {
      /* A structurally valid stream may still lack enough transfer scaffolding
       * to reach curl or feed its fake peer. Repair one missing prerequisite
       * before dispatch so structured mutation converges on executable inputs. */
      result = InsertRecord(data, size, max_size, parsed, &random);
    }
    else {
      /* Dispatch exactly one local structural operation. Equal-ish weighting
       * keeps growth, shrinkage, order, type, and payload exploration in
       * circulation; duplicate falls back to insertion when no repeatable
       * record is available, avoiding a wasted no-op mutation. */
      switch(random.Index(7)) {
        case 0:
          result = MutateRecordValue(data, size, max_size, parsed, &random);
          break;
        case 1:
          result = InsertRecord(data, size, max_size, parsed, &random);
          break;
        case 2:
          result = EraseRecord(data, size, parsed, &random);
          break;
        case 3:
          result = DuplicateRecord(data, size, max_size, parsed, &random);
          if(result == size)
            result = InsertRecord(data, size, max_size, parsed, &random);
          break;
        case 4:
          result = ChangeRecordType(data, size, parsed, &random);
          break;
        case 5:
          result = SwapAdjacentRecords(data, size, parsed, &random);
          break;
        default:
          result = MutateRecordValue(data, size, max_size, parsed, &random);
          break;
      }
    }
  }

  /* Older corpus records and valid raw edits can both carry routing hostnames.
   * Repair them only after the chosen mutation so no return path bypasses the
   * resolver-stall policy. Malformed raw results retain their framing and
   * continue to exercise the legacy TLV parser. */
  return CanonicalizeRoutingValues(data, result, max_size);
}

/**
 * Builds a useful child from record-aligned pieces of two valid parents.
 * A prefix/suffix splice preserves coherent option groups better than arbitrary
 * bytes, while the duplicate policy and required transfer records keep the
 * child executable. Invalid parents deliberately retain byte crossover so
 * malformed framing survives rather than being repaired away.
 */
size_t CrossOver(const uint8_t *data1, size_t size1,
                 const uint8_t *data2, size_t size2,
                 uint8_t *out, size_t max_out_size,
                 unsigned int seed) {
  Random random(static_cast<uint64_t>(seed) ^
                (static_cast<uint64_t>(size1) << 32) ^ size2);
  const ParsedInput first = Parse(data1, size1);
  const ParsedInput second = Parse(data2, size2);
  /* Invalid inputs still have a valid prefix, but repairing them here would
   * erase the malformed framing that made those parents interesting. Empty
   * inputs have no record genetics, so retain bounded byte crossover. The
   * common routing finalizer changes only a byte child that happens to become a
   * complete executable TLV stream. */
  if(!first.valid || !second.valid || !first.count || !second.count)
    return CanonicalizeRoutingValues(
        out, LocalByteCrossOver(data1, size1, data2, size2, out,
                                max_out_size, &random),
        max_out_size);

  std::array<uint8_t, kMaximumKnownType + 1> seen = {};
  size_t out_size = 0;

  /* Reserve the transfer scaffold before optional inherited records. This
   * prevents a splice from producing a syntactically valid child that stalls
   * waiting for a missing fake-peer response. */
  if(!AppendRequiredRecord(1, data1, first, data2, second, out,
                           max_out_size, &out_size, &seen, &random) ||
     (TargetNeedsResponse() &&
      !AppendRequiredRecord(2, data1, first, data2, second, out,
                            max_out_size, &out_size, &seen, &random)))
    return CanonicalizeRoutingValues(
        out, LocalByteCrossOver(data1, size1, data2, size2, out,
                                max_out_size, &random),
        max_out_size);

  const size_t first_end = 1 + random.Index(first.count);
  const size_t second_start = random.Index(second.count);

  /* Take a non-empty prefix from parent one and a suffix from parent two.
   * AppendRecord copies whole records, suppresses duplicate scalar entries,
   * and respects capacity, so each structured result validates. */
  for(size_t i = 0; i < first_end; ++i) {
    if(!AppendRecord(data1, first.records[i], out, max_out_size,
                     &out_size, &seen))
      break;
  }
  for(size_t i = second_start; i < second.count; ++i) {
    if(!AppendRecord(data2, second.records[i], out, max_out_size,
                     &out_size, &seen))
      break;
  }

  if(!out_size)
    out_size = LocalByteCrossOver(data1, size1, data2, size2, out,
                                 max_out_size, &random);

  /* Crossover inherits payloads verbatim, so route safety must be restored
   * after genetic selection rather than while copying one parent. */
  return CanonicalizeRoutingValues(out, out_size, max_out_size);
}

/** Reuses Parse so validation cannot drift from edit preconditions. */
bool IsStructurallyValid(const uint8_t *data, size_t size) {
  return Parse(data, size).valid;
}

}  // namespace legacy_tlv_mutator

/** LibFuzzer ABI adapter; all policy remains testable in the namespaced API. */
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                           size_t max_size,
                                           unsigned int seed) {
  return legacy_tlv_mutator::Mutate(data, size, max_size, seed);
}

/** LibFuzzer ABI adapter for the record-aware crossover implementation. */
extern "C" size_t LLVMFuzzerCustomCrossOver(
    const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2,
    uint8_t *out, size_t max_out_size, unsigned int seed) {
  return legacy_tlv_mutator::CrossOver(data1, size1, data2, size2, out,
                                       max_out_size, seed);
}
