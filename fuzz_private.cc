/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

// Input-driven fuzzing for small curl-private containers, hostname matching,
// debug wrappers, and the callback surface of an unconnected Happy Eyeballs
// filter. The first byte selects a lane; every action after it comes from the
// input. All per-input allocations, descriptors, peers, and filters are
// released before return.

#include "fuzz_private.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

extern "C" {
#include "curl_setup.h"
#include "cf-ip-happy.h"
#include "cfilters.h"
#include "dynhds.h"
#include "peer.h"
#include "protocol.h"
#include "ptrarray.h"
#include "uint-spbset.h"
#include "urldata.h"
#if defined(USE_OPENSSL) || defined(USE_SCHANNEL)
#include "vtls/hostcheck.h"
#endif

void ptrarray_clear(struct ptrarray *pa);
uint32_t ptrarray_count(struct ptrarray *pa);
void *ptrarray_get(struct ptrarray *pa, uint32_t idx);

bool dynhds_contains(struct dynhds *dynhds, const char *name,
                     size_t namelen);
bool dynhds_ccontains(struct dynhds *dynhds, const char *name);
size_t dynhds_count_name(struct dynhds *dynhds, const char *name,
                         size_t namelen);
size_t dynhds_ccount_name(struct dynhds *dynhds, const char *name);
size_t dynhds_remove(struct dynhds *dynhds, const char *name,
                     size_t namelen);
CURLcode dynhds_set(struct dynhds *dynhds, const char *name,
                    size_t namelen, const char *value, size_t valuelen);
size_t dynhds_cremove(struct dynhds *dynhds, const char *name);

void uint32_spbset_clear(struct uint32_spbset *bset);
}

namespace private_fuzzer {
namespace {

constexpr std::size_t kMaxOperations = 256;
constexpr std::size_t kMaxPointers = 256;
constexpr std::size_t kMaxHeaderFieldLength = 31;
#if defined(USE_OPENSSL) || defined(USE_SCHANNEL)
constexpr std::size_t kMaxHostcheckInputBytes = 4096;
constexpr std::size_t kMaxHostcheckNameLength = 255;
constexpr std::size_t kMaxHostcheckRecords = 32;
#endif

class InputCursor {
 public:
  InputCursor(const std::uint8_t *data, std::size_t size)
      : data_(data), size_(size), offset_(0) {}

  bool empty() const { return offset_ >= size_; }
  std::size_t remaining() const { return size_ - offset_; }

  std::uint8_t TakeByte() {
    return empty() ? 0 : data_[offset_++];
  }

  std::uint32_t TakeU32() {
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index)
      value = (value << 8) | TakeByte();
    return value;
  }

  std::string TakeBytes(std::size_t length) {
    length = length < remaining() ? length : remaining();
    const char *begin = reinterpret_cast<const char *>(data_ + offset_);
    offset_ += length;
    return std::string(begin, length);
  }

 private:
  const std::uint8_t *data_;
  std::size_t size_;
  std::size_t offset_;
};

void FuzzPointerArray(InputCursor input) {
  struct ptrarray pointers;
  std::array<std::uint8_t, kMaxPointers> tokens = {};
  std::vector<void *> expected;
  Curl_ptrarray_init(&pointers);

  for (std::size_t operation = 0;
       operation < kMaxOperations && !input.empty(); ++operation) {
    switch (input.TakeByte()) {
      case '+': {
        const std::size_t token = input.TakeByte();
        if (expected.size() < kMaxPointers &&
            Curl_ptrarray_add(&pointers, &tokens[token]) == CURLE_OK)
          expected.push_back(&tokens[token]);
        break;
      }
      case '0': {
        const CURLcode result = Curl_ptrarray_add(&pointers, nullptr);
        assert(result == CURLE_BAD_FUNCTION_ARGUMENT);
        break;
      }
      case '?': {
        const std::size_t span = expected.size() + 2;
        const std::size_t index = input.TakeByte() % span;
        void *want = index < expected.size() ? expected[index] : nullptr;
        void *actual =
            ptrarray_get(&pointers, static_cast<uint32_t>(index));
        assert(actual == want);
        break;
      }
      case '#': {
        const uint32_t count = ptrarray_count(&pointers);
        assert(count == expected.size());
        break;
      }
      case '-': {
        const std::size_t span = expected.size() + 2;
        const std::size_t index = input.TakeByte() % span;
        void *want = index < expected.size() ? expected[index] : nullptr;
        void *actual = Curl_ptrarray_remove(
            &pointers, static_cast<uint32_t>(index));
        assert(actual == want);
        if (index < expected.size())
          expected.erase(expected.begin() + static_cast<std::ptrdiff_t>(index));
        break;
      }
      case 'C':
        ptrarray_clear(&pointers);
        expected.clear();
        break;
      default:
        break;
    }
    assert(CURL_PTRARRAY_COUNT(&pointers) == expected.size());
  }

  ptrarray_clear(&pointers);
}

void FuzzDynamicHeaders(InputCursor input) {
  const std::uint8_t config = input.TakeByte();
  const std::size_t max_entries = 1 + (config & 31U);
  const std::size_t max_string_bytes = 16 + input.TakeByte();
  struct dynhds headers;
  Curl_dynhds_init(&headers, max_entries, max_string_bytes);
  if (config & 0x20U)
    Curl_dynhds_set_opts(&headers, DYNHDS_OPT_LOWERCASE);

  for (std::size_t operation = 0;
       operation < kMaxOperations && !input.empty(); ++operation) {
    const char opcode = static_cast<char>(input.TakeByte());
    if (input.remaining() < 2)
      break;
    const std::size_t name_length =
        input.TakeByte() & kMaxHeaderFieldLength;
    const std::size_t value_length =
        input.TakeByte() & kMaxHeaderFieldLength;
    if (input.remaining() < name_length + value_length)
      break;
    const std::string name = input.TakeBytes(name_length);
    const std::string value = input.TakeBytes(value_length);
    const bool valid_name = !name.empty() && name.front() != '\0';

    switch (opcode) {
      case 'A':
        if (valid_name)
          (void)Curl_dynhds_add(&headers, name.data(), name.size(),
                                value.data(), value.size());
        break;
      case 'a':
        if (valid_name)
          (void)Curl_dynhds_cadd(&headers, name.c_str(), value.c_str());
        break;
      case '?':
        (void)dynhds_contains(&headers, name.data(), name.size());
        break;
      case 'C':
        (void)dynhds_ccontains(&headers, name.c_str());
        break;
      case 'N':
        (void)dynhds_count_name(&headers, name.data(), name.size());
        break;
      case 'n':
        (void)dynhds_ccount_name(&headers, name.c_str());
        break;
      case 'S':
        if (valid_name)
          (void)dynhds_set(&headers, name.data(), name.size(), value.data(),
                           value.size());
        break;
      case 'R':
        (void)dynhds_remove(&headers, name.data(), name.size());
        break;
      case 'r':
        (void)dynhds_cremove(&headers, name.c_str());
        break;
      case 'X':
        Curl_dynhds_reset(&headers);
        break;
      default:
        break;
    }
    assert(Curl_dynhds_count(&headers) <= max_entries);
  }

  Curl_dynhds_free(&headers);
}

void FuzzSparseBitset(InputCursor input) {
  struct uint32_spbset values;
  Curl_uint32_spbset_init(&values);

  for (std::size_t operation = 0;
       operation < kMaxOperations && !input.empty(); ++operation) {
    const char opcode = static_cast<char>(input.TakeByte());
    switch (opcode) {
      case '+':
        (void)Curl_uint32_spbset_add(&values, input.TakeU32());
        break;
      case '-':
        Curl_uint32_spbset_remove(&values, input.TakeU32());
        break;
      case '?':
        (void)Curl_uint32_spbset_contains(&values, input.TakeU32());
        break;
      case '#':
        (void)Curl_uint32_spbset_count(&values);
        break;
      case 'F': {
        uint32_t first = 0;
        (void)Curl_uint32_spbset_first(&values, &first);
        break;
      }
      case 'N': {
        uint32_t next = 0;
        (void)Curl_uint32_spbset_next(&values, input.TakeU32(), &next);
        break;
      }
      case 'C':
        uint32_spbset_clear(&values);
        break;
      default:
        break;
    }
  }

  Curl_uint32_spbset_destroy(&values);
}

#if defined(USE_OPENSSL) || defined(USE_SCHANNEL)
// Interpret newline-delimited `certificate-pattern|hostname` records. Keep the
// hostname NUL-terminated for Curl_host_is_ipnum, but copy the pattern into an
// exact-sized allocation so hostcheck cannot rely on a courtesy terminator.
// Invalid records are ignored rather than reinterpreted.
void FuzzHostcheck(InputCursor input) {
  const std::string records =
      input.TakeBytes(std::min(input.remaining(), kMaxHostcheckInputBytes));
  std::size_t record_start = 0;
  for (std::size_t operation = 0;
       operation < kMaxHostcheckRecords && record_start <= records.size();
       ++operation) {
    const std::size_t record_end = records.find('\n', record_start);
    const std::size_t bounded_end =
        record_end == std::string::npos ? records.size() : record_end;
    const std::size_t separator = records.find('|', record_start);
    if (separator < bounded_end) {
      const std::size_t pattern_length =
          std::min(separator - record_start, kMaxHostcheckNameLength);
      const std::size_t hostname_start = separator + 1;
      const std::size_t hostname_length =
          std::min(bounded_end - hostname_start, kMaxHostcheckNameLength);
      std::unique_ptr<char[]> pattern;
      if (pattern_length != 0) {
        pattern = std::make_unique<char[]>(pattern_length);
        std::copy_n(records.data() + record_start, pattern_length,
                    pattern.get());
      }
      const std::string hostname =
          records.substr(hostname_start, hostname_length);
      (void)Curl_cert_hostcheck(pattern.get(), pattern_length, hostname.c_str(),
                                hostname.size());
    }
    if (record_end == std::string::npos)
      break;
    record_start = record_end + 1;
  }
}
#endif

#ifdef _WIN32
constexpr const char *kNullDevice = "NUL";

int OpenNullDevice() { return _open(kNullDevice, _O_RDWR); }
void CloseDescriptor(int descriptor) { _close(descriptor); }
#else
constexpr const char *kNullDevice = "/dev/null";

int OpenNullDevice() { return open(kNullDevice, O_RDWR); }
void CloseDescriptor(int descriptor) { close(descriptor); }
#endif

const char *FileMode(std::uint8_t selector) {
  static const char *const modes[] = {"r", "r+", "w", "a"};
  return modes[selector & 3U];
}

const char *DebugSource(std::uint8_t flags) {
  return flags & 0x80U ? "fuzz_private.cc" : nullptr;
}

void CloseSocket(curl_socket_t *socket) {
  if (*socket != CURL_SOCKET_BAD) {
    (void)curl_dbg_sclose(*socket, 0, nullptr);
    *socket = CURL_SOCKET_BAD;
  }
}

void FuzzMemoryDebug(InputCursor input) {
#ifdef CURL_MEMDEBUG
  curl_socket_t sockets[2] = {CURL_SOCKET_BAD, CURL_SOCKET_BAD};

  for (std::size_t operation = 0;
       operation < kMaxOperations && !input.empty(); ++operation) {
    const char opcode = static_cast<char>(input.TakeByte());
    const std::uint8_t flags = input.TakeByte();
    const char *source = DebugSource(flags);
    switch (opcode) {
      case 'S':
#ifdef HAVE_SOCKETPAIR
        CloseSocket(&sockets[0]);
        CloseSocket(&sockets[1]);
        (void)curl_dbg_socketpair(AF_UNIX,
                                  (flags & 1U) ? SOCK_DGRAM : SOCK_STREAM, 0,
                                  sockets, flags, source);
#endif
        break;
      case 'A': {
        struct sockaddr_storage address = {};
        curl_socklen_t address_length = sizeof(address);
        const curl_socket_t socket =
            sockets[0] != CURL_SOCKET_BAD && !(flags & 1U)
                ? sockets[0]
                : CURL_SOCKET_BAD;
        curl_socket_t accepted =
            curl_dbg_accept(socket, (flags & 2U) ? &address : nullptr,
                            (flags & 2U) ? &address_length : nullptr, flags,
                            source);
        CloseSocket(&accepted);
        break;
      }
      case 'D': {
        const int descriptor = OpenNullDevice();
        FILE *stream =
            curl_dbg_fdopen(descriptor, FileMode(flags), flags, source);
        if (stream)
          (void)curl_dbg_fclose(stream, flags, source);
        else if (descriptor >= 0)
          CloseDescriptor(descriptor);
        break;
      }
      case 'R': {
        FILE *stream = curl_dbg_fopen(kNullDevice, "r+", flags, source);
        if (stream) {
          stream = curl_dbg_freopen(kNullDevice, FileMode(flags), stream,
                                    flags, source);
          if (stream)
            (void)curl_dbg_fclose(stream, flags, source);
        }
        break;
      }
      default:
        break;
    }
  }

  CloseSocket(&sockets[0]);
  CloseSocket(&sockets[1]);
#else
  (void)input;
#endif
}

class CurlRuntime final {
 public:
  CurlRuntime() : initialized_(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK) {}
  ~CurlRuntime() {
    if (initialized_)
      curl_global_cleanup();
  }

  bool initialized() const { return initialized_; }

 private:
  bool initialized_;
};

bool CurlRuntimeReady() {
  static const CurlRuntime runtime;
  return runtime.initialized();
}

void FuzzHappyEyeballs(InputCursor input) {
  if (!CurlRuntimeReady())
    return;

  CURL *easy = curl_easy_init();
  if (!easy)
    return;
  struct Curl_easy *data = reinterpret_cast<struct Curl_easy *>(easy);
  struct Curl_peer *origin = nullptr;
  struct Curl_peer *alternative = nullptr;
  struct Curl_peer *tunnel = nullptr;
  struct Curl_cfilter anchor = {};
  const struct Curl_scheme *scheme = Curl_get_scheme("http");
  const std::uint8_t flags = input.TakeByte() & 7U;
  const std::uint16_t port = static_cast<std::uint16_t>(1U + flags);

  CURLcode result = scheme
                        ? Curl_peer_create(data, scheme, "origin.test", port,
                                           &origin)
                        : CURLE_FAILED_INIT;
  if (!result && (flags & 2U))
    result = Curl_peer_create(data, scheme, "peer.test", port + 1,
                              &alternative);
  if (!result && (flags & 4U))
    result =
        Curl_peer_create(data, scheme, "tunnel.test", port + 2, &tunnel);

  const std::uint8_t transport =
      (flags & 1U) && !tunnel ? TRNSPRT_UDP : TRNSPRT_TCP;
  if (!result) {
    result = Curl_cf_ip_happy_insert_after(
        &anchor, data, origin, alternative ? alternative : origin, transport,
        tunnel, TRNSPRT_TCP);
  }

  if (!result) {
    struct Curl_cfilter *happy = anchor.next;
    for (std::size_t operation = 0;
         operation < kMaxOperations && !input.empty(); ++operation) {
      switch (input.TakeByte()) {
        case 'P': {
          const bool pending = happy->cft->has_data_pending(happy, data);
          assert(!pending);
          break;
        }
        case 'Q': {
          int reply_ms = -2;
          const CURLcode query_result = happy->cft->query(
              happy, data, CF_QUERY_CONNECT_REPLY_MS, &reply_ms, nullptr);
          assert(query_result == CURLE_OK);
          assert(reply_ms == -1);
          break;
        }
        case 'S': {
          bool done = false;
          const CURLcode shutdown_result =
              happy->cft->do_shutdown(happy, data, &done);
          assert(shutdown_result == CURLE_OK);
          assert(done);
          break;
        }
        default:
          break;
      }
    }
    Curl_conn_cf_discard_chain(&anchor.next, data);
  }

  Curl_peer_unlink(&tunnel);
  Curl_peer_unlink(&alternative);
  Curl_peer_unlink(&origin);
  curl_easy_cleanup(easy);
}

}  // namespace

int TestOneInput(const std::uint8_t *data, std::size_t size) {
  if (!data || !size)
    return 0;

  InputCursor input(data + 1, size - 1);
  switch (data[0]) {
    case 'P':
      FuzzPointerArray(input);
      break;
    case 'D':
      FuzzDynamicHeaders(input);
      break;
    case 'U':
      FuzzSparseBitset(input);
      break;
    case 'M':
      FuzzMemoryDebug(input);
      break;
    case 'H':
      FuzzHappyEyeballs(input);
      break;
#if defined(USE_OPENSSL) || defined(USE_SCHANNEL)
    case 'C':
      FuzzHostcheck(input);
      break;
#endif
    default:
      break;
  }
  return 0;
}

}  // namespace private_fuzzer

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                      std::size_t size) {
  return private_fuzzer::TestOneInput(data, size);
}
