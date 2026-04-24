/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

// Direct fuzz harness for curl's DOH (DNS-over-HTTPS) parser entrypoints.
// Targets the attack surface exposed to a compromised DOH server: raw DNS
// wire-format bytes flowing into doh_resp_decode, plus the request-side
// doh_req_encode. Deliberately skips the network-plumbing paths around
// Curl_doh / doh_probe_run - those are reachable via curl_fuzzer_proto if /
// when we wire them up separately.
//
// doh.h cannot be included directly because it pulls in urldata.h and most
// of curl's internal header tree. Instead we forward-declare the handful of
// symbols and constants we need; the real definitions live in the curl
// static lib, exported because the repo-level build now compiles curl with
// -DUNITTESTS (see CMakeLists.txt). struct dohentry is treated as opaque -
// we hand the parser an aligned byte buffer sized well above the real
// struct and let the parser's compiled-in layout knowledge handle the rest.

#include <stddef.h>
#include <stdint.h>
#include <cstring>
#include <signal.h>
#include <string>
#include <vector>

#include <curl/curl.h>

extern "C" {

// Mirror curl's DNStype enum values (lib/doh.h).
typedef enum {
  CURL_DNS_TYPE_A = 1,
  CURL_DNS_TYPE_AAAA = 28,
  CURL_DNS_TYPE_HTTPS = 65
} DNStype;

// Match DOH_MAX_DNSREQ_SIZE from lib/doh.h — size of the request buffer
// doh_req_encode writes into. The real caller in doh.c uses the same.
#define FUZZ_DOH_MAX_DNSREQ_SIZE (256 + 16)

// Opaque dohentry — forward-declared so we can pass pointers into curl.
struct dohentry;

void de_init(struct dohentry *de);
void de_cleanup(struct dohentry *d);
int doh_resp_decode(const unsigned char *doh, size_t dohlen,
                    DNStype dnstype, struct dohentry *d);
int doh_req_encode(const char *host, DNStype dnstype,
                   unsigned char *dnsp, size_t len, size_t *olen);

}  // extern "C"

namespace {

// Run de_init / doh_resp_decode / de_cleanup against a byte payload for a
// given DNS record type. Uses an aligned byte buffer as opaque storage for
// the dohentry (real size is ~660 bytes in our DEBUGBUILD; 4 KiB with 16-byte
// alignment is generous headroom for any future layout growth).
void RunDecode(const uint8_t *body, size_t len, DNStype dnstype) {
  alignas(16) unsigned char de_storage[4096];
  auto *de = reinterpret_cast<struct dohentry *>(de_storage);
  de_init(de);
  (void)doh_resp_decode(body, len, dnstype, de);
  de_cleanup(de);
}

// Exercise the request-encoder with the payload interpreted as a hostname.
// doh_req_encode measures the host with strlen() and asserts the result is
// non-zero (DEBUGASSERT(hostlen) at doh.c:105). The real caller in doh.c is
// fed from name resolution, which can't produce an empty string, so guard on
// the strlen here too — including the leading-NUL case where the payload is
// non-empty but the C-string representation is zero-length.
void RunEncode(const uint8_t *body, size_t len) {
  std::string host(reinterpret_cast<const char *>(body), len);
  if (std::strlen(host.c_str()) == 0) {
    return;
  }
  unsigned char req[FUZZ_DOH_MAX_DNSREQ_SIZE];
  size_t olen = 0;
  (void)doh_req_encode(host.c_str(), CURL_DNS_TYPE_A, req, sizeof(req), &olen);
}

}  // namespace

// Fuzzing entry point. First byte selects the parser target; remaining bytes
// are the payload fed to that parser. One byte of in-band selection lets
// libFuzzer cross-pollinate between targets from a shared corpus rather than
// maintaining one corpus per entrypoint. We read the selector from data[0]
// directly rather than through FuzzedDataProvider because the latter consumes
// integrals from the tail of the buffer, which would put the selector in the
// wrong place for seeds authored with the selector up front.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Ignore SIGPIPE in case any decoder path touches stderr through curl's
  // trace machinery and hits a closed pipe during fuzzer harness runs.
  signal(SIGPIPE, SIG_IGN);

  if (size < 1) {
    return 0;
  }
  const uint8_t selector = data[0] & 0x03;
  const uint8_t *payload = data + 1;
  const size_t payload_len = size - 1;

  switch (selector) {
    case 0:
      RunDecode(payload, payload_len, CURL_DNS_TYPE_A);
      break;
    case 1:
      RunDecode(payload, payload_len, CURL_DNS_TYPE_AAAA);
      break;
    case 2:
      RunDecode(payload, payload_len, CURL_DNS_TYPE_HTTPS);
      break;
    default:
      RunEncode(payload, payload_len);
      break;
  }

  return 0;
}
