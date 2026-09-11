# curl-fuzzer

curl-fuzzer contains the fuzz targets, seed corpora, build integration, and
testcase tools used by curl's
[OSS-Fuzz project](https://github.com/google/oss-fuzz/tree/master/projects/curl).
It can also build standalone binaries for local regression testing and crash
reproduction.

The repository has three target families:

- **Legacy fuzzers** (`curl_fuzzer` and its protocol variants) drive libcurl
  from a stable Type-Length-Value (TLV) input.
- **Structured fuzzers** use a protobuf `Scenario`, target-specific mutation
  policies, and bounded in-process protocol peers.
- **Direct fuzzers** feed raw bytes to focused parsers such as URL, DoH, netrc,
  and buffer-queue code.

Start with [Getting started](getting-started.md), then use the dedicated
[legacy](legacy/overview.md) or [structured](proto/overview.md) guide when
changing a harness or adding seeds.

## Online tools

The [legacy TLV corpus decoder](https://fuzz.curl.se/corpus-decoder/)
runs entirely in the browser. Selected testcase data never leaves the device.
Structured protobuf inputs can be decoded locally with `read_proto_corpus`; see
[Scenarios and corpora](proto/scenarios.md).

## Sources of truth

Avoid copying lists that must be kept synchronized:

- [`scripts/fuzz_targets`](https://github.com/curl/curl-fuzzer/blob/master/scripts/fuzz_targets)
  defines the targets packaged for each architecture and sanitizer.
- [`schemas/curl_fuzzer.proto`](https://github.com/curl/curl-fuzzer/blob/master/schemas/curl_fuzzer.proto)
  is the complete structured scenario schema, including the stable
  `CurlOptionId` values used by serialized corpora. Its marker-delimited enum
  block also defines the active `SetOption` surface.
- [`corpora/`](https://github.com/curl/curl-fuzzer/tree/master/corpora)
  contains checked-in legacy and direct-fuzzer inputs.
- [`scenarios/curl_fuzzer_proto/`](https://github.com/curl/curl-fuzzer/tree/master/scenarios/curl_fuzzer_proto)
  contains the reviewable structured seed sources.
