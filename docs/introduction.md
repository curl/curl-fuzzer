# curl-fuzzer

curl-fuzzer contains the fuzz targets, seed corpora, build integration, and
testcase tools used by curl's
[OSS-Fuzz project](https://github.com/google/oss-fuzz/tree/master/projects/curl).
It can also build standalone binaries for local regression testing and crash
reproduction.

The repository has two target families:

- **Structured fuzzers** use typed protobuf scenarios, generated
  target-specific mutation roots, and bounded in-process protocol peers.
- **Direct fuzzers** feed raw bytes to focused parsers such as URL, DoH, netrc,
  and buffer-queue code.

Start with [Getting started](getting-started.md), then use the
[structured harness guide](proto/overview.md) when changing a harness or adding
protobuf seeds.

## Online tools

The [corpus decoder](https://fuzz.curl.se/corpus-decoder/) accepts structured
protobuf `Scenario` files and runs entirely in the browser. Selected testcase
data never leaves the device. For command-line protobuf decoding, see
[Scenarios and corpora](proto/scenarios.md).

## Sources of truth

Avoid copying lists that must be kept synchronized:

- [`scripts/fuzz_targets`](https://github.com/curl/curl-fuzzer/blob/master/scripts/fuzz_targets)
  defines the targets packaged for each architecture and sanitizer.
- [`schemas/curl_fuzzer.proto`](https://github.com/curl/curl-fuzzer/blob/master/schemas/curl_fuzzer.proto)
  is the complete annotated authoring schema. Typed `SetOption` fields own
  native curl-option identity and profile membership; structured-field
  annotations own the remainder of each generated profile's input surface.
- [`schemas/eligibility_options.proto`](https://github.com/curl/curl-fuzzer/blob/master/schemas/eligibility_options.proto)
  defines the profile registry and eligibility metadata interpreted at build
  time. It does not define a second serialized Scenario format.
- [`corpora/`](https://github.com/curl/curl-fuzzer/tree/master/corpora)
  contains checked-in direct-fuzzer inputs.
- [`scenarios/curl_fuzzer_proto/`](https://github.com/curl/curl-fuzzer/tree/master/scenarios/curl_fuzzer_proto)
  contains the reviewable structured seed sources.
