# Reproducing fuzzer findings

OSS-Fuzz reports identify the target binary, fuzzing engine, sanitizer, and
platform that found a failure. Reproduce with the closest available
configuration: a crash found under UndefinedBehaviorSanitizer, for example,
may not be visible in the default AddressSanitizer build.

These instructions assume that the testcase has been downloaded from the
OSS-Fuzz report.

## Inspect the testcase

### Legacy TLV targets

Decode a legacy input with the Python tool:

```shell
read_corpus clusterfuzz-testcase-minimized-curl_fuzzer_http-<id>
```

For example, a URL-only input is displayed as:

```text
TLVContents(type='CURLOPT_URL' (1), length=16, data=b'http://127.0.0.1')
```

The hosted [legacy corpus decoder](https://fuzz.curl.se/corpus-decoder/)
provides the same kind of inspection in a browser without uploading the file.

### Structured protobuf targets

From a source checkout, `read_proto_corpus` uses the checked-in schema to print
field names. It can also use a staged copy under `build/schemas/` when the
source schema is unavailable:

```shell
read_proto_corpus \
  clusterfuzz-testcase-minimized-curl_fuzzer_proto_http-<id>
```

The command requires `protoc`. If it cannot find either schema, it falls back
to `protoc --decode_raw`; pass `--proto-file` to select one explicitly.

Published reproduction images also include the staged schema and a
`decode-scenario` command:

```shell
docker run --rm -i \
  -v "$PWD/clusterfuzz-testcase-minimized-curl_fuzzer_proto_multi-<id>:/testcase:ro" \
  curlfuzzer.azurecr.io/address-libfuzzer \
  decode-scenario /testcase
```

It also accepts the testcase on standard input:

```shell
docker run --rm -i curlfuzzer.azurecr.io/address-libfuzzer decode-scenario \
  < clusterfuzz-testcase-minimized-curl_fuzzer_proto_multi-<id>
```

Direct parser targets consume target-specific raw bytes and generally have no
separate decoder.

## Reproduce with a local standalone build

Build the target, optionally against a local curl checkout:

```shell
./mainline.sh -t curl_fuzzer_http
./mainline.sh -c /path/to/curl -t curl_fuzzer_http
```

The resulting binary is under `build/`. Set `FUZZ_VERBOSE` to enable detailed
libcurl logging:

```shell
FUZZ_VERBOSE=1 ./build/curl_fuzzer_http \
  clusterfuzz-testcase-minimized-curl_fuzzer_http-<id>
```

The default build uses AddressSanitizer. It is suitable for many
`libfuzzer_asan` findings and provides a fast edit-build-replay loop. A matching
OSS-Fuzz container is preferable when the report uses another sanitizer,
engine, architecture, or dependency configuration.

## Reproduce in OSS-Fuzz

Follow the upstream
[OSS-Fuzz reproduction guide](https://google.github.io/oss-fuzz/advanced-topics/reproducing/)
for complete instructions. From an OSS-Fuzz checkout, an UndefinedBehaviorSanitizer
HTTP reproduction is:

```shell
python3 infra/helper.py build_image curl
python3 infra/helper.py build_fuzzers --sanitizer undefined curl
python3 infra/helper.py reproduce \
  curl curl_fuzzer_http \
  /path/to/clusterfuzz-testcase-minimized-curl_fuzzer_http-<id>
```

Once reproduced, use the normal sanitizer stack trace, debugger, and targeted
logging to narrow the fault. For AddressSanitizer investigations in GDB, a
breakpoint on `__asan::ReportGenericError` can stop at the point where the
runtime reports the invalid access.
