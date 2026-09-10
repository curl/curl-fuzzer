# Architecture

Every packaged legacy or structured target has a same-named source file under
[`fuzzer_entrypoints/`](https://github.com/curl/curl-fuzzer/tree/master/fuzzer_entrypoints).
These thin files give OSS-Fuzz and Fuzz Introspector an unambiguous target
identity while sharing the substantial harness implementation. Direct targets
define their entrypoints in their top-level implementation files instead.

| Target family | Shared implementation | Input model |
| --- | --- | --- |
| `curl_fuzzer` and protocol variants | `legacy_fuzzer.cc`, `curl_fuzzer_tlv.cc`, and callback/socket helpers | Stable binary TLV stream |
| `curl_fuzzer_proto*` | `proto_fuzzer/` and generated protobuf sources | `curl.fuzzer.proto.Scenario` |
| `fuzz_url`, `fuzz_bufq`, `fuzz_doh`, `fuzz_netrc` | Dedicated source files | Raw target-specific bytes |

The normal data flow is:

```text
seed corpus -> fuzzer engine -> target entrypoint -> shared harness -> libcurl
```

Legacy targets configure transfers and scripted responses from TLVs. Fixed
structured targets first constrain a protobuf scenario to the compiled target
profile, then run it against an appropriate bounded in-process peer. The
original compatibility target retains its historical mixed behavior. Direct
targets skip the transfer harness and exercise a narrow parser or data
structure.

## Build-time generation

The structured build derives several artifacts rather than checking them in:

1. The supported curl option list and curl headers populate the generated
   `CurlOptionId` enum.
2. `protoc` generates the C++ message implementation.
3. Textproto files under `scenarios/` are encoded into binary entries under
   `build/generated_corpora/`.
4. OSS-Fuzz packaging creates one seed archive per target.

The textproto scenarios remain reviewable, and the generated enum values match
the curl revision being built.

## Conditional targets

[`scripts/fuzz_targets`](https://github.com/curl/curl-fuzzer/blob/master/scripts/fuzz_targets)
is the canonical packaged target list. The structured suite is 64-bit only.
The GnuTLS, Mbed TLS, and HTTP/3 variants are omitted under MemorySanitizer
because their complete dependency stacks cannot currently be instrumented.
