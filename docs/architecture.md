# Architecture

Every packaged legacy or structured target has a same-named source file under
[`fuzzer_entrypoints/`](https://github.com/curl/curl-fuzzer/tree/master/fuzzer_entrypoints).
These thin files give OSS-Fuzz and Fuzz Introspector an unambiguous target
identity while sharing the substantial harness implementation. Direct targets
define their entrypoints in their top-level implementation files instead.

| Target family | Shared implementation | Input model |
| --- | --- | --- |
| `curl_fuzzer` and protocol variants | `legacy_fuzzer.cc`, `curl_fuzzer_tlv.cc`, and callback/socket helpers | Stable binary TLV stream |
| `curl_fuzzer_proto*` | `proto_fuzzer/`, generated profile Traits, and generated protobuf sources | Target-specific generated message lowered to an internal `Scenario` |
| `fuzz_url`, `fuzz_bufq`, `fuzz_doh`, `fuzz_netrc` | Dedicated source files | Raw target-specific bytes |

The normal data flow is:

```text
seed corpus -> fuzzer engine -> target entrypoint -> shared harness -> libcurl
```

Legacy targets configure transfers and scripted responses from TLVs. Each
structured target asks libprotobuf-mutator to operate on its generated
restricted message type, lowers that message into the common internal runtime
`Scenario`, applies semantic normalization and bounds, then runs it against an
appropriate bounded in-process peer. The compatibility target has a generated
broad root and retains its mixed execution behavior. Direct targets skip the
transfer harness and exercise a narrow parser or data structure.

## Build-time generation

The structured build derives several artifacts from the checked-in annotated
schema:

1. Host `protoc` emits a descriptor set containing the schema, eligibility
   metadata, imports, and source locations.
2. The schema-eligibility generator validates the complete profile registry
   and every annotated field. For typed `SetOption` fields it also verifies the
   declared `CURLOPT_*` name and protobuf type against the selected curl
   headers.
3. That one model emits a metadata-free full authoring view, the generic
   internal runtime schema and native option dispatch, one restricted schema
   per profile, direct lower/lift/pruning Traits, and deterministic reports.
4. `protoc` generates the internal runtime C++ type and each target's selected
   profile type. Only the selected profile object is linked into that target.
5. Checked-in textprotos are encoded as the full authoring `Scenario` with
   ordinary `protoc --encode`, then packaged into one seed archive per target.

Restricted roots retain the authoring field numbers and wire types. They can
therefore parse the ordinary authored seed bytes directly; unsupported fields
become unknown fields and are discarded before lowering. Conditional
eligibility is pruned after selector normalization and before shape bounds.
This relationship applies to the new schema and its generated views, not to
pre-cutover binary corpora.

Schema annotations own option identity, value kind, and static or conditional
profile membership. Runtime C++ continues to own protocol mechanics, selector
normalization, work limits, curl object lifetimes, and local transport safety.

## Conditional targets

[`scripts/fuzz_targets`](https://github.com/curl/curl-fuzzer/blob/master/scripts/fuzz_targets)
is the canonical packaged target list. The base structured suite is included
in OSS-Fuzz's AddressSanitizer/i386 build. The GnuTLS, Mbed TLS, and HTTP/3
variants are omitted from i386 and MemorySanitizer builds because their
complete dependency stacks have not been validated for those configurations.
