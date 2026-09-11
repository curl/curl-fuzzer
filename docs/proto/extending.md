# Extending the structured suite

Structured inputs work best when mutations reliably reach curl without making
each iteration expensive. Extend the smallest existing surface that owns the
behavior. Consider serialization compatibility, object lifetimes, target
policy, and local transport isolation together.

## Add a supported curl option

`SetOption` is for scalar values and copied or scenario-owned strings. To add
one:

1. Add its stable numeric value in alphabetical order between the
   `CURL-OPTIONS` markers in the `CurlOptionId` enum in
   `schemas/curl_fuzzer.proto`. This block is the active option list. Existing
   values are part of the corpus wire format and must not be changed or reused.
2. If its `curl.h` type does not determine the intended protobuf value kind,
   update the overrides in
   `src/curl_fuzzer_tools/generate_option_manifest.py`.
3. Decide which fixed profiles may retain it. The fast HTTP, HTTP/2 proxy,
   HTTP/3, TELNET, FTP, and TFTP lanes use explicit option allowlists in
   `proto_fuzzer/target_policy.cc`.
4. Add a correlated textproto seed when reaching useful code requires other
   options or particular peer bytes.

At build time the generator reads the selected checkout's `curl.h`, validates
the marker-delimited names and numbers against it, stages the schema in the
build tree, and emits the C++ value-kind dispatch table.

Callbacks, slists, files, and other pointer-bearing options usually need a
schema-native field plus explicit harness-owned storage. Their backing objects
must remain alive through transfer completion and easy-handle cleanup. Existing
examples include request headers, MIME, upload state, TELNET options, resolver
entries, and bounded anonymous parser files.

Keep filename-backed cookie, Alt-Svc, and HSTS options out of `SetOption`; the
baseline owns their fixed `/dev/null` sinks, while the enum exposes only their
in-memory controls. `CURLOPT_FTPPORT` and `CURLOPT_FTP_USE_EPRT` are safe
because the FTP peer confines active listeners to loopback. FTPS and the
slist-backed QUOTE options need protocol-specific transport and ownership
before they can join this surface. The TFTP controls reuse the schema's upload
body and size fields to exercise option negotiation and raw RRQ/WRQ creation.

Some scalar options still need correlated seeds. The HTTP Message Signature
key, key ID, header list, and algorithm options are one example: keep their
values together in the deep HTTP corpus so mutations can reach both parsing
and rejection paths.

## Add or change a schema field

The binary corpus is persistent. Add new fields with unused field numbers and
append new enum values; never renumber or reuse an existing tag. Choose a
default that preserves the behavior of older serialized inputs.

Then update all parts of the contract:

- Add an appropriate complexity limit in `proto_fuzzer/scenario_limits.h`.
- Bound the runtime-visible value and remove it from profiles that cannot use
  it in `proto_fuzzer/target_policy.cc`.
- Implement ownership and execution in the request-data, runner, or peer layer.
- Ensure the compatibility target does not silently acquire new semantics from
  bytes that older schemas treated as unknown.
- Add policy tests for retention, removal, canonicalization, and boundary
  values, plus runtime tests when the field owns resources or changes I/O.

Protobuf `repeated` and `bytes` fields have no intrinsic work bound. In fixed
lanes, a runtime that merely ignores an oversized suffix is not sufficient:
the target postprocessor must remove it too, or libprotobuf-mutator will
continue allocating and mutating data that cannot add coverage. The historical
compatibility lane cannot acquire a new postprocessor, so its runtime boundary
must remain safe without changing existing input semantics.

## Add a target profile

A new lane normally requires all of the following:

1. A `TargetProfile` and a complete `RunModeFor` mapping in
   `proto_fuzzer/target_profile.h`.
2. A policy branch in `proto_fuzzer/target_policy.cc` that fixes routing,
   retains only meaningful fields, and applies shared bounds.
3. A bounded peer or runner path. It must not consult ambient DNS, proxies,
   trust stores, or remote endpoints, and malformed scripts must terminate by
   operation or idle budgets rather than long wall-clock waits.
4. A thin `fuzzer_entrypoints/curl_fuzzer_proto_<name>.cc` binding all three
   libFuzzer entrypoints to the same profile.
5. A CMake executable declaration, generated corpus declaration (or an
   explicit reuse mapping in `scripts/fuzz_corpus_helpers.sh`), and dependency
   from the executable to that corpus.
6. An `ossconfig/<target>.options` file and an entry in
   `scripts/fuzz_targets`, with architecture or sanitizer gates when required.
7. Entrypoint, target-policy, peer/runtime, packaging, and representative
   scenario tests.
8. A row in [Target profiles](target-profiles.md).

Keep throughput-sensitive parsing separate from expensive lifecycle, TLS, file
parser, or timed work. Existing `http`, `http_deep`, and `timing` profiles show
how one protocol surface can be split without making its fast lane pay for
every coverage feature.

## Verify a change

Run the focused Python tests for schema generation and target wiring, then
build the affected binary and the C++ unit-test aggregate:

```shell
uv run --extra python-tests pytest \
  tests/test_generate_option_manifest.py \
  tests/test_fuzzer_entrypoints.py
./mainline.sh -t curl_fuzzer_proto_http
cmake --build build --target fuzzer_unit_tests
ctest --test-dir build --output-on-failure
```

Replace the example target with the lane being changed. Finally, decode and
replay each new generated seed as described in
[Writing and inspecting scenarios](scenarios.md). For performance-sensitive
policy changes, use the [benchmarking guide](../benchmarking.md); source
coverage and executions per second answer different questions and should be
checked together.
