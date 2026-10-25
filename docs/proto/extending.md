# Extending the structured suite

Structured inputs work best when mutations reliably reach curl without making
each iteration expensive. Extend the smallest existing surface that owns the
behavior. Consider serialization compatibility, object lifetimes, target
policy, and local transport isolation together.

## Add a supported curl option

`SetOption` is for scalar values and copied or scenario-owned strings. The
complete checklist for an ordinary addition is:

1. Confirm that the option fits this path. Callbacks, slists, blobs, filenames,
   and other pointer-bearing state usually need a schema-native field and
   explicit runtime ownership instead.
2. Add one field to `SetOption.setting` in `schemas/curl_fuzzer.proto`. Assign a
   new, never-reused tag and use `bool`, `uint64`, or `bytes` according to the
   value curl consumes.
3. Add the field's `(curl.fuzzer.schema.curl_option)` annotation with the exact
   native `CURLOPT_*` name and its complete profile eligibility. Use a closed
   conditional guard only when normalized selector
   state really changes whether the option is meaningful.
4. Add or update a target-relevant textproto seed when useful reachability
   requires correlated options, request data, or peer bytes.
5. Run the schema tests, inspect the affected generated profile report, build
   that target, decode its generated seed, and replay it. Add runtime tests if
   the option needs value normalization, new selector semantics, ownership, or
   peer behavior.

The schema generator checks the native name and declared protobuf type against
the selected checkout's `curl.h`. From that one field it derives the internal
`CurlOptionId`, value-kind/native manifest, lookup switch, allowed profile
cases, and direct lower/lift transfers.
Do not add a handwritten C++ option ID, kind override, profile allowlist, or
adapter case. If none of the existing closed guard facts describes a new
conditional rule, add and test a new fact deliberately; do not encode an
arbitrary expression in the schema.

Callbacks, slists, files, and other pointer-bearing options usually need a
schema-native field plus explicit harness-owned storage. Their backing objects
must remain alive through transfer completion and easy-handle cleanup. Existing
examples include request headers, MIME, upload state, TELNET options, resolver
entries, and bounded anonymous parser files.

Keep filename-backed cookie, Alt-Svc, and HSTS options out of `SetOption`; the
baseline owns their fixed `/dev/null` sinks, while the typed option oneof
exposes only their in-memory controls. `CURLOPT_FTPPORT` and
`CURLOPT_FTP_USE_EPRT` are safe
because the plaintext FTP peer confines active listeners to loopback; the
implicit-TLS FTPS lane removes them and supports passive data channels only.
The slist-backed QUOTE options still need protocol-specific ownership before
they can join this surface. The TFTP controls reuse the schema's upload
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

- Add complete schema-owned eligibility, including contextual-path metadata
  when applicable. If a closed guard fact reads the new field, add its path to
  that fact's generator-owned input list; schema generation verifies that every
  guarded profile retains it through selector normalization.
- Add an appropriate complexity limit in `proto_fuzzer/scenario_limits.h` and
  enforce the runtime-visible bound in `proto_fuzzer/target_policy.cc`.
- Implement ownership and execution in the request-data, runner, or peer layer.
- Decide deliberately whether the generated compatibility root should expose
  the field; a newly assigned tag must not accidentally reinterpret historical
  bytes.
- Add policy tests for retention, removal, canonicalization, and boundary
  values, plus runtime tests when the field owns resources or changes I/O.

Protobuf `repeated` and `bytes` fields have no intrinsic work bound. In fixed
lanes, a runtime that merely ignores an oversized suffix is not sufficient.
The profile projection must exclude ineligible shapes, and target normalization
must prune conditional fields before applying bounds so libprotobuf-mutator
does not keep allocating and mutating data that cannot add coverage. Runtime
bounds remain necessary for direct callers and for the broad compatibility
lane.

## Add a target profile

A new lane normally requires all of the following:

1. A file-level profile declaration in `schemas/curl_fuzzer.proto`, including
   its exact C++ `TargetProfile` name, generated root, and empty-option policy;
   add complete membership to every field and option it can reach.
2. A `TargetProfile` and complete `RunModeFor` mapping in
   `proto_fuzzer/target_profile.h`. Schema generation checks that this C++ enum
   and the registry are complete and unique.
3. A policy branch in `proto_fuzzer/target_policy.cc` that fixes routing,
   normalizes selectors, and applies semantic bounds. Static field and option
   membership belongs in the schema, not this branch.
4. A bounded peer or runner path. It must not consult ambient DNS, proxies,
   trust stores, or remote endpoints, and malformed scripts must terminate by
   operation or idle budgets rather than long wall-clock waits.
5. A thin `fuzzer_entrypoints/curl_fuzzer_proto_<name>.cc` including its
   generated Traits and binding all three libFuzzer entrypoints to that same
   concrete message type.
6. A CMake executable and profile-generation declaration, generated corpus
   declaration (or an explicit reuse mapping in
   `scripts/fuzz_corpus_helpers.sh`), and dependency from the executable to
   that corpus.
7. An `ossconfig/<target>.options` file and an entry in
   `scripts/fuzz_targets`, with architecture or sanitizer gates when required.
8. Schema-generation, entrypoint, target-policy, peer/runtime, packaging, and
   representative scenario tests.
9. A row in [Target profiles](target-profiles.md).

Keep throughput-sensitive parsing separate from expensive lifecycle, TLS, file
parser, or timed work. Existing `http`, `http_deep`, and `timing` profiles show
how one protocol surface can be split without making its fast lane pay for
every coverage feature.

## Verify a change

Keep function descriptions, parameter contracts, and return documentation beside
their definitions in `.cc` files. Do not repeat them on header declarations.
Class, type, and field documentation stays in headers, as does documentation for
functions defined there and pure virtual contracts. Run the placement and
coverage checks with `cmake --build build --target doxygen-check`.

Run the focused Python tests for schema generation and target wiring, then
build the affected binary and the C++ unit-test aggregate:

```shell
uv run --extra python-tests pytest \
  tests/test_schema_eligibility.py \
  tests/test_active_schema_cutover.py \
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
