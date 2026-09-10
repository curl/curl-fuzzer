# Extending the legacy fuzzers

Legacy inputs are a persistent binary format. Treat an assigned type number as
part of the corpus compatibility contract: allocate a previously unused ID and
never reuse or renumber an existing one. The grouped ranges in
`legacy_tlv_mutator.cc` also make the value representation part of that choice.

## Add a TLV type

1. Add the `TLV_TYPE_*` value to `curl_fuzzer.h`.
2. Implement its behavior in `fuzz_parse_tlv()` in `curl_fuzzer_tlv.cc`.
   `FSINGLETONTLV` handles a string-valued curl option, `FU32TLV` handles a
   four-byte option declared by libcurl as `long`, and `FU32TLV_OFF_T` handles
   a four-byte option declared as `curl_off_t`. The numeric macros enforce
   these option families at compile time. List-like, raw-byte, or nested data
   needs an explicit switch case and cleanup in `FUZZ_DATA` where applicable.
3. Add the same numeric ID to `BaseType` and a decoder label to `TYPEMAP` in
   `src/curl_fuzzer_tools/corpus.py`. If contributors should be able to seed
   it from the command line, add the corresponding argument and encoder call
   in `src/curl_fuzzer_tools/generate_corpus.py`.
4. Audit `GetTypeInfo()` and the type-selection bounds in
   `legacy_tlv_mutator.cc`. The mutator must know whether the payload is bytes,
   a string, a four-byte integer, or nested MIME, and whether it may repeat.
   Extending an ID range can also require updating the maximum known ID, the
   dense ordinal mapping, and its compile-time synchronization assertions.
5. If the option can trigger name resolution or another external side effect,
   extend the mutator's canonicalization/safety policy and its tests before
   making that type eligible for structured insertion.
6. Add focused parser, generator, and mutator tests, then generate or update a
   seed that reaches the new behavior.

`FUZZ_CURLOPT_TRACKER_SPACE` is not a TLV-ID limit. `FSET_OPTION` and
`FCHECK_OPTION_UNSET` index the tracker with `CURLOPTNAME % 1000`; when adding a
tracked curl option, verify that this remainder is smaller than the allocated
tracker space. The tracker enforces singleton curl options; this size check
avoids introducing an out-of-bounds index.

`tests/test_tlv_constants_sync.py` rejects duplicate numeric IDs and missing or
extra values between `curl_fuzzer.h` and Python's `BaseType`. It does not
replace the behavioral tests needed for the parser and mutator.

## Add a protocol target

When a new target can use the existing TLV execution model:

1. Add `fuzzer_entrypoints/<target>.cc` following an existing legacy wrapper.
   Its basename must match the executable so coverage and Fuzz Introspector
   attribution remain distinct.
2. Add `curl_add_fuzzer(<target> <TOKEN>)` and the target to the aggregate
   `fuzz` target in `CMakeLists.txt`. This defines `FUZZ_PROTOCOLS_<TOKEN>` for
   the shared sources.
3. Add or reuse the matching branch in `fuzz_set_allowed_protocols()` in
   `legacy_fuzzer.cc`. If this expands the generic target too, update the
   reviewed list in `legacy_protocol_allowlist.cc`. Protocols that can bypass
   the fake-socket model require a safety review rather than automatic
   inclusion.
4. Teach `DefaultUrl()`, `DefaultResponse()`, and, where appropriate,
   `TargetNeedsResponse()` in `legacy_tlv_mutator.cc` how to create useful
   transfer scaffolding for the compile-time token.
5. Add the executable to `scripts/fuzz_targets` so packaging, public-corpus
   downloads, and replay tooling agree with CMake.
6. Create `corpora/<target>/` with at least one decoded and replayed seed.

The generic allow-list deliberately excludes protocols such as TELNET when the
legacy harness cannot safely isolate their I/O. A new protocol-specific target
must preserve the harness's isolation and must not introduce an unintended
network or blocking-standard-input path.

## Relevant checks

Run the focused Python checks after changing IDs, generation, entrypoints, or
packaging:

```shell
python -m pip install -e '.[python-tests]'
python -m pytest \
  tests/test_tlv_constants_sync.py \
  tests/test_generate_corpus.py \
  tests/test_fuzzer_entrypoints.py
```

After configuring a normal build, compile and run the C++ policy tests:

```shell
cmake --build build --target \
  legacy_tlv_mutator_test legacy_protocol_allowlist_test
ctest --test-dir build --output-on-failure \
  -R 'legacy_(tlv_mutator|protocol_allowlist)_test'
```

`tests/legacy_tlv_mutator_test.cc` covers framing, bounds, transfer-scaffold
repair, routing canonicalization, raw mutation, and record crossover.
`tests/legacy_protocol_allowlist_test.cc` verifies that the generic allow-list
is both supported by the linked libcurl and limited to reviewed protocols. A
full AddressSanitizer `./mainline.sh` build also builds `fuzzer_unit_tests` and
runs CTest.
