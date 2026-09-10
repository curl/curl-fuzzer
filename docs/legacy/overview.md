# Legacy TLV fuzzers

The legacy fuzzers are the `curl_fuzzer` executable and the protocol-specific
`curl_fuzzer_*` executables declared with `curl_add_fuzzer()` in
`CMakeLists.txt`. They consume a compact binary
[type-length-value stream](tlv-format.md). The name *legacy* distinguishes this
input model from the structured protobuf scenario fuzzers; these targets are
still maintained and run by OSS-Fuzz.

The current protocol-specific targets cover DICT, file, FTP, Gopher, HTTP,
HTTPS, IMAP, LDAP, MQTT, POP3, RTSP, SMTP, TFTP, and WebSocket. The unsuffixed
`curl_fuzzer` target enables the reviewed subset of protocols supported by the
libcurl build. Direct byte-oriented targets such as `fuzz_url`, `fuzz_doh`,
`fuzz_netrc`, and `fuzz_bufq` do not use the TLV harness.

## Execution model

The format can describe both sides of one transfer: curl options and upload
data configure the client, while response TLVs provide bytes for the simulated
peer. A particular testcase need not contain every kind of record.

1. A same-named source under `fuzzer_entrypoints/` exports
   `LLVMFuzzerTestOneInput()` and delegates to `LegacyFuzzerTestOneInput()`.
   Keeping a distinct entrypoint per executable lets Fuzz Introspector
   attribute coverage to the correct target.
2. `legacy_fuzzer.cc` initializes one `CURL` easy handle and asks
   `curl_fuzzer_tlv.cc` to parse every record. Known records configure curl,
   uploads, MIME data, or one of the two simulated connections.
3. The target applies its compile-time protocol allow-list and standard safety
   options. The generic target intersects its reviewed allow-list with the
   protocols advertised by the linked libcurl.
4. `curl_fuzzer_callback.cc` supplies non-blocking Unix `socketpair()` sockets
   in place of network sockets. `fuzz_handle_transfer()` drives the easy handle
   through the multi API and releases successive response records as curl
   writes requests.
5. All per-input handles, lists, MIME objects, and sockets are released before
   the next testcase.

The harness also directs connections to loopback, uses short transfer
timeouts, limits output, and rejects protocols outside the target's allow-list.
Resolver-sensitive proxy, interface, FTP active-mode, and pre-proxy values are
canonicalized before a transfer so an old or newly mutated corpus entry cannot
introduce an external hostname lookup.

## Structure-aware mutation

`legacy_tlv_mutator.cc` exports libFuzzer's custom mutator and crossover
callbacks. Most mutations operate on complete records. They preserve known
value shapes, keep numeric values four bytes long, avoid duplicate scalar
options, and preserve existing URL and, except for the file target,
initial-response records. When either prerequisite is missing, successive
structured mutations add it before making other edits, provided the output
buffer has enough capacity.

When both parents are structurally valid and non-empty, crossover normally
combines whole records while reserving space for those prerequisites. It falls
back to bounded byte crossover for invalid or empty parents, or when the output
buffer cannot hold the required records.

When the mutator seed is divisible by 16, mutation instead takes a byte-level
lane (`LLVMFuzzerMutate` when available). This continues to explore corrupt
lengths, unknown types, and other parser failures that structure-preserving
edits cannot create. The ordinary lane truncates malformed inputs to their
valid prefix and converges toward the transfer scaffolding needed to exercise
curl.

See [Working with corpora](corpora.md) for decoding, creating, and replaying
inputs, or [Extending the legacy fuzzers](extending.md) when adding coverage.

## Source map

| Path                                 | Responsibility                                     |
|--------------------------------------|----------------------------------------------------|
| `fuzzer_entrypoints/curl_fuzzer*.cc` | Per-binary libFuzzer entrypoints                   |
| `legacy_fuzzer.cc`                   | Per-input lifecycle, curl setup, and transfer loop |
| `curl_fuzzer_tlv.cc`                 | TLV parsing and mapping to curl operations         |
| `curl_fuzzer_callback.cc`            | Simulated sockets and read/write callbacks         |
| `curl_fuzzer.h`                      | Wire IDs, shared state, and parser helpers         |
| `legacy_protocol_allowlist.cc`       | Generic target's reviewed protocol policy          |
| `legacy_tlv_mutator.cc`              | Structure-aware mutation and crossover             |
| `src/curl_fuzzer_tools/corpus.py`    | Python encoder, decoder, and ID map                |
