# Comparing fuzzer coverage and speed

`scripts/compare_fuzzers.py` runs repeatable A/B measurements against
production-style libFuzzer binaries. It records libFuzzer coverage (`cov`),
features (`ft`), executions per second, corpus growth, peak RSS, and wall/user/
system time. Complete logs and crash artifacts are retained, and any failed or
unparseable run makes the command fail.

Build the baseline and candidate with the same curl revision, compiler,
sanitizer, and OSS-Fuzz settings. For example, use two OSS-Fuzz output
directories produced with the address sanitizer and libFuzzer. Then run:

```shell
scripts/compare_fuzzers.py \
  --baseline-dir /path/to/baseline/out/curl \
  --candidate-dir /path/to/candidate/out/curl \
  --seconds 30 \
  --repeats 5 \
  --cpu 0 \
  --output build/measurements/comparison.json
```

The defaults cover the legacy FTP/HTTP/HTTPS/TFTP/WS targets and the fixed
structured fast HTTP, deep HTTP, HTTPS, WS, WSS, TELNET, FTP, TFTP, API, and
timing lanes. The deep HTTP target
retains stateful authentication, redirect, upload, MIME, and result-probe
work so the ordinary HTTP lane can concentrate its CPU budget on single-request
URL and response parsing. The original mixed-semantics
`curl_fuzzer_proto` target is retained for OSS-Fuzz corpus and testcase
compatibility, but is not benchmarked by default because its variable scheme
and timing policy obscures lane-level throughput.
Repeat `--target` to choose a different same-name A/B set:

```shell
scripts/compare_fuzzers.py \
  --baseline-dir /path/to/baseline/out/curl \
  --candidate-dir /path/to/candidate/out/curl \
  --target curl_fuzzer_proto_http \
  --target curl_fuzzer_proto_http_deep \
  --target curl_fuzzer_proto \
  --target fuzz_url
```

To compare a legacy target with a differently named proto replacement, use a
target pair:

```shell
scripts/compare_fuzzers.py \
  --baseline-dir /path/to/legacy/out/curl \
  --candidate-dir /path/to/proto/out/curl \
  --target-pair curl_fuzzer_http=curl_fuzzer_proto_http \
  --target-pair curl_fuzzer_https=curl_fuzzer_proto_https \
  --target-pair curl_fuzzer_ftp=curl_fuzzer_proto_ftp \
  --target-pair curl_fuzzer_tftp=curl_fuzzer_proto_tftp \
  --target-pair curl_fuzzer_ws=curl_fuzzer_proto_ws
```

The label in the report is, for example,
`curl_fuzzer_http=>curl_fuzzer_proto_http`. Each side of a mapped pair receives its
own native corpus and seed archive; legacy TLV bytes are never passed to the
protobuf target. Same-name `--target` comparisons retain the stricter behavior
of sharing one content-identical snapshot. `--corpus TARGET=PATH` overrides are
keyed by the actual binary target name, so a mapped pair may supply one override
for each side.

For a same-name target, the input snapshot combines the checked-in corpus with
the baseline's `<target>_seed_corpus.zip`, deduplicating by SHA-256. A mapped
pair resolves the checked-in corpus and seed archive independently from its
baseline and candidate layouts. Add a downloaded fleet corpus with
`--public-corpus-root ossfuzz_corpus`. Override a target's inputs completely
with one or more `--corpus TARGET=PATH` arguments; `PATH` may be a directory,
zip archive, or individual input.

For every fixed proto lane, `--public-corpus-root` also includes the historical
`curl_fuzzer_proto` public corpus. The protobuf wire format is shared, and the
lane postprocessor normalizes scheme and timing controls before replay, so this
preserves accumulated fleet coverage while the new target corpora grow.

Every run gets a fresh copy of one content-addressed snapshot. Repeat `N` uses
the deterministic seed `--seed-base + N - 1`; baseline/candidate order
alternates between repeats to reduce ordering bias. The JSON records corpus and
binary hashes, exact managed arguments, host details, individual results, and
medians. Raw `cov` and `ft` values are only comparable when compiler
instrumentation and the curl revision are held constant. They remain recorded
for mapped targets, but their cross-harness deltas are deliberately reported as
null; use the source coverage comparison below for legacy-to-proto parity.

## Compare curl source coverage

Raw libFuzzer `cov` and `ft` counters include each harness and cannot prove
coverage parity between a legacy target and a proto target. The comparison
helper can additionally replay the fixed native corpus through standalone LLVM
coverage builds and compare curl-relative function and code-region identities.

Create an instrumented build in each source worktree with `codecoverage.sh`.
The default build layout puts binaries under `build-coverage/` and curl sources
under `build-coverage/curl/src/curl_external`, which the helper detects:

```shell
(cd /path/to/baseline-worktree && ./codecoverage.sh)
(cd /path/to/candidate-worktree && ./codecoverage.sh)

scripts/compare_fuzzers.py \
  --baseline-dir /path/to/baseline-libfuzzer-out \
  --candidate-dir /path/to/candidate-libfuzzer-out \
  --target-pair curl_fuzzer_http=curl_fuzzer_proto_http \
  --target-pair curl_fuzzer_http=curl_fuzzer_proto_http_deep \
  --target-pair curl_fuzzer_http=curl_fuzzer_proto_timing \
  --coverage-baseline-dir /path/to/baseline-worktree/build-coverage \
  --coverage-candidate-dir /path/to/candidate-worktree/build-coverage \
  --seconds 60 \
  --repeats 5
```

The aggregate source-coverage comparison unions the three candidate lanes, so
the fast target can intentionally omit stateful behavior without making the
replacement-parity number look worse. Benchmark the fast lane separately when
judging whether it can take over the legacy HTTP CPU allocation; the deep and
timing targets exist to retain coverage, not to match its throughput.

When curl was supplied with `codecoverage.sh -c`, pass the source roots
explicitly:

```shell
scripts/compare_fuzzers.py \
  ... \
  --baseline-curl-source-dir /path/to/baseline-curl \
  --candidate-curl-source-dir /path/to/candidate-curl
```

Use `--llvm-profdata` and `--llvm-cov` for versioned executable names, and
`--coverage-wall-timeout` to change the per-target replay limit. The helper
validates all binaries and tools before fuzzing, requires byte-identical curl
`lib/` and `src/` source trees, and rejects a coverage binary that produces no
profile. This prevents line-number comparisons across different curl revisions
from looking meaningful.

The main JSON gains a `source_coverage` object with per-target and aggregate
summaries. Its comparison records baseline-retention percentages plus complete
`baseline_only` and `candidate_only` function/region lists. Raw profiles,
merged profiles, exports, and replay logs are preserved below
`<log-dir>/source-coverage/`. The source metric deliberately replays a fixed
input snapshot; discoveries from the timed fuzzing runs do not leak into it.
Timer and event-loop scheduling can still move an occasional region between
runs, so repeat the replay before treating a marginal one-region gap as real.

For a conventional combined HTML report, a single target can still be replayed
after an instrumented build exists:

```shell
BUILD_DIR="$PWD/build-coverage" \
TARGETS=curl_fuzzer_proto_http \
scripts/run_coverage.sh
```

Use source coverage and libFuzzer features together when evaluating corpus
minimization or harness changes: line coverage alone does not preserve value,
counter, and indirect-call features used by the mutation scheduler.
