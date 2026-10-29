# Coverage

`codecoverage.sh` builds curl and the fuzzers with LLVM source-based coverage,
replays the available corpora, and reports libcurl and curl-fuzzer separately.
The libcurl report includes curl's `lib/`, public `include/curl/` headers, and
any mapped `src/` files. The harness report covers checked-in C++ sources and
headers, excluding tests, generated protobuf code, dependency build trees, and
the standalone replay engine.

```shell
./codecoverage.sh
```

The generated reports under `build-coverage/coverage/` are:

- `summary.txt` and `html/index.html`, libcurl text and
  annotated HTML reports;
- `harness-summary.txt` and `harness-html/index.html`,
  harness text and annotated HTML reports;
- `curl-coverage.json` and `harness-coverage.json`,
  scoped LLVM exports for further analysis;
- `report.md` and `gaps.json`, separate line, function,
  region, and branch counts plus ranked remaining gaps;
- `replay-status.json`, per-target input counts, exit codes, runner counters,
  and fresh profile evidence;
- `replay-logs/` and `replay-counters/`, retained target diagnostics and
  numeric input outcomes.

Percentages use exact covered/total counters. An unavailable metric or empty
denominator is not reported as 100%. Counts cover sources mapped into the
selected binaries; disabled features and other platforms require separate
builds. Compare changes using the same curl revision, toolchain, features, and
corpora, and investigate failed or incomplete replay before interpreting a
result as complete. `report.md` labels the selected replay as complete or
partial before presenting coverage percentages. A complete replay requires
every selected target to finish every counted input without detected errors
and to write a fresh nonempty profile; it does not mean 100% source coverage.
Failed, missing, or incomplete targets remain explicit while later targets
continue to contribute partial coverage.

Measure a local curl checkout with:

```shell
./codecoverage.sh -c /path/to/curl
```

If `ossfuzz_corpus/` exists, its downloaded inputs are replayed alongside the
checked-in or generated seeds. To rerun one target after an instrumented build:

```shell
BUILD_DIR="$PWD/build-coverage" \
TARGETS=curl_fuzzer_proto_http \
./scripts/run_coverage.sh
```

Each invocation replaces the previous replay profiles and derived reports,
so a single-target rerun reports only that selection. Failed merges retain
replay diagnostics without leaving old coverage reports available.

The GitHub Actions `Coverage` workflow is manual. It uploads both source reports
and their gap summaries and replay diagnostics, writes `report.md` to the job
summary, and reuses a public-corpus cache whose key changes each ISO week.

For controlled A/B performance and source-coverage comparisons, see
[Benchmarking](benchmarking.md).

`curl_fuzzer_proto_api` supplements corpus replay with deterministic public
compatibility API probes, such as formatting and deprecated form serialization.
The probes execute once per process in coverage builds (`ENABLE_COVERAGE=ON`
or `SANITIZER=coverage`) and Fuzz Introspector builds
(`SANITIZER=introspector`). They reuse the proto runtime's global curl
initialization and never perform global cleanup from an input callback. The
runtime releases its global resolver and TLS state only during process exit.
An initialization hook covers empty-corpus merge jobs, while the first input
callback is a fallback for standalone replay engines that omit that hook.

Utility probes cover the version string, documented date formats, and
deprecated escape/unescape aliases with short fixed strings and explicit binary
lengths.

Dynamic formatting probes use curl's real private buffer type and small
explicit limits to exercise exact fits, staging boundaries, and size-limit
errors. They allocate at most 1 KiB per case rather than depending on allocation
failures or large formatted output.

Every structured target supports allocation fault injection through the
scenario's `fail_allocations` field. The shared runtime installs libcurl's
[`curl_global_init_mem`](https://curl.se/libcurl/c/curl_global_init_mem.html)
callbacks once, before its ordinary global initialization, then arms them only
for the shared scenario runner. Protobuf parsing remains outside the selected
sequence; libcurl easy-handle setup, transfer driving, result probes, and
teardown are all part of it except for narrowly scoped harness ownership
operations. The `COPYPOSTFIELDS` ownership commit and pushed-handle cleanup
enumeration suppress injected failures; allocations in those scopes neither
count nor consume ordinals, leaving failures pending for subsequent injectable
allocations. Result probes still honor their public state preconditions: in
particular, upkeep runs only after an easy drive has progressed far enough to
attach its private multi.

Values are one-based positive-size allocation attempt numbers. Fixed target
policies sort, deduplicate, and retain at most four ordinals in the range
1..4096; the compatibility runtime applies the same safety bound without
rewriting its persistent input. A plan such as `5, 9` rejects the fifth
attempt, then interprets 9 as the ninth attempt on the execution path already
changed by that first failure. Ordinals reproduce within the same target,
build, TLS backend, and input; they are not source locations or portable
identifiers.

The API target keeps its event-based easy drive for inputs without a failure
plan. When a plan is present, the target normalizes that drive to ordinary
`curl_easy_perform`: after its socket-monitor allocation fails, curl's current
debug event adapter returns a status outside the socket-callback contract and
later removes a record it never inserted. This keeps the ordinal plan focused
on libcurl transfer and parser state without call-stack-dependent exclusions.

MIME bodies retain `CURLOPT_CRLF` and `CURLOPT_TRANSFERTEXT` under active plans,
so allocation injection covers failures while curl composes its MIME and
line-conversion readers. curl clears the partially installed reader stack if
that setup fails.

The active state is thread-local. Worker-thread allocations pass through, and
only allocations routed through libcurl's configured callbacks are counted.
This includes most libcurl storage and some dependency allocations made
through curl-provided adapters, but not general C++ harness, protobuf, or TLS
library heaps. Free is never rejected, a rejected realloc preserves its input,
and zero-size calls do not consume an ordinal. Each fuzzer entry resets the
controller before parsing so the standalone runner's timeout jump cannot carry
an armed plan into the next input.
