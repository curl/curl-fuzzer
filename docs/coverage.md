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
  region, and branch counts plus ranked remaining gaps.

Percentages use exact covered/total counters. An unavailable metric or empty
denominator is not reported as 100%. Counts cover sources mapped into the
selected binaries; disabled features and other platforms require separate
builds. Compare changes using the same curl revision, toolchain, features, and
corpora, and investigate failed or incomplete replay before interpreting a
result as complete.

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

The GitHub Actions `Coverage` workflow is manual. It uploads both source reports
and their gap summaries, writes `report.md` to the job summary, and reuses a
public-corpus cache whose key changes each ISO week.

For controlled A/B performance and source-coverage comparisons, see
[Benchmarking](benchmarking.md).
