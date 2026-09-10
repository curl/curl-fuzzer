# Coverage

`codecoverage.sh` builds curl and the fuzzers with LLVM source-based coverage,
replays the available corpora, and limits the report to curl's `lib/` and
`src/` trees.

```shell
./codecoverage.sh
```

The generated reports are:

- `build-coverage/coverage/summary.txt`, an `llvm-cov report` summary;
- `build-coverage/coverage/html/index.html`, a browsable annotated report.

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

The GitHub Actions `Coverage` workflow is manual. It uploads both reports,
writes the text summary to the job summary, and reuses a public-corpus cache
whose key changes each ISO week.

For controlled A/B performance and source-coverage comparisons, see
[Benchmarking](benchmarking.md).
