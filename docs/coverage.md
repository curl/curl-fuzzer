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

Capsule encoding, decoding, and connection-filter coverage belongs to the
existing `curl_fuzzer_proto_http3` target. A CONNECT-UDP proxy scenario drives
the production easy-handle path; only the unreachable 1 GiB scalar varint
boundary is checked once at target startup. The timing target reaches MIME file
rewind through a backpressured 307 easy-handle retry and checks the portable
no-descriptor wait once at startup.

`include/curl/typecheck-gcc.h` is a special case when reading runtime reports:
its `CURLWARNING` helpers exist to produce compile-time API type diagnostics.
LLVM can count their shared macro body as an uncovered function even though
correctly typed calls do not execute it. The API target therefore invokes one
no-op helper directly from C, with its expected compiler warning suppressed.
It does not pass an invalid value through a libcurl varargs API. This gives the
header a truthful execution count while documenting why ordinary API use
cannot reach it.

## Local Fuzz Introspector report

Generate a source-based static reachability report using the same exclusions as
the compiler-based Introspector build. This excludes tests, examples, the curl
command-line tool and other paths listed in
[`fuzz_introspector_exclusion.config`](../fuzz_introspector_exclusion.config).
It does not execute a corpus or measure runtime coverage.

Install the upstream revision pinned by the Introspector CI workflow in a
separate environment (tested with Python 3.12):

```shell
python3.12 -m venv /tmp/curl-introspector-venv
/tmp/curl-introspector-venv/bin/python -m pip install \
  'git+https://github.com/ossf/fuzz-introspector.git@8bc858d7dd66f390e5bbd38c44d31fce41b72103#subdirectory=src'

/tmp/curl-introspector-venv/bin/python scripts/run_introspector_report.py \
  --curl-source /path/to/curl /tmp/curl-introspector-filtered
```

Open `/tmp/curl-introspector-filtered/fuzz_report.html`. The output directory
must be new or empty so stale metadata cannot enter the report.
`source-selection.json` records the checkout revisions, included sources and
excluded paths. Tracked files and unignored local C/C++ files are selected with
Git; ignored build outputs and nested checkouts are not scanned. Rules match
canonical `/src/curl/` and `/src/curl_fuzzer/` paths regardless of where the local
checkouts live. The command leaves the source files untouched.

For a comparison including tests and examples, repeat the command with
`--no-exclusions` and a different output directory. Both reports measure static
source reachability; their percentages are not runtime line-coverage results.

This filtering applies to this local command. OSS-Fuzz's daily source frontend
runs before the project's build script and does not read `FILES_TO_AVOID`.
Changing the config alone therefore does not filter that daily source report;
the compiler-based Introspector build does read it.
