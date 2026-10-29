# curl-fuzzer

Fuzz targets, seed corpora, and developer tooling for curl and libcurl. This
repository supplies the harnesses used by curl's
[OSS-Fuzz project](https://github.com/google/oss-fuzz/tree/master/projects/curl).

[Documentation](https://fuzz.curl.se/) ·
[Corpus decoder](https://fuzz.curl.se/corpus-decoder/) ·
[Reproducing findings](REPRODUCING.md) ·
[Benchmarking](BENCHMARKING.md) ·
[Profiling](PROFILING.md)

## Fuzzer families

| Family | Purpose | Seed source |
| --- | --- | --- |
| Structured `curl_fuzzer_proto*` | Typed protobuf scenarios projected into generated target-specific mutation roots, with in-process protocol peers | `scenarios/curl_fuzzer_proto/` |
| Direct `fuzz_*` targets | Focused fuzzing of URL, buffer queue, DoH, and netrc parsing | `corpora/<target>/` |

The conditional list in [`scripts/fuzz_targets`](scripts/fuzz_targets) is the
source of truth for targets packaged for OSS-Fuzz. The base structured targets
are built for OSS-Fuzz's AddressSanitizer/i386 configuration. The GnuTLS,
mbedTLS, and HTTP/3 variants are omitted from i386 and MemorySanitizer builds.

## Build and replay locally

The primary local workflow targets Linux and requires Bash, Clang, CMake 3.24
or newer, Python 3.10 or newer, the Protocol Buffers compiler (`protoc`) and
well-known `.proto` files (`protobuf-compiler` plus `libprotobuf-dev` on Debian
and Ubuntu), the project Python dependencies, a build tool such as Ninja or
Make, and network access for the initial dependency build. The schema generator
runs during CMake configuration, so install its dependencies before building:

```shell
uv sync
# Or, in an activated virtual environment: python -m pip install -e .
```

Build all targets against the latest curl source:

```shell
./mainline.sh
```

Use `-c` to build a local curl checkout, or `-t` to build one target:

```shell
./mainline.sh -c /path/to/curl
./mainline.sh -t curl_fuzzer_proto_http
```

The default AddressSanitizer build creates standalone replay binaries under
`build/` and runs the CTest suite. A binary accepts either individual inputs or
directories:

```shell
FUZZ_VERBOSE=1 ./build/curl_fuzzer_proto_http \
  build/generated_corpora/curl_fuzzer_proto_http/basic_get.scenario
./build/curl_fuzzer_proto_http \
  build/generated_corpora/curl_fuzzer_proto_http/
```

These standalone binaries replay inputs; they do not perform mutation fuzzing.
See the [local fuzzing guide](https://fuzz.curl.se/getting-started.html#run-mutation-fuzzing)
for the OSS-Fuzz workflow and sanitizer options.

## Python tools

The Python package requires Python 3.10 or newer. With
[`uv`](https://docs.astral.sh/uv/):

```shell
uv sync
uv run read_proto_corpus /path/to/testcase
```

Or use a conventional virtual environment:

```shell
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
read_proto_corpus /path/to/testcase
```

Useful commands include:

- `read_proto_corpus` for binary protobuf scenarios; named fields require
  `protoc`, but do not require a prior build from a source checkout.
- `generate_decoder_html` for the standalone browser decoder for protobuf
  `Scenario` inputs. Run `npm ci --ignore-scripts` once before
  building it so the pinned protobuf.js runtime can be bundled into the page.
  For an annotated schema, the generator uses `protoc` to produce the current
  metadata-free authoring view; it falls back to a staged build copy only when
  `protoc` is unavailable.
- `compare_fuzzers` for repeatable throughput and source-coverage comparisons
  between production libFuzzer builds.

Each command supports `--help`. The complete list of installed entry points is
in [`pyproject.toml`](pyproject.toml).

## Corpora

Download the public OSS-Fuzz corpora for every currently supported target:

```shell
./scripts/download_public_corpus.sh
```

Inputs are extracted to `ossfuzz_corpus/<target>/`. Existing non-empty target
directories are retained; pass `-f` to refresh them. Missing public corpora are
reported and skipped because newly added targets may not have one yet.

Automatic replay of structured public corpora is fail-closed across the typed
schema cutover. After the upstream structured corpora have been replaced, move
any existing `ossfuzz_corpus` aside, download a fresh snapshot, then explicitly
mark that root current:

```shell
mv ossfuzz_corpus ossfuzz_corpus.pre-schema-owned-eligibility
./scripts/download_public_corpus.sh
touch ossfuzz_corpus/.structured-schema-owned-eligibility-v1
```

The downloader never creates this marker because public ZIPs do not identify
their schema. Do not mark a root that still contains pre-cutover structured
directories.

Bootstrap the dedicated HTTP/2 corpus from current typed Scenario inputs after
downloading them (requires `protoc` and its well-known schemas, provided by
`protobuf-compiler` and `libprotobuf-dev` on Debian and Ubuntu):

```shell
uv run bootstrap_http2_corpus
```

This adds byte-identical inputs whose final explicit `CURLOPT_HTTP_VERSION`
setting in the first 64 options is prior knowledge (`http_version: 5`) to
`ossfuzz_corpus/curl_fuzzer_proto_http2/`. It excludes HTTP/1 version selections, overridden
version settings, and malformed protobufs. The predicate is conservative;
it does not simulate curl's validation or target normalization. Native inputs
are retained, and the manifest under `ossfuzz_corpus/.manifests/` records source,
schema, and selected corpus hashes plus rejected input hashes. Existing corpus
routing picks up this native directory for coverage, benchmarking, and profiling.
The command does not migrate pre-cutover generic-option bytes; use those only
with the curl-fuzzer revision and target that produced them. Default source
discovery requires the same structured-corpus epoch marker; explicit `--source`
inputs remain the caller's responsibility.

The bootstrap is additive. Before refreshing public corpora, use the downloader's
`-f` flag so the bootstrapped directory does not hide a newly published native
corpus, then rerun the bootstrap. `--source` accepts repeatable directory, ZIP,
or file inputs; `--output-zip` writes a reproducible selected-input archive for
a one-time upload to the dedicated OSS-Fuzz target. Keep ZIPs and manifests
outside replay directories. Run `uv run bootstrap_http2_corpus --help` for paths.

For direct targets, checked-in binary seeds live in `corpora/`. For structured
targets, checked-in textproto files under `scenarios/` are the source of truth.
They use the full typed authoring schema; CMake encodes them with ordinary
`protoc --encode` into the build tree. Generated profile roots preserve the
authoring field numbers, so each target reads the same bytes and discards fields
and option cases outside its schema-owned surface. Historical binaries from the
pre-cutover generic-option schema must be reproduced with their original
revision; they are not auto-detected or converted by the runtime.

## Coverage

Build coverage-instrumented targets, replay local and downloaded corpora, and
produce text and HTML reports with:

```shell
./codecoverage.sh
```

The reports are written to:

- `build-coverage/coverage/summary.txt`
- `build-coverage/coverage/html/index.html`
- `build-coverage/coverage/harness-summary.txt`
- `build-coverage/coverage/harness-html/index.html`
- `build-coverage/coverage/report.md`
- `build-coverage/coverage/gaps.json`

The existing summary and HTML paths report curl's `lib/`, `include/curl/`, and
`src/` sources.
The harness reports cover checked-in C++ sources and headers, excluding tests,
the standalone replay engine, generated code, and dependency build trees.
`report.md` tracks line, function, region, and branch coverage separately for
each source group and ranks remaining gaps. `gaps.json` preserves exact
covered/total counters; an unavailable metric or empty denominator is not
reported as 100%. The scoped LLVM exports, `curl-coverage.json` and
`harness-coverage.json`, support further analysis.

Coverage measures the sources mapped into the selected binaries. Disabled
features and other platforms need their own builds, and failures or incomplete
corpus replay need investigation before interpreting a result as complete.
Compare changes using the same curl revision, toolchain, features, and corpora.

The structured `curl_fuzzer_proto_api` coverage/introspection build runs
the curl API probes once during initialization, with a first-callback fallback
for standalone runners. Those probes reuse the live proto curl runtime; global
cleanup is deferred until process exit.

Pass `-c /path/to/curl` to cover a local curl checkout. The manual `Coverage`
GitHub Actions workflow publishes the same reports and reuses a public-corpus
cache keyed by ISO week.

## Development

Install the Python test dependencies and run the repository checks with:

```shell
uv sync --extra python-tests
uv run pytest tests/test_*.py
./lint.sh
```

Contributor documentation for the structured and direct harnesses is in the
[documentation site](https://fuzz.curl.se/). See
[REPRODUCING.md](REPRODUCING.md) for crash investigation and
[BENCHMARKING.md](BENCHMARKING.md) for controlled performance and source
coverage comparisons, and [PROFILING.md](PROFILING.md) for CPU hotspot
analysis.

## License

curl-fuzzer is distributed under the curl license. See [LICENSE](LICENSE).
