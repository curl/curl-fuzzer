# curl-fuzzer

Fuzz targets, seed corpora, and developer tooling for curl and libcurl. This
repository supplies the harnesses used by curl's
[OSS-Fuzz project](https://github.com/google/oss-fuzz/tree/master/projects/curl).

[Documentation](https://fuzz.curl.se/) ·
[Legacy TLV corpus decoder](https://fuzz.curl.se/corpus-decoder/) ·
[Reproducing findings](REPRODUCING.md) ·
[Benchmarking](BENCHMARKING.md)

## Fuzzer families

| Family | Purpose | Seed source |
| --- | --- | --- |
| Legacy `curl_fuzzer` and protocol variants | Protocol-specific libcurl transfers driven by the established TLV format | `corpora/<target>/` |
| Structured `curl_fuzzer_proto*` | Protobuf scenarios with target-specific policies and in-process protocol peers | `scenarios/curl_fuzzer_proto/` |
| Direct `fuzz_*` targets | Focused fuzzing of URL, buffer queue, DoH, and netrc parsing | `corpora/<target>/` |

The conditional list in [`scripts/fuzz_targets`](scripts/fuzz_targets) is the
source of truth for targets packaged for OSS-Fuzz. Structured targets are not
built for i386, and some TLS and HTTP/3 variants are omitted from
MemorySanitizer builds.

## Build and replay locally

The primary local workflow targets Linux and requires Bash, Clang, CMake 3.24
or newer, Python 3, a build tool such as Ninja or Make, and network access for
the initial dependency build.

Build all targets against the latest curl source:

```shell
./mainline.sh
```

Use `-c` to build a local curl checkout, or `-t` to build one target:

```shell
./mainline.sh -c /path/to/curl
./mainline.sh -t curl_fuzzer_http
```

The default AddressSanitizer build creates standalone replay binaries under
`build/` and runs the CTest suite. A binary accepts either individual inputs or
directories:

```shell
FUZZ_VERBOSE=1 ./build/curl_fuzzer_http \
  corpora/curl_fuzzer_http/test_url_http
./build/curl_fuzzer_http corpora/curl_fuzzer_http/
```

These standalone binaries replay inputs; they do not perform mutation fuzzing.
See the [local fuzzing guide](https://fuzz.curl.se/getting-started.html#run-mutation-fuzzing)
for the OSS-Fuzz workflow and sanitizer options.

## Python tools

The Python package requires Python 3.10 or newer. With
[`uv`](https://docs.astral.sh/uv/):

```shell
uv sync
uv run read_corpus corpora/curl_fuzzer_http/test_url_http
```

Or use a conventional virtual environment:

```shell
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
read_corpus corpora/curl_fuzzer_http/test_url_http
```

Useful commands include:

- `read_corpus` for legacy TLV inputs.
- `read_proto_corpus` for binary protobuf scenarios; named fields require
  `protoc` and the generated schema from a build.
- `generate_corpus` for legacy TLV seeds.
- `tlv_to_proto` for converting legacy HTTP corpus entries to textproto.
- `generate_decoder_html` for the standalone legacy corpus decoder.

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

For legacy targets, checked-in binary seeds live in `corpora/`. For structured
targets, checked-in textproto files under `scenarios/` are the source of truth;
CMake generates their binary corpus entries in the build tree.

## Coverage

Build coverage-instrumented targets, replay local and downloaded corpora, and
produce text and HTML reports with:

```shell
./codecoverage.sh
```

The reports are written to:

- `build-coverage/coverage/summary.txt`
- `build-coverage/coverage/html/index.html`

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

Contributor documentation for the legacy and structured harnesses is in the
[documentation site](https://fuzz.curl.se/). See
[REPRODUCING.md](REPRODUCING.md) for crash investigation and
[BENCHMARKING.md](BENCHMARKING.md) for controlled performance and source
coverage comparisons.

## License

curl-fuzzer is distributed under the curl license. See [LICENSE](LICENSE).
