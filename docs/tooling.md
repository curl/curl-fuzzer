# Python tools

The `curl-fuzzer-tools` package requires Python 3.10 or newer.

## Install with uv

```shell
uv sync
uv run read_proto_corpus /path/to/testcase
```

Add the Python test extra when developing:

```shell
uv sync --extra python-tests
```

## Install with pip

```shell
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Commands

| Command | Purpose |
| --- | --- |
| `read_proto_corpus` | Decode one binary protobuf scenario using `protoc` |
| `generate_decoder_html` | Build the standalone browser decoder for protobuf `Scenario` inputs |
| `generate_matrix` | Package built fuzzers into balanced artifact shards and produce the CI matrix |
| `prepare_fuzzer` | Extract one fuzzer and its supporting files from a CI artifact shard |
| `generate_schema_eligibility` | Validate annotated schema eligibility and emit authoring, runtime, profile, adapter, report, and machine-contract artifacts |
| `compare_fuzzers` | Compare repeatable throughput and source coverage measurements between fuzzer builds |
| `profile_fuzzer` | Collect a reproducible Linux perf profile from one production libFuzzer target |
| `bootstrap_http2_corpus` | Select compatible HTTP/2 inputs into a dedicated corpus |
| `check_python_protobuf` | Verify that the installed Python protobuf runtime is compatible |
| `coverage_history` | Fetch aggregate or per-target OSS-Fuzz curl/lib history as a table, JSON, CSV, or SVG |

Run any command with `--help` for its complete interface.

## OSS-Fuzz coverage history

`coverage_history` reads the public daily `summary.json` artifacts and sums
the files under `curl/lib`. Aggregate reports use
`https://storage.googleapis.com/oss-fuzz-coverage/curl/reports/{YYYYMMDD}/linux/summary.json`;
passing `--target` selects
`https://storage.googleapis.com/oss-fuzz-coverage/curl/reports-by-target/{YYYYMMDD}/{TARGET}/linux/summary.json`.
Each JSON or CSV observation retains the exact URL used.

```shell
uv run coverage_history \
  --start 2026-10-01 --end 2026-10-28 \
  --format svg --metric functions > curl-lib-functions.svg

uv run coverage_history \
  --start 2026-10-01 --end 2026-10-28 \
  --target curl_fuzzer_proto_ldap --format json
```

## Schema generation and seed encoding

CMake invokes `generate_schema_eligibility` after host `protoc` has compiled
the annotated schema to a descriptor set. The command validates the profile
registry, contextual field shapes, native option names and types, and the
mapping to the C++ `TargetProfile` enum. Its generated files live under
`build/schema_eligibility/`; the metadata-free full authoring schema is staged
separately at `build/schemas/curl_fuzzer.proto`.

Normal checked-in textprotos need no projection command. CMake encodes the full
authoring `Scenario` with ordinary `protoc --encode`, and each restricted target
root preserves retained field tags while discarding unknown fields. Generated
conditional pruning and C++ target normalization run after the target parses
those bytes.

The typed-option edit was a breaking in-place schema change. Historical binary
inputs are not detected or converted by current tooling; reproduce them with
the curl-fuzzer revision and target that produced them.

## Browser decoder

The [published decoder](https://fuzz.curl.se/corpus-decoder/) accepts protobuf
`Scenario` inputs and does not upload the selected file. The generator bundles
the locked protobuf.js runtime and a metadata-free full authoring schema into
the HTML, so the resulting page does not need the generator-only eligibility
import and does not load a decoder from a CDN. It reuses
`build/schemas/curl_fuzzer.proto` when available; otherwise it invokes `protoc`
on the annotated checked-in schema and strips the metadata in memory. Build the
complete documentation site and decoder locally with:

```shell
npm ci --ignore-scripts --no-audit --no-fund
mdbook-mermaid install .
mdbook build
uv run generate_decoder_html --output _site/corpus-decoder/index.html
```

Then open `_site/index.html` for the book or
`_site/corpus-decoder/index.html` for the decoder. Build mdBook first because it
recreates the output directory.
