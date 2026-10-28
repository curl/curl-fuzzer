# Python tools

The `curl-fuzzer-tools` package requires Python 3.10 or newer.

## Install with uv

```shell
uv sync
uv run read_corpus corpora/curl_fuzzer_http/test_url_http
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

| Command                    | Purpose                                                                                         |
|----------------------------|-------------------------------------------------------------------------------------------------|
| `read_corpus`              | Decode one legacy TLV input                                                                     |
| `read_proto_corpus`        | Decode one binary protobuf scenario using `protoc`                                              |
| `generate_corpus`          | Generate a legacy TLV testcase                                                                  |
| `tlv_to_proto`             | Convert supported fields from a directory of legacy TLV inputs to textproto                     |
| `generate_decoder_html`    | Build the standalone browser decoder for legacy TLV and protobuf `Scenario` inputs              |
| `corpus_to_pcap`           | Convert response TLVs to a packet capture; requires Scapy from the development dependency group |
| `generate_matrix`          | Package built fuzzers into balanced artifact shards and produce the CI matrix                    |
| `prepare_fuzzer`           | Extract one fuzzer and its supporting files from a CI artifact shard                             |
| `generate_schema_eligibility` | Validate annotated schema eligibility and emit authoring, runtime, profile, adapter, report, and machine-contract artifacts |
| `compare_fuzzers`          | Compare repeatable throughput and source coverage measurements between fuzzer builds            |
| `profile_fuzzer`           | Collect a reproducible Linux perf profile from one production libFuzzer target                  |
| `coverage_history`         | Fetch aggregate or per-target OSS-Fuzz curl/lib history as a table, JSON, CSV, or SVG            |

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

## Proto migration function-parity ratchet

`compare_fuzzers --source-only` replays fixed native corpora through standalone
coverage binaries without running the timed libFuzzer benchmark phase. Run the
development gate with manifests retained alongside the audit artifacts:

```shell
uv run compare_fuzzers \
  --source-only \
  --coverage-baseline-dir build-coverage \
  --coverage-candidate-dir build-coverage \
  --parity-manifest /path/to/current/proto-migration-v1.json \
  --previous-parity-manifest /path/to/trusted/proto-migration-v1.json \
  --public-corpus-root /path/to/downloaded-corpora \
  --output build/measurements/proto-parity.json
```

For structured targets, a `--public-corpus-root` is accepted only with the
current epoch marker documented in [Corpus management](corpora.md).

For the initial bootstrap, the same audited v1 artifact can be supplied as
both the current and trusted prior manifest. After a ratchet update, retain
the promoted candidate durably with the audit artifacts; the prior path must
refer to that trusted predecessor. The code-pinned digest authenticates the
immutable baseline, but the hashes alone cannot reconstruct the manifest.
The [audited bootstrap artifact](https://gist.githubusercontent.com/cmeister2/60576b256b6bc2b19914905ab3632827/raw/44ef4e61f113c02880bf00773f704995853047a1/proto-migration-v1-bootstrap.json)
has full-file SHA-256
`3f1a0ace8a4d15581a4906ed9c8a15e7691bd82e3a57203c2c3dece6a4d2c1d0`.

The immutable v1 replay policy fixes the per-input timeout at 10 seconds,
matching the baseline audit. Manifest mode selects that value automatically
and rejects a different `--coverage-input-timeout`; ordinary source-coverage
runs retain their 25-second default. Manifest mode also defaults the outer
`--coverage-wall-timeout` to 7200 seconds because several complete audit
targets exceed the ordinary 300-second default. The outer limit remains
overrideable: it can only reject an incomplete target run, while the exact
replay counters prevent partial evidence from passing.

The v1 gate blocks only on whole functions. Three complete full-corpus replays
reproduced the same 2,237-function legacy universe exactly, but their ordinary
region universes differed because of wall-clock exact-zero paths, randomized
hash topology, resolver scheduling, and one non-atomic derived-counter
underflow. Region observations are summarized under `parity.regions` as
`indeterminate_nondeterministic`; complete comparison details remain under
`source_coverage`. They do not affect the development gate's status. The
result always sets `gate_scope` to
`development_function_parity` and `retirement_eligible` to `false`.

Do not interpret exit 0 as full source parity or permission to remove a legacy
target. Ordinary regions remain mandatory for retirement. Before a later
manifest makes them blocking, the remaining hash, time, and thread behavior
must be deterministic and the exact region universe must reproduce in two
independent full runs. Adding exact exclusions until an unstable run passes is
not an acceptable substitute.

Manifest mode requires both suites to come from the same coverage build. This
binds them to one curl checkout, feature configuration, TLS selection, and
toolchain. When no `--target` or `--target-pair` is supplied, the command uses
the manifest's ordered target-pair mapping. It validates that mapping against
`scripts/fuzz_targets`: all 10 legacy targets and all 30 proto lanes must be
represented. Only the standalone `fuzz_url`, `fuzz_bufq`, `fuzz_doh`, and
`fuzz_netrc` targets are outside the migration inventory. Unsupported target
inventory assignment forms fail closed so a new lane cannot evade the map.

Coverage builds compile both libcurl and the fuzzer code with
`-fprofile-update=atomic`, because replayed transfers can update profile
counters from multiple threads. The export parser requires function and
ordinary region counts to be JSON integers from zero through
`INT64_MAX - 1`; it rejects negative, saturated, and out-of-range values
instead of treating corrupt counter expressions as covered.

Source-only corpus discovery uses seed archives beside the coverage binaries,
plus checked-in corpora, explicit `--corpus` inputs, and the optional public
corpus root. Each unique variant and target is replayed once even when several
pairs reference it. Same-name comparisons intentionally share one snapshot.
The baseline audit attempted 46 public archives: 16 were available and 30
returned HTTP 403. The manifest binds only the exact available-corpus
snapshots; inaccessible archives were not measured and are not treated as
empty corpora.

Every standalone runner must write the exact five integer counters requested
through `FUZZ_REPLAY_STATUS_FILE`. The gate requires
`attempted == completed == expected > 0` and zero `timed_out`, `input_errors`,
and `path_errors`. It sets `FUZZ_TIMEOUT_SECS` from
`--coverage-input-timeout` and removes ambient replay/profile settings first.
Before assembling or replaying the corpus, manifest mode also sends and
receives a fixed payload over a local `AF_UNIX` socket pair. This fails fast in
execution sandboxes that let callbacks return normally while denying the
socket I/O required to reach protocol states; callback completion alone is not
evidence that a transfer ran.
It also discards ambient `ASAN_OPTIONS` and `LSAN_OPTIONS`, then pins
`ASAN_OPTIONS=detect_leaks=0`, matching the immutable manifest policy and the
baseline audit. Leak checking is outside this source-coverage comparison:
allowing LeakSanitizer to change the runner's exit status would reject
otherwise complete replay evidence and can prevent profile finalization.
Sanitizer findings remain the responsibility of the normal fuzzing and test
jobs. The exact policy is retained in the result's
`config.coverage_replay_sanitizer_environment` field.
Every raw profile, merged profile, LLVM export, status file, binary, and corpus
archive must exist and be nonempty; replay logs may legitimately be empty.
Paths, byte sizes, and SHA-256 hashes are recorded in schema-version 4 JSON.

The content-addressed corpus ZIPs are retained below the source-coverage log
directory after the temporary replay tree is removed. An artifact's `sha256`
identifies the ZIP bytes. Its `content_sha256` identifies the canonical set of
input content hashes and sizes and is the value used for manifest binding;
these two hashes normally differ.

The exit status is 0 for a trustworthy passing whole-function ratchet, 1 for a
newly missing or reappearing resolved function, and 2 for configuration,
manifest binding, inventory, or incomplete-evidence errors. An unrecorded
known gap that happens to execute is listed under `eligible_resolutions` but is
advisory and does not change the exit status. This avoids tightening the
ratchet around scheduler-sensitive incidental coverage. Region-only
differences remain diagnostic and never change the exit status. A post-replay
binding error is saved as structured `parity` data alongside the retained
source evidence before exit 2. The output path is cleared before semantic
validation so a stale passing result cannot survive failed setup or replay;
input/output collision checks run before that cleanup.

### Updating the ratchet

The v1 baseline fixes the gate policy, curl source identity, mapping and
inventories, baseline corpus identities, baseline covered references, initial
gaps, canonicalization, and audit provenance. Their canonical immutable-section
SHA-256 is pinned both in the supplied manifest and in `coverage_parity.py`.
It hashes every top-level field except `resolved_gaps` and the digest field
itself. The exact initial function and diagnostic region-reference sets are
independently pinned at 215 identities
(`da37b0ff5442655adb94150e2ae1f2f59cbde2c2d8c3ffddbd5584d79668f538`)
and 6,470 identities
(`90765eab0b68a4d8fe40e57b2eb24c68dc872493bd83e183213dc4c9155f2bf6`).
Identity hashes are SHA-256 over UTF-8 JSON for the whole lexicographically
sorted identity array, using `ensure_ascii=false`, separators `[",", ":"]`,
and sorted object keys.

An ordinary improvement may only add a function already present in
`initial_gaps.functions` to `resolved_gaps.functions`. A fresh result must list
it under `eligible_resolutions`, and targeted evidence must establish that the
coverage is intentional and reproducible before it is recorded. Create an
external candidate from the trusted prior manifest, add only the verified
resolutions, and rerun the full ratchet. A resolution becomes binding when the
passing candidate is retained as the trusted artifact for the next run.
`resolved_gaps.regions` must remain empty while regions are diagnostic. Do not
remove a resolved function or edit any baseline field. Every manifest run
requires `--previous-parity-manifest`; the command rejects a candidate that
changes the immutable digest or drops a prior function resolution. The trust
boundary is the code-pinned immutable digest together with deliberate
selection of the durable, content-addressed prior artifact.

Changing the gate policy, `initial_gaps`, curl source, target mapping or
inventory, baseline corpora or covered references, canonicalization, or
provenance is a baseline refresh, not an ordinary ratchet update. A refresh
requires a new full audit and an explicit update to the code-pinned baseline
digest and initial-set hashes.

## Browser decoder

The [published decoder](https://fuzz.curl.se/corpus-decoder/)
accepts legacy TLV and protobuf `Scenario` inputs. It detects the format
automatically, allows manual selection, and does not upload the selected file.
Empty, unknown-only, or damaged inputs may require selecting a format manually.
The generator bundles the locked protobuf.js runtime and a metadata-free full
authoring schema into the HTML, so the resulting page does not need the
generator-only eligibility import and does not load a decoder from a CDN. It
reuses `build/schemas/curl_fuzzer.proto` when available; otherwise it invokes
`protoc` on the annotated checked-in schema and strips the metadata in memory.
Build the complete documentation site and decoder locally with:

```shell
npm ci --ignore-scripts --no-audit --no-fund
mdbook-mermaid install .
mdbook build
uv run generate_decoder_html --output _site/corpus-decoder/index.html
```

Then open `_site/index.html` for the book or
`_site/corpus-decoder/index.html` for the decoder. Build mdBook first because it
recreates the output directory.
