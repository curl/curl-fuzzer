# Profiling fuzzer CPU use

`profile_fuzzer` records an on-CPU sampling profile for one
production libFuzzer binary. It is intended to find functions and call paths
that consume a significant part of the fuzzing budget. Use
[`compare_fuzzers`](BENCHMARKING.md) afterwards to measure whether a
change actually improves executions per second.

The profiler requires Linux `perf` and Python 3.10 or newer. The fuzzer should
be an optimized, symbolized AddressSanitizer/libFuzzer build with frame pointers.
The default binaries produced by `mainline.sh` use the standalone replay engine
and are deliberately rejected.

## Build a profiling binary

An OSS-Fuzz libFuzzer build supplies the same compiler, sanitizer, and runtime
shape used by the fleet. Given an OSS-Fuzz checkout at `/path/to/oss-fuzz`:

```shell
python3 /path/to/oss-fuzz/infra/helper.py build_fuzzers \
  --sanitizer address \
  --engine libfuzzer \
  curl "$PWD"
```

The binaries, seed archives, dictionaries, and options are written beneath
`/path/to/oss-fuzz/build/out/curl/`. A target's packaged `.options` file is part
of the workload: for example, the structured targets set `max_len`, and the
multi target sets a shorter per-input timeout.

Downloaded public corpora provide a more representative input population:

```shell
./scripts/download_public_corpus.sh
```

## Record a profile

Profile one target for 60 seconds:

```shell
uv run profile_fuzzer \
  --binary-dir /path/to/oss-fuzz/build/out/curl \
  --target curl_fuzzer_proto_http \
  --public-corpus-root ossfuzz_corpus \
  --seconds 60 \
  --output-dir build/profiles/proto-http
```

The profiler combines the checked-in corpus when a source checkout is
available, the target's packaged seed ZIP, and compatible public corpora. It
deduplicates inputs by SHA-256 and runs with a fixed libFuzzer seed. Repeat
`--corpus PATH` to replace these default sources. Each path may be a directory,
ZIP archive, or individual input.

By default, the profiler loads `<target>.options` beside the binary, falling
back to `ossconfig/<target>.options` when a source checkout is available. Use
`--options-file` to select another file and `--fuzzer-arg=-name=value` for
additional non-managed libFuzzer settings. The profiler owns duration, seed,
timeouts, artifacts, final stats, and single-process execution so the metadata
cannot disagree with the sampled workload.

The default event is the user-space software clock at 99 Hz. It works without a
virtualized hardware performance counter and measures time actually executing
on a CPU:

```shell
uv run profile_fuzzer ... \
  --event cpu-clock:u \
  --frequency 99
```

The default `fp` call graph requires frame pointers. Use `--call-graph dwarf`
for an existing binary that omitted them; DWARF stack samples are larger and
cost more to collect. `--cpu N` optionally pins the workload to one CPU.

The output directory must not already exist. A successful run contains:

- `perf.data`, the original sampling data;
- `perf-report.txt`, a symbolized flat report with all sampled symbols;
- `fuzzer.log`, including the exact perf and libFuzzer diagnostics;
- `metadata.json`, with binary and corpus hashes, commands, effective options,
  host settings, execution metrics, and supplied provenance;
- `corpus.zip`, the exact deduplicated inputs present before fuzzing starts;
- `summary.md`, including the highest-overhead symbols; and
- `artifacts/`, for any testcase emitted by libFuzzer.

Pass `corpus.zip` back through `--corpus` to repeat the workload after its
original sources have changed or disappeared.

The text report remains useful after the build host is gone. Interactive use of
`perf.data` requires the exact profiled binary and its build ID; its SHA-256 and
original path are recorded in `metadata.json`. Preserve that binary alongside
the profile, then add it to perf's build-ID cache before opening the data if the
original path is unavailable.

CI or build wrappers can attach revision information without exposing the
complete environment:

```shell
uv run profile_fuzzer ... \
  --provenance curl_revision=0123456789abcdef \
  --provenance oss_fuzz_revision=fedcba9876543210
```

## Run a profile in GitHub Actions

The **Profile fuzzer** workflow can be dispatched manually from the Actions
tab. Select a structured target and a 30, 60, or 120 second duration. The job
builds that target with OSS-Fuzz's AddressSanitizer/libFuzzer configuration,
downloads the public corpus, and records a user-space `cpu-clock` profile.

The uploaded `profile-...` artifact contains the report, raw `perf.data`, log,
metadata, exact `corpus.zip`, build-toolchain manifest, and any testcase emitted
by the fuzzer. It also includes `oss-fuzz-build.tar` with the exact binary,
options, seed archive, and `llvm-symbolizer` needed to inspect the raw profile
after the hosted runner has gone away.

## Interpreting results

Start with the highest-overhead symbols, then use the recorded call stacks in
`perf.data` to distinguish work owned by the harness from libcurl, TLS, parsing,
compression, protobuf mutation, and sanitizer checks. A hot function can be
called frequently because it is valuable coverage, so treat the profile as a
place to investigate rather than a reason to remove behavior.

Sampling overhead makes the run unsuitable as a throughput benchmark. Compare
the candidate against an unchanged baseline with the same corpus and repeated
runs as described in [Benchmarking](BENCHMARKING.md).

CPU samples deliberately exclude time spent asleep or blocked. Targets whose
purpose includes timing, backpressure, or scheduler behavior need separate
off-CPU analysis.

If `perf record` reports a permission error, inspect
`/proc/sys/kernel/perf_event_paranoid` and the host's perf policy. The profiler
does not invoke `sudo`; changing that policy belongs to the local machine or CI
runner configuration.
