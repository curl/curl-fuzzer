# Getting started

## Prerequisites

The primary local workflow targets 64-bit Linux. It requires:

- Bash and common build tools;
- Clang and Clang++;
- CMake 3.24 or newer;
- Ninja or Make;
- Python 3;
- Git and network access for the first dependency build.

The build downloads and compiles curl and its static dependencies. It can take
several minutes and use substantial disk space on its first run; later runs
reuse the build tree.

## Build all fuzzers

From the repository root, run:

```shell
./mainline.sh
```

This builds curl master and the fuzz targets with AddressSanitizer. Outputs are
placed under `build/`. The local build links a standalone replay engine and, on
the default non-MemorySanitizer path, runs the CTest suite.

To use an existing curl checkout:

```shell
./mainline.sh -c /path/to/curl
```

To build one CMake target instead of the aggregate `fuzz` target:

```shell
./mainline.sh -t curl_fuzzer_http
```

MemorySanitizer builds use a separate directory and are compile/link checks:

```shell
SANITIZER=memory ./mainline.sh
```

## Replay inputs

Standalone binaries accept files and directories. A file produces a detailed
per-input trace; a directory is walked recursively:

```shell
FUZZ_VERBOSE=1 ./build/curl_fuzzer_http \
  corpora/curl_fuzzer_http/test_url_http

./build/curl_fuzzer_http corpora/curl_fuzzer_http/
```

Set `FUZZ_VERBOSE` to any value to enable libcurl's verbose output. Structured
targets use generated binary seeds under `build/generated_corpora/`:

```shell
./build/curl_fuzzer_proto_http \
  build/generated_corpora/curl_fuzzer_proto_http/
```

## Run mutation fuzzing

`mainline.sh` produces replay binaries by default; it does not begin a mutation
fuzzing campaign. The most production-like local route uses the
[OSS-Fuzz helper](https://google.github.io/oss-fuzz/getting-started/new-project-guide/#building-and-running-your-fuzzer):

```shell
git clone --depth 1 https://github.com/google/oss-fuzz.git .oss-fuzz
python3 .oss-fuzz/infra/helper.py build_image curl
python3 .oss-fuzz/infra/helper.py build_fuzzers \
  --sanitizer address --engine libfuzzer curl "$PWD"

mkdir -p build/local-corpus/curl_fuzzer_http
cp corpora/curl_fuzzer_http/* build/local-corpus/curl_fuzzer_http/
python3 .oss-fuzz/infra/helper.py run_fuzzer \
  --corpus-dir "$PWD/build/local-corpus/curl_fuzzer_http" \
  curl curl_fuzzer_http
```

Pass libFuzzer arguments after the target name when needed. The helper keeps
the compiler, sanitizer, engine, and packaging behavior aligned with OSS-Fuzz.
