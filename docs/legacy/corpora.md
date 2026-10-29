# Working with legacy corpora

Checked-in seeds live in `corpora/<target>/`. The active target list is
maintained in `scripts/fuzz_targets`; do not infer it from old corpus
directories that may remain for historical targets.

The commands below assume the repository's Python package is installed in an
active Python 3.10 or newer environment:

```shell
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

With `uv`, the same tools can be invoked as `uv run read_corpus`,
`uv run generate_corpus`, and `uv run generate_decoder_html` without manually
activating the environment.

## Inspect a testcase

`read_corpus` prints one decoded record per line:

```console
$ read_corpus corpora/curl_fuzzer/test_file_nobody
TLVContents(type='CURLOPT_URL' (1), length=24, data=b'file:///proc/self/status')
TLVContents(type='CURLOPT_HEADER' (27), length=4, data=b'\x00\x00\x00\x01')
TLVContents(type='CURLOPT_NOBODY' (28), length=4, data=b'\x00\x00\x00\x01')
```

For interactive inspection, use the published
[corpus decoder](../corpus-decoder/). It recognizes legacy TLV inputs and reads
the selected file entirely in the browser. To generate a standalone copy
locally:

```shell
generate_decoder_html --output /tmp/curl-corpus-decoder.html
```

## Generate a seed

`generate_corpus` always requires an output path and URL. Other flags add
responses, uploads, authentication, headers, MIME parts, and selected curl
options. Run `generate_corpus --help` for the implemented set.

The historical `--hsts` argument emits disabled TLV type 51 and should not be
used for a new seed; see [Parser behavior](tlv-format.md#parser-behavior).

This Bash example creates an HTTP seed with an initial server response and
then checks its contents:

```shell
generate_corpus \
  --output /tmp/http-seed \
  --url http://127.0.0.1/ \
  --rsp0 $'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
read_corpus /tmp/http-seed
```

Responses can instead come from a binary file (`--rsp0file`) or the
`<reply><data>` section of a curl test (`--rsp0test` together with
`--curl_test_dir`). Repeated options such as `--header`, `--mailrecipient`, and
`--mimepart name:value` may be supplied more than once.

Before checking in a seed, put it under the matching active target directory,
decode it, and replay it with that target. Use a URL for the intended protocol:
the generic legacy target selects the protocol from that URL.

## DoH loopback seeds

`curl_fuzzer` cannot install its socketpair mocks on the internal easy handle
curl creates for DNS-over-HTTPS probes, so ordinary `CURLOPT_DOH_URL` inputs
always fail in the sandbox. The harness-owned records below let a seed point the
probe at a real listener on `127.0.0.1` instead:

- `TLV_TYPE_DOH_LOOPBACK` (162): start the listener and set `CURLOPT_DOH_URL`.
- `TLV_TYPE_DOH_RESPONSE` (163): optional raw DNS response body to serve; the
  default synthesizes A, AAAA, or HTTPS RR answers matching the query.
- `TLV_TYPE_DOH_HTTP_STATUS` (164): HTTP status to return (default `200`).
- `TLV_TYPE_VERBOSE` (165): enable curl's DoH tracing with a no-op debug
  callback, which exercises the status/error string helpers.

The listener answers with plaintext HTTP, which requires the debug-enabled
curl build used by this repository. If `socket`/`bind` is unavailable, the
input runs without DoH rather than failing. While a loopback input runs, the
harness temporarily sets `no_proxy`/`NO_PROXY` to `*` and restores the prior
environment afterwards, so ambient proxy settings cannot divert the internal
DoH handle. The mutator preserves these records when they are inherited from a
seed but never invents them for other inputs. See
`corpora/curl_fuzzer/doh_loopback*` for examples.

## Build and replay

Build one target with the repository's standalone replay engine:

```shell
./mainline.sh -t curl_fuzzer
```

The resulting runner accepts files and directories. A directory is walked
recursively:

```shell
./build/curl_fuzzer corpora/curl_fuzzer/test_file_nobody
./build/curl_fuzzer corpora/curl_fuzzer/
```

Set `FUZZ_VERBOSE=1` when replaying one testcase to show curl's verbose trace
and the simulated peer traffic:

```shell
FUZZ_VERBOSE=1 ./build/curl_fuzzer /path/to/testcase
```

The default local build replays inputs; it does not perform mutation. Follow
the [local mutation workflow](../getting-started.md#run-mutation-fuzzing) to
build and run the target through OSS-Fuzz's libFuzzer environment. LibFuzzer
then discovers `LLVMFuzzerCustomMutator` and `LLVMFuzzerCustomCrossOver` from
`legacy_tlv_mutator.cc`; see
[Legacy TLV fuzzers](overview.md#structure-aware-mutation) for their policy.

## Public OSS-Fuzz corpora

Download all currently published corpora with:

```shell
./scripts/download_public_corpus.sh
```

The script writes each archive beneath `ossfuzz_corpus/<target>/`, skips
targets without a published archive, and accepts `-f` to refresh existing
downloads. `codecoverage.sh` replays these directories alongside the checked-in
seeds when they are present.
