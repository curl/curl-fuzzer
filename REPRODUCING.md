# Reproducing Fuzzer Findings

## Decode Structured Scenarios

ACR repro images include the build-specific scenario schema and a `decode-scenario`
command. To decode a ClusterFuzz testcase on the host, mount it into the container:

```shell
docker run --rm -i \
  -v "$PWD/clusterfuzz-testcase-minimized-curl_fuzzer_proto_multi-5329718237528064:/testcase:ro" \
  curlfuzzer.azurecr.io/address-libfuzzer \
  decode-scenario /testcase
```

The command also accepts scenario data on standard input:

```shell
docker run --rm -i curlfuzzer.azurecr.io/address-libfuzzer decode-scenario \
  < clusterfuzz-testcase-minimized-curl_fuzzer_proto_multi-5329718237528064
```
# Reproducing OSS-Fuzz issues
## Reproducible vs non-reproducible
OSS-Fuzz generates two kinds of issues; reproducible and non-reproducible. It _generally_ only raises issues for reproducible problems; that is, a testcase that can be passed to the relevant fuzzer which causes a crash. They are marked as such in the OSS-Fuzz dashboard.

These instructions are for diagnosing reproducible problems.

## Getting started
### Reading the testcase
OSS-Fuzz should have given you a testcase that causes a crash in a fuzzer. Often the general area of the problem can be divined by reading the contents.

For most fuzzers, this is done using `read_corpus`:
```
$ read_corpus corpora/curl_fuzzer_http/test_url_http
TLVContents(type='CURLOPT_URL' (1), length=16, data=b'http://127.0.0.1')
```
This example shows a testcase consisting of a configured URL (`CURLOPT_URL`). There are many other options available; run `generate_corpus --help` for a comprehensive list.

## Determining how to reproduce
Assuming the previous step didn't immediately reveal the problem, you can run the testcase against the fuzzer. OSS-Fuzz uses lots of different types of fuzzing engine, so it's worth checking if you can run against the mainline fuzzer.

When OSS-Fuzz raises an issue, it includes information at the top of the report:

```
Detailed report: https://oss-fuzz.com/testcase?key=<testcase-key>

Project: curl
Fuzzer: libFuzzer_curl_fuzzer_http
Fuzz target binary: curl_fuzzer_http
Job Type: libfuzzer_asan_curl
Platform Id: linux
```
This shows:
- which fuzzing binary was being run
- what engine was being used (libfuzzer, afl)
- what sanitization options were being used (libasan = address sanitization, libubsan = undefined behaviour sanitization)

The fuzzing binaries built by `mainline.sh` can be used to reproduce issues which are using `libasan`. **For issues hit using libubsan, these should be reproduced using the OSS-Fuzz environment!**

## Reproducing using a `mainline.sh` binary
To reproduce, execute the fuzzer with the testcase as a parameter. Setting the environment variable FUZZ_VERBOSE=yes will cause the fuzzer to output in-depth information about what it's doing at each stage:
```
$ FUZZ_VERBOSE=yes ./curl_fuzzer_http ../clusterfuzz-testcase-minimized-<testcase-key>
```
If reproduction succeeds, the fuzzer will emit the same sanitizer report or crash described by OSS-Fuzz.

From here, you can either:
- modify libcurl to output extra diagnostics and rerun after recompiling
- use GDB to diagnose the fuzzer live
  - Setting a breakpoint on `__asan::ReportGenericError` will stop execution at the point where libasan detects a failure; this can be very useful to get to the correct point of failure.

If this hasn't worked then you may want to run in the OSS-Fuzz environment.

## Running in the OSS-Fuzz environment
Rather than reiterate OSS-Fuzz's guidance, you can read it at [https://github.com/google/oss-fuzz/blob/master/docs/reproducing.md](https://github.com/google/oss-fuzz/blob/master/docs/reproducing.md).

For an HTTP testcase, the equivalent commands are:
```
$ python infra/helper.py build_image curl
$ python infra/helper.py build_fuzzers --sanitizer undefined curl
$ python infra/helper.py reproduce curl curl_fuzzer_http ../clusterfuzz-testcase-minimized-<testcase-key>
```
