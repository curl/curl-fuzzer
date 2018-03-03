# Reproducing OSS-Fuzz issues
## Reproducible vs non-reproducible 
OSS-Fuzz generates two kinds of issues; reproducible and non-reproducible. It _generally_ only raises issues for reproducible problems; that is, a testcase that can be passed to the relevant fuzzer which causes a crash. They are marked as such in the OSS-Fuzz dashboard.

These instructions are for diagnosing reproducible problems.

## Getting started
### Reading the testcase
OSS-Fuzz should have given you a testcase that causes a crash in a fuzzer. Often the general area of the problem can be divined by reading the contents.

For most fuzzers, this is done using `read_corpus.py`:
```
$ python read_corpus.py --input ../clusterfuzz-testcase-minimized-6660139718279168
TLVHeader(type='CURLOPT_URL' (1), length=15, data='smb:/ @ /   /  ')
TLVHeader(type='Server banner (sent on connection)' (2), length=82, data='  \x00      \x00\x00\x00\x00                                                                     ')
2017-11-04 12:38:06,213 INFO  Returning 0
```
This example shows a testcase consisting of a configured URL (`CURLOPT_URL`) and a message sent to libcurl when it connects to that URL for the first time. There are many other options available; check `generate_corpus.py` for a comprehensive list.

The fnmatch fuzzer uses a special format of two null terminated strings, representing the pattern and string passed to Curl_fnmatch. This can be examined in your favourite text editor.

## Determining how to reproduce
Assuming the previous step didn't immediately reveal the problem, you can run the testcase against the fuzzer. OSS-Fuzz uses lots of different types of fuzzing engine, so it's worth checking if you can run against the mainline fuzzer.

When OSS-Fuzz raises an issue, it includes information at the top of the report:

```
Detailed report: https://oss-fuzz.com/testcase?key=6660139718279168

Project: curl
Fuzzer: libFuzzer_curl_fuzzer_smb
Fuzz target binary: curl_fuzzer_smb
Job Type: libfuzzer_ubsan_curl
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
$ FUZZ_VERBOSE=yes ./curl_fuzzer_smb ../clusterfuzz-testcase-minimized-6660139718279168
* STATE: INIT => CONNECT handle 0x62a000000208; line 1425 (connection #-5000)
* Unwillingly accepted illegal URL using 1 slash!
* Connecting to hostname: 127.0.1.127
* Added connection 0. The cache now contains 1 members
[../clusterfuzz-testcase-minimized-6660139718279168] Opened.. Read 109 bytes, fuzzing.. FUZZ: Using socket manager 0
FUZZ[0]: Using socket manager 0
FUZZ[0]: Sending initial response
FUZZ[0]: Shutting down server socket: 4
*   Trying 127.0.1.127...
* Could not set TCP_NODELAY: Operation not supported
* STATE: CONNECT => WAITCONNECT handle 0x62a000000208; line 1477 (connection #0)
* Connected to 127.0.1.127 () port 445 (#0)
* STATE: WAITCONNECT => SENDPROTOCONNECT handle 0x62a000000208; line 1594 (connection #0)
* Marked for [keep alive]: SMB default
* STATE: SENDPROTOCONNECT => PROTOCONNECT handle 0x62a000000208; line 1608 (connection #0)
FUZZ: Initial perform; still running? 1
* SMB conn 0x61d000001ac0 state change from SMB_CONNECTING to SMB_NEGOTIATE
curl_fuzzer_smb: memdebug.c:167: void *curl_domalloc(size_t, int, const char *): Assertion `wantedsize != 0' failed.
Aborted
```
Hooray, we hit the bug!

From here, you can either:
- modify libcurl to output extra diagnostics and rerun after recompiling
- use GDB to diagnose the fuzzer live
  - Setting a breakpoint on `__asan::ReportGenericError` will stop execution at the point where libasan detects a failure; this can be very useful to get to the correct point of failure.

If this hasn't worked then you may want to run in the OSS-Fuzz environment.

## Running in the OSS-Fuzz environment
Rather than reiterate OSS-Fuzz's guidance, you can read it at [https://github.com/google/oss-fuzz/blob/master/docs/reproducing.md](https://github.com/google/oss-fuzz/blob/master/docs/reproducing.md).

As an example, building the environment for the SMB example in previous sections would consist of running:
```
$ python infra/helper.py build_image curl
$ python infra/helper.py build_fuzzers --sanitizer undefined curl
$ python infra/helper.py reproduce curl curl_fuzzer_smb ../clusterfuzz-testcase-minimized-6660139718279168
```
