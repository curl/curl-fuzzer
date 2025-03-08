# curl-fuzzer

Code and corpora for curl and libcurl fuzzing.

This is the curl fuzzing [OSS-Fuzz](https://github.com/google/oss-fuzz/tree/master/projects/curl) runs for us, non-stop.

## I just want to get fuzzing!

Great! Run `./mainline.sh`. It will download you a fresh copy of curl, compile
it with `clang`, install it to a temporary directory, then compile the fuzzer
against curl. It'll also run the regression testcases.

If you have a local copy of curl that you want to use instead, pass the path as
an argument to `./mainline.sh`. It will compile and install that curl to a
temporary directory instead.

`./mainline.sh` is run regressibly by Github Actions.

## I want more information when running a testcase or multiple testcases

Setting the `FUZZ_VERBOSE` environment variable turns on curl verbose logging.
This can be useful when debugging a single testcase.

## I want to download public corpus test files from OSS-Fuzz

The public corpus links for each target should be accessible here:

- [curl_fuzzer_dict](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_dict/public.zip)
- [curl_fuzzer_file](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_file/public.zip)
- [curl_fuzzer_ftp](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_ftp/public.zip)
- [curl_fuzzer_gopher](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_gopher/public.zip)
- [curl_fuzzer_http](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_http/public.zip)
- [curl_fuzzer_https](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_https/public.zip)
- [curl_fuzzer_imap](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_imap/public.zip)
- [curl_fuzzer_ldap](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_ldap/public.zip)
- [curl_fuzzer_mqtt](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_mqtt/public.zip)
- [curl_fuzzer_pop3](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_pop3/public.zip)
- [curl_fuzzer_rtmp](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_rtmp/public.zip)
- [curl_fuzzer_rtsp](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_rtsp/public.zip)
- [curl_fuzzer_scp](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_scp/public.zip)
- [curl_fuzzer_sftp](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_sftp/public.zip)
- [curl_fuzzer_smb](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_smb/public.zip)
- [curl_fuzzer_smtp](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_smtp/public.zip)
- [curl_fuzzer_tftp](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_tftp/public.zip)
- [curl_fuzzer_ws](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer_ws/public.zip)
- [curl_fuzzer](https://storage.googleapis.com/curl-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/curl_fuzzer/public.zip)
- fuzz_url: no public link yet.

## I want to reproduce an error hit overnight by OSS-Fuzz

Check out [REPRODUCING.md](REPRODUCING.md) for more detailed instructions.

## What's in this testcase?

To look at the contents of a testcase, run
```shell
poetry run read_corpus <path/to/file>
```
This will print out a list of contents inside the file.

## I want to generate a new testcase

To generate a new testcase, run
```shell
poetry run generate_corpus
```
with appropriate options.

# I want to enhance the fuzzer!

Wonderful! Here's a bit of information you may need to know.

## File format

Testcases are written in a Type-Length-Value or TLV format. Each TLV has:

- 16 bits for the Type
- 32 bits for the Length of the TLV data
- 0 - length bytes of data.

TLV type numbers are defined in both corpus.py and curl_fuzzer.h.

## Adding a new TLV.

To add a new TLV:

- Add support for it in the Python scripts: `generate_corpus.py`, `corpus.py`.
  This means adding options for reading the value of the TLV from the user (or
  from a file, or from test data)
- Add support for it in the fuzzer: `curl_fuzzer.cc`, `curl_fuzzer.h`. This
  likely means adding handling of the TLV to `fuzz_parse_tlv()`.
- Ensure that `FUZZ_CURLOPT_TRACKER_SPACE` can encompass your additional TLVs!
- If you decide to change a TLV number after you have created it and have
  generated test cases before you changed the TLV, rerun the test case
  generation to ensure your current TLV numbering maps your test cases as you
  expect.
