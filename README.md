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

`./mainline.sh` is run regressibly by Travis CI.

## I want to find the code coverage from the testcases

Run `./codecoverage.sh`. It will download you a fresh copy of curl, compile it
with `gcc`, install it, then compile the fuzzer against it. It'll then run a
coverage run and work out the coverage of the test cases, using `lcov` to
generate coverage information.

`./codecoverage.sh` is run regressibly by Travis CI.

## I want more information when running a testcase or multiple testcases

Setting the `FUZZ_VERBOSE` environment variable turns on curl verbose logging.
This can be useful when debugging a single testcase.

## I want to reproduce an error hit overnight by OSS-Fuzz

Check out [REPRODUCING.md](REPRODUCING.md) for more detailed instructions.

## What's in this testcase?

To look at the contents of a testcase, run
```
python read_corpus.py --input <path/to/file>
```
This will print out a list of contents inside the file.

## I want to generate a new testcase

To generate a new testcase, run `python generate_corpus.py` with appropriate
options.

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
