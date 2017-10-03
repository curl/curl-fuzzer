#!/bin/bash

set -ex

pushd curl_fuzz_data

zip ../curl_fuzzer_seed_corpus.zip *

popd
