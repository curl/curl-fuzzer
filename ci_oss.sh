#!/bin/bash

set -ex

# Store the current directory.
CURL_FUZZER_DIR=$(pwd)

PROJECT_NAME=curl

# Clone the oss-fuzz repository
git clone https://github.com/google/oss-fuzz.git /tmp/ossfuzz

# Work out which branch to clone from, inside Docker
BRANCH=${GITHUB_REF}

# Modify the oss-fuzz Dockerfile so that we're using the checked-out code from CI
sed -i "s@RUN git clone --depth 1 https://github.com/curl/curl-fuzzer.git /src/curl_fuzzer@COPY ./curl_fuzzer /src/curl_fuzzer@" /tmp/ossfuzz/projects/${PROJECT_NAME}/Dockerfile

# Try and build the fuzzers. Need to copy the fuzzer directory to the
# build context first.
pushd /tmp/ossfuzz
cp -r ${CURL_FUZZER_DIR} projects/curl/curl_fuzzer
python3 infra/helper.py build_image --pull ${PROJECT_NAME}
python3 infra/helper.py build_fuzzers ${PROJECT_NAME}
python3 infra/helper.py check_build ${PROJECT_NAME} --engine libfuzzer --sanitizer address --architecture x86_64
popd
