#!/bin/bash

set -ex

PROJECT_NAME=curl

# Clone the oss-fuzz repository
git clone https://github.com/google/oss-fuzz.git /tmp/ossfuzz

# Work out which branch to clone from, inside Docker
BRANCH=${GITHUB_REF}

# Modify the oss-fuzz Dockerfile so that we're checking out the current reference on CI.
sed -i "s@RUN git clone --depth 1 https://github.com/curl/curl-fuzzer.git /src/curl_fuzzer@RUN git config --global remote.origin.fetch '+refs/pull/*:refs/remotes/origin/pull/*' \&\& git clone https://github.com/curl/curl-fuzzer.git /src/curl_fuzzer \&\& cd /src/curl_fuzzer \&\& git checkout -b ${BRANCH}@" /tmp/ossfuzz/projects/${PROJECT_NAME}/Dockerfile

# Try and build the fuzzers
pushd /tmp/ossfuzz
python3 infra/helper.py build_image --pull ${PROJECT_NAME}
python3 infra/helper.py build_fuzzers ${PROJECT_NAME}
python3 infra/helper.py check_build ${PROJECT_NAME} --engine libfuzzer --sanitizer address --architecture x86_64
popd
