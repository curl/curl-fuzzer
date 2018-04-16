#!/bin/bash

set -ex

# Clone the oss-fuzz repository
git clone https://github.com/google/oss-fuzz.git /tmp/ossfuzz

# Modify the oss-fuzz Dockerfile so that we're checking out this branch.
sed -i "s@https://github.com/curl/curl-fuzzer.git@-b $TRAVIS_BRANCH https://github.com/curl/curl-fuzzer.git@" /tmp/ossfuzz/projects/curl/Dockerfile

# Try and build the curl fuzzers
pushd /tmp/ossfuzz
python infra/helper.py build_image --pull curl
python infra/helper.py build_fuzzers curl
popd
