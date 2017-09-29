#!/bin/bash

set -ex

# Use gcc to test the code as code coverage is easier.
export CC=gcc
export CXX=g++
export CFLAGS=
export CXXFLAGS=

# Download cURL to a temporary folder.
./download_curl.sh /tmp/curlcov

# Move cURL to a subfolder of this folder to get the paths right.
if [[ -d ./curl ]]
then
  rm -rf ./curl
fi
mv /tmp/curlcov ./curl

# Compile and install cURL to a second folder with code coverage.
./install_curl.sh -c ./curl /tmp/curlcov_install

# Compile and test the fuzzer with code coverage
./compile_fuzzer.sh -c /tmp/curlcov_install

# Do a "make check-code-coverage" run to generate the coverage info.
make check-code-coverage
