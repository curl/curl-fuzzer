#!/bin/bash

set -ex

CURLDIR=$1
if [[ -z ${CURLDIR} ]]
then
  CURLDIR=/tmp/curlprof
fi

export CC=gcc
export CXX=g++
export CFLAGS="-pg"
export CXXFLAGS="-pg"

if [[ ! -d ${CURLDIR} ]]
then
    # Download cURL to the specified folder
    ./download_curl.sh ${CURLDIR}
fi

# Compile and install cURL to a second folder.
./install_curl.sh ${CURLDIR} /tmp/curlprof_install

# Compile and test the fuzzer.
./compile_fuzzer.sh /tmp/curlprof_install

# Call gprof to get a profiling report.
gprof ./curl_fuzzer
