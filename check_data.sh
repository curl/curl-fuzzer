#!/bin/bash

set -ex

DEBUG=0

if [[ ${DEBUG} == 1 ]]
then
  # Run each test individually so we can see where it crashes
  for ii in curl_fuzz_data/*
  do
    ./curl_fuzzer $ii
  done
else
  # Run the fuzzer over all tests at once, which is faster.
  ./curl_fuzzer curl_fuzz_data/*
fi
