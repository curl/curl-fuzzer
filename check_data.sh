#!/bin/bash

set -e

DEBUG=0

# Allows us to add an extra testing corpus locally.
if [[ -d ./extra_corpus ]]
then
    EXTRA_CORPUS=./extra_corpus/*
else
    EXTRA_CORPUS=
fi

if [[ ${DEBUG} == 1 ]]
then
  # Run each test individually so we can see where it crashes
  for ii in curl_fuzz_data/* ${EXTRA_CORPUS}
  do
    ./curl_fuzzer $ii
  done
else
  # Run the fuzzer over all tests at once, which is faster.
  ./curl_fuzzer curl_fuzz_data/* ${EXTRA_CORPUS}
fi
