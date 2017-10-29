#!/bin/bash

. fuzz_targets

DEBUG=0

if [[ ${DEBUG} == 1 ]]
then
  set -x
else
  set -e
fi

# Allows us to add an extra testing corpus locally.
if [[ -d ./extra_corpus ]]
then
    EXTRA_CORPUS=./extra_corpus/*
else
    EXTRA_CORPUS=
fi

for TARGET in ${FUZZ_TARGETS}
do
  TEST_CASES=corpora/${TARGET}/* ${EXTRA_CORPUS}

  if [[ ${DEBUG} == 1 ]]
  then
    # Run each test individually so we can see where it crashes
    for ii in ${TEST_CASES}
    do
      ./${TARGET} $ii
    done
  else
    # Run the fuzzer over all tests at once, which is faster.
    ./${TARGET} ${TEST_CASES}
  fi
done