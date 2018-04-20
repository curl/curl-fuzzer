#!/bin/bash

# Exit if the build root has not been defined.
[[ -d ${BUILD_ROOT} ]] || exit 1

. ${BUILD_ROOT}/scripts/fuzz_targets

if [[ ${DEBUG} == 1 ]]
then
  set -ex
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
  TEST_CASES=${BUILD_ROOT}/corpora/${TARGET}/* ${EXTRA_CORPUS}

  if [[ ${DEBUG} == 1 ]]
  then
    # Run each test individually so we can see where it crashes
    for ii in ${TEST_CASES}
    do
      ${BUILD_ROOT}/${TARGET} $ii
    done
  else
    # Run the fuzzer over all tests at once, which is faster.
    ${BUILD_ROOT}/${TARGET} ${TEST_CASES}
  fi
done
