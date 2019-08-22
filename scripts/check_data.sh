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
    EXTRA_CORPUS=./extra_corpus/
else
    EXTRA_CORPUS=
fi

for TARGET in ${FUZZ_TARGETS}
do
  if [[ ${TARGET} == "curl_fuzzer_ftp" ]] || [[ ${TARGET} == "curl_fuzzer_smtp" ]] || [[ ${TARGET} == "curl_fuzzer_smtp" ]] || [[ ${TARGET} == "curl_fuzzer" ]]
  then
    # For the moment, disable some problematic corpuses
    echo "Skipping ${TARGET}"
  else
    if [[ ${DEBUG} == 1 ]]
    then
      # Call tests individually
      PERCALL=1
    else
      # Call tests 100 at a time for speed.
      PERCALL=100
    fi

    find ${BUILD_ROOT}/corpora/${TARGET}/ ${EXTRA_CORPUS} -type f -print0 | xargs -0 -L${PERCALL} ${BUILD_ROOT}/${TARGET}
  fi
done
