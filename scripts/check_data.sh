#!/usr/bin/env bash

SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_ROOT=$(readlink -f "${SCRIPTDIR}/..")

# Temporarily ignore corpus checking in memory sanitizer mode.
if [[ ${SANITIZER} == "memory" ]]
then
  echo "Temporarily ignore corpuses in memory mode, to let ossfuzz have fun"
  exit 0
fi

# Exit if the build root has not been defined.
. "${SCRIPTDIR}"/fuzz_targets

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

    # shellcheck disable=SC2248
    find "${BUILD_ROOT}/corpora/${TARGET}/" ${EXTRA_CORPUS} -type f -print0 | xargs -0 -L${PERCALL} "${BUILD_ROOT}/build/${TARGET}"
  fi
done
