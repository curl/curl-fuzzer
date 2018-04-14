#!/bin/bash

set -ex

# Exit if the build root has not been defined.
[[ -d ${BUILD_ROOT} ]] || exit 1

. ${BUILD_ROOT}/scripts/fuzz_targets

for TARGET in ${FUZZ_TARGETS}
do
	pushd ${BUILD_ROOT}/corpora/${TARGET}
	zip ../../${TARGET}_seed_corpus.zip *
	popd
done
