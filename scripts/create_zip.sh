#!/bin/bash

set -ex

SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_ROOT=$(readlink -f "${SCRIPTDIR}/..")

. ${SCRIPTDIR}/fuzz_targets

for TARGET in ${FUZZ_TARGETS}
do
	pushd ${BUILD_ROOT}/corpora/${TARGET}
	zip ../../${TARGET}_seed_corpus.zip *
	popd
done
