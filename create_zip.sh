#!/bin/bash

set -ex

. fuzz_targets

for TARGET in ${FUZZ_TARGETS}
do
	pushd corpora/${TARGET}
	zip ../../${TARGET}_seed_corpus.zip *
	popd
done
