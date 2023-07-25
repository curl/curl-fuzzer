#!/bin/bash
# If any commands fail, fail the script immediately.
set -ex

export CFLAGS=
export CXXFLAGS=

SRCDIR=$1

pushd ${SRCDIR}

./configure
make
make install

popd
