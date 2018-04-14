#!/bin/bash

set -ex

# Exit if the build root has not been defined.
[[ -d ${BUILD_ROOT} ]] || exit 1
SCRIPTDIR=${BUILD_ROOT}/scripts

DEPENDENCY=$1
DEPENDENCYDIR=$2
INSTALLDIR=$3

if [[ -z ${DEPENDENCYDIR} ]]
then
  DEPENDENCYDIR=/tmp/${DEPENDENCY}
fi

# Download the code if it isn't present
if [[ ! -d ${DEPENDENCYDIR} ]]
then
  ${SCRIPTDIR}/download_${DEPENDENCY}.sh ${DEPENDENCYDIR}
fi

# Compile and install the code
${SCRIPTDIR}/install_${DEPENDENCY}.sh ${DEPENDENCYDIR} ${INSTALLDIR}
