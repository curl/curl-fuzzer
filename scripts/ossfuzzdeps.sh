#!/bin/bash
#
# This script is called from google/oss-fuzz:projects/curl/Dockerfile to install necessary
# dependencies for building curl fuzz targets.
#
# Use it to compile and install all the dependencies

set -ex
SCRIPTDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Download dependencies for oss-fuzz
apt-get update
apt-get install -y make \
                   autoconf \
                   automake \
                   libtool \
                   libgmp-dev \
                   libssl-dev \
                   zlib1g-dev \
                   pkg-config \
                   wget \
                   cmake

# Compile and install the dependencies as well.
${SCRIPTDIR}/compile_target.sh deps
