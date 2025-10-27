#!/usr/bin/env bash
#
# This script is called from google/oss-fuzz:projects/curl/Dockerfile to install necessary
# dependencies for building curl fuzz targets.
#
# Use it to compile and install all the dependencies

set -ex

# Work out if we need to install with sudo or not.
if [[ $(id -u) -eq 0 ]]
then
    # We are root, so we can install without sudo.
    echo "Running as root, no sudo required."
    export SUDO=""
else
    # We are not root, so we need to use sudo.
    echo "Running as non-root, using sudo."
    export SUDO="sudo"
fi

# Download dependencies for oss-fuzz
$SUDO apt-get -o Dpkg::Use-Pty=0 update
$SUDO apt-get -o Dpkg::Use-Pty=0 install -y \
    make \
    autoconf \
    automake \
    libtool \
    libgmp-dev \
    libssl-dev \
    zlib1g-dev \
    pkg-config \
    wget \
    cmake \
    ninja-build \
    groff-base
