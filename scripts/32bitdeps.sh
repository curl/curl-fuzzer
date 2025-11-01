#!/usr/bin/env bash
#
# This script is called in a 32-bit build environment to install necessary
# dependencies.

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
$SUDO dpkg --add-architecture i386
$SUDO apt-get -o Dpkg::Use-Pty=0 update
$SUDO apt-get -o Dpkg::Use-Pty=0 install -y \
  protobuf-compiler:i386 \
  libprotobuf-dev:i386 \
  libstdc++-9-dev:i386
