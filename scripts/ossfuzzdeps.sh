#!/bin/bash

set -ex

# Download dependencies for oss-fuzz
apt-get update
apt-get install -y make \
                   autoconf \
                   automake \
                   libtool \
                   libssl-dev \
                   zlib1g-dev \
                   pkg-config
