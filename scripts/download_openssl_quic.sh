#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Clone the curl repository to the specified directory.
git clone --depth 1 -b openssl-3.1.4+quic https://github.com/quictls/openssl $1
