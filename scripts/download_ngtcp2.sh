#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Clone the repository to the specified directory.
git clone --depth 1 --branch v1.1.0 https://github.com/ngtcp2/ngtcp2 $1
