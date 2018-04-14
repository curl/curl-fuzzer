#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Clone the repository to the specified directory.
git clone --branch OpenSSL_1_0_2m https://github.com/openssl/openssl $1

