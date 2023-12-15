#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

git clone --depth 1 --branch v1.1.0 https://github.com/ngtcp2/nghttp3 $1
