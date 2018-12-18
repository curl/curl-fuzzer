#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Clone the repository to the specified directory.
git clone --depth=1 --branch v1.35.1 https://github.com/nghttp2/nghttp2 $1
