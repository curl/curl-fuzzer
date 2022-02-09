#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Clone the repository to the specified directory.
git clone --branch v1.58.0 https://github.com/nghttp2/nghttp2 $1
