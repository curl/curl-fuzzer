#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

wget https://zlib.net/zlib.tar.gz -O /tmp/src.tar.gz
tar -xvf /tmp/src.tar.gz --directory /tmp

# Move the directory into the correct place
mv -v /tmp/zlib-* "$1"
