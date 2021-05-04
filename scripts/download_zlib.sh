#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Seems that https://www.zlib.net/zlib-1.2.11.tar.gz is now behind a proxy and
# wget downloads an HTML page instead of the archive.
# As a workaround, download this same archive (same hash) from the LIBPNG mirror
wget https://kumisystems.dl.sourceforge.net/project/libpng/zlib/1.2.11/zlib-1.2.11.tar.gz -O /tmp/zlib-1.2.11.tar.gz
tar -xvf /tmp/zlib-1.2.11.tar.gz --directory /tmp

# Copy the directory into the correct place
mv -v /tmp/zlib-1.2.11 $1
