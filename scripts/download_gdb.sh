#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

wget https://ftp.gnu.org/gnu/gdb/gdb-13.2.tar.xz -O /tmp/gdb.tar.gz
tar -xvf /tmp/gdb.tar.gz --directory /tmp

# Move the directory into the correct place
mv -v /tmp/gdb-* "$1"
