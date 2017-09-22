#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

# Make an install target for curl.
mkdir /tmp/curl_install

git clone http://github.com/curl/curl /tmp/curl

pushd /tmp/curl

# Build the library.
export CC=clang
export CXX=clang++
export CFLAGS="-fsanitize=address"
export CXXFLAGS="-fsanitize=address -stdlib=libstdc++"

./buildconf
./configure --prefix=/tmp/curl_install --disable-shared --enable-debug --enable-maintainer-mode
make
make install

popd