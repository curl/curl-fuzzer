#!/bin/bash

# If any commands fail, fail the script immediately.
set -ex

latest="$(wget https://www.zlib.net/ -O - |
  hxclean | hxselect -i -c -s '\n' 'a::attr(href)' |
  grep -o -E 'zlib-[0-9.]+\.tar.gz' | sort -u -r | head -1)"

wget "https://www.zlib.net/${latest}" -O /tmp/src.tar.gz
tar -xvf /tmp/src.tar.gz --directory /tmp

# Move the directory into the correct place
mv -v /tmp/zlib-* "$1"
