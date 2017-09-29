#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
AUTOMAKE_OPTIONS = foreign nostdinc
ACLOCAL_AMFLAGS = -I m4

@CODE_COVERAGE_RULES@

# Include debug symbols by default as recommended by libfuzzer.
AM_CXXFLAGS = -g -I@INSTALLDIR@/include

LIBS = -lpthread -lm

# Run e.g. "make all LIB_FUZZING_ENGINE=/path/to/libFuzzer.a"
# to link the fuzzer(s) against a real fuzzing engine.
#
# OSS-Fuzz will define its own value for LIB_FUZZING_ENGINE.
LIB_FUZZING_ENGINE ?= libstandaloneengine.a

FUZZPROGS = curl_fuzzer
FUZZLIBS = libstandaloneengine.a

curl_fuzzer_SOURCES = curl_fuzzer.cc
curl_fuzzer_CXXFLAGS = $(AM_CXXFLAGS) $(CODE_COVERAGE_CXXFLAGS)
curl_fuzzer_LDADD = @INSTALLDIR@/lib/libcurl.la $(LIB_FUZZING_ENGINE) $(CODE_COVERAGE_LIBS)

libstandaloneengine_a_SOURCES = standalone_fuzz_target_runner.cc
libstandaloneengine_a_CXXFLAGS = $(AM_CXXFLAGS)

# Some more targets.
zip:
	zip -q -r curl_fuzzer_seed_corpus.zip curl_fuzz_data

check: all
	./check_data.sh

noinst_PROGRAMS = $(FUZZPROGS)
noinst_LIBRARIES = $(FUZZLIBS)
