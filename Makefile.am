#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
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
AM_CXXFLAGS = -g -I@INSTALLDIR@/include -I@INSTALLDIR@/utfuzzer

LIBS = -lpthread -lm

# Run e.g. "make all LIB_FUZZING_ENGINE=/path/to/libFuzzer.a"
# to link the fuzzer(s) against a real fuzzing engine.
#
# OSS-Fuzz will define its own value for LIB_FUZZING_ENGINE.
LIB_FUZZING_ENGINE ?= libstandaloneengine.a

FUZZPROGS = curl_fuzzer \
 curl_fuzzer_altsvc \
 curl_fuzzer_base64 \
 curl_fuzzer_dict \
 curl_fuzzer_doh \
 curl_fuzzer_escape \
 curl_fuzzer_file \
 curl_fuzzer_ftp \
 curl_fuzzer_gopher \
 curl_fuzzer_http \
 curl_fuzzer_https \
 curl_fuzzer_imap \
 curl_fuzzer_ldap \
 curl_fuzzer_mqtt \
 curl_fuzzer_parsedate \
 curl_fuzzer_pop3 \
 curl_fuzzer_rtmp \
 curl_fuzzer_rtsp \
 curl_fuzzer_scp \
 curl_fuzzer_sftp \
 curl_fuzzer_smb \
 curl_fuzzer_smtp \
 curl_fuzzer_ws \
 curl_fuzzer_tftp \
 fuzz_url

FUZZLIBS = libstandaloneengine.a

COMMON_SOURCES = curl_fuzzer.cc curl_fuzzer_tlv.cc curl_fuzzer_callback.cc
COMMON_FLAGS = $(AM_CXXFLAGS) $(CODE_COVERAGE_CXXFLAGS)
COMMON_LDADD = @INSTALLDIR@/lib/libcurl.la $(LIB_FUZZING_ENGINE) $(CODE_COVERAGE_LIBS)

libstandaloneengine_a_SOURCES = standalone_fuzz_target_runner.cc
libstandaloneengine_a_CXXFLAGS = $(AM_CXXFLAGS)

# The main fuzzer; tests everything
curl_fuzzer_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_ALL
curl_fuzzer_LDADD = $(COMMON_LDADD)

# Protocol specific fuzzers
curl_fuzzer_dict_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_dict_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_DICT
curl_fuzzer_dict_LDADD = $(COMMON_LDADD)
curl_fuzzer_file_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_file_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_FILE
curl_fuzzer_file_LDADD = $(COMMON_LDADD)
curl_fuzzer_ftp_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_ftp_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_FTP
curl_fuzzer_ftp_LDADD = $(COMMON_LDADD)
curl_fuzzer_gopher_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_gopher_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_GOPHER
curl_fuzzer_gopher_LDADD = $(COMMON_LDADD)
curl_fuzzer_http_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_http_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_HTTP
curl_fuzzer_http_LDADD = $(COMMON_LDADD)
curl_fuzzer_https_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_https_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_HTTPS
curl_fuzzer_https_LDADD = $(COMMON_LDADD)
curl_fuzzer_imap_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_imap_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_IMAP
curl_fuzzer_imap_LDADD = $(COMMON_LDADD)
curl_fuzzer_ldap_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_ldap_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_LDAP
curl_fuzzer_ldap_LDADD = $(COMMON_LDADD)
curl_fuzzer_mqtt_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_mqtt_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_MQTT
curl_fuzzer_mqtt_LDADD = $(COMMON_LDADD)
curl_fuzzer_pop3_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_pop3_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_POP3
curl_fuzzer_pop3_LDADD = $(COMMON_LDADD)
curl_fuzzer_rtmp_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_rtmp_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_RTMP
curl_fuzzer_rtmp_LDADD = $(COMMON_LDADD)
curl_fuzzer_rtsp_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_rtsp_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_RTSP
curl_fuzzer_rtsp_LDADD = $(COMMON_LDADD)
curl_fuzzer_scp_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_scp_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_SCP
curl_fuzzer_scp_LDADD = $(COMMON_LDADD)
curl_fuzzer_sftp_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_sftp_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_SFTP
curl_fuzzer_sftp_LDADD = $(COMMON_LDADD)
curl_fuzzer_smb_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_smb_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_SMB
curl_fuzzer_smb_LDADD = $(COMMON_LDADD)
curl_fuzzer_smtp_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_smtp_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_SMTP
curl_fuzzer_smtp_LDADD = $(COMMON_LDADD)
curl_fuzzer_tftp_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_tftp_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_TFTP
curl_fuzzer_tftp_LDADD = $(COMMON_LDADD)
curl_fuzzer_ws_SOURCES = $(COMMON_SOURCES)
curl_fuzzer_ws_CXXFLAGS = $(COMMON_FLAGS) -DFUZZ_PROTOCOLS_WS
curl_fuzzer_ws_LDADD = $(COMMON_LDADD)

fuzz_url_SOURCES = fuzz_url.cc
fuzz_url_CXXFLAGS = $(COMMON_FLAGS)
fuzz_url_LDADD = $(COMMON_LDADD)

# Unit test fuzzers
curl_fuzzer_fnmatch_SOURCES = fuzz_fnmatch.cc
curl_fuzzer_fnmatch_CXXFLAGS = $(COMMON_FLAGS)
curl_fuzzer_fnmatch_LDADD = $(COMMON_LDADD)

curl_fuzzer_altsvc_SOURCES = fuzz_altsvc.cc
curl_fuzzer_altsvc_CXXFLAGS = $(COMMON_FLAGS) -I$(CURLDIR)
curl_fuzzer_altsvc_LDADD = $(COMMON_LDADD)

curl_fuzzer_base64_SOURCES = fuzz_base64.cc
curl_fuzzer_base64_CXXFLAGS = $(COMMON_FLAGS) -I$(CURLDIR)
curl_fuzzer_base64_LDADD = $(COMMON_LDADD)

curl_fuzzer_doh_SOURCES = fuzz_doh.cc
curl_fuzzer_doh_CXXFLAGS = $(COMMON_FLAGS) -I$(CURLDIR)
curl_fuzzer_doh_LDADD = $(COMMON_LDADD)

curl_fuzzer_escape_SOURCES = fuzz_escape.cc
curl_fuzzer_escape_CXXFLAGS = $(COMMON_FLAGS) -I$(CURLDIR)
curl_fuzzer_escape_LDADD = $(COMMON_LDADD)

curl_fuzzer_parsedate_SOURCES = fuzz_parsedate.cc
curl_fuzzer_parsedate_CXXFLAGS = $(COMMON_FLAGS) -I$(CURLDIR)
curl_fuzzer_parsedate_LDADD = $(COMMON_LDADD)

# Create the seed corpora zip files.
zip:
	BUILD_ROOT=$(PWD) scripts/create_zip.sh

# Test the seed corpora regressibly.
check: all
	BUILD_ROOT=$(PWD) scripts/check_data.sh

noinst_PROGRAMS = $(FUZZPROGS)
noinst_LIBRARIES = $(FUZZLIBS)
