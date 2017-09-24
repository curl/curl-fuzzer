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
#***************************************************************************
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)

dnl We don't know the version number "statically" so we use a dash here
AC_INIT([curl-fuzzer], [-], [a suitable curl mailing list: https://curl.haxx.se/mail/])

dnl configure script copyright
AC_COPYRIGHT([Copyright (c) 1998 - 2017 Daniel Stenberg, <daniel@haxx.se>
This configure script may be copied, distributed and modified under the
terms of the curl license; see COPYING for more details])

AM_INIT_AUTOMAKE()
AC_PROG_CXX
AC_PROG_LIBTOOL

AC_CONFIG_FILES([
  Makefile
])
AC_SUBST([INSTALLDIR])
AC_OUTPUT