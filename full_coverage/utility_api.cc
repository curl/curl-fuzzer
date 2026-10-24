/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "full_coverage/utility_api.h"

#include <ctime>

#include <curl/curl.h>

namespace full_coverage {
namespace {

/** Replay ordinary formats documented by curl and its date-parser tests. */
void ExerciseDates()
{
  // Valid formats and ordinary calendar variants follow
  // curl/docs/libcurl/curl_getdate.md. Epoch,
  // unsupported-format, calendar-range, and time_t-range examples come from
  // curl/tests/libtest/lib517.c. Every input is a short, fixed date string.
  const char *const dates[] = {
      "Sun, 06 Nov 1994 08:49:37 GMT",
      "Sunday, 06-Nov-94 08:49:37 GMT",
      "Sun Nov  6 08:49:37 1994",
      "06-Jul-94 08:49:37",
      "GMT 08:49:37 06-Aug-95 Sunday",
      "94 6 Oct 08:49:37",
      "1994 Mar 6",
      "1994.Feb.6",
      "Sun/Jun/6/93/GMT",
      "Mon, 06 Nov 1995 08:49:37 CET",
      "Tue, 06 Nov 2001 08:49:37 EST",
      "Sun, 12 Sep 2004 15:05:58 -0700",
      "Fri, 11 Sep 2009 21:32:11 +0200",
      "20040912 15:05:58 -0700",
      "20040911 +0200",
      "Saturday, May 5 GMT 11:56:27 2035",
      "Sat, 15-Apr-17 21:01:22 GMT",
      "Wed, 31 Dec 2008 23:59:60 GMT",
      "Thu, 01-Jan-1970 00:00:00 GMT",
      "Thu, 31-Dec-1969 23:59:59 GMT",
      "IAintNoDateFool",
      "1994-11-06T08:49:37Z",
      "Thu, 01-Jan-1499 00:00:00 GMT",
      "Sun, 06 Nov 1900 08:49:37 GMT",
      "Sun, 06 Nov 2044 08:49:37 GMT",
      ""};
  for(const char *date : dates) {
    const volatile std::time_t parsed = curl_getdate(date, nullptr);
    (void)parsed;
  }
  const volatile std::time_t missing = curl_getdate(nullptr, nullptr);
  (void)missing;
}

/** Cover compatibility aliases and the explicit binary-length API contract. */
void ExerciseEscaping()
{
  const char *const strings[] = {
      "",
      "data to convert",
      "a/b?c=d&reserved=+ %#",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"};
  for(const char *text : strings) {
    char *encoded = curl_escape(text, 0);
    if(encoded) {
      curl_free(curl_unescape(encoded, 0));
      int length = 0;
      curl_free(curl_easy_unescape(nullptr, encoded, 0, &length));
    }
    curl_free(encoded);
  }

  // The escaping documentation specifies byte-oriented encoding. Explicit
  // lengths preserve an embedded NUL and a non-ASCII byte through decoding.
  const char binary[] = {'a', '\0', '%', static_cast<char>(0xff)};
  char *encoded = curl_escape(binary, static_cast<int>(sizeof(binary)));
  if(encoded) {
    int length = 0;
    curl_free(curl_easy_unescape(nullptr, encoded, 0, &length));
    curl_free(curl_unescape(encoded, 0));
  }
  curl_free(encoded);
  curl_free(curl_unescape("%00%FF%41", 9));

  // These rejected length values are ordinary API-contract checks from
  // curl/tests/libtest/lib1605.c; no memory or operating-system faults occur.
  curl_free(curl_easy_escape(nullptr, "", -1));
  int length = 0;
  curl_free(curl_easy_unescape(nullptr, "%41%41%41%41", -1, &length));
}

}  // namespace

void ExerciseUtilityApiCoverageWithInitializedCurl()
{
  // The returned version string has static storage and must not be freed.
  const char *volatile version = curl_version();
  (void)version;
  ExerciseDates();
  ExerciseEscaping();
}

void ExerciseUtilityApiCoverage()
{
  if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    return;

  ExerciseUtilityApiCoverageWithInitializedCurl();
  curl_global_cleanup();
}

}  // namespace full_coverage
