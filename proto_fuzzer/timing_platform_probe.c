/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/* Exercise portable time helpers through the existing timing lane. */

#include <curl/curl.h>
#include <stdbool.h>
#include <stdlib.h>

#include "curl_setup.h"
#include "curlx/strparse.h"
#include "curlx/timediff.h"
#include "curlx/timeval.h"
#include "curlx/wait.h"
#include "curlx/warnless.h"

void curl_fuzzer_probe_timing_platform(void) {
  struct Curl_str text;
  struct curltime newer;
  struct curltime older;
  struct timeval value;

  /* One real millisecond wait per process reaches curlx_mstotv on POSIX. */
  if (curlx_wait_ms(1) != 0 || curlx_wait_ms(-1) != -1) abort();

  /* Only the optional c-ares backend calls this conversion in libcurl. */
  value.tv_sec = 1;
  value.tv_usec = 234000;
  if (curlx_tvtoms(&value) != 1234) abort();

  /* These conversion helpers are public inside curl but have no active
   * caller in this Linux configuration. Keep their debug preconditions true
   * and verify a small value survives each conversion. */
  if (curlx_ultouc(7) != 7 || curlx_uztoul(7) != 7 || curlx_sltoui(7) != 7 || curlx_uztosz(7) != 7 ||
      curlx_sztosi(7) != 7 || curlx_uitous(7) != 7 || curlx_sitouz(7) != 7) {
    abort();
  }

  older.tv_sec = 1;
  older.tv_usec = 900;
  newer.tv_sec = 2;
  newer.tv_usec = 100;
  if (curlx_timediff_ceil_ms(newer, older) != 1000 || curlx_timediff_us(newer, older) != 999200) {
    abort();
  }

  curlx_str_assign(&text, "abc", 3);
  curlx_str_trim(&text, 1);
  if (text.len != 2) abort();
}
