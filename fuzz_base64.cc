/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017, Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

extern "C"
{
  #include <stdlib.h>
  #include <signal.h>
  #include <string.h>
  #include <unistd.h>
  #include <inttypes.h>
  #include <curl/curl.h>
  #include <lib/curl_base64.h>
  #include <lib/curl_printf.h>
  #include <lib/curl_memory.h>
  #include <lib/memdebug.h>
  #include <assert.h>
}

#include <string>

/* #define DEBUG(STMT)  STMT */
#define DEBUG(STMT)


void curl_dbg_free(void *ptr)
{
  if(ptr) {
    void *mem = (void *)((char *)ptr - 8);

    /* free for real */
    (Curl_cfree)(mem);
  }
}


/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL fnmatch function.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  std::string s(reinterpret_cast<const char*>(data), size);
  CURLcode fnrc;
  unsigned char *outptr = NULL, *outptr2 = NULL;
  char *recodeptr = NULL;
  size_t inlen = strlen(s.c_str()), outlen, outlen2, recodelen;

  fnrc = Curl_base64_decode(s.c_str(), &outptr, &outlen);

  (void)fnrc;
  DEBUG(printf("Curl_base64_decode returned %d with %s\n", fnrc, s.c_str()));

  if (fnrc != CURLE_OK)
    goto EXIT_LABEL;

  fnrc = Curl_base64_encode((const char *)outptr, outlen, &recodeptr, &recodelen);

  if (fnrc != CURLE_OK)
    goto EXIT_LABEL;

  (void)fnrc;
  DEBUG(printf("Curl_base64_encode returned %d with %s\n", fnrc, s.c_str()));

  fnrc = Curl_base64_decode(recodeptr, &outptr2, &outlen2);

  DEBUG(printf("Sizes og:%lu decode:%lu recode:%lu decode2:%lu, Strings '%s' '%s'\n", inlen, outlen, recodelen, outlen2, s.c_str(), recodeptr));

  assert(fnrc == CURLE_OK);
  assert(outlen == outlen2);
  assert(!memcmp(outptr, outptr2, outlen));

EXIT_LABEL:

  curl_dbg_free(outptr);
  curl_dbg_free(outptr2);
  curl_dbg_free(recodeptr);

  return 0;
}
