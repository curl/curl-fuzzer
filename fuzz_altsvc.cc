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
  #define HAVE_STRUCT_TIMEVAL // HACK to let it compile
  #include <stdlib.h>
  #include <signal.h>
  #include <string.h>
  #include <unistd.h>
  #include <inttypes.h>
  #include <curl/curl.h>
  #include <assert.h>

  enum alpnid {
    ALPN_none = 0,
    ALPN_h1 = CURLALTSVC_H1,
    ALPN_h2 = CURLALTSVC_H2,
    ALPN_h3 = CURLALTSVC_H3
  };

  struct altsvcinfo *Curl_altsvc_init(void);
  CURLcode Curl_altsvc_parse(struct Curl_easy *data,
                            struct altsvcinfo *altsvc, const char *value,
                            enum alpnid srcalpn, const char *srchost,
                            unsigned short srcport);
  void Curl_altsvc_cleanup(struct altsvcinfo **altsvc);

}

#include <string>

/* #define DEBUG(STMT)  STMT */
#define DEBUG(STMT)


/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL fnmatch function.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  std::string s(reinterpret_cast<const char*>(data), size);

  struct Curl_easy *curl;
  CURLcode fnrc;
  struct altsvcinfo *asi;

  asi = Curl_altsvc_init();
  curl_global_init(CURL_GLOBAL_ALL);
  curl = (Curl_easy*)curl_easy_init();

  fnrc = Curl_altsvc_parse(curl, asi, s.c_str(), ALPN_h1, "example.com", 1234);
  (void)fnrc;

  DEBUG(printf("Curl_altsvc_parse returned %d with %s\n", fnrc, s.c_str()));
  assert(fnrc == CURLE_OK);

  curl_easy_cleanup(curl);
  Curl_altsvc_cleanup(&asi);
  curl_global_cleanup();

  return 0;
}
