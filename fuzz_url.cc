/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <curl/curl.h>

namespace {

// Keep controls at the end so existing URL-shaped corpus entries retain a
// useful prefix as their state-machine value. The complete input still goes
// through the historical raw URL parse before these bytes are interpreted.
enum ControlIndex {
  kPartControl,
  kActionControl,
  kSetFlagsControl,
  kGetFlagsControl,
  kUrlFlagsControl,
  kControlCount,
};

// Bound repeated encoding and duplication work independently of the raw URL
// parse, which intentionally preserves the target's original input semantics.
constexpr size_t kMaxComponentBytes = 4 * 1024;
constexpr char kBaseUrl[] =
    "imap://user:password;type=i@[fe80::1%25eth0]:143/a/b?base=1#old";

constexpr CURLUPart kUrlParts[] = {
    CURLUPART_URL,  CURLUPART_SCHEME, CURLUPART_USER,  CURLUPART_PASSWORD,
    CURLUPART_OPTIONS, CURLUPART_HOST, CURLUPART_PORT,  CURLUPART_PATH,
    CURLUPART_QUERY, CURLUPART_FRAGMENT, CURLUPART_ZONEID,
};

unsigned int SelectFlags(const unsigned int *flags, size_t count,
                         uint8_t selector)
{
  return flags[selector % count];
}

unsigned int SetFlags(CURLUPart part, uint8_t selector)
{
  switch(part) {
  case CURLUPART_URL: {
    constexpr unsigned int flags[] = {
        0,
        CURLU_GUESS_SCHEME,
        CURLU_DEFAULT_SCHEME,
        CURLU_NON_SUPPORT_SCHEME,
        CURLU_PATH_AS_IS,
        CURLU_DISALLOW_USER,
        CURLU_NO_AUTHORITY,
        CURLU_ALLOW_SPACE,
        CURLU_URLENCODE,
        CURLU_NON_SUPPORT_SCHEME | CURLU_NO_AUTHORITY | CURLU_ALLOW_SPACE |
            CURLU_URLENCODE,
    };
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  case CURLUPART_SCHEME: {
    constexpr unsigned int flags[] = {0, CURLU_NON_SUPPORT_SCHEME};
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  case CURLUPART_HOST: {
    constexpr unsigned int flags[] = {
        0, CURLU_URLENCODE, CURLU_NO_AUTHORITY,
        CURLU_URLENCODE | CURLU_NO_AUTHORITY,
    };
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  case CURLUPART_QUERY: {
    constexpr unsigned int flags[] = {
        0, CURLU_URLENCODE, CURLU_APPENDQUERY,
        CURLU_APPENDQUERY | CURLU_URLENCODE,
    };
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  case CURLUPART_PORT:
    return 0;
  default: {
    constexpr unsigned int flags[] = {0, CURLU_URLENCODE};
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  }
}

unsigned int GetFlags(CURLUPart part, uint8_t selector)
{
  switch(part) {
  case CURLUPART_URL: {
    constexpr unsigned int flags[] = {
        0,
        CURLU_DEFAULT_PORT,
        CURLU_NO_DEFAULT_PORT,
        CURLU_DEFAULT_SCHEME,
        CURLU_URLENCODE,
#if LIBCURL_VERSION_NUM >= 0x075800
        CURLU_PUNYCODE,
#endif
#if LIBCURL_VERSION_NUM >= 0x080300
        CURLU_PUNY2IDN,
#endif
#if LIBCURL_VERSION_NUM >= 0x080800
        CURLU_GET_EMPTY,
#endif
#if LIBCURL_VERSION_NUM >= 0x080900
        CURLU_NO_GUESS_SCHEME,
#endif
    };
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  case CURLUPART_SCHEME: {
    constexpr unsigned int flags[] = {
        0,
#if LIBCURL_VERSION_NUM >= 0x080900
        CURLU_NO_GUESS_SCHEME,
#endif
    };
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  case CURLUPART_HOST: {
    constexpr unsigned int flags[] = {
        0,
        CURLU_URLDECODE,
        CURLU_URLENCODE,
#if LIBCURL_VERSION_NUM >= 0x075800
        CURLU_PUNYCODE,
#endif
#if LIBCURL_VERSION_NUM >= 0x080300
        CURLU_PUNY2IDN,
#endif
    };
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  case CURLUPART_PORT: {
    constexpr unsigned int flags[] = {
        0, CURLU_DEFAULT_PORT, CURLU_NO_DEFAULT_PORT,
    };
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  case CURLUPART_QUERY:
  case CURLUPART_FRAGMENT: {
    constexpr unsigned int flags[] = {
        0,
        CURLU_URLDECODE,
#if LIBCURL_VERSION_NUM >= 0x080800
        CURLU_GET_EMPTY,
        CURLU_URLDECODE | CURLU_GET_EMPTY,
#endif
    };
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  default: {
    constexpr unsigned int flags[] = {0, CURLU_URLDECODE, CURLU_URLENCODE};
    return SelectFlags(flags, sizeof(flags) / sizeof(flags[0]), selector);
  }
  }
}

void ConsumeUrlPart(CURLU *url, CURLUPart part, unsigned int flags)
{
  char *value = nullptr;
  if(curl_url_get(url, part, &value, flags) == CURLUE_OK)
    curl_free(value);
}

void ProbeInvalidContractsOnce(CURLU *url, const char *value)
{
  static const bool probed = [url, value] {
    constexpr CURLUPart unknown_part = static_cast<CURLUPart>(15);
    char *result = nullptr;

    (void)curl_url_get(nullptr, CURLUPART_URL, &result, 0);
    (void)curl_url_set(nullptr, CURLUPART_URL, value, 0);
    (void)curl_url_dup(nullptr);
    curl_url_cleanup(nullptr);
    (void)curl_url_get(url, CURLUPART_URL, nullptr, 0);
    ConsumeUrlPart(url, unknown_part, 0);
    (void)curl_url_set(url, unknown_part, value, 0);
    (void)curl_url_set(url, unknown_part, nullptr, 0);
    return true;
  }();
  (void)probed;
}

void ExerciseUrlState(const char *value, const uint8_t *controls)
{
  const CURLUPart part =
      kUrlParts[controls[kPartControl] %
                (sizeof(kUrlParts) / sizeof(kUrlParts[0]))];
  const uint8_t action = controls[kActionControl] % 3;
  const unsigned int set_flags = SetFlags(part, controls[kSetFlagsControl]);
  const unsigned int get_flags = GetFlags(part, controls[kGetFlagsControl]);

  CURLU *url = curl_url();
  if(!url)
    return;
  if(curl_url_set(url, CURLUPART_URL, kBaseUrl, 0) != CURLUE_OK) {
    curl_url_cleanup(url);
    return;
  }

  if(action == 0)
    (void)curl_url_set(url, part, value, set_flags);
  else if(action == 2)
    (void)curl_url_set(url, part, nullptr, 0);
  ConsumeUrlPart(url, part, get_flags);

  CURLU *duplicate = curl_url_dup(url);
  if(duplicate) {
    unsigned int query_flags = CURLU_APPENDQUERY;
    if(controls[kSetFlagsControl] & 1)
      query_flags |= CURLU_URLENCODE;
    (void)curl_url_set(duplicate, CURLUPART_QUERY, value, query_flags);
    ConsumeUrlPart(duplicate, CURLUPART_QUERY,
                   GetFlags(CURLUPART_QUERY, controls[kGetFlagsControl]));
    ConsumeUrlPart(duplicate, CURLUPART_URL,
                   GetFlags(CURLUPART_URL, controls[kGetFlagsControl]));

    (void)curl_url_set(duplicate, CURLUPART_URL, kBaseUrl, 0);
    (void)curl_url_set(duplicate, CURLUPART_URL, value,
                       SetFlags(CURLUPART_URL, controls[kUrlFlagsControl]));
    ConsumeUrlPart(duplicate, CURLUPART_URL,
                   GetFlags(CURLUPART_URL, controls[kGetFlagsControl]));
    curl_url_cleanup(duplicate);
  }

  ProbeInvalidContractsOnce(url, value);
  curl_url_cleanup(url);
}

} // namespace

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL URL API.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  CURLU *uh = curl_url();

  /* it works on a null-terminated string */
  if(size && size != SIZE_MAX) {
    char *newp = (char *)malloc(size + 1);
    if(newp) {
      memcpy(newp, data, size);
      /* make sure it is zero terminated */
      newp[size] = 0;
      curl_url_set(uh, CURLUPART_URL, newp, CURLU_GUESS_SCHEME);

      if(size >= kControlCount) {
        size_t value_size = size - kControlCount;
        if(value_size > kMaxComponentBytes)
          value_size = kMaxComponentBytes;
        newp[value_size] = 0;
        ExerciseUrlState(newp, data + size - kControlCount);
      }
      free(newp);
    }
  }
  curl_url_cleanup(uh);

  /* This function must always return 0. Non-zero codes are reserved. */
  return 0;
}
