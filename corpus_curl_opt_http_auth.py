#!/usr/bin/env python
# Allow using strings to represent CURLOPT_HTTPAUTH values when
# generating corpus files. The original defines live in curl.h.

from enum import Enum

class CurlOptHttpAuth(Enum):
    #define CURLAUTH_NONE         ((unsigned long)0)
    CURLAUTH_NONE = 0
    #define CURLAUTH_BASIC        (((unsigned long)1)<<0)
    CURLAUTH_BASIC = 1
    #define CURLAUTH_DIGEST       (((unsigned long)1)<<1)
    CURLAUTH_DIGEST = 2
    #define CURLAUTH_NEGOTIATE    (((unsigned long)1)<<2)
    CURLAUTH_NEGOTIATE = 4
    #define CURLAUTH_NTLM         (((unsigned long)1)<<3)
    CURLAUTH_NTLM = 8
    #define CURLAUTH_DIGEST_IE    (((unsigned long)1)<<4)
    CURLAUTH_DIGEST_IE = 16
    #define CURLAUTH_NTLM_WB      (((unsigned long)1)<<5)
    CURLAUTH_NTLM_WB = 32
    #define CURLAUTH_BEARER       (((unsigned long)1)<<6)
    CURLAUTH_BEARER = 64
    #define CURLAUTH_AWS_SIGV4    (((unsigned long)1)<<7)
    CURLAUTH_AWS_SIGV4 = 128
    #define CURLAUTH_ONLY         (((unsigned long)1)<<31)
    CURLAUTH_ONLY = 2147483648
    #define CURLAUTH_ANY          (~CURLAUTH_DIGEST_IE)
    CURLAUTH_ANY = 4294967279
    #define CURLAUTH_ANYSAFE      (~(CURLAUTH_BASIC|CURLAUTH_DIGEST_IE))
    CURLAUTH_ANYSAFE = 4294967278
