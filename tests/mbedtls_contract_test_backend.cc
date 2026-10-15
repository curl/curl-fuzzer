/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <mbedtls/ssl.h>

int mbedtls_test_handshake_result = 0;
int mbedtls_test_read_result = MBEDTLS_ERR_SSL_WANT_READ;
int mbedtls_test_write_result = 1;
int mbedtls_test_close_result = 0;
int mbedtls_test_reset_result = 0;

extern "C" void mbedtls_ssl_init(mbedtls_ssl_context *) {}
extern "C" void mbedtls_ssl_free(mbedtls_ssl_context *) {}

extern "C" int mbedtls_ssl_session_reset(mbedtls_ssl_context *) {
  return mbedtls_test_reset_result;
}

extern "C" int mbedtls_ssl_handshake(mbedtls_ssl_context *) {
  return mbedtls_test_handshake_result;
}

extern "C" int mbedtls_ssl_read(mbedtls_ssl_context *, unsigned char *,
                                size_t) {
  return mbedtls_test_read_result;
}

extern "C" int mbedtls_ssl_write(mbedtls_ssl_context *, const unsigned char *,
                                 size_t) {
  return mbedtls_test_write_result;
}

extern "C" int mbedtls_ssl_close_notify(mbedtls_ssl_context *) {
  return mbedtls_test_close_result;
}
