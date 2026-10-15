/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <gnutls/gnutls.h>

#include <cstddef>
#include <cstdint>

int gnutls_test_handshake_result = GNUTLS_E_SUCCESS;
ssize_t gnutls_test_send_result = 1;
ssize_t gnutls_test_early_send_result = 1;
ssize_t gnutls_test_recv_result = GNUTLS_E_AGAIN;
int gnutls_test_bye_result = GNUTLS_E_SUCCESS;

namespace {
alignas(std::max_align_t) unsigned char session_storage;
} // namespace

extern "C" int gnutls_init(gnutls_session_t *session, unsigned int) {
  *session = reinterpret_cast<gnutls_session_t>(&session_storage);
  return GNUTLS_E_SUCCESS;
}

extern "C" void gnutls_deinit(gnutls_session_t) {}

extern "C" int gnutls_handshake(gnutls_session_t) {
  return gnutls_test_handshake_result;
}

extern "C" ssize_t gnutls_record_send(gnutls_session_t, const void *, size_t) {
  return gnutls_test_send_result;
}

extern "C" ssize_t gnutls_record_send_early_data(gnutls_session_t, const void *,
                                                 size_t) {
  return gnutls_test_early_send_result;
}

extern "C" ssize_t gnutls_record_recv(gnutls_session_t, void *, size_t) {
  return gnutls_test_recv_result;
}

extern "C" int gnutls_bye(gnutls_session_t, gnutls_close_request_t) {
  return gnutls_test_bye_result;
}

extern "C" int gnutls_error_is_fatal(int error) {
  return error == GNUTLS_E_FATAL_ALERT_RECEIVED ||
         error == GNUTLS_E_DECRYPTION_FAILED;
}
