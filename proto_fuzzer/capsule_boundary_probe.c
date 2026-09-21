/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/*
 * Production capsule traffic is capped far below the 1 GiB QUIC-varint
 * boundary. Check that scalar encoder boundary once in the HTTP/3 target;
 * ordinary inputs still exercise the rest of the implementation through the
 * CONNECT-UDP easy path.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

size_t capsule_encap_udp_hdr(uint8_t *hdr, size_t hdrlen, size_t payload_len);

void curl_fuzzer_probe_capsule_boundary(void) {
  uint8_t header[10];
  if (capsule_encap_udp_hdr(header, sizeof(header), 1073741823U) == 0) abort();
}
