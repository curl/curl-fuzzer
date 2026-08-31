/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef HEADER_CURL_FUZZER_LEGACY_PROTOCOL_ALLOWLIST_H
#define HEADER_CURL_FUZZER_LEGACY_PROTOCOL_ALLOWLIST_H

#include <string>

namespace legacy_protocol_allowlist {

/**
 * Builds the generic legacy fuzzer's protocol list from the protocols that
 * its linked libcurl actually supports.
 *
 * Keeping the safety policy separate from libcurl's build-time feature set is
 * important: an unsupported name makes CURLOPT_PROTOCOLS_STR reject the whole
 * list, while automatically accepting every advertised protocol could enable
 * a newly added protocol before the harness is safe to drive it.
 */
std::string Build(const char *const *supported_protocols);

/**
 * Returns the process-wide protocol list for the linked libcurl.
 *
 * Fuzz inputs cannot change libcurl's compiled protocol set, so rebuilding the
 * same string for every mutation would add cost without adding coverage.
 */
const std::string &ForCurrentCurl();

}  // namespace legacy_protocol_allowlist

#endif  // HEADER_CURL_FUZZER_LEGACY_PROTOCOL_ALLOWLIST_H
