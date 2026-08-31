/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "legacy_protocol_allowlist.h"

#include <curl/curl.h>

#include <cstring>

namespace legacy_protocol_allowlist {
namespace {

/*
 * This is a harness safety policy, rather than a copy of libcurl's protocol
 * registry. In particular, TELNET remains exclusive to the proto fuzzer
 * because the legacy harness cannot prevent it from reading stdin. New curl
 * protocols must likewise be reviewed before being added here.
 */
const char *const kIntendedProtocols[] = {
    "dict",   "file",   "ftp",    "ftps",   "gopher", "gophers",
    "http",   "https",  "imap",   "imaps",  "mqtt",   "pop3",
    "pop3s",  "ldap",   "ldaps",  "rtmp",   "rtmpe",  "rtmps",
    "rtmpt",  "rtmpte", "rtmpts", "scp",    "sftp",   "rtsp",
    "smb",    "smbs",   "smtp",   "smtps",  "tftp",   "ws",
    "wss",    nullptr};

/**
 * Tests support against libcurl's authoritative runtime protocol list so a
 * dependency variant cannot poison the complete CURLOPT_PROTOCOLS_STR value.
 */
bool IsSupported(const char *candidate,
                 const char *const *supported_protocols) {
  if (!supported_protocols) {
    return false;
  }

  for (const char *const *protocol = supported_protocols; *protocol;
       ++protocol) {
    if (std::strcmp(candidate, *protocol) == 0) {
      return true;
    }
  }
  return false;
}

}  // namespace

std::string Build(const char *const *supported_protocols) {
  std::string allowed;
  for (const char *const *candidate = kIntendedProtocols; *candidate;
       ++candidate) {
    if (!IsSupported(*candidate, supported_protocols)) {
      continue;
    }
    if (!allowed.empty()) {
      allowed.push_back(',');
    }
    allowed.append(*candidate);
  }
  return allowed;
}

const std::string &ForCurrentCurl() {
  static const std::string allowed = []() {
    const curl_version_info_data *const info =
        curl_version_info(CURLVERSION_NOW);
    return Build(info ? info->protocols : nullptr);
  }();
  return allowed;
}

}  // namespace legacy_protocol_allowlist
