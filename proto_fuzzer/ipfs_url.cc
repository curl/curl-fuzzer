/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of IPFS/IPNS gateway URL construction.

#include "proto_fuzzer/ipfs_url.h"

#include <string_view>

namespace proto_fuzzer {

namespace {

// libcurl has no ipfs:// handler: curl's command-line tool rewrites those
// schemes onto an HTTP gateway before configuring its easy handle. The runner
// mirrors that rewrite against a fixed loopback authority; CONNECT_TO and
// OPENSOCKET still confine the resulting HTTP GET to the in-process
// MockServer, so no gateway process, DNS lookup, or external port is involved.
constexpr char kIpfsGatewayBaseUrl[] = "http://127.0.1.127:8080";

/// Collapse "." and ".." path segments per RFC 3986 section 5.2.4 without
/// decoding percent-encoded bytes (an encoded "%2e" must not become a real
/// separator). The result is rooted at the input's own root, so ".." can never
/// climb above it — matching how curl's tool_ipfs.c normalizes the user path
/// before prepending `/ipfs/<cid>`.
std::string RemoveDotSegments(std::string_view path) {
  std::string input(path);
  std::string output;
  while (!input.empty()) {
    if (input.rfind("../", 0) == 0) {
      input.erase(0, 3);
    } else if (input.rfind("./", 0) == 0) {
      input.erase(0, 2);
    } else if (input.rfind("/./", 0) == 0) {
      input.replace(0, 3, "/");
    } else if (input == "/.") {
      input = "/";
    } else if (input.rfind("/../", 0) == 0) {
      input.replace(0, 4, "/");
      const std::size_t slash = output.rfind('/');
      output.erase(slash == std::string::npos ? 0 : slash);
    } else if (input == "/..") {
      input = "/";
      const std::size_t slash = output.rfind('/');
      output.erase(slash == std::string::npos ? 0 : slash);
    } else if (input == "." || input == "..") {
      input.clear();
    } else {
      const std::size_t segment_start = (input[0] == '/') ? 1 : 0;
      const std::size_t segment_end = input.find('/', segment_start);
      if (segment_end == std::string::npos) {
        output += input;
        input.clear();
      } else {
        output += input.substr(0, segment_end);
        input.erase(0, segment_end);
      }
    }
  }
  return output;
}

/// Split a pinned CID/name from its mutable suffix, collapse dot segments in
/// the suffix's path portion (leaving any query and fragment intact), and
/// rejoin. This reproduces tool_ipfs.c, which normalizes the user path before
/// prepending `/ipfs/<cid>` so a suffix ending in "/../.." cannot erase the
/// gateway namespace.
std::string NormalizeIpfsHostPath(std::string_view host_path) {
  const std::size_t suffix_start = host_path.find_first_of("/?#");
  if (suffix_start == std::string_view::npos) {
    return std::string(host_path);
  }
  const std::string_view identifier = host_path.substr(0, suffix_start);
  const std::string_view suffix = host_path.substr(suffix_start);
  const std::size_t path_end = suffix.find_first_of("?#");
  const std::string_view path = (path_end == std::string_view::npos) ? suffix : suffix.substr(0, path_end);
  const std::string_view query_fragment =
      (path_end == std::string_view::npos) ? std::string_view() : suffix.substr(path_end);
  std::string result(identifier);
  result += RemoveDotSegments(path);
  result += query_fragment;
  return result;
}

}  // namespace

/// Build the IPFS/IPNS gateway URL for the given scheme and pinned host_path.
/// The mutable suffix's dot segments are normalized before the `/ipfs/<cid>` or
/// `/ipns/<name>` namespace is prepended, matching curl's tool_ipfs.c ordering
/// so a suffix ending in "/../.." cannot erase the namespace.
/// @param scheme SCHEME_IPFS or SCHEME_IPNS.
/// @param host_path Canonical identifier (CID/name) followed by the mutable
///                  path, query, and fragment suffix.
/// @return The HTTP gateway URL curl will request.
std::string BuildIpfsGatewayUrl(curl::fuzzer::proto::Scheme scheme, const std::string& host_path) {
  const char* prefix = scheme == curl::fuzzer::proto::SCHEME_IPNS ? "ipns" : "ipfs";
  return std::string(kIpfsGatewayBaseUrl) + "/" + prefix + "/" + NormalizeIpfsHostPath(host_path);
}

}  // namespace proto_fuzzer
