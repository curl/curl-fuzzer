/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief IPFS/IPNS gateway URL construction shared by the scenario runner and
///        its transcript-level tests.

#ifndef PROTO_FUZZER_IPFS_URL_H_
#define PROTO_FUZZER_IPFS_URL_H_

#include <string>

#include "curl_fuzzer.pb.h"

namespace proto_fuzzer {

std::string BuildIpfsGatewayUrl(curl::fuzzer::proto::Scheme scheme, const std::string& host_path);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_IPFS_URL_H_
