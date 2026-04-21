/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Select()-based curl_multi perform loop for driving a single
///        transfer against a MockServer.

#ifndef PROTO_FUZZER_TRANSFER_H_
#define PROTO_FUZZER_TRANSFER_H_

#include <curl/curl.h>

namespace proto_fuzzer {

class MockServer;

CURLMcode DriveTransfer(CURL* easy, MockServer& mock);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TRANSFER_H_
