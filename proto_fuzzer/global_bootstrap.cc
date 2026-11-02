/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Process-retained curl global lifecycle for ordinary proto targets.

#include "proto_fuzzer/curl_global_lifecycle.h"

namespace {

// The MultiSSL target deliberately omits this object so it can select and
// initialize one backend independently for each input.
proto_fuzzer::CurlGlobalLifecycle kGlobalBootstrap;

}  // namespace
