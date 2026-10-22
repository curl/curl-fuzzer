/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Translates Scenario SetOption messages into curl_easy_setopt calls,
///        plus the fixed baseline setopts the harness always applies.

#ifndef PROTO_FUZZER_OPTION_APPLY_H_
#define PROTO_FUZZER_OPTION_APPLY_H_

#include <curl/curl.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/option_model.h"

namespace proto_fuzzer {

/// Reset curl's global trace configuration to a known off baseline for the
/// lifetime of one input.
///
/// curl_global_trace() only mutates the components it names and exposes no
/// read-back, so a true save/restore is not possible through the public API.
/// Instead the guard resets "-all" on both entry and exit: the input's trace
/// selection is contained to the guard's scope, and a previous input's "all"
/// (or any subset it left enabled) cannot leak into the next input. This makes
/// coverage and any trace-dependent failure independent of corpus order.
class ScopedTraceReset final {
 public:
  ScopedTraceReset() { (void)curl_global_trace("-all"); }
  ~ScopedTraceReset() { (void)curl_global_trace("-all"); }

  ScopedTraceReset(const ScopedTraceReset&) = delete;
  ScopedTraceReset& operator=(const ScopedTraceReset&) = delete;
  ScopedTraceReset(ScopedTraceReset&&) = delete;
  ScopedTraceReset& operator=(ScopedTraceReset&&) = delete;
};

struct curl_slist* ApplyBaselineOptions(CURL* easy, curl::fuzzer::proto::Scheme scheme, bool trace_ids = false,
                                        const std::string& trace_config = {});

CURLcode ApplySetOption(CURL* easy, const curl::fuzzer::proto::SetOption& option);

std::size_t RuntimeOptionCount(const curl::fuzzer::proto::Scenario& scenario);

std::size_t ApplyScenarioOptions(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_OPTION_APPLY_H_
