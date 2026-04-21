/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief libFuzzer entrypoint for the libprotobuf-mutator HTTP fuzzer.
///        Wires DEFINE_BINARY_PROTO_FUZZER to ScenarioRunner::Run.

#include <curl/curl.h>
#include <libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/scenario_runner.h"

namespace {

// Wire curl_global_init once so repeated fuzz iterations don't pay for it on every call. libFuzzer reuses the process;
// static ctors run once.
struct CurlGlobalBootstrap {
  CurlGlobalBootstrap() { curl_global_init(CURL_GLOBAL_ALL); }
};
const CurlGlobalBootstrap kGlobalBootstrap;

}  // namespace

/// @brief libFuzzer entry point. libFuzzer will call this function with a valid Scenario protobuf message on each
/// fuzzing iteration. The function is expected to run the scenario and return. Any crashes or undefined behavior during
/// scenario execution will be reported by libFuzzer as fuzzing bugs.
/// @param scenario The Scenario describing the curl operations to perform.
DEFINE_BINARY_PROTO_FUZZER(const curl::fuzzer::proto::Scenario& scenario) {
  proto_fuzzer::ScenarioRunner().Run(scenario);
}
