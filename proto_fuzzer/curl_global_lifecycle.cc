/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/curl_global_lifecycle.h"

#include <curl/curl.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>

#include "proto_fuzzer/allocation_fault_injection.h"

namespace proto_fuzzer {
namespace {

CurlGlobalLifecycle* registered_lifecycles = nullptr;

}  // namespace

/// Initialize curl and its allocation hooks for this process.
/// @param cleanup Optional cleanup callback used by focused lifecycle tests.
CurlGlobalLifecycle::CurlGlobalLifecycle(CleanupFunction cleanup) noexcept
    : cleanup_(cleanup != nullptr ? cleanup : &curl_global_cleanup) {
  // Curl_tls_keylog_open() runs once during global initialization. Keep the
  // default output bounded while allowing a reproducer to select another path.
  (void)setenv("SSLKEYLOGFILE", "/dev/null", 0);

  // Mock-peer teardown can race a write. Surface that as a socket error rather
  // than allowing SIGPIPE to terminate the process.
  std::signal(SIGPIPE, SIG_IGN);

  const bool callbacks_active = allocation_fault_injection::InitializeCurl();
  if (allocation_fault_injection::ClaimCurlInitializationReference()) {
    ++initialization_count_;
  }
  if (!callbacks_active) {
    std::fputs("warning: libcurl allocation fault injection is unavailable\n", stderr);
  }
  if (initialization_count_ == 0 && curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK) {
    ++initialization_count_;
  }
  initialized_ = initialization_count_ != 0;
  next_registered_ = registered_lifecycles;
  registered_lifecycles = this;
}

CurlGlobalLifecycle::~CurlGlobalLifecycle() {
  FinalizeForProcessExit();
  CurlGlobalLifecycle** link = &registered_lifecycles;
  while (*link != nullptr && *link != this) {
    link = &(*link)->next_registered_;
  }
  if (*link == this) {
    *link = next_registered_;
  }
  next_registered_ = nullptr;
}

/// Release this object's references after the fuzz engine has stopped.
void CurlGlobalLifecycle::FinalizeForProcessExit() noexcept {
  if (!initialized_) {
    return;
  }
  allocation_fault_injection::Reset();
  while (initialization_count_ != 0) {
    cleanup_();
    --initialization_count_;
  }
  initialized_ = false;
}

/// Finalize all registered process lifecycles before static destruction.
void FinalizeRegisteredCurlGlobalLifecyclesForExit() noexcept {
  for (CurlGlobalLifecycle* lifecycle = registered_lifecycles; lifecycle != nullptr;
       lifecycle = lifecycle->next_registered_) {
    lifecycle->FinalizeForProcessExit();
  }
}

}  // namespace proto_fuzzer
