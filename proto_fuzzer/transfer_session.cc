/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Ordered easy-handle and retained-option resource ownership.

#include "proto_fuzzer/transfer_session.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>

#include "proto_fuzzer/api_lifecycle.h"
#include "proto_fuzzer/bounded_anonymous_input_file.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {
namespace {

constexpr char kDevNullPath[] = "/dev/null";
constexpr char kAltSvcOrigin[] = "altsvc-origin.test";
constexpr char kAltSvcLoopbackResolve[] = "*:80:127.0.1.127";

/// Fail closed before any resolver backend starts ambient DNS work.
int AbortUnexpectedAltSvcResolve(void*, void*, void*) { return 1; }

bool HasCanonicalAltSvcAuthority(const std::string& host_path) {
  const std::size_t host_size = sizeof(kAltSvcOrigin) - 1;
  return host_path.compare(0, host_size, kAltSvcOrigin) == 0 &&
         (host_path.size() == host_size || host_path[host_size] == '/' || host_path[host_size] == '?' ||
          host_path[host_size] == '#');
}

/// Repeat fixed-target bounds for direct runtime and compatibility callers.
void PrepareInputFile(const std::string& contents, std::size_t* remaining_bytes, BoundedAnonymousInputFile* input_file,
                      bool guard_netrc = false) {
  const std::size_t size = std::min(contents.size(), std::min(scenario_limits::kMaxFileInputBytes, *remaining_bytes));
  if (size == 0) {
    return;
  }
  if (guard_netrc) {
    // Retain a parser-neutral newline when curl's loader drops comment lines.
    // Charge only protobuf bytes to the shared budget, as before.
    std::string guarded_contents(1, '\n');
    guarded_contents.append(contents.data(), size);
    if (input_file->Write(reinterpret_cast<const std::uint8_t*>(guarded_contents.data()), guarded_contents.size())) {
      *remaining_bytes -= size;
    }
  } else if (input_file->Write(reinterpret_cast<const std::uint8_t*>(contents.data()), size)) {
    *remaining_bytes -= size;
  }
}

}  // namespace

/// Files are allocated only for parser-input lanes and survive easy cleanup.
struct TransferSession::ParserInputs {
  BoundedAnonymousInputFile cookie{scenario_limits::kMaxFileInputBytes};
  BoundedAnonymousInputFile altsvc{scenario_limits::kMaxFileInputBytes};
  BoundedAnonymousInputFile hsts{scenario_limits::kMaxFileInputBytes};
  BoundedAnonymousInputFile netrc{scenario_limits::kMaxFileInputBytes + 1};
  BoundedAnonymousInputFile crl{scenario_limits::kMaxFileInputBytes};
};

TransferSession::TransferSession() = default;
TransferSession::~TransferSession() { Close(); }

/// Allocate the easy lazily so unused concurrent-transfer slots stay empty.
/// @return Whether the session has a usable easy handle.
bool TransferSession::Initialize() {
  if (!easy_) {
    easy_.reset(curl_easy_init());
  }
  return easy_ != nullptr;
}

/// Borrow the owned easy; callers must not clean it themselves.
/// @return Easy handle, or nullptr before successful initialization.
CURL* TransferSession::easy() const { return easy_.get(); }

/// Apply baseline options and retain their CONNECT_TO storage.
/// @param scheme Protocol serviced by the installed peer.
/// @param trace_ids Whether to enable bounded trace-ID diagnostics.
void TransferSession::ApplyBaseline(curl::fuzzer::proto::Scheme scheme, bool trace_ids) {
  if (easy_) {
    // Apply the new pointer before releasing the previous list.
    connect_to_.reset(ApplyBaselineOptions(easy_.get(), scheme, trace_ids));
  }
}

/// Reset pre-transfer configuration while preserving prepared parser files.
/// @return False if request or API callback state has already been installed.
bool TransferSession::ResetConfiguration() {
  if (!easy_ || request_data_ || api_lifecycle_) {
    return false;
  }
  curl_easy_reset(easy_.get());
  connect_to_.reset();
  altsvc_resolve_.reset();
  return true;
}

/// Copy bounded parser inputs into lazily allocated anonymous files.
/// @param scenario Source of parser-file bytes; not retained.
/// @param mode Select deep HTTP or TLS parser inputs.
/// @return False after easy initialization, when paths may be retained.
bool TransferSession::PrepareInputFiles(const curl::fuzzer::proto::Scenario& scenario, ScenarioRunMode mode) {
  if (easy_) {
    return false;
  }
  if (mode != ScenarioRunMode::kDeepHttpCoverage && mode != ScenarioRunMode::kTlsCoverage) {
    return true;
  }
  parser_inputs_ = std::make_unique<ParserInputs>();
  std::size_t remaining_bytes = scenario_limits::kMaxFileInputTotalBytes;
  if (mode == ScenarioRunMode::kDeepHttpCoverage) {
    PrepareInputFile(scenario.cookie_file(), &remaining_bytes, &parser_inputs_->cookie);
    PrepareInputFile(scenario.altsvc_file(), &remaining_bytes, &parser_inputs_->altsvc);
    PrepareInputFile(scenario.hsts_file(), &remaining_bytes, &parser_inputs_->hsts);
    PrepareInputFile(scenario.netrc_file(), &remaining_bytes, &parser_inputs_->netrc, true);
  } else {
    PrepareInputFile(scenario.crl_file(), &remaining_bytes, &parser_inputs_->crl);
  }
  return true;
}

/// Apply prepared parser paths after baseline and peer installation.
void TransferSession::ApplyInputFiles() {
  if (!easy_ || !parser_inputs_) {
    return;
  }
  if (const char* path = parser_inputs_->cookie.path()) {
    (void)curl_easy_setopt(easy_.get(), CURLOPT_COOKIEFILE, path);
  }
  // Alt-Svc/HSTS use one option for input and cleanup output. Load first,
  // then restore the fixed sink; both loaders retain earlier file entries.
  if (const char* path = parser_inputs_->altsvc.path()) {
    (void)curl_easy_setopt(easy_.get(), CURLOPT_ALTSVC, path);
    (void)curl_easy_setopt(easy_.get(), CURLOPT_ALTSVC, kDevNullPath);
  }
  if (const char* path = parser_inputs_->hsts.path()) {
    (void)curl_easy_setopt(easy_.get(), CURLOPT_HSTS, path);
    (void)curl_easy_setopt(easy_.get(), CURLOPT_HSTS, kDevNullPath);
  }
  if (const char* path = parser_inputs_->netrc.path()) {
    (void)curl_easy_setopt(easy_.get(), CURLOPT_NETRC_FILE, path);
    (void)curl_easy_setopt(easy_.get(), CURLOPT_NETRC, CURL_NETRC_REQUIRED);
  }
  if (const char* path = parser_inputs_->crl.path()) {
    (void)curl_easy_setopt(easy_.get(), CURLOPT_CRLFILE, path);
  }
}

/// Enable isolated Alt-Svc routing for the canonical deep-HTTP authority.
/// @param host_path Scenario URL authority/path used by this transfer.
void TransferSession::ConfigureAltSvcRouting(const std::string& host_path) {
  if (!easy_ || !parser_inputs_ || parser_inputs_->altsvc.path() == nullptr ||
      !HasCanonicalAltSvcAuthority(host_path)) {
    return;
  }
  CurlSlistPtr resolve(curl_slist_append(nullptr, kAltSvcLoopbackResolve));
  if (!resolve || curl_easy_setopt(easy_.get(), CURLOPT_RESOLVE, resolve.get()) != CURLE_OK) {
    return;
  }
  // Adopt only after installation; failures leave the previous list alive.
  altsvc_resolve_ = std::move(resolve);
  if (curl_easy_setopt(easy_.get(), CURLOPT_RESOLVER_START_FUNCTION, &AbortUnexpectedAltSvcResolve) == CURLE_OK) {
    // CONNECT_TO takes precedence over Alt-Svc. Only detach it when the
    // wildcard host cache and fail-closed resolver callback are installed.
    (void)curl_easy_setopt(easy_.get(), CURLOPT_CONNECT_TO, nullptr);
  }
}

/// Install owned request attachments. The Scenario remains borrowed.
/// @param scenario Live, unmodified source until session teardown.
/// @param apply_resolve_entries Install resolver-lane mappings.
/// @return Request owner, or nullptr without an easy or if already installed.
ScenarioRequestData* TransferSession::InstallRequestData(const curl::fuzzer::proto::Scenario& scenario,
                                                         bool apply_resolve_entries) {
  if (!easy_ || request_data_) {
    return nullptr;
  }
  request_data_.emplace(easy_.get(), scenario, apply_resolve_entries);
  return &*request_data_;
}

/// Install API/share state that survives easy cleanup.
/// @param plan Live plan until session teardown.
/// @param url URL used only during lifecycle construction.
/// @return Lifecycle owner, or nullptr if absent/already installed.
ApiLifecycle* TransferSession::InstallApiLifecycle(const curl::fuzzer::proto::ApiPlan& plan, std::string_view url) {
  if (!easy_ || api_lifecycle_) {
    return nullptr;
  }
  api_lifecycle_ = std::make_unique<ApiLifecycle>(easy_.get(), plan, url);
  return api_lifecycle_.get();
}

/// Release all resources in their required order. Safe to call repeatedly.
void TransferSession::Close() {
  request_data_.reset();
  easy_.reset();
  api_lifecycle_.reset();
  altsvc_resolve_.reset();
  connect_to_.reset();
  parser_inputs_.reset();
}

}  // namespace proto_fuzzer
