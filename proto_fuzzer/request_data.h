/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Owns pointer-valued HTTP headers, TELNET options, MIME state, and
///        upload callback state derived from a Scenario.

#ifndef PROTO_FUZZER_REQUEST_DATA_H_
#define PROTO_FUZZER_REQUEST_DATA_H_

#include <curl/curl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// Cursor and policy behind the request read/seek callbacks. Keeping it per
/// RunScenario invocation avoids the file-static state that made nested or
/// concurrent reproductions share an upload cursor, and gives retry paths a
/// real rewindable source rather than stdin.
class UploadScriptState {
 public:
  /// C-compatible hook invoked immediately before each read result is chosen.
  /// TELNET uses it to drain replies while curl's synchronous protocol loop
  /// prevents the outer mock driver from running.
  using BeforeReadCallback = void (*)(void*);

  explicit UploadScriptState(const curl::fuzzer::proto::Scenario& scenario);

  /// A temporary Scenario cannot satisfy the borrowed payload's lifetime.
  UploadScriptState(curl::fuzzer::proto::Scenario&& scenario) = delete;
  UploadScriptState(const curl::fuzzer::proto::Scenario&& scenario) = delete;

  std::size_t Read(char* buffer, std::size_t capacity);

  int Seek(curl_off_t requested_offset, int origin);

  std::size_t data_size() const;

  std::size_t read_step_count() const;

  std::size_t offset() const;

  bool scripted() const;

 private:
  friend class ScenarioRequestData;

  void SetBeforeReadCallback(BeforeReadCallback callback, void* userdata);

  static std::size_t ReadCallback(char* buffer, std::size_t size, std::size_t nitems, void* userdata);

  static int SeekCallback(void* userdata, curl_off_t offset, int origin);

  std::string_view data_;
  std::array<std::size_t, scenario_limits::kMaxUploadReadSteps> read_sizes_;
  std::size_t read_step_count_;
  std::size_t total_size_;
  std::size_t max_read_size_;
  std::size_t offset_;
  std::size_t next_read_size_;
  curl::fuzzer::proto::UploadTerminal terminal_;
  curl::fuzzer::proto::UploadSeekResult seek_result_;
  BeforeReadCallback before_read_callback_;
  void* before_read_userdata_;
  bool scripted_;
};

/// Counts the resources that survived allocation and runtime budgets. Tests
/// use these numbers to keep the anti-complexity limits from regressing while
/// the fuzzer itself deliberately ignores individual setup failures.
struct RequestBuildStats {
  /// Number of top-level CURLOPT_HTTPHEADER entries retained.
  std::size_t request_headers = 0;
  /// Number of fuzzed CURLOPT_RESOLVE entries retained before the fixed
  /// loopback mapping was appended.
  std::size_t resolve_entries = 0;
  /// Number of CURLOPT_TELNETOPTIONS entries retained.
  std::size_t telnet_options = 0;
  /// Number of top-level and nested curl_mimepart objects constructed.
  std::size_t mime_parts = 0;
  /// Number of per-part header entries transferred to curl MIME ownership.
  std::size_t mime_headers = 0;
  /// Materialized bytes supplied by compact generated MIME sources.
  std::size_t generated_mime_bytes = 0;
};

/// Builds HTTP headers or TELNET options, MIME state, and upload callbacks
/// whose storage or userdata libcurl retains by pointer. Keeping them in one
/// scope makes their lifetime visibly encompass the complete multi-handle
/// drive rather than relying on setopt copying data that its API explicitly
/// does not copy.
class ScenarioRequestData {
 public:
  ScenarioRequestData(CURL* easy, const curl::fuzzer::proto::Scenario& scenario, bool apply_resolve_entries = false);

  /// A temporary Scenario cannot outlive the upload view retained for curl.
  ScenarioRequestData(CURL* easy, curl::fuzzer::proto::Scenario&& scenario,
                      bool apply_resolve_entries = false) = delete;
  ScenarioRequestData(CURL* easy, const curl::fuzzer::proto::Scenario&& scenario,
                      bool apply_resolve_entries = false) = delete;

  ~ScenarioRequestData();

  ScenarioRequestData(const ScenarioRequestData&) = delete;
  ScenarioRequestData& operator=(const ScenarioRequestData&) = delete;

  const RequestBuildStats& stats() const;

  const UploadScriptState& upload_state() const;

  bool upload_callbacks_installed() const;

  bool resolve_entries_ready() const;

  void SetBeforeUploadReadCallback(UploadScriptState::BeforeReadCallback callback, void* userdata);

 private:
  CURL* easy_;
  CurlSlistPtr request_headers_;
  CurlSlistPtr resolve_entries_;
  CurlSlistPtr telnet_options_;
  CurlMimePtr mime_post_;
  UploadScriptState upload_state_;
  bool upload_callbacks_installed_;
  bool resolve_entries_ready_;
  RequestBuildStats stats_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_REQUEST_DATA_H_
