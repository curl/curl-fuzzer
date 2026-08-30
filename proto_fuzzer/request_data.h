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
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// Cursor and policy behind the request read/seek callbacks. Keeping it per
/// ScenarioRunner invocation avoids the file-static state that made nested or
/// concurrent reproductions share an upload cursor, and gives retry paths a
/// real rewindable source rather than stdin.
class UploadScriptState {
 public:
  /// C-compatible hook invoked immediately before each read result is chosen.
  /// TELNET uses it to drain replies while curl's synchronous protocol loop
  /// prevents the outer mock driver from running.
  using BeforeReadCallback = void (*)(void*);

  /// Borrow a capped scripted source. When Scenario.upload is absent,
  /// non-TELNET schemes retain the historical 16 KiB `U` stream while TELNET
  /// reports immediate EOF so merely selecting the protocol cannot inject
  /// unsolicited terminal input. Borrowing avoids duplicating every fuzzed
  /// body before curl can read it; `scenario` must therefore remain alive and
  /// unmodified until this state is destroyed.
  /// @param scenario Source and lifetime owner of callback bytes and outcomes.
  explicit UploadScriptState(const curl::fuzzer::proto::Scenario& scenario);

  /// A temporary Scenario cannot satisfy the borrowed payload's lifetime.
  UploadScriptState(curl::fuzzer::proto::Scenario&& scenario) = delete;

  /// Copy the next bounded chunk and advance the cursor. Public so focused
  /// tests can validate callback semantics without relying on HTTP timing.
  /// @param buffer Destination supplied by curl.
  /// @param capacity Writable bytes in `buffer`.
  /// @return Bytes copied, zero for EOF, CURL_READFUNC_ABORT, or the TELNET-
  ///         only CURL_READFUNC_PAUSE outcome.
  std::size_t Read(char* buffer, std::size_t capacity);

  /// Apply the configured seek outcome and, for OK, move the bounded cursor.
  /// Successful seeks restart the short-read sequence so retries replay the
  /// same callback fragmentation deterministically.
  /// @param requested_offset Offset interpreted relative to `origin`.
  /// @param origin One of SEEK_SET, SEEK_CUR, or SEEK_END.
  /// @return A CURL_SEEKFUNC_* result.
  int Seek(curl_off_t requested_offset, int origin);

  /// @return Number of bytes visible to the callback after caps.
  std::size_t data_size() const;

  /// @return Number of retained per-read limits after caps.
  std::size_t read_step_count() const;

  /// @return Current byte cursor, exposed for deterministic unit tests.
  std::size_t offset() const;

  /// @return Whether Scenario.upload was present instead of using fallback.
  bool scripted() const;

 private:
  friend class ScenarioRequestData;

  /// Install a protocol hook without exposing the mutable cursor or curl's
  /// retained callback userdata outside its owner.
  void SetBeforeReadCallback(BeforeReadCallback callback, void* userdata);

  /// libcurl trampoline that protects multiplication of its two buffer-size
  /// arguments before forwarding to Read().
  static std::size_t ReadCallback(char* buffer, std::size_t size, std::size_t nitems, void* userdata);

  /// libcurl trampoline for the userdata-first seek callback signature.
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
  /// Number of CURLOPT_TELNETOPTIONS entries retained.
  std::size_t telnet_options = 0;
  /// Number of top-level and nested curl_mimepart objects constructed.
  std::size_t mime_parts = 0;
  /// Number of per-part header entries transferred to curl MIME ownership.
  std::size_t mime_headers = 0;
};

/// Builds HTTP headers or TELNET options, MIME state, and upload callbacks
/// whose storage or userdata libcurl retains by pointer. Keeping them in one
/// scope makes their lifetime visibly encompass the complete multi-handle
/// drive rather than relying on setopt copying data that its API explicitly
/// does not copy.
class ScenarioRequestData {
 public:
  /// Construct and apply the pointer-valued fields in `scenario` to `easy`.
  /// `easy` must remain alive until this object is destroyed, because cleanup
  /// first detaches the pointers from the handle and only then frees them.
  /// @param easy Easy handle that will perform this scenario.
  /// @param scenario Source headers/TELNET options, optional MIME body, and
  ///                 upload script.
  ScenarioRequestData(CURL* easy, const curl::fuzzer::proto::Scenario& scenario);

  /// A temporary Scenario cannot outlive the upload view retained for curl.
  ScenarioRequestData(CURL* easy, curl::fuzzer::proto::Scenario&& scenario) = delete;

  /// Detach pointer options/callbacks and release request allocations.
  ~ScenarioRequestData();

  ScenarioRequestData(const ScenarioRequestData&) = delete;
  ScenarioRequestData& operator=(const ScenarioRequestData&) = delete;

  /// Return resource counts after caps and allocation failures were applied.
  /// @return Immutable construction statistics.
  const RequestBuildStats& stats() const;

  /// Return the callback state retained for the complete drive. This is mainly
  /// useful to ownership tests; the runner itself lets libcurl mutate it.
  /// @return Immutable upload state.
  const UploadScriptState& upload_state() const;

  /// Return whether this scenario needed raw upload callbacks. Exposing the
  /// decision lets ownership tests ensure ordinary requests avoid redundant
  /// setopt/teardown work without exposing either userdata pointer.
  /// @return True when read and seek callbacks were attached to the handle.
  bool upload_callbacks_installed() const;

  /// Arrange protocol-specific work immediately before every upload read.
  /// This is intentionally a narrow callback seam rather than exposing curl's
  /// retained READFUNCTION userdata or the mutable upload cursor.
  /// @param callback Function to invoke, or nullptr to clear the hook.
  /// @param userdata Borrowed pointer passed to `callback`.
  void SetBeforeUploadReadCallback(UploadScriptState::BeforeReadCallback callback, void* userdata);

 private:
  CURL* easy_;
  curl_slist* request_headers_;
  curl_slist* telnet_options_;
  curl_mime* mime_post_;
  UploadScriptState upload_state_;
  bool upload_callbacks_installed_;
  RequestBuildStats stats_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_REQUEST_DATA_H_
