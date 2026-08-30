/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Builds bounded curl_slist and curl_mime state from a Scenario.

#include "proto_fuzzer/request_data.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>

#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

namespace {

/// Borrow the protobuf string when it already fits curl's NUL-terminated API,
/// allocating `truncated` only for compatibility inputs that bypass the fixed
/// target postprocessor. The callers below all synchronously copy this value,
/// so neither pointer escapes the call. Embedded NUL bytes deliberately remain:
/// curl observes the same prefix as before while an oversized invisible suffix
/// cannot dominate allocation.
const char* BoundedCString(const std::string& value, std::size_t limit, std::string* truncated) {
  if (value.size() <= limit) {
    return value.c_str();
  }
  truncated->assign(value.data(), limit);
  return truncated->c_str();
}

/// Raw read/seek callbacks are useful only when a script exists or a supported
/// SetOption can make curl request caller-provided body bytes. CURLOPT_POST is
/// included because POST without POSTFIELDS/MIME also falls back to the read
/// callback. Avoiding callbacks for ordinary requests removes eight setopt
/// calls across setup and teardown, while any potentially body-reading option
/// retains the non-blocking fallback regardless of its mutated value.
bool NeedsUploadCallbacks(const curl::fuzzer::proto::Scenario& scenario) {
  // curl's TELNET implementation polls stdin unless a READFUNCTION was
  // explicitly installed. Always provide the bounded per-scenario source,
  // even when there is no upload payload to send.
  if (scenario.scheme() == curl::fuzzer::proto::SCHEME_TELNET || scenario.has_upload()) {
    return true;
  }
  const std::size_t option_count = RuntimeOptionCount(scenario);
  for (std::size_t index = 0; index < option_count; ++index) {
    const auto& option = scenario.options(static_cast<int>(index));
    if (option.option_id() == curl::fuzzer::proto::CURLOPT_UPLOAD ||
        option.option_id() == curl::fuzzer::proto::CURLOPT_POST) {
      return true;
    }
  }
  return false;
}

/// Translate the mutation-friendly enum to curl's spelling. Restricting this
/// field to supported encoders spends cycles in encoder implementations rather
/// than repeatedly rediscovering the same invalid-string rejection.
const char* MimeEncoderName(curl::fuzzer::proto::MimeEncoder encoder) {
  switch (encoder) {
    case curl::fuzzer::proto::MIME_ENCODER_BINARY:
      return "binary";
    case curl::fuzzer::proto::MIME_ENCODER_8BIT:
      return "8bit";
    case curl::fuzzer::proto::MIME_ENCODER_7BIT:
      return "7bit";
    case curl::fuzzer::proto::MIME_ENCODER_BASE64:
      return "base64";
    case curl::fuzzer::proto::MIME_ENCODER_QUOTED_PRINTABLE:
      return "quoted-printable";
    case curl::fuzzer::proto::MIME_ENCODER_UNSPECIFIED:
    default:
      return nullptr;
  }
}

/// Append at most `limit` protobuf byte strings to a curl list. curl_slist_append
/// leaves the old head valid on allocation failure, so only replace the head
/// after a successful append and stop rather than burning the rest of the
/// iteration on allocations that are already failing.
template <typename RepeatedBytes>
curl_slist* BuildStringList(const RepeatedBytes& values, std::size_t count_limit, std::size_t value_limit,
                            std::size_t* applied) {
  curl_slist* list = nullptr;
  std::string truncated;
  const std::size_t count = std::min<std::size_t>(count_limit, values.size());
  for (std::size_t i = 0; i < count; ++i) {
    const std::string& value = values.Get(static_cast<int>(i));
    curl_slist* appended = curl_slist_append(list, BoundedCString(value, value_limit, &truncated));
    if (appended == nullptr) {
      break;
    }
    list = appended;
    ++*applied;
  }
  return list;
}

/// Apply the metadata shared by top-level and nested protobuf part types. The
/// MIME API copies these strings, so temporary bounded buffers are sufficient;
/// only the MIME root itself needs to outlive the perform loop.
template <typename ProtoPart>
void ApplyPartMetadata(curl_mimepart* part, const ProtoPart& source, RequestBuildStats* stats) {
  // Reuse the rare compatibility-path allocation across all three fields;
  // ordinary postprocessed metadata never writes this scratch string.
  std::string truncated;
  if (!source.name().empty()) {
    (void)curl_mime_name(part, BoundedCString(source.name(), scenario_limits::kMaxMetadataBytes, &truncated));
  }
  if (!source.filename().empty()) {
    (void)curl_mime_filename(part, BoundedCString(source.filename(), scenario_limits::kMaxMetadataBytes, &truncated));
  }
  if (!source.content_type().empty()) {
    (void)curl_mime_type(part, BoundedCString(source.content_type(), scenario_limits::kMaxMetadataBytes, &truncated));
  }
  if (const char* encoder = MimeEncoderName(source.encoder())) {
    (void)curl_mime_encoder(part, encoder);
  }

  std::size_t header_count = 0;
  curl_slist* headers = BuildStringList(source.headers(), scenario_limits::kMaxMimeHeadersPerPart,
                                        scenario_limits::kMaxMetadataBytes, &header_count);
  if (headers != nullptr) {
    // take_ownership=1 is crucial: unlike the strings above, MIME retains the
    // list pointer. Once attached, the root curl_mime_free call recursively
    // releases it, including lists on nested parts.
    const CURLcode result = curl_mime_headers(part, headers, 1);
    if (result == CURLE_OK) {
      stats->mime_headers += header_count;
    } else {
      curl_slist_free_all(headers);
    }
  }
}

/// Copy bounded binary data into a MIME part. curl_mime_data accepts an
/// explicit size, so embedded NUL bytes remain fuzzable here unlike in the
/// metadata and header APIs.
void ApplyPartData(curl_mimepart* part, const std::string& data) {
  const std::size_t size = std::min(data.size(), scenario_limits::kMaxMimeDataBytes);
  const char* bytes = data.empty() ? "" : data.data();
  (void)curl_mime_data(part, bytes, size);
}

/// Populate the fixed-depth child body and debit the shared total-part budget.
/// Returning an empty MIME object when the child list is empty is intentional:
/// curl's empty multipart serialization is useful coverage and remains cheap.
void PopulateSubparts(curl_mime* mime, const curl::fuzzer::proto::MimeSubparts& source, std::size_t* remaining_parts,
                      RequestBuildStats* stats) {
  const std::size_t count = std::min<std::size_t>(scenario_limits::kMaxNestedMimeParts, source.parts_size());
  for (std::size_t i = 0; i < count && *remaining_parts != 0; ++i) {
    curl_mimepart* part = curl_mime_addpart(mime);
    if (part == nullptr) {
      break;
    }
    --*remaining_parts;
    ++stats->mime_parts;
    const auto& proto_part = source.parts(static_cast<int>(i));
    ApplyPartMetadata(part, proto_part, stats);
    ApplyPartData(part, proto_part.data());
  }
}

/// Construct the top MIME tree. curl_mime_subparts transfers ownership only
/// on success, so failed attachments are freed immediately while successful
/// ones are left for the top-level root to release recursively.
curl_mime* BuildMimePost(CURL* easy, const curl::fuzzer::proto::MimePost& source, RequestBuildStats* stats) {
  curl_mime* mime = curl_mime_init(easy);
  if (mime == nullptr) {
    return nullptr;
  }

  std::size_t remaining_parts = scenario_limits::kMaxTotalMimeParts;
  const std::size_t count = std::min<std::size_t>(scenario_limits::kMaxTopLevelMimeParts, source.parts_size());
  for (std::size_t i = 0; i < count && remaining_parts != 0; ++i) {
    curl_mimepart* part = curl_mime_addpart(mime);
    if (part == nullptr) {
      break;
    }
    --remaining_parts;
    ++stats->mime_parts;
    const auto& proto_part = source.parts(static_cast<int>(i));
    ApplyPartMetadata(part, proto_part, stats);

    switch (proto_part.content_case()) {
      case curl::fuzzer::proto::MimePart::kData:
        ApplyPartData(part, proto_part.data());
        break;
      case curl::fuzzer::proto::MimePart::kSubparts: {
        curl_mime* subparts = curl_mime_init(easy);
        if (subparts == nullptr) {
          break;
        }
        PopulateSubparts(subparts, proto_part.subparts(), &remaining_parts, stats);
        if (curl_mime_subparts(part, subparts) != CURLE_OK) {
          curl_mime_free(subparts);
        }
        break;
      }
      case curl::fuzzer::proto::MimePart::CONTENT_NOT_SET:
      default:
        break;
    }
  }
  return mime;
}

}  // namespace

/// Borrow and cap the immutable upload shape once, before libcurl receives a
/// userdata pointer. ScenarioRunner keeps the protobuf alive for the complete
/// drive, so a view removes a per-input body copy without weakening callback
/// lifetime. For non-TELNET schemes, the absent-message fallback avoids a
/// 16 KiB allocation by synthesizing the same `U` bytes as the old callback.
/// TELNET deliberately starts at EOF so an absent script cannot become input.
UploadScriptState::UploadScriptState(const curl::fuzzer::proto::Scenario& scenario)
    : data_(),
      read_step_count_(0),
      total_size_(scenario.scheme() == curl::fuzzer::proto::SCHEME_TELNET ? 0 : scenario_limits::kMaxUploadBytes),
      max_read_size_(scenario.scheme() == curl::fuzzer::proto::SCHEME_TELNET ? scenario_limits::kMaxTelnetUploadReadSize
                                                                             : scenario_limits::kMaxUploadReadSize),
      offset_(0),
      next_read_size_(0),
      terminal_(curl::fuzzer::proto::UPLOAD_TERMINAL_EOF),
      seek_result_(curl::fuzzer::proto::UPLOAD_SEEK_CANTSEEK),
      before_read_callback_(nullptr),
      before_read_userdata_(nullptr),
      scripted_(scenario.has_upload()) {
  if (!scripted_) {
    return;
  }

  const auto& upload = scenario.upload();
  const std::size_t data_limit = scenario.scheme() == curl::fuzzer::proto::SCHEME_TELNET
                                     ? scenario_limits::kMaxTelnetUploadBytes
                                     : scenario_limits::kMaxUploadBytes;
  const std::size_t data_size = std::min(upload.data().size(), data_limit);
  data_ = std::string_view(upload.data().data(), data_size);
  total_size_ = data_.size();
  terminal_ = upload.terminal();
  if (scenario.scheme() != curl::fuzzer::proto::SCHEME_TELNET &&
      terminal_ == curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE) {
    // Event-driven protocols need an external resume source. Interpret this
    // TELNET-specific outcome as EOF before curl can retain a paused transfer.
    terminal_ = curl::fuzzer::proto::UPLOAD_TERMINAL_EOF;
  }
  seek_result_ = upload.seek_result();

  const std::size_t read_step_limit = scenario.scheme() == curl::fuzzer::proto::SCHEME_TELNET
                                          ? scenario_limits::kMaxTelnetUploadReadSteps
                                          : scenario_limits::kMaxUploadReadSteps;
  read_step_count_ = std::min<std::size_t>(upload.read_sizes_size(), read_step_limit);
  for (std::size_t i = 0; i < read_step_count_; ++i) {
    const std::size_t requested = upload.read_sizes(static_cast<int>(i));
    // Zero-as-one ensures every retained step makes progress; see the schema
    // comment for why zero is not treated as an early EOF sentinel.
    read_sizes_[i] = std::max<std::size_t>(1, std::min(requested, max_read_size_));
  }
}

/// Return bytes from either the explicit payload or the allocation-free
/// fallback. Terminal outcomes are emitted only after all data is consumed so
/// a mutation can independently control fragmentation and completion policy.
std::size_t UploadScriptState::Read(char* buffer, std::size_t capacity) {
  // TELNET can produce negotiation replies while one curl_multi_perform call
  // owns the thread. Empty them before returning more callback bytes;
  // otherwise send_telnet_data() can consume the whole bounded transfer
  // timeout while the synchronous path waits for socket capacity.
  if (before_read_callback_ != nullptr) {
    before_read_callback_(before_read_userdata_);
  }
  if (offset_ >= total_size_) {
    switch (terminal_) {
      case curl::fuzzer::proto::UPLOAD_TERMINAL_ABORT:
        return CURL_READFUNC_ABORT;
      case curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE:
        return CURL_READFUNC_PAUSE;
      case curl::fuzzer::proto::UPLOAD_TERMINAL_EOF:
      default:
        return 0;
    }
  }
  if (buffer == nullptr || capacity == 0) {
    return 0;
  }

  std::size_t chunk_limit = std::min(capacity, max_read_size_);
  if (next_read_size_ < read_step_count_) {
    chunk_limit = std::min(chunk_limit, read_sizes_[next_read_size_++]);
  }
  const std::size_t count = std::min(chunk_limit, total_size_ - offset_);
  if (scripted_) {
    std::memcpy(buffer, data_.data() + offset_, count);
  } else {
    std::memset(buffer, 'U', count);
  }
  offset_ += count;
  return count;
}

/// Model only seeks curl can meaningfully request from a bounded memory
/// source. Explicit range checks avoid signed overflow and keep a bogus
/// mutation from wrapping into an in-bounds cursor.
int UploadScriptState::Seek(curl_off_t requested_offset, int origin) {
  switch (seek_result_) {
    case curl::fuzzer::proto::UPLOAD_SEEK_CANTSEEK:
      return CURL_SEEKFUNC_CANTSEEK;
    case curl::fuzzer::proto::UPLOAD_SEEK_FAIL:
      return CURL_SEEKFUNC_FAIL;
    case curl::fuzzer::proto::UPLOAD_SEEK_OK:
      break;
    default:
      return CURL_SEEKFUNC_CANTSEEK;
  }

  const curl_off_t current = static_cast<curl_off_t>(offset_);
  const curl_off_t end = static_cast<curl_off_t>(total_size_);
  curl_off_t base = 0;
  switch (origin) {
    case SEEK_SET:
      base = 0;
      break;
    case SEEK_CUR:
      base = current;
      break;
    case SEEK_END:
      base = end;
      break;
    default:
      return CURL_SEEKFUNC_FAIL;
  }

  // Both base and end are at most 16 KiB. Comparing the requested delta to
  // these small bounds before addition handles even CURL_OFF_T_MIN safely.
  if (requested_offset < -base || requested_offset > end - base) {
    return CURL_SEEKFUNC_FAIL;
  }
  offset_ = static_cast<std::size_t>(base + requested_offset);
  next_read_size_ = 0;
  return CURL_SEEKFUNC_OK;
}

/// Multiplication is normally benign because curl uses size=1, but callbacks
/// are an API boundary. Abort an impossible overflowing pair: saturating to
/// SIZE_MAX would let Read() copy into a buffer whose real extent is unknown.
std::size_t UploadScriptState::ReadCallback(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
  if (userdata == nullptr || size == 0 || nitems == 0) {
    return 0;
  }
  const std::size_t max = std::numeric_limits<std::size_t>::max();
  if (nitems > max / size) {
    return CURL_READFUNC_ABORT;
  }
  return static_cast<UploadScriptState*>(userdata)->Read(buffer, size * nitems);
}

/// Keep the C callback a one-line type bridge so all outcome/cursor behaviour
/// remains directly unit-testable in Seek().
int UploadScriptState::SeekCallback(void* userdata, curl_off_t offset, int origin) {
  if (userdata == nullptr) {
    return CURL_SEEKFUNC_FAIL;
  }
  return static_cast<UploadScriptState*>(userdata)->Seek(offset, origin);
}

std::size_t UploadScriptState::data_size() const { return total_size_; }

std::size_t UploadScriptState::read_step_count() const { return read_step_count_; }

std::size_t UploadScriptState::offset() const { return offset_; }

bool UploadScriptState::scripted() const { return scripted_; }

void UploadScriptState::SetBeforeReadCallback(BeforeReadCallback callback, void* userdata) {
  before_read_callback_ = callback;
  before_read_userdata_ = userdata;
}

/// Build the protocol-specific pointer-valued request features and attach them
/// to the easy handle. Setup errors are deliberately non-fatal: malformed or
/// partially allocated scenarios should still exercise whatever curl state
/// was built.
ScenarioRequestData::ScenarioRequestData(CURL* easy, const curl::fuzzer::proto::Scenario& scenario)
    : easy_(easy),
      request_headers_(nullptr),
      telnet_options_(nullptr),
      mime_post_(nullptr),
      upload_state_(scenario),
      upload_callbacks_installed_(false) {
  if (easy_ == nullptr) {
    return;
  }

  if (NeedsUploadCallbacks(scenario)) {
    // Install a per-run memory source even when Scenario.upload is absent but
    // CURLOPT_UPLOAD or TELNET may request caller input. Non-TELNET schemes
    // retain the historical fallback bytes; TELNET returns EOF. Either result
    // replaces stdin and cannot block OSS-Fuzz. The state remains scoped to
    // the complete drive so retries cannot share a cursor across iterations.
    upload_callbacks_installed_ = true;
    (void)curl_easy_setopt(easy_, CURLOPT_READFUNCTION, &UploadScriptState::ReadCallback);
    (void)curl_easy_setopt(easy_, CURLOPT_READDATA, &upload_state_);
    (void)curl_easy_setopt(easy_, CURLOPT_SEEKFUNCTION, &UploadScriptState::SeekCallback);
    (void)curl_easy_setopt(easy_, CURLOPT_SEEKDATA, &upload_state_);
  }

  // HTTP headers/MIME and TELNET options are mutually exclusive because only
  // the selected protocol can observe them. Avoid allocating protocol-inert
  // lists and trees in compatibility inputs that bypass target policy.
  if (scenario.scheme() == curl::fuzzer::proto::SCHEME_TELNET) {
    telnet_options_ = BuildStringList(scenario.telnet_options(), scenario_limits::kMaxTelnetOptions,
                                      scenario_limits::kMaxTelnetOptionBytes, &stats_.telnet_options);
    if (telnet_options_ != nullptr) {
      (void)curl_easy_setopt(easy_, CURLOPT_TELNETOPTIONS, telnet_options_);
    }
  } else {
    request_headers_ = BuildStringList(scenario.request_headers(), scenario_limits::kMaxRequestHeaders,
                                       scenario_limits::kMaxMetadataBytes, &stats_.request_headers);
    if (request_headers_ != nullptr) {
      (void)curl_easy_setopt(easy_, CURLOPT_HTTPHEADER, request_headers_);
    }

    if (scenario.has_mime_post()) {
      mime_post_ = BuildMimePost(easy_, scenario.mime_post(), &stats_);
      if (mime_post_ != nullptr) {
        (void)curl_easy_setopt(easy_, CURLOPT_MIMEPOST, mime_post_);
      }
    }
  }
}

/// Detach resources while the easy handle is valid, then free them. libcurl
/// does not copy headers, MIME roots, or callback userdata, so releasing any
/// one before the mock drive ends would create a use-after-free; relying on
/// easy cleanup to own header/MIME allocations would instead leak iterations.
ScenarioRequestData::~ScenarioRequestData() {
  if (easy_ != nullptr) {
    // Clear callbacks before their userdata member is destroyed. There is no
    // perform in this destructor, but making the handle non-dangling keeps the
    // ownership rule robust if cleanup later gains diagnostics or getinfo.
    if (upload_callbacks_installed_) {
      (void)curl_easy_setopt(easy_, CURLOPT_SEEKFUNCTION, nullptr);
      (void)curl_easy_setopt(easy_, CURLOPT_SEEKDATA, nullptr);
      (void)curl_easy_setopt(easy_, CURLOPT_READFUNCTION, nullptr);
      (void)curl_easy_setopt(easy_, CURLOPT_READDATA, nullptr);
    }
    if (mime_post_ != nullptr) {
      (void)curl_easy_setopt(easy_, CURLOPT_MIMEPOST, nullptr);
    }
    if (request_headers_ != nullptr) {
      (void)curl_easy_setopt(easy_, CURLOPT_HTTPHEADER, nullptr);
    }
    if (telnet_options_ != nullptr) {
      (void)curl_easy_setopt(easy_, CURLOPT_TELNETOPTIONS, nullptr);
    }
  }
  curl_mime_free(mime_post_);
  curl_slist_free_all(telnet_options_);
  curl_slist_free_all(request_headers_);
}

/// Expose cap-aware counts without exposing or transferring the owned curl
/// pointers themselves.
const RequestBuildStats& ScenarioRequestData::stats() const { return stats_; }

const UploadScriptState& ScenarioRequestData::upload_state() const { return upload_state_; }

bool ScenarioRequestData::upload_callbacks_installed() const { return upload_callbacks_installed_; }

void ScenarioRequestData::SetBeforeUploadReadCallback(UploadScriptState::BeforeReadCallback callback, void* userdata) {
  upload_state_.SetBeforeReadCallback(callback, userdata);
}

}  // namespace proto_fuzzer
