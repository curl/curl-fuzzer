/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the request-aligned in-process RTSP peer.

#include "proto_fuzzer/rtsp_mock_server.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace proto_fuzzer {

namespace {

/// Remove a command line's trailing CR/LF so header parsing does not treat the
/// terminator as part of a value.
/// @param line Complete newline-terminated line.
/// @return The line without its line ending.
std::string_view TrimLineEnding(std::string_view line) {
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
    line.remove_suffix(1);
  }
  return line;
}

/// Compare two ASCII tokens ignoring case. Header names are case-insensitive,
/// and protocol bytes outside ASCII have no valid interpretation here.
/// @param actual Observed token.
/// @param expected Literal comparison token.
/// @return true when both tokens contain the same case-folded ASCII bytes.
bool EqualsIgnoreCase(std::string_view actual, std::string_view expected) {
  if (actual.size() != expected.size()) {
    return false;
  }
  for (std::size_t index = 0; index < actual.size(); ++index) {
    unsigned char left = static_cast<unsigned char>(actual[index]);
    unsigned char right = static_cast<unsigned char>(expected[index]);
    if (left >= 'a' && left <= 'z') {
      left = static_cast<unsigned char>(left - 'a' + 'A');
    }
    if (right >= 'a' && right <= 'z') {
      right = static_cast<unsigned char>(right - 'a' + 'A');
    }
    if (left != right) {
      return false;
    }
  }
  return true;
}

/// Extract a header value from one complete header line. Only an exact
/// case-insensitive field name followed by a colon matches, so a value that
/// happens to contain the same text cannot be mistaken for the header.
/// @param line Complete header line, including its line ending.
/// @param name Case-insensitive field name without the colon.
/// @param value Receives the trimmed value when the header matches.
/// @return true when the field name matched.
bool HeaderValue(std::string_view line, std::string_view name, std::string_view* value) {
  const std::string_view trimmed = TrimLineEnding(line);
  if (trimmed.size() <= name.size() || trimmed[name.size()] != ':' ||
      !EqualsIgnoreCase(trimmed.substr(0, name.size()), name)) {
    return false;
  }

  std::size_t begin = name.size() + 1;
  while (begin < trimmed.size() && (trimmed[begin] == ' ' || trimmed[begin] == '\t')) {
    ++begin;
  }
  std::string_view parsed = trimmed.substr(begin);
  while (!parsed.empty() && (parsed.back() == ' ' || parsed.back() == '\t')) {
    parsed.remove_suffix(1);
  }
  *value = parsed;
  return true;
}

/// Parse a non-negative decimal field without relying on locale-sensitive or
/// throwing library conversions. Oversized values saturate, because the
/// caller only needs a bounded amount of subsequent work.
/// @param text Decimal digits with no sign or other characters.
/// @param result Receives the parsed or saturated value.
/// @return true when every byte was a decimal digit and the text was nonempty.
bool ParseDecimal(std::string_view text, std::uint64_t* result) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char byte : text) {
    if (byte < '0' || byte > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(byte - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
      value = std::numeric_limits<std::uint64_t>::max();
    } else {
      value = value * 10U + digit;
    }
  }
  *result = value;
  return true;
}

/// Recognize the empty line that terminates an RTSP request header block.
/// @param line Complete line, including its line ending.
/// @return true when the line contains no bytes before its line ending.
bool IsBlankLine(std::string_view line) { return TrimLineEnding(line).empty(); }

}  // namespace

/// Begin without a borrowed protobuf or open socketpair. RunLoop borrows a
/// Scenario only for the synchronous drive in which socket callbacks can run.
RtspMockServer::RtspMockServer()
    : in_request_(false),
      in_headers_(false),
      have_client_cseq_(false),
      have_content_length_(false),
      client_cseq_(0),
      last_client_cseq_(0),
      content_length_(0),
      request_count_(0),
      response_count_(0) {}

/// Release the server-owned socketpair half after curl has returned its client
/// descriptor. The out-of-line destructor keeps inherited transport ownership
/// local to this translation unit.
RtspMockServer::~RtspMockServer() = default;

/// Expose how far the bounded request stream progressed. The parser counts a
/// request only after its header block and any announced body were consumed.
/// @return Complete requests observed in the most recent drive.
std::size_t RtspMockServer::request_count() const { return request_count_; }

/// Expose how many scripted replies could be released before the bounded
/// script ran out.
/// @return Scripted replies written in the most recent drive.
std::size_t RtspMockServer::response_count() const { return response_count_; }

/// Expose the last parsed client sequence number so tests can verify that one
/// request advanced the exchange exactly once.
/// @return Last request CSeq, or zero when no parseable CSeq was present.
std::uint32_t RtspMockServer::last_client_cseq() const { return last_client_cseq_; }

/// @return Start line of the most recently completed request.
const std::string& RtspMockServer::last_request_line() const { return last_request_line_; }

/// @return Method token of the most recently completed request.
const std::string& RtspMockServer::last_method() const { return last_method_; }

/// @return Stream URI token of the most recently completed request.
const std::string& RtspMockServer::last_stream_uri() const { return last_stream_uri_; }

/// Clear RTSP's per-request parse state before the next drive. The shared base
/// has already reset the transport, reply cursor, transcript, upload capture,
/// and body mode.
void RtspMockServer::ResetProtocolState() {
  in_request_ = false;
  in_headers_ = false;
  have_client_cseq_ = false;
  have_content_length_ = false;
  client_cseq_ = 0;
  last_client_cseq_ = 0;
  content_length_ = 0;
  request_count_ = 0;
  response_count_ = 0;
  last_request_line_.clear();
  last_method_.clear();
  last_stream_uri_.clear();
}

/// Start a new request after the previous one completed. The request line is
/// parsed for observability, while the reply itself stays scripted.
/// @param line Complete request start line, including its line ending.
void RtspMockServer::BeginRequest(std::string_view line) {
  const std::string_view trimmed = TrimLineEnding(line);
  last_request_line_.assign(trimmed.data(), trimmed.size());
  const std::string_view method = FirstToken(trimmed);
  const std::string_view stream_uri = SecondToken(trimmed);
  last_method_.assign(method.data(), method.size());
  last_stream_uri_.assign(stream_uri.data(), stream_uri.size());

  in_request_ = true;
  in_headers_ = true;
  have_client_cseq_ = false;
  have_content_length_ = false;
  client_cseq_ = 0;
  content_length_ = 0;
}

/// Parse the two headers that change how the peer stays synchronized. Other
/// headers remain part of the transcript and are otherwise opaque to the peer.
/// @param line Complete header line, including its line ending.
void RtspMockServer::ParseHeader(std::string_view line) {
  std::string_view value;
  if (HeaderValue(line, "CSeq", &value)) {
    std::uint64_t parsed = 0;
    if (ParseDecimal(value, &parsed)) {
      have_client_cseq_ = true;
      client_cseq_ =
          static_cast<std::uint32_t>(std::min<std::uint64_t>(parsed, std::numeric_limits<std::uint32_t>::max()));
    }
    return;
  }

  if (HeaderValue(line, "Content-Length", &value)) {
    std::uint64_t parsed = 0;
    if (ParseDecimal(value, &parsed)) {
      have_content_length_ = true;
      content_length_ =
          static_cast<std::size_t>(std::min<std::uint64_t>(parsed, std::numeric_limits<std::size_t>::max()));
    }
  }
}

/// Complete one request: advance the scripted reply cursor, record the parsed
/// exchange, and return to start-line mode. An empty scripted reply still
/// advances the cursor because it is a meaningful truncation mutation.
void RtspMockServer::FinishRequest() {
  ++request_count_;
  last_client_cseq_ = have_client_cseq_ ? client_cseq_ : 0;
  if (WriteNextReply()) {
    ++response_count_;
  }

  in_request_ = false;
  in_headers_ = false;
  have_client_cseq_ = false;
  have_content_length_ = false;
  client_cseq_ = 0;
  content_length_ = 0;
}

/// Consume one complete request line or header line. The blank line that ends
/// the header block is the reply trigger: an announced body first switches the
/// shared parser into exact-length mode, whose completion calls
/// HandleBodyComplete().
/// @param line Complete line sent by curl.
void RtspMockServer::HandleLine(std::string_view line) {
  if (!in_request_) {
    BeginRequest(line);
    return;
  }

  if (IsBlankLine(line)) {
    in_headers_ = false;
    if (have_content_length_ && content_length_ != 0) {
      BeginExactBody(content_length_);
      return;
    }
    FinishRequest();
    return;
  }

  if (in_headers_) {
    ParseHeader(line);
  }
}

/// Release the reply after an announced request body was drained exactly.
void RtspMockServer::HandleBodyComplete() { FinishRequest(); }

}  // namespace proto_fuzzer
