/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief HTTP/2 structured-action serialization and client frame tracking.

#include "proto_fuzzer/h2_plan.h"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

namespace {

constexpr std::string_view kClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::size_t kFrameHeaderSize = 9;
constexpr std::size_t kMaxFramePayload = 16384;

constexpr std::uint8_t kDataFrame = 0;
constexpr std::uint8_t kHeadersFrame = 1;
constexpr std::uint8_t kRstStreamFrame = 3;
constexpr std::uint8_t kSettingsFrame = 4;
constexpr std::uint8_t kPushPromiseFrame = 5;
constexpr std::uint8_t kPingFrame = 6;
constexpr std::uint8_t kGoawayFrame = 7;
constexpr std::uint8_t kWindowUpdateFrame = 8;
constexpr std::uint8_t kContinuationFrame = 9;

constexpr std::uint8_t kFlagAck = 0x1;
constexpr std::uint8_t kFlagEndStream = 0x1;
constexpr std::uint8_t kFlagEndHeaders = 0x4;

void AppendUint32(std::string* output, std::uint32_t value) {
  output->push_back(static_cast<char>((value >> 24U) & 0xffU));
  output->push_back(static_cast<char>((value >> 16U) & 0xffU));
  output->push_back(static_cast<char>((value >> 8U) & 0xffU));
  output->push_back(static_cast<char>(value & 0xffU));
}

std::uint32_t ReadUint32(const char* input) {
  const auto* bytes = reinterpret_cast<const unsigned char*>(input);
  return (static_cast<std::uint32_t>(bytes[0]) << 24U) | (static_cast<std::uint32_t>(bytes[1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[2]) << 8U) | static_cast<std::uint32_t>(bytes[3]);
}

void AppendFrame(std::string* output, std::uint32_t declared_length, std::uint8_t type, std::uint8_t flags,
                 std::uint32_t stream_id, std::string_view payload) {
  const std::uint32_t length = declared_length & 0x00ffffffU;
  output->push_back(static_cast<char>((length >> 16U) & 0xffU));
  output->push_back(static_cast<char>((length >> 8U) & 0xffU));
  output->push_back(static_cast<char>(length & 0xffU));
  output->push_back(static_cast<char>(type));
  output->push_back(static_cast<char>(flags));
  AppendUint32(output, stream_id & 0x7fffffffU);
  output->append(payload.data(), payload.size());
}

std::uint32_t CanonicalStatus(std::uint32_t status) {
  if (status >= 100U && status <= 599U) {
    return status;
  }
  return status == 0U ? 200U : 100U + (status % 500U);
}

std::string BoundedString(const std::string& input, std::size_t limit) { return input.substr(0, limit); }

std::string CanonicalHeaderName(const std::string& input) {
  std::string name = BoundedString(input, scenario_limits::kMaxHttp3HeaderNameBytes);
  if (name.empty()) {
    return "x-fuzz";
  }
  for (char& byte : name) {
    const unsigned char value = static_cast<unsigned char>(byte);
    const bool alpha = (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
    const bool digit = value >= '0' && value <= '9';
    const bool punctuation = value == '!' || value == '#' || value == '$' || value == '%' || value == '&' ||
                             value == '\'' || value == '*' || value == '+' || value == '-' || value == '.' ||
                             value == '^' || value == '_' || value == '`' || value == '|' || value == '~';
    if (value >= 'A' && value <= 'Z') {
      byte = static_cast<char>(value - 'A' + 'a');
    } else if (!alpha && !digit && !punctuation) {
      byte = '-';
    }
  }
  return name;
}

std::string CanonicalHeaderValue(const std::string& input) {
  std::string value = BoundedString(input, scenario_limits::kMaxMetadataBytes);
  for (char& byte : value) {
    const unsigned char character = static_cast<unsigned char>(byte);
    if ((character < 0x20U && character != '\t') || character == 0x7fU) {
      byte = ' ';
    }
  }
  return value;
}

}  // namespace

H2PlanDriver::H2PlanDriver()
    : plan_(nullptr),
      deflater_(nullptr),
      next_action_(0),
      remaining_yields_(0),
      initial_settings_sent_(false),
      client_settings_ack_sent_(false),
      expect_client_preface_(true),
      observed_client_settings_(0) {
  (void)nghttp2_hd_deflate_new(&deflater_, 4096);
}

H2PlanDriver::~H2PlanDriver() { nghttp2_hd_deflate_del(deflater_); }

void H2PlanDriver::Reset(const curl::fuzzer::proto::Http2Plan& plan, std::string scheme, std::string authority) {
  plan_ = &plan;
  next_action_ = 0;
  remaining_yields_ = 0;
  initial_settings_sent_ = false;
  client_settings_ack_sent_ = false;
  expect_client_preface_ = true;
  observed_client_settings_ = 0;
  client_bytes_.clear();
  request_streams_.clear();
  pushed_streams_.clear();
  client_streams_.clear();
  scheme_ = std::move(scheme);
  authority_ = std::move(authority);
  nghttp2_hd_deflate_del(deflater_);
  deflater_ = nullptr;
  (void)nghttp2_hd_deflate_new(&deflater_, 4096);
}

void H2PlanDriver::ObserveIncomingData(const unsigned char* data, std::size_t size) {
  if (data == nullptr || size == 0) {
    return;
  }
  if (size > scenario_limits::kMaxHttp2ObservedBytes ||
      client_bytes_.size() > scenario_limits::kMaxHttp2ObservedBytes - size) {
    client_bytes_.clear();
    expect_client_preface_ = false;
    return;
  }
  client_bytes_.append(reinterpret_cast<const char*>(data), size);
  ParseClientFrames();
}

void H2PlanDriver::ParseClientFrames() {
  if (expect_client_preface_) {
    if (client_bytes_.size() < kClientPreface.size()) {
      return;
    }
    if (std::string_view(client_bytes_).substr(0, kClientPreface.size()) == kClientPreface) {
      client_bytes_.erase(0, kClientPreface.size());
    }
    expect_client_preface_ = false;
  }

  std::size_t consumed = 0;
  while (client_bytes_.size() - consumed >= kFrameHeaderSize) {
    const auto* header = reinterpret_cast<const unsigned char*>(client_bytes_.data() + consumed);
    const std::size_t payload_size = (static_cast<std::size_t>(header[0]) << 16U) |
                                     (static_cast<std::size_t>(header[1]) << 8U) | static_cast<std::size_t>(header[2]);
    if (payload_size > scenario_limits::kMaxHttp2ObservedBytes ||
        client_bytes_.size() - consumed < kFrameHeaderSize + payload_size) {
      break;
    }
    const std::uint8_t type = header[3];
    const std::uint8_t flags = header[4];
    const std::uint32_t stream_id = ReadUint32(client_bytes_.data() + consumed + 5) & 0x7fffffffU;
    RecordClientFrame(type, flags, stream_id);
    consumed += kFrameHeaderSize + payload_size;
  }
  client_bytes_.erase(0, consumed);
}

void H2PlanDriver::RecordClientFrame(std::uint8_t type, std::uint8_t flags, std::uint32_t stream_id) {
  if (type == kSettingsFrame && stream_id == 0 && (flags & kFlagAck) == 0) {
    ++observed_client_settings_;
    return;
  }
  if (stream_id == 0) {
    return;
  }

  auto& stream = client_streams_[stream_id];
  if (type == kHeadersFrame) {
    ++stream.headers;
    if ((stream_id & 1U) != 0 &&
        std::find(request_streams_.begin(), request_streams_.end(), stream_id) == request_streams_.end()) {
      request_streams_.push_back(stream_id);
    }
  } else if (type == kDataFrame) {
    ++stream.data;
  }
  if ((type == kHeadersFrame || type == kDataFrame) && (flags & kFlagEndStream) != 0) {
    ++stream.end_stream;
  }
}

std::uint32_t H2PlanDriver::ResolveStream(const curl::fuzzer::proto::Http2StreamRef& stream,
                                          bool allow_connection) const {
  using StreamRef = curl::fuzzer::proto::Http2StreamRef;
  switch (stream.target_case()) {
    case StreamRef::kConnection:
      return allow_connection ? 0U : 1U;
    case StreamRef::kRequestIndex: {
      const std::size_t index = static_cast<std::size_t>(stream.request_index());
      if (index < request_streams_.size()) {
        return request_streams_[index];
      }
      return 1U + 2U * static_cast<std::uint32_t>(index % 0x3fffffffU);
    }
    case StreamRef::kPushIndex: {
      const std::size_t index = static_cast<std::size_t>(stream.push_index());
      if (index < pushed_streams_.size()) {
        return pushed_streams_[index];
      }
      return 2U + 2U * static_cast<std::uint32_t>(index % 0x3fffffffU);
    }
    case StreamRef::kExplicitId:
      return stream.explicit_id() & 0x7fffffffU;
    case StreamRef::kLatestRequest:
    case StreamRef::TARGET_NOT_SET:
    default:
      return request_streams_.empty() ? 1U : request_streams_.back();
  }
}

std::uint32_t H2PlanDriver::ResolvePromisedStream(const curl::fuzzer::proto::Http2StreamRef& stream) {
  std::uint32_t stream_id = 0;
  if (stream.target_case() == curl::fuzzer::proto::Http2StreamRef::TARGET_NOT_SET ||
      stream.target_case() == curl::fuzzer::proto::Http2StreamRef::kLatestRequest ||
      stream.target_case() == curl::fuzzer::proto::Http2StreamRef::kConnection) {
    stream_id = 2U + 2U * static_cast<std::uint32_t>(pushed_streams_.size());
  } else {
    stream_id = ResolveStream(stream, false);
  }
  if (std::find(pushed_streams_.begin(), pushed_streams_.end(), stream_id) == pushed_streams_.end()) {
    pushed_streams_.push_back(stream_id);
  }
  return stream_id;
}

bool H2PlanDriver::WaitSatisfied(const curl::fuzzer::proto::Http2Wait& wait) const {
  const std::size_t required = std::max<std::size_t>(1, std::min<std::size_t>(wait.count(), 16));
  if (wait.event() == curl::fuzzer::proto::HTTP2_CLIENT_EVENT_SETTINGS) {
    return observed_client_settings_ >= required;
  }
  const std::uint32_t stream_id = ResolveStream(wait.stream(), false);
  const auto found = client_streams_.find(stream_id);
  if (found == client_streams_.end()) {
    return false;
  }
  switch (wait.event()) {
    case curl::fuzzer::proto::HTTP2_CLIENT_EVENT_HEADERS:
      return found->second.headers >= required;
    case curl::fuzzer::proto::HTTP2_CLIENT_EVENT_DATA:
      return found->second.data >= required;
    case curl::fuzzer::proto::HTTP2_CLIENT_EVENT_END_STREAM:
      return found->second.end_stream >= required;
    case curl::fuzzer::proto::HTTP2_CLIENT_EVENT_SETTINGS:
    default:
      return false;
  }
}

bool H2PlanDriver::EncodeHeaders(const std::vector<std::pair<std::string, std::string>>& headers, std::string* output) {
  if (deflater_ == nullptr || output == nullptr) {
    return false;
  }
  std::vector<nghttp2_nv> name_values;
  name_values.reserve(headers.size());
  for (const auto& header : headers) {
    nghttp2_nv nv{};
    nv.name = reinterpret_cast<std::uint8_t*>(const_cast<char*>(header.first.data()));
    nv.value = reinterpret_cast<std::uint8_t*>(const_cast<char*>(header.second.data()));
    nv.namelen = header.first.size();
    nv.valuelen = header.second.size();
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    name_values.push_back(nv);
  }
  const std::size_t bound = nghttp2_hd_deflate_bound(deflater_, name_values.data(), name_values.size());
  if (bound > scenario_limits::kMaxHttp2HeaderBytes * 2U) {
    return false;
  }
  output->resize(bound);
  const nghttp2_ssize encoded = nghttp2_hd_deflate_hd2(deflater_, reinterpret_cast<std::uint8_t*>(output->data()),
                                                       output->size(), name_values.data(), name_values.size());
  if (encoded < 0) {
    output->clear();
    return false;
  }
  output->resize(static_cast<std::size_t>(encoded));
  return true;
}

bool H2PlanDriver::SerializeAction(const curl::fuzzer::proto::Http2Action& action, std::string* output) {
  using Action = curl::fuzzer::proto::Http2Action;
  output->clear();
  switch (action.action_case()) {
    case Action::kSettings: {
      std::string payload;
      const auto& settings = action.settings();
      if (!settings.ack()) {
        const std::size_t count = std::min<std::size_t>(scenario_limits::kMaxHttp2Settings,
                                                        static_cast<std::size_t>(settings.entries_size()));
        payload.reserve(count * 6U);
        for (std::size_t index = 0; index < count; ++index) {
          const auto& entry = settings.entries(static_cast<int>(index));
          const std::uint16_t identifier = static_cast<std::uint16_t>(entry.identifier());
          payload.push_back(static_cast<char>((identifier >> 8U) & 0xffU));
          payload.push_back(static_cast<char>(identifier & 0xffU));
          AppendUint32(&payload, entry.value());
        }
      }
      AppendFrame(output, payload.size(), kSettingsFrame, settings.ack() ? kFlagAck : 0, 0, payload);
      return true;
    }
    case Action::kHeaders: {
      const auto& headers = action.headers();
      std::vector<std::pair<std::string, std::string>> fields;
      const std::size_t count =
          std::min<std::size_t>(scenario_limits::kMaxHttp2Headers, static_cast<std::size_t>(headers.fields_size()));
      fields.reserve(count + 1U);
      if (!headers.trailers()) {
        fields.emplace_back(":status", std::to_string(CanonicalStatus(headers.status_code())));
      }
      std::size_t bytes = 0;
      for (std::size_t index = 0; index < count && bytes < scenario_limits::kMaxHttp2HeaderBytes; ++index) {
        const auto& field = headers.fields(static_cast<int>(index));
        std::string name = CanonicalHeaderName(field.name());
        std::string value = CanonicalHeaderValue(field.value());
        const std::size_t remaining = scenario_limits::kMaxHttp2HeaderBytes - bytes;
        if (name.size() + value.size() > remaining) {
          value.resize(remaining > name.size() ? remaining - name.size() : 0);
          name.resize(std::min(name.size(), remaining));
        }
        bytes += name.size() + value.size();
        fields.emplace_back(std::move(name), std::move(value));
      }
      std::string block;
      if (!EncodeHeaders(fields, &block)) {
        return false;
      }
      const std::uint32_t stream_id = ResolveStream(headers.stream(), false);
      std::size_t offset = 0;
      do {
        const std::size_t chunk_size = std::min(kMaxFramePayload, block.size() - offset);
        const bool last = offset + chunk_size == block.size();
        std::uint8_t flags = last ? kFlagEndHeaders : 0;
        if (offset == 0 && headers.end_stream()) {
          flags |= kFlagEndStream;
        }
        AppendFrame(output, chunk_size, offset == 0 ? kHeadersFrame : kContinuationFrame, flags, stream_id,
                    std::string_view(block).substr(offset, chunk_size));
        offset += chunk_size;
      } while (offset < block.size());
      return true;
    }
    case Action::kData: {
      const auto& data = action.data();
      const std::string payload = BoundedString(data.data(), scenario_limits::kMaxHttp2DataBytes);
      const std::uint32_t stream_id = ResolveStream(data.stream(), false);
      std::size_t offset = 0;
      do {
        const std::size_t chunk_size = std::min(kMaxFramePayload, payload.size() - offset);
        const bool last = offset + chunk_size == payload.size();
        AppendFrame(output, chunk_size, kDataFrame, last && data.end_stream() ? kFlagEndStream : 0, stream_id,
                    std::string_view(payload).substr(offset, chunk_size));
        offset += chunk_size;
      } while (offset < payload.size());
      return true;
    }
    case Action::kWindowUpdate: {
      const auto& update = action.window_update();
      std::string payload;
      AppendUint32(&payload, std::max(1U, update.increment() & 0x7fffffffU));
      AppendFrame(output, payload.size(), kWindowUpdateFrame, 0, ResolveStream(update.stream(), true), payload);
      return true;
    }
    case Action::kRstStream: {
      const auto& reset = action.rst_stream();
      std::string payload;
      AppendUint32(&payload, reset.error_code());
      AppendFrame(output, payload.size(), kRstStreamFrame, 0, ResolveStream(reset.stream(), false), payload);
      return true;
    }
    case Action::kPing: {
      std::array<char, 8> opaque{};
      const std::string& source = action.ping().opaque_data();
      std::copy_n(source.begin(), std::min(source.size(), opaque.size()), opaque.begin());
      AppendFrame(output, opaque.size(), kPingFrame, action.ping().ack() ? kFlagAck : 0, 0,
                  std::string_view(opaque.data(), opaque.size()));
      return true;
    }
    case Action::kGoaway: {
      const auto& goaway = action.goaway();
      std::string payload;
      AppendUint32(&payload, ResolveStream(goaway.last_stream(), true));
      AppendUint32(&payload, goaway.error_code());
      payload.append(BoundedString(goaway.debug_data(), scenario_limits::kMaxHttp2RawFrameBytes));
      AppendFrame(output, payload.size(), kGoawayFrame, 0, 0, payload);
      return true;
    }
    case Action::kPushPromise: {
      const auto& promise = action.push_promise();
      std::vector<std::pair<std::string, std::string>> fields = {
          {":method", "GET"}, {":scheme", scheme_}, {":authority", authority_}, {":path", "/push"}};
      const std::size_t count = std::min<std::size_t>(scenario_limits::kMaxHttp2Headers,
                                                      static_cast<std::size_t>(promise.request_headers_size()));
      for (std::size_t index = 0; index < count; ++index) {
        const auto& field = promise.request_headers(static_cast<int>(index));
        fields.emplace_back(CanonicalHeaderName(field.name()), CanonicalHeaderValue(field.value()));
      }
      std::string block;
      if (!EncodeHeaders(fields, &block)) {
        return false;
      }
      const std::uint32_t parent = ResolveStream(promise.parent_stream(), false);
      const std::uint32_t promised = ResolvePromisedStream(promise.promised_stream());
      std::string first_payload;
      AppendUint32(&first_payload, promised);
      const std::size_t first_size = std::min(kMaxFramePayload - 4U, block.size());
      first_payload.append(block.data(), first_size);
      AppendFrame(output, first_payload.size(), kPushPromiseFrame, first_size == block.size() ? kFlagEndHeaders : 0,
                  parent, first_payload);
      std::size_t offset = first_size;
      while (offset < block.size()) {
        const std::size_t chunk_size = std::min(kMaxFramePayload, block.size() - offset);
        offset += chunk_size;
        AppendFrame(output, chunk_size, kContinuationFrame, offset == block.size() ? kFlagEndHeaders : 0, parent,
                    std::string_view(block).substr(offset - chunk_size, chunk_size));
      }
      return true;
    }
    case Action::kWireFrame: {
      const auto& frame = action.wire_frame();
      const std::string payload = BoundedString(frame.payload(), scenario_limits::kMaxHttp2RawFrameBytes);
      const std::uint32_t declared = frame.use_declared_length() ? frame.declared_length() : payload.size();
      AppendFrame(output, declared, static_cast<std::uint8_t>(frame.type()), static_cast<std::uint8_t>(frame.flags()),
                  frame.stream_id(), payload);
      return true;
    }
    case Action::kRawBytes:
      *output = BoundedString(action.raw_bytes(), scenario_limits::kMaxHttp2RawFrameBytes);
      return true;
    case Action::kWait:
    case Action::kYieldTurns:
    case Action::ACTION_NOT_SET:
    default:
      return false;
  }
}

bool H2PlanDriver::NextChunk(std::string* output) {
  if (output == nullptr || plan_ == nullptr) {
    return false;
  }
  output->clear();
  if (!initial_settings_sent_) {
    curl::fuzzer::proto::Http2Action initial;
    *initial.mutable_settings() = plan_->initial_settings();
    initial.mutable_settings()->set_ack(false);
    (void)SerializeAction(initial, output);
    initial_settings_sent_ = true;
    return true;
  }
  if (!client_settings_ack_sent_) {
    if (observed_client_settings_ == 0) {
      return false;
    }
    AppendFrame(output, 0, kSettingsFrame, kFlagAck, 0, {});
    client_settings_ack_sent_ = true;
    return true;
  }

  const std::size_t action_count =
      std::min<std::size_t>(scenario_limits::kMaxHttp2Actions, static_cast<std::size_t>(plan_->actions_size()));
  if (next_action_ >= action_count) {
    return false;
  }
  const auto& action = plan_->actions(static_cast<int>(next_action_));
  if (action.action_case() == curl::fuzzer::proto::Http2Action::kWait) {
    if (!WaitSatisfied(action.wait())) {
      return false;
    }
    ++next_action_;
    return true;
  }
  if (action.action_case() == curl::fuzzer::proto::Http2Action::kYieldTurns) {
    if (remaining_yields_ == 0) {
      remaining_yields_ = std::min<std::size_t>(scenario_limits::kMaxHttp2YieldTurns, action.yield_turns());
      if (remaining_yields_ == 0) {
        ++next_action_;
        return true;
      }
    }
    --remaining_yields_;
    if (remaining_yields_ == 0) {
      ++next_action_;
    }
    return true;
  }

  (void)SerializeAction(action, output);
  ++next_action_;
  return true;
}

bool H2PlanDriver::has_pending_work() const {
  if (plan_ == nullptr || !initial_settings_sent_ || !client_settings_ack_sent_) {
    return plan_ != nullptr;
  }
  return next_action_ <
         std::min<std::size_t>(scenario_limits::kMaxHttp2Actions, static_cast<std::size_t>(plan_->actions_size()));
}

std::size_t H2PlanDriver::observed_request_count() const { return request_streams_.size(); }

std::size_t H2PlanDriver::observed_client_settings_count() const { return observed_client_settings_; }

}  // namespace proto_fuzzer
