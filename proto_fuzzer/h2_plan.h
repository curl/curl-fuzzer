/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Stateful serializer for structured HTTP/2 peer actions.

#ifndef PROTO_FUZZER_H2_PLAN_H_
#define PROTO_FUZZER_H2_PLAN_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/incoming_data_observer.h"

/// Opaque nghttp2 HPACK encoder state.
struct nghttp2_hd_deflater;

namespace proto_fuzzer {

/// Converts Http2Plan actions to correlated wire frames while tracking the
/// request streams observed from curl. It has no transport dependency and can
/// therefore serve both TLS and cleartext H2 origin peers.
class H2PlanDriver final : public IncomingDataObserver {
 public:
  H2PlanDriver();
  ~H2PlanDriver() override;

  H2PlanDriver(const H2PlanDriver&) = delete;
  H2PlanDriver& operator=(const H2PlanDriver&) = delete;

  /// Reset HPACK and stream state for one connection.
  /// @param plan Ordered H2 actions and initial peer settings to execute.
  /// @param scheme Scheme used in generated push-request pseudo-headers.
  /// @param authority Authority used in generated push-request pseudo-headers.
  void Reset(const curl::fuzzer::proto::Http2Plan& plan, std::string scheme = "https",
             std::string authority = "tls.test");

  /// Parse client frame headers after transport decoding.
  /// @param data Contiguous bytes received from curl.
  /// @param size Number of bytes available at `data`.
  void ObserveIncomingData(const unsigned char* data, std::size_t size) override;

  /// Advance one scripted boundary. `output` receives zero or more complete
  /// HTTP/2 frames. A true result also represents a consumed wait or yield;
  /// false means the next barrier is not ready or the plan is complete.
  /// @param output Destination for the serialized frame bytes.
  /// @return true when a frame, wait, or yield boundary was consumed.
  bool NextChunk(std::string* output);

  /// @return true while startup or a bounded action remains to be processed.
  bool has_pending_work() const;

  /// @return number of distinct client request streams observed.
  std::size_t observed_request_count() const;

  /// @return number of non-ACK client SETTINGS frames observed.
  std::size_t observed_client_settings_count() const;

 private:
  struct ClientStreamState {
    std::size_t headers = 0;
    std::size_t data = 0;
    std::size_t end_stream = 0;
  };

  std::uint32_t ResolveStream(const curl::fuzzer::proto::Http2StreamRef& stream, bool allow_connection) const;
  std::uint32_t ResolvePromisedStream(const curl::fuzzer::proto::Http2StreamRef& stream);
  bool WaitSatisfied(const curl::fuzzer::proto::Http2Wait& wait) const;
  bool SerializeAction(const curl::fuzzer::proto::Http2Action& action, std::string* output);
  bool EncodeHeaders(const std::vector<std::pair<std::string, std::string>>& headers, std::string* output);
  void ParseClientFrames();
  void RecordClientFrame(std::uint8_t type, std::uint8_t flags, std::uint32_t stream_id);

  const curl::fuzzer::proto::Http2Plan* plan_;
  nghttp2_hd_deflater* deflater_;
  std::size_t next_action_;
  std::size_t remaining_yields_;
  bool initial_settings_sent_;
  bool client_settings_ack_sent_;
  bool expect_client_preface_;
  std::size_t observed_client_settings_;
  std::string client_bytes_;
  std::vector<std::uint32_t> request_streams_;
  std::vector<std::uint32_t> pushed_streams_;
  std::unordered_map<std::uint32_t, ClientStreamState> client_streams_;
  std::string scheme_;
  std::string authority_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_H2_PLAN_H_
