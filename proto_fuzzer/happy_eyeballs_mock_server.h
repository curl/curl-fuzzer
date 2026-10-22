/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief HappyEyeballsMockServer — a loopback peer that lets curl's
///        happy-eyeballs connection filter race several real in-progress
///        connects instead of accepting the first preconnected socketpair.

#ifndef PROTO_FUZZER_HAPPY_EYEBALLS_MOCK_SERVER_H_
#define PROTO_FUZZER_HAPPY_EYEBALLS_MOCK_SERVER_H_

#include <curl/curl.h>

#include <cstddef>
#include <string>
#include <vector>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/mock_server_base.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::HappyEyeballsMockServer
/// @brief Resolver-lane peer that exposes two cached loopback addresses and
///        returns unconnected non-blocking sockets, so every address reaches
///        curl's normal TCP connect path. The first address deliberately has a
///        full accept queue and stays in progress; the second address has a
///        real listener that serves the scenario response to the winner.
class HappyEyeballsMockServer : public MockServerBase {
 public:
  HappyEyeballsMockServer();
  ~HappyEyeballsMockServer() override;

  HappyEyeballsMockServer(const HappyEyeballsMockServer&) = delete;
  HappyEyeballsMockServer& operator=(const HappyEyeballsMockServer&) = delete;

  void Install(CURL* easy) override;

  void ConfigureRequestData(ScenarioRequestData* request_data) override;

  /// @return Number of sockets handed to curl through HandleOpenSocket.
  std::size_t opened_socket_count() const { return opened_socket_count_; }

  /// @return Number of connections accepted by the serving listener.
  std::size_t accepted_peer_count() const { return accepted_peer_count_; }

  /// @return Ephemeral loopback port, or zero when listener setup failed.
  int listener_port() const { return listener_port_; }

 protected:
  curl_socket_t HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) override;

  SocketSetupDisposition GetSocketSetupDisposition(curl_socket_t curlfd, curlsocktype purpose) const override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// One accepted loopback connection and its response-delivery cursor.
  struct Peer {
    int fd = -1;
    const curl::fuzzer::proto::Connection* script = nullptr;
    std::size_t next_chunk = 0;
    std::string pending;
    std::size_t pending_offset = 0;
    bool sent_final = false;
  };

  bool OpenListeners();

  void CloseListeners();

  bool AcceptPending();

  bool ServicePeers();

  void ClosePeer(Peer* peer);

  const curl::fuzzer::proto::Connection* ScriptForAccept(std::size_t index) const;

  bool IsOwnedDestination(const struct curl_sockaddr* address) const;

  CURL* easy_;

  /// Listener on 127.0.0.1 whose accept queue is pre-filled by dummies.
  int race_fd_;
  /// Listener on the alternate 127.x address that actually serves responses.
  int serve_fd_;
  int listener_port_;
  /// Alternate loopback address the resolver entry races against 127.0.0.1.
  std::string serve_address_;
  /// Client halves that keep race_fd_'s accept queue intentionally full.
  std::vector<int> dummy_fds_;

  std::size_t opened_socket_count_;
  std::size_t accepted_peer_count_;

  /// True once both listeners and the CURLOPT_RESOLVE/PORT mapping are in
  /// place. RunLoop refuses to drive curl when this is false so a partial
  /// setup can never fall through to a real (external) connection.
  bool setup_ok_ = false;

  /// Scenario that owns every Peer::script and stays alive for RunLoop.
  const curl::fuzzer::proto::Scenario* scenario_;

  std::vector<Peer> peers_;

  /// Owns the CURLOPT_RESOLVE records curl retains for the transfer.
  CurlSlistPtr resolve_list_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_HAPPY_EYEBALLS_MOCK_SERVER_H_
