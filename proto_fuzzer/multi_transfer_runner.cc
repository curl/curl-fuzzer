/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the bounded concurrent easy-handle runner.

#include "proto_fuzzer/multi_transfer_runner.h"

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <string>

#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/mock_server.h"
#include "proto_fuzzer/multi_socket_driver.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

namespace {

/// One easy handle and every caller-owned pointer installed on it. Declaration
/// order makes reverse destruction detach request data, clean the easy, then
/// release CONNECT_TO storage if an early return bypasses explicit teardown.
struct TransferState {
  CurlSlistPtr connect_to;
  CurlEasyPtr easy;
  std::unique_ptr<ScenarioRequestData> request_data;
  bool attached = false;
};

constexpr int kMaxDriveIterations = 512;
constexpr int kMaxIdleIterations = 8;

std::size_t RuntimeTransferCount(const curl::fuzzer::proto::MultiPlan& plan) {
  return std::max(scenario_limits::kMinMultiTransfers,
                  std::min(static_cast<std::size_t>(plan.transfer_count()), scenario_limits::kMaxMultiTransfers));
}

/// Consume every currently queued completion before handle removal can discard
/// it. Re-added handles may complete more than once, so count messages rather
/// than only distinct easy pointers.
bool DrainCompletionMessages(CURLM* multi, std::array<TransferState, scenario_limits::kMaxMultiTransfers>* transfers,
                             std::size_t transfer_count, MultiTransferRunStats* stats) {
  bool consumed = false;
  int messages_remaining = 0;
  CURLMsg* message = nullptr;
  while ((message = curl_multi_info_read(multi, &messages_remaining)) != nullptr) {
    consumed = true;
    if (message->msg != CURLMSG_DONE) {
      continue;
    }
    for (std::size_t index = 0; index < transfer_count; ++index) {
      TransferState& transfer = (*transfers)[index];
      if (transfer.easy.get() == message->easy_handle) {
        ++stats->completion_messages;
        break;
      }
    }
  }
  return consumed;
}

/// Apply one schema-safe lifecycle transition. Return true only when libcurl
/// accepted a state change; consuming an ineffective action is tracked
/// separately so later ordered actions remain reachable.
bool ApplyAction(const curl::fuzzer::proto::MultiAction& action, CURLM* multi,
                 std::array<TransferState, scenario_limits::kMaxMultiTransfers>* transfers,
                 std::size_t transfer_count) {
  if (transfer_count == 0) {
    return false;
  }
  TransferState& transfer = (*transfers)[static_cast<std::size_t>(action.transfer_selector()) % transfer_count];
  CURL* easy = transfer.easy.get();
  if (easy == nullptr) {
    return false;
  }

  switch (action.kind()) {
    case curl::fuzzer::proto::MULTI_ACTION_PAUSE_RECV:
      return curl_easy_pause(easy, CURLPAUSE_RECV) == CURLE_OK;
    case curl::fuzzer::proto::MULTI_ACTION_PAUSE_SEND:
      return curl_easy_pause(easy, CURLPAUSE_SEND) == CURLE_OK;
    case curl::fuzzer::proto::MULTI_ACTION_PAUSE_ALL:
      return curl_easy_pause(easy, CURLPAUSE_ALL) == CURLE_OK;
    case curl::fuzzer::proto::MULTI_ACTION_RESUME:
      return curl_easy_pause(easy, CURLPAUSE_CONT) == CURLE_OK;
    case curl::fuzzer::proto::MULTI_ACTION_REMOVE:
      if (transfer.attached && curl_multi_remove_handle(multi, easy) == CURLM_OK) {
        transfer.attached = false;
        return true;
      }
      return false;
    case curl::fuzzer::proto::MULTI_ACTION_READD:
      if (!transfer.attached && curl_multi_add_handle(multi, easy) == CURLM_OK) {
        transfer.attached = true;
        return true;
      }
      return false;
    case curl::fuzzer::proto::MULTI_ACTION_NONE:
    default:
      return false;
  }
}

/// Cover the public wait/poll/fdset queries from a valid shared-multi state
/// without introducing wall-clock delay.
void ProbeMultiWaitApis(CURLM* multi) {
  int numfds = 0;
  (void)curl_multi_poll(multi, nullptr, 0, 0, &numfds);
  (void)curl_multi_wait(multi, nullptr, 0, 0, &numfds);

  fd_set readfds;
  fd_set writefds;
  fd_set exceptfds;
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_ZERO(&exceptfds);
  int maxfd = -1;
  (void)curl_multi_fdset(multi, &readfds, &writefds, &exceptfds, &maxfd);
  long timeout_ms = -1;
  (void)curl_multi_timeout(multi, &timeout_ms);
}

}  // namespace

/// Construct a stateless runner; all ownership is scoped to Run().
MultiTransferRunner::MultiTransferRunner() = default;

/// Default destructor; Run() dismantles each shared-multi lifecycle in place.
MultiTransferRunner::~MultiTransferRunner() = default;

MultiTransferRunStats MultiTransferRunner::Run(const curl::fuzzer::proto::Scenario& scenario) {
  MultiTransferRunStats stats;
  const auto& plan = scenario.multi_plan();
  const std::size_t transfer_count = RuntimeTransferCount(plan);
  stats.configured_handles = transfer_count;

  // The peer and socket callback state must outlive multi cleanup, which can
  // synchronously announce socket removals and close cached connections.
  MockServer mock;
  mock.SetScripts(scenario);
  mock.SetKeepConnectionsOpen(plan.keep_connections_open());
  MultiSocketDriver socket_driver;
  CurlMultiPtr multi(curl_multi_init());
  if (!multi) {
    return stats;
  }

  const long max_host_connections =
      static_cast<long>(std::min<std::size_t>(plan.max_host_connections(), transfer_count));
  const long max_total_connections =
      static_cast<long>(std::min<std::size_t>(plan.max_total_connections(), transfer_count));
  const long cache_size =
      static_cast<long>(std::min<std::size_t>(plan.connection_cache_size(), scenario_limits::kMaxMultiTransfers * 2));
  (void)curl_multi_setopt(multi.get(), CURLMOPT_MAX_HOST_CONNECTIONS, max_host_connections);
  (void)curl_multi_setopt(multi.get(), CURLMOPT_MAX_TOTAL_CONNECTIONS, max_total_connections);
  (void)curl_multi_setopt(multi.get(), CURLMOPT_MAXCONNECTS, cache_size);
  (void)curl_multi_setopt(multi.get(), CURLMOPT_PIPELINING,
                          plan.multiplex() ? static_cast<long>(CURLPIPE_MULTIPLEX) : 0L);

  const bool socket_mode = plan.drive_mode() == curl::fuzzer::proto::MULTI_DRIVE_SOCKET;
  const bool socket_driver_installed = socket_mode && socket_driver.Install(multi.get());
  std::array<TransferState, scenario_limits::kMaxMultiTransfers> transfers;
  const std::string url = "http://" + scenario.host_path();
  for (std::size_t index = 0; index < transfer_count; ++index) {
    TransferState& transfer = transfers[index];
    transfer.easy.reset(curl_easy_init());
    if (!transfer.easy) {
      continue;
    }
    transfer.connect_to.reset(ApplyBaselineOptions(transfer.easy.get(), curl::fuzzer::proto::SCHEME_HTTP));
    (void)curl_easy_setopt(transfer.easy.get(), CURLOPT_URL, url.c_str());
    mock.Install(transfer.easy.get());
    (void)ApplyScenarioOptions(transfer.easy.get(), scenario);
    transfer.request_data = std::make_unique<ScenarioRequestData>(transfer.easy.get(), scenario);
    mock.ConfigureRequestData(transfer.request_data.get());
    if (curl_multi_add_handle(multi.get(), transfer.easy.get()) == CURLM_OK) {
      transfer.attached = true;
      ++stats.added_handles;
    }
  }

  if (stats.added_handles == 0) {
    multi.reset();
    return stats;
  }

  const std::size_t action_count = std::min<std::size_t>(plan.actions_size(), scenario_limits::kMaxMultiActions);
  std::size_t next_action = 0;
  bool initial_action_changed = false;
  if (next_action < action_count) {
    initial_action_changed =
        ApplyAction(plan.actions(static_cast<int>(next_action++)), multi.get(), &transfers, transfer_count);
    ++stats.actions_consumed;
  }

  int running_handles = 0;
  CURLMcode result = socket_driver_installed ? socket_driver.Start(&running_handles)
                                             : curl_multi_perform(multi.get(), &running_handles);
  bool completion_progress = DrainCompletionMessages(multi.get(), &transfers, transfer_count, &stats);
  ProbeMultiWaitApis(multi.get());
  if (plan.wake_multi()) {
    if (socket_driver_installed) {
      socket_driver.ProbeControlApis();
    } else {
      (void)curl_multi_wakeup(multi.get());
    }
  }

  int idle_iterations = initial_action_changed || completion_progress ? 0 : 1;
  for (int iteration = 0; result == CURLM_OK && iteration < kMaxDriveIterations; ++iteration) {
    if (running_handles == 0 && next_action >= action_count) {
      break;
    }

    bool made_progress = mock.ServiceConnections();
    if (next_action < action_count) {
      made_progress =
          ApplyAction(plan.actions(static_cast<int>(next_action++)), multi.get(), &transfers, transfer_count) ||
          made_progress;
      ++stats.actions_consumed;
      // Consuming an ordered no-op is still harness progress: continue to the
      // next action instead of letting an idle transport hide its suffix.
      made_progress = true;
    }

    const int running_before = running_handles;
    if (socket_driver_installed) {
      const MultiSocketDriver::DriveResult drive = socket_driver.DriveReady(&running_handles);
      result = drive.code;
      made_progress = drive.made_progress || made_progress;
    } else {
      result = curl_multi_perform(multi.get(), &running_handles);
      made_progress = running_handles != running_before || made_progress;
    }
    made_progress = DrainCompletionMessages(multi.get(), &transfers, transfer_count, &stats) || made_progress;

    if (made_progress) {
      idle_iterations = 0;
    } else if (++idle_iterations >= kMaxIdleIterations) {
      break;
    }
  }

  (void)DrainCompletionMessages(multi.get(), &transfers, transfer_count, &stats);
  stats.opened_connections = mock.opened_connection_count();
  for (std::size_t index = 0; index < transfer_count; ++index) {
    TransferState& transfer = transfers[index];
    if (!transfer.easy) {
      continue;
    }
    (void)curl_easy_pause(transfer.easy.get(), CURLPAUSE_CONT);
    if (transfer.attached) {
      (void)curl_multi_remove_handle(multi.get(), transfer.easy.get());
      transfer.attached = false;
    }
  }

  // Destroy the multi while both its socket callback storage and mock peer are
  // live, then detach request-data pointers before cleaning each easy handle.
  multi.reset();
  for (std::size_t index = 0; index < transfer_count; ++index) {
    transfers[index].request_data.reset();
    transfers[index].easy.reset();
    transfers[index].connect_to.reset();
  }
  return stats;
}

}  // namespace proto_fuzzer
