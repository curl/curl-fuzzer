/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/multi_transfer_runner.h"

#include <curl/curl.h>

#include <cstddef>
#include <string>

#include "proto_fuzzer/scenario_limits.h"
#include "test_assertions.h"

namespace {

using curl::fuzzer::proto::Scenario;
using test_support::Expect;

void AddCompleteResponse(curl::fuzzer::proto::Connection *connection,
                         char body) {
  connection->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n" +
      std::string(1, body));
}

void AddBrotliExpansionResponse(curl::fuzzer::proto::Connection *connection) {
  // This malformed ten-byte stream expands past 13 MiB before Brotli reports
  // its format error. Keep it small so this test also protects the workload
  // bound that prevents compressed fuzz inputs from amplifying CPU work.
  constexpr char kCompressed[] = "\x08\x04\xe8\x0c\xd4\x44\x55\x30\x12\x03";
  connection->set_initial_response(
      std::string("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n"
                  "Connection: close\r\n\r\n") +
      std::string(kCompressed, sizeof(kCompressed) - 1));
}

void TestCompletesConcurrentHandles() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("multi.test/parallel");
  AddCompleteResponse(scenario.mutable_connection(), 'a');
  AddCompleteResponse(scenario.add_subsequent_connections(), 'b');
  AddCompleteResponse(scenario.add_subsequent_connections(), 'c');
  auto *plan = scenario.mutable_multi_plan();
  plan->set_transfer_count(3);
  plan->set_max_host_connections(3);
  plan->set_max_total_connections(3);

  const proto_fuzzer::MultiTransferRunStats stats =
      proto_fuzzer::RunMultiTransferScenario(scenario);
  Expect(stats.configured_handles == 3 && stats.added_handles == 3,
         "multi runner did not attach every configured easy handle");
  Expect(stats.completion_messages == 3,
         "multi runner did not consume every concurrent completion");
  Expect(stats.info_read_notifications > 0,
         "multi runner did not dispatch INFO_READ notifications");
  Expect(stats.easy_done_notifications > 0,
         "multi runner did not dispatch EASY_DONE notifications");
}

void TestNotificationTypeValidation() {
  CURLM *multi = curl_multi_init();
  Expect(multi != nullptr, "could not create multi handle");

  Expect(curl_multi_notify_enable(multi, CURLMNOTIFY_INFO_READ) == CURLM_OK,
         "valid notification enable failed");
  Expect(curl_multi_notify_disable(multi, CURLMNOTIFY_INFO_READ) == CURLM_OK,
         "valid notification disable failed");
  Expect(curl_multi_notify_enable(multi, CURLMNOTIFY_LAST) ==
             CURLM_UNKNOWN_OPTION,
         "invalid notification enable was accepted");
  Expect(curl_multi_notify_disable(multi, CURLMNOTIFY_LAST) ==
             CURLM_UNKNOWN_OPTION,
         "invalid notification disable was accepted");

  curl_multi_cleanup(multi);
}

void TestQueuesAndReusesOneConnection() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("multi.test/reuse");
  auto *connection = scenario.mutable_connection();
  connection->add_on_readable("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na");
  connection->add_on_readable("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb");
  connection->add_on_readable("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nc");
  auto *plan = scenario.mutable_multi_plan();
  plan->set_transfer_count(3);
  plan->set_max_host_connections(1);
  plan->set_max_total_connections(1);
  plan->set_connection_cache_size(1);
  plan->set_keep_connections_open(true);

  const proto_fuzzer::MultiTransferRunStats stats =
      proto_fuzzer::RunMultiTransferScenario(scenario);
  Expect(stats.completion_messages == 3,
         "queued transfers did not all complete on the reusable connection");
  Expect(stats.opened_connections == 1,
         "queued transfers opened another connection instead of reusing one");
}

void TestConsumesBoundedActions() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("multi.test/actions");
  AddCompleteResponse(scenario.mutable_connection(), 'a');
  auto *plan = scenario.mutable_multi_plan();
  plan->set_transfer_count(99);
  plan->set_drive_mode(curl::fuzzer::proto::MULTI_DRIVE_SOCKET);
  plan->add_actions()->set_kind(curl::fuzzer::proto::MULTI_ACTION_PAUSE_RECV);
  plan->add_actions()->set_kind(curl::fuzzer::proto::MULTI_ACTION_RESUME);
  plan->add_actions()->set_kind(curl::fuzzer::proto::MULTI_ACTION_REMOVE);
  plan->add_actions()->set_kind(curl::fuzzer::proto::MULTI_ACTION_READD);
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxMultiActions; ++index) {
    plan->add_actions()->set_kind(curl::fuzzer::proto::MULTI_ACTION_NONE);
  }

  const proto_fuzzer::MultiTransferRunStats stats =
      proto_fuzzer::RunMultiTransferScenario(scenario);
  Expect(stats.configured_handles ==
             proto_fuzzer::scenario_limits::kMaxMultiTransfers,
         "multi runner did not enforce its runtime handle cap");
  Expect(stats.actions_consumed ==
             proto_fuzzer::scenario_limits::kMaxMultiActions,
         "multi runner did not consume exactly its bounded action prefix");
}

void TestAppliesClosedStateProbeToEveryHandle() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("multi.test/state-probe");
  scenario.mutable_connection()->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
  scenario.mutable_connection()->add_on_readable("a");
  scenario.mutable_connection()->add_on_readable("b");
  auto *second = scenario.add_subsequent_connections();
  second->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
  second->add_on_readable("c");
  second->add_on_readable("d");
  auto *plan = scenario.mutable_multi_plan();
  plan->set_transfer_count(2);
  plan->set_max_host_connections(2);
  plan->set_max_total_connections(2);
  plan->set_state_probe_profile(
      curl::fuzzer::proto::MULTI_STATE_PROBE_PROGRESS_RATE_LIMIT);

  const proto_fuzzer::MultiTransferRunStats stats =
      proto_fuzzer::RunMultiTransferScenario(scenario);
  Expect(stats.added_handles == 2 && stats.state_probe_handles == 2,
         "multi runner did not apply the complete closed state probe");
}

void TestBoundsDecodedResponseWorkAfterInputOptions() {
  Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  scenario.set_host_path("multi.test/decoded-response-limit");
  auto *accept_encoding = scenario.add_options();
  accept_encoding->set_option_id(curl::fuzzer::proto::CURLOPT_ACCEPT_ENCODING);
  accept_encoding->set_string_value("");
  auto *maxfilesize = scenario.add_options();
  maxfilesize->set_option_id(curl::fuzzer::proto::CURLOPT_MAXFILESIZE_LARGE);
  maxfilesize->set_uint_value(64 * 1024 * 1024);
  AddBrotliExpansionResponse(scenario.mutable_connection());
  AddBrotliExpansionResponse(scenario.add_subsequent_connections());
  auto *plan = scenario.mutable_multi_plan();
  plan->set_transfer_count(2);
  plan->set_max_host_connections(2);
  plan->set_max_total_connections(2);

  const proto_fuzzer::MultiTransferRunStats stats =
      proto_fuzzer::RunMultiTransferScenario(scenario);
  Expect(stats.completion_messages == 2 &&
             stats.response_limit_completions == 2,
         "input options removed the multi runner decoded-response limit");
}

} // namespace

int main() {
  TestCompletesConcurrentHandles();
  TestNotificationTypeValidation();
  TestQueuesAndReusesOneConnection();
  TestConsumesBoundedActions();
  TestAppliesClosedStateProbeToEveryHandle();
  TestBoundsDecodedResponseWorkAfterInputOptions();
  return 0;
}
