/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/multi_transfer_runner.h"

#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string>

#include "proto_fuzzer/scenario_limits.h"

namespace {

using curl::fuzzer::proto::Scenario;

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

void AddCompleteResponse(curl::fuzzer::proto::Connection *connection,
                         char body) {
  connection->set_initial_response(
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n" +
      std::string(1, body));
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
      proto_fuzzer::MultiTransferRunner().Run(scenario);
  Expect(stats.configured_handles == 3 && stats.added_handles == 3,
         "multi runner did not attach every configured easy handle");
  Expect(stats.completion_messages == 3,
         "multi runner did not consume every concurrent completion");
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
      proto_fuzzer::MultiTransferRunner().Run(scenario);
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
      proto_fuzzer::MultiTransferRunner().Run(scenario);
  Expect(stats.configured_handles ==
             proto_fuzzer::scenario_limits::kMaxMultiTransfers,
         "multi runner did not enforce its runtime handle cap");
  Expect(stats.actions_consumed ==
             proto_fuzzer::scenario_limits::kMaxMultiActions,
         "multi runner did not consume exactly its bounded action prefix");
}

} // namespace

int main() {
  TestCompletesConcurrentHandles();
  TestQueuesAndReusesOneConnection();
  TestConsumesBoundedActions();
  return 0;
}
