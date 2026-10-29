/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <curl/curl.h>

#include <cstddef>

#include "proto_fuzzer/multi_socket_driver.h"
#include "tests/test_assertions.h"

extern "C" int TestNotifySocket(curl_socket_t socket, int what);
extern "C" std::size_t TestSocketAssignmentCount();

namespace {

using test_support::Expect;

void TestWatchExhaustion() {
  proto_fuzzer::MultiSocketDriver driver;
  Expect(!driver.watch_exhausted(), "fresh driver reports watch exhaustion");
  char multi_token = 0;
  Expect(driver.Install(reinterpret_cast<CURLM *>(&multi_token)),
         "socket driver callback installation failed");

  for (curl_socket_t socket = 1; socket <= 16; ++socket) {
    Expect(TestNotifySocket(socket, CURL_POLL_IN) == 0,
           "watch table rejected a descriptor within capacity");
  }
  Expect(!driver.watch_exhausted(), "full table reported premature exhaustion");
  Expect(TestSocketAssignmentCount() == 16, "not every accepted watch was associated");
  Expect(TestNotifySocket(1, CURL_POLL_OUT) == 0,
         "interest update failed when the watch table was full");
  Expect(!driver.watch_exhausted(), "existing watch update exhausted the table");

  Expect(TestNotifySocket(17, CURL_POLL_IN) == -1,
         "exhaustion did not report a socket-callback error");
  Expect(driver.watch_exhausted(), "exhaustion status was not retained");
  Expect(TestSocketAssignmentCount() == 16, "rejected descriptor was associated anyway");

  Expect(TestNotifySocket(1, CURL_POLL_REMOVE) == 0,
         "watch removal failed after exhaustion");
  Expect(TestNotifySocket(17, CURL_POLL_INOUT) == 0,
         "released watch slot could not be reused");
  Expect(driver.watch_exhausted(), "slot reuse cleared the exhaustion status");
  Expect(TestSocketAssignmentCount() == 18, "slot removal or reuse lost an association");

  proto_fuzzer::MultiSocketDriver next_driver;
  Expect(!next_driver.watch_exhausted(), "exhaustion leaked to another drive");
}

} // namespace

int main() {
  TestWatchExhaustion();
  return 0;
}
