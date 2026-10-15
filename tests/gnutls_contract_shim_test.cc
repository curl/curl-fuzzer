/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <gnutls/gnutls.h>

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <string>

#include "test_assertions.h"

extern int gnutls_test_handshake_result;
extern ssize_t gnutls_test_send_result;
extern ssize_t gnutls_test_early_send_result;
extern ssize_t gnutls_test_recv_result;
extern int gnutls_test_bye_result;

namespace {

using test_support::Expect;

gnutls_session_t NewSession() {
  gnutls_session_t session = nullptr;
  Expect(gnutls_init(&session, GNUTLS_CLIENT) == GNUTLS_E_SUCCESS,
         "fake gnutls_init failed");
  return session;
}

void ResetResults() {
  gnutls_test_handshake_result = GNUTLS_E_SUCCESS;
  gnutls_test_send_result = 1;
  gnutls_test_early_send_result = 1;
  gnutls_test_recv_result = GNUTLS_E_AGAIN;
  gnutls_test_bye_result = GNUTLS_E_SUCCESS;
}

void TestExactSendRetryAndNullFlush() {
  ResetResults();
  gnutls_session_t session = NewSession();
  const std::array<unsigned char, 4> data{{1, 2, 3, 4}};

  gnutls_test_send_result = GNUTLS_E_AGAIN;
  Expect(gnutls_record_send(session, data.data(), data.size()) ==
             GNUTLS_E_AGAIN,
         "fake send did not block");
  gnutls_test_send_result = GNUTLS_E_INTERRUPTED;
  Expect(gnutls_record_send(session, nullptr, 0) == GNUTLS_E_INTERRUPTED,
         "NULL,0 did not flush the queued send");
  gnutls_test_send_result = static_cast<ssize_t>(data.size());
  Expect(gnutls_record_send(session, data.data(), data.size()) ==
             static_cast<ssize_t>(data.size()),
         "exact send retry failed");
  gnutls_deinit(session);
}

void TestEarlyDataRetry() {
  ResetResults();
  gnutls_session_t session = NewSession();
  const std::array<unsigned char, 3> data{{5, 6, 7}};
  gnutls_test_early_send_result = GNUTLS_E_AGAIN;
  (void)gnutls_record_send_early_data(session, data.data(), data.size());
  gnutls_test_early_send_result = static_cast<ssize_t>(data.size());
  Expect(gnutls_record_send_early_data(session, data.data(), data.size()) ==
             static_cast<ssize_t>(data.size()),
         "early-data retry failed");
  gnutls_deinit(session);
}

void TestFatalStateClearsOnDeinitAndAddressReuse() {
  ResetResults();
  gnutls_session_t session = NewSession();
  gnutls_test_handshake_result = GNUTLS_E_FATAL_ALERT_RECEIVED;
  Expect(gnutls_handshake(session) == GNUTLS_E_FATAL_ALERT_RECEIVED,
         "fake handshake did not fail fatally");
  gnutls_deinit(session);

  gnutls_session_t replacement = NewSession();
  Expect(replacement == session, "fake backend did not reuse its address");
  gnutls_test_handshake_result = GNUTLS_E_SUCCESS;
  Expect(gnutls_handshake(replacement) == GNUTLS_E_SUCCESS,
         "reused session retained fatal state");
  gnutls_deinit(replacement);
}

void TestByeRetryAndWriteShutdownAllowsReceive() {
  ResetResults();
  gnutls_session_t session = NewSession();

  gnutls_test_bye_result = GNUTLS_E_AGAIN;
  Expect(gnutls_bye(session, GNUTLS_SHUT_WR) == GNUTLS_E_AGAIN,
         "fake bye did not return GNUTLS_E_AGAIN");
  gnutls_test_bye_result = GNUTLS_E_INTERRUPTED;
  Expect(gnutls_bye(session, GNUTLS_SHUT_WR) == GNUTLS_E_INTERRUPTED,
         "fake bye did not return GNUTLS_E_INTERRUPTED");
  gnutls_test_bye_result = GNUTLS_E_SUCCESS;
  Expect(gnutls_bye(session, GNUTLS_SHUT_WR) == GNUTLS_E_SUCCESS,
         "fake write shutdown did not succeed");

  char byte = 0;
  gnutls_test_recv_result = 1;
  Expect(gnutls_record_recv(session, &byte, sizeof(byte)) == 1,
         "GNUTLS_SHUT_WR incorrectly prohibited receiving");
  gnutls_deinit(session);
}

void TestByeStateClearsOnDeinitAndAddressReuse() {
  ResetResults();
  gnutls_session_t session = NewSession();
  Expect(gnutls_bye(session, GNUTLS_SHUT_RDWR) == GNUTLS_E_SUCCESS,
         "fake full shutdown did not succeed");
  gnutls_deinit(session);

  gnutls_session_t replacement = NewSession();
  Expect(replacement == session, "fake backend did not reuse its address");
  const char byte = 'x';
  gnutls_test_send_result = 1;
  Expect(gnutls_record_send(replacement, &byte, sizeof(byte)) == 1,
         "reused session retained shutdown state");
  gnutls_deinit(replacement);
}

void ViolateRetryPointer() {
  ResetResults();
  gnutls_session_t session = NewSession();
  const std::array<unsigned char, 2> first{{1, 2}};
  const std::array<unsigned char, 2> second{{1, 2}};
  gnutls_test_send_result = GNUTLS_E_AGAIN;
  (void)gnutls_record_send(session, first.data(), first.size());
  (void)gnutls_record_send(session, second.data(), second.size());
}

void ViolateRetrySize() {
  ResetResults();
  gnutls_session_t session = NewSession();
  const std::array<unsigned char, 3> data{{1, 2, 3}};
  gnutls_test_send_result = GNUTLS_E_AGAIN;
  (void)gnutls_record_send(session, data.data(), data.size());
  (void)gnutls_record_send(session, data.data(), data.size() - 1);
}

void ViolateRetryApi() {
  ResetResults();
  gnutls_session_t session = NewSession();
  const std::array<unsigned char, 2> data{{1, 2}};
  gnutls_test_send_result = GNUTLS_E_AGAIN;
  (void)gnutls_record_send(session, data.data(), data.size());
  (void)gnutls_record_send_early_data(session, data.data(), data.size());
}

void ViolateAfterFatalHandshake() {
  ResetResults();
  gnutls_session_t session = NewSession();
  gnutls_test_handshake_result = GNUTLS_E_FATAL_ALERT_RECEIVED;
  (void)gnutls_handshake(session);
  char byte = 0;
  (void)gnutls_record_recv(session, &byte, sizeof(byte));
}

void ViolateAfterFatalRecv() {
  ResetResults();
  gnutls_session_t session = NewSession();
  gnutls_test_recv_result = GNUTLS_E_DECRYPTION_FAILED;
  char byte = 0;
  (void)gnutls_record_recv(session, &byte, sizeof(byte));
  (void)gnutls_bye(session, GNUTLS_SHUT_RDWR);
}

void ViolateAfterFatalBye() {
  ResetResults();
  gnutls_session_t session = NewSession();
  gnutls_test_bye_result = GNUTLS_E_FATAL_ALERT_RECEIVED;
  (void)gnutls_bye(session, GNUTLS_SHUT_RDWR);
  char byte = 0;
  (void)gnutls_record_recv(session, &byte, sizeof(byte));
}

void ViolateSendAfterWriteShutdown() {
  ResetResults();
  gnutls_session_t session = NewSession();
  (void)gnutls_bye(session, GNUTLS_SHUT_WR);
  const char byte = 'x';
  (void)gnutls_record_send(session, &byte, sizeof(byte));
}

void ViolateReceiveAfterFullShutdown() {
  ResetResults();
  gnutls_session_t session = NewSession();
  (void)gnutls_bye(session, GNUTLS_SHUT_RDWR);
  char byte = 0;
  (void)gnutls_record_recv(session, &byte, sizeof(byte));
}

using Violation = void (*)();

void ExpectViolation(Violation violate, const char *first, const char *second) {
  int diagnostic_pipe[2];
  Expect(pipe(diagnostic_pipe) == 0, "could not create diagnostic pipe");
  std::fflush(nullptr);

  const pid_t child = fork();
  Expect(child >= 0, "could not fork GnuTLS contract test");
  if (child == 0) {
    close(diagnostic_pipe[0]);
    if (dup2(diagnostic_pipe[1], STDERR_FILENO) < 0) {
      _exit(90);
    }
    close(diagnostic_pipe[1]);
    violate();
    _exit(91);
  }

  close(diagnostic_pipe[1]);
  std::string diagnostic;
  std::array<char, 512> buffer{};
  for (;;) {
    const ssize_t length =
        read(diagnostic_pipe[0], buffer.data(), buffer.size());
    if (length > 0) {
      diagnostic.append(buffer.data(), static_cast<std::size_t>(length));
      continue;
    }
    if (length < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  close(diagnostic_pipe[0]);

  int status = 0;
  pid_t waited = 0;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  Expect(waited == child, "could not wait for GnuTLS contract child");
  Expect(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
         "GnuTLS contract violation did not abort");
  Expect(diagnostic.find("GnuTLS contract assertion failed") !=
             std::string::npos,
         "diagnostic omitted GnuTLS assertion context");
  Expect(diagnostic.find(first) != std::string::npos,
         "diagnostic omitted first expected detail");
  Expect(diagnostic.find(second) != std::string::npos,
         "diagnostic omitted second expected detail");
}

} // namespace

int main() {
  TestExactSendRetryAndNullFlush();
  TestEarlyDataRetry();
  TestFatalStateClearsOnDeinitAndAddressReuse();
  TestByeRetryAndWriteShutdownAllowsReceive();
  TestByeStateClearsOnDeinitAndAddressReuse();
  ExpectViolation(ViolateRetryPointer, "gnutls_record_send", "pointer changed");
  ExpectViolation(ViolateRetrySize, "gnutls_record_send", "size changed");
  ExpectViolation(ViolateRetryApi, "gnutls_record_send_early_data", "same API");
  ExpectViolation(ViolateAfterFatalHandshake, "gnutls_handshake",
                  "gnutls_record_recv");
  ExpectViolation(ViolateAfterFatalRecv, "gnutls_record_recv", "gnutls_bye");
  ExpectViolation(ViolateAfterFatalBye, "gnutls_bye", "gnutls_record_recv");
  ExpectViolation(ViolateSendAfterWriteShutdown, "GNUTLS_SHUT_WR", "sends");
  ExpectViolation(ViolateReceiveAfterFullShutdown, "GNUTLS_SHUT_RDWR",
                  "receives");
  return 0;
}
