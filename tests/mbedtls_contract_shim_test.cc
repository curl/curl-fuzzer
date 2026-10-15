/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <mbedtls/ssl.h>

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <string>

#include "test_assertions.h"

extern int mbedtls_test_handshake_result;
extern int mbedtls_test_read_result;
extern int mbedtls_test_write_result;
extern int mbedtls_test_close_result;
extern int mbedtls_test_reset_result;

namespace {

using test_support::Expect;

void ResetResults() {
  mbedtls_test_handshake_result = 0;
  mbedtls_test_read_result = MBEDTLS_ERR_SSL_WANT_READ;
  mbedtls_test_write_result = 1;
  mbedtls_test_close_result = 0;
  mbedtls_test_reset_result = 0;
}

void TestExactWriteRetry() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  const std::array<unsigned char, 4> data{{1, 2, 3, 4}};
  mbedtls_test_write_result = MBEDTLS_ERR_SSL_WANT_WRITE;
  Expect(mbedtls_ssl_write(&ssl, data.data(), data.size()) ==
             MBEDTLS_ERR_SSL_WANT_WRITE,
         "fake write did not block");
  mbedtls_test_write_result = static_cast<int>(data.size());
  Expect(mbedtls_ssl_write(&ssl, data.data(), data.size()) ==
             static_cast<int>(data.size()),
         "exact Mbed TLS retry failed");
  mbedtls_ssl_free(&ssl);
}

void TestFatalStateClearsOnReset() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  mbedtls_test_handshake_result = MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE;
  (void)mbedtls_ssl_handshake(&ssl);
  Expect(mbedtls_ssl_session_reset(&ssl) == 0, "fake session reset failed");
  mbedtls_test_handshake_result = 0;
  Expect(mbedtls_ssl_handshake(&ssl) == 0,
         "successful reset retained fatal state");
  mbedtls_ssl_free(&ssl);
}

void TestFatalStateClearsOnFreeAndAddressReuse() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  mbedtls_test_read_result = 0;
  unsigned char byte = 0;
  (void)mbedtls_ssl_read(&ssl, &byte, sizeof(byte));
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_init(&ssl);
  mbedtls_test_handshake_result = 0;
  Expect(mbedtls_ssl_handshake(&ssl) == 0,
         "reinitialized address retained fatal state");
  mbedtls_ssl_free(&ssl);
}

void TestNewSessionTicketAllowsReadAndWriteRetry() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  std::array<unsigned char, 2> data{{1, 2}};

  mbedtls_test_read_result = MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
  Expect(mbedtls_ssl_read(&ssl, data.data(), data.size()) ==
             MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET,
         "fake read did not report a new session ticket");
  mbedtls_test_read_result = MBEDTLS_ERR_SSL_WANT_READ;
  Expect(mbedtls_ssl_read(&ssl, data.data(), data.size()) ==
             MBEDTLS_ERR_SSL_WANT_READ,
         "new session ticket poisoned the read path");

  mbedtls_test_write_result = MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
  Expect(mbedtls_ssl_write(&ssl, data.data(), data.size()) ==
             MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET,
         "fake write did not report a new session ticket");
  mbedtls_test_write_result = static_cast<int>(data.size());
  Expect(mbedtls_ssl_write(&ssl, data.data(), data.size()) ==
             static_cast<int>(data.size()),
         "new session ticket poisoned the write retry");
  mbedtls_ssl_free(&ssl);
}

void TestPeerCloseAllowsCloseNotify() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  unsigned char byte = 0;
  mbedtls_test_read_result = MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  Expect(mbedtls_ssl_read(&ssl, &byte, sizeof(byte)) ==
             MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY,
         "fake read did not report the peer close-notify");
  mbedtls_test_close_result = MBEDTLS_ERR_SSL_WANT_WRITE;
  Expect(mbedtls_ssl_close_notify(&ssl) == MBEDTLS_ERR_SSL_WANT_WRITE,
         "peer close-notify prevented a blocked reciprocal close-notify");
  mbedtls_test_close_result = 0;
  Expect(mbedtls_ssl_close_notify(&ssl) == 0,
         "peer close-notify prevented the reciprocal close-notify");
  mbedtls_ssl_free(&ssl);
}

void TestPeerCloseStateClearsOnReset() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  unsigned char byte = 0;
  mbedtls_test_read_result = MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  (void)mbedtls_ssl_read(&ssl, &byte, sizeof(byte));
  Expect(mbedtls_ssl_session_reset(&ssl) == 0, "fake session reset failed");
  mbedtls_test_read_result = MBEDTLS_ERR_SSL_WANT_READ;
  Expect(mbedtls_ssl_read(&ssl, &byte, sizeof(byte)) ==
             MBEDTLS_ERR_SSL_WANT_READ,
         "successful reset retained peer-close state");
  mbedtls_ssl_free(&ssl);
}

void TestPeerCloseStateClearsOnFreeAndAddressReuse() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  unsigned char byte = 0;
  mbedtls_test_read_result = MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  (void)mbedtls_ssl_read(&ssl, &byte, sizeof(byte));
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_init(&ssl);
  mbedtls_test_write_result = 1;
  Expect(mbedtls_ssl_write(&ssl, &byte, sizeof(byte)) == 1,
         "reinitialized address retained peer-close state");
  mbedtls_ssl_free(&ssl);
}

void ViolateRetryPointer() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  const std::array<unsigned char, 2> first{{1, 2}};
  const std::array<unsigned char, 2> second{{1, 2}};
  mbedtls_test_write_result = MBEDTLS_ERR_SSL_WANT_READ;
  (void)mbedtls_ssl_write(&ssl, first.data(), first.size());
  (void)mbedtls_ssl_write(&ssl, second.data(), second.size());
}

void ViolateRetryLength() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  const std::array<unsigned char, 3> data{{1, 2, 3}};
  mbedtls_test_write_result = MBEDTLS_ERR_SSL_WANT_WRITE;
  (void)mbedtls_ssl_write(&ssl, data.data(), data.size());
  (void)mbedtls_ssl_write(&ssl, data.data(), data.size() - 1);
}

void ViolateAfterFatalHandshake() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  mbedtls_test_handshake_result = MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE;
  (void)mbedtls_ssl_handshake(&ssl);
  unsigned char byte = 0;
  (void)mbedtls_ssl_read(&ssl, &byte, sizeof(byte));
}

void ViolateReadAfterPeerClose() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  unsigned char byte = 0;
  mbedtls_test_read_result = MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  (void)mbedtls_ssl_read(&ssl, &byte, sizeof(byte));
  (void)mbedtls_ssl_close_notify(&ssl);
  (void)mbedtls_ssl_read(&ssl, &byte, sizeof(byte));
}

void ViolateWriteAfterPeerClose() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  unsigned char byte = 0;
  mbedtls_test_read_result = MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  (void)mbedtls_ssl_read(&ssl, &byte, sizeof(byte));
  (void)mbedtls_ssl_write(&ssl, &byte, sizeof(byte));
}

void ViolateCloseAfterFatalRead() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  mbedtls_test_read_result = 0;
  unsigned char byte = 0;
  (void)mbedtls_ssl_read(&ssl, &byte, sizeof(byte));
  (void)mbedtls_ssl_close_notify(&ssl);
}

void ViolateAfterFailedReset() {
  ResetResults();
  mbedtls_ssl_context ssl{};
  mbedtls_ssl_init(&ssl);
  mbedtls_test_handshake_result = MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE;
  (void)mbedtls_ssl_handshake(&ssl);
  mbedtls_test_reset_result = MBEDTLS_ERR_SSL_ALLOC_FAILED;
  (void)mbedtls_ssl_session_reset(&ssl);
  (void)mbedtls_ssl_handshake(&ssl);
}

using Violation = void (*)();

void ExpectViolation(Violation violate, const char *first, const char *second) {
  int diagnostic_pipe[2];
  Expect(pipe(diagnostic_pipe) == 0, "could not create diagnostic pipe");
  std::fflush(nullptr);
  const pid_t child = fork();
  Expect(child >= 0, "could not fork Mbed TLS contract test");
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
  Expect(waited == child, "could not wait for Mbed TLS contract child");
  Expect(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
         "Mbed TLS contract violation did not abort");
  Expect(diagnostic.find("Mbed TLS contract assertion failed") !=
             std::string::npos,
         "diagnostic omitted Mbed TLS assertion context");
  Expect(diagnostic.find(first) != std::string::npos,
         "diagnostic omitted first expected detail");
  Expect(diagnostic.find(second) != std::string::npos,
         "diagnostic omitted second expected detail");
}

} // namespace

int main() {
  TestExactWriteRetry();
  TestFatalStateClearsOnReset();
  TestFatalStateClearsOnFreeAndAddressReuse();
  TestNewSessionTicketAllowsReadAndWriteRetry();
  TestPeerCloseAllowsCloseNotify();
  TestPeerCloseStateClearsOnReset();
  TestPeerCloseStateClearsOnFreeAndAddressReuse();
  ExpectViolation(ViolateRetryPointer, "mbedtls_ssl_write", "pointer changed");
  ExpectViolation(ViolateRetryLength, "mbedtls_ssl_write", "length changed");
  ExpectViolation(ViolateAfterFatalHandshake, "mbedtls_ssl_handshake",
                  "mbedtls_ssl_read");
  ExpectViolation(ViolateReadAfterPeerClose,
                  "MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY", "mbedtls_ssl_read");
  ExpectViolation(ViolateWriteAfterPeerClose, "mbedtls_ssl_read",
                  "mbedtls_ssl_write");
  ExpectViolation(ViolateCloseAfterFatalRead, "mbedtls_ssl_read",
                  "mbedtls_ssl_close_notify");
  ExpectViolation(ViolateAfterFailedReset, "mbedtls_ssl_handshake",
                  "mbedtls_ssl_session_reset or mbedtls_ssl_free");
  return 0;
}
