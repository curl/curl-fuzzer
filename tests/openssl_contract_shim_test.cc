/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <string>
#include <thread>

#include "proto_fuzzer/tls_test_credentials.h"
#include "test_assertions.h"

namespace {

using test_support::Expect;

struct ClientConnection {
  SSL_CTX *context = nullptr;
  SSL *ssl = nullptr;
  BIO *input = nullptr;

  ClientConnection() {
    context = SSL_CTX_new(TLS_client_method());
    Expect(context != nullptr, "could not allocate OpenSSL context");
    ssl = SSL_new(context);
    Expect(ssl != nullptr, "could not allocate OpenSSL connection");

    input = BIO_new(BIO_s_mem());
    BIO *output = BIO_new(BIO_s_mem());
    Expect(input != nullptr && output != nullptr,
           "could not allocate OpenSSL memory BIOs");
    BIO_set_mem_eof_return(input, -1);
    SSL_set_bio(ssl, input, output);
    SSL_set_connect_state(ssl);
  }

  ~ClientConnection() {
    SSL_free(ssl);
    SSL_CTX_free(context);
  }

  void Free() {
    SSL_free(ssl);
    ssl = nullptr;
    input = nullptr;
  }

  ClientConnection(const ClientConnection &) = delete;
  ClientConnection &operator=(const ClientConnection &) = delete;
};

bool AdvanceHandshake(SSL *ssl) {
  const int result = SSL_do_handshake(ssl);
  if (result == 1) {
    return true;
  }
  const int error = SSL_get_error(ssl, result);
  Expect(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE,
         "in-memory TLS handshake failed");
  return false;
}

struct ConnectedPair {
  SSL_CTX *client_context = nullptr;
  SSL_CTX *server_context = nullptr;
  SSL *client = nullptr;
  SSL *server = nullptr;

  ConnectedPair() {
    client_context = SSL_CTX_new(TLS_client_method());
    server_context = SSL_CTX_new(TLS_server_method());
    Expect(client_context != nullptr && server_context != nullptr,
           "could not allocate OpenSSL handshake contexts");

    BIO *certificate_bio = BIO_new_mem_buf(
        proto_fuzzer::tls_test_credentials::kCertificatePem, -1);
    BIO *key_bio =
        BIO_new_mem_buf(proto_fuzzer::tls_test_credentials::kPrivateKeyPem, -1);
    Expect(certificate_bio != nullptr && key_bio != nullptr,
           "could not allocate credential BIOs");
    X509 *certificate =
        PEM_read_bio_X509(certificate_bio, nullptr, nullptr, nullptr);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
    Expect(certificate != nullptr && key != nullptr,
           "could not parse test credentials");
    Expect(SSL_CTX_use_certificate(server_context, certificate) == 1 &&
               SSL_CTX_use_PrivateKey(server_context, key) == 1 &&
               SSL_CTX_check_private_key(server_context) == 1,
           "could not configure server credentials");
    X509_free(certificate);
    EVP_PKEY_free(key);
    BIO_free(certificate_bio);
    BIO_free(key_bio);

    client = SSL_new(client_context);
    server = SSL_new(server_context);
    Expect(client != nullptr && server != nullptr,
           "could not allocate handshake connections");

    BIO *client_bio = nullptr;
    BIO *server_bio = nullptr;
    Expect(BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) == 1,
           "could not allocate OpenSSL BIO pair");
    SSL_set_bio(client, client_bio, client_bio);
    SSL_set_bio(server, server_bio, server_bio);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    bool client_done = false;
    bool server_done = false;
    for (std::size_t attempt = 0;
         attempt < 100 && (!client_done || !server_done); ++attempt) {
      if (!client_done) {
        client_done = AdvanceHandshake(client);
      }
      if (!server_done) {
        server_done = AdvanceHandshake(server);
      }
    }
    Expect(client_done && server_done,
           "in-memory TLS handshake did not complete");
  }

  ~ConnectedPair() {
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_context);
    SSL_CTX_free(server_context);
  }

  ConnectedPair(const ConnectedPair &) = delete;
  ConnectedPair &operator=(const ConnectedPair &) = delete;
};

void ExpectWantRead(ClientConnection &connection) {
  const int result = SSL_do_handshake(connection.ssl);
  Expect(result < 0, "empty memory BIO unexpectedly completed a handshake");
  Expect(SSL_get_error(connection.ssl, result) == SSL_ERROR_WANT_READ,
         "empty memory BIO did not produce SSL_ERROR_WANT_READ");
}

int ReadFatalAlert(ClientConnection &connection) {
  ExpectWantRead(connection);

  // A complete fatal handshake_failure alert is deterministic and requires no
  // certificate setup. OpenSSL classifies the next handshake result as
  // SSL_ERROR_SSL, which terminates this connection.
  constexpr std::array<unsigned char, 7> fatal_alert{0x15, 0x03, 0x03, 0x00,
                                                     0x02, 0x02, 0x28};
  Expect(BIO_write(connection.input, fatal_alert.data(), fatal_alert.size()) ==
             static_cast<int>(fatal_alert.size()),
         "could not feed fatal TLS alert");

  char byte = 0;
  const int result = SSL_read(connection.ssl, &byte, sizeof(byte));
  Expect(result < 0, "fatal TLS alert unexpectedly produced application data");
  return result;
}

void PoisonWithFatalAlert(ClientConnection &connection) {
  const int result = ReadFatalAlert(connection);
  Expect(SSL_get_error(connection.ssl, result) == SSL_ERROR_SSL,
         "fatal TLS alert did not produce SSL_ERROR_SSL");
}

void TestRetryableErrorDoesNotPoison() {
  ClientConnection connection;
  ExpectWantRead(connection);
  ExpectWantRead(connection);
}

int BeginBlockedWrite(ClientConnection &connection, const void *buffer,
                      int length) {
  const int result = SSL_write(connection.ssl, buffer, length);
  Expect(result <= 0, "empty memory BIO unexpectedly completed SSL_write");
  const int error = SSL_get_error(connection.ssl, result);
  Expect(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE,
         "SSL_write did not produce a retryable error");
  return error;
}

int BeginBlockedWriteEx(ClientConnection &connection, const void *buffer,
                        std::size_t length) {
  std::size_t written = 0;
  const int result = SSL_write_ex(connection.ssl, buffer, length, &written);
  Expect(result == 0, "empty memory BIO unexpectedly completed SSL_write_ex");
  const int error = SSL_get_error(connection.ssl, result);
  Expect(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE,
         "SSL_write_ex did not produce a retryable error");
  return error;
}

void TestExactWriteRetry() {
  ClientConnection connection;
  const std::array<unsigned char, 4> data{{1, 2, 3, 4}};
  (void)BeginBlockedWrite(connection, data.data(), data.size());
  (void)BeginBlockedWrite(connection, data.data(), data.size());
}

void TestExactWriteExRetry() {
  ClientConnection connection;
  const std::array<unsigned char, 4> data{{1, 2, 3, 4}};
  (void)BeginBlockedWriteEx(connection, data.data(), data.size());
  (void)BeginBlockedWriteEx(connection, data.data(), data.size());
}

void TestMovingWriteBufferWithSameContents() {
  ClientConnection connection;
  (void)SSL_set_mode(connection.ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  const std::array<unsigned char, 4> first{{1, 2, 3, 4}};
  const std::array<unsigned char, 4> second{{1, 2, 3, 4}};
  (void)BeginBlockedWrite(connection, first.data(), first.size());
  (void)BeginBlockedWrite(connection, second.data(), second.size());
}

void TestPositiveResultCanBeClassified() {
  ConnectedPair connections;
  const char byte = 'x';
  const int result = SSL_write(connections.client, &byte, sizeof(byte));
  Expect(result == 1, "in-memory SSL_write did not write one byte");
  Expect(SSL_get_error(connections.client, result) == SSL_ERROR_NONE,
         "positive SSL_write result did not classify as SSL_ERROR_NONE");
}

void TestShutdownZeroClassificationDoesNotPoison() {
  ConnectedPair connections;

  const int shutdown_result = SSL_shutdown(connections.client);
  Expect(shutdown_result == 0,
         "first in-memory SSL_shutdown did not remain in progress");

  // A zero shutdown result is not an error, but SSL_get_error can classify it
  // as fatal. The monitor must not poison the connection from that misleading
  // classification: OpenSSL still permits reads while awaiting the peer's
  // close_notify.
  const int shutdown_error = SSL_get_error(connections.client, shutdown_result);
  Expect(shutdown_error == SSL_ERROR_SSL || shutdown_error == SSL_ERROR_SYSCALL,
         "SSL_shutdown zero was not classified as a fatal-looking error");

  char byte = 0;
  const int read_result = SSL_read(connections.client, &byte, sizeof(byte));
  Expect(read_result < 0,
         "shutdown read unexpectedly produced application data");
  Expect(SSL_get_error(connections.client, read_result) == SSL_ERROR_WANT_READ,
         "shutdown read did not wait for the peer close_notify");
}

void TestFatalConnectionCanBeFreed() {
  ClientConnection connection;
  PoisonWithFatalAlert(connection);
  connection.Free();

  ClientConnection replacement;
  ExpectWantRead(replacement);
}

void TestFatalConnectionCanBeCleared() {
  ClientConnection connection;
  PoisonWithFatalAlert(connection);
  Expect(SSL_clear(connection.ssl) == 1,
         "could not clear fatally classified connection");
  ExpectWantRead(connection);
}

void ViolateWithWrite() {
  ClientConnection connection;
  PoisonWithFatalAlert(connection);
  const char byte = 0;
  (void)SSL_write(connection.ssl, &byte, sizeof(byte));
}

void ViolateWithShutdown() {
  ClientConnection connection;
  PoisonWithFatalAlert(connection);
  (void)SSL_shutdown(connection.ssl);
}

void ViolateAfterInterleavedClassification() {
  ClientConnection fatal;
  ClientConnection retryable;

  const int fatal_result = ReadFatalAlert(fatal);
  ExpectWantRead(retryable);
  Expect(SSL_get_error(fatal.ssl, fatal_result) == SSL_ERROR_SSL,
         "interleaved fatal TLS result lost its classification");

  const char byte = 0;
  (void)SSL_write(fatal.ssl, &byte, sizeof(byte));
}

void ViolateWithWrongGetErrorResult() {
  ClientConnection connection;
  const int result = SSL_do_handshake(connection.ssl);
  Expect(result < 0, "empty memory BIO unexpectedly completed a handshake");
  (void)SSL_get_error(connection.ssl, result - 1);
}

void ViolateWithWrongGetErrorConnection() {
  ClientConnection pending;
  ClientConnection unrelated;
  const int result = SSL_do_handshake(pending.ssl);
  Expect(result < 0, "empty memory BIO unexpectedly completed a handshake");
  (void)SSL_get_error(unrelated.ssl, result);
}

void TestInterveningCallOnOtherSslDoesNotInvalidate() {
  ClientConnection pending;
  const int result = SSL_do_handshake(pending.ssl);
  Expect(result < 0, "empty memory BIO unexpectedly completed a handshake");

  // Activity on a different SSL object does not supersede this SSL's saved
  // result.
  SSL_CTX *context = SSL_CTX_new(TLS_client_method());
  Expect(context != nullptr, "could not allocate intervening context");
  SSL *intervening = SSL_new(context);
  Expect(intervening != nullptr, "could not allocate intervening connection");
  Expect(SSL_get_error(pending.ssl, result) == SSL_ERROR_WANT_READ,
         "different SSL invalidated the pending classification");
  SSL_free(intervening);
  SSL_CTX_free(context);
}

void TestCrossObjectInterleavingCanBeClassified() {
  ClientConnection first;
  ClientConnection second;
  const int first_result = SSL_do_handshake(first.ssl);
  const int second_result = SSL_do_handshake(second.ssl);
  Expect(first_result < 0 && second_result < 0,
         "empty memory BIO unexpectedly completed a handshake");
  Expect(SSL_get_error(second.ssl, second_result) == SSL_ERROR_WANT_READ,
         "second interleaved result did not classify as WANT_READ");
  Expect(SSL_get_error(first.ssl, first_result) == SSL_ERROR_WANT_READ,
         "first interleaved result did not survive other-object activity");
}

void TestCrossThreadSequentialClassification() {
  ClientConnection connection;
  int result = 0;
  std::thread io_thread([&] { result = SSL_do_handshake(connection.ssl); });
  io_thread.join();
  Expect(result < 0, "empty memory BIO unexpectedly completed a handshake");

  int error = SSL_ERROR_NONE;
  std::thread classification_thread(
      [&] { error = SSL_get_error(connection.ssl, result); });
  classification_thread.join();
  Expect(error == SSL_ERROR_WANT_READ,
         "result could not be classified from a different thread");
}

void ViolateWithStaleSameSslResult() {
  ConnectedPair connections;
  const char sent = 'x';
  const int old_result = SSL_write(connections.client, &sent, sizeof(sent));
  Expect(old_result == 1, "in-memory SSL_write did not write one byte");

  char received = 0;
  const int latest_result =
      SSL_read(connections.client, &received, sizeof(received));
  Expect(latest_result < 0,
         "in-memory SSL_read unexpectedly produced application data");
  (void)SSL_get_error(connections.client, old_result);
}

void BeginWantWrite(ConnectedPair &connections,
                    const std::array<unsigned char, 16384> &data) {
  for (std::size_t attempt = 0; attempt < 100; ++attempt) {
    const int result = SSL_write(connections.client, data.data(), data.size());
    if (result > 0) {
      Expect(result == static_cast<int>(data.size()),
             "in-memory SSL_write unexpectedly completed partially");
      continue;
    }
    Expect(SSL_get_error(connections.client, result) == SSL_ERROR_WANT_WRITE,
           "saturated memory BIO did not produce SSL_ERROR_WANT_WRITE");
    return;
  }
  Expect(false, "could not saturate the in-memory OpenSSL transport");
}

void TestReadAllowedDuringWantWrite() {
  ConnectedPair connections;
  const std::array<unsigned char, 16384> data{};
  BeginWantWrite(connections, data);

  char byte = 0;
  const int result = SSL_read(connections.client, &byte, sizeof(byte));
  Expect(result < 0, "read unexpectedly produced application data");
  Expect(SSL_get_error(connections.client, result) == SSL_ERROR_WANT_READ,
         "read during WANT_WRITE did not remain allowed");
}

void ViolateWantWriteWithShutdown() {
  ConnectedPair connections;
  const std::array<unsigned char, 16384> data{};
  BeginWantWrite(connections, data);
  (void)SSL_shutdown(connections.client);
}

void ViolateWantWriteWithPeek() {
  ConnectedPair connections;
  const std::array<unsigned char, 16384> data{};
  BeginWantWrite(connections, data);
  char byte = 0;
  (void)SSL_peek(connections.client, &byte, sizeof(byte));
}

void ViolateWriteRetryPointer() {
  ClientConnection connection;
  const std::array<unsigned char, 2> first{{1, 2}};
  const std::array<unsigned char, 2> second{{1, 2}};
  (void)BeginBlockedWrite(connection, first.data(), first.size());
  (void)SSL_write(connection.ssl, second.data(), second.size());
}

void ViolateWriteRetryLength() {
  ClientConnection connection;
  const std::array<unsigned char, 3> data{{1, 2, 3}};
  (void)BeginBlockedWrite(connection, data.data(), data.size());
  (void)SSL_write(connection.ssl, data.data(), data.size() - 1);
}

void ViolateWriteRetryContents() {
  ClientConnection connection;
  std::array<unsigned char, 3> data{{1, 2, 3}};
  (void)BeginBlockedWrite(connection, data.data(), data.size());
  data[1] ^= 0xff;
  (void)SSL_write(connection.ssl, data.data(), data.size());
}

void ViolateMovingWriteRetryContents() {
  ClientConnection connection;
  (void)SSL_set_mode(connection.ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  const std::array<unsigned char, 3> first{{1, 2, 3}};
  const std::array<unsigned char, 3> second{{1, 9, 3}};
  (void)BeginBlockedWrite(connection, first.data(), first.size());
  (void)SSL_write(connection.ssl, second.data(), second.size());
}

void ViolateWriteRetryApi() {
  ClientConnection connection;
  const std::array<unsigned char, 2> data{{1, 2}};
  (void)BeginBlockedWrite(connection, data.data(), data.size());
  std::size_t written = 0;
  (void)SSL_write_ex(connection.ssl, data.data(), data.size(), &written);
}

void ViolateWriteRetryWithEx2() {
  ClientConnection connection;
  const std::array<unsigned char, 2> data{{1, 2}};
  (void)BeginBlockedWrite(connection, data.data(), data.size());
  std::size_t written = 0;
  (void)SSL_write_ex2(connection.ssl, data.data(), data.size(), 0, &written);
}

void ViolateWriteRetryWithEarlyData() {
  ClientConnection connection;
  const std::array<unsigned char, 2> data{{1, 2}};
  (void)BeginBlockedWrite(connection, data.data(), data.size());
  std::size_t written = 0;
  (void)SSL_write_early_data(connection.ssl, data.data(), data.size(),
                             &written);
}

void ViolateWriteRetryWithSendfile() {
  ClientConnection connection;
  const std::array<unsigned char, 2> data{{1, 2}};
  (void)BeginBlockedWrite(connection, data.data(), data.size());
  (void)SSL_sendfile(connection.ssl, -1, 0, data.size(), 0);
}

void ViolateWriteExRetryLength() {
  ClientConnection connection;
  const std::array<unsigned char, 3> data{{1, 2, 3}};
  (void)BeginBlockedWriteEx(connection, data.data(), data.size());
  std::size_t written = 0;
  (void)SSL_write_ex(connection.ssl, data.data(), data.size() - 1, &written);
}

using Violation = void (*)();

std::string RunViolation(Violation violate) {
  int diagnostic_pipe[2];
  Expect(pipe(diagnostic_pipe) == 0, "could not create diagnostic pipe");
  std::fflush(nullptr);

  const pid_t child = fork();
  Expect(child >= 0, "could not fork OpenSSL contract test");
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
  Expect(waited == child, "could not wait for OpenSSL contract child");
  Expect(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
         "OpenSSL contract violation did not abort");
  Expect(diagnostic.find("OpenSSL contract assertion failed") !=
             std::string::npos,
         "contract diagnostic omitted the assertion context");
  return diagnostic;
}

void ExpectViolationAbortsWithDiagnostic(Violation violate,
                                         const char *attempted_api) {
  const std::string diagnostic = RunViolation(violate);
  Expect(diagnostic.find("SSL_read returned -1") != std::string::npos,
         "contract diagnostic omitted the fatal API and result");
  Expect(diagnostic.find("SSL_ERROR_SSL") != std::string::npos,
         "contract diagnostic omitted the fatal classification");
  const std::string expected_attempt = std::string(attempted_api) + " called";
  Expect(diagnostic.find(expected_attempt) != std::string::npos,
         "contract diagnostic omitted the attempted API");
}

void ExpectGetErrorViolation(Violation violate, const char *detail) {
  const std::string diagnostic = RunViolation(violate);
  Expect(diagnostic.find("SSL_get_error called") != std::string::npos,
         "ordering diagnostic omitted SSL_get_error");
  Expect(diagnostic.find(detail) != std::string::npos,
         "ordering diagnostic omitted expected predecessor detail");
}

void ExpectWriteRetryViolation(Violation violate, const char *detail) {
  const std::string diagnostic = RunViolation(violate);
  Expect(diagnostic.find("pending") != std::string::npos &&
             diagnostic.find("write retry") != std::string::npos,
         "retry diagnostic omitted pending write context");
  Expect(diagnostic.find(detail) != std::string::npos,
         "retry diagnostic omitted expected mismatch detail");
}

void TestIoAfterFatalAbortsWithDiagnostic() {
  ExpectViolationAbortsWithDiagnostic(ViolateWithWrite, "SSL_write");
}

void TestShutdownAfterFatalAbortsWithDiagnostic() {
  ExpectViolationAbortsWithDiagnostic(ViolateWithShutdown, "SSL_shutdown");
}

void TestInterleavedClassificationPoisonsOriginalConnection() {
  ExpectViolationAbortsWithDiagnostic(ViolateAfterInterleavedClassification,
                                      "SSL_write");
}

void TestGetErrorRequiresLatestSavedResult() {
  ExpectGetErrorViolation(ViolateWithWrongGetErrorResult,
                          "latest monitored I/O was SSL_do_handshake");
}

void TestGetErrorRequiresExactConnection() {
  ExpectGetErrorViolation(ViolateWithWrongGetErrorConnection,
                          "no saved monitored I/O result");
}

void TestLaterSameSslIoInvalidatesOlderResult() {
  ExpectGetErrorViolation(ViolateWithStaleSameSslResult,
                          "latest monitored I/O was SSL_read");
}

} // namespace

int main() {
  TestRetryableErrorDoesNotPoison();
  TestExactWriteRetry();
  TestExactWriteExRetry();
  TestMovingWriteBufferWithSameContents();
  TestPositiveResultCanBeClassified();
  TestShutdownZeroClassificationDoesNotPoison();
  TestInterveningCallOnOtherSslDoesNotInvalidate();
  TestCrossObjectInterleavingCanBeClassified();
  TestCrossThreadSequentialClassification();
  TestReadAllowedDuringWantWrite();
  TestFatalConnectionCanBeFreed();
  TestFatalConnectionCanBeCleared();
  TestIoAfterFatalAbortsWithDiagnostic();
  TestShutdownAfterFatalAbortsWithDiagnostic();
  TestInterleavedClassificationPoisonsOriginalConnection();
  TestGetErrorRequiresLatestSavedResult();
  TestGetErrorRequiresExactConnection();
  TestLaterSameSslIoInvalidatesOlderResult();
  ExpectWriteRetryViolation(ViolateWriteRetryPointer, "buffer pointer changed");
  ExpectWriteRetryViolation(ViolateWriteRetryLength, "length changed");
  ExpectWriteRetryViolation(ViolateWriteRetryContents,
                            "buffer contents changed");
  ExpectWriteRetryViolation(ViolateMovingWriteRetryContents,
                            "buffer contents changed");
  ExpectWriteRetryViolation(ViolateWriteRetryApi,
                            "same OpenSSL write function");
  ExpectWriteRetryViolation(ViolateWriteRetryWithEx2,
                            "same OpenSSL write function");
  ExpectWriteRetryViolation(ViolateWriteRetryWithEarlyData,
                            "same OpenSSL write function");
  ExpectWriteRetryViolation(ViolateWriteRetryWithSendfile,
                            "same OpenSSL write function");
  ExpectWriteRetryViolation(ViolateWriteExRetryLength, "length changed");
  ExpectWriteRetryViolation(ViolateWantWriteWithShutdown,
                            "SSL_ERROR_WANT_WRITE");
  ExpectWriteRetryViolation(ViolateWantWriteWithPeek, "SSL_ERROR_WANT_WRITE");
  return 0;
}
