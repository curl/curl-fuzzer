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
#include <cstdlib>
#include <iostream>
#include <string>

#include "proto_fuzzer/tls_test_credentials.h"

namespace {

void Expect(bool condition, const char *message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

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

void TestUnrelatedGetErrorDoesNotPoison() {
  ClientConnection pending;
  ClientConnection unrelated;

  const int result = SSL_do_handshake(pending.ssl);
  Expect(result < 0, "empty memory BIO unexpectedly completed a handshake");

  // OpenSSL 4 classifies this deliberately mismatched query as a fatal
  // syscall error. The wrapper must ignore that classification because the
  // preceding I/O result belongs to a different SSL object.
  Expect(SSL_get_error(unrelated.ssl, result) == SSL_ERROR_SYSCALL,
         "mismatched SSL_get_error probe was not classified as expected");
  ExpectWantRead(unrelated);
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

using Violation = void (*)();

void ExpectViolationAbortsWithDiagnostic(Violation violate,
                                         const char *attempted_api) {
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
         "I/O after fatal OpenSSL result did not abort");
  Expect(diagnostic.find("OpenSSL contract assertion failed") !=
             std::string::npos,
         "contract diagnostic omitted the assertion context");
  Expect(diagnostic.find("SSL_read returned -1") != std::string::npos,
         "contract diagnostic omitted the fatal API and result");
  Expect(diagnostic.find("SSL_ERROR_SSL") != std::string::npos,
         "contract diagnostic omitted the fatal classification");
  const std::string expected_attempt = std::string(attempted_api) + " called";
  Expect(diagnostic.find(expected_attempt) != std::string::npos,
         "contract diagnostic omitted the attempted API");
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

} // namespace

int main() {
  TestRetryableErrorDoesNotPoison();
  TestUnrelatedGetErrorDoesNotPoison();
  TestShutdownZeroClassificationDoesNotPoison();
  TestFatalConnectionCanBeFreed();
  TestFatalConnectionCanBeCleared();
  TestIoAfterFatalAbortsWithDiagnostic();
  TestShutdownAfterFatalAbortsWithDiagnostic();
  TestInterleavedClassificationPoisonsOriginalConnection();
  return 0;
}
