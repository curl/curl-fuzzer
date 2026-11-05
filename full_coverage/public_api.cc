/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "full_coverage/public_api.h"

#include <array>
#include <cstdarg>
#include <cstdio>

#include <unistd.h>

#include <curl/curl.h>
#include <curl/mprintf.h>

namespace full_coverage {
namespace {

/** Reuse a valid argument list across the public va_list formatting APIs. */
void ExerciseVariadicFormatting(FILE *stream, const char *format, ...)
{
  char buffer[4096];
  va_list args;
  va_start(args, format);
  va_list copy;
  va_copy(copy, args);
  curl_mvsnprintf(buffer, sizeof(buffer), format, copy);
  va_end(copy);
  va_copy(copy, args);
  curl_mvsnprintf(buffer, 1, format, copy);
  va_end(copy);
  va_copy(copy, args);
  curl_mvsprintf(buffer, format, copy);
  va_end(copy);
  va_copy(copy, args);
  curl_free(curl_mvaprintf(format, copy));
  va_end(copy);
  if(stream) {
    va_copy(copy, args);
    curl_mvfprintf(stream, format, copy);
    va_end(copy);
  }
  va_end(args);
}

/** Exercise the stdout va_list wrapper with an empty formatted result. */
void ExerciseVariadicStdout(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  curl_mvprintf(format, args);
  va_end(args);
}

/** Consume the in-memory serialization produced by the legacy form API. */
size_t DiscardFormData(void *, const char *, size_t length)
{
  return length;
}

/** Exercise public easy/header/share contracts that reject invalid state. */
void ExerciseEasyContractErrors()
{
  constexpr unsigned int kAllHeaderOrigins =
      CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX |
      CURLH_PSEUDO;
  char byte = 0;
  size_t transferred = 0;
  long response_code = 0;
  curl_header *header = nullptr;

  // Null handles are documented API errors. Supplying otherwise valid output
  // storage keeps these calls inside libcurl's guard paths without touching
  // the network or relying on allocation failure.
  (void)curl_easy_perform(nullptr);
  (void)curl_easy_getinfo(nullptr, CURLINFO_RESPONSE_CODE, &response_code);
  (void)curl_easy_setopt(nullptr, CURLOPT_URL, "https://api.test/");
  (void)curl_easy_pause(nullptr, CURLPAUSE_CONT);
  (void)curl_easy_send(nullptr, &byte, sizeof(byte), &transferred);
  (void)curl_easy_recv(nullptr, &byte, sizeof(byte), &transferred);
  (void)curl_easy_upkeep(nullptr);
  (void)curl_easy_ssls_import(nullptr, nullptr, nullptr, 0, nullptr, 0);
  (void)curl_easy_ssls_export(nullptr, nullptr, nullptr);
  (void)curl_easy_header(nullptr, "Content-Type", 0, kAllHeaderOrigins, -1,
                         &header);
  (void)curl_easy_nextheader(nullptr, kAllHeaderOrigins, -1, nullptr);
  (void)curl_easy_duphandle(nullptr);
  curl_easy_reset(nullptr);
  curl_easy_cleanup(nullptr);

  CURL *easy = curl_easy_init();
  if(!easy)
    return;

  // A fresh handle has no transfer connection, response headers, or TLS
  // sessions. Cover each public validation result without starting a transfer.
  (void)curl_easy_pause(easy, CURLPAUSE_ALL);
  (void)curl_easy_send(easy, &byte, sizeof(byte), nullptr);
  (void)curl_easy_send(easy, nullptr, sizeof(byte), &transferred);
  (void)curl_easy_send(easy, &byte, sizeof(byte), &transferred);
  (void)curl_easy_recv(easy, &byte, sizeof(byte), nullptr);
  (void)curl_easy_recv(easy, nullptr, sizeof(byte), &transferred);
  (void)curl_easy_recv(easy, &byte, sizeof(byte), &transferred);
  (void)curl_easy_ssls_import(easy, nullptr, nullptr, 0, nullptr, 0);
  (void)curl_easy_ssls_export(easy, nullptr, nullptr);

  (void)curl_easy_header(easy, nullptr, 0, kAllHeaderOrigins, -1, &header);
  (void)curl_easy_header(easy, "Content-Type", 0, kAllHeaderOrigins, -1,
                         nullptr);
  (void)curl_easy_header(easy, "Content-Type", 0, 0, -1, &header);
  (void)curl_easy_header(easy, "Content-Type", 0, 1U << 31, -1, &header);
  (void)curl_easy_header(easy, "Content-Type", 0, kAllHeaderOrigins, -2,
                         &header);
  (void)curl_easy_header(easy, "Content-Type", 0, kAllHeaderOrigins, -1,
                         &header);
  (void)curl_easy_nextheader(easy, kAllHeaderOrigins, 1, nullptr);
  (void)curl_easy_nextheader(easy, kAllHeaderOrigins, -1, nullptr);

  CURLSH *share = curl_share_init();
  if(share) {
    constexpr curl_lock_data kShareKinds[] = {
        CURL_LOCK_DATA_DNS, CURL_LOCK_DATA_COOKIE, CURL_LOCK_DATA_HSTS,
        CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_DATA_CONNECT,
        CURL_LOCK_DATA_PSL,
    };
    (void)curl_share_setopt(share, static_cast<CURLSHoption>(99), nullptr);
    (void)curl_share_setopt(share, CURLSHOPT_SHARE,
                            static_cast<curl_lock_data>(99));
    (void)curl_share_setopt(share, CURLSHOPT_UNSHARE,
                            static_cast<curl_lock_data>(99));
    for(curl_lock_data kind : kShareKinds)
      (void)curl_share_setopt(share, CURLSHOPT_SHARE, kind);
    for(curl_lock_data kind : kShareKinds)
      (void)curl_share_setopt(share, CURLSHOPT_UNSHARE, kind);

    if(curl_easy_setopt(easy, CURLOPT_SHARE, share) == CURLE_OK) {
      (void)curl_share_setopt(share, CURLSHOPT_USERDATA, nullptr);
      (void)curl_share_cleanup(share);
      (void)curl_easy_setopt(easy, CURLOPT_SHARE, nullptr);
    }
    (void)curl_share_cleanup(share);
  }

  curl_easy_cleanup(easy);
}

/** Keep deprecated, still-supported form helpers reachable in profiling. */
void ExerciseLegacyForms()
{
  curl_httppost *first = nullptr;
  curl_httppost *last = nullptr;
  curl_formadd(&first, &last, CURLFORM_COPYNAME, "field",
               CURLFORM_COPYCONTENTS, "value", CURLFORM_END);
  const char contents[] = "file contents";
  curl_formadd(&first, &last, CURLFORM_COPYNAME, "attachment",
               CURLFORM_BUFFER, "example.txt", CURLFORM_BUFFERPTR, contents,
               CURLFORM_BUFFERLENGTH, static_cast<long>(sizeof(contents) - 1),
               CURLFORM_CONTENTTYPE, "text/plain", CURLFORM_END);
  curl_forms fields[] = {
      {CURLFORM_COPYNAME, "array-field"},
      {CURLFORM_COPYCONTENTS, "array-value"},
      {CURLFORM_END, nullptr}};
  curl_formadd(&first, &last, CURLFORM_ARRAY, fields, CURLFORM_END);
  // Multiple files in one field create the legacy API's subordinate chain.
  // /dev/null supplies a deterministic, empty local file for serialization.
  curl_formadd(&first, &last, CURLFORM_COPYNAME, "empty-files",
               CURLFORM_FILE, "/dev/null", CURLFORM_CONTENTTYPE, "text/plain",
               CURLFORM_FILE, "/dev/null", CURLFORM_FILENAME, "empty.txt",
               CURLFORM_END);

  // A name containing NUL bytes is documented as invalid. Put it on the last
  // of three files so rejection cleans up both copied fields and a partially
  // constructed subordinate chain, while preserving the previously added form.
  char invalid_name[] = {'a', '\0', 'b'};
  curl_formadd(&first, &last, CURLFORM_COPYNAME, "invalid-files",
               CURLFORM_FILE, "/dev/null", CURLFORM_FILE, "/dev/null",
               CURLFORM_FILE, "/dev/null", CURLFORM_COPYNAME, invalid_name,
               CURLFORM_NAMELENGTH, static_cast<long>(sizeof(invalid_name)),
               CURLFORM_END);
  if(first)
    curl_formget(first, nullptr, DiscardFormData);
  curl_formfree(first);
  curl_formfree(nullptr);
}

/** Exercise duplicate membership and real extra-fd readiness without I/O. */
void ExerciseMultiWaitApis()
{
  CURLM *multi = curl_multi_init();
  CURL *easy = curl_easy_init();
  if(!multi || !easy) {
    curl_easy_cleanup(easy);
    curl_multi_cleanup(multi);
    return;
  }

  const bool attached = curl_multi_add_handle(multi, easy) == CURLM_OK;
  if(attached)
    (void)curl_multi_add_handle(multi, easy);

  unsigned int fd_count = 0;
  (void)curl_multi_waitfds(nullptr, nullptr, 0, &fd_count);
  (void)curl_multi_waitfds(multi, nullptr, 1, &fd_count);
  (void)curl_multi_waitfds(multi, nullptr, 0, nullptr);
  (void)curl_multi_waitfds(multi, nullptr, 0, &fd_count);

  int numfds = 0;
  (void)curl_multi_wait(multi, nullptr, 0, -1, &numfds);

  int fds[2] = {-1, -1};
  if(pipe(fds) == 0) {
    const char ready = 'x';
    if(write(fds[1], &ready, sizeof(ready)) == 1) {
      std::array<curl_waitfd, 2> waitfds = {{
          {fds[0], CURL_WAIT_POLLIN | CURL_WAIT_POLLPRI, 0},
          {fds[1], CURL_WAIT_POLLOUT, 0},
      }};
      (void)curl_multi_wait(multi, waitfds.data(),
                            static_cast<unsigned int>(waitfds.size()), 0,
                            &numfds);
      (void)curl_multi_poll(multi, waitfds.data(),
                            static_cast<unsigned int>(waitfds.size()), 0,
                            &numfds);
    }
    close(fds[0]);
    close(fds[1]);
  }

  if(attached)
    (void)curl_multi_remove_handle(multi, easy);
  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);
}

}  // namespace

void ExercisePublicApiCoverageWithInitializedCurl()
{
  char buffer[4096];
  curl_msnprintf(buffer, sizeof(buffer),
                "%+08d %i %u %#o %#x %#X %ld %lu %lld %llu %%",
                -42, 0, 42U, 42U, 42U, 42U, -42L, 42UL, -42LL, 42ULL);
  curl_msnprintf(buffer, sizeof(buffer), "%*.*s %c %p",
                -12, 4, "example", 'x', static_cast<void *>(buffer));
  curl_msnprintf(buffer, sizeof(buffer), "%+.3f %.2e %g %G",
                1.25, -1.25, 0.00125, 12500.0);
  curl_msnprintf(buffer, 1, "%s", "truncated");
  curl_msnprintf(buffer, 0, "%s", "zero-capacity");
  curl_msprintf(buffer, "%s:%d", "value", 42);
  curl_free(curl_maprintf("%2$s:%1$d", 42, "position"));
  // The stdout wrappers remain quiet while covering their public entrypoints.
  curl_mprintf("%s", "");
  ExerciseVariadicStdout("%s", "");

  FILE *stream = std::tmpfile();
  if(stream)
    curl_mfprintf(stream, "%s:%d", "stream", 42);
  ExerciseVariadicFormatting(stream, "%s:%+08d:%.2f", "variadic", -42, 1.25);
  if(stream)
    std::fclose(stream);

  ExerciseEasyContractErrors();
  ExerciseLegacyForms();
  ExerciseMultiWaitApis();
}

void ExercisePublicApiCoverage()
{
  if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    return;

  ExercisePublicApiCoverageWithInitializedCurl();
  curl_global_cleanup();
}

}  // namespace full_coverage
