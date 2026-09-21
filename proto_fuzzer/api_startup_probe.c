/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/* Keep the deprecated public ABI visible to this compatibility probe. */
#ifndef CURL_DISABLE_DEPRECATION
#define CURL_DISABLE_DEPRECATION
#endif
#include <curl/curl.h>
#include <curl/mprintf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *probe_malloc(size_t size) { return malloc(size); }
static void probe_free(void *ptr) { free(ptr); }
static void *probe_realloc(void *ptr, size_t size) { return realloc(ptr, size); }
static void *probe_calloc(size_t count, size_t size) { return calloc(count, size); }
static char *probe_strdup(const char *value) {
  size_t size = strlen(value) + 1;
  char *copy = malloc(size);
  if (copy) memcpy(copy, value, size);
  return copy;
}

static size_t discard_form_bytes(void *arg, const char *bytes, size_t size) {
  (void)arg;
  (void)bytes;
  return size;
}

static void probe_mvsprintf(char *buffer, const char *format, ...) {
  va_list args;
  va_start(args, format);
  (void)curl_mvsprintf(buffer, format, args);
  va_end(args);
}

static void probe_mvprintf(const char *format, ...) {
  va_list args;
  va_start(args, format);
  (void)curl_mvprintf(format, args);
  va_end(args);
}

static void probe_mvfprintf(FILE *stream, const char *format, ...) {
  va_list args;
  va_start(args, format);
  (void)curl_mvfprintf(stream, format, args);
  va_end(args);
}

static void probe_typecheck_warning(void) {
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wattribute-warning"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattribute-warning"
#endif
  Wcurl_easy_setopt_err_long();
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
}

void curl_fuzzer_probe_api_startup(void) {
  char *unescaped;
  const curl_ssl_backend **available = NULL;
  struct curl_httppost *form = NULL;
  struct curl_httppost *last = NULL;
  struct curl_httppost *invalid = NULL;
  struct curl_httppost *invalid_last = NULL;
  char print_buffer[256];
  FILE *print_sink;

  probe_typecheck_warning();

  /* Exercise public compatibility APIs that no transfer path calls. */
  (void)curl_easy_header(NULL, NULL, 0, CURLH_HEADER, -1, NULL);
  unescaped = curl_unescape("%41", 0);
  curl_free(unescaped);
  (void)curl_getdate("Thu, 01 Jan 1970 00:00:00 GMT", NULL);
  (void)curl_version();
  (void)curl_global_sslset(CURLSSLBACKEND_NONE, NULL, &available);

  /* libcurl is already initialized. This only balances its init refcount and
   * therefore cannot replace the process-wide allocator callbacks. */
  if (curl_global_init_mem(CURL_GLOBAL_ALL, probe_malloc, probe_free, probe_realloc, probe_strdup, probe_calloc) ==
      CURLE_OK)
    curl_global_cleanup();

  /* Cover the legacy printf ABI, including its va_list wrappers and the
   * pointer/floating-point formatting branches. */
  (void)curl_msprintf(print_buffer, "literal %p %.2f", (void *)print_buffer, 1.25);
  probe_mvsprintf(print_buffer, "%s", "value");
  (void)curl_mprintf("");
  probe_mvprintf("");
  print_sink = fopen("/dev/null", "wb");
  if (print_sink) {
    (void)curl_mfprintf(print_sink, "%p %.2f", (void *)print_buffer, 1.25);
    probe_mvfprintf(print_sink, "");
    fclose(print_sink);
  }

  if (curl_formadd(&form, &last, CURLFORM_COPYNAME, "field", CURLFORM_COPYCONTENTS, "value", CURLFORM_END) ==
      CURL_FORMADD_OK) {
    (void)curl_formget(form, NULL, discard_form_bytes);
    curl_formfree(form);
  }

  /* The second file is deliberately inconsistent with CONTENTSLENGTH. This
   * covers cleanup of a partly assembled multi-file form without opening it. */
  (void)curl_formadd(&invalid, &invalid_last, CURLFORM_COPYNAME, "file", CURLFORM_FILE, "/dev/null", CURLFORM_FILE,
                     "/dev/null", CURLFORM_CONTENTSLENGTH, 1L, CURLFORM_END);
  curl_formfree(invalid);
}
