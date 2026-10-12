/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "full_coverage/public_api.h"

#include <cstdarg>
#include <cstdio>

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

/** Consume the in-memory serialization produced by the legacy form API. */
size_t DiscardFormData(void *, const char *, size_t length)
{
  return length;
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
  if(first)
    curl_formget(first, nullptr, DiscardFormData);
  curl_formfree(first);
  curl_formfree(nullptr);
}

}  // namespace

void ExercisePublicApiCoverage()
{
  if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    return;

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

  FILE *stream = std::tmpfile();
  if(stream)
    curl_mfprintf(stream, "%s:%d", "stream", 42);
  ExerciseVariadicFormatting(stream, "%s:%+08d:%.2f", "variadic", -42, 1.25);
  if(stream)
    std::fclose(stream);

  ExerciseLegacyForms();
  curl_global_cleanup();
}

}  // namespace full_coverage
