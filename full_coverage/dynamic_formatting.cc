/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "full_coverage/dynamic_formatting.h"

#include <cstdarg>
#include <cstring>

// Use curl's real private layout, including its debug-build fields.
extern "C" {
#include "curl_setup.h"
#include "curlx/dynbuf.h"
}

namespace full_coverage {
namespace {

/** Call the va_list formatter with an independently bounded destination. */
void ExerciseFormat(size_t limit, const char *format, ...)
{
  dynbuf buffer;
  curlx_dyn_init(&buffer, limit);
  va_list args;
  va_start(args, format);
  volatile int result = curlx_dyn_vprintf(&buffer, format, args);
  va_end(args);
  (void)result;
  curlx_dyn_free(&buffer);
}

}  // namespace

void ExerciseDynamicFormattingCoverage()
{
  // Exact fit and the first byte above the limit cover the staged formatter's
  // normal size-limit handling without relying on failed allocations.
  ExerciseFormat(8, "%s", "1234567");
  ExerciseFormat(8, "%s", "12345678");
  ExerciseFormat(8, "%08d", 1);
  ExerciseFormat(8, "%c", 'x');
  ExerciseFormat(8, "%s", "");

  char text[601];
  std::memset(text, 'x', sizeof(text) - 1);
  text[sizeof(text) - 1] = '\0';
  // Cross the staging buffer boundary both with room and at a small limit.
  ExerciseFormat(1024, "%s", text);
  ExerciseFormat(512, "%s", text);
}

}  // namespace full_coverage
