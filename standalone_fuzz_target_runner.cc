/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <system_error>

#include "testinput.h"

/**
 * Per-input timeout (seconds). When LLVMFuzzerTestOneInput hangs (busy
 * loop, blocking I/O, etc.) we'd otherwise hang the whole corpus replay
 * and get SIGKILLed by the CI runner with no trace of which input is at
 * fault. An itimer + siglongjmp lets us abort the one call, log the
 * offender, and move on. Tune via FUZZ_TIMEOUT_SECS.
 *
 * Longjmping out of the fuzzer skips any destructors/cleanup in that
 * call, so we leak whatever that input allocated. That's acceptable for a
 * short-running replay; libFuzzer behaves the same way under -timeout.
 */
static const int DEFAULT_TIMEOUT_SECS = 25;
static int g_timeout_secs = DEFAULT_TIMEOUT_SECS;
static sigjmp_buf g_timeout_env;
static const char *g_current_path;
static volatile sig_atomic_t g_timeout_armed;

/**
 * Optional replay accounting for coverage runs. Completed inputs returned from
 * the callback after a successful read; timeouts and input preparation errors
 * remain separate. Path errors include failed metadata checks and traversals.
 * Counters do not change the runner's continue-on-error or exit-code behavior.
 */
struct ReplayStatus {
  /// Files selected for replay, including failed input preparation.
  size_t attempted;
  /// Successfully read inputs whose fuzzer callbacks returned normally.
  size_t completed;
  /// Callbacks interrupted by the per-input timeout.
  size_t timed_out;
  /// Files whose open, allocation, seek, or read preparation failed.
  size_t input_errors;
  /// Failed path metadata checks or directory traversals.
  size_t path_errors;
};
/// Aggregate counters across all file and directory arguments in this process.
static ReplayStatus g_replay_status;

/**
 * Write numeric replay counters to FUZZ_REPLAY_STATUS_FILE on normal exit.
 * An absent or empty path disables the sidecar. Open and write failures are
 * logged without changing the runner's exit status. Callers must remove stale
 * sidecars before replay because an interrupted process never reaches here.
 */
static void write_replay_status(void)
{
  const char *path = getenv("FUZZ_REPLAY_STATUS_FILE");
  if(!path || !*path)
    return;

  FILE *status = fopen(path, "w");
  if(!status) {
    fprintf(stderr, "[%s] Replay status open failed.\n", path);
    return;
  }
  const int written = fprintf(
    status,
    "{\"attempted\":%zu,\"completed\":%zu,\"timed_out\":%zu,"
    "\"input_errors\":%zu,\"path_errors\":%zu}\n",
    g_replay_status.attempted, g_replay_status.completed,
    g_replay_status.timed_out, g_replay_status.input_errors,
    g_replay_status.path_errors);
  const int closed = fclose(status);
  if(written < 0 || closed != 0)
    fprintf(stderr, "[%s] Replay status write failed.\n", path);
}

static void timeout_handler(int sig)
{
  (void)sig;
  if(g_timeout_armed) {
    g_timeout_armed = 0;
    siglongjmp(g_timeout_env, 1);
  }
}

static void install_timeout_handler(void)
{
  const char *env = getenv("FUZZ_TIMEOUT_SECS");
  if(env && *env) {
    int v = atoi(env);
    if(v >= 0)
      g_timeout_secs = v;
  }
  if(g_timeout_secs <= 0)
    return;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = timeout_handler;
  sigemptyset(&sa.sa_mask);
  /* No SA_RESTART: we want syscalls to return EINTR so the longjmp path
   * can unwind even out of blocking I/O. */
  sigaction(SIGALRM, &sa, NULL);
}

/**
 * Read one file and feed its contents through LLVMFuzzerTestOneInput.
 * If verbose is true, print the familiar per-file trace; otherwise stay
 * silent so a progress bar in the caller doesn't get drowned out.
 */
static void run_one_file(const char *path, bool verbose)
{
  g_replay_status.attempted++;
  if(verbose)
    printf("[%s] ", path);

  FILE *infile = fopen(path, "rb");
  if(!infile) {
    g_replay_status.input_errors++;
    fprintf(stderr, "[%s] Open failed.\n", path);
    return;
  }

  if(verbose)
    printf("Opened.. ");

  bool input_error = (fseek(infile, 0L, SEEK_END) != 0);
  const long input_size = ftell(infile);
  if(input_size < 0)
    input_error = true;
  size_t buffer_len = static_cast<size_t>(input_size);
  if(fseek(infile, 0L, SEEK_SET) != 0)
    input_error = true;

  uint8_t *buffer = (uint8_t *)calloc(buffer_len, sizeof(uint8_t));
  if(buffer) {
    if(fread(buffer, sizeof(uint8_t), buffer_len, infile) != buffer_len ||
       ferror(infile))
      input_error = true;
    if(input_error) {
      g_replay_status.input_errors++;
      fprintf(stderr, "[%s] Read failed.\n", path);
    }
    if(verbose)
      printf("Read %zu bytes, fuzzing.. ", buffer_len);

    g_current_path = path;
    if(g_timeout_secs > 0) {
      if(sigsetjmp(g_timeout_env, 1) == 0) {
        g_timeout_armed = 1;
        alarm((unsigned int)g_timeout_secs);
        LLVMFuzzerTestOneInput(buffer, buffer_len);
        alarm(0);
        g_timeout_armed = 0;
        if(!input_error)
          g_replay_status.completed++;
        if(verbose)
          printf("complete !!");
      }
      else {
        /* Took the longjmp from timeout_handler. */
        alarm(0);
        g_replay_status.timed_out++;
        fprintf(stderr,
                "\n[%s] TIMEOUT after %ds, skipping\n",
                path, g_timeout_secs);
      }
    }
    else {
      LLVMFuzzerTestOneInput(buffer, buffer_len);
      if(!input_error)
        g_replay_status.completed++;
      if(verbose)
        printf("complete !!");
    }
    free(buffer);
  }
  else {
    g_replay_status.input_errors++;
    fprintf(stderr,
            "[%s] Failed to allocate %zu bytes \n",
            path,
            buffer_len);
  }

  fclose(infile);
  if(verbose)
    printf("\n");
}

/**
 * Walk a directory tree, feeding each regular file through
 * LLVMFuzzerTestOneInput, and report progress on stderr. Two passes: one
 * to count files (so we can print N/TOTAL), one to actually run them.
 * Counting a few tens of thousands of paths is negligible next to the
 * replay cost.
 *
 * On a TTY, progress uses \r so the line rewrites in place. Off a TTY
 * (CI logs, file redirect), we emit a fresh line every ~5% so the log
 * stays readable and interleaved output doesn't clobber the bar.
 */
static void process_directory(const char *dir_path)
{
  namespace fs = std::filesystem;
  std::error_code ec;

  size_t total = 0;
  for(auto it = fs::recursive_directory_iterator(
          dir_path,
          fs::directory_options::skip_permission_denied, ec);
      !ec && it != fs::recursive_directory_iterator();
      it.increment(ec)) {
    const bool regular = it->is_regular_file(ec);
    if(ec)
      g_replay_status.path_errors++;
    if(regular && !ec)
      total++;
  }
  if(ec)
    g_replay_status.path_errors++;

  const bool is_tty = isatty(fileno(stderr));
  const size_t tick = std::max<size_t>(1, total / 20);
  size_t processed = 0;
  size_t next_tick = tick;

  fprintf(stderr, "[%s] %zu files\n", dir_path, total);

  ec.clear();
  for(auto it = fs::recursive_directory_iterator(
          dir_path,
          fs::directory_options::skip_permission_denied, ec);
      !ec && it != fs::recursive_directory_iterator();
      it.increment(ec)) {
    const bool regular = it->is_regular_file(ec);
    if(ec)
      g_replay_status.path_errors++;
    if(regular && !ec) {
      run_one_file(it->path().c_str(), /*verbose=*/false);
      processed++;
      if(is_tty) {
        fprintf(stderr, "\r[%s] %zu/%zu (%.1f%%)",
                dir_path, processed, total,
                total ? 100.0 * (double)processed / (double)total : 0.0);
        fflush(stderr);
      }
      else if(processed >= next_tick || processed == total) {
        fprintf(stderr, "[%s] %zu/%zu\n", dir_path, processed, total);
        next_tick = processed + tick;
      }
    }
  }
  if(is_tty)
    fprintf(stderr, "\n");
  if(ec) {
    g_replay_status.path_errors++;
    fprintf(stderr, "[%s] walk failed: %s\n",
            dir_path, ec.message().c_str());
  }
}

/**
 * Main procedure for standalone fuzzing engine.
 *
 * Accepts a mix of file and directory paths as arguments:
 * - For a file, reads the file into memory and passes it to the fuzzing
 *   interface (with verbose per-file trace, handy for reproducing a
 *   single crash).
 * - For a directory, walks it recursively, feeds every regular file
 *   inside through the fuzzer, and prints a progress bar on stderr.
 *
 * Directory mode is what scripts/run_coverage.sh and scripts/check_data.sh
 * lean on to avoid spawning one process per ~100 corpus files; with a few
 * thousand inputs per target, process-launch overhead dominates otherwise
 * (especially under profile-runtime instrumentation, which writes a fresh
 * .profraw for every process).
 */
int main(int argc, char **argv)
{
  namespace fs = std::filesystem;

  install_timeout_handler();

  for(int ii = 1; ii < argc; ii++) {
    std::error_code ec;
    auto status = fs::status(argv[ii], ec);
    if(ec) {
      g_replay_status.path_errors++;
      fprintf(stderr, "[%s] stat failed: %s\n",
              argv[ii], ec.message().c_str());
      continue;
    }

    if(fs::is_directory(status)) {
      process_directory(argv[ii]);
    }
    else {
      run_one_file(argv[ii], /*verbose=*/true);
    }
  }

  write_replay_status();
  return 0;
}
