"""Exercise curl-global reference ownership with a deterministic test model."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_each_lifecycle_balances_a_distinct_global_reference(tmp_path: Path) -> None:
    """A later lifecycle must not consume the allocator's retained reference."""
    compiler = shutil.which("clang++") or shutil.which("g++")
    if compiler is None:
        pytest.skip("a C++ compiler is required")

    curl_include = tmp_path / "curl"
    curl_include.mkdir()
    (curl_include / "curl.h").write_text(
        """
#ifndef TEST_CURL_CURL_H_
#define TEST_CURL_CURL_H_
extern "C" {
typedef enum { CURLE_OK = 0 } CURLcode;
#define CURL_GLOBAL_ALL 3L
CURLcode curl_global_init(long flags);
void curl_global_cleanup(void);
}
#endif
""",
        encoding="utf-8",
    )
    proto_include = tmp_path / "proto_fuzzer"
    proto_include.mkdir()
    (proto_include / "allocation_fault_injection.h").write_text(
        """
#ifndef TEST_ALLOCATION_FAULT_INJECTION_H_
#define TEST_ALLOCATION_FAULT_INJECTION_H_
namespace proto_fuzzer::allocation_fault_injection {
bool InitializeCurl() noexcept;
bool ClaimCurlInitializationReference() noexcept;
void Reset() noexcept;
}
#endif
""",
        encoding="utf-8",
    )
    driver = tmp_path / "driver.cc"
    driver.write_text(
        r"""
#include <cstdio>
#include <cstdlib>

#include <curl/curl.h>

#include "proto_fuzzer/curl_global_lifecycle.h"

namespace {

int active_references = 0;
int cleanup_calls = 0;
int public_init_calls = 0;
int reset_calls = 0;
bool allocator_initialized = false;
bool allocator_reference_claimed = false;

void Expect(bool condition, const char* message) {
  if (!condition) {
    std::fputs(message, stderr);
    std::fputc('\n', stderr);
    std::exit(EXIT_FAILURE);
  }
}

}  // namespace

extern "C" CURLcode curl_global_init(long) {
  ++active_references;
  ++public_init_calls;
  return CURLE_OK;
}

extern "C" void curl_global_cleanup() {
  Expect(active_references > 0, "cleanup consumed an unowned reference");
  --active_references;
  ++cleanup_calls;
}

namespace proto_fuzzer::allocation_fault_injection {

bool InitializeCurl() noexcept {
  if (!allocator_initialized) {
    allocator_initialized = true;
    ++active_references;
  }
  return true;
}

bool ClaimCurlInitializationReference() noexcept {
  if (allocator_reference_claimed) {
    return false;
  }
  allocator_reference_claimed = true;
  return true;
}

void Reset() noexcept { ++reset_calls; }

}  // namespace proto_fuzzer::allocation_fault_injection

int main() {
  proto_fuzzer::CurlGlobalLifecycle base;
  Expect(base.initialized(), "base lifecycle did not initialize");
  Expect(active_references == 1 && public_init_calls == 0,
         "base lifecycle did not claim the allocator reference");

  {
    proto_fuzzer::CurlGlobalLifecycle additional;
    Expect(additional.initialized(), "additional lifecycle did not initialize");
    Expect(active_references == 2 && public_init_calls == 1,
           "additional lifecycle reused the allocator reference");
  }
  Expect(active_references == 1 && cleanup_calls == 1,
         "additional lifecycle did not release exactly its own reference");

  proto_fuzzer::FinalizeRegisteredCurlGlobalLifecyclesForExit();
  Expect(active_references == 0 && cleanup_calls == 2 && reset_calls == 2,
         "process-exit finalization did not release the base reference");
  proto_fuzzer::FinalizeRegisteredCurlGlobalLifecyclesForExit();
  Expect(cleanup_calls == 2 && reset_calls == 2,
         "process-exit finalization was not idempotent");
}
""",
        encoding="utf-8",
    )
    binary = tmp_path / "curl-global-lifecycle-model"
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(tmp_path),
            "-I",
            str(REPO_ROOT),
            str(REPO_ROOT / "proto_fuzzer" / "curl_global_lifecycle.cc"),
            str(driver),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run([str(binary)], check=True, timeout=5)
