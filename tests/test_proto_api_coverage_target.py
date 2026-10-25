"""Exercise the proto API target's process-once coverage-probe lifecycle."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_api_probes_run_once_from_initialize_or_callback(tmp_path: Path) -> None:
    """Initialization and standalone fallback both preserve ordinary inputs."""
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
    generated_include = tmp_path / "generated" / "api"
    generated_include.mkdir(parents=True)
    (generated_include / "api_traits.h").write_text(
        "namespace proto_fuzzer::generated { "
        "struct ApiTraits { static constexpr int kProfile = 0; }; }\n",
        encoding="utf-8",
    )
    proto_include = tmp_path / "proto_fuzzer"
    proto_include.mkdir()
    (proto_include / "fuzzer_main.h").write_text(
        r"""
#ifndef TEST_PROTO_FUZZER_MAIN_H_
#define TEST_PROTO_FUZZER_MAIN_H_
#include <cstddef>
#include <cstdint>
#include <cstdio>
namespace proto_fuzzer {
struct ProfileFuzzerTraits {
  int profile;
};
template <typename Traits>
constexpr ProfileFuzzerTraits BindProfileFuzzer() {
  return {Traits::kProfile};
}
inline int ProtoFuzzerTestOneInput(const std::uint8_t *data, std::size_t size,
                                   const ProfileFuzzerTraits &) {
  (void)data;
  (void)size;
  std::puts("ordinary API scenario");
  return 0;
}
std::size_t ProtoFuzzerCustomMutator(std::uint8_t *, std::size_t size,
                                     std::size_t, unsigned int,
                                     const ProfileFuzzerTraits &) {
  return size;
}
std::size_t ProtoFuzzerCustomCrossOver(const std::uint8_t *, std::size_t size1,
                                       const std::uint8_t *, std::size_t,
                                       std::uint8_t *, std::size_t,
                                       unsigned int,
                                       const ProfileFuzzerTraits &) {
  return size1;
}
}  // namespace proto_fuzzer
#endif
""",
        encoding="utf-8",
    )
    driver = tmp_path / "driver.cc"
    driver.write_text(
        r"""
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string_view>

#include <curl/curl.h>

extern "C" int LLVMFuzzerInitialize(int *, char ***);
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *, std::size_t);

extern "C" CURLcode curl_global_init(long) {
  std::puts("public global init");
  return CURLE_OK;
}
extern "C" void curl_global_cleanup() {
  std::puts("deferred cleanup call");
}

namespace full_coverage {
void ExercisePublicApiCoverageWithInitializedCurl() {
  std::puts("public API probe");
}
void ExerciseUtilityApiCoverageWithInitializedCurl() {
  std::puts("utility API probe");
}
void ExerciseDynamicFormattingCoverage() {
  std::puts("dynamic format probe");
}
}  // namespace full_coverage

namespace proto_fuzzer {
void FinalizeRegisteredCurlGlobalLifecyclesForExit() {
  std::puts("bootstrap final cleanup");
}
}  // namespace proto_fuzzer

int main(int argc, char **argv) {
  if (argc == 1 || std::string_view(argv[1]) != "fallback") {
    char **argvp = argv;
    LLVMFuzzerInitialize(&argc, &argvp);
  }
  const std::uint8_t seed[] = {1};
  LLVMFuzzerTestOneInput(seed, sizeof(seed));
  LLVMFuzzerTestOneInput(seed, sizeof(seed));
}
""",
        encoding="utf-8",
    )
    binary = tmp_path / "proto-api-coverage-target"
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DPROTO_FUZZER_API_COVERAGE_PROBES",
            "-I",
            str(tmp_path),
            "-I",
            str(REPO_ROOT),
            str(REPO_ROOT / "fuzzer_entrypoints" / "curl_fuzzer_proto_api.cc"),
            str(REPO_ROOT / "proto_fuzzer" / "api_coverage_probes.cc"),
            str(driver),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    expected = [
        "public global init",
        "public API probe",
        "utility API probe",
        "dynamic format probe",
        "ordinary API scenario",
        "ordinary API scenario",
        "deferred cleanup call",
        "bootstrap final cleanup",
    ]
    initialized = subprocess.run(
        [str(binary)], check=True, capture_output=True, text=True, timeout=5
    )
    fallback = subprocess.run(
        [str(binary), "fallback"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert initialized.stdout.splitlines() == expected
    assert fallback.stdout.splitlines() == expected
