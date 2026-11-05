"""Exercise the raw URL target's input-driven API state machine."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_fuzz_url_preserves_raw_parse_and_owns_results(tmp_path: Path) -> None:
    """Every typed selector is safe while the historical parse remains first."""
    compiler = shutil.which("clang++") or shutil.which("g++")
    if compiler is None:
        pytest.skip("a C++ compiler is required")

    curl_include = tmp_path / "curl"
    curl_include.mkdir()
    (curl_include / "curl.h").write_text(
        r"""
#ifndef TEST_CURL_CURL_H_
#define TEST_CURL_CURL_H_

#include <stddef.h>

#define LIBCURL_VERSION_NUM 0x081600

typedef enum {
  CURLUE_OK,
  CURLUE_BAD_HANDLE,
  CURLUE_BAD_PARTPOINTER,
  CURLUE_UNKNOWN_PART = 9
} CURLUcode;

typedef enum {
  CURLUPART_URL,
  CURLUPART_SCHEME,
  CURLUPART_USER,
  CURLUPART_PASSWORD,
  CURLUPART_OPTIONS,
  CURLUPART_HOST,
  CURLUPART_PORT,
  CURLUPART_PATH,
  CURLUPART_QUERY,
  CURLUPART_FRAGMENT,
  CURLUPART_ZONEID
} CURLUPart;

#define CURLU_DEFAULT_PORT (1U << 0)
#define CURLU_NO_DEFAULT_PORT (1U << 1)
#define CURLU_DEFAULT_SCHEME (1U << 2)
#define CURLU_NON_SUPPORT_SCHEME (1U << 3)
#define CURLU_PATH_AS_IS (1U << 4)
#define CURLU_DISALLOW_USER (1U << 5)
#define CURLU_URLDECODE (1U << 6)
#define CURLU_URLENCODE (1U << 7)
#define CURLU_APPENDQUERY (1U << 8)
#define CURLU_GUESS_SCHEME (1U << 9)
#define CURLU_NO_AUTHORITY (1U << 10)
#define CURLU_ALLOW_SPACE (1U << 11)
#define CURLU_PUNYCODE (1U << 12)
#define CURLU_PUNY2IDN (1U << 13)
#define CURLU_GET_EMPTY (1U << 14)
#define CURLU_NO_GUESS_SCHEME (1U << 15)

typedef struct Curl_URL CURLU;

#ifdef __cplusplus
extern "C" {
#endif
CURLU *curl_url(void);
void curl_url_cleanup(CURLU *url);
CURLU *curl_url_dup(const CURLU *url);
CURLUcode curl_url_get(const CURLU *url, CURLUPart part, char **value,
                       unsigned int flags);
CURLUcode curl_url_set(CURLU *url, CURLUPart part, const char *value,
                       unsigned int flags);
void curl_free(void *value);
#ifdef __cplusplus
}
#endif

#endif
""",
        encoding="utf-8",
    )

    driver = tmp_path / "driver.cc"
    driver.write_text(
        r"""
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <curl/curl.h>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *, std::size_t);

struct Curl_URL {
  int marker;
};

namespace {

struct Event {
  char kind;
  int part;
  unsigned int flags;
};

std::vector<Event> events;
unsigned int set_parts;
unsigned int clear_parts;
unsigned int get_parts;
std::size_t legacy_parses;
std::size_t query_appends;
std::size_t duplicates;
std::size_t null_contracts;
int live_handles;
int live_results;
bool fail_create;
bool fail_duplicate;
bool fail_get;

constexpr char kBaseUrl[] =
    "imap://user:password;type=i@[fe80::1%25eth0]:143/a/b?base=1#old";

bool IsKnownPart(CURLUPart part) {
  const int value = static_cast<int>(part);
  return value >= static_cast<int>(CURLUPART_URL) &&
         value <= static_cast<int>(CURLUPART_ZONEID);
}

void Run(const std::vector<std::uint8_t> &input) {
  events.clear();
  const std::uint8_t *data = input.empty() ? nullptr : input.data();
  assert(LLVMFuzzerTestOneInput(data, input.size()) == 0);
  assert(!events.empty());
  assert(events[0].kind == 'n');
  if(!input.empty()) {
    assert(events.size() >= 2);
    assert(events[1].kind == 's');
    assert(events[1].part == CURLUPART_URL);
    assert(events[1].flags == CURLU_GUESS_SCHEME);
  }
  assert(live_handles == 0);
  assert(live_results == 0);
}

std::vector<std::uint8_t> Input(std::uint8_t part, std::uint8_t action) {
  return {'v', 'a', 'l', 'u', 'e', part, action, 0, 0, 0x80};
}

}  // namespace

extern "C" CURLU *curl_url(void) {
  events.push_back({'n', -1, 0});
  if(fail_create) {
    fail_create = false;
    return nullptr;
  }
  ++live_handles;
  return static_cast<CURLU *>(std::calloc(1, sizeof(CURLU)));
}

extern "C" void curl_url_cleanup(CURLU *url) {
  events.push_back({'c', -1, 0});
  if(url != nullptr) {
    --live_handles;
    std::free(url);
  }
}

extern "C" CURLU *curl_url_dup(const CURLU *url) {
  events.push_back({'d', -1, 0});
  if(url == nullptr) {
    ++null_contracts;
    return nullptr;
  }
  ++duplicates;
  if(fail_duplicate)
    return nullptr;
  ++live_handles;
  return static_cast<CURLU *>(std::calloc(1, sizeof(CURLU)));
}

extern "C" CURLUcode curl_url_get(const CURLU *url, CURLUPart part,
                                   char **value, unsigned int flags) {
  events.push_back({'g', static_cast<int>(part), flags});
  if(url == nullptr) {
    ++null_contracts;
    return CURLUE_BAD_HANDLE;
  }
  if(value == nullptr) {
    ++null_contracts;
    return CURLUE_BAD_PARTPOINTER;
  }
  if(!IsKnownPart(part))
    return CURLUE_UNKNOWN_PART;
  get_parts |= 1U << static_cast<unsigned int>(part);
  if(fail_get)
    return CURLUE_BAD_PARTPOINTER;
  *value = static_cast<char *>(std::malloc(1));
  assert(*value != nullptr);
  (*value)[0] = '\0';
  ++live_results;
  return CURLUE_OK;
}

extern "C" CURLUcode curl_url_set(CURLU *url, CURLUPart part,
                                   const char *value, unsigned int flags) {
  events.push_back({'s', static_cast<int>(part), flags});
  if(url == nullptr) {
    ++null_contracts;
    return CURLUE_BAD_HANDLE;
  }
  if(!IsKnownPart(part))
    return CURLUE_UNKNOWN_PART;
  if(part == CURLUPART_URL && flags == CURLU_GUESS_SCHEME) {
    ++legacy_parses;
    return CURLUE_OK;
  }
  if(value == nullptr) {
    clear_parts |= 1U << static_cast<unsigned int>(part);
    return CURLUE_OK;
  }
  if(std::strcmp(value, kBaseUrl) != 0)
    set_parts |= 1U << static_cast<unsigned int>(part);
  if(part == CURLUPART_QUERY && (flags & CURLU_APPENDQUERY) != 0)
    ++query_appends;
  return CURLUE_OK;
}

extern "C" void curl_free(void *value) {
  assert(value != nullptr);
  --live_results;
  std::free(value);
}

int main() {
  Run({});
  Run({1, 2, 3, 4});
  Run({'a', 0, 'b', 0, 0, 0, 0, 0});

  for(std::uint8_t part = 0; part <= CURLUPART_ZONEID; ++part) {
    for(std::uint8_t action = 0; action < 3; ++action)
      Run(Input(part, action));
  }

  constexpr unsigned int kAllParts = (1U << 11) - 1;
  assert(set_parts == kAllParts);
  assert(clear_parts == kAllParts);
  assert(get_parts == kAllParts);
  assert(legacy_parses >= 35);
  assert(query_appends >= 33);
  assert(duplicates >= 33);
  assert(null_contracts != 0);

  fail_create = true;
  Run(Input(CURLUPART_URL, 0));
  fail_duplicate = true;
  Run(Input(CURLUPART_HOST, 0));
  fail_duplicate = false;
  fail_get = true;
  Run(Input(CURLUPART_QUERY, 1));
  fail_get = false;
}
""",
        encoding="utf-8",
    )

    binary = tmp_path / "fuzz-url-target-test"
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(tmp_path),
            str(REPO_ROOT / "fuzz_url.cc"),
            str(driver),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run([str(binary)], check=True, timeout=5)
