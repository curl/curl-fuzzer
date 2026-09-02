/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of safe easy/share/query lifecycle probes.

#include "proto_fuzzer/api_lifecycle.h"

#include <curl/curl.h>
#include <curl/curlver.h>
#include <curl/easy.h>
#include <curl/header.h>
#include <curl/options.h>
#include <curl/urlapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "proto_fuzzer/curl_raii.h"

namespace proto_fuzzer {

namespace {

constexpr unsigned int kAllHeaderOrigins = CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX | CURLH_PSEUDO;
constexpr std::size_t kMaxResultHeaders = 16;

/// Every public CURLUPart value uses the same `char**` output contract, so it
/// is safe and cheap to traverse the complete table for each mutated URL.
constexpr CURLUPart kUrlParts[] = {
    CURLUPART_URL,  CURLUPART_SCHEME, CURLUPART_USER,  CURLUPART_PASSWORD, CURLUPART_OPTIONS, CURLUPART_HOST,
    CURLUPART_PORT, CURLUPART_PATH,   CURLUPART_QUERY, CURLUPART_FRAGMENT, CURLUPART_ZONEID,
};

/// Retrieve one owned URL result and release it on the same path. Keeping the
/// ownership rule next to the call prevents later table expansion from
/// turning successful getters into one leak per fuzz iteration.
void ProbeUrlPart(CURLU* url, CURLUPart part, unsigned int flags) {
  char* result = nullptr;
  if (curl_url_get(url, part, &result, flags) == CURLUE_OK) {
    curl_free(result);
  }
}

/// Output storage family required by curl_easy_getinfo's varargs contract.
enum class InfoResultType {
  kString,
  kLong,
  kDouble,
  kOffset,
  kSocket,
  kCertificateInfo,
  kTlsSessionInfo,
  kOwnedSlist,
  kUnknown,
};

/// A CURLINFO value paired with the exact output type libcurl expects. Raw
/// protobuf numbers never become CURLINFO values because a mismatched varargs
/// pointer would be undefined behavior in the harness rather than fuzz input.
struct InfoDescriptor {
  CURLINFO info;
  InfoResultType result_type;
};

// Put one value from every dispatch family first so even a small corpus seed
// reaches all typed getinfo paths; the remaining entries broaden state and
// result-specific coverage as selectors mutate.
constexpr InfoDescriptor kInfoDescriptors[] = {
    {CURLINFO_EFFECTIVE_URL, InfoResultType::kString},
    {CURLINFO_RESPONSE_CODE, InfoResultType::kLong},
    {CURLINFO_TOTAL_TIME, InfoResultType::kDouble},
    {CURLINFO_SIZE_DOWNLOAD_T, InfoResultType::kOffset},
    {CURLINFO_ACTIVESOCKET, InfoResultType::kSocket},
    {CURLINFO_CERTINFO, InfoResultType::kCertificateInfo},
    {CURLINFO_TLS_SSL_PTR, InfoResultType::kTlsSessionInfo},
    {CURLINFO_SSL_ENGINES, InfoResultType::kOwnedSlist},
    {CURLINFO_NONE, InfoResultType::kUnknown},
    {CURLINFO_CONTENT_TYPE, InfoResultType::kString},
    {CURLINFO_PRIVATE, InfoResultType::kString},
    {CURLINFO_FTP_ENTRY_PATH, InfoResultType::kString},
    {CURLINFO_REDIRECT_URL, InfoResultType::kString},
    {CURLINFO_PRIMARY_IP, InfoResultType::kString},
    {CURLINFO_RTSP_SESSION_ID, InfoResultType::kString},
    {CURLINFO_LOCAL_IP, InfoResultType::kString},
    {CURLINFO_SCHEME, InfoResultType::kString},
    {CURLINFO_EFFECTIVE_METHOD, InfoResultType::kString},
    {CURLINFO_REFERER, InfoResultType::kString},
    {CURLINFO_CAINFO, InfoResultType::kString},
    {CURLINFO_CAPATH, InfoResultType::kString},
    {CURLINFO_HEADER_SIZE, InfoResultType::kLong},
    {CURLINFO_REQUEST_SIZE, InfoResultType::kLong},
    {CURLINFO_SSL_VERIFYRESULT, InfoResultType::kLong},
    {CURLINFO_FILETIME, InfoResultType::kLong},
    {CURLINFO_REDIRECT_COUNT, InfoResultType::kLong},
    {CURLINFO_HTTP_CONNECTCODE, InfoResultType::kLong},
    {CURLINFO_HTTPAUTH_AVAIL, InfoResultType::kLong},
    {CURLINFO_PROXYAUTH_AVAIL, InfoResultType::kLong},
    {CURLINFO_OS_ERRNO, InfoResultType::kLong},
    {CURLINFO_NUM_CONNECTS, InfoResultType::kLong},
    {CURLINFO_CONDITION_UNMET, InfoResultType::kLong},
    {CURLINFO_RTSP_CLIENT_CSEQ, InfoResultType::kLong},
    {CURLINFO_RTSP_SERVER_CSEQ, InfoResultType::kLong},
    {CURLINFO_RTSP_CSEQ_RECV, InfoResultType::kLong},
    {CURLINFO_PRIMARY_PORT, InfoResultType::kLong},
    {CURLINFO_LOCAL_PORT, InfoResultType::kLong},
    {CURLINFO_HTTP_VERSION, InfoResultType::kLong},
    {CURLINFO_PROXY_SSL_VERIFYRESULT, InfoResultType::kLong},
    {CURLINFO_PROXY_ERROR, InfoResultType::kLong},
    {CURLINFO_NAMELOOKUP_TIME, InfoResultType::kDouble},
    {CURLINFO_CONNECT_TIME, InfoResultType::kDouble},
    {CURLINFO_PRETRANSFER_TIME, InfoResultType::kDouble},
    {CURLINFO_STARTTRANSFER_TIME, InfoResultType::kDouble},
    {CURLINFO_REDIRECT_TIME, InfoResultType::kDouble},
    {CURLINFO_APPCONNECT_TIME, InfoResultType::kDouble},
    {CURLINFO_SIZE_UPLOAD_T, InfoResultType::kOffset},
    {CURLINFO_SPEED_DOWNLOAD_T, InfoResultType::kOffset},
    {CURLINFO_SPEED_UPLOAD_T, InfoResultType::kOffset},
    {CURLINFO_FILETIME_T, InfoResultType::kOffset},
    {CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, InfoResultType::kOffset},
    {CURLINFO_CONTENT_LENGTH_UPLOAD_T, InfoResultType::kOffset},
    {CURLINFO_TOTAL_TIME_T, InfoResultType::kOffset},
    {CURLINFO_NAMELOOKUP_TIME_T, InfoResultType::kOffset},
    {CURLINFO_CONNECT_TIME_T, InfoResultType::kOffset},
    {CURLINFO_PRETRANSFER_TIME_T, InfoResultType::kOffset},
    {CURLINFO_STARTTRANSFER_TIME_T, InfoResultType::kOffset},
    {CURLINFO_REDIRECT_TIME_T, InfoResultType::kOffset},
    {CURLINFO_APPCONNECT_TIME_T, InfoResultType::kOffset},
    {CURLINFO_RETRY_AFTER, InfoResultType::kOffset},
#if LIBCURL_VERSION_NUM >= 0x080200
    {CURLINFO_XFER_ID, InfoResultType::kOffset},
    {CURLINFO_CONN_ID, InfoResultType::kOffset},
#endif
#if LIBCURL_VERSION_NUM >= 0x080600
    {CURLINFO_QUEUE_TIME_T, InfoResultType::kOffset},
#endif
#if LIBCURL_VERSION_NUM >= 0x080700
    {CURLINFO_USED_PROXY, InfoResultType::kLong},
#endif
#if LIBCURL_VERSION_NUM >= 0x080a00
    {CURLINFO_POSTTRANSFER_TIME_T, InfoResultType::kOffset},
#endif
#if LIBCURL_VERSION_NUM >= 0x080b00
    {CURLINFO_EARLYDATA_SENT_T, InfoResultType::kOffset},
#endif
#if LIBCURL_VERSION_NUM >= 0x080c00
    {CURLINFO_HTTPAUTH_USED, InfoResultType::kLong},
    {CURLINFO_PROXYAUTH_USED, InfoResultType::kLong},
#endif
#if LIBCURL_VERSION_NUM >= 0x081400
    {CURLINFO_SIZE_DELIVERED, InfoResultType::kOffset},
#endif
    {CURLINFO_COOKIELIST, InfoResultType::kOwnedSlist},
};

constexpr std::size_t kInfoDescriptorCount = sizeof(kInfoDescriptors) / sizeof(kInfoDescriptors[0]);
static_assert(kInfoDescriptorCount <= 96, "the three API result seeds cover selector indexes 0 through 95");

/// Typed data domains accepted by CURLSHOPT_SHARE. The table intentionally
/// includes reserved/sentinel values: libcurl safely rejects them with
/// CURLSHE_BAD_OPTION, covering the public error path without fabricated
/// pointers or undefined varargs types.
constexpr curl_lock_data kShareData[] = {
    CURL_LOCK_DATA_COOKIE, CURL_LOCK_DATA_DNS,  CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_DATA_CONNECT, CURL_LOCK_DATA_PSL,
    CURL_LOCK_DATA_HSTS,   CURL_LOCK_DATA_NONE, CURL_LOCK_DATA_SHARE,       CURL_LOCK_DATA_LAST,
};
constexpr std::size_t kShareDataCount = sizeof(kShareData) / sizeof(kShareData[0]);

/// Call one CURLINFO descriptor with storage matching its encoded type.
void ProbeInfoDescriptor(CURL* easy, const InfoDescriptor& descriptor) {
  switch (descriptor.result_type) {
    case InfoResultType::kString: {
      char* result = nullptr;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      return;
    }
    case InfoResultType::kLong: {
      long result = 0;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      return;
    }
    case InfoResultType::kDouble: {
      double result = 0;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      return;
    }
    case InfoResultType::kOffset: {
      curl_off_t result = 0;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      return;
    }
    case InfoResultType::kSocket: {
      curl_socket_t result = CURL_SOCKET_BAD;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      return;
    }
    case InfoResultType::kCertificateInfo: {
      struct curl_certinfo* result = nullptr;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      return;
    }
    case InfoResultType::kTlsSessionInfo: {
      struct curl_tlssessioninfo* result = nullptr;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      return;
    }
    case InfoResultType::kOwnedSlist: {
      struct curl_slist* result = nullptr;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      curl_slist_free_all(result);
      return;
    }
    case InfoResultType::kUnknown: {
      void* result = nullptr;
      (void)curl_easy_getinfo(easy, descriptor.info, &result);
      return;
    }
  }
}

/// Exercise every documented error-string table once per process. These APIs
/// are pure enum lookups; repeatedly asking LPM to rediscover all consecutive
/// values would consume corpus energy without adding state-dependent behavior.
void ProbeKnownErrorStringsOnce() {
  static const bool probed = [] {
    for (int code = 0; code <= static_cast<int>(CURL_LAST); ++code) {
      (void)curl_easy_strerror(static_cast<CURLcode>(code));
    }
    (void)curl_multi_strerror(CURLM_CALL_MULTI_PERFORM);
    for (int code = 0; code <= static_cast<int>(CURLM_LAST); ++code) {
      (void)curl_multi_strerror(static_cast<CURLMcode>(code));
    }
    for (int code = 0; code <= static_cast<int>(CURLSHE_LAST); ++code) {
      (void)curl_share_strerror(static_cast<CURLSHcode>(code));
    }
    for (int code = 0; code <= static_cast<int>(CURLUE_LAST); ++code) {
      (void)curl_url_strerror(static_cast<CURLUcode>(code));
    }
    return true;
  }();
  (void)probed;
}

/// Traverse the immutable public setopt metadata once per process. Iterating
/// every entry exercises option_next's table walk and gives both lookup APIs a
/// successful query for every supported type without charging every fuzz case
/// for the same version-dependent static data.
void ProbeEasyOptionMetadataOnce() {
  static const bool probed = [] {
    const struct curl_easyoption* option = nullptr;
    std::size_t count = 0;
    while (count++ < 512 && (option = curl_easy_option_next(option)) != nullptr) {
      (void)curl_easy_option_by_name(option->name);
      (void)curl_easy_option_by_id(option->id);
    }
    (void)curl_easy_option_by_name("");
    (void)curl_easy_option_by_name("NOT_A_CURL_OPTION");
    (void)curl_easy_option_by_id(CURLOPT_LASTENTRY);
    return true;
  }();
  (void)probed;
}

}  // namespace

/// Preserve the caller's plan by reference because ScenarioRunner keeps the
/// source Scenario alive and unmodified for this object's complete lifetime.
ApiLifecycle::ApiLifecycle(CURL* easy, const curl::fuzzer::proto::ApiPlan& plan, std::string_view url)
    : easy_(easy), plan_(plan), share_(nullptr) {
  ProbeKnownErrorStringsOnce();
  ProbeEasyOptionMetadataOnce();
  ProbeUrlAndEscaping(url);
  if (plan_.attach_share()) {
    ConfigureShare();
  }
}

/// ScenarioRunner keeps this owner alive through easy cleanup, which releases
/// even an incomplete connection's share reference before CleanupShare runs.
ApiLifecycle::~ApiLifecycle() { CleanupShare(); }

/// Count callback dispatch while leaving synchronization to applications that
/// actually use multiple threads. The state is owned by this lifecycle and
/// remains valid until after the final share cleanup callback.
void ApiLifecycle::ShareLock(CURL* /*easy*/, curl_lock_data /*data*/, curl_lock_access /*access*/, void* user_data) {
  auto* state = static_cast<ShareCallbackState*>(user_data);
  ++state->locks;
}

/// Match ShareLock without recursively entering any libcurl API.
void ApiLifecycle::ShareUnlock(CURL* /*easy*/, curl_lock_data /*data*/, void* user_data) {
  auto* state = static_cast<ShareCallbackState*>(user_data);
  ++state->unlocks;
}

/// Configure cache domains before attachment, when SHARE/UNSHARE transitions
/// are valid. Once attached, probe mutable userdata plus the cleanup API's
/// safe CURLSHE_IN_USE refusal without destroying the referenced handle.
void ApiLifecycle::ConfigureShare() {
  share_ = curl_share_init();
  if (share_ == nullptr) {
    return;
  }

  // Install userdata before exposing either callback. curl_share_setopt does
  // not invoke them itself, but every later easy/share operation must observe
  // a fully formed callback tuple if curl begins using the configured domains.
  (void)curl_share_setopt(share_, CURLSHOPT_USERDATA, &share_callback_state_);
  (void)curl_share_setopt(share_, CURLSHOPT_LOCKFUNC, &ApiLifecycle::ShareLock);
  (void)curl_share_setopt(share_, CURLSHOPT_UNLOCKFUNC, &ApiLifecycle::ShareUnlock);

  const std::size_t selector_count = std::min<std::size_t>(scenario_limits::kMaxApiShareDataSelectors,
                                                           static_cast<std::size_t>(plan_.share_data_selectors_size()));
  for (std::size_t index = 0; index < selector_count; ++index) {
    const std::uint32_t selector = plan_.share_data_selectors(static_cast<int>(index));
    const curl_lock_data data = kShareData[selector % kShareDataCount];
    if (curl_share_setopt(share_, CURLSHOPT_SHARE, data) == CURLSHE_OK) {
      // Exercise the reversible transition before any transfer can populate
      // the selected cache, then leave the domain enabled. In particular,
      // unsharing CONNECT after use makes current curl stop treating its
      // connection pool as cleanup-owned, so doing teardown in that order
      // would manufacture a deterministic leak in the harness.
      (void)curl_share_setopt(share_, CURLSHOPT_UNSHARE, data);
      (void)curl_share_setopt(share_, CURLSHOPT_SHARE, data);
    }
  }

  if (curl_easy_setopt(easy_, CURLOPT_SHARE, share_) == CURLE_OK) {
    // USERDATA remains mutable while attached; cleanup is the complementary
    // ownership check and returns CURLSHE_IN_USE without destroying the share.
    (void)curl_share_setopt(share_, CURLSHOPT_USERDATA, &share_callback_state_);
    (void)curl_share_cleanup(share_);
  }
}

/// Destroy share state only after the owner has cleaned the easy. Explicitly
/// detaching first is not equivalent: curl rejects that setopt while an
/// incomplete transfer still has a connection, but easy cleanup always drops
/// the reference. Keep successful domains configured because share cleanup
/// uses those bits to identify caches populated during the transfer.
void ApiLifecycle::CleanupShare() {
  if (share_ == nullptr) {
    return;
  }
  if (curl_share_cleanup(share_) == CURLSHE_OK) {
    share_ = nullptr;
  }
}

/// Feed URL and percent-encoding APIs bytes from the same bounded scenario as
/// the transfer. A valid fallback URL keeps getter success paths reachable
/// even when a mutation makes the complete URL unparsable; the rejected parse
/// still executes first, so this does not hide malformed-input branches.
void ApiLifecycle::ProbeUrlAndEscaping(std::string_view url) {
  const std::size_t bounded_size = std::min(url.size(), scenario_limits::kMaxApiStringBytes);
  const std::string input(url.substr(0, bounded_size));

  CURLU* url_handle = curl_url();
  if (url_handle != nullptr) {
    const unsigned int parse_flags = CURLU_ALLOW_SPACE | CURLU_NON_SUPPORT_SCHEME;
    if (curl_url_set(url_handle, CURLUPART_URL, input.c_str(), parse_flags) != CURLUE_OK) {
      (void)curl_url_set(url_handle, CURLUPART_SCHEME, "http", 0);
      (void)curl_url_set(url_handle, CURLUPART_HOST, "api.test", 0);
      (void)curl_url_set(url_handle, CURLUPART_PATH, input.c_str(), CURLU_URLENCODE);
    }

    // Zero and URLDECODE take distinct getter paths for most components;
    // unsupported combinations are documented errors rather than unsafe raw
    // varargs, so traversing the full typed part table is intentional.
    for (const CURLUPart part : kUrlParts) {
      ProbeUrlPart(url_handle, part, 0);
      ProbeUrlPart(url_handle, part, CURLU_URLDECODE);
    }
    ProbeUrlPart(url_handle, CURLUPART_URL, CURLU_DEFAULT_PORT);
    ProbeUrlPart(url_handle, CURLUPART_URL, CURLU_NO_DEFAULT_PORT);
    ProbeUrlPart(url_handle, CURLUPART_URL, CURLU_URLENCODE);
#if LIBCURL_VERSION_NUM >= 0x075800
    ProbeUrlPart(url_handle, CURLUPART_HOST, CURLU_PUNYCODE);
#endif
#if LIBCURL_VERSION_NUM >= 0x080300
    ProbeUrlPart(url_handle, CURLUPART_HOST, CURLU_PUNY2IDN);
#endif
#if LIBCURL_VERSION_NUM >= 0x080800
    ProbeUrlPart(url_handle, CURLUPART_QUERY, CURLU_GET_EMPTY);
    ProbeUrlPart(url_handle, CURLUPART_FRAGMENT, CURLU_GET_EMPTY);
#endif
#if LIBCURL_VERSION_NUM >= 0x080900
    ProbeUrlPart(url_handle, CURLUPART_URL, CURLU_NO_GUESS_SCHEME);
#endif

    // Mutate only the duplicate so the original handle's getter state remains
    // attributable to parsing the scenario URL rather than this lifecycle
    // probe's own append operation.
    CURLU* duplicate = curl_url_dup(url_handle);
    if (duplicate != nullptr) {
      (void)curl_url_set(duplicate, CURLUPART_QUERY, input.c_str(), CURLU_APPENDQUERY | CURLU_URLENCODE);
      ProbeUrlPart(duplicate, CURLUPART_URL, 0);
      curl_url_cleanup(duplicate);
    }
    curl_url_cleanup(url_handle);
  }

  // Exercise explicit binary lengths as well as the NUL-terminated API path.
  // The API policy caps input far below INT_MAX, making the signed conversion
  // and worst-case threefold escaping allocation deterministic.
  const int input_length = static_cast<int>(input.size());
  char* escaped = curl_easy_escape(easy_, input.data(), input_length);
  if (escaped != nullptr) {
    int decoded_length = 0;
    char* decoded = curl_easy_unescape(easy_, escaped, 0, &decoded_length);
    curl_free(decoded);
    curl_free(escaped);
  }
  int decoded_length = 0;
  char* decoded = curl_easy_unescape(easy_, input.data(), input_length, &decoded_length);
  curl_free(decoded);
}

/// Select through the typed descriptor table, suppressing duplicates whose
/// only effect would be charging an iteration for the same immutable result.
/// Header traversal remains unconditional in the API lane because it exposes
/// a separate public API and is independently capped.
void ApiLifecycle::ProbeTransferResults(bool probe_upkeep) {
  std::array<bool, kInfoDescriptorCount> seen{};
  const std::size_t selector_count = std::min<std::size_t>(scenario_limits::kMaxApiInfoSelectors,
                                                           static_cast<std::size_t>(plan_.easy_info_selectors_size()));
  for (std::size_t index = 0; index < selector_count; ++index) {
    const std::uint32_t selector = plan_.easy_info_selectors(static_cast<int>(index));
    const std::size_t descriptor_index = selector % kInfoDescriptorCount;
    if (!seen[descriptor_index]) {
      ProbeInfoDescriptor(easy_, kInfoDescriptors[descriptor_index]);
      seen[descriptor_index] = true;
    }
  }

  struct curl_header* header = nullptr;
  (void)curl_easy_header(easy_, "Content-Type", 0, kAllHeaderOrigins, -1, &header);
  header = nullptr;
  for (std::size_t index = 0; index < kMaxResultHeaders; ++index) {
    header = curl_easy_nextheader(easy_, kAllHeaderOrigins, -1, header);
    if (header == nullptr) {
      break;
    }
  }

  // curl_easy_perform retains an internal multi that upkeep expects. The
  // external multi paths destroy theirs before result probing, and current
  // debug builds deliberately reject upkeep on that detached handle state.
  if (probe_upkeep) {
    (void)curl_easy_upkeep(easy_);
  }

  // Post-transfer pause calls deliberately cover the public API's rejected
  // inactive-handle path without changing the request that populated results.
  (void)curl_easy_pause(easy_, CURLPAUSE_ALL);
  (void)curl_easy_pause(easy_, CURLPAUSE_CONT);
}

/// The duplicate inherits borrowed slists and callback userdata but not the
/// source share. Reset it immediately while those owners are still alive,
/// then cleanup; performing it would reuse mock/request cursors and test a
/// harness artifact instead of libcurl's duplication lifecycle.
void ApiLifecycle::ProbeEasyDuplication() {
  if (!plan_.duplicate_easy()) {
    return;
  }
  CurlEasyPtr duplicate(curl_easy_duphandle(easy_));
  if (duplicate != nullptr) {
    curl_easy_reset(duplicate.get());
  }
}

}  // namespace proto_fuzzer
