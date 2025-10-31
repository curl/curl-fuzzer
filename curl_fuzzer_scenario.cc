#include "curl_fuzzer_scenario.h"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <curl/curl.h>
#include <google/protobuf/repeated_field.h>

namespace curl_fuzzer {
namespace {

enum class OptionValueKind {
  kUnknown,
  kString,
  kUint32,
  kUint64,
  kBool,
  kHttpPost,
  kMime,
};

struct OptionDescriptor {
  curl::fuzzer::proto::CurlOptionId id;
  OptionValueKind kind;
  bool singleton;
  const char *name;
  CURLoption curlopt;
};

#include "generated/curl_fuzzer_option_manifest.inc"

const OptionDescriptor *LookupDescriptor(curl::fuzzer::proto::CurlOptionId id) {
  for(size_t ii = 0; ii < kOptionManifestSize; ++ii) {
    if(kOptionManifest[ii].id == id) {
      return &kOptionManifest[ii];
    }
  }
  return nullptr;
}

// Human-readable label for logging; keeps prints decipherable instead of raw enums.
const char *OptionScopeName(curl::fuzzer::proto::OptionScope scope) {
  switch(scope) {
    case curl::fuzzer::proto::OPTION_SCOPE_UNSPECIFIED:
      return "unspecified";
    case curl::fuzzer::proto::OPTION_SCOPE_DEFAULT:
      return "default";
    case curl::fuzzer::proto::OPTION_SCOPE_PROXY:
      return "proxy";
    case curl::fuzzer::proto::OPTION_SCOPE_DOH:
      return "doh";
    case curl::fuzzer::proto::OPTION_SCOPE_TLS:
      return "tls";
    case curl::fuzzer::proto::OptionScope_INT_MIN_SENTINEL_DO_NOT_USE_:
    case curl::fuzzer::proto::OptionScope_INT_MAX_SENTINEL_DO_NOT_USE_:
      return "sentinel";
  }
  return "unknown";
}

// Logs use textual names for transfer kinds so scenario traces stay readable.
const char *TransferKindName(curl::fuzzer::proto::TransferKind kind) {
  switch(kind) {
    case curl::fuzzer::proto::TRANSFER_KIND_UNSPECIFIED:
      return "unspecified";
    case curl::fuzzer::proto::TRANSFER_KIND_UPLOAD:
      return "upload";
    case curl::fuzzer::proto::TRANSFER_KIND_POSTFIELDS:
      return "postfields";
    case curl::fuzzer::proto::TRANSFER_KIND_SEND:
      return "send";
    case curl::fuzzer::proto::TransferKind_INT_MIN_SENTINEL_DO_NOT_USE_:
    case curl::fuzzer::proto::TransferKind_INT_MAX_SENTINEL_DO_NOT_USE_:
      return "sentinel";
  }
  return "unknown";
}

// The fuzzer prints stage transitions; mapping the enum keeps diagnostics obvious.
const char *ResponseStageName(curl::fuzzer::proto::ResponseStage stage) {
  switch(stage) {
    case curl::fuzzer::proto::RESPONSE_STAGE_UNSPECIFIED:
      return "unspecified";
    case curl::fuzzer::proto::RESPONSE_STAGE_ON_CONNECT:
      return "on_connect";
    case curl::fuzzer::proto::RESPONSE_STAGE_ON_READABLE:
      return "on_readable";
    case curl::fuzzer::proto::ResponseStage_INT_MIN_SENTINEL_DO_NOT_USE_:
    case curl::fuzzer::proto::ResponseStage_INT_MAX_SENTINEL_DO_NOT_USE_:
      return "sentinel";
  }
  return "unknown";
}

// Shutdown policies surface in verbose traces; stringifying the enum clarifies intent.
const char *ShutdownPolicyName(curl::fuzzer::proto::ShutdownPolicy policy) {
  switch(policy) {
    case curl::fuzzer::proto::SHUTDOWN_POLICY_UNSPECIFIED:
      return "unspecified";
    case curl::fuzzer::proto::SHUTDOWN_POLICY_HALF_CLOSE_AFTER_LAST_RESPONSE:
      return "half_close";
    case curl::fuzzer::proto::SHUTDOWN_POLICY_KEEP_OPEN:
      return "keep_open";
    case curl::fuzzer::proto::SHUTDOWN_POLICY_CLOSE_IMMEDIATELY:
      return "close_immediately";
    case curl::fuzzer::proto::ShutdownPolicy_INT_MIN_SENTINEL_DO_NOT_USE_:
    case curl::fuzzer::proto::ShutdownPolicy_INT_MAX_SENTINEL_DO_NOT_USE_:
      return "sentinel";
  }
  return "unknown";
}

std::string SanitizedSnippet(std::string_view data, size_t max_len = 64) {
  std::string out;
  size_t limit = std::min(data.size(), max_len);
  out.reserve(limit * 4);
  for(size_t ii = 0; ii < limit; ++ii) {
    unsigned char ch = static_cast<unsigned char>(data[ii]);
    if(std::isprint(ch) && ch != '\\' && ch != '"') {
      out.push_back(static_cast<char>(ch));
    }
    else {
      char buf[5];
      std::snprintf(buf, sizeof(buf), "\\x%02X", ch);
      out.append(buf);
    }
  }
  if(data.size() > limit) {
    out.append("…");
  }
  return out;
}

std::string HexSnippet(std::string_view data, size_t max_len = 16) {
  static constexpr char kHexDigits[] = "0123456789ABCDEF";
  std::string out;
  size_t limit = std::min(data.size(), max_len);
  out.reserve(limit * 3);
  for(size_t ii = 0; ii < limit; ++ii) {
    unsigned char ch = static_cast<unsigned char>(data[ii]);
    if(ii > 0) {
      out.push_back(' ');
    }
    out.push_back(kHexDigits[(ch >> 4) & 0x0F]);
    out.push_back(kHexDigits[ch & 0x0F]);
  }
  if(data.size() > limit) {
    out.append(" …");
  }
  return out;
}

// Helper summaries annotate verbose logging without dumping entire buffers.
std::string SummarizeText(std::string_view data) {
  std::string summary = "len=" + std::to_string(data.size());
  summary.append(" text=\"");
  summary.append(SanitizedSnippet(data, 80));
  summary.push_back('"');
  return summary;
}

// Presents binary payloads in a compact mixed hex/text form for diagnostics.
std::string SummarizeBinary(std::string_view data) {
  std::string summary = "len=" + std::to_string(data.size());
  if(!data.empty()) {
    summary.append(" hex=[");
    summary.append(HexSnippet(data, 16));
    summary.append("] ascii=\"");
    summary.append(SanitizedSnippet(data, 32));
    summary.push_back('"');
  }
  return summary;
}

// Encodes headers for trace logs so we can see what mutator just set.
std::string SummarizeHeaderValue(const curl::fuzzer::proto::HeaderValue &value) {
  switch(value.value_case()) {
    case curl::fuzzer::proto::HeaderValue::kText:
      return std::string("text ") + SummarizeText(value.text());
    case curl::fuzzer::proto::HeaderValue::kBinary:
      return std::string("binary ") + SummarizeBinary(value.binary());
    case curl::fuzzer::proto::HeaderValue::VALUE_NOT_SET:
    default:
      return "unset";
  }
}

// Distills response payloads plus hints to one log line for replay debugging.
std::string SummarizeResponse(const curl::fuzzer::proto::Response &response) {
  std::string summary = SummarizeBinary(response.payload());
  if(response.has_hint()) {
    std::string hints;
    if(response.hint().chunked()) {
      hints.append(hints.empty() ? "chunked" : ",chunked");
    }
    if(response.hint().websocket_frame()) {
      hints.append(hints.empty() ? "websocket" : ",websocket");
    }
    if(response.hint().tls_record()) {
      hints.append(hints.empty() ? "tls_record" : ",tls_record");
    }
    if(!hints.empty()) {
      summary.append(" hints=");
      summary.append(hints);
    }
  }
  if(response.has_delay_before()) {
    summary.append(" delay_ms=");
    summary.append(std::to_string(response.delay_before().milliseconds()));
  }
  return summary;
}

// Breaks down MIME parts so verbose output shows the shape of each upload.
std::string SummarizeMimePart(const curl::fuzzer::proto::MimePart &part) {
  std::string summary;
  if(!part.name().empty()) {
    summary.append("name=");
    summary.append(SummarizeText(part.name()));
    summary.append(" ");
  }
  if(!part.filename().empty()) {
    summary.append("filename=");
    summary.append(SummarizeText(part.filename()));
    summary.append(" ");
  }
  if(!part.content_type().empty()) {
    summary.append("content_type=\"");
    summary.append(part.content_type());
    summary.append("\" ");
  }
  switch(part.body_case()) {
    case curl::fuzzer::proto::MimePart::kBytesValue:
      summary.append("body_bytes ");
      summary.append(SummarizeBinary(part.bytes_value()));
      summary.append(" ");
      break;
    case curl::fuzzer::proto::MimePart::kInlineData:
      summary.append("body_inline ");
      summary.append(SummarizeText(part.inline_data()));
      summary.append(" ");
      break;
    case curl::fuzzer::proto::MimePart::BODY_NOT_SET:
    default:
      break;
  }
  summary.append("headers=");
  summary.append(std::to_string(part.headers_size()));
  return summary;
}

// Similar to MIME summaries but tailored for classic form posts.
std::string SummarizeFormField(const curl::fuzzer::proto::FormField &field) {
  std::string summary;
  summary.append("name=");
  summary.append(SummarizeText(field.name()));
  summary.append(" ");
  switch(field.body_case()) {
    case curl::fuzzer::proto::FormField::kInlineData:
      summary.append("inline ");
      summary.append(SummarizeText(field.inline_data()));
      break;
    case curl::fuzzer::proto::FormField::kBytesValue:
      summary.append("bytes ");
      summary.append(SummarizeBinary(field.bytes_value()));
      break;
    case curl::fuzzer::proto::FormField::BODY_NOT_SET:
    default:
      summary.append("empty");
      break;
  }
  return summary;
}

// Owns scratch buffers that mirror proto data so libcurl can outlive the message.
class ScenarioState {
 public:
  ScenarioState() = default;
  ScenarioState(const ScenarioState &) = delete;
  ScenarioState &operator=(const ScenarioState &) = delete;

  // Curl expects zero-terminated strings that stay valid; copy them into owned storage.
  const char *CopyString(std::string_view sv) {
    auto owned = std::make_unique<char[]>(sv.size() + 1);
    std::memcpy(owned.get(), sv.data(), sv.size());
    owned[sv.size()] = '\0';
    const char *ptr = owned.get();
    cstrings_.push_back(std::move(owned));
    return ptr;
  }

  // Binary blobs need stable backing memory for CURLFORM_PTRCONTENTS and similar paths.
  std::pair<const uint8_t *, size_t> CopyBytes(std::string_view sv) {
    byte_buffers_.emplace_back();
    auto &storage = byte_buffers_.back();
    storage.assign(reinterpret_cast<const uint8_t *>(sv.data()),
                   reinterpret_cast<const uint8_t *>(sv.data()) + sv.size());
    const uint8_t *ptr = storage.data();
    return {ptr, storage.size()};
  }

  // Converts proto headers to the format curl_slist requires, owning the storage.
  int HeaderValueToCString(const curl::fuzzer::proto::HeaderValue &value,
                           const char **out) {
    switch(value.value_case()) {
      case curl::fuzzer::proto::HeaderValue::kText:
        *out = CopyString(value.text());
        return 0;
      case curl::fuzzer::proto::HeaderValue::kBinary: {
        auto view = CopyBytes(value.binary());
        if(view.second == 0) {
          *out = CopyString("");
        }
        else {
          *out = CopyString(std::string_view(reinterpret_cast<const char *>(view.first), view.second));
        }
        return 0;
      }
      case curl::fuzzer::proto::HeaderValue::VALUE_NOT_SET:
      default:
        *out = CopyString("");
        return 0;
    }
  }

 private:
  std::vector<std::vector<uint8_t>> byte_buffers_;
  std::vector<std::unique_ptr<char[]>> cstrings_;
};

// Passed into the fuzz harness so the lifetime of ScenarioState is reference counted.
void DestroyScenarioState(void *ptr) {
  delete static_cast<ScenarioState *>(ptr);
}

// curl_easy_setopt "long" overload accepts several proto numeric types; normalize here.
long ProtoToLong(const curl::fuzzer::proto::SetOption &option) {
  switch(option.value_case()) {
    case curl::fuzzer::proto::SetOption::kInt32Value:
      return static_cast<long>(option.int32_value());
    case curl::fuzzer::proto::SetOption::kUint32Value:
      return static_cast<long>(option.uint32_value());
    case curl::fuzzer::proto::SetOption::kInt64Value:
      return static_cast<long>(option.int64_value());
    case curl::fuzzer::proto::SetOption::kUint64Value:
      return static_cast<long>(option.uint64_value());
    case curl::fuzzer::proto::SetOption::kBoolValue:
      return option.bool_value() ? 1L : 0L;
    case curl::fuzzer::proto::SetOption::kDoubleValue:
      return static_cast<long>(option.double_value());
    case curl::fuzzer::proto::SetOption::kStringValue:
    case curl::fuzzer::proto::SetOption::kBytesValue:
    case curl::fuzzer::proto::SetOption::VALUE_NOT_SET:
      return 0L;
    default:
      return 0L;
  }
}

// Some CURLOPTs expect curl_off_t; reuse ProtoToLong while preserving native width.
curl_off_t ProtoToOffT(const curl::fuzzer::proto::SetOption &option) {
  switch(option.value_case()) {
    case curl::fuzzer::proto::SetOption::kUint64Value:
      return static_cast<curl_off_t>(option.uint64_value());
    case curl::fuzzer::proto::SetOption::kInt64Value:
      return static_cast<curl_off_t>(option.int64_value());
    case curl::fuzzer::proto::SetOption::kUint32Value:
      return static_cast<curl_off_t>(option.uint32_value());
    case curl::fuzzer::proto::SetOption::kInt32Value:
      return static_cast<curl_off_t>(option.int32_value());
    case curl::fuzzer::proto::SetOption::kBoolValue:
    case curl::fuzzer::proto::SetOption::kDoubleValue:
    case curl::fuzzer::proto::SetOption::kStringValue:
    case curl::fuzzer::proto::SetOption::kBytesValue:
    case curl::fuzzer::proto::SetOption::VALUE_NOT_SET:
      return static_cast<curl_off_t>(ProtoToLong(option));
    default:
      return static_cast<curl_off_t>(ProtoToLong(option));
  }
}

// Prevents conflicting mutations: once an option is set we refuse to overwrite it.
int EnsureOptionUnset(FUZZ_DATA *fuzz, CURLoption opt, const OptionDescriptor *desc) {
  (void)desc;
  if(fuzz->options[opt % 1000] != 0) {
    return 255;
  }
  return 0;
}

// Tracks which curl options have been claimed, so EnsureOptionUnset can police reuse.
void MarkOptionSet(FUZZ_DATA *fuzz, CURLoption opt) {
  fuzz->options[opt % 1000] = 1;
}

// Shared helpers wrap curl_easy_setopt calls and mark bookkeeping on success.
int ApplyStringOption(FUZZ_DATA *fuzz,
                      const OptionDescriptor *desc,
                      const char *value) {
  CURLcode code = curl_easy_setopt(fuzz->easy, desc->curlopt, value);
  if(code != CURLE_OK) {
    return static_cast<int>(code);
  }
  MarkOptionSet(fuzz, desc->curlopt);
  return 0;
}

int ApplyLongOption(FUZZ_DATA *fuzz,
                    const OptionDescriptor *desc,
                    long value) {
  CURLcode code = curl_easy_setopt(fuzz->easy, desc->curlopt, value);
  if(code != CURLE_OK) {
    return static_cast<int>(code);
  }
  MarkOptionSet(fuzz, desc->curlopt);
  return 0;
}

int ApplyOffOption(FUZZ_DATA *fuzz,
                   const OptionDescriptor *desc,
                   curl_off_t value) {
  CURLcode code = curl_easy_setopt(fuzz->easy, desc->curlopt, value);
  if(code != CURLE_OK) {
    return static_cast<int>(code);
  }
  MarkOptionSet(fuzz, desc->curlopt);
  return 0;
}

// Central dispatcher for option mutations: validates descriptor, enforces scope rules,
// and copies data so curl references remain valid after the protobuf message is gone.
int ApplySetOption(const curl::fuzzer::proto::SetOption &option,
                   ScenarioState *state,
                   FUZZ_DATA *fuzz) {
  const OptionDescriptor *desc = LookupDescriptor(option.option_id());
  if(desc == nullptr) {
    return 255;
  }

  int rc = 0;
  const char *scope_name = OptionScopeName(option.scope());
  switch(desc->kind) {
    case OptionValueKind::kString: {
      const char *value = nullptr;
      std::string detail;
      switch(option.value_case()) {
        case curl::fuzzer::proto::SetOption::kStringValue: {
          detail = std::string("string ") + SummarizeText(option.string_value());
          value = state->CopyString(option.string_value());
          break;
        }
        case curl::fuzzer::proto::SetOption::kBytesValue: {
          detail = std::string("bytes ") + SummarizeBinary(option.bytes_value());
          auto view = state->CopyBytes(option.bytes_value());
          if(view.second == 0 || view.first == nullptr) {
            value = state->CopyString("");
          }
          else {
            value = state->CopyString(std::string_view(reinterpret_cast<const char *>(view.first), view.second));
          }
          break;
        }
        default: {
          detail = "string <empty>";
          value = state->CopyString("");
          break;
        }
      }
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      rc = ApplyStringOption(fuzz, desc, value);
      if(rc == 0 && fuzz->verbose) {
        FV_PRINTF(fuzz,
                  "SCENARIO: set_option %s scope=%s %s\n",
                  desc->name,
                  scope_name,
                  detail.c_str());
      }
      return rc;
    }
    case OptionValueKind::kUint32: {
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      long value = ProtoToLong(option);
      rc = ApplyLongOption(fuzz, desc, value);
      if(rc == 0 && fuzz->verbose) {
        std::string detail = "uint32=" + std::to_string(static_cast<long long>(value));
        FV_PRINTF(fuzz,
                  "SCENARIO: set_option %s scope=%s %s\n",
                  desc->name,
                  scope_name,
                  detail.c_str());
      }
      return rc;
    }
    case OptionValueKind::kUint64: {
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      curl_off_t value = ProtoToOffT(option);
      rc = ApplyOffOption(fuzz, desc, value);
      if(rc == 0 && fuzz->verbose) {
        std::string detail = "uint64=" + std::to_string(static_cast<long long>(value));
        FV_PRINTF(fuzz,
                  "SCENARIO: set_option %s scope=%s %s\n",
                  desc->name,
                  scope_name,
                  detail.c_str());
      }
      return rc;
    }
    case OptionValueKind::kBool: {
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      const bool has_bool_value =
        option.value_case() == curl::fuzzer::proto::SetOption::kBoolValue;
      long value = has_bool_value ? (option.bool_value() ? 1L : 0L) : ProtoToLong(option);
      rc = ApplyLongOption(fuzz, desc, value);
      if(rc == 0 && fuzz->verbose) {
        std::string detail;
        if(has_bool_value) {
          detail = std::string("bool=") + (option.bool_value() ? "true" : "false");
        }
        else {
          detail = "long=" + std::to_string(static_cast<long long>(value));
        }
        FV_PRINTF(fuzz,
                  "SCENARIO: set_option %s scope=%s %s\n",
                  desc->name,
                  scope_name,
                  detail.c_str());
      }
      return rc;
    }
    case OptionValueKind::kHttpPost: {
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      if(fuzz->httppost == NULL) {
        return 255;
      }
      CURLcode code = curl_easy_setopt(fuzz->easy, desc->curlopt, fuzz->httppost);
      if(code != CURLE_OK) {
        return static_cast<int>(code);
      }
      MarkOptionSet(fuzz, desc->curlopt);
      if(fuzz->verbose) {
        FV_PRINTF(fuzz,
                  "SCENARIO: set_option %s scope=%s httppost attached\n",
                  desc->name,
                  scope_name);
      }
      return 0;
    }
    case OptionValueKind::kMime: {
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      if(fuzz->mime == NULL) {
        return 255;
      }
      CURLcode code = curl_easy_setopt(fuzz->easy, desc->curlopt, fuzz->mime);
      if(code != CURLE_OK) {
        return static_cast<int>(code);
      }
      MarkOptionSet(fuzz, desc->curlopt);
      if(fuzz->verbose) {
        FV_PRINTF(fuzz,
                  "SCENARIO: set_option %s scope=%s mime attached\n",
                  desc->name,
                  scope_name);
      }
      return 0;
    }
    case OptionValueKind::kUnknown:
    default:
      return 255;
  }
}

// Adds a header to the easy handle: we store it in a curl_slist the harness will free.
int ApplyHeader(const curl::fuzzer::proto::AddHeader &header,
                ScenarioState *state,
                FUZZ_DATA *fuzz) {
  std::string detail = SummarizeHeaderValue(header.value());
  const char *value = nullptr;
  int rc = state->HeaderValueToCString(header.value(), &value);
  if(rc != 0) {
    return rc;
  }
  curl_slist *new_list = curl_slist_append(fuzz->header_list, value);
  if(new_list == NULL) {
    return 255;
  }
  fuzz->header_list = new_list;
  fuzz->header_list_count++;
  if(fuzz->verbose) {
    FV_PRINTF(fuzz,
              "SCENARIO: add_header #%d %s\n",
              fuzz->header_list_count,
              detail.c_str());
  }
  return 0;
}

// POP3/SMTP fuzzers need dynamic recipient lists; mirror header handling for mail APIs.
int ApplyMailRecipient(const curl::fuzzer::proto::AddMailRecipient &recipient,
                       ScenarioState *state,
                       FUZZ_DATA *fuzz) {
  std::string detail = SummarizeHeaderValue(recipient.value());
  const char *value = nullptr;
  int rc = state->HeaderValueToCString(recipient.value(), &value);
  if(rc != 0) {
    return rc;
  }
  curl_slist *new_list = curl_slist_append(fuzz->mail_recipients_list, value);
  if(new_list == NULL) {
    return 255;
  }
  fuzz->mail_recipients_list = new_list;
  fuzz->header_list_count++;
  if(fuzz->verbose) {
    FV_PRINTF(fuzz,
              "SCENARIO: add_mail_recipient #%d %s\n",
              fuzz->header_list_count,
              detail.c_str());
  }
  return 0;
}

// Captures upload payloads in ScenarioState buffers and toggles CURLOPTs accordingly.
int ApplyRegisterUpload(const curl::fuzzer::proto::RegisterUpload &upload,
                        ScenarioState *state,
                        FUZZ_DATA *fuzz) {
  auto view = state->CopyBytes(upload.payload());
  const uint8_t *data = view.first;
  size_t length = view.second;
  fuzz->upload1_data = data;
  fuzz->upload1_data_len = length;
  fuzz->upload1_data_written = 0;
  const OptionDescriptor *upload_desc = LookupDescriptor(curl::fuzzer::proto::CURLOPT_UPLOAD);
  if(upload_desc != nullptr) {
    int rc = EnsureOptionUnset(fuzz, upload_desc->curlopt, upload_desc);
    if(rc != 0) {
      return rc;
    }
    rc = ApplyLongOption(
        fuzz,
        upload_desc,
        upload.kind() == curl::fuzzer::proto::TRANSFER_KIND_POSTFIELDS ? 0L : 1L);
    if(rc != 0) {
      return rc;
    }
  }

  const OptionDescriptor *length_desc =
      LookupDescriptor(curl::fuzzer::proto::CURLOPT_INFILESIZE_LARGE);
  if(length_desc != nullptr) {
    int rc = EnsureOptionUnset(fuzz, length_desc->curlopt, length_desc);
    if(rc != 0) {
      return rc;
    }
    rc = ApplyOffOption(fuzz, length_desc, static_cast<curl_off_t>(length));
    if(rc != 0) {
      return rc;
    }
  }
  if(fuzz->verbose) {
    std::string detail = SummarizeBinary(upload.payload());
    std::string size_hint = std::to_string(static_cast<unsigned long long>(upload.size_hint()));
    FV_PRINTF(fuzz,
              "SCENARIO: register_upload kind=%s %s size_hint=%s\n",
              TransferKindName(upload.kind()),
              detail.c_str(),
              size_hint.c_str());
  }
  return 0;
}

// Builds individual MIME parts while copying proto-managed storage into curl-owned form.
int ApplyMimePart(const curl::fuzzer::proto::MimePart &part,
                  ScenarioState *state,
                  curl_mime *mime) {
  curl_mimepart *m = curl_mime_addpart(mime);
  if(m == NULL) {
    return 255;
  }
  if(!part.name().empty()) {
    const char *name = state->CopyString(part.name());
    curl_mime_name(m, name);
  }
  if(!part.filename().empty()) {
    const char *filename = state->CopyString(part.filename());
    curl_mime_filename(m, filename);
  }
  if(!part.content_type().empty()) {
    const char *ctype = state->CopyString(part.content_type());
    curl_mime_type(m, ctype);
  }
  switch(part.body_case()) {
    case curl::fuzzer::proto::MimePart::kBytesValue: {
      auto view = state->CopyBytes(part.bytes_value());
      CURLcode code = curl_mime_data(m, reinterpret_cast<const char *>(view.first), view.second);
      if(code != CURLE_OK) {
        return static_cast<int>(code);
      }
      break;
    }
    case curl::fuzzer::proto::MimePart::kInlineData: {
      const char *text = state->CopyString(part.inline_data());
      CURLcode code = curl_mime_data(m, text, CURL_ZERO_TERMINATED);
      if(code != CURLE_OK) {
        return static_cast<int>(code);
      }
      break;
    }
    case curl::fuzzer::proto::MimePart::BODY_NOT_SET:
    default:
      break;
  }
  for(const auto &header : part.headers()) {
    const char *hv = nullptr;
    int rc = state->HeaderValueToCString(header, &hv);
    if(rc != 0) {
      return rc;
    }
    struct curl_slist *list = curl_slist_append(nullptr, hv);
    if(list == NULL) {
      return 255;
    }
    CURLcode code = curl_mime_headers(m, list, 1);
    if(code != CURLE_OK) {
      return static_cast<int>(code);
    }
  }
  return 0;
}

// Lazily allocates a curl_mime handle and appends each proto part for the active request.
int ApplyConfigureMime(const curl::fuzzer::proto::ConfigureMime &config,
                       ScenarioState *state,
                       FUZZ_DATA *fuzz) {
  if(fuzz->mime == NULL) {
    fuzz->mime = curl_mime_init(fuzz->easy);
    if(fuzz->mime == NULL) {
      return 255;
    }
  }
  size_t index = 0;
  for(const auto &part : config.parts()) {
    if(fuzz->verbose) {
      std::string detail = SummarizeMimePart(part);
      FV_PRINTF(fuzz,
                "SCENARIO: configure_mime part[%zu] %s\n",
                index,
                detail.c_str());
    }
    int rc = ApplyMimePart(part, state, fuzz->mime);
    if(rc != 0) {
      return rc;
    }
    ++index;
  }
  return 0;
}

// Recreates the legacy curl_httppost linked list for form submissions, stitching chains
// together across multiple actions so later CURLOPT_HTTPPOST calls see all parts.
int ApplyConfigureHttpPost(const curl::fuzzer::proto::ConfigureHttpPost &config,
                           ScenarioState *state,
                           FUZZ_DATA *fuzz) {
  struct curl_httppost *post = NULL;
  struct curl_httppost *last = NULL;
  size_t index = 0;
  for(const auto &field : config.fields()) {
    if(fuzz->verbose) {
      std::string detail = SummarizeFormField(field);
      FV_PRINTF(fuzz,
                "SCENARIO: configure_http_post field[%zu] %s\n",
                index,
                detail.c_str());
    }
    const char *name = state->CopyString(field.name());
    CURLFORMcode form_rc = CURL_FORMADD_OK;
    switch(field.body_case()) {
      case curl::fuzzer::proto::FormField::kInlineData: {
        const char *data = state->CopyString(field.inline_data());
        form_rc = curl_formadd(&post, &last,
                               CURLFORM_COPYNAME, name,
                               CURLFORM_COPYCONTENTS, data,
                               CURLFORM_END);
        break;
      }
      case curl::fuzzer::proto::FormField::kBytesValue: {
        auto view = state->CopyBytes(field.bytes_value());
        form_rc = curl_formadd(&post, &last,
                               CURLFORM_COPYNAME, name,
                               CURLFORM_PTRCONTENTS, view.first,
                               CURLFORM_CONTENTLEN, static_cast<curl_off_t>(view.second),
                               CURLFORM_END);
        break;
      }
      case curl::fuzzer::proto::FormField::BODY_NOT_SET:
      default:
        form_rc = curl_formadd(&post, &last,
                               CURLFORM_COPYNAME, name,
                               CURLFORM_END);
        break;
    }
    if(form_rc != CURL_FORMADD_OK) {
      if(post != NULL) {
        curl_formfree(post);
      }
      return 255;
    }
    ++index;
  }
  if(post == NULL) {
    return 0;
  }

  if(fuzz->httppost == NULL) {
    fuzz->httppost = post;
  }
  else {
    struct curl_httppost *tail = fuzz->last_post_part;
    if(tail == NULL) {
      tail = fuzz->httppost;
      while(tail->next != NULL) {
        tail = tail->next;
      }
    }
    tail->next = post;
  }

  fuzz->last_post_part = last;
  return 0;
}

// Copies response payloads into ScenarioState buffers so socket managers can replay them.
int ApplyResponse(const curl::fuzzer::proto::Response &response,
                  ScenarioState *state,
                  FUZZ_RESPONSE *dest) {
  auto view = state->CopyBytes(response.payload());
  dest->data = view.first;
  dest->data_len = view.second;
  return 0;
}

// Applies scripted server behaviour: each connection slot gets preset responses and
// optional follow-up messages so the harness can emulate remote peers.
int ApplyConnections(const google::protobuf::RepeatedPtrField<curl::fuzzer::proto::Connection> &connections,
                     ScenarioState *state,
                     FUZZ_DATA *fuzz) {
  for(const auto &connection : connections) {
    if(connection.id() >= FUZZ_NUM_CONNECTIONS) {
      continue;
    }
    FUZZ_SOCKET_MANAGER *manager = &fuzz->sockman[connection.id()];
    if(fuzz->verbose) {
      uint32_t idle_ms = connection.has_idle_after_send()
                             ? connection.idle_after_send().milliseconds()
                             : 0U;
      FV_PRINTF(fuzz,
                "SCENARIO: connection %u policy=%s idle_after_send_ms=%u responses=%d\n",
                connection.id(),
                ShutdownPolicyName(connection.shutdown_policy()),
                idle_ms,
                connection.on_readable_size() + (connection.has_initial_response() ? 1 : 0));
    }
    if(connection.has_initial_response()) {
      int rc = ApplyResponse(connection.initial_response(), state, &manager->responses[0]);
      if(rc != 0) {
        return rc;
      }
      if(fuzz->verbose) {
        std::string detail = SummarizeResponse(connection.initial_response());
        FV_PRINTF(fuzz,
                  "SCENARIO: connection %u initial_response %s\n",
                  connection.id(),
                  detail.c_str());
      }
    }
    int idx = 1;
    for(const auto &resp : connection.on_readable()) {
      if(idx >= TLV_MAX_NUM_RESPONSES) {
        break;
      }
      int rc = ApplyResponse(resp, state, &manager->responses[idx]);
      if(rc != 0) {
        return rc;
      }
      if(fuzz->verbose) {
        std::string detail = SummarizeResponse(resp);
        FV_PRINTF(fuzz,
                  "SCENARIO: connection %u on_readable[%d] %s\n",
                  connection.id(),
                  idx - 1,
                  detail.c_str());
      }
      idx++;
    }
  }
  return 0;
}

// Allows actions to enqueue additional responses after the scenario starts executing,
// modelling dynamically generated server data.
int ApplyRegisterResponse(const curl::fuzzer::proto::RegisterResponse &registration,
                          ScenarioState *state,
                          FUZZ_DATA *fuzz) {
  uint32_t id = registration.connection_id();
  if(id >= FUZZ_NUM_CONNECTIONS) {
    return 255;
  }
  FUZZ_SOCKET_MANAGER *manager = &fuzz->sockman[id];
  int rc = 0;
  int stage_index = -1;
  switch(registration.stage()) {
    case curl::fuzzer::proto::RESPONSE_STAGE_ON_CONNECT:
      rc = ApplyResponse(registration.response(), state, &manager->responses[0]);
      break;
    case curl::fuzzer::proto::RESPONSE_STAGE_ON_READABLE: {
      for(int idx = 1; idx < TLV_MAX_NUM_RESPONSES; ++idx) {
        if(manager->responses[idx].data_len == 0 && manager->responses[idx].data == NULL) {
          rc = ApplyResponse(registration.response(), state, &manager->responses[idx]);
          stage_index = idx - 1;
          break;
        }
      }
      if(stage_index == -1) {
        return 255;
      }
      break;
    }
    case curl::fuzzer::proto::RESPONSE_STAGE_UNSPECIFIED:
    default:
      return 255;
  }
  if(rc != 0) {
    return rc;
  }
  if(fuzz->verbose) {
    std::string detail = SummarizeResponse(registration.response());
    if(registration.stage() == curl::fuzzer::proto::RESPONSE_STAGE_ON_READABLE) {
      FV_PRINTF(fuzz,
                "SCENARIO: register_response conn=%u stage=%s index=%d %s\n",
                id,
                ResponseStageName(registration.stage()),
                stage_index,
                detail.c_str());
    }
    else {
      FV_PRINTF(fuzz,
                "SCENARIO: register_response conn=%u stage=%s %s\n",
                id,
                ResponseStageName(registration.stage()),
                detail.c_str());
    }
  }
  return 0;
}

// Dispatches scenario actions in declaration order so state builds up deterministically.
int ApplyAction(const curl::fuzzer::proto::Action &action,
                ScenarioState *state,
                FUZZ_DATA *fuzz) {
  switch(action.kind_case()) {
    case curl::fuzzer::proto::Action::kSetOption:
      return ApplySetOption(action.set_option(), state, fuzz);
    case curl::fuzzer::proto::Action::kAddHeader:
      return ApplyHeader(action.add_header(), state, fuzz);
    case curl::fuzzer::proto::Action::kAddMailRecipient:
      return ApplyMailRecipient(action.add_mail_recipient(), state, fuzz);
    case curl::fuzzer::proto::Action::kConfigureMime:
      return ApplyConfigureMime(action.configure_mime(), state, fuzz);
    case curl::fuzzer::proto::Action::kConfigureHttpPost:
      return ApplyConfigureHttpPost(action.configure_http_post(), state, fuzz);
    case curl::fuzzer::proto::Action::kRegisterUpload:
      return ApplyRegisterUpload(action.register_upload(), state, fuzz);
    case curl::fuzzer::proto::Action::kRegisterResponse:
      return ApplyRegisterResponse(action.register_response(), state, fuzz);
    case curl::fuzzer::proto::Action::KIND_NOT_SET:
    default:
      return 0;
  }
}

}  // namespace

// Entry point from the fuzz harness: hydrate scenario state, run all actions, then wire
// up scripted connections so the fuzzer sees a complete environment.
int ApplyScenario(const curl::fuzzer::proto::Scenario &scenario,
                  FUZZ_DATA *fuzz) {
  auto state = std::make_unique<ScenarioState>();
  int rc = 0;
  for(const auto &action : scenario.actions()) {
    rc = ApplyAction(action, state.get(), fuzz);
    if(rc != 0) {
      return rc;
    }
  }
  rc = ApplyConnections(scenario.connections(), state.get(), fuzz);
  if(rc != 0) {
    return rc;
  }

  fuzz->scenario_state = state.release();
  fuzz->scenario_state_destructor = DestroyScenarioState;
  return 0;
}

}  // namespace curl_fuzzer
