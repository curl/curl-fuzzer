#include "curl_fuzzer_scenario.h"

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
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

class ScenarioState {
 public:
  ScenarioState() = default;
  ScenarioState(const ScenarioState &) = delete;
  ScenarioState &operator=(const ScenarioState &) = delete;

  int LoadBlobs(const curl::fuzzer::proto::Scenario &scenario) {
    blobs_.clear();
    for(const auto &blob : scenario.blobs()) {
      std::vector<uint8_t> bytes;
      switch(blob.payload_case()) {
        case curl::fuzzer::proto::DataBlob::kRaw:
          bytes.assign(blob.raw().begin(), blob.raw().end());
          break;
        case curl::fuzzer::proto::DataBlob::kUtf8: {
          const std::string &utf8 = blob.utf8();
          bytes.assign(utf8.begin(), utf8.end());
          break;
        }
        case curl::fuzzer::proto::DataBlob::PAYLOAD_NOT_SET:
          bytes.clear();
          break;
      }
      blobs_.emplace(blob.id(), std::move(bytes));
    }
    return 0;
  }

  const std::vector<uint8_t> *LookupBlob(uint32_t id) const {
    auto it = blobs_.find(id);
    if(it == blobs_.end()) {
      return nullptr;
    }
    return &it->second;
  }

  int ResolveBlobRef(const curl::fuzzer::proto::BlobRef &ref,
                     const uint8_t **data,
                     size_t *length) const {
    auto *blob = LookupBlob(ref.blob_id());
    if(blob == nullptr) {
      return 255;
    }
    size_t offset = ref.has_offset() ? ref.offset() : 0;
    if(offset > blob->size()) {
      return 255;
    }
    size_t view_len = ref.has_length() ? ref.length() : (blob->size() - offset);
    if(offset + view_len > blob->size()) {
      return 255;
    }
    *data = blob->data() + offset;
    *length = view_len;
    return 0;
  }

  const char *CopyString(std::string_view sv) {
    auto owned = std::make_unique<char[]>(sv.size() + 1);
    std::memcpy(owned.get(), sv.data(), sv.size());
    owned[sv.size()] = '\0';
    const char *ptr = owned.get();
    cstrings_.push_back(std::move(owned));
    return ptr;
  }

  int HeaderValueToCString(const curl::fuzzer::proto::HeaderValue &value,
                           const char **out) {
    switch(value.value_case()) {
      case curl::fuzzer::proto::HeaderValue::kText:
        *out = CopyString(value.text());
        return 0;
      case curl::fuzzer::proto::HeaderValue::kBlob: {
        const uint8_t *data = nullptr;
        size_t length = 0;
        int rc = ResolveBlobRef(value.blob(), &data, &length);
        if(rc != 0) {
          return rc;
        }
        *out = CopyString(std::string_view(reinterpret_cast<const char *>(data), length));
        return 0;
      }
      case curl::fuzzer::proto::HeaderValue::VALUE_NOT_SET:
      default:
        *out = CopyString("");
        return 0;
    }
  }

 private:
  std::unordered_map<uint32_t, std::vector<uint8_t>> blobs_;
  std::vector<std::unique_ptr<char[]>> cstrings_;
};

void DestroyScenarioState(void *ptr) {
  delete static_cast<ScenarioState *>(ptr);
}

bool HasStructuredTag(const curl::fuzzer::proto::Scenario &scenario) {
  const auto &metadata = scenario.metadata();
  for(const auto &label : metadata.labels()) {
    if(label == "structured-scenario" || label == "curl-structured") {
      return true;
    }
  }
  const auto &annotations = metadata.annotations();
  auto it = annotations.find("format");
  if(it != annotations.end()) {
    const std::string &value = it->second;
    if(value == "curl-structured" || value == "curl-structured-v1") {
      return true;
    }
  }
  return false;
}

long ProtoToLong(const curl::fuzzer::proto::SetOption &option) {
  if(option.has_int32_value()) {
    return static_cast<long>(option.int32_value());
  }
  if(option.has_uint32_value()) {
    return static_cast<long>(option.uint32_value());
  }
  if(option.has_int64_value()) {
    return static_cast<long>(option.int64_value());
  }
  if(option.has_uint64_value()) {
    return static_cast<long>(option.uint64_value());
  }
  if(option.has_bool_value()) {
    return option.bool_value() ? 1L : 0L;
  }
  if(option.has_double_value()) {
    return static_cast<long>(option.double_value());
  }
  return 0L;
}

curl_off_t ProtoToOffT(const curl::fuzzer::proto::SetOption &option) {
  if(option.has_uint64_value()) {
    return static_cast<curl_off_t>(option.uint64_value());
  }
  if(option.has_int64_value()) {
    return static_cast<curl_off_t>(option.int64_value());
  }
  if(option.has_uint32_value()) {
    return static_cast<curl_off_t>(option.uint32_value());
  }
  if(option.has_int32_value()) {
    return static_cast<curl_off_t>(option.int32_value());
  }
  return static_cast<curl_off_t>(ProtoToLong(option));
}

int EnsureOptionUnset(FUZZ_DATA *fuzz, CURLoption opt, const OptionDescriptor *desc) {
  (void)desc;
  if(fuzz->options[opt % 1000] != 0) {
    return 255;
  }
  return 0;
}

void MarkOptionSet(FUZZ_DATA *fuzz, CURLoption opt) {
  fuzz->options[opt % 1000] = 1;
}

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

int ApplySetOption(const curl::fuzzer::proto::SetOption &option,
                   ScenarioState *state,
                   FUZZ_DATA *fuzz) {
  const OptionDescriptor *desc = LookupDescriptor(option.option_id());
  if(desc == nullptr) {
    return 255;
  }

  int rc = 0;
  switch(desc->kind) {
    case OptionValueKind::kString: {
      const char *value = nullptr;
      if(option.has_string_value()) {
        value = state->CopyString(option.string_value());
      }
      else if(option.has_blob()) {
        const uint8_t *data = nullptr;
        size_t len = 0;
        rc = state->ResolveBlobRef(option.blob(), &data, &len);
        if(rc != 0) {
          return rc;
        }
        value = state->CopyString(std::string_view(reinterpret_cast<const char *>(data), len));
      }
      else {
        value = state->CopyString("");
      }
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      return ApplyStringOption(fuzz, desc, value);
    }
    case OptionValueKind::kUint32: {
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      long value = ProtoToLong(option);
      return ApplyLongOption(fuzz, desc, value);
    }
    case OptionValueKind::kUint64: {
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      curl_off_t value = ProtoToOffT(option);
      return ApplyOffOption(fuzz, desc, value);
    }
    case OptionValueKind::kBool: {
      rc = EnsureOptionUnset(fuzz, desc->curlopt, desc);
      if(rc != 0) {
        return rc;
      }
      long value = option.has_bool_value() ? (option.bool_value() ? 1L : 0L) : ProtoToLong(option);
      return ApplyLongOption(fuzz, desc, value);
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
      return 0;
    }
    case OptionValueKind::kUnknown:
    default:
      return 255;
  }
}

int ApplyHeader(const curl::fuzzer::proto::AddHeader &header,
                ScenarioState *state,
                FUZZ_DATA *fuzz) {
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
  return 0;
}

int ApplyMailRecipient(const curl::fuzzer::proto::AddMailRecipient &recipient,
                       ScenarioState *state,
                       FUZZ_DATA *fuzz) {
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
  return 0;
}

int ApplyRegisterUpload(const curl::fuzzer::proto::RegisterUpload &upload,
                        ScenarioState *state,
                        FUZZ_DATA *fuzz) {
  const uint8_t *data = nullptr;
  size_t length = 0;
  int rc = state->ResolveBlobRef(upload.payload(), &data, &length);
  if(rc != 0) {
    return rc;
  }
  fuzz->upload1_data = data;
  fuzz->upload1_data_len = length;
  fuzz->upload1_data_written = 0;
  const OptionDescriptor *upload_desc = LookupDescriptor(curl::fuzzer::proto::CURLOPT_UPLOAD);
  if(upload_desc != nullptr) {
    rc = EnsureOptionUnset(fuzz, upload_desc->curlopt, upload_desc);
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
    rc = EnsureOptionUnset(fuzz, length_desc->curlopt, length_desc);
    if(rc != 0) {
      return rc;
    }
    return ApplyOffOption(fuzz, length_desc, static_cast<curl_off_t>(length));
  }
  return 0;
}

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
    case curl::fuzzer::proto::MimePart::kBlob: {
      const uint8_t *data = nullptr;
      size_t len = 0;
      int rc = state->ResolveBlobRef(part.blob(), &data, &len);
      if(rc != 0) {
        return rc;
      }
      CURLcode code = curl_mime_data(m, reinterpret_cast<const char *>(data), len);
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

int ApplyConfigureMime(const curl::fuzzer::proto::ConfigureMime &config,
                       ScenarioState *state,
                       FUZZ_DATA *fuzz) {
  if(fuzz->mime == NULL) {
    fuzz->mime = curl_mime_init(fuzz->easy);
    if(fuzz->mime == NULL) {
      return 255;
    }
  }
  for(const auto &part : config.parts()) {
    int rc = ApplyMimePart(part, state, fuzz->mime);
    if(rc != 0) {
      return rc;
    }
  }
  return 0;
}

int ApplyConfigureHttpPost(const curl::fuzzer::proto::ConfigureHttpPost &config,
                           ScenarioState *state,
                           FUZZ_DATA *fuzz) {
  struct curl_httppost *post = NULL;
  struct curl_httppost *last = fuzz->httppost;
  for(const auto &field : config.fields()) {
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
      case curl::fuzzer::proto::FormField::kBlob: {
        const uint8_t *data = nullptr;
        size_t len = 0;
        int rc = state->ResolveBlobRef(field.blob(), &data, &len);
        if(rc != 0) {
          return rc;
        }
        form_rc = curl_formadd(&post, &last,
                               CURLFORM_COPYNAME, name,
                               CURLFORM_PTRCONTENTS, data,
                               CURLFORM_CONTENTLEN, static_cast<curl_off_t>(len),
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
      return 255;
    }
  }
  if(fuzz->httppost == NULL) {
    fuzz->httppost = post;
  }
  else if(post != NULL) {
    fuzz->last_post_part->next = post;
  }
  fuzz->last_post_part = last;
  return 0;
}

int ApplyResponse(const curl::fuzzer::proto::Response &response,
                  ScenarioState *state,
                  FUZZ_RESPONSE *dest) {
  const uint8_t *data = nullptr;
  size_t len = 0;
  int rc = state->ResolveBlobRef(response.payload(), &data, &len);
  if(rc != 0) {
    return rc;
  }
  dest->data = data;
  dest->data_len = len;
  return 0;
}

int ApplyConnections(const google::protobuf::RepeatedPtrField<curl::fuzzer::proto::Connection> &connections,
                     ScenarioState *state,
                     FUZZ_DATA *fuzz) {
  for(const auto &connection : connections) {
    if(connection.id() >= FUZZ_NUM_CONNECTIONS) {
      continue;
    }
    FUZZ_SOCKET_MANAGER *manager = &fuzz->sockman[connection.id()];
    if(connection.has_initial_response()) {
      int rc = ApplyResponse(connection.initial_response(), state, &manager->responses[0]);
      if(rc != 0) {
        return rc;
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
      idx++;
    }
  }
  return 0;
}

int ApplyRegisterResponse(const curl::fuzzer::proto::RegisterResponse &registration,
                          ScenarioState *state,
                          FUZZ_DATA *fuzz) {
  uint32_t id = registration.connection_id();
  if(id >= FUZZ_NUM_CONNECTIONS) {
    return 255;
  }
  FUZZ_SOCKET_MANAGER *manager = &fuzz->sockman[id];
  switch(registration.stage()) {
    case curl::fuzzer::proto::RESPONSE_STAGE_ON_CONNECT:
      return ApplyResponse(registration.response(), state, &manager->responses[0]);
    case curl::fuzzer::proto::RESPONSE_STAGE_ON_READABLE: {
      for(int idx = 1; idx < TLV_MAX_NUM_RESPONSES; ++idx) {
        if(manager->responses[idx].data_len == 0 && manager->responses[idx].data == NULL) {
          return ApplyResponse(registration.response(), state, &manager->responses[idx]);
        }
      }
      return 255;
    }
    case curl::fuzzer::proto::RESPONSE_STAGE_UNSPECIFIED:
    default:
      return 255;
  }
}

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

int ApplyGlobalDefaults(const curl::fuzzer::proto::GlobalConfig &config,
                        ScenarioState *state,
                        FUZZ_DATA *fuzz) {
  for(const auto &option : config.defaults()) {
    int rc = ApplySetOption(option, state, fuzz);
    if(rc != 0) {
      return rc;
    }
  }
  if(!config.allowed_protocols().empty()) {
    std::string protocols;
    for(size_t ii = 0; ii < static_cast<size_t>(config.allowed_protocols_size()); ++ii) {
      if(ii > 0) {
        protocols.append(",");
      }
      protocols.append(config.allowed_protocols(ii));
    }
    const char *value = state->CopyString(protocols);
    CURLcode code = curl_easy_setopt(fuzz->easy, CURLOPT_PROTOCOLS_STR, value);
    if(code != CURLE_OK) {
      return static_cast<int>(code);
    }
  }
  if(config.timeout_ms() != 0) {
    CURLcode code =
        curl_easy_setopt(fuzz->easy, CURLOPT_TIMEOUT_MS, static_cast<long>(config.timeout_ms()));
    if(code != CURLE_OK) {
      return static_cast<int>(code);
    }
  }
  if(config.server_response_timeout_ms() != 0) {
    CURLcode code = curl_easy_setopt(fuzz->easy,
                                     CURLOPT_SERVER_RESPONSE_TIMEOUT,
                                     static_cast<long>(config.server_response_timeout_ms()));
    if(code != CURLE_OK) {
      return static_cast<int>(code);
    }
  }
  if(config.verbose()) {
    CURLcode code = curl_easy_setopt(fuzz->easy, CURLOPT_VERBOSE, 1L);
    if(code != CURLE_OK) {
      return static_cast<int>(code);
    }
  }
  return 0;
}

}  // namespace

bool TryParseScenario(const uint8_t *data,
                      size_t size,
                      curl::fuzzer::proto::Scenario *out) {
  if(size < 2) {
    return false;
  }
  curl::fuzzer::proto::Scenario scenario;
  if(!scenario.ParseFromArray(data, static_cast<int>(size))) {
    return false;
  }
  if(!HasStructuredTag(scenario) &&
     scenario.actions_size() == 0 &&
     scenario.connections_size() == 0 &&
     scenario.blobs_size() == 0) {
    return false;
  }
  out->Swap(&scenario);
  return true;
}

int ApplyScenario(const curl::fuzzer::proto::Scenario &scenario,
                  FUZZ_DATA *fuzz) {
  auto state = std::make_unique<ScenarioState>();
  int rc = state->LoadBlobs(scenario);
  if(rc != 0) {
    return rc;
  }
  rc = ApplyGlobalDefaults(scenario.global(), state.get(), fuzz);
  if(rc != 0) {
    return rc;
  }
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
