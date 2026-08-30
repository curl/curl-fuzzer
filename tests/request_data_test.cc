/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/scenario_limits.h"

#include <curl/curl.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

void Fail(const char *message) {
  std::cerr << message << '\n';
  std::exit(1);
}

void Expect(bool condition, const char *message) {
  if (!condition) {
    Fail(message);
  }
}

void PopulatePart(curl::fuzzer::proto::MimeDataPart *part) {
  part->set_name("child");
  part->set_data("binary\0data", 11);
  part->set_filename("child.bin");
  part->set_content_type("application/octet-stream");
  part->set_encoder(curl::fuzzer::proto::MIME_ENCODER_BASE64);
  for (int i = 0; i < 12; ++i) {
    part->add_headers("X-Child-Header: " + std::to_string(i));
  }
}

void TestConstructionBudgetsAndOwnership() {
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed");

  curl::fuzzer::proto::Scenario scenario;
  for (std::size_t i = 0;
       i < proto_fuzzer::scenario_limits::kMaxRequestHeaders + 8; ++i) {
    scenario.add_request_headers("X-Request-Header: " + std::to_string(i));
  }
  for (std::size_t i = 0;
       i < proto_fuzzer::scenario_limits::kMaxTopLevelMimeParts + 24; ++i) {
    auto *part = scenario.mutable_mime_post()->add_parts();
    part->set_name("parent");
    part->set_filename("parent.txt");
    part->set_content_type("multipart/mixed");
    part->set_encoder(curl::fuzzer::proto::MIME_ENCODER_QUOTED_PRINTABLE);
    for (std::size_t j = 0;
         j < proto_fuzzer::scenario_limits::kMaxMimeHeadersPerPart + 4; ++j) {
      part->add_headers("X-Parent-Header: " + std::to_string(j));
    }
    for (std::size_t j = 0;
         j < proto_fuzzer::scenario_limits::kMaxNestedMimeParts + 4; ++j) {
      PopulatePart(part->mutable_subparts()->add_parts());
    }
  }

  {
    proto_fuzzer::ScenarioRequestData request_data(easy, scenario);
    const auto &stats = request_data.stats();
    Expect(stats.request_headers ==
               proto_fuzzer::scenario_limits::kMaxRequestHeaders,
           "request header budget changed");
    Expect(stats.mime_parts ==
               proto_fuzzer::scenario_limits::kMaxTotalMimeParts,
           "total MIME part budget changed");
    const std::size_t expected_mime_headers =
        proto_fuzzer::scenario_limits::kMaxTotalMimeParts *
        proto_fuzzer::scenario_limits::kMaxMimeHeadersPerPart;
    Expect(stats.mime_headers == expected_mime_headers,
           "per-part MIME header budget changed");
  }

  // Destruction above detaches both pointer options before freeing them. Easy
  // cleanup under ASan/UBSan therefore also regression-tests the ownership
  // order without requiring a network transfer in this focused unit test.
  curl_easy_cleanup(easy);
}

void TestFallbackUploadRemainsDeterministic() {
  curl::fuzzer::proto::Scenario scenario;
  proto_fuzzer::UploadScriptState state(scenario);

  Expect(!state.scripted(), "absent upload did not select fallback");
  Expect(state.data_size() == proto_fuzzer::scenario_limits::kMaxUploadBytes,
         "fallback upload size changed");
  Expect(state.read_step_count() == 0,
         "fallback upload unexpectedly acquired read steps");

  char bytes[9] = {};
  Expect(state.Read(bytes, sizeof(bytes)) == sizeof(bytes),
         "fallback upload returned a short first read");
  Expect(std::memcmp(bytes, "UUUUUUUUU", sizeof(bytes)) == 0,
         "fallback upload byte pattern changed");
  Expect(state.Seek(0, SEEK_SET) == CURL_SEEKFUNC_CANTSEEK,
         "fallback upload unexpectedly became rewindable");
}

void TestTelnetWithoutUploadUsesImmediateEof() {
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed for TELNET callback policy");

  curl::fuzzer::proto::Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_TELNET);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, scenario);
    Expect(request_data.upload_callbacks_installed(),
           "TELNET did not replace curl's stdin read path");
    Expect(!request_data.upload_state().scripted(),
           "absent TELNET upload unexpectedly became scripted");
    Expect(request_data.upload_state().data_size() == 0,
           "absent TELNET upload retained compatibility fallback bytes");
  }

  proto_fuzzer::UploadScriptState state(scenario);
  char byte = 0;
  Expect(state.Read(&byte, 1) == 0,
         "absent TELNET upload did not report immediate EOF");
  curl_easy_cleanup(easy);
}

void TestPauseTerminalIsTelnetOnly() {
  curl::fuzzer::proto::Scenario telnet;
  telnet.set_scheme(curl::fuzzer::proto::SCHEME_TELNET);
  telnet.mutable_upload()->set_terminal(
      curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE);
  proto_fuzzer::UploadScriptState telnet_state(telnet);
  char byte = 0;
  Expect(telnet_state.Read(&byte, 1) == CURL_READFUNC_PAUSE,
         "TELNET pause terminal was not surfaced");

  curl::fuzzer::proto::Scenario http;
  http.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  http.mutable_upload()->set_terminal(
      curl::fuzzer::proto::UPLOAD_TERMINAL_PAUSE);
  proto_fuzzer::UploadScriptState http_state(http);
  Expect(http_state.Read(&byte, 1) == 0,
         "non-TELNET pause survived the runtime safety boundary");
}

void TestTelnetUploadUsesWorkAndWriteCaps() {
  curl::fuzzer::proto::Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_TELNET);
  auto *upload = scenario.mutable_upload();
  upload->set_data(std::string(
      proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes + 17, '\xff'));
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxTelnetUploadReadSteps + 3;
       ++index) {
    upload->add_read_sizes(std::numeric_limits<std::uint32_t>::max());
  }

  proto_fuzzer::UploadScriptState state(scenario);
  Expect(state.scripted(), "TELNET upload did not select scripted bytes");
  Expect(state.data_size() ==
             proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes,
         "TELNET upload exceeded its total work cap");
  Expect(state.read_step_count() ==
             proto_fuzzer::scenario_limits::kMaxTelnetUploadReadSteps,
         "TELNET runtime exceeded its fragmentation-step budget");

  std::vector<char> retained(
      proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes + 17);
  const std::size_t first = state.Read(retained.data(), retained.size());
  Expect(first <= proto_fuzzer::scenario_limits::kMaxTelnetUploadReadSize,
         "TELNET callback exceeded its per-write cap");
  Expect(first == proto_fuzzer::scenario_limits::kMaxTelnetUploadBytes,
         "unfragmented TELNET upload retained callback-invisible work");
  Expect(std::memcmp(retained.data(), upload->data().data(), first) == 0,
         "TELNET upload cap changed the retained prefix");
  Expect(state.Read(retained.data(), retained.size()) == 0,
         "TELNET upload exposed bytes beyond its total work cap");
}

void TestTelnetOptionConstructionBudgetsAndOwnership() {
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed for TELNET options");

  curl::fuzzer::proto::Scenario scenario;
  scenario.set_scheme(curl::fuzzer::proto::SCHEME_TELNET);
  for (std::size_t index = 0;
       index < proto_fuzzer::scenario_limits::kMaxTelnetOptions + 3; ++index) {
    scenario.add_telnet_options(std::string(
        proto_fuzzer::scenario_limits::kMaxTelnetOptionBytes + 17, 't'));
  }
  {
    // libcurl has no CURLINFO getter for CURLOPT_TELNETOPTIONS, so sanitizers
    // enforce the ownership contract while the cap is checked via stats.
    proto_fuzzer::ScenarioRequestData request_data(easy, scenario);
    Expect(request_data.stats().telnet_options ==
               proto_fuzzer::scenario_limits::kMaxTelnetOptions,
           "TELNET option list exceeded its runtime count budget");
  }

  curl::fuzzer::proto::Scenario http;
  http.set_scheme(curl::fuzzer::proto::SCHEME_HTTP);
  http.add_telnet_options("TTYPE=must-not-be-applied");
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, http);
    Expect(request_data.stats().telnet_options == 0,
           "non-TELNET scenario built a protocol-inert retained slist");
  }

  // Destruction must detach CURLOPT_TELNETOPTIONS before freeing the slist;
  // easy cleanup under ASan catches a dangling pointer regression.
  curl_easy_cleanup(easy);
}

void TestScriptedReadSequenceCapsAndAbort() {
  curl::fuzzer::proto::Scenario scenario;
  auto *upload = scenario.mutable_upload();
  upload->set_data("abcdef");
  upload->add_read_sizes(2);
  upload->add_read_sizes(0);
  upload->add_read_sizes(3);
  upload->set_terminal(curl::fuzzer::proto::UPLOAD_TERMINAL_ABORT);

  proto_fuzzer::UploadScriptState state(scenario);
  char bytes[8] = {};
  Expect(state.Read(bytes, sizeof(bytes)) == 2 &&
             std::memcmp(bytes, "ab", 2) == 0,
         "first scripted short read was not retained");
  Expect(state.Read(bytes, sizeof(bytes)) == 1 && bytes[0] == 'c',
         "zero read size did not canonicalize to one byte");
  Expect(state.Read(bytes, sizeof(bytes)) == 3 &&
             std::memcmp(bytes, "def", 3) == 0,
         "third scripted short read was not retained");
  Expect(state.Read(bytes, sizeof(bytes)) == CURL_READFUNC_ABORT,
         "scripted terminal abort was not surfaced");

  curl::fuzzer::proto::Scenario oversized;
  auto *oversized_upload = oversized.mutable_upload();
  oversized_upload->set_data(
      std::string(proto_fuzzer::scenario_limits::kMaxUploadBytes + 9, 'x'));
  for (std::size_t i = 0;
       i < proto_fuzzer::scenario_limits::kMaxUploadReadSteps + 9; ++i) {
    oversized_upload->add_read_sizes(static_cast<std::uint32_t>(
        proto_fuzzer::scenario_limits::kMaxUploadReadSize + 1));
  }
  proto_fuzzer::UploadScriptState capped(oversized);
  Expect(capped.data_size() == proto_fuzzer::scenario_limits::kMaxUploadBytes,
         "runtime retained upload bytes beyond the cap");
  Expect(capped.read_step_count() ==
             proto_fuzzer::scenario_limits::kMaxUploadReadSteps,
         "runtime retained upload read steps beyond the cap");

  std::vector<char> retained(proto_fuzzer::scenario_limits::kMaxUploadBytes);
  Expect(capped.Read(retained.data(), retained.size()) == retained.size(),
         "runtime did not expose the capped upload prefix");
  Expect(std::memcmp(retained.data(), oversized_upload->data().data(),
                     retained.size()) == 0,
         "compatibility upload truncation changed the retained prefix");
  Expect(capped.Read(retained.data(), retained.size()) == 0,
         "bytes beyond the upload cap became callback-visible");
}

void TestScriptedUploadBorrowsScenarioStorage() {
  curl::fuzzer::proto::Scenario scenario;
  std::string *payload = scenario.mutable_upload()->mutable_data();
  *payload = "borrowed";

  proto_fuzzer::UploadScriptState state(scenario);
  // Changing one byte cannot reallocate std::string storage. This focused
  // probe demonstrates that the callback state views the Scenario-owned bytes
  // instead of making the per-iteration copy this optimization removes. The
  // production runner itself keeps the Scenario immutable for the full drive.
  (*payload)[0] = 'B';

  char bytes[8] = {};
  Expect(state.Read(bytes, sizeof(bytes)) == sizeof(bytes) &&
             std::memcmp(bytes, "Borrowed", sizeof(bytes)) == 0,
         "scripted upload did not borrow Scenario storage");
}

void TestScriptedSeekOutcomes() {
  curl::fuzzer::proto::Scenario scenario;
  auto *upload = scenario.mutable_upload();
  upload->set_data("abcdef");
  upload->add_read_sizes(3);
  upload->set_seek_result(curl::fuzzer::proto::UPLOAD_SEEK_OK);

  proto_fuzzer::UploadScriptState rewindable(scenario);
  char bytes[8] = {};
  Expect(rewindable.Read(bytes, sizeof(bytes)) == 3,
         "rewindable source did not consume its first step");
  Expect(rewindable.Seek(0, SEEK_SET) == CURL_SEEKFUNC_OK &&
             rewindable.offset() == 0,
         "rewind-to-zero failed");
  Expect(rewindable.Read(bytes, sizeof(bytes)) == 3 &&
             std::memcmp(bytes, "abc", 3) == 0,
         "rewind did not restart callback fragmentation");
  Expect(rewindable.Seek(-2, SEEK_END) == CURL_SEEKFUNC_OK &&
             rewindable.offset() == 4,
         "bounded seek from end failed");
  Expect(rewindable.Seek(1, SEEK_END) == CURL_SEEKFUNC_FAIL &&
             rewindable.offset() == 4,
         "out-of-range seek changed the cursor");
  Expect(rewindable.Seek(0, 99) == CURL_SEEKFUNC_FAIL,
         "invalid seek origin was accepted");

  upload->set_seek_result(curl::fuzzer::proto::UPLOAD_SEEK_CANTSEEK);
  proto_fuzzer::UploadScriptState cannot_seek(scenario);
  Expect(cannot_seek.Seek(0, SEEK_SET) == CURL_SEEKFUNC_CANTSEEK,
         "CANTSEEK outcome was not surfaced");

  upload->set_seek_result(curl::fuzzer::proto::UPLOAD_SEEK_FAIL);
  proto_fuzzer::UploadScriptState failing_seek(scenario);
  Expect(failing_seek.Seek(0, SEEK_SET) == CURL_SEEKFUNC_FAIL,
         "FAIL seek outcome was not surfaced");
}

void TestOptionValueCasesFollowTheGeneratedManifest() {
  curl::fuzzer::proto::Scenario scenario;

  auto *string_option = scenario.add_options();
  string_option->set_option_id(curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST);
  string_option->set_uint_value(42);

  auto *uint_option = scenario.add_options();
  uint_option->set_option_id(curl::fuzzer::proto::CURLOPT_MAXREDIRS);
  uint_option->set_bool_value(true);

  auto *bool_option = scenario.add_options();
  bool_option->set_option_id(curl::fuzzer::proto::CURLOPT_NOBODY);
  bool_option->set_uint_value(7);

  auto *correct_mode = scenario.add_options();
  correct_mode->set_option_id(curl::fuzzer::proto::CURLOPT_HTTPAUTH);
  correct_mode->set_uint_value(2);

  auto *unknown = scenario.add_options();
  unknown->set_option_id(curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED);
  unknown->set_string_value("mutation sentinel");

  proto_fuzzer::CanonicalizeOptionValueCases(&scenario);

  Expect(scenario.options(0).value_case() ==
                 curl::fuzzer::proto::SetOption::kStringValue &&
             scenario.options(0).string_value().empty(),
         "string option retained a runtime-invisible oneof member");
  Expect(scenario.options(1).value_case() ==
                 curl::fuzzer::proto::SetOption::kUintValue &&
             scenario.options(1).uint_value() == 1,
         "boolean representation lost its numeric truth value");
  Expect(scenario.options(2).value_case() ==
                 curl::fuzzer::proto::SetOption::kBoolValue &&
             scenario.options(2).bool_value(),
         "non-zero integer representation lost its boolean truth value");
  Expect(scenario.options(3).value_case() ==
                 curl::fuzzer::proto::SetOption::kUintValue &&
             scenario.options(3).uint_value() == 2,
         "correctly typed option changed during canonicalization");
  Expect(scenario.options(4).value_case() ==
                 curl::fuzzer::proto::SetOption::kStringValue &&
             scenario.options(4).string_value() == "mutation sentinel",
         "unknown option lost its mutation path to a supported id");
}

void TestIntegralOptionDecoderUsesGeneratedKinds() {
  const std::uint64_t all_bits = ~std::uint64_t{0};

  curl::fuzzer::proto::SetOption integer_from_bool;
  integer_from_bool.set_option_id(curl::fuzzer::proto::CURLOPT_MAXREDIRS);
  integer_from_bool.set_bool_value(true);
  Expect(proto_fuzzer::DecodeIntegralOptionValue(integer_from_bool) == 1,
         "integer option did not convert true to one");

  curl::fuzzer::proto::SetOption integer_from_uint;
  integer_from_uint.set_option_id(curl::fuzzer::proto::CURLOPT_HTTPAUTH);
  integer_from_uint.set_uint_value(all_bits);
  Expect(proto_fuzzer::DecodeIntegralOptionValue(integer_from_uint) == all_bits,
         "integer option did not preserve its full-width value");

  curl::fuzzer::proto::SetOption boolean_from_uint;
  boolean_from_uint.set_option_id(curl::fuzzer::proto::CURLOPT_NOBODY);
  boolean_from_uint.set_uint_value(all_bits);
  Expect(proto_fuzzer::DecodeIntegralOptionValue(boolean_from_uint) == 1,
         "boolean option did not normalize a non-zero integer");
  boolean_from_uint.set_uint_value(0);
  Expect(proto_fuzzer::DecodeIntegralOptionValue(boolean_from_uint) == 0,
         "boolean option did not preserve integer zero");

  curl::fuzzer::proto::SetOption non_integral;
  non_integral.set_option_id(curl::fuzzer::proto::CURLOPT_MAXREDIRS);
  non_integral.set_string_value("not an integer");
  Expect(proto_fuzzer::DecodeIntegralOptionValue(non_integral) == 0,
         "non-integral oneof arm did not use the scalar default");

  curl::fuzzer::proto::SetOption string_option;
  string_option.set_option_id(curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST);
  string_option.set_uint_value(42);
  Expect(proto_fuzzer::DecodeIntegralOptionValue(string_option) == 0,
         "string descriptor unexpectedly acquired an integral value");
}

void TestSetOptionDecodesIntegralRepresentations() {
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed for scalar option decoding");

  curl::fuzzer::proto::SetOption nobody;
  nobody.set_option_id(curl::fuzzer::proto::CURLOPT_NOBODY);
  nobody.set_uint_value(7);
  Expect(proto_fuzzer::ApplySetOption(easy, nobody) == CURLE_OK,
         "integer representation of a boolean option was rejected");

  const char *effective_method = nullptr;
  Expect(curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_METHOD,
                           &effective_method) == CURLE_OK &&
             effective_method != nullptr &&
             std::strcmp(effective_method, "HEAD") == 0,
         "non-zero integer representation did not enable a boolean option");

  nobody.set_uint_value(0);
  Expect(proto_fuzzer::ApplySetOption(easy, nobody) == CURLE_OK,
         "zero integer representation of a boolean option was rejected");
  Expect(curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_METHOD,
                           &effective_method) == CURLE_OK &&
             effective_method != nullptr &&
             std::strcmp(effective_method, "GET") == 0,
         "zero integer representation did not disable a boolean option");

  curl_easy_cleanup(easy);
}

void TestSetOptionBorrowsBinaryPostFields() {
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed for option application");

  curl::fuzzer::proto::Scenario scenario;
  auto *postfields = scenario.add_options();
  postfields->set_option_id(curl::fuzzer::proto::CURLOPT_POSTFIELDS);
  postfields->set_string_value("alpha\0beta", 10);

  Expect(proto_fuzzer::ApplySetOption(easy, *postfields) == CURLE_OK,
         "binary POSTFIELDS option was rejected");

  curl::fuzzer::proto::SetOption unknown;
  unknown.set_option_id(curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED);
  Expect(proto_fuzzer::ApplySetOption(easy, unknown) == CURLE_UNKNOWN_OPTION,
         "unknown option unexpectedly resolved through the generated switch");

  // The easy handle is deliberately destroyed while the protobuf owner still
  // exists. Under ASan this protects the borrowing contract and, unlike the
  // old vector-backed API, needs no parallel lifetime container.
  curl_easy_cleanup(easy);
}

void TestCompatibilityOptionSuffixIsRuntimeInvisible() {
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed for runtime option bound");

  curl::fuzzer::proto::Scenario scenario;
  for (std::size_t i = 0; i + 1 < proto_fuzzer::scenario_limits::kMaxOptions;
       ++i) {
    auto *option = scenario.add_options();
    option->set_option_id(curl::fuzzer::proto::CURLOPT_HTTPGET);
    option->set_bool_value(true);
  }
  auto *retained_method = scenario.add_options();
  retained_method->set_option_id(curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST);
  retained_method->set_string_value("retained-method");

  auto *ignored_method = scenario.add_options();
  ignored_method->set_option_id(curl::fuzzer::proto::CURLOPT_CUSTOMREQUEST);
  ignored_method->set_string_value("ignored-method");
  auto *ignored_upload = scenario.add_options();
  ignored_upload->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  ignored_upload->set_bool_value(true);

  Expect(proto_fuzzer::ApplyScenarioOptions(easy, scenario) ==
             proto_fuzzer::scenario_limits::kMaxOptions,
         "runtime attempted options beyond the shared cap");
  const char *effective_method = nullptr;
  Expect(curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_METHOD,
                           &effective_method) == CURLE_OK &&
             effective_method != nullptr &&
             std::strcmp(effective_method, "retained-method") == 0,
         "option suffix overrode the retained runtime prefix");

  {
    proto_fuzzer::ScenarioRequestData request_data(easy, scenario);
    Expect(!request_data.upload_callbacks_installed(),
           "ignored option suffix changed request callback setup");
  }

  curl_easy_cleanup(easy);
}

void TestEmptyAndNullInputsRemainCheap() {
  curl::fuzzer::proto::Scenario scenario;
  scenario.mutable_mime_post();

  proto_fuzzer::ScenarioRequestData null_request_data(nullptr, scenario);
  Expect(null_request_data.stats().request_headers == 0,
         "null easy handle constructed headers");
  Expect(null_request_data.stats().mime_parts == 0,
         "null easy handle constructed MIME parts");
  Expect(!null_request_data.upload_callbacks_installed(),
         "null easy handle installed upload callbacks");

  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed for empty scenario");
  {
    proto_fuzzer::ScenarioRequestData empty_request_data(easy, scenario);
    Expect(empty_request_data.stats().mime_parts == 0,
           "empty MIME body constructed a part");
    Expect(!empty_request_data.upload_callbacks_installed(),
           "ordinary request installed raw upload callbacks");
  }
  curl_easy_cleanup(easy);
}

void TestUploadCallbackInstallationIsDemandDriven() {
  CURL *easy = curl_easy_init();
  Expect(easy != nullptr, "curl_easy_init failed for callback policy");

  curl::fuzzer::proto::Scenario scripted;
  scripted.mutable_upload()->set_data("body");
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, scripted);
    Expect(request_data.upload_callbacks_installed(),
           "scripted upload did not install callbacks");
  }

  curl::fuzzer::proto::Scenario option_only;
  auto *upload_option = option_only.add_options();
  upload_option->set_option_id(curl::fuzzer::proto::CURLOPT_UPLOAD);
  upload_option->set_bool_value(false);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, option_only);
    Expect(request_data.upload_callbacks_installed(),
           "upload option lost the non-blocking fallback callbacks");
    Expect(!request_data.upload_state().scripted(),
           "upload option without a script stopped using fallback bytes");
  }

  curl::fuzzer::proto::Scenario post_only;
  auto *post_option = post_only.add_options();
  post_option->set_option_id(curl::fuzzer::proto::CURLOPT_POST);
  post_option->set_bool_value(false);
  {
    proto_fuzzer::ScenarioRequestData request_data(easy, post_only);
    Expect(request_data.upload_callbacks_installed(),
           "POST option lost its non-blocking fallback callbacks");
    Expect(!request_data.upload_state().scripted(),
           "POST option without a script stopped using fallback bytes");
  }

  curl_easy_cleanup(easy);
}

} // namespace

int main() {
  Expect(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK,
         "curl_global_init failed");
  TestConstructionBudgetsAndOwnership();
  TestEmptyAndNullInputsRemainCheap();
  TestUploadCallbackInstallationIsDemandDriven();
  TestFallbackUploadRemainsDeterministic();
  TestTelnetWithoutUploadUsesImmediateEof();
  TestPauseTerminalIsTelnetOnly();
  TestTelnetUploadUsesWorkAndWriteCaps();
  TestTelnetOptionConstructionBudgetsAndOwnership();
  TestScriptedReadSequenceCapsAndAbort();
  TestScriptedUploadBorrowsScenarioStorage();
  TestScriptedSeekOutcomes();
  TestOptionValueCasesFollowTheGeneratedManifest();
  TestIntegralOptionDecoderUsesGeneratedKinds();
  TestSetOptionDecodesIntegralRepresentations();
  TestSetOptionBorrowsBinaryPostFields();
  TestCompatibilityOptionSuffixIsRuntimeInvisible();
  curl_global_cleanup();
  return 0;
}
