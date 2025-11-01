#ifndef CURL_FUZZER_SCENARIO_H_
#define CURL_FUZZER_SCENARIO_H_

#include <cstddef>
#include <cstdint>

#include "curl_fuzzer.h"
#include "curl_fuzzer.pb.h"

namespace curl_fuzzer {

// Attempt to parse the input buffer as a structured Scenario proto. Returns
// true on success and writes the decoded scenario to |out|. The parsed data is
// independent of the original buffer once this function returns.
bool TryParseScenario(const uint8_t *data,
                      size_t size,
                      curl::fuzzer::proto::Scenario *out);

// Apply a decoded Scenario onto the existing FUZZ_DATA setup. On success the
// FUZZ_DATA instance is ready for curl option setup (fuzz_set_easy_options) and
// subsequent execution. Returns 0 on success, or a non-zero error code that
// matches the legacy TLV error semantics.
int ApplyScenario(const curl::fuzzer::proto::Scenario &scenario,
                  FUZZ_DATA *fuzz);

}  // namespace curl_fuzzer

#endif  // CURL_FUZZER_SCENARIO_H_
