/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Owns an easy handle and the backing storage retained by its options.

#ifndef PROTO_FUZZER_TRANSFER_SESSION_H_
#define PROTO_FUZZER_TRANSFER_SESSION_H_

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/curl_raii.h"
#include "proto_fuzzer/request_data.h"
#include "proto_fuzzer/target_profile.h"

namespace proto_fuzzer {

class ApiLifecycle;

/// Own per-transfer resources with one teardown contract: detach request
/// callbacks and lists, clean the easy, then release share state, baseline
/// lists, and parser files. The installed peer and any borrowed Scenario must
/// outlive this session. Multi owners must remove the easy before Close().
/// Sessions cannot move because callbacks retain addresses of their state.
class TransferSession {
 public:
  TransferSession();
  ~TransferSession();

  TransferSession(const TransferSession&) = delete;
  TransferSession& operator=(const TransferSession&) = delete;
  TransferSession(TransferSession&&) = delete;
  TransferSession& operator=(TransferSession&&) = delete;

  bool Initialize();

  CURL* easy() const;

  void ApplyBaseline(curl::fuzzer::proto::Scheme scheme, bool trace_ids = false);

  bool ResetConfiguration();

  bool PrepareInputFiles(const curl::fuzzer::proto::Scenario& scenario, ScenarioRunMode mode);

  void ApplyInputFiles();

  void ConfigureAltSvcRouting(const std::string& host_path);

  ScenarioRequestData* InstallRequestData(const curl::fuzzer::proto::Scenario& scenario,
                                          bool apply_resolve_entries = false);
  ScenarioRequestData* InstallRequestData(curl::fuzzer::proto::Scenario&&, bool = false) = delete;
  ScenarioRequestData* InstallRequestData(const curl::fuzzer::proto::Scenario&&, bool = false) = delete;

  ApiLifecycle* InstallApiLifecycle(const curl::fuzzer::proto::ApiPlan& plan, std::string_view url);
  ApiLifecycle* InstallApiLifecycle(curl::fuzzer::proto::ApiPlan&&, std::string_view) = delete;
  ApiLifecycle* InstallApiLifecycle(const curl::fuzzer::proto::ApiPlan&&, std::string_view) = delete;

  void Close();

 private:
  struct ParserInputs;

  std::unique_ptr<ParserInputs> parser_inputs_;
  CurlSlistPtr connect_to_;
  CurlSlistPtr altsvc_resolve_;
  std::unique_ptr<ApiLifecycle> api_lifecycle_;
  CurlEasyPtr easy_;
  std::optional<ScenarioRequestData> request_data_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_TRANSFER_SESSION_H_
