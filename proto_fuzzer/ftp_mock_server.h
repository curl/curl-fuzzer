/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Command-aware in-process peer for curl's FTP state machine.

#ifndef PROTO_FUZZER_FTP_MOCK_SERVER_H_
#define PROTO_FUZZER_FTP_MOCK_SERVER_H_

#include <curl/curl.h>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

#include "curl_fuzzer.pb.h"
#include "proto_fuzzer/mock_server_base.h"
#include "proto_fuzzer/scenario_limits.h"

namespace proto_fuzzer {

/// @class proto_fuzzer::FtpMockServer
/// @brief Keeps FTP's control and passive/active data connections alive.
///
/// FTP cannot use the generic one-script-per-socket HTTP peer: curl opens a
/// passive data socket while it still needs the control socket for TYPE,
/// SIZE, RETR/STOR, and the final transfer reply. This peer therefore treats
/// Scenario.connection as a command-aligned control script and the bounded
/// subsequent_connections prefix as data streams. Passive transfers use
/// socketpairs; active transfers let curl create a loopback listener and have
/// the mock connect to it after observing the generated PORT/EPRT command.
/// All work remains
/// in-process and non-waiting so malformed scripts terminate by operation
/// budget or EOF rather than by curl's FTP response timeout.
class FtpMockServer final : public MockServerBase {
 public:
  FtpMockServer();

  ~FtpMockServer() override;

  const std::string& control_transcript() const;

  const std::string& uploaded_data() const;

  std::size_t opened_data_connection_count() const;

 protected:
  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;

  SocketSetupDisposition GetSocketSetupDisposition(curl_socket_t curlfd, curlsocktype purpose) const override;

  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// Direction determines whether a data peer should be preloaded and
  /// half-closed for a download or kept readable while curl uploads to it.
  enum class TransferDirection {
    kNone,
    kDownload,
    kUpload,
  };

  /// One passive or active socket and its borrowed script must outlive the control
  /// command that starts it. A fixed array keeps protobuf repetition from
  /// turning into an unbounded collection of live descriptors.
  struct DataChannel {
    /// Scenario-owned bytes remain stable throughout the synchronous drive.
    const curl::fuzzer::proto::Connection* script = nullptr;
    /// The server half stays owned after curl receives the client fd.
    std::unique_ptr<MockConnection> connection;
    /// Connecting side of an active-mode TCP data channel. This remains -1
    /// for passive socketpairs and until the PORT/EPRT command is accepted.
    int active_fd = -1;
    /// EPSV/PASV may open the socket well before RETR/STOR makes data valid.
    bool transfer_started = false;
    /// Upload peers are drained on every outer-loop turn.
    bool upload = false;
  };

  void ResetForScenario(const curl::fuzzer::proto::Scenario& scenario);

  static void ApplyScriptBackpressure(MockConnection* connection, const curl::fuzzer::proto::Connection& script);

  bool ServiceControlConnection();

  bool ServiceUploadConnections();

  void HandleControlCommand(std::string_view command);

  void StartNextTransfer(TransferDirection direction);

  void PreloadDownload(DataChannel* channel);

  bool UsesActiveMode() const;

  curl_socket_t OpenActiveListener(struct curl_sockaddr* address);

  void ConnectActiveDataChannel();

  void CloseActiveDescriptors();

  static bool WriteActiveBytes(int fd, const unsigned char* data, std::size_t size);

  static bool ReadActiveBytes(int fd, std::string* output);

  void QueueTransferCompletion();

  const std::string* NextControlReply();

  bool WriteControlBytes(std::string_view bytes);

  static std::string_view CommandVerb(std::string_view command);

  static bool VerbEquals(std::string_view verb, std::string_view expected_uppercase);

  static TransferDirection DirectionForVerb(std::string_view verb);

  bool IsConfiguredCustomDownload(std::string_view verb) const;

  static int FirstReplyCode(std::string_view response);

  static bool TailNeedsOnlyNewline(std::string_view response);

  static void CapturePrefix(std::string_view source, std::size_t limit, std::string* destination);

  void FinishConnections(bool completed);

  /// Three data sockets cover listing plus two file transfers while
  /// matching the repository-wide four-connection scenario budget.
  static constexpr std::size_t kMaxDataChannels = scenario_limits::kMaxConnections - 1;

  /// Observability must not grow with a future curl command loop; these caps
  /// exceed current normalized URL/upload budgets without affecting protocol
  /// processing or socket draining.
  static constexpr std::size_t kMaxCapturedControlBytes = 64 * 1024;
  static constexpr std::size_t kMaxCapturedUploadBytes = 2 * scenario_limits::kMaxUploadBytes;

  /// Borrowed only while RunLoop is active, including every socket callback.
  const curl::fuzzer::proto::Scenario* scenario_;
  /// Curl records the callback's original IP destination before accepting our
  /// already-connected descriptor, so an AF_UNIX pair can drive EPSV/PASV
  /// without paying for a TCP handshake on every fuzz iteration.
  std::unique_ptr<MockConnection> control_connection_;
  /// Fixed passive peer storage keeps control and data descriptors concurrent.
  std::array<DataChannel, kMaxDataChannels> data_channels_;
  /// Number of subsequent scripts already assigned to curl-opened sockets.
  std::size_t next_data_script_;
  /// Duplicate of curl's pending active listener. The duplicate observes the
  /// same bind/listen state but is never handed to libcurl.
  int active_listener_fd_;
  /// Non-owning identity of the matching descriptor handed to curl. It marks
  /// the one IPCXN socket that still needs curl's ordinary bind/listen setup.
  curl_socket_t active_listener_client_fd_;
  /// Channel awaiting the server-side connect, or kMaxDataChannels when none.
  std::size_t pending_active_channel_;
  /// Runtime-visible prefix of primary on_readable response fragments.
  std::size_t control_reply_count_;
  /// Cursor advanced once per command, plus once per accepted transfer final.
  std::size_t next_control_reply_;
  /// Partial command bytes retained until curl supplies a newline.
  std::string pending_control_bytes_;
  /// Bounded test-facing record of complete commands sent by curl.
  std::string control_transcript_;
  /// Bounded test-facing prefix of bytes drained from upload peers.
  std::string uploaded_data_;
  /// Prevent a second control socket from displacing the live first one.
  bool control_opened_;
};

}  // namespace proto_fuzzer

#endif  // PROTO_FUZZER_FTP_MOCK_SERVER_H_
