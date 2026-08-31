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
/// @brief Keeps FTP's control and passive-data connections alive together.
///
/// FTP cannot use the generic one-script-per-socket HTTP peer: curl opens a
/// passive data socket while it still needs the control socket for TYPE,
/// SIZE, RETR/STOR, and the final transfer reply. This peer therefore treats
/// Scenario.connection as a command-aligned control script and the bounded
/// subsequent_connections prefix as passive data streams. All work remains
/// in-process and non-waiting so malformed scripts terminate by operation
/// budget or EOF rather than by curl's FTP response timeout.
class FtpMockServer final : public MockServerBase {
 public:
  /// Construct an idle server. RunLoop borrows a Scenario only for the
  /// synchronous DriveScenario call in which socket callbacks can run.
  FtpMockServer();

  /// Release every socketpair peer after curl has returned its client fds.
  ~FtpMockServer() override;

  /// Expose commands sent by curl so tests can verify that a seed reached the
  /// intended FTP states without coupling assertions to curl debug output.
  /// The capture is bounded independently of protocol processing.
  /// @return A prefix of complete control commands, including line endings.
  const std::string& control_transcript() const;

  /// Expose a bounded prefix of uploaded data while continuing to drain all
  /// client bytes, preventing test observability from creating backpressure.
  /// @return Bytes curl sent over passive upload connections.
  const std::string& uploaded_data() const;

  /// Let tests distinguish control-only failures from paths that reached
  /// curl's passive connection setup.
  /// @return Number of bounded passive socketpairs handed to curl.
  std::size_t opened_data_connection_count() const;

 protected:
  /// Assign the first socket to the control script and later sockets to at
  /// most three passive data scripts. The callback arguments are deliberately
  /// ignored: FTPPORT is excluded by target policy, while socketpairs are
  /// already connected for both EPSV and PASV paths.
  curl_socket_t HandleOpenSocket(curlsocktype purpose = CURLSOCKTYPE_IPCXN,
                                 struct curl_sockaddr* address = nullptr) override;

  /// Drive curl and the command-aware peer in alternating, bounded turns.
  /// @param multi Multi handle containing `easy`.
  /// @param easy Easy handle already installed on this mock.
  /// @param scenario Control and passive-data scripts to borrow.
  void RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) override;

 private:
  /// Direction determines whether a passive peer should be preloaded and
  /// half-closed for a download or kept readable while curl uploads to it.
  enum class TransferDirection {
    kNone,
    kDownload,
    kUpload,
  };

  /// One passive socket and its borrowed script must outlive the control
  /// command that starts it. A fixed array keeps protobuf repetition from
  /// turning into an unbounded collection of live descriptors.
  struct DataChannel {
    /// Scenario-owned bytes remain stable throughout the synchronous drive.
    const curl::fuzzer::proto::Connection* script = nullptr;
    /// The server half stays owned after curl receives the client fd.
    std::unique_ptr<MockConnection> connection;
    /// EPSV/PASV may open the socket well before RETR/STOR makes data valid.
    bool transfer_started = false;
    /// Upload peers are drained on every outer-loop turn.
    bool upload = false;
  };

  /// Reset every borrowed pointer, descriptor, cursor, and observable capture
  /// before a new drive so reusing a server cannot join two FTP sessions.
  void ResetForScenario(const curl::fuzzer::proto::Scenario& scenario);

  /// Apply a script's bounded transport knobs when its socket is created.
  /// This mirrors the generic peer for compatibility inputs without allowing
  /// narrowing of an arbitrary protobuf uint32 into a negative socket size.
  static void ApplyScriptBackpressure(MockConnection* connection, const curl::fuzzer::proto::Connection& script);

  /// Read all presently available control bytes and answer each complete
  /// command with exactly one scripted fragment.
  /// @return true when bytes or a command/reply cursor advanced.
  bool ServiceControlConnection();

  /// Drain every active upload socket even after the capture prefix is full.
  /// @return true when curl produced at least one data byte.
  bool ServiceUploadConnections();

  /// Consume and dispatch one complete FTP command. Responses stay aligned
  /// to commands rather than perform calls, which are not protocol events.
  /// @param command One newline-terminated command from curl.
  void HandleControlCommand(std::string_view command);

  /// Select the next unopened passive peer and prepare it for the transfer.
  /// @param direction Whether curl will read or write the data connection.
  void StartNextTransfer(TransferDirection direction);

  /// Preload all bounded download fragments once RETR/LIST has been accepted.
  /// Delaying until the command prevents an early EOF from perturbing curl's
  /// passive setup states.
  /// @param channel Passive peer whose script supplies the download bytes.
  void PreloadDownload(DataChannel* channel);

  /// Queue the transfer-final response before curl observes data EOF. curl's
  /// FTP completion path performs a blocking control read inside
  /// curl_multi_perform, so the outer mock loop cannot provide this reply
  /// afterwards.
  void QueueTransferCompletion();

  /// Return the next command-aligned control fragment within the shared
  /// response-count budget.
  /// @return Scenario-owned reply, or nullptr after the bounded prefix.
  const std::string* NextControlReply();

  /// Write raw control bytes while treating a peer race as an ordinary failed
  /// mock write rather than a reason to alter protocol cursors.
  /// @param bytes Response fragment to queue.
  /// @return true when the complete fragment was queued.
  bool WriteControlBytes(std::string_view bytes);

  /// Extract the command verb without allocating, retaining arbitrary command
  /// arguments for curl while limiting mock interpretation to routing.
  /// @param command Complete command line.
  /// @return View of its first non-whitespace token.
  static std::string_view CommandVerb(std::string_view command);

  /// Compare an arbitrary verb to an ASCII FTP command independent of curl's
  /// chosen letter case and without locale-dependent transformations.
  /// @param verb Parsed command token.
  /// @param expected_uppercase Literal uppercase command name.
  /// @return true when the verbs are equal ignoring ASCII case.
  static bool VerbEquals(std::string_view verb, std::string_view expected_uppercase);

  /// Recognize only commands that make curl use its secondary socket. Keeping
  /// PRET and setup commands out is essential because their replies precede,
  /// rather than complete, a data transfer.
  /// @param verb Parsed FTP command verb.
  /// @return transfer direction, or kNone for control-only commands.
  static TransferDirection DirectionForVerb(std::string_view verb);

  /// Recognize the last CURLOPT_CUSTOMREQUEST value as a data command. Curl
  /// uses this option in place of LIST, so the peer must not require mutations
  /// to rediscover one of its small built-in verb allowlist before releasing
  /// the passive payload.
  /// @param verb Parsed command token sent by curl.
  /// @return true when verb matches the effective custom request option.
  bool IsConfiguredCustomDownload(std::string_view verb) const;

  /// Find the first complete numeric FTP response in a raw fragment. curl may
  /// accept informational lines before it, so inspecting only byte zero would
  /// fail to start data for otherwise valid scripts.
  /// @param response Raw control fragment.
  /// @return numeric status, or -1 when no terminating line is present.
  static int FirstReplyCode(std::string_view response);

  /// Detect a truncated but otherwise valid status line at the response tail.
  /// Appending only CRLF in this case avoids leaving a synthetic reply queued
  /// for a later wildcard transfer.
  /// @param response Raw control fragment.
  /// @return true when the unterminated tail begins with "ddd ".
  static bool TailNeedsOnlyNewline(std::string_view response);

  /// Bound transcript and upload observability separately from the bytes that
  /// must still be parsed or drained to keep curl moving.
  /// @param source Newly observed bytes.
  /// @param limit Maximum retained destination size.
  /// @param destination Capture buffer receiving the available prefix.
  static void CapturePrefix(std::string_view source, std::size_t limit, std::string* destination);

  /// Make cleanup non-blocking by preloading QUIT's 221 reply after a complete
  /// transfer, or by exposing immediate EOF after an incomplete drive.
  /// @param completed Whether curl reported that the transfer stopped.
  void FinishConnections(bool completed);

  /// Three passive sockets cover listing plus two file transfers while
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
