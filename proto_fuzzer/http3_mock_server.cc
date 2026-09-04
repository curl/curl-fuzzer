/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief ngtcp2 QUIC transport and nghttp3 peer implementation.

#include "proto_fuzzer/http3_mock_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "proto_fuzzer/multi_socket_driver.h"
#include "proto_fuzzer/scenario_limits.h"
#include "proto_fuzzer/tls_test_credentials.h"

namespace proto_fuzzer {

namespace {

constexpr std::int64_t kNoStreamId = -1;
constexpr std::size_t kMaxDatagramsPerTurn = 64;
constexpr std::size_t kServerConnectionIdBytes = 18;
constexpr std::size_t kReceiveBufferBytes = 64 * 1024;
// One request plus the six HTTP/3 critical streams leave room for every
// bounded action to create a fresh raw unidirectional stream.
constexpr std::size_t kMaxStreams = scenario_limits::kMaxHttp3Actions + 8;
constexpr std::size_t kMaxWritesPerTurn = 64;
constexpr std::size_t kMaxPendingPlaintextBytes = 64 * 1024;
constexpr int kHttp3IdleIterations = 32;
// QUIC's first two bits select one of these wire widths. The remaining bits
// encode the integer itself.
constexpr std::array<std::size_t, 4> kQuicVarintByteWidths = {1, 2, 4, 8};
constexpr unsigned int kQuicVarintTagBits = 2;
constexpr unsigned int kQuicVarintTagShift = CHAR_BIT - kQuicVarintTagBits;
static_assert(CHAR_BIT == 8, "QUIC varints require 8-bit bytes");

enum StreamRoleIndex : std::size_t {
  kResponseStream = 0,
  kControlStream = 1,
  kQpackEncoderStream = 2,
  kQpackDecoderStream = 3,
  kStreamRoleCount = 4,
};

/// Keep server-side OpenSSL failures from changing error classification in
/// curl's OpenSSL client, which executes on the same thread.
class OpenSslErrorQueueGuard {
 public:
  OpenSslErrorQueueGuard() { ERR_clear_error(); }
  ~OpenSslErrorQueueGuard() { ERR_clear_error(); }

  OpenSslErrorQueueGuard(const OpenSslErrorQueueGuard&) = delete;
  OpenSslErrorQueueGuard& operator=(const OpenSslErrorQueueGuard&) = delete;
};

/// Configure callback-created descriptors explicitly: curl's requested
/// SOCK_NONBLOCK and SOCK_CLOEXEC flags do not constrain an application fd.
bool ConfigureSocket(int fd) {
  if (fd < 0) {
    return false;
  }
  const int descriptor_flags = ::fcntl(fd, F_GETFD, 0);
  if (descriptor_flags < 0 || ::fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) < 0) {
    return false;
  }
  const int status_flags = ::fcntl(fd, F_GETFL, 0);
  return status_flags >= 0 && ::fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) == 0;
}

/// Bind one private IPv4 UDP endpoint to an ephemeral loopback port.
int OpenLoopbackSocket(struct sockaddr_in* bound_address) {
  if (bound_address == nullptr) {
    return -1;
  }

  const int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0 || !ConfigureSocket(fd)) {
    if (fd >= 0) {
      (void)::close(fd);
    }
    return -1;
  }

  struct sockaddr_in requested = {};
  requested.sin_family = AF_INET;
  requested.sin_port = htons(0);
  requested.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(fd, reinterpret_cast<const struct sockaddr*>(&requested), sizeof(requested)) != 0) {
    (void)::close(fd);
    return -1;
  }

  socklen_t length = sizeof(*bound_address);
  std::memset(bound_address, 0, sizeof(*bound_address));
  if (::getsockname(fd, reinterpret_cast<struct sockaddr*>(bound_address), &length) != 0 ||
      length != sizeof(*bound_address) || bound_address->sin_family != AF_INET) {
    (void)::close(fd);
    return -1;
  }
  return fd;
}

/// Replace all destination metadata curl can retain with the private listener.
bool RewriteDestination(struct curl_sockaddr* address, const struct sockaddr_in& destination) {
  if (address == nullptr || sizeof(destination) > sizeof(address->addr)) {
    return false;
  }
  address->family = AF_INET;
  address->socktype = SOCK_DGRAM;
  address->protocol = IPPROTO_UDP;
  address->addrlen = sizeof(destination);
  std::memset(&address->addr, 0, sizeof(address->addr));
  std::memcpy(&address->addr, &destination, sizeof(destination));
  return true;
}

/// Select only the final RFC HTTP/3 ALPN identifier.
int SelectHttp3Alpn(SSL* /*ssl*/, const unsigned char** selected, unsigned char* selected_length,
                    const unsigned char* client_protocols, unsigned int client_protocols_length, void* /*userdata*/) {
  static constexpr unsigned char server_protocols[] = {2, 'h', '3'};
  unsigned char* match = nullptr;
  unsigned char match_length = 0;
  const int result = SSL_select_next_proto(&match, &match_length, server_protocols, sizeof(server_protocols),
                                           client_protocols, client_protocols_length);
  if (result != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  *selected = match;
  *selected_length = match_length;
  return SSL_TLSEXT_ERR_OK;
}

/// Append one profile-selected certificate without transferring a malformed
/// object into the context on parse failure.
bool AddExtraChainCertificate(SSL_CTX* context, const char* certificate_pem) {
  BIO* certificate_bio = BIO_new_mem_buf(certificate_pem, -1);
  if (certificate_bio == nullptr) {
    return false;
  }
  X509* certificate = PEM_read_bio_X509(certificate_bio, nullptr, nullptr, nullptr);
  BIO_free(certificate_bio);
  if (certificate == nullptr) {
    return false;
  }
  if (SSL_CTX_add_extra_chain_cert(context, certificate) != 1) {
    X509_free(certificate);
    return false;
  }
  return true;
}

/// Parse the checked-in key and profile-selected chain entirely in memory.
bool LoadCredentials(SSL_CTX* context, curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain) {
  BIO* certificate_bio = BIO_new_mem_buf(tls_test_credentials::kCertificatePem, -1);
  BIO* key_bio = BIO_new_mem_buf(tls_test_credentials::kPrivateKeyPem, -1);
  if (certificate_bio == nullptr || key_bio == nullptr) {
    BIO_free(certificate_bio);
    BIO_free(key_bio);
    return false;
  }

  X509* certificate = PEM_read_bio_X509(certificate_bio, nullptr, nullptr, nullptr);
  EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
  BIO_free(certificate_bio);
  BIO_free(key_bio);
  if (certificate == nullptr || key == nullptr) {
    X509_free(certificate);
    EVP_PKEY_free(key);
    return false;
  }

  const bool loaded = SSL_CTX_use_certificate(context, certificate) == 1 && SSL_CTX_use_PrivateKey(context, key) == 1 &&
                      SSL_CTX_check_private_key(context) == 1;
  X509_free(certificate);
  EVP_PKEY_free(key);
  if (!loaded) {
    return false;
  }

  if (certificate_chain == curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_ALL_KEY_TYPES) {
    return AddExtraChainCertificate(context, tls_test_credentials::kRsaCertificatePem) &&
           AddExtraChainCertificate(context, tls_test_credentials::kDsaCertificatePem) &&
           AddExtraChainCertificate(context, tls_test_credentials::kDhCertificatePem);
  }
  return true;
}

/// Create a TLS 1.3 context for ngtcp2's OpenSSL crypto adapter.
SSL_CTX* CreateTlsContext(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain) {
  OpenSslErrorQueueGuard error_guard;
  SSL_CTX* context = SSL_CTX_new(TLS_server_method());
  if (context == nullptr || !LoadCredentials(context, certificate_chain)) {
    SSL_CTX_free(context);
    return nullptr;
  }

  if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1) {
    SSL_CTX_free(context);
    return nullptr;
  }
  (void)SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_alpn_select_cb(context, &SelectHttp3Alpn, nullptr);
  return context;
}

/// Encode one QUIC variable-length integer in its shortest representation.
void AppendQuicVarint(std::string* output, std::uint64_t value) {
  value &= scenario_limits::kMaxQuicVarint;
  for (std::size_t encoding = 0; encoding < kQuicVarintByteWidths.size(); ++encoding) {
    const std::size_t byte_width = kQuicVarintByteWidths[encoding];
    const unsigned int value_bits = static_cast<unsigned int>(byte_width * CHAR_BIT - kQuicVarintTagBits);
    if (value >= (std::uint64_t{1} << value_bits)) {
      continue;
    }

    for (std::size_t byte = byte_width; byte != 0; --byte) {
      const unsigned int shift = static_cast<unsigned int>((byte - 1) * CHAR_BIT);
      unsigned char encoded_byte = static_cast<unsigned char>(value >> shift);
      if (byte == byte_width) {
        encoded_byte |= static_cast<unsigned char>(encoding << kQuicVarintTagShift);
      }
      output->push_back(static_cast<char>(encoded_byte));
    }
    return;
  }
}

/// Normalize a header name again at the runtime boundary. Fixed H3 targets
/// already run the postprocessor; this also keeps direct unit-test scenarios
/// safe to pass to nghttp3.
std::string NormalizeHeaderName(const std::string& source) {
  std::string result = source.substr(0, scenario_limits::kMaxHttp3HeaderNameBytes);
  if (result.empty()) {
    return "x-fuzz";
  }
  for (char& byte : result) {
    const unsigned char value = static_cast<unsigned char>(byte);
    const bool lower = value >= 'a' && value <= 'z';
    const bool upper = value >= 'A' && value <= 'Z';
    const bool digit = value >= '0' && value <= '9';
    const bool punctuation = value == '!' || value == '#' || value == '$' || value == '%' || value == '&' ||
                             value == '\'' || value == '*' || value == '+' || value == '-' || value == '.' ||
                             value == '^' || value == '_' || value == '`' || value == '|' || value == '~';
    if (upper) {
      byte = static_cast<char>(value - 'A' + 'a');
    } else if (!lower && !digit && !punctuation) {
      byte = '-';
    }
  }
  return result;
}

/// Remove control bytes that would make a structured field value malformed.
std::string NormalizeHeaderValue(const std::string& source) {
  std::string result = source.substr(0, scenario_limits::kMaxHttp3HeaderValueBytes);
  for (char& byte : result) {
    const unsigned char value = static_cast<unsigned char>(byte);
    if ((value < 0x20U && value != '\t') || value == 0x7fU) {
      byte = ' ';
    }
  }
  return result;
}

/// Return ngtcp2's nanosecond-resolution monotonic timestamp.
ngtcp2_tstamp QuicNow() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<ngtcp2_tstamp>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

}  // namespace

/// Private transport and HTTP/3 state. Keeping ngtcp2, OpenSSL, and nghttp3
/// out of the public header lets other proto targets compile without their
/// include trees.
class Http3MockServerImpl {
 public:
  explicit Http3MockServerImpl(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain)
      : context_(CreateTlsContext(certificate_chain)), crypto_connection_ref_{&GetQuicConnection, this} {
    role_stream_ids_.fill(kNoStreamId);
    streams_.reserve(kMaxStreams);
    retained_writes_.reserve(kMaxWritesPerTurn);
  }

  ~Http3MockServerImpl() {
    ResetPeer();
    OpenSslErrorQueueGuard error_guard;
    SSL_CTX_free(context_);
  }

  Http3MockServerImpl(const Http3MockServerImpl&) = delete;
  Http3MockServerImpl& operator=(const Http3MockServerImpl&) = delete;

  curl_socket_t OpenSocket(curlsocktype purpose, struct curl_sockaddr* address) {
    if (purpose != CURLSOCKTYPE_IPCXN || address == nullptr || socket_opened_ || context_ == nullptr) {
      return CURL_SOCKET_BAD;
    }
    socket_opened_ = true;

    struct sockaddr_in listener_address = {};
    server_fd_ = OpenLoopbackSocket(&listener_address);
    if (server_fd_ < 0 || !RewriteDestination(address, listener_address)) {
      ResetPeer();
      return CURL_SOCKET_BAD;
    }
    server_port_ = ntohs(listener_address.sin_port);
    local_address_ = listener_address;

    const int client_fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client_fd < 0 || !ConfigureSocket(client_fd)) {
      if (client_fd >= 0) {
        (void)::close(client_fd);
      }
      ResetPeer();
      return CURL_SOCKET_BAD;
    }
    return static_cast<curl_socket_t>(client_fd);
  }

  void BeginScenario(const curl::fuzzer::proto::Scenario& scenario) {
    ResetPeer();
    scenario_ = &scenario;
    default_response_.Clear();
    default_response_.set_status_code(200);
    default_response_.set_finish_stream(true);
  }

  std::size_t DrivePeerTurn() {
    if (server_fd_ < 0 || transport_failed_) {
      return 0;
    }

    OpenSslErrorQueueGuard error_guard;
    std::size_t progress = HandleExpiry();
    if (transport_failed_) {
      return progress;
    }
    progress += ReadDatagrams();
    if (quic_connection_ == nullptr || transport_failed_) {
      return progress;
    }

    if (handshake_complete_ && !close_requested_ && !close_sent_) {
      progress += CreateServerStreams();
      progress += DriveApplicationOutput();
    }
    progress += FlushTransportPackets();
    return progress;
  }

  bool handshake_complete() const { return handshake_complete_; }

  bool request_headers_received() const { return request_headers_received_; }

  std::size_t executed_action_count() const { return next_action_; }

  std::uint16_t server_port() const { return server_port_; }

 private:
  // ngtcp2 acknowledges QUIC writes by stream offset, while nghttp3 accepts
  // acknowledgement only for its own serialized bytes. Track those regions
  // separately from deliberately raw script writes.
  struct StreamState {
    struct ManagedWriteRange {
      std::uint64_t begin = 0;
      std::uint64_t end = 0;
    };

    std::int64_t id = kNoStreamId;
    std::uint64_t write_offset = 0;
    std::vector<ManagedWriteRange> managed_write_ranges;
    std::vector<std::uint64_t> managed_fin_offsets;
    std::size_t next_managed_ack_range = 0;
    std::size_t next_managed_fin_offset = 0;
  };

  // Queue at most one application write at a time. The byte string is kept in
  // retained_writes_ because ngtcp2 may submit only a prefix on each turn.
  struct PendingWrite {
    std::int64_t stream_id = kNoStreamId;
    const std::string* bytes = nullptr;
    std::size_t offset = 0;
    bool finish_stream = false;
    bool nghttp3_managed = false;
    bool completes_action = false;

    bool active() const { return stream_id != kNoStreamId; }

    void Clear() {
      stream_id = kNoStreamId;
      bytes = nullptr;
      offset = 0;
      finish_stream = false;
      nghttp3_managed = false;
      completes_action = false;
    }
  };

  // nghttp3 pulls response bytes through a callback. This state lets that
  // callback preserve the scenario's chunk boundaries and final-stream intent.
  struct ResponseBodyState {
    std::vector<std::string> chunks;
    std::size_t next_chunk = 0;
    bool finish_stream = false;
    bool has_trailers = false;
  };

  enum class WriteResult {
    kComplete,
    kBlocked,
    kFailed,
  };

  // Tear down in protocol-layer order: HTTP/3 retains references into QUIC,
  // and OpenSSL's app data points back to this object until it is cleared.
  void ResetPeer() {
    OpenSslErrorQueueGuard error_guard;
    pending_write_.Clear();
    nghttp3_conn_del(http3_connection_);
    http3_connection_ = nullptr;
    ngtcp2_conn_del(quic_connection_);
    quic_connection_ = nullptr;
    if (tls_connection_ != nullptr) {
      SSL_set_app_data(tls_connection_, nullptr);
      SSL_free(tls_connection_);
      tls_connection_ = nullptr;
    }
    ngtcp2_crypto_ossl_ctx_del(crypto_context_);
    crypto_context_ = nullptr;
    streams_.clear();
    retained_writes_.clear();
    if (server_fd_ >= 0) {
      (void)::close(server_fd_);
      server_fd_ = -1;
    }

    scenario_ = nullptr;
    role_stream_ids_.fill(kNoStreamId);
    std::memset(&local_address_, 0, sizeof(local_address_));
    std::memset(&remote_address_, 0, sizeof(remote_address_));
    ngtcp2_path_storage_zero(&path_storage_);
    response_body_.chunks.clear();
    response_body_.next_chunk = 0;
    response_body_.finish_stream = false;
    response_body_.has_trailers = false;
    next_action_ = 0;
    server_port_ = 0;
    socket_opened_ = false;
    handshake_complete_ = false;
    request_headers_received_ = false;
    server_streams_bound_ = false;
    bootstrap_drained_ = false;
    waiting_for_h3_drain_ = false;
    waiting_drain_completes_action_ = false;
    final_response_submitted_ = false;
    default_response_started_ = false;
    http3_failed_ = false;
    transport_failed_ = false;
    close_requested_ = false;
    close_sent_ = false;
    close_error_code_ = 0;
    random_counter_ = 0;
  }

  // ngtcp2 calls into this group while it owns QUIC parsing and encryption.
  // Each callback bridges a transport event into the separately-owned nghttp3
  // connection or records enough state for a later application turn.
  static ngtcp2_conn* GetQuicConnection(ngtcp2_crypto_conn_ref* connection_ref) {
    auto* self = static_cast<Http3MockServerImpl*>(connection_ref->user_data);
    return self == nullptr ? nullptr : self->quic_connection_;
  }

  static int HandshakeCompleted(ngtcp2_conn* /*connection*/, void* user_data) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    self->handshake_complete_ = true;
    return 0;
  }

  static int ReceiveTransmitKey(ngtcp2_conn* /*connection*/, ngtcp2_encryption_level level, void* user_data) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT || self->server_streams_bound_) {
      return 0;
    }
    // HTTP/3 application streams become valid only after 1-RTT keys exist.
    // Bind its critical streams before allowing script output onto the peer.
    if (!self->CreateHttp3Connection()) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    (void)self->CreateServerStreams();
    return self->server_streams_bound_ ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
  }

  static void GenerateRandomBytes(std::uint8_t* destination, std::size_t length,
                                  const ngtcp2_rand_ctx* random_context) {
    if (random_context == nullptr) {
      std::memset(destination, 0, length);
      return;
    }
    auto* self = static_cast<Http3MockServerImpl*>(random_context->native_handle);
    if (self == nullptr) {
      std::memset(destination, 0, length);
      return;
    }
    self->FillRandom(destination, length);
  }

  static int GetNewConnectionId(ngtcp2_conn* /*connection*/, ngtcp2_cid* connection_id,
                                ngtcp2_stateless_reset_token* reset_token, std::size_t connection_id_length,
                                void* user_data) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr || connection_id == nullptr || reset_token == nullptr ||
        connection_id_length > sizeof(connection_id->data)) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    connection_id->datalen = connection_id_length;
    self->FillRandom(connection_id->data, connection_id_length);
    self->FillRandom(reset_token->data, sizeof(reset_token->data));
    return 0;
  }

  static int OpenRemoteStream(ngtcp2_conn* /*connection*/, std::int64_t stream_id, void* user_data) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr || self->streams_.size() >= kMaxStreams) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    StreamState state;
    state.id = stream_id;
    self->streams_.push_back(state);
    if (self->role_stream_ids_[kResponseStream] == kNoStreamId && ngtcp2_is_bidi_stream(stream_id)) {
      self->role_stream_ids_[kResponseStream] = stream_id;
    }
    return 0;
  }

  // ngtcp2 presents decrypted stream bytes; nghttp3 parses the HTTP/3 layer.
  // Extending QUIC's flow-control windows by the consumed amount keeps only
  // parsed bytes eligible for further client transmission.
  static int ReceiveQuicStreamData(ngtcp2_conn* connection, std::uint32_t flags, std::int64_t stream_id,
                                   std::uint64_t /*offset*/, const std::uint8_t* data, std::size_t length,
                                   void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr || self->http3_connection_ == nullptr || self->http3_failed_) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    const nghttp3_ssize consumed =
        nghttp3_conn_read_stream2(self->http3_connection_, stream_id, data, length, flags & NGTCP2_STREAM_DATA_FLAG_FIN,
                                  ngtcp2_conn_get_timestamp(connection));
    if (consumed < 0) {
      self->http3_failed_ = true;
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    ngtcp2_conn_extend_max_stream_offset(connection, stream_id, static_cast<std::uint64_t>(consumed));
    ngtcp2_conn_extend_max_offset(connection, static_cast<std::uint64_t>(consumed));
    return 0;
  }

  // A transport acknowledgement covers both raw fuzz bytes and nghttp3 output.
  // Report only intersecting nghttp3-managed ranges back to nghttp3; otherwise
  // its write offsets would advance for bytes it never generated.
  static int AckedStreamDataOffset(ngtcp2_conn* /*connection*/, std::int64_t stream_id, std::uint64_t offset,
                                   std::uint64_t length, void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr || self->http3_connection_ == nullptr || self->http3_failed_) {
      return 0;
    }

    StreamState* stream = self->FindStream(stream_id);
    if (stream == nullptr || offset > UINT64_MAX - length) {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    if (length == 0) {
      if (stream->next_managed_fin_offset < stream->managed_fin_offsets.size() &&
          stream->managed_fin_offsets[stream->next_managed_fin_offset] == offset) {
        ++stream->next_managed_fin_offset;
        if (nghttp3_conn_add_ack_offset(self->http3_connection_, stream_id, 0) != 0) {
          self->http3_failed_ = true;
          return NGTCP2_ERR_CALLBACK_FAILURE;
        }
      }
      return 0;
    }

    const std::uint64_t end = offset + length;
    std::uint64_t managed_length = 0;
    for (std::size_t index = stream->next_managed_ack_range; index < stream->managed_write_ranges.size(); ++index) {
      const StreamState::ManagedWriteRange& range = stream->managed_write_ranges[index];
      if (range.end <= offset) {
        stream->next_managed_ack_range = index + 1;
        continue;
      }
      if (range.begin >= end) {
        break;
      }
      managed_length += std::min(range.end, end) - std::max(range.begin, offset);
      if (range.end <= end) {
        stream->next_managed_ack_range = index + 1;
      }
    }

    if (managed_length != 0 && nghttp3_conn_add_ack_offset(self->http3_connection_, stream_id, managed_length) != 0) {
      self->http3_failed_ = true;
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  // Keep nghttp3's stream lifecycle synchronized with QUIC resets, STOP_SENDING
  // events, and close error-code flags.
  static int CloseQuicStream(ngtcp2_conn* /*connection*/, std::uint32_t flags, std::int64_t stream_id,
                             std::uint64_t receive_error_code, std::uint64_t transmit_error_code, void* user_data,
                             void* /*stream_user_data*/) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr || self->http3_connection_ == nullptr || self->http3_failed_) {
      return 0;
    }
    std::uint32_t http3_flags = NGHTTP3_STREAM_CLOSE_FLAG_NONE;
    if ((flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET) != 0) {
      http3_flags |= NGHTTP3_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET;
    }
    if ((flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET) != 0) {
      http3_flags |= NGHTTP3_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET;
    }
    const int result = nghttp3_conn_close_stream2(self->http3_connection_, http3_flags, stream_id, receive_error_code,
                                                  transmit_error_code);
    if (result != 0 && result != NGHTTP3_ERR_STREAM_NOT_FOUND) {
      self->http3_failed_ = true;
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  static int ResetQuicStream(ngtcp2_conn* /*connection*/, std::int64_t stream_id, std::uint64_t /*final_size*/,
                             std::uint64_t /*application_error_code*/, void* user_data, void* /*stream_user_data*/) {
    return ShutdownHttp3StreamRead(stream_id, user_data);
  }

  static int StopSendingQuicStream(ngtcp2_conn* /*connection*/, std::int64_t stream_id,
                                   std::uint64_t /*application_error_code*/, void* user_data,
                                   void* /*stream_user_data*/) {
    return ShutdownHttp3StreamRead(stream_id, user_data);
  }

  static int ShutdownHttp3StreamRead(std::int64_t stream_id, void* user_data) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr || self->http3_connection_ == nullptr || self->http3_failed_) {
      return 0;
    }
    const int result = nghttp3_conn_shutdown_stream_read(self->http3_connection_, stream_id);
    if (result != 0 && result != NGHTTP3_ERR_STREAM_NOT_FOUND) {
      self->http3_failed_ = true;
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }

  // Create HTTP/3 once the QUIC handshake can carry application traffic.
  // Dynamic QPACK is intentionally disabled so scenarios cannot retain table
  // state beyond the bounded peer lifetime.
  bool CreateHttp3Connection() {
    if (http3_connection_ != nullptr) {
      return true;
    }
    nghttp3_callbacks callbacks = {};
    callbacks.recv_data = &ReceiveRequestData;
    callbacks.deferred_consume = &DeferredConsumeRequestData;
    callbacks.end_headers = &EndRequestHeaders;
    callbacks.end_stream = &EndRequestStream;
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 0;
    settings.qpack_encoder_max_dtable_capacity = 0;
    settings.qpack_blocked_streams = 0;
    if (nghttp3_conn_server_new(&http3_connection_, &callbacks, &settings, nullptr, this) != 0) {
      http3_failed_ = true;
      return false;
    }
    nghttp3_conn_set_max_concurrent_streams(http3_connection_, kMaxStreams);
    return true;
  }

  // QUIC needs unpredictable-looking connection IDs and reset tokens, but
  // fuzzing needs deterministic reruns. This local generator is not used for
  // cryptographic secrecy.
  void FillRandom(std::uint8_t* destination, std::size_t length) {
    std::uint64_t state = ++random_counter_ * UINT64_C(0x9e3779b97f4a7c15);
    for (std::size_t index = 0; index < length; ++index) {
      state ^= state >> 12U;
      state ^= state << 25U;
      state ^= state >> 27U;
      destination[index] = static_cast<std::uint8_t>((state * UINT64_C(0x2545f4914f6cdd1d)) >> 56U);
    }
  }

  // The first valid Initial establishes the sole remote endpoint. Construct
  // all three protocol layers here because ngtcp2's crypto callbacks need a
  // live server-side SSL object while processing this packet.
  bool InitializeConnection(const ngtcp2_pkt_hd& header, const struct sockaddr_in& remote_address) {
    if (quic_connection_ != nullptr || header.type != NGTCP2_PKT_INITIAL) {
      return false;
    }

    remote_address_ = remote_address;
    ngtcp2_path_storage_init(&path_storage_, reinterpret_cast<const ngtcp2_sockaddr*>(&local_address_),
                             sizeof(local_address_), reinterpret_cast<const ngtcp2_sockaddr*>(&remote_address_),
                             sizeof(remote_address_), nullptr);

    ngtcp2_callbacks callbacks = {};
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.handshake_completed = &HandshakeCompleted;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data = &ReceiveQuicStreamData;
    callbacks.acked_stream_data_offset = &AckedStreamDataOffset;
    callbacks.stream_open = &OpenRemoteStream;
    callbacks.stream_reset = &ResetQuicStream;
    callbacks.rand = &GenerateRandomBytes;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.stream_stop_sending = &StopSendingQuicStream;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.recv_tx_key = &ReceiveTransmitKey;
    callbacks.get_new_connection_id2 = &GetNewConnectionId;
    callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    callbacks.stream_close2 = &CloseQuicStream;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = QuicNow();
    settings.rand_ctx.native_handle = this;
    settings.no_pmtud = 1;
    settings.max_tx_udp_payload_size = packet_buffer_.size();

    ngtcp2_transport_params parameters;
    ngtcp2_transport_params_default(&parameters);
    parameters.initial_max_stream_data_bidi_local = kMaxPendingPlaintextBytes;
    parameters.initial_max_stream_data_bidi_remote = kMaxPendingPlaintextBytes;
    parameters.initial_max_stream_data_uni = kMaxPendingPlaintextBytes;
    parameters.initial_max_data = kMaxPendingPlaintextBytes * 4U;
    parameters.initial_max_streams_bidi = kMaxStreams;
    parameters.initial_max_streams_uni = kMaxStreams;
    parameters.max_idle_timeout = 5U * NGTCP2_SECONDS;
    parameters.active_connection_id_limit = 2;
    parameters.original_dcid = header.dcid;
    parameters.original_dcid_present = 1;

    ngtcp2_cid server_cid = {};
    server_cid.datalen = kServerConnectionIdBytes;
    FillRandom(server_cid.data, server_cid.datalen);
    if (ngtcp2_conn_server_new(&quic_connection_, &header.scid, &server_cid, &path_storage_.path, header.version,
                               &callbacks, &settings, &parameters, nullptr, this) != 0) {
      return false;
    }

    if (ngtcp2_crypto_ossl_ctx_new(&crypto_context_, nullptr) != 0) {
      return false;
    }
    tls_connection_ = SSL_new(context_);
    if (tls_connection_ == nullptr) {
      return false;
    }
    ngtcp2_crypto_ossl_ctx_set_ssl(crypto_context_, tls_connection_);
    if (ngtcp2_crypto_ossl_configure_server_session(tls_connection_) != 0) {
      return false;
    }
    SSL_set_app_data(tls_connection_, &crypto_connection_ref_);
    SSL_set_accept_state(tls_connection_);
    ngtcp2_conn_set_tls_native_handle(quic_connection_, crypto_context_);
    return true;
  }

  // Drain a bounded datagram batch. Before connection setup, accept only a
  // valid QUIC Initial; afterwards, ignore packets from other UDP endpoints.
  std::size_t ReadDatagrams() {
    std::size_t progress = 0;
    for (std::size_t packet = 0; packet < kMaxDatagramsPerTurn; ++packet) {
      struct sockaddr_in remote_address = {};
      socklen_t remote_length = sizeof(remote_address);
      const ssize_t received = ::recvfrom(server_fd_, receive_buffer_.data(), receive_buffer_.size(), 0,
                                          reinterpret_cast<struct sockaddr*>(&remote_address), &remote_length);
      if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          transport_failed_ = true;
        }
        break;
      }
      if (received == 0 || remote_length != sizeof(remote_address) || remote_address.sin_family != AF_INET) {
        continue;
      }
      ++progress;

      if (quic_connection_ == nullptr) {
        ngtcp2_pkt_hd header = {};
        if (ngtcp2_accept(&header, receive_buffer_.data(), static_cast<std::size_t>(received)) != 0) {
          continue;
        }
        if (!InitializeConnection(header, remote_address)) {
          transport_failed_ = true;
          return progress;
        }
      } else if (remote_address.sin_port != remote_address_.sin_port ||
                 remote_address.sin_addr.s_addr != remote_address_.sin_addr.s_addr) {
        continue;
      }

      ngtcp2_pkt_info packet_info = {};
      const int result = ngtcp2_conn_read_pkt(quic_connection_, &path_storage_.path, &packet_info,
                                              receive_buffer_.data(), static_cast<std::size_t>(received), QuicNow());
      if (result != 0) {
        transport_failed_ = true;
        return progress;
      }
    }
    return progress;
  }

  // ngtcp2 timers can make handshake, loss-recovery, or close packets ready
  // even when curl has not sent a new UDP datagram this turn.
  std::size_t HandleExpiry() {
    if (quic_connection_ == nullptr) {
      return 0;
    }
    const ngtcp2_tstamp now = QuicNow();
    if (ngtcp2_conn_get_expiry2(quic_connection_) > now) {
      return 0;
    }
    const int result = ngtcp2_conn_handle_expiry(quic_connection_, now);
    if (result != 0) {
      transport_failed_ = true;
    }
    return 1;
  }

  // A nonblocking socket can defer a packet without making the peer invalid.
  // Hard send errors are terminal because no later turn can repair the path.
  bool SendPacket(const ngtcp2_path& path, const std::uint8_t* data, std::size_t length) {
    const ngtcp2_addr* destination = &path.remote;
    if (destination->addr == nullptr || destination->addrlen == 0) {
      destination = &path_storage_.path.remote;
    }
    const ssize_t sent = ::sendto(server_fd_, data, length, 0,
                                  reinterpret_cast<const struct sockaddr*>(destination->addr), destination->addrlen);
    if (sent == static_cast<ssize_t>(length)) {
      return true;
    }
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
      return false;
    }
    transport_failed_ = true;
    return false;
  }

  // Serialize all QUIC control traffic after application writes. A requested
  // CONNECTION_CLOSE takes priority and is emitted at most once.
  std::size_t FlushTransportPackets() {
    if (quic_connection_ == nullptr || transport_failed_ || close_sent_) {
      return 0;
    }

    if (close_requested_) {
      ngtcp2_ccerr error;
      ngtcp2_ccerr_default(&error);
      ngtcp2_ccerr_set_application_error(&error, close_error_code_, nullptr, 0);
      ngtcp2_path_storage output_path;
      ngtcp2_path_storage_zero(&output_path);
      ngtcp2_pkt_info packet_info = {};
      const ngtcp2_tstamp now = QuicNow();
      const ngtcp2_ssize written = ngtcp2_conn_write_connection_close(
          quic_connection_, &output_path.path, &packet_info, packet_buffer_.data(), packet_buffer_.size(), &error, now);
      if (written < 0) {
        transport_failed_ = true;
        return 0;
      }
      close_sent_ = true;
      if (written == 0) {
        return 1;
      }
      ngtcp2_conn_update_pkt_tx_time(quic_connection_, now);
      (void)SendPacket(output_path.path, packet_buffer_.data(), static_cast<std::size_t>(written));
      return 1;
    }

    std::size_t progress = 0;
    for (std::size_t packet = 0; packet < kMaxWritesPerTurn; ++packet) {
      ngtcp2_path_storage output_path;
      ngtcp2_path_storage_zero(&output_path);
      ngtcp2_pkt_info packet_info = {};
      const ngtcp2_tstamp now = QuicNow();
      const ngtcp2_ssize written = ngtcp2_conn_write_pkt(quic_connection_, &output_path.path, &packet_info,
                                                         packet_buffer_.data(), packet_buffer_.size(), now);
      if (written < 0) {
        transport_failed_ = true;
        break;
      }
      if (written == 0) {
        break;
      }
      ngtcp2_conn_update_pkt_tx_time(quic_connection_, now);
      if (!SendPacket(output_path.path, packet_buffer_.data(), static_cast<std::size_t>(written))) {
        break;
      }
      ++progress;
    }
    return progress;
  }

  // HTTP/3 requires one control stream and two QPACK streams before it can
  // send response metadata. Their stream IDs are retained by role so script
  // actions can target them without exposing transport-chosen IDs.
  std::size_t CreateServerStreams() {
    if (server_streams_bound_ || quic_connection_ == nullptr || http3_connection_ == nullptr || http3_failed_) {
      return 0;
    }

    std::size_t progress = 0;
    const std::array<StreamRoleIndex, 3> roles = {kControlStream, kQpackEncoderStream, kQpackDecoderStream};
    for (const StreamRoleIndex role : roles) {
      if (role_stream_ids_[role] != kNoStreamId) {
        continue;
      }
      const std::int64_t stream_id = OpenUnidirectionalStream();
      if (stream_id == kNoStreamId) {
        return progress;
      }
      role_stream_ids_[role] = stream_id;
      ++progress;
    }

    if (role_stream_ids_[kControlStream] == kNoStreamId || role_stream_ids_[kQpackEncoderStream] == kNoStreamId ||
        role_stream_ids_[kQpackDecoderStream] == kNoStreamId) {
      return progress;
    }
    if (nghttp3_conn_bind_qpack_streams(http3_connection_, role_stream_ids_[kQpackEncoderStream],
                                        role_stream_ids_[kQpackDecoderStream]) != 0 ||
        nghttp3_conn_bind_control_stream(http3_connection_, role_stream_ids_[kControlStream]) != 0) {
      http3_failed_ = true;
      return progress;
    }
    server_streams_bound_ = true;
    return progress + 1;
  }

  std::int64_t OpenUnidirectionalStream() {
    if (quic_connection_ == nullptr || streams_.size() >= kMaxStreams) {
      return kNoStreamId;
    }
    std::int64_t stream_id = kNoStreamId;
    if (ngtcp2_conn_open_uni_stream(quic_connection_, &stream_id, nullptr) != 0) {
      return kNoStreamId;
    }

    StreamState state;
    state.id = stream_id;
    streams_.push_back(state);
    return stream_id;
  }

  // Advance protocol-generated output before one scenario action. This keeps
  // QPACK/control bytes causally ahead of raw writes and makes each turn's
  // work bounded even when the client is blocked.
  std::size_t DriveApplicationOutput() {
    std::size_t progress = 0;

    if (pending_write_.active()) {
      const bool completes_action = pending_write_.completes_action;
      const WriteResult result = FlushPendingWrite(&progress);
      if (result == WriteResult::kBlocked) {
        return progress;
      }
      if (result == WriteResult::kFailed && transport_failed_) {
        return progress;
      }
      if (completes_action) {
        ++next_action_;
        return progress + 1;
      }
      if (result == WriteResult::kFailed && waiting_for_h3_drain_) {
        waiting_for_h3_drain_ = false;
        if (waiting_drain_completes_action_) {
          ++next_action_;
        }
        return progress + 1;
      }
    }

    if (!server_streams_bound_) {
      return progress;
    }
    if (!bootstrap_drained_) {
      if (http3_failed_ || PumpNghttp3(&progress)) {
        bootstrap_drained_ = true;
        ++progress;
      }
      return progress;
    }
    if (waiting_for_h3_drain_) {
      if (http3_failed_ || PumpNghttp3(&progress)) {
        waiting_for_h3_drain_ = false;
        if (waiting_drain_completes_action_) {
          ++next_action_;
        }
        waiting_drain_completes_action_ = false;
        ++progress;
      }
      return progress;
    }

    // Reading a request can produce QPACK decoder instructions independently
    // of a response action. Keep those ahead of script-controlled raw writes.
    if (!http3_failed_ && !PumpNghttp3(&progress)) {
      return progress;
    }
    if (transport_failed_) {
      return progress;
    }

    const std::size_t action_count =
        scenario_ == nullptr
            ? 0
            : std::min<std::size_t>(scenario_limits::kMaxHttp3Actions, scenario_->http3_plan().actions_size());
    if (next_action_ >= action_count) {
      // An empty H3 plan still needs one successful response after a request.
      if (action_count == 0 && !default_response_started_ && request_headers_received_) {
        default_response_started_ = true;
        if (SubmitStructuredResponse(default_response_)) {
          waiting_for_h3_drain_ = true;
          waiting_drain_completes_action_ = false;
          ++progress;
        }
      }
      return progress;
    }

    const auto& action = scenario_->http3_plan().actions(static_cast<int>(next_action_));
    if (action.has_structured_response()) {
      if (!request_headers_received_) {
        return progress;
      }
      if (SubmitStructuredResponse(action.structured_response())) {
        waiting_for_h3_drain_ = true;
        waiting_drain_completes_action_ = true;
      } else {
        ++next_action_;
      }
      return progress + 1;
    }

    if (action.has_stream_write()) {
      const auto& write = action.stream_write();
      const std::int64_t stream_id = StreamForRole(write.role());
      if (stream_id == kNoStreamId) {
        return progress;
      }
      const std::size_t length = std::min<std::size_t>(scenario_limits::kMaxHttp3RawWriteBytes, write.data().size());
      QueueWrite(stream_id, write.data().substr(0, length), write.finish_stream(), false, true);
      return progress + 1;
    }

    if (action.has_open_unidirectional_stream()) {
      const auto& open = action.open_unidirectional_stream();
      const std::int64_t stream_id = OpenUnidirectionalStream();
      if (stream_id == kNoStreamId) {
        ++next_action_;
        return progress + 1;
      }
      const std::size_t length = std::min<std::size_t>(scenario_limits::kMaxHttp3RawWriteBytes, open.data().size());
      QueueWrite(stream_id, open.data().substr(0, length), open.finish_stream(), false, true);
      return progress + 1;
    }

    if (action.has_stream_reset()) {
      const auto& reset = action.stream_reset();
      const std::int64_t stream_id = StreamForRole(reset.role());
      if (stream_id == kNoStreamId) {
        return progress;
      }
      (void)ngtcp2_conn_shutdown_stream_write(quic_connection_, 0, stream_id,
                                              reset.application_error_code() & scenario_limits::kMaxQuicVarint);
      ++next_action_;
      return progress + 1;
    }

    if (action.has_goaway()) {
      const std::int64_t control_stream_id = StreamForRole(curl::fuzzer::proto::HTTP3_STREAM_CONTROL);
      if (control_stream_id == kNoStreamId) {
        return progress;
      }
      // HTTP/3 GOAWAY is a raw control-stream frame so its identifier remains
      // directly mutation-controlled instead of being selected by nghttp3.
      std::string payload;
      AppendQuicVarint(&payload, action.goaway().id());
      std::string frame;
      AppendQuicVarint(&frame, 0x07U);
      AppendQuicVarint(&frame, payload.size());
      frame.append(payload);
      QueueWrite(control_stream_id, std::move(frame), false, false, true);
      return progress + 1;
    }

    if (action.has_connection_close()) {
      close_error_code_ = action.connection_close().application_error_code() & scenario_limits::kMaxQuicVarint;
      close_requested_ = true;
      ++next_action_;
      return progress + 1;
    }

    ++next_action_;
    return progress + 1;
  }

  // Retain script and nghttp3 bytes until ngtcp2 accepts their full prefix.
  // Only one pending write exists, preserving ordering between action types.
  void QueueWrite(std::int64_t stream_id, std::string bytes, bool finish_stream, bool nghttp3_managed,
                  bool completes_action) {
    retained_writes_.push_back(std::make_unique<std::string>(std::move(bytes)));
    pending_write_.stream_id = stream_id;
    pending_write_.bytes = retained_writes_.back().get();
    pending_write_.offset = 0;
    pending_write_.finish_stream = finish_stream;
    pending_write_.nghttp3_managed = nghttp3_managed;
    pending_write_.completes_action = completes_action;
  }

  // Packetize one prefix through ngtcp2. For nghttp3-managed output, record
  // the exact submitted offsets so its acknowledgement accounting can exclude
  // interleaved raw writes on the same QUIC stream.
  WriteResult FlushPendingWrite(std::size_t* progress) {
    if (!pending_write_.active()) {
      return WriteResult::kComplete;
    }

    if (pending_write_.bytes == nullptr || pending_write_.offset > pending_write_.bytes->size()) {
      pending_write_.Clear();
      return WriteResult::kFailed;
    }

    const std::size_t remaining = pending_write_.bytes->size() - pending_write_.offset;
    if (remaining == 0 && !pending_write_.finish_stream) {
      pending_write_.Clear();
      ++*progress;
      return WriteResult::kComplete;
    }

    ngtcp2_vec vector = {};
    vector.base =
        reinterpret_cast<std::uint8_t*>(const_cast<char*>(pending_write_.bytes->data() + pending_write_.offset));
    vector.len = remaining;
    const std::size_t vector_count = remaining == 0 ? 0 : 1;
    const std::uint32_t flags =
        pending_write_.finish_stream ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;
    ngtcp2_path_storage output_path;
    ngtcp2_path_storage_zero(&output_path);
    ngtcp2_pkt_info packet_info = {};
    ngtcp2_ssize submitted = -1;
    const ngtcp2_tstamp now = QuicNow();
    const ngtcp2_ssize packet_length = ngtcp2_conn_writev_stream(
        quic_connection_, &output_path.path, &packet_info, packet_buffer_.data(), packet_buffer_.size(), &submitted,
        flags, pending_write_.stream_id, vector_count == 0 ? nullptr : &vector, vector_count, now);
    if (packet_length == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
      return WriteResult::kBlocked;
    }
    if (packet_length == NGTCP2_ERR_STREAM_SHUT_WR || packet_length == NGTCP2_ERR_STREAM_NOT_FOUND) {
      pending_write_.Clear();
      return WriteResult::kFailed;
    }
    if (packet_length < 0) {
      transport_failed_ = true;
      pending_write_.Clear();
      return WriteResult::kFailed;
    }
    if (packet_length == 0) {
      return WriteResult::kBlocked;
    }
    ngtcp2_conn_update_pkt_tx_time(quic_connection_, now);
    (void)SendPacket(output_path.path, packet_buffer_.data(), static_cast<std::size_t>(packet_length));
    ++*progress;
    if (transport_failed_) {
      pending_write_.Clear();
      return WriteResult::kFailed;
    }

    if (submitted >= 0) {
      StreamState* stream = FindStream(pending_write_.stream_id);
      if (stream == nullptr || static_cast<std::uint64_t>(submitted) > UINT64_MAX - stream->write_offset) {
        transport_failed_ = true;
        pending_write_.Clear();
        return WriteResult::kFailed;
      }
      const std::uint64_t write_begin = stream->write_offset;
      stream->write_offset += static_cast<std::uint64_t>(submitted);
      if (pending_write_.nghttp3_managed) {
        if (nghttp3_conn_add_write_offset(http3_connection_, pending_write_.stream_id,
                                          static_cast<std::uint64_t>(submitted)) != 0) {
          http3_failed_ = true;
          pending_write_.Clear();
          return WriteResult::kFailed;
        }
        if (submitted != 0) {
          stream->managed_write_ranges.push_back({write_begin, stream->write_offset});
        } else if (pending_write_.finish_stream && pending_write_.offset == pending_write_.bytes->size()) {
          stream->managed_fin_offsets.push_back(write_begin);
        }
      }
      pending_write_.offset += static_cast<std::size_t>(submitted);
    }
    if (submitted < 0 || pending_write_.offset != pending_write_.bytes->size()) {
      return WriteResult::kBlocked;
    }
    pending_write_.Clear();
    return WriteResult::kComplete;
  }

  // Let nghttp3 serialize response/control bytes, then feed each generated
  // vector through the same QUIC write path as raw scenario data. Stop when a
  // raw action is pending so it cannot be reordered behind generated output.
  bool PumpNghttp3(std::size_t* progress) {
    if (http3_connection_ == nullptr || http3_failed_) {
      return true;
    }

    for (std::size_t operation = 0; operation < kMaxWritesPerTurn; ++operation) {
      if (pending_write_.active()) {
        if (!pending_write_.nghttp3_managed) {
          return false;
        }
        const WriteResult result = FlushPendingWrite(progress);
        if (result == WriteResult::kBlocked) {
          return false;
        }
        if (result == WriteResult::kFailed) {
          http3_failed_ = true;
          return true;
        }
      }

      std::array<nghttp3_vec, 16> vectors;
      std::int64_t stream_id = -1;
      int finish_stream = 0;
      const nghttp3_ssize vector_count =
          nghttp3_conn_writev_stream(http3_connection_, &stream_id, &finish_stream, vectors.data(), vectors.size());
      if (vector_count < 0) {
        http3_failed_ = true;
        return true;
      }
      if (vector_count == 0 && stream_id == -1) {
        return true;
      }

      StreamState* stream = FindStream(stream_id);
      if (stream == nullptr) {
        http3_failed_ = true;
        return true;
      }

      std::string bytes;
      if (vector_count > 0) {
        std::size_t total = 0;
        for (nghttp3_ssize index = 0; index < vector_count; ++index) {
          if (vectors[static_cast<std::size_t>(index)].len > kMaxPendingPlaintextBytes - total) {
            http3_failed_ = true;
            return true;
          }
          total += vectors[static_cast<std::size_t>(index)].len;
        }
        bytes.reserve(total);
        for (nghttp3_ssize index = 0; index < vector_count; ++index) {
          const nghttp3_vec& vector = vectors[static_cast<std::size_t>(index)];
          bytes.append(reinterpret_cast<const char*>(vector.base), vector.len);
        }
      }

      QueueWrite(stream->id, std::move(bytes), finish_stream != 0, true, false);
    }
    return false;
  }

  // Convert a bounded schema response into nghttp3-owned fields and pull-based
  // body state. Interim responses do not consume the single final response.
  bool SubmitStructuredResponse(const curl::fuzzer::proto::Http3Response& response) {
    if (http3_connection_ == nullptr || http3_failed_ || role_stream_ids_[kResponseStream] == kNoStreamId) {
      return false;
    }

    std::uint32_t status_code = response.status_code();
    if (status_code < 100U || status_code > 599U) {
      status_code = 100U + status_code % 500U;
    }
    std::vector<std::pair<std::string, std::string>> fields;
    fields.reserve(1 + std::min<std::size_t>(scenario_limits::kMaxHttp3Headers, response.response_headers_size()));
    fields.emplace_back(":status", std::to_string(status_code));
    AppendHeaders(&fields, response.response_headers(), scenario_limits::kMaxHttp3Headers);
    const std::vector<nghttp3_nv> name_values = MakeNameValues(fields);
    const std::int64_t response_stream_id = static_cast<std::int64_t>(role_stream_ids_[kResponseStream]);

    if (status_code < 200U) {
      return nghttp3_conn_submit_info(http3_connection_, response_stream_id, name_values.data(), name_values.size()) ==
             0;
    }
    if (final_response_submitted_) {
      return false;
    }

    response_body_.chunks.clear();
    response_body_.next_chunk = 0;
    response_body_.finish_stream = response.finish_stream();
    response_body_.has_trailers = response.response_trailers_size() != 0;
    std::size_t body_bytes = 0;
    const std::size_t body_chunks =
        std::min<std::size_t>(scenario_limits::kMaxHttp3BodyChunks, response.body_chunks_size());
    response_body_.chunks.reserve(body_chunks);
    for (std::size_t index = 0; index < body_chunks && body_bytes < scenario_limits::kMaxHttp3BodyBytes; ++index) {
      const std::string& source = response.body_chunks(static_cast<int>(index));
      const std::size_t length = std::min(source.size(), scenario_limits::kMaxHttp3BodyBytes - body_bytes);
      response_body_.chunks.emplace_back(source.data(), length);
      body_bytes += length;
    }

    nghttp3_data_reader reader = {};
    reader.read_data = &ReadResponseBody;
    if (nghttp3_conn_submit_response(http3_connection_, response_stream_id, name_values.data(), name_values.size(),
                                     &reader) != 0) {
      return false;
    }
    final_response_submitted_ = true;

    if (response_body_.has_trailers) {
      std::vector<std::pair<std::string, std::string>> trailers;
      trailers.reserve(std::min<std::size_t>(scenario_limits::kMaxHttp3Trailers, response.response_trailers_size()));
      AppendHeaders(&trailers, response.response_trailers(), scenario_limits::kMaxHttp3Trailers);
      const std::vector<nghttp3_nv> trailer_values = MakeNameValues(trailers);
      if (nghttp3_conn_submit_trailers(http3_connection_, response_stream_id, trailer_values.data(),
                                       trailer_values.size()) != 0) {
        http3_failed_ = true;
      }
    }
    return true;
  }

  template <typename RepeatedHeaders>
  static void AppendHeaders(std::vector<std::pair<std::string, std::string>>* destination,
                            const RepeatedHeaders& source, std::size_t count_limit) {
    std::size_t remaining = scenario_limits::kMaxHttp3HeaderBytes;
    const std::size_t count = std::min<std::size_t>(count_limit, source.size());
    for (std::size_t index = 0; index < count && remaining != 0; ++index) {
      std::string name = NormalizeHeaderName(source.Get(static_cast<int>(index)).name());
      std::string value = NormalizeHeaderValue(source.Get(static_cast<int>(index)).value());
      if (name.size() > remaining) {
        name.resize(remaining);
        value.clear();
      } else if (value.size() > remaining - name.size()) {
        value.resize(remaining - name.size());
      }
      remaining -= name.size() + value.size();
      destination->emplace_back(std::move(name), std::move(value));
    }
  }

  static std::vector<nghttp3_nv> MakeNameValues(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::vector<nghttp3_nv> name_values;
    name_values.reserve(fields.size());
    for (const auto& field : fields) {
      nghttp3_nv name_value = {};
      name_value.name = reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.first.data()));
      name_value.value = reinterpret_cast<std::uint8_t*>(const_cast<char*>(field.second.data()));
      name_value.namelen = field.first.size();
      name_value.valuelen = field.second.size();
      name_value.flags = NGHTTP3_NV_FLAG_NONE;
      name_values.push_back(name_value);
    }
    return name_values;
  }

  StreamState* FindStream(std::int64_t stream_id) {
    for (StreamState& stream : streams_) {
      if (stream.id == stream_id) {
        return &stream;
      }
    }
    return nullptr;
  }

  std::int64_t StreamForRole(curl::fuzzer::proto::Http3StreamRole role) {
    const int role_value = static_cast<int>(role);
    if (role_value < 0 || role_value >= static_cast<int>(kStreamRoleCount)) {
      return kNoStreamId;
    }
    return role_stream_ids_[static_cast<std::size_t>(role_value)];
  }

  // nghttp3 callbacks replenish QUIC flow-control credit only as application
  // bytes are consumed, then discover the first request stream for responses.
  static int ReceiveRequestData(nghttp3_conn* /*connection*/, std::int64_t stream_id, const std::uint8_t* /*data*/,
                                std::size_t data_length, void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self != nullptr && self->quic_connection_ != nullptr) {
      ngtcp2_conn_extend_max_stream_offset(self->quic_connection_, stream_id, data_length);
      ngtcp2_conn_extend_max_offset(self->quic_connection_, data_length);
    }
    return 0;
  }

  static int DeferredConsumeRequestData(nghttp3_conn* /*connection*/, std::int64_t stream_id, std::size_t consumed,
                                        void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self != nullptr && self->quic_connection_ != nullptr) {
      ngtcp2_conn_extend_max_stream_offset(self->quic_connection_, stream_id, consumed);
      ngtcp2_conn_extend_max_offset(self->quic_connection_, consumed);
    }
    return 0;
  }

  static int EndRequestHeaders(nghttp3_conn* /*connection*/, std::int64_t stream_id, int /*finish_stream*/,
                               void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self != nullptr) {
      if (self->role_stream_ids_[kResponseStream] == kNoStreamId) {
        self->role_stream_ids_[kResponseStream] = stream_id;
        if (self->FindStream(stream_id) == nullptr && self->streams_.size() < kMaxStreams) {
          StreamState state;
          state.id = stream_id;
          self->streams_.push_back(state);
        }
      }
      if (self->role_stream_ids_[kResponseStream] == stream_id) {
        self->request_headers_received_ = true;
      }
    }
    return 0;
  }

  static int EndRequestStream(nghttp3_conn* /*connection*/, std::int64_t /*stream_id*/, void* /*user_data*/,
                              void* /*stream_user_data*/) {
    return 0;
  }

  // nghttp3 pulls one schema body chunk per call. EOF may keep the stream open
  // for trailers or a deliberate no-FIN response.
  static nghttp3_ssize ReadResponseBody(nghttp3_conn* /*connection*/, std::int64_t /*stream_id*/, nghttp3_vec* vectors,
                                        std::size_t vector_count, std::uint32_t* flags, void* user_data,
                                        void* /*stream_user_data*/) {
    auto* self = static_cast<Http3MockServerImpl*>(user_data);
    if (self == nullptr || vectors == nullptr || vector_count == 0 || flags == nullptr) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    while (self->response_body_.next_chunk < self->response_body_.chunks.size() &&
           self->response_body_.chunks[self->response_body_.next_chunk].empty()) {
      ++self->response_body_.next_chunk;
    }
    if (self->response_body_.next_chunk == self->response_body_.chunks.size()) {
      *flags = NGHTTP3_DATA_FLAG_EOF;
      if (!self->response_body_.finish_stream && !self->response_body_.has_trailers) {
        *flags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
      }
      return 0;
    }

    const std::string& chunk = self->response_body_.chunks[self->response_body_.next_chunk++];
    vectors[0].base = reinterpret_cast<std::uint8_t*>(const_cast<char*>(chunk.data()));
    vectors[0].len = chunk.size();
    *flags = NGHTTP3_DATA_FLAG_NONE;
    if (self->response_body_.next_chunk == self->response_body_.chunks.size()) {
      *flags |= NGHTTP3_DATA_FLAG_EOF;
      if (!self->response_body_.finish_stream && !self->response_body_.has_trailers) {
        *flags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
      }
    }
    return 1;
  }

  // Layer-owned transport state. The destruction order in ResetPeer mirrors
  // these dependencies: HTTP/3, QUIC, TLS adapter, then TLS context/socket.
  SSL_CTX* context_ = nullptr;
  ngtcp2_conn* quic_connection_ = nullptr;
  SSL* tls_connection_ = nullptr;
  ngtcp2_crypto_ossl_ctx* crypto_context_ = nullptr;
  ngtcp2_crypto_conn_ref crypto_connection_ref_;
  nghttp3_conn* http3_connection_ = nullptr;
  const curl::fuzzer::proto::Scenario* scenario_ = nullptr;
  std::vector<StreamState> streams_;
  std::vector<std::unique_ptr<std::string>> retained_writes_;
  std::array<std::int64_t, kStreamRoleCount> role_stream_ids_;
  PendingWrite pending_write_;
  ResponseBodyState response_body_;
  curl::fuzzer::proto::Http3Response default_response_;
  ngtcp2_path_storage path_storage_ = {};
  struct sockaddr_in local_address_ = {};
  struct sockaddr_in remote_address_ = {};
  std::array<std::uint8_t, kReceiveBufferBytes> receive_buffer_ = {};
  std::array<std::uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> packet_buffer_ = {};
  std::uint64_t random_counter_ = 0;
  std::uint64_t close_error_code_ = 0;
  std::size_t next_action_ = 0;
  int server_fd_ = -1;
  std::uint16_t server_port_ = 0;
  bool socket_opened_ = false;
  bool handshake_complete_ = false;
  bool request_headers_received_ = false;
  bool server_streams_bound_ = false;
  bool bootstrap_drained_ = false;
  bool waiting_for_h3_drain_ = false;
  bool waiting_drain_completes_action_ = false;
  bool final_response_submitted_ = false;
  bool default_response_started_ = false;
  bool http3_failed_ = false;
  bool transport_failed_ = false;
  bool close_requested_ = false;
  bool close_sent_ = false;
};

Http3MockServer::Http3MockServer() : Http3MockServer(curl::fuzzer::proto::TLS_CERTIFICATE_CHAIN_DEFAULT_EC) {}

Http3MockServer::Http3MockServer(curl::fuzzer::proto::TlsCertificateChainProfile certificate_chain)
    : impl_(new Http3MockServerImpl(certificate_chain)) {}

Http3MockServer::~Http3MockServer() = default;

void Http3MockServer::Install(CURL* easy) {
  // Curl trusts the checked-in server certificate directly and must use HTTP/3
  // rather than silently falling back to an HTTP/1 or HTTP/2 code path.
  MockServerBase::Install(easy);
  struct curl_blob trust_anchor = {const_cast<char*>(tls_test_credentials::kCertificatePem),
                                   sizeof(tls_test_credentials::kCertificatePem) - 1, CURL_BLOB_NOCOPY};
  (void)curl_easy_setopt(easy, CURLOPT_CAINFO_BLOB, &trust_anchor);
  (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
  (void)curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);
  (void)curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3ONLY);
}

bool Http3MockServer::handshake_complete() const { return impl_ != nullptr && impl_->handshake_complete(); }

bool Http3MockServer::request_headers_received() const { return impl_ != nullptr && impl_->request_headers_received(); }

std::size_t Http3MockServer::executed_action_count() const {
  return impl_ == nullptr ? 0 : impl_->executed_action_count();
}

std::uint16_t Http3MockServer::server_port() const { return impl_ == nullptr ? 0 : impl_->server_port(); }

curl_socket_t Http3MockServer::HandleOpenSocket(curlsocktype purpose, struct curl_sockaddr* address) {
  return impl_ == nullptr ? CURL_SOCKET_BAD : impl_->OpenSocket(purpose, address);
}

void Http3MockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  (void)easy;
  if (impl_ == nullptr) {
    return;
  }
  impl_->BeginScenario(scenario);

  int still_running = 1;
  int idle_iterations = 0;
  if (MultiSocketDriver* driver = multi_socket_driver(); driver != nullptr) {
    // Alternate curl readiness processing with one bounded peer turn. Neither
    // side blocks, so an idle limit prevents a malformed case spinning forever.
    CURLMcode result = driver->Start(&still_running);
    for (int iteration = 0; result == CURLM_OK && iteration < kMaxDriveIterations && still_running != 0; ++iteration) {
      std::size_t progress = impl_->DrivePeerTurn();
      const MultiSocketDriver::DriveResult drive_result = driver->DriveReady(&still_running);
      result = drive_result.code;
      progress += drive_result.made_progress ? 1U : 0U;
      if (progress != 0) {
        idle_iterations = 0;
      } else if (++idle_iterations >= kHttp3IdleIterations) {
        break;
      }
    }
    return;
  }

  // The fallback exercises curl's public multi-perform API while preserving
  // the same peer-first/idle-limit behavior as the socket-action driver.
  for (int iteration = 0; iteration < kMaxDriveIterations && still_running != 0; ++iteration) {
    const int running_before = still_running;
    const CURLMcode result = curl_multi_perform(multi, &still_running);
    if (result != CURLM_OK) {
      break;
    }

    std::size_t progress = still_running == running_before ? 0U : 1U;
    progress += impl_->DrivePeerTurn();
    if (progress != 0) {
      idle_iterations = 0;
    } else if (++idle_iterations >= kHttp3IdleIterations) {
      break;
    }
  }
}

}  // namespace proto_fuzzer
