/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Implementation of the resolver lane's loopback DoH responder.

#include "proto_fuzzer/doh_https_rr_mock_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

#include "proto_fuzzer/bounded_anonymous_input_file.h"
#include "proto_fuzzer/option_apply.h"
#include "proto_fuzzer/tls_test_credentials.h"

namespace proto_fuzzer {

namespace {

constexpr char kDohPath[] = "/dns-query";
constexpr unsigned short kDnsQtypeA = 1;
constexpr unsigned short kDnsQtypeAAAA = 28;
constexpr unsigned short kDnsQtypeHTTPS = 65;
constexpr std::size_t kDnsHeaderSize = 12;
constexpr std::size_t kDnsAnswerHeaderSize = 12;

/// Return whether one closed parent-option probe requires an HTTPS DoH handle.
bool OptionProbeNeedsHttps(curl::fuzzer::proto::DohOptionProbeMode mode) {
  switch (mode) {
    case curl::fuzzer::proto::DOH_OPTION_PROBE_CUSTOM_STDERR:
    case curl::fuzzer::proto::DOH_OPTION_PROBE_TLS_PATHS:
    case curl::fuzzer::proto::DOH_OPTION_PROBE_SSL_CTX:
      return true;
    case curl::fuzzer::proto::DOH_OPTION_PROBE_DEFAULT:
    default:
      return false;
  }
}

/// Detect the ECH modes that ask the TLS backend to obtain its configuration
/// from an HTTPS resource record. A literal ECHConfigList already supplies the
/// configuration, while GREASE deliberately does not wait for DNS.
bool EchNeedsPendingHttpsRr(const curl::fuzzer::proto::Scenario& scenario) {
  const std::size_t option_count = RuntimeOptionCount(scenario);
  for (std::size_t index = 0; index < option_count; ++index) {
    const auto& option = scenario.options(static_cast<int>(index));
    if (option.option_id() != curl::fuzzer::proto::CURLOPT_ECH) {
      continue;
    }
    const std::string& value = option.string_value();
    if (value == "true" || value == "hard" || value.rfind("pn:", 0) == 0) {
      return true;
    }
  }
  return false;
}

/// Save one proxy environment variable before the responder replaces it.
/// @param name Environment variable name.
/// @param[out] value Previous value when it was set.
/// @param[out] was_set Whether the variable existed before the override.
void SaveEnvironment(const char* name, std::string* value, bool* was_set) {
  value->clear();
  *was_set = false;
  const char* current = std::getenv(name);
  if (current != nullptr) {
    value->assign(current);
    *was_set = true;
  }
}

/// Restore one saved environment variable, removing it when it was originally
/// absent.
/// @param name Environment variable name.
/// @param value Saved value.
/// @param was_set Whether the variable existed before the override.
void RestoreEnvironment(const char* name, const std::string& value, bool was_set) {
  if (was_set) {
    (void)setenv(name, value.c_str(), 1);
  } else {
    (void)unsetenv(name);
  }
}

/// Switch a descriptor to non-blocking mode.
/// @param fd Descriptor to update.
/// @return true on success.
bool MakeNonBlocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

/// Locate the end of an HTTP request's headers.
/// @param request Buffered request bytes.
/// @return Offset just past the empty line, or npos while incomplete.
std::size_t FindHeaderEnd(const std::string& request) {
  const std::size_t end = request.find("\r\n\r\n");
  return end == std::string::npos ? std::string::npos : end + 4;
}

/// Parse the Content-Length field from a buffered HTTP request.
/// @param request Buffered request bytes.
/// @param header_end Offset just past the header block.
/// @param[out] content_length Parsed non-negative length.
/// @return true when a valid Content-Length header was present.
bool ParseContentLength(const std::string& request, std::size_t header_end, std::size_t* content_length) {
  std::size_t position = 0;
  while (position + 1 < header_end) {
    const std::size_t line_end = request.find("\r\n", position);
    if (line_end == std::string::npos || line_end >= header_end) {
      break;
    }
    constexpr char kName[] = "content-length:";
    const std::size_t name_size = sizeof(kName) - 1;
    if ((line_end - position) > name_size) {
      bool matches = true;
      for (std::size_t index = 0; index < name_size; ++index) {
        const char actual = request[position + index];
        const char expected = kName[index];
        const char folded = (actual >= 'A' && actual <= 'Z') ? static_cast<char>(actual - 'A' + 'a') : actual;
        if (folded != expected) {
          matches = false;
          break;
        }
      }
      if (matches) {
        const char* value = request.c_str() + position + name_size;
        char* parsed_end = nullptr;
        const unsigned long parsed = std::strtoul(value, &parsed_end, 10);
        if (parsed_end != value) {
          *content_length = static_cast<std::size_t>(parsed);
          return true;
        }
      }
    }
    position = line_end + 2;
  }
  return false;
}

/// Synthesize a minimal DNS response matching the probe's QTYPE. A and AAAA
/// answers point at loopback so curl can construct its connection, while an
/// HTTPS query receives an HTTPS resource record carrying alpn=h2,h3. This is
/// the record `cf-https-connect` reads to choose its first ALPN attempt; other
/// QTYPEs receive NOTIMP.
/// @param query DNS request body.
/// @param[out] response Synthesized DNS answer.
/// @param[out] httpsrr Whether the response carried an HTTPS resource record.
/// @return true when a response was produced.
bool BuildDnsResponse(const std::string& query, std::string* response, bool* httpsrr) {
  const auto* bytes = reinterpret_cast<const unsigned char*>(query.data());
  const std::size_t query_len = query.size();
  if (query_len < kDnsHeaderSize) {
    return false;
  }

  std::size_t position = kDnsHeaderSize;
  while (position < query_len) {
    const unsigned char label = bytes[position];
    if (label == 0) {
      ++position;
      break;
    }
    if (label & 0xc0) {
      return false;
    }
    if ((position + 1 + label) > query_len) {
      return false;
    }
    position += static_cast<std::size_t>(1) + label;
  }
  if ((position + 4) > query_len) {
    return false;
  }

  const std::size_t qname_end = position;
  const unsigned short qtype = static_cast<unsigned short>((bytes[qname_end] << 8) | bytes[qname_end + 1]);
  const std::size_t question_len = (qname_end + 4) - kDnsHeaderSize;
  const bool has_answer = qtype == kDnsQtypeA || qtype == kDnsQtypeAAAA || qtype == kDnsQtypeHTTPS;

  std::size_t rdlength = 0;
  switch (qtype) {
    case kDnsQtypeA:
      rdlength = 4;
      break;
    case kDnsQtypeAAAA:
      rdlength = 16;
      break;
    case kDnsQtypeHTTPS:
      // priority, root target, an alpn SvcParam whose length-prefixed values
      // are "h2" and "h3".
      rdlength = 13;
      break;
    default:
      break;
  }

  const std::size_t total = kDnsHeaderSize + question_len + (has_answer ? (kDnsAnswerHeaderSize + rdlength) : 0);
  if (total > 512) {
    return false;
  }

  response->assign(total, '\0');
  auto* out = reinterpret_cast<unsigned char*>(response->data());
  out[0] = bytes[0];  // preserve the probe's transaction ID
  out[1] = bytes[1];
  out[2] = 0x81;                      // QR=1, RD=1
  out[3] = has_answer ? 0x80 : 0x84;  // RA=1; rcode 4 (NOTIMP) otherwise
  out[5] = 1;                         // QDCOUNT
  out[7] = has_answer ? 1 : 0;        // ANCOUNT
  std::memcpy(&out[kDnsHeaderSize], &bytes[kDnsHeaderSize], question_len);

  if (has_answer) {
    unsigned char* answer = &out[kDnsHeaderSize + question_len];
    *answer++ = 0xc0;  // compressed name pointer to the question
    *answer++ = 0x0c;
    *answer++ = static_cast<unsigned char>(qtype >> 8);
    *answer++ = static_cast<unsigned char>(qtype & 0xff);
    *answer++ = 0;
    *answer++ = 1;  // CLASS IN
    *answer++ = 0;
    *answer++ = 0;
    *answer++ = 0;
    *answer++ = 60;  // TTL
    *answer++ = 0;
    *answer++ = static_cast<unsigned char>(rdlength);
    switch (qtype) {
      case kDnsQtypeA:
        *answer++ = 127;
        *answer++ = 0;
        *answer++ = 0;
        *answer++ = 1;
        break;
      case kDnsQtypeAAAA:
        std::memset(answer, 0, 16);
        answer[15] = 1;  // ::1
        break;
      case kDnsQtypeHTTPS: {
        static const unsigned char kHttpsRecord[] = {
            0, 1,         // priority = 1
            0,            // root target (".")
            0, 1,         // SvcParamKey = alpn
            0, 6,         // SvcParamValue length
            2, 'h', '2',  // h2
            2, 'h', '3'   // h3
        };
        std::memcpy(answer, kHttpsRecord, sizeof(kHttpsRecord));
        *httpsrr = true;
        break;
      }
      default:
        break;
    }
  }
  return true;
}

}  // namespace

/// Retain decrypted HTTP request bytes from one accepted TLS connection.
/// The transport may report several records in one drive turn, so overflow is
/// sticky until the owning slot is closed.
/// @param data First decrypted byte.
/// @param size Number of decrypted bytes.
void DohHttpsRrMockServer::DohConnection::ObserveIncomingData(const unsigned char* data, std::size_t size) {
  if (request_overflow || data == nullptr || request.size() > kMaxRequestBytes ||
      size > kMaxRequestBytes - request.size()) {
    request_overflow = true;
    return;
  }
  request.append(reinterpret_cast<const char*>(data), size);
}

/// Construct an idle responder. The listener and proxy bypass are installed
/// by Install(), after the TLS carrier has prepared the outer peer.
/// @param scenario Source of the fixed TLS, DoH, and ECH configuration.
DohHttpsRrMockServer::DohHttpsRrMockServer(const curl::fuzzer::proto::Scenario& scenario)
    : H2OriginMockServer(scenario.tls_certificate_chain()),
      easy_(nullptr),
      listener_(-1),
      option_probe_mode_(scenario.doh().option_probe_mode()),
      transport_mode_(OptionProbeNeedsHttps(option_probe_mode_) ? curl::fuzzer::proto::DOH_TRANSPORT_HTTPS
                                                                : scenario.doh().transport_mode()),
      diagnostic_stream_(nullptr),
      tls_path_fixture_(nullptr),
      internal_ssl_ctx_callback_count_(0),
      doh_tls_transport_(
          transport_mode_ == curl::fuzzer::proto::DOH_TRANSPORT_HTTPS
              ? std::make_unique<TlsMockTransport>(TlsApplicationProtocol::kHttp11, scenario.tls_certificate_chain())
              : nullptr),
      doh_request_count_(0),
      httpsrr_answer_count_(0),
      response_mode_(scenario.doh().response_mode()),
      defer_httpsrr_(EchNeedsPendingHttpsRr(scenario)),
      setup_ok_(false),
      proxy_bypass_active_(false),
      lower_no_proxy_was_set_(false),
      upper_no_proxy_was_set_(false) {
  if (option_probe_mode_ == curl::fuzzer::proto::DOH_OPTION_PROBE_CUSTOM_STDERR) {
    diagnostic_stream_ = std::tmpfile();
  } else if (option_probe_mode_ == curl::fuzzer::proto::DOH_OPTION_PROBE_TLS_PATHS) {
    tls_path_fixture_ = std::make_unique<BoundedAnonymousInputFile>(sizeof(tls_test_credentials::kCertificatePem) - 1);
    (void)tls_path_fixture_->Write(reinterpret_cast<const std::uint8_t*>(tls_test_credentials::kCertificatePem),
                                   sizeof(tls_test_credentials::kCertificatePem) - 1);
  }
}

/// Release the loopback listener and restore the proxy environment before the
/// base carrier tears down its TLS context.
DohHttpsRrMockServer::~DohHttpsRrMockServer() {
  StopListener();
  EndProxyBypass();
  if (diagnostic_stream_ != nullptr) {
    std::fclose(diagnostic_stream_);
  }
}

/// Read a bounded prefix without changing the stream position retained by
/// libcurl. The internal DoH request line appears before the outer transfer can
/// connect, so the prefix is sufficient to distinguish internal diagnostics.
/// @return Captured diagnostic bytes, or an empty string when unavailable.
std::string DohHttpsRrMockServer::custom_stderr_contents() {
  if (diagnostic_stream_ == nullptr || std::fflush(diagnostic_stream_) != 0) {
    return {};
  }
  const int fd = fileno(diagnostic_stream_);
  if (fd < 0) {
    return {};
  }
  std::array<char, kMaxDiagnosticBytes> buffer{};
  ssize_t size;
  do {
    size = pread(fd, buffer.data(), buffer.size(), 0);
  } while (size < 0 && errno == EINTR);
  return size > 0 ? std::string(buffer.data(), static_cast<std::size_t>(size)) : std::string();
}

/// @return Whether the procfs-backed TLS pathname fixture was prepared.
bool DohHttpsRrMockServer::tls_path_fixture_ready() const {
  return tls_path_fixture_ != nullptr && tls_path_fixture_->path() != nullptr;
}

/// Bind the DoH listener, point CURLOPT_DOH_URL at it, and bypass ambient
/// proxies for curl's internal handle. RunLoop refuses to drive the transfer
/// after any partial setup so curl cannot fall back to an unrelated resolver.
/// @param easy Easy handle that will perform the HTTPS transfer.
void DohHttpsRrMockServer::Install(CURL* easy) {
  H2OriginMockServer::Install(easy);
  easy_ = easy;
  setup_ok_ = false;
  if (easy_ == nullptr) {
    return;
  }
  if (!ConfigureHttpsOptions()) {
    return;
  }
  if (!StartListener()) {
    return;
  }
  if (curl_easy_setopt(easy_, CURLOPT_DOH_URL, doh_url_.c_str()) != CURLE_OK) {
    StopListener();
    return;
  }
  if (!BeginProxyBypass()) {
    StopListener();
    return;
  }
  setup_ok_ = true;
}

/// Reassert the listener URL and fixed H2 selection after the scenario's
/// option prefix has run. The DoH URL is absent from the mutation grammar, but
/// CURLOPT_HTTP_VERSION is useful in the ordinary resolver lane and must not
/// override this peer's transport.
/// @param request_data Installed request state; unused by this transport.
void DohHttpsRrMockServer::ConfigureRequestData(ScenarioRequestData* /*request_data*/) {
  setup_ok_ = false;
  if (easy_ == nullptr || doh_url_.empty() || !proxy_bypass_active_) {
    return;
  }
  if (!ConfigureHttpsOptions()) {
    return;
  }
  if (curl_easy_setopt(easy_, CURLOPT_DOH_URL, doh_url_.c_str()) != CURLE_OK) {
    return;
  }
  setup_ok_ = curl_easy_setopt(easy_, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS) == CURLE_OK;
}

/// Refuse to enter libcurl when any local resolver setup step failed. Without
/// a usable CURLOPT_DOH_URL, the HTTPS transfer would otherwise fall back to
/// the process's native resolver before the socket callback can confine its
/// destination.
/// @param multi Multi handle already containing `easy`.
/// @param easy Easy handle driving the outer HTTPS transfer.
/// @param scenario Source of the bounded HTTP/2 response plan.
void DohHttpsRrMockServer::RunLoop(CURLM* multi, CURL* easy, const curl::fuzzer::proto::Scenario& scenario) {
  if (!setup_ok_) {
    return;
  }
  H2OriginMockServer::RunLoop(multi, easy, scenario);
}

/// Observe the outer transfer and advance every pending DoH exchange. curl
/// owns the DoH easy handle, so this runs from the same deterministic outer
/// loop that advances the mocked TLS connection.
/// @param easy Active easy handle whose TLS state is observed.
void DohHttpsRrMockServer::ObserveActiveTransfer(CURL* easy) {
  TlsMockServer::ObserveActiveTransfer(easy);
  ServiceDohConnections();
}

/// Bind one non-blocking HTTP listener on 127.0.0.1 and build the
/// CURLOPT_DOH_URL value that points at its selected plaintext or TLS peer.
/// @return true when the listener is ready.
bool DohHttpsRrMockServer::StartListener() {
  if (listener_ >= 0) {
    return true;
  }

  struct sockaddr_in address;
  std::memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;

  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return false;
  }
  const int reuse = 1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  if (bind(fd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) < 0 || listen(fd, 8) < 0 ||
      !MakeNonBlocking(fd)) {
    close(fd);
    return false;
  }

  socklen_t address_len = sizeof(address);
  if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&address), &address_len) < 0) {
    close(fd);
    return false;
  }

  listener_ = fd;
  const char* scheme = transport_mode_ == curl::fuzzer::proto::DOH_TRANSPORT_HTTPS ? "https" : "http";
  doh_url_ =
      std::string(scheme) + "://127.0.0.1:" + std::to_string(static_cast<int>(ntohs(address.sin_port))) + kDohPath;
  return true;
}

/// Install the parent options that curl copies onto each internal HTTPS DoH
/// handle. Hostname checks are disabled only because the fixed listener URL
/// uses a numeric loopback address; peer verification still uses the outer
/// transport's checked-in CA blob. CERTINFO, NOSIGNAL, and the base class's
/// X25519 setting deliberately exercise their internal-handle propagation.
/// @return true when plaintext mode needs no setup or every option succeeded.
bool DohHttpsRrMockServer::ConfigureHttpsOptions() {
  if (transport_mode_ != curl::fuzzer::proto::DOH_TRANSPORT_HTTPS) {
    return true;
  }

  bool configured = true;
  configured = curl_easy_setopt(easy_, CURLOPT_DOH_SSL_VERIFYHOST, 0L) == CURLE_OK && configured;
  configured = curl_easy_setopt(easy_, CURLOPT_DOH_SSL_VERIFYPEER, 1L) == CURLE_OK && configured;
  configured = curl_easy_setopt(easy_, CURLOPT_CERTINFO, 1L) == CURLE_OK && configured;
  configured = curl_easy_setopt(easy_, CURLOPT_NOSIGNAL, 1L) == CURLE_OK && configured;

  switch (option_probe_mode_) {
    case curl::fuzzer::proto::DOH_OPTION_PROBE_CUSTOM_STDERR:
      if (diagnostic_stream_ == nullptr) {
        return false;
      }
      configured = curl_easy_setopt(easy_, CURLOPT_STDERR, diagnostic_stream_) == CURLE_OK && configured;
      break;
    case curl::fuzzer::proto::DOH_OPTION_PROBE_TLS_PATHS: {
      const char* path = tls_path_fixture_ == nullptr ? nullptr : tls_path_fixture_->path();
      if (path == nullptr) {
        return false;
      }
      configured = curl_easy_setopt(easy_, CURLOPT_CAINFO, path) == CURLE_OK && configured;
      configured = curl_easy_setopt(easy_, CURLOPT_CAPATH, path) == CURLE_OK && configured;
      configured = curl_easy_setopt(easy_, CURLOPT_CRLFILE, path) == CURLE_OK && configured;
      break;
    }
    case curl::fuzzer::proto::DOH_OPTION_PROBE_SSL_CTX:
      configured =
          curl_easy_setopt(easy_, CURLOPT_SSL_CTX_FUNCTION, &DohHttpsRrMockServer::ObserveSslContext) == CURLE_OK &&
          configured;
      configured = curl_easy_setopt(easy_, CURLOPT_SSL_CTX_DATA, this) == CURLE_OK && configured;
      break;
    case curl::fuzzer::proto::DOH_OPTION_PROBE_DEFAULT:
    default:
      break;
  }
  return configured;
}

/// Observe callback/data propagation without inspecting the backend context or
/// re-entering libcurl from inside its TLS setup callback.
/// @param easy Handle whose SSL context is being initialized.
/// @param ssl_context Backend context; intentionally opaque to this probe.
/// @param user_data Server pointer installed with CURLOPT_SSL_CTX_DATA.
/// @return CURLE_OK so the handshake continues normally.
CURLcode DohHttpsRrMockServer::ObserveSslContext(CURL* easy, void* /*ssl_context*/, void* user_data) {
  auto* server = static_cast<DohHttpsRrMockServer*>(user_data);
  if (server != nullptr && easy != server->easy_) {
    ++server->internal_ssl_ctx_callback_count_;
  }
  return CURLE_OK;
}

/// Close the listener and every accepted DoH connection.
void DohHttpsRrMockServer::StopListener() {
  if (listener_ >= 0) {
    close(listener_);
    listener_ = -1;
  }
  for (DohConnection& connection : connections_) {
    CloseConnection(&connection);
  }
  doh_url_.clear();
}

/// Force no_proxy for the internal DoH handle, which does not inherit the
/// parent transfer's CURLOPT_PROXY.
/// @return true when both environment overrides are active.
bool DohHttpsRrMockServer::BeginProxyBypass() {
  if (proxy_bypass_active_) {
    return true;
  }
  SaveEnvironment("no_proxy", &saved_no_proxy_lower_, &lower_no_proxy_was_set_);
  SaveEnvironment("NO_PROXY", &saved_no_proxy_upper_, &upper_no_proxy_was_set_);
  proxy_bypass_active_ = true;
  if (setenv("no_proxy", "*", 1) != 0 || setenv("NO_PROXY", "*", 1) != 0) {
    EndProxyBypass();
    return false;
  }
  return true;
}

/// Restore the proxy environment replaced by BeginProxyBypass.
void DohHttpsRrMockServer::EndProxyBypass() {
  if (!proxy_bypass_active_) {
    return;
  }
  RestoreEnvironment("no_proxy", saved_no_proxy_lower_, lower_no_proxy_was_set_);
  RestoreEnvironment("NO_PROXY", saved_no_proxy_upper_, upper_no_proxy_was_set_);
  saved_no_proxy_lower_.clear();
  saved_no_proxy_upper_.clear();
  lower_no_proxy_was_set_ = false;
  upper_no_proxy_was_set_ = false;
  proxy_bypass_active_ = false;
}

/// Close one accepted connection and reset its buffers.
/// @param connection Connection to release.
void DohHttpsRrMockServer::CloseConnection(DohConnection* connection) {
  connection->tls.reset();
  if (connection->fd >= 0) {
    close(connection->fd);
    connection->fd = -1;
  }
  connection->request.clear();
  connection->response.clear();
  connection->response_offset = 0;
  connection->deferred_write_turns = 0;
  connection->writing = false;
  connection->request_overflow = false;
}

/// Accept every pending DoH probe, up to the fixed connection budget.
void DohHttpsRrMockServer::AcceptConnections() {
  if (listener_ < 0) {
    return;
  }
  for (;;) {
    const int fd = accept(listener_, nullptr, nullptr);
    if (fd < 0) {
      return;
    }
    if (!MakeNonBlocking(fd)) {
      close(fd);
      continue;
    }
    DohConnection* slot = nullptr;
    for (DohConnection& connection : connections_) {
      if (!connection.active()) {
        slot = &connection;
        break;
      }
    }
    if (slot == nullptr) {
      close(fd);
      continue;
    }
    slot->request.clear();
    slot->response.clear();
    slot->response_offset = 0;
    slot->deferred_write_turns = 0;
    slot->writing = false;
    slot->request_overflow = false;
    if (transport_mode_ == curl::fuzzer::proto::DOH_TRANSPORT_HTTPS) {
      if (doh_tls_transport_ == nullptr) {
        close(fd);
        continue;
      }
      std::unique_ptr<MockConnection> tls = doh_tls_transport_->CreateAcceptedConnection(fd);
      if (tls == nullptr || !tls->ok()) {
        continue;
      }
      tls->SetIncomingDataObserver(slot);
      slot->tls = std::move(tls);
    } else {
      slot->fd = fd;
    }
  }
}

/// Advance each accepted connection: buffer the request, synthesize the answer,
/// then send it until the peer drains or closes.
void DohHttpsRrMockServer::ServiceDohConnections() {
  AcceptConnections();

  for (DohConnection& connection : connections_) {
    if (!connection.active()) {
      continue;
    }

    if (!connection.writing) {
      if (connection.tls != nullptr) {
        (void)connection.tls->DrainIncoming();
        if (connection.request_overflow) {
          CloseConnection(&connection);
        }
      } else {
        for (;;) {
          char buffer[1024];
          const ssize_t received = recv(connection.fd, buffer, sizeof(buffer), 0);
          if (received > 0) {
            if (connection.request.size() + static_cast<std::size_t>(received) > kMaxRequestBytes) {
              CloseConnection(&connection);
              break;
            }
            connection.request.append(buffer, static_cast<std::size_t>(received));
            continue;
          }
          if (received == 0) {
            CloseConnection(&connection);
            break;
          }
          if (errno == EINTR) {
            continue;
          }
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
          }
          CloseConnection(&connection);
          break;
        }
      }
      if (connection.active() && CompleteRequest(&connection)) {
        connection.writing = true;
      }
    }

    if (!connection.active() || !connection.writing) {
      continue;
    }

    // Let an address answer advance the outer connection once before making
    // its HTTPS resource record readable. This deterministic one-turn skew
    // exercises the TLS backend's normal "HTTPS-RR still pending" state
    // without a clock, scheduler race, or external resolver.
    if (connection.deferred_write_turns != 0) {
      --connection.deferred_write_turns;
      continue;
    }

    if (connection.tls != nullptr) {
      if (connection.response_offset < connection.response.size()) {
        if (!connection.tls->WriteAll(reinterpret_cast<const unsigned char*>(connection.response.data()),
                                      connection.response.size())) {
          CloseConnection(&connection);
          continue;
        }
        connection.response_offset = connection.response.size();
        connection.tls->ShutdownWrite();
      } else {
        (void)connection.tls->DrainIncoming();
      }
      // TLS writes may require exact retries on later drive turns. Retain the
      // bounded slot until responder teardown rather than guessing completion
      // from an OpenSSL progress count.
      continue;
    }

    while (connection.response_offset < connection.response.size()) {
      const ssize_t sent = send(connection.fd, connection.response.data() + connection.response_offset,
                                connection.response.size() - connection.response_offset, MSG_NOSIGNAL);
      if (sent > 0) {
        connection.response_offset += static_cast<std::size_t>(sent);
        continue;
      }
      if (sent < 0 && errno == EINTR) {
        continue;
      }
      if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      }
      CloseConnection(&connection);
      break;
    }
    if (connection.fd >= 0 && connection.response_offset >= connection.response.size()) {
      CloseConnection(&connection);
    }
  }
}

/// Test whether a buffered request is complete and, if so, synthesize its HTTP
/// response. Unsupported or malformed DNS bodies still receive a bounded HTTP
/// response so curl's DoH probe reports a protocol error instead of hanging.
/// @param connection Connection whose request buffer is inspected.
/// @return true when a response is ready to write.
bool DohHttpsRrMockServer::CompleteRequest(DohConnection* connection) {
  const std::size_t header_end = FindHeaderEnd(connection->request);
  if (header_end == std::string::npos) {
    return false;
  }

  std::size_t content_length = 0;
  const bool has_length = ParseContentLength(connection->request, header_end, &content_length);
  if (has_length) {
    if (content_length > (kMaxRequestBytes - header_end)) {
      CloseConnection(connection);
      return false;
    }
    if (connection->request.size() < header_end + content_length) {
      return false;
    }
  } else {
    content_length = connection->request.size() - header_end;
  }

  if (response_mode_ == curl::fuzzer::proto::DOH_RESPONSE_MODE_TRANSPORT_ERROR) {
    ++doh_request_count_;
    CloseConnection(connection);
    return false;
  }

  const std::string body = connection->request.substr(header_end, content_length);
  std::string dns;
  bool httpsrr = false;
  if (!BuildDnsResponse(body, &dns, &httpsrr)) {
    dns.clear();
  }
  if (response_mode_ == curl::fuzzer::proto::DOH_RESPONSE_MODE_MALFORMED_DNS) {
    // A non-empty, header-short message reaches curl's DoH decode error path
    // after an otherwise successful HTTP exchange. Keeping one byte avoids
    // conflating the parser failure with an empty response body.
    dns.assign(1, '\0');
    httpsrr = false;
  }

  if (response_mode_ == curl::fuzzer::proto::DOH_RESPONSE_MODE_HTTP_ERROR) {
    dns.clear();
    httpsrr = false;
  }

  connection->response =
      (response_mode_ == curl::fuzzer::proto::DOH_RESPONSE_MODE_HTTP_ERROR ? "HTTP/1.1 404 DoH\r\n"
                                                                           : "HTTP/1.1 200 DoH\r\n") +
      std::string(
          "Content-Type: application/dns-message\r\n"
          "Content-Length: ") +
      std::to_string(dns.size()) +
      "\r\n"
      "Connection: close\r\n"
      "\r\n" +
      dns;
  if (connection->response.size() > kMaxResponseBytes) {
    CloseConnection(connection);
    return false;
  }
  connection->response_offset = 0;
  connection->deferred_write_turns = httpsrr && defer_httpsrr_ ? 1 : 0;
  ++doh_request_count_;
  if (httpsrr) {
    ++httpsrr_answer_count_;
  }
  return true;
}

}  // namespace proto_fuzzer
