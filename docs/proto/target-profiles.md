# Target profiles

All structured targets are generated from one authoring schema and share most
of the runtime, but each target gives libprotobuf-mutator its own restricted
message type. Retained fields keep the authoring field numbers and wire types,
so ordinary authored seed bytes remain profile-compatible. A profile defines
the mutation surface, peer, semantic normalization, and work budget.

| Target | Profile and peer focus |
|---|---|
| `curl_fuzzer_proto` | Broad generated compatibility profile for mixed HTTP, HTTPS, WebSocket, and TELNET behavior. It preserves the historical execution mode, but uses the new typed-option schema like every other target. |
| `curl_fuzzer_proto_http` | High-throughput plaintext HTTP/1 and h2c upgrade negotiation. Retains cheap request options and raw response parsing; removes MIME, uploads, follow-on sockets, prior-knowledge HTTP/2, HTTP/3 selection, and timing controls. |
| `curl_fuzzer_proto_http_deep` | Stateful HTTP coverage, including redirects, dead connection-pool pruning, authentication, MIME construction and redirected body rewinds, uploads, result APIs, bounded cookie, Alt-Svc, HSTS, and netrc files; harness-owned forward-proxy, HTTP CONNECT (including a bounded pending HAProxy-prefix pollset profile), and abstract Unix-domain transports; plus fixed no-proxy/environment-proxy parsing and owned-loopback interface/keepalive setup. |
| `curl_fuzzer_proto_http2` | High-throughput HTTP/2 origin frames over plaintext prior knowledge, using the same structured and malformed frame grammar as the TLS lane. |
| `curl_fuzzer_proto_https` | HTTP/1.1 through a real in-process TLS peer, including certificate, session, TLS result-state, bounded CRL input, closed harness-owned client-credential profiles, and a fixed OpenSSL clean-handshake-close probe. |
| `curl_fuzzer_proto_https_gnutls` / `curl_fuzzer_proto_https_mbedtls` | The HTTPS profile with a GnuTLS or mbedTLS curl client; the local server side remains the harness TLS peer and both variants reuse the HTTPS generated seed corpus. |
| `curl_fuzzer_proto_https_h2` | Structured and malformed HTTP/2 origin frames after a verified TLS/ALPN handshake, input-selectable X25519 or provider-default key exchange, plus push, live stream-weight, fatal-session, and upkeep probes. |
| `curl_fuzzer_proto_http3` | Structured or raw HTTP/3/QPACK work after a real local QUIC/TLS handshake, or capsule traffic through a local HTTP/1.1 CONNECT-UDP proxy. |
| `curl_fuzzer_proto_h2_proxy` | An HTTP/1.1 origin request through a fixed trust-anchor-verified HTTPS CONNECT proxy. `connection.proxy_protocol` selects the existing HTTP/2 frame peer or a bounded HTTP/1.1 CONNECT response profile; proxy authentication options remain owned by this lane. |
| `curl_fuzzer_proto_socks4` | HTTP through an in-process SOCKS4, SOCKS4A, SOCKS5, or SOCKS5-hostname proxy, including scripted SOCKS5 username/password authentication and an optional fixed HAProxy protocol-v1 prefix. The historical basename is retained as the target identity. |
| `curl_fuzzer_proto_resolver` | Localhost and bounded `CURLOPT_RESOLVE` cache operations; deterministic positive, negative, link-local retry, queued-cancellation/idle-wait, and Unix-socket resolver states; a real loopback happy-eyeballs race; and loopback DoH success or malformed-answer diagnostics. |
| `curl_fuzzer_proto_ws` | Plaintext WebSocket handshake, framing, callbacks, and manual-drive paths. |
| `curl_fuzzer_proto_wss` | Verified in-process TLS followed by the WebSocket handshake, framing, callbacks, and manual-drive paths. |
| `curl_fuzzer_proto_telnet` | Bounded TELNET negotiation and callback-backed input against a preloaded local peer. |
| `curl_fuzzer_proto_ftp` | Plain FTP control plus passive or loopback-confined active data connections. The same target runs implicit-TLS `ftps://` scenarios through a verified in-process TLS peer, with both control and passive data channels wrapped and active mode deliberately unavailable. |
| `curl_fuzzer_proto_tftp` | Packet-preserving TFTP exchanges over private loopback UDP endpoints. |
| `curl_fuzzer_proto_smtp` | Single-connection SMTP greeting, EHLO/HELO, mail envelope, DATA body upload and EOB drain, graceful QUIT, and opt-in active pollset probes. The same target also runs implicit-TLS `smtps://` scenarios through a verified in-process TLS peer. |
| `curl_fuzzer_proto_imap` | Single-connection IMAP greeting, CAPABILITY, LOGIN/AUTHENTICATE (including SASL LOGIN, DIGEST-MD5 challenge handling, and XOAUTH2 bearer construction), SELECT, SEARCH, FETCH literals and custom listings, APPEND uploads, tagged completion, and opt-in active pollset probes. The same target also runs implicit-TLS `imaps://` scenarios through a verified in-process TLS peer. |
| `curl_fuzzer_proto_pop3` | Single-connection POP3 greeting, CAPA, USER/PASS or APOP, LIST, RETR multi-line bodies, QUIT, and opt-in active pollset probes. The same target also runs implicit-TLS `pop3s://` scenarios through a verified in-process TLS peer. |
| `curl_fuzzer_proto_mqtt` | Single-connection binary MQTT CONNECT/CONNACK, PUBLISH or SUBSCRIBE/SUBACK, server-initiated PUBLISH packets, and DISCONNECT. The same target also runs implicit-TLS `mqtts://` scenarios through a verified in-process TLS peer. |
| `curl_fuzzer_proto_dict` | Single-connection DICT lookups. curl writes CLIENT, one URL-derived command, and QUIT together, then reads the multi-line text response until the peer half-closes. |
| `curl_fuzzer_proto_gopher` | Bounded Gopher or Gophers selectors through a stream peer, using the TLS peer for Gophers when available. |
| `curl_fuzzer_proto_file` | `file://` URL parsing with a fuzz-controlled authority and suffix, pinned to `/dev/null`. There is no network peer; bounded uploads exercise the local write path only against that fixed sink. |
| `curl_fuzzer_proto_ldap` | Single-connection BER/ASN.1 LDAP simple or SASL PLAIN bind and search through OpenLDAP, including bounded root-DSE mechanism discovery, a scripted bind reply, scripted search-result entries, and synthesized search completion. `ldap_starttls` drives a correlated plaintext ExtendedRequest/ExtendedResponse before curl installs its TLS filter; `SCHEME_LDAPS` runs the ordinary exchange over implicit TLS against the in-process OpenSSL peer. |
| `curl_fuzzer_proto_rtsp` | Single-connection, request-aligned RTSP method/CSeq exchanges, SDP response bodies, and PLAY responses with interleaved RTP packets. |
| `curl_fuzzer_proto_ipfs` | `ipfs://` and `ipns://` gateway rewrites as ordinary HTTP GETs against the in-process HTTP peer, with a pinned CID/name and a mutation-controlled gateway path. |
| `curl_fuzzer_proto_api` | Easy, share, multi, URL, connect-only, pause/resume, callback-MIME same-handle reuse, and typed result API lifecycles described by `api_plan`. |
| `curl_fuzzer_proto_multi` | Two to four easy handles on one shared multi handle, with bounded scheduling actions, connection-cache controls, an opt-in closed progress/rate-limit probe, and a five-second packaged timeout. |
| `curl_fuzzer_proto_timing` | Plain HTTP or WebSocket backpressure and timed-wait behavior; it guarantees a non-default bounded pressure configuration. |

The exact target inventory and platform gates are maintained in
`scripts/fuzz_targets`. The base structured targets are included in OSS-Fuzz's
AddressSanitizer/i386 build. The GnuTLS, mbedTLS, and HTTP/3 variants are
excluded from i386 and MemorySanitizer builds, and HTTP/3 is created only when
its dependency variant is enabled.
MemorySanitizer omits OpenSSL and the TLS mock peer. The plaintext
`curl_fuzzer_proto_http2` lane remains active in that build. In contrast,
`curl_fuzzer_proto_https_h2` and `curl_fuzzer_proto_h2_proxy` return without
driving their peer-dependent scenarios, while `curl_fuzzer_proto_https` cannot
complete its ordinary verified-TLS path.

## What policy application changes

Before a fixed target executes a loaded or newly mutated generated message, its
postprocessor lowers it into the internal runtime representation and:

- fixes or narrows the scheme and, where required, canonicalizes the authority;
- evaluates generated conditional eligibility after selector normalization;
- removes variant-specific options and fields that the selected mode cannot
  consume;
- caps options, headers, response chunks, connection count, upload data, MIME
  parts, API actions, and protocol-specific byte budgets; and
- canonicalizes small enums and transport settings onto useful, safe ranges.

Static option and field selection is declared beside fields in
`schemas/curl_fuzzer.proto` and compiled into each generated profile root.
Conditional membership is also declared there and emitted as a generated
pruner. The shared limits and semantic selector normalization remain in
`proto_fuzzer/scenario_limits.h` and `proto_fuzzer/target_policy.cc`. Runtime
code repeats important bounds so callers that bypass mutation policy cannot
create unchecked work.
The packaged libFuzzer configuration also caps each serialized structured
input at 32 KiB.

Fast lanes clear backpressure because a single mutated value would otherwise
move an ordinary case into a timed loop. The timing lane does the inverse and
forces bounded pressure. Direct HTTP/3 discards the stream `Connection`;
CONNECT-UDP mode retains it and clears direct HTTP/3 actions. FTP, TFTP,
SMTP, IMAP, POP3, MQTT, DICT, LDAP, LDAPS, FTPS, MQTTS, IMAPS, POP3S, RTSP,
IPFS/IPNS, TELNET, Gopher, and FILE prune fields that their specialized peers
(or, for FILE, the peerless local reader) cannot observe. The IPFS/IPNS lane
rewrites both schemes to a `/ipfs/<cid>` or `/ipns/<name>` HTTP path on a fixed
loopback gateway before the request reaches the ordinary HTTP peer. The FILE
lane additionally replaces the URL path with `/dev/null`. It retains bounded
upload state and can write only to that fixed sink; the authority, query, and
fragment remain mutation-controlled so URL parsing still has fuzzing value
without granting access to host files.

The resolver profile also clears arbitrary backpressure. Its successful
HTTPS-RR exchange has a trace-enabled coverage twin with the same peer
transcript; trace state remains scoped to that input. A second HTTPS-RR seed
requests ECH and defers that answer for one drive turn, so TLS setup observes
the record as pending before the transfer completes. Its five threaded
`resolver_mode` values install one fixed timed-drive marker instead. Their
authorities are pinned to names handled by the resolver binary's target-local
`getaddrinfo` backend: no ambient name service is consulted, returned address
lists are owned and bounded, and a fixed family delay makes the partial-result
path intentional. The queued-cancellation mode holds one worker-owned lookup,
cancels only later queue-owned work, then requires the public `THREADS` trace
to report the worker idle after release; acquiring that trace state proves the
worker entered its configured timed wait. The Unix mode gives curl a fixed
nonexistent pathname, but the open-socket callback still substitutes its
anonymous socketpair. The DoH error mode serves one-byte DNS messages over the
same loopback HTTP transport used by the successful HTTPS-RR mode. A dedicated
localhost seed balances the process-wide curl cleanup and
allocator-preserving reinitialization lifecycle between inputs, after all
per-transfer resolver workers have been joined.

The fixed SMTP, IMAP, POP3, FTP/FTPS, MQTT/MQTTS, and proxy-transport profiles
retain `probe_multi_pollset`; deep HTTP retains it only for its CONNECT proxy
mode. Every other fixed profile clears it. The flag adds zero-timeout public
multi-poll calls only while those peers' perform loop has a live transfer and
protocol socket, so ordinary false/default corpus entries do not pay for an
unconditional polling syscall. The proxy-transport lane may probe several
bounded perform turns because its HAProxy filter is installed only after SOCKS
negotiation completes.

The multi profile's `MULTI_STATE_PROBE_PROGRESS_RATE_LIMIT` value is a closed
state-machine probe. The runtime redirects the internal progress meter to an
owned anonymous temporary stream, enables it, and applies a fixed one-byte per
second receive limit plus a 20-millisecond transfer timeout to every easy
handle. The authored seed releases each two-byte response body over two peer
turns so curl must observe the rate-limited state before cleanup. None of the
sink, rate, or timeout values is mutation-controlled, and failure to create the
anonymous stream leaves the probe disabled.

This probe deliberately does not manufacture the error-only
`Curl_creader_free` path: that function needs a request-body reader to be
created and then rejected, which would couple this generic state-machine case
to an unrelated allocation-failure index. It also does not claim
`Curl_multi_wakeup_internal`, whose live call site belongs to the threaded
resolver lifecycle rather than the generic multi runner. The identity content
decoder used by the seed does safely exercise `Curl_cwriter_def_write` as part
of the response path.

The compatibility profile is intentionally broad. Its generated root preserves
empty option slots and its runner keeps the mixed execution mode rather than
applying one fixed lane's restrictions. The typed-option cutover was still a
breaking in-place format change: pre-cutover OSS-Fuzz corpus and crash files
must be replayed with their original revision and target. New fields and enum
values must continue to avoid reinterpreting older wire tags.

## Choosing a target for a seed or crash

Use the narrowest target that owns the behavior:

- Prefer `http` for cheap request/response parsing, `http_deep` for stateful or
  file-backed work, and `timing` for intentional backpressure.
- Use `https`, `http2`, `https_h2`, or `http3` according to the actual transport
  rather than putting protocol frame setup into an HTTP seed.
- Put lifecycle-only work in `api` or `multi`, keeping it out of protocol-hot
  loops.
- Replay a crash with the binary and curl-fuzzer revision named by OSS-Fuzz.
  Profile roots preserve common field tags, but different profiles can discard
  or normalize the same bytes differently, and pre-cutover bytes use a
  different option layout.

See [Writing and inspecting scenarios](scenarios.md) for corpus generation and
[Extending the structured suite](extending.md) for the invariants a new lane
must implement.
