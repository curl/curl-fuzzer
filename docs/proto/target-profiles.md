# Target profiles

All structured targets share the binary `Scenario` wire format and most of the
runtime. A target profile defines which part of that format is meaningful,
which peer is used, and how much work one mutation may create.

| Target | Profile and peer focus |
|---|---|
| `curl_fuzzer_proto` | Compatibility target for the historical mixed HTTP, HTTPS, WebSocket, and TELNET corpus. It deliberately has no profile postprocessor. |
| `curl_fuzzer_proto_http` | High-throughput plaintext HTTP/1 and h2c upgrade negotiation. Retains cheap request options and raw response parsing; removes MIME, uploads, follow-on sockets, prior-knowledge HTTP/2, HTTP/3 selection, and timing controls. |
| `curl_fuzzer_proto_http_deep` | Stateful HTTP coverage, including redirects, authentication, MIME, uploads, result APIs, bounded cookie, Alt-Svc, HSTS, and netrc files, plus harness-owned forward-proxy, HTTP CONNECT, and abstract Unix-domain transports. |
| `curl_fuzzer_proto_http2` | High-throughput HTTP/2 origin frames over plaintext prior knowledge, using the same structured and malformed frame grammar as the TLS lane. |
| `curl_fuzzer_proto_https` | HTTP/1.1 through a real in-process TLS peer, including certificate, session, TLS result-state, bounded CRL input, and closed harness-owned client-credential profiles. |
| `curl_fuzzer_proto_https_gnutls` / `curl_fuzzer_proto_https_mbedtls` | The HTTPS profile with a GnuTLS or mbedTLS curl client; the local server side remains the harness TLS peer and both variants reuse the HTTPS generated seed corpus. |
| `curl_fuzzer_proto_https_h2` | Structured and malformed HTTP/2 origin frames after a verified TLS/ALPN handshake, input-selectable X25519 or provider-default key exchange, plus push and upkeep probes. |
| `curl_fuzzer_proto_http3` | Structured or raw HTTP/3/QPACK work after a real local QUIC/TLS handshake, or capsule traffic through a local HTTP/1.1 CONNECT-UDP proxy. |
| `curl_fuzzer_proto_h2_proxy` | An HTTP/1.1 origin request through a fixed trust-anchor-verified HTTPS/HTTP/2 CONNECT proxy; mutations control bounded raw proxy frames and origin request settings. |
| `curl_fuzzer_proto_socks4` | HTTP through an in-process SOCKS4, SOCKS4A, SOCKS5, or SOCKS5-hostname proxy, including scripted SOCKS5 username/password authentication and an optional fixed HAProxy protocol-v1 prefix. The historical basename is retained for accumulated-corpus compatibility. |
| `curl_fuzzer_proto_resolver` | Localhost and bounded `CURLOPT_RESOLVE` cache operations; deterministic positive, negative, link-local retry, and Unix-socket resolver states; a real loopback happy-eyeballs race; and loopback DoH success or malformed-answer diagnostics. |
| `curl_fuzzer_proto_ws` | Plaintext WebSocket handshake, framing, callbacks, and manual-drive paths. |
| `curl_fuzzer_proto_wss` | Verified in-process TLS followed by the WebSocket handshake, framing, callbacks, and manual-drive paths. |
| `curl_fuzzer_proto_telnet` | Bounded TELNET negotiation and callback-backed input against a preloaded local peer. |
| `curl_fuzzer_proto_ftp` | Plain FTP control plus passive or loopback-confined active data connections. The same target runs implicit-TLS `ftps://` scenarios through a verified in-process TLS peer, with both control and passive data channels wrapped and active mode deliberately unavailable. |
| `curl_fuzzer_proto_tftp` | Packet-preserving TFTP exchanges over private loopback UDP endpoints. |
| `curl_fuzzer_proto_smtp` | Single-connection SMTP greeting, EHLO/HELO, mail envelope, DATA body upload and EOB drain, graceful QUIT, and opt-in active pollset probes. The same target also runs implicit-TLS `smtps://` scenarios through a verified in-process TLS peer. |
| `curl_fuzzer_proto_imap` | Single-connection IMAP greeting, CAPABILITY, LOGIN/AUTHENTICATE, SELECT, FETCH literals, APPEND uploads, tagged completion, and opt-in active pollset probes. The same target also runs implicit-TLS `imaps://` scenarios through a verified in-process TLS peer. |
| `curl_fuzzer_proto_pop3` | Single-connection POP3 greeting, CAPA, USER/PASS or APOP, LIST, RETR multi-line bodies, QUIT, and opt-in active pollset probes. The same target also runs implicit-TLS `pop3s://` scenarios through a verified in-process TLS peer. |
| `curl_fuzzer_proto_mqtt` | Single-connection binary MQTT CONNECT/CONNACK, PUBLISH or SUBSCRIBE/SUBACK, server-initiated PUBLISH packets, and DISCONNECT. The same target also runs implicit-TLS `mqtts://` scenarios through a verified in-process TLS peer. |
| `curl_fuzzer_proto_dict` | Single-connection DICT lookups. curl writes CLIENT, one URL-derived command, and QUIT together, then reads the multi-line text response until the peer half-closes. |
| `curl_fuzzer_proto_gopher` | Bounded Gopher or Gophers selectors through a stream peer, using the TLS peer for Gophers when available. |
| `curl_fuzzer_proto_file` | `file://` URL parsing with a fuzz-controlled authority and suffix, pinned to `/dev/null`. There is no network peer; bounded uploads exercise the local write path only against that fixed sink. |
| `curl_fuzzer_proto_ldap` | Single-connection BER/ASN.1 LDAP simple or SASL PLAIN bind and search through OpenLDAP, including bounded root-DSE mechanism discovery, a scripted bind reply, scripted search-result entries, and synthesized search completion. `SCHEME_LDAPS` runs the identical exchange over implicit TLS against the in-process OpenSSL peer. |
| `curl_fuzzer_proto_rtsp` | Single-connection, request-aligned RTSP method/CSeq exchanges, SDP response bodies, and PLAY responses with interleaved RTP packets. |
| `curl_fuzzer_proto_ipfs` | `ipfs://` and `ipns://` gateway rewrites as ordinary HTTP GETs against the in-process HTTP peer, with a pinned CID/name and a mutation-controlled gateway path. |
| `curl_fuzzer_proto_api` | Easy, share, multi, URL, connect-only, pause/resume, and typed result API lifecycles described by `api_plan`. |
| `curl_fuzzer_proto_multi` | Two to four easy handles on one shared multi handle, with bounded scheduling actions, connection-cache controls, and a five-second packaged timeout. |
| `curl_fuzzer_proto_timing` | Plain HTTP or WebSocket backpressure and timed-wait behavior; it guarantees a non-default bounded pressure configuration. |

The exact target inventory and platform gates are maintained in
`scripts/fuzz_targets`. Structured targets are excluded from i386 builds. The
GnuTLS, mbedTLS, and HTTP/3 variants are also excluded from MemorySanitizer
builds, and HTTP/3 is created only when its dependency variant is enabled.
MemorySanitizer omits OpenSSL and the TLS mock peer. The plaintext
`curl_fuzzer_proto_http2` lane remains active in that build. In contrast,
`curl_fuzzer_proto_https_h2` and `curl_fuzzer_proto_h2_proxy` return without
driving their peer-dependent scenarios, while `curl_fuzzer_proto_https` cannot
complete its ordinary verified-TLS path.

## What policy application changes

Before a fixed target executes a loaded or newly mutated message, its
postprocessor:

- fixes or narrows the scheme and, where required, canonicalizes the authority;
- retains only options that can affect that peer and transfer mode;
- removes protocol-specific plans, file inputs, and connection shapes that the
  lane cannot consume;
- caps options, headers, response chunks, connection count, upload data, MIME
  parts, API actions, and protocol-specific byte budgets; and
- canonicalizes small enums and transport settings onto useful, safe ranges.

The shared limits are in `proto_fuzzer/scenario_limits.h`; profile-specific
selection is in `proto_fuzzer/target_policy.cc`. Runtime code repeats important
bounds so callers that bypass mutation policy cannot create unchecked work.
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

The resolver profile also clears arbitrary backpressure. Its four threaded
`resolver_mode` values install one fixed timed-drive marker instead. Their
authorities are pinned to names handled by the resolver binary's target-local
`getaddrinfo` backend: no ambient name service is consulted, returned address
lists are owned and bounded, and a fixed family delay makes the partial-result
path intentional. The Unix mode gives curl a fixed nonexistent pathname, but
the open-socket callback still substitutes its anonymous socketpair. The DoH
error mode serves one-byte DNS messages over the same loopback HTTP transport
used by the successful HTTPS-RR mode. A dedicated localhost seed balances the
process-wide curl cleanup and allocator-preserving reinitialization lifecycle
between inputs, after all per-transfer resolver workers have been joined.

The fixed SMTP, IMAP, POP3, FTP/FTPS, MQTT/MQTTS, and proxy-transport profiles
retain `probe_multi_pollset`; deep HTTP retains it only for its CONNECT proxy
mode. Every other fixed profile clears it. The flag adds zero-timeout public
multi-poll calls only while those peers' perform loop has a live transfer and
protocol socket, so ordinary false/default corpus entries do not pay for an
unconditional polling syscall. The proxy-transport lane may probe several
bounded perform turns because its HAProxy filter is installed only after SOCKS
negotiation completes.

The compatibility profile is intentionally different. Existing OSS-Fuzz
inputs are keyed to `curl_fuzzer_proto`, so changing its normalization would
change the meaning of accumulated corpus and crash files. New protocol enum
values and fields must therefore default to the old behavior or be gated so
the compatibility runner does not reinterpret historical wire data.

## Choosing a target for a seed or crash

Use the narrowest target that owns the behavior:

- Prefer `http` for cheap request/response parsing, `http_deep` for stateful or
  file-backed work, and `timing` for intentional backpressure.
- Use `https`, `http2`, `https_h2`, or `http3` according to the actual transport
  rather than putting protocol frame setup into an HTTP seed.
- Put lifecycle-only work in `api` or `multi`, keeping it out of protocol-hot
  loops.
- Replay a crash with the binary named by OSS-Fuzz. Although fixed lanes share
  a wire format, their policies can transform the same bytes differently.

See [Writing and inspecting scenarios](scenarios.md) for corpus generation and
[Extending the structured suite](extending.md) for the invariants a new lane
must implement.
