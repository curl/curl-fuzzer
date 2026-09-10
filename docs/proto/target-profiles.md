# Target profiles

All structured targets share the binary `Scenario` wire format and most of the
runtime. A target profile defines which part of that format is meaningful,
which peer is used, and how much work one mutation may create.

| Target | Profile and peer focus |
|---|---|
| `curl_fuzzer_proto` | Compatibility target for the historical mixed HTTP, HTTPS, WebSocket, and TELNET corpus. It deliberately has no profile postprocessor. |
| `curl_fuzzer_proto_http` | High-throughput plaintext HTTP. Retains cheap request options and raw response parsing; removes MIME, uploads, follow-on sockets, and timing controls. |
| `curl_fuzzer_proto_http_deep` | Stateful HTTP coverage, including redirects, authentication, MIME, uploads, result APIs, and bounded cookie, Alt-Svc, HSTS, and netrc files. |
| `curl_fuzzer_proto_https` | HTTP/1.1 through a real in-process TLS peer, including certificate, session, TLS result-state, and bounded CRL-input coverage. |
| `curl_fuzzer_proto_https_gnutls` / `curl_fuzzer_proto_https_mbedtls` | The HTTPS profile with a GnuTLS or mbedTLS curl client; the local server side remains the harness TLS peer and both variants reuse the HTTPS generated seed corpus. |
| `curl_fuzzer_proto_https_h2` | Raw HTTP/2 origin frames after a verified TLS/ALPN handshake, plus push and upkeep probes. |
| `curl_fuzzer_proto_http3` | Structured or raw HTTP/3/QPACK work after a real local QUIC/TLS handshake. |
| `curl_fuzzer_proto_h2_proxy` | An HTTP/1.1 origin request through a fixed trust-anchor-verified HTTPS/HTTP/2 CONNECT proxy; mutations control bounded raw proxy frames and origin request settings. |
| `curl_fuzzer_proto_socks4` | HTTP through an in-process SOCKS4 or SOCKS4A proxy. |
| `curl_fuzzer_proto_resolver` | Localhost resolution and bounded `CURLOPT_RESOLVE` host-cache operations while harness callbacks retain transport control. |
| `curl_fuzzer_proto_ws` | Plaintext WebSocket handshake, framing, callbacks, and manual-drive paths. |
| `curl_fuzzer_proto_wss` | Secure-WebSocket setup under a fixed WSS scheme, with backpressure removed from this fast lane. |
| `curl_fuzzer_proto_telnet` | Bounded TELNET negotiation and callback-backed input against a preloaded local peer. |
| `curl_fuzzer_proto_ftp` | Plain FTP control plus passive or loopback-confined active data connections. |
| `curl_fuzzer_proto_tftp` | Packet-preserving TFTP exchanges over private loopback UDP endpoints. |
| `curl_fuzzer_proto_gopher` | Bounded Gopher or Gophers selectors through a stream peer, using the TLS peer for Gophers when available. |
| `curl_fuzzer_proto_api` | Easy, share, multi, URL, connect-only, pause/resume, and typed result API lifecycles described by `api_plan`. |
| `curl_fuzzer_proto_multi` | Two to four easy handles on one shared multi handle, with bounded scheduling actions, connection-cache controls, and a five-second packaged timeout. |
| `curl_fuzzer_proto_timing` | Plain HTTP or WebSocket backpressure and timed-wait behavior; it guarantees a non-default bounded pressure configuration. |

The exact target inventory and platform gates are maintained in
`scripts/fuzz_targets`. Structured targets are excluded from i386 builds. The
GnuTLS, mbedTLS, and HTTP/3 variants are also excluded from MemorySanitizer
builds, and HTTP/3 is created only when its dependency variant is enabled.
MemorySanitizer omits OpenSSL and the TLS mock peer. In that build,
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
forces bounded pressure. HTTP/3 discards the stream `Connection` entirely,
while FTP, TFTP, TELNET, and Gopher prune fields that their specialized peers
cannot observe.

The compatibility profile is intentionally different. Existing OSS-Fuzz
inputs are keyed to `curl_fuzzer_proto`, so changing its normalization would
change the meaning of accumulated corpus and crash files. New protocol enum
values and fields must therefore default to the old behavior or be gated so
the compatibility runner does not reinterpret historical wire data.

## Choosing a target for a seed or crash

Use the narrowest target that owns the behavior:

- Prefer `http` for cheap request/response parsing, `http_deep` for stateful or
  file-backed work, and `timing` for intentional backpressure.
- Use `https`, `https_h2`, or `http3` according to the actual transport rather
  than putting TLS or frame setup into an HTTP seed.
- Put lifecycle-only work in `api` or `multi`, keeping it out of protocol-hot
  loops.
- Replay a crash with the binary named by OSS-Fuzz. Although fixed lanes share
  a wire format, their policies can transform the same bytes differently.

See [Writing and inspecting scenarios](scenarios.md) for corpus generation and
[Extending the structured suite](extending.md) for the invariants a new lane
must implement.
