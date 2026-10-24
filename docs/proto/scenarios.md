# Writing and inspecting scenarios

The checked-in scenario sources live below `scenarios/curl_fuzzer_proto/` and
use protobuf's text format. They are the source of truth for seed inputs. Do
not check generated `.scenario` files into `corpora/`; CMake writes those
derived binary files to `build/generated_corpora/<corpus-name>/`. The corpus
name normally matches the target. The GnuTLS and mbedTLS HTTPS variants reuse
`build/generated_corpora/curl_fuzzer_proto_https/`; the canonical mapping is
in `scripts/fuzz_corpus_helpers.sh`.

## A minimal scenario

```protobuf
scheme: SCHEME_HTTP
host_path: "127.0.0.1/basic"
connection {
  initial_response: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
}
```

`scheme` and `host_path` form the request URL. Most byte-bearing fields use
protobuf `bytes`, so textproto escape sequences can represent arbitrary wire
data. `SetOption` entries use a checked-in `CURLOPT_*` identifier and a `oneof`
typed value. At most one value member can be present; authored seeds should use
the kind expected by that option:

```protobuf
options {
  option_id: CURLOPT_NOBODY
  bool_value: true
}
```

The main groups of fields are:

- Request configuration: `options`, `request_headers`, `mime_post`, `upload`,
  and `telnet_options`.
- Peer work: `connection`, `subsequent_connections`, structured WebSocket
  frames, and `http3_plan`.
- Focused lanes: `api_plan`, `multi_plan`, `resolve_entries`, `happy_eyeballs`,
  `doh_https_rr`, TLS certificate selection, HTTPS/H2 key-exchange selection,
  `socks_proxy_mode`, `haproxy_protocol`, `http_transport_mode`, `trace_ids`,
  `probe_multi_pollset`, filename-backed parser inputs, and
  `fail_allocations`.

Read the comments in `schemas/curl_fuzzer.proto` for the complete field
contract. Its checked-in `CurlOptionId` numbers are part of the serialized
corpus format. During the build, the option-manifest generator validates them
against the selected curl checkout's `curl.h`, then stages an identical schema
at `build/schemas/curl_fuzzer.proto`. The entries between the schema's
`CURL-OPTIONS` markers are the active options available to `SetOption`.

## Peer scripts depend on the target

For the ordinary HTTP peer, `connection.initial_response` is sent when curl
opens the socket and each `on_readable` value is released on a later readable
turn. `subsequent_connections` supplies bounded scripts for redirects,
authentication retries, and other fresh HTTP sockets.

The deep HTTP lane can instead select a fixed plaintext forward proxy, a fixed
HTTP/1.1 CONNECT proxy, or a fixed abstract Unix-domain origin with
`http_transport_mode`. Proxy traffic is always directed to a numeric loopback
endpoint and every socket is replaced by the in-process peer; Unix mode uses a
harness-owned abstract name and creates no filesystem entry. Use
request-triggered `on_readable` chunks for these modes. A CONNECT script puts
the tunnel response first and the origin response second.

Other peers intentionally give those fields narrower meanings:

- WebSocket scenarios use a peer that generates the `101` handshake and
  accepts either raw chunks or structured `server_frames`. The WSS lane runs
  that same Upgrade, framing, callback, and manual-drive behavior after a
  verified in-process TLS handshake. For `CURLOPT_CONNECT_ONLY=2`, the peer
  coalesces the first bounded frame with the `101` response so libcurl must
  preserve already-read payload for `curl_ws_recv`; later chunks are delivered
  by the manual-drive tail.
- The dedicated HTTPS peer encrypts connection-script bytes as HTTP
  application data. The compatibility target preserves its older behavior and
  treats HTTPS script bytes as raw TLS records.
- TELNET preloads a bounded response before entering curl's blocking protocol
  loop.
- FTP treats the primary connection as command-aligned control replies and
  follow-on connections as data streams. An `SCHEME_FTPS` scenario runs the
  identical command and passive-data exchange over implicit TLS: the control
  connection and each EPSV/PASV data connection complete a verified handshake,
  and the script must answer curl's `PBSZ 0` and `PROT P` commands after login.
  Its fixed authority is `tls.test`, matching the checked-in trust anchor, and
  the handshakes carry no ALPN extension. Active mode is not available in this
  lane because it would require wrapping a real TCP listener rather than a
  socketpair; `CURLOPT_FTPPORT` is removed from FTPS inputs.
- TFTP preserves packet boundaries: the initial response and each readable
  chunk are separate datagrams.
- SMTP uses the primary connection as command-aligned replies. The initial
  response is the 220 greeting, each readable chunk answers the next command,
  and after a 354 DATA reply the peer drains the dot-stuffed message body up to
  its `\r\n.\r\n` end marker before releasing the final 250. Envelope
  recipients come from the schema-native `mail_rcpt` list because
  `CURLOPT_MAIL_RCPT` is a `curl_slist`; the URL path supplies curl's EHLO
  domain rather than the recipient in current libcurl. An `SCHEME_SMTPS`
  scenario runs the identical exchange over implicit TLS; its fixed authority
  is `tls.test`, matching the checked-in trust anchor, and the handshake carries
  no ALPN extension.
- IMAP uses the primary connection as command-aligned replies. The initial
  response is the `* OK` greeting, each readable chunk answers the next
  command, and a status line beginning with `OK`, `NO`, `BAD`, or `PREAUTH`
  receives curl's generated command tag. A `{N}` literal copies the next N
  bytes verbatim, so FETCH bodies and their tagged completion can share one
  chunk. An accepted APPEND continuation drains exactly the announced literal
  size. An `SCHEME_IMAPS` scenario runs the identical exchange over implicit
  TLS; its fixed authority is `tls.test`, matching the checked-in trust anchor,
  and the handshake carries no ALPN extension.
- POP3 also uses command-aligned replies, but its `+OK`/`-ERR` status lines
  need no rewriting. Multi-line CAPA, LIST, and RETR replies include their
  terminating dot line and are written unchanged. An `SCHEME_POP3S` scenario
  runs the identical exchange over implicit TLS against the same `tls.test`
  authority and also negotiates no ALPN protocol.
- The proxy-transport lane uses request-triggered chunks for each SOCKS reply
  and then for tunneled HTTP. SOCKS5 advertises deterministic no-auth and
  username/password methods; the scripted method-selection byte chooses the
  path. `haproxy_protocol` inserts a protocol-v1 prefix after tunnel setup with
  fixed loopback metadata, never a fuzz-selected endpoint.
- SMTP, IMAP, POP3, FTP, FTPS, MQTT, MQTTS, the proxy-transport lane, and deep
  HTTP CONNECT retain the opt-in `probe_multi_pollset` field. When it is true,
  their drivers call zero-timeout `curl_multi_poll` after successful perform
  turns while both the transfer and protocol connection are live. This reaches
  protocol/filter pollset callbacks without delaying the default false path.
  Other fixed target policies, including direct, forward-proxy, and Unix-domain
  deep HTTP, clear the field until their loops have a useful intermediate
  state to probe.
- MQTT treats the primary connection as a binary packet stream. The initial
  response is the CONNACK, while each readable chunk is an opaque
  server-initiated packet (for example PUBLISH followed by a server
  DISCONNECT) released after the peer acknowledges curl's SUBSCRIBE. Client
  packets are delimited by MQTT's fixed header and base-128 remaining length,
  not by newlines; the URL path becomes the publish/subscribe topic and
  `CURLOPT_POSTFIELDS` supplies the publish payload. An `SCHEME_MQTTS` scenario
  runs the identical packet exchange over implicit TLS; its fixed authority is
  `tls.test`, matching the checked-in trust anchor, and the handshake carries
  no ALPN extension.
- DICT uses the primary connection for one request/response exchange. curl
  writes a `CLIENT` identification line, a command derived from the URL path
  (`DEFINE` from `/d:word`, `MATCH` from `/match:word:db`, `SHOW` from
  `/show:db`, or a raw command with colons replaced by spaces), and `QUIT` in a
  single send. It then reads the response as an unframed text stream, so the
  first non-`CLIENT`/non-`QUIT` `on_readable` entry is the complete body and
  the peer half-closes after writing it. Include the RFC 2229 `.\r\n`
  terminator in the seed when a well-formed body is desired; curl does not
  parse it and treats EOF as end-of-transfer. `initial_response` is normally
  empty because DICT has no server greeting.
- FILE has no peer and opens the local filesystem directly. Its target policy
  keeps the fuzz-controlled authority, query, and fragment but replaces the
  URL path with `/dev/null`; response scripts and socket controls are removed.
  Bounded upload scripts and their scalar controls are retained because the
  same fixed path is a safe write sink. Mutations therefore exercise
  `file://` parsing and curl's local read, write, range, resume,
  time-condition, and metadata paths without reading or writing an arbitrary
  host path.
- LDAP is BER/ASN.1, not line-oriented. `initial_response`, when present, is
  the scripted bind reply and is released only after curl's bindRequest with
  its envelope messageID rewritten to the request id; an empty value asks the
  peer to synthesize a successful bind. Each readable chunk is one complete
  server LDAPMessage (for example a searchResEntry) forwarded after the
  searchRequest and likewise renumbered. A scripted searchResDone ends the
  search; otherwise the peer synthesizes one. The URL path carries the base DN,
  attributes, scope, and filter, because this curl revision's OpenLDAP handler
  does not consult `CURLOPT_CUSTOMREQUEST`. An `SCHEME_LDAPS` scenario runs the
  identical BER exchange over implicit TLS. In this curl revision OpenLDAP
  itself is built without TLS: `lib/openldap.c` drives curl's SSL connection
  filter and routes OpenLDAP's sockbuf I/O through curl's send/receive
  callbacks, so the in-process peer terminates ordinary TLS records and then
  parses decrypted LDAPMessages. The fixed authority is `tls.test`, matching
  the checked-in trust anchor, and the handshake carries no ALPN extension.
- RTSP is request-aligned and has no server greeting. The peer consumes each
  request start line and header block, releases the next `on_readable` entry
  only after the terminating empty line, and drains any announced
  `Content-Length` body exactly. A response chunk may carry the status line,
  headers, an SDP/parameter body, and RFC 2326 interleaved RTP frames
  (`$`, channel, 16-bit length, payload). `CURLOPT_RTSP_REQUEST` selects the
  method, and the response's own CSeq stays mutation-controlled so mismatches
  reach curl's `CURLE_RTSP_CSEQ_ERROR` path.
- IPFS and IPNS are gateway schemes rather than wire protocols. libcurl has no
  `ipfs://` handler; curl's command-line tool rewrites `ipfs://<cid>` and
  `ipns://<name>` to `<gateway>/ipfs/<cid>` or `<gateway>/ipns/<name>` before
  issuing an ordinary HTTP request. The structured lane mirrors that rewrite
  against a fixed loopback gateway and the in-process HTTP peer. `host_path`
  holds a pinned CID/name followed by the mutation-controlled gateway path,
  query, and fragment; the runner prepends the gateway authority.
- The resolver lane's `doh_https_rr` flag binds a loopback DoH responder and
  points `CURLOPT_DOH_URL` at it. The responder answers address and HTTPS
  queries; its HTTPS record carries `alpn=h2,h3`, so the outer HTTPS transfer
  completes through the in-process TLS/ALPN h2 peer using `http2_plan`.
  `CURLOPT_RESOLVE` is cleared because it cannot carry SVCB/HTTPS records.
- HTTP/2 origin and proxy lanes treat connection bytes as raw HTTP/2 frames
  after a fixed prior-knowledge or TLS/ALPN setup. The fast HTTP lane retains
  the HTTP/1.1 h2c Upgrade request and `101` transition instead.
- Direct HTTP/3 uses ordered `http3_plan` actions after a valid QUIC/TLS
  handshake and discards the ordinary connection script. Setting
  `http3_plan.use_h1_connect_udp_proxy` instead uses `connection` for a local
  HTTP/1.1 CONNECT-UDP upgrade and capsule bytes; direct HTTP/3 actions are
  cleared.

Use a seed already assigned to the intended target as the closest example.
A valid protobuf message can still be irrelevant to a lane if that lane's
policy removes the field or replaces its scheme.

## Select allocation failures

All structured targets can reject selected libcurl allocation attempts while
driving a transfer:

```protobuf
fail_allocations: 5
fail_allocations: 9
```

Ordinals are one-based and count positive-size calls on the fuzzer thread
through the callbacks installed by `curl_global_init_mem`. Scenario parsing
stays outside the sequence; libcurl setup, transfer driving, result probes,
and cleanup inside the shared scenario runner are included except for narrow
harness ownership scopes. The `COPYPOSTFIELDS` ownership commit and
pushed-handle cleanup enumeration neither fail nor advance the ordinal counter,
so failures remain pending for subsequent injectable allocations. Fixed target
policies retain the four smallest distinct values after folding them into
1..4096; the compatibility target applies that bound at execution time without
rewriting the message. State-dependent probes still require the preceding
transfer entrypoint to establish their documented runtime state.

In the API target, a scenario that combines `API_DRIVE_EASY_EVENTS` with an
allocation plan is normalized to `API_DRIVE_EASY_PERFORM`. After its
heap-backed socket-monitor allocation fails, curl's current debug event adapter
returns a status outside the socket-callback contract; event-based driving
remains available when no allocation failure is selected.

An active plan combined with an HTTP-family MIME body also removes the
`CURLOPT_CRLF` and `CURLOPT_TRANSFERTEXT` line-ending conversion options before
execution. curl currently installs the MIME reader before allocating the
conversion reader, and the allocation-error path can otherwise leave the freed
MIME reader installed. MIME failures remain selected, while ordinary inputs
still cover MIME with line-ending conversion. Compatibility inputs receive the
same execution-only safety rule without changing their serialized messages.

Multiple failures describe one evolving execution. In the example, 9 means
the ninth allocation attempt on the path produced after attempt 5 failed, not
the ninth attempt from a failure-free baseline. Keep failure seeds with the
target that produced them: allocation sequences can change with the target,
curl revision, build configuration, and TLS backend. Resolver and peer worker
threads deliberately do not inherit the calling thread's plan.

## Add a seed

1. Put a descriptively named `.textproto` file in the closest protocol
   directory under `scenarios/curl_fuzzer_proto/`. Its filename stem must be
   unique across every source directory combined into the destination corpus,
   because generated corpora are flat.
2. Check the corpus declarations in `CMakeLists.txt`. Directory membership is
   not the complete assignment rule: the fast HTTP set is explicit, the deep
   and compatibility sets combine selected directories, and the timing set is
   selected by a `backpressure` filename pattern.
3. Build the destination target. CMake encodes the source with the staged
   schema and creates `<name>.scenario` in the corpus assigned to that target.
4. Decode the generated file and replay it through the matching executable.

For example:

```shell
./mainline.sh -t curl_fuzzer_proto_http
uv run read_proto_corpus \
  build/generated_corpora/curl_fuzzer_proto_http/basic_get.scenario
FUZZ_VERBOSE=1 ./build/curl_fuzzer_proto_http \
  build/generated_corpora/curl_fuzzer_proto_http/basic_get.scenario
```

Adding a new fast-HTTP seed also requires updating its explicit list and count
check in `CMakeLists.txt`.

## Decode a binary input

For interactive inspection, use the published
[corpus decoder](../corpus-decoder/). It recognizes protobuf `Scenario` files
and reads the selected file entirely in the browser.

`read_proto_corpus` wraps `protoc` and prints named textproto fields using the
checked-in schema. It falls back to the staged build copy when the source
schema is unavailable:

```shell
uv run read_proto_corpus path/to/crash-input
uv run read_proto_corpus \
  --proto-file build/schemas/curl_fuzzer.proto path/to/crash-input
```

The command requires `protoc` on `PATH`. It checks `--proto-file`, then
`CURL_FUZZER_PROTO`, the checkout's `schemas/curl_fuzzer.proto`, and finally
`build/schemas/curl_fuzzer.proto`. Without a schema it falls back to
wire-level field numbers; request that form explicitly with `--raw`:

```shell
uv run read_proto_corpus --raw path/to/crash-input
```

Use the schema from the curl-fuzzer revision that produced the input when
investigating `CURLOPT_*` values.
