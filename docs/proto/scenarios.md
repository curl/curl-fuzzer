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
  TLS certificate selection, HTTPS/H2 key-exchange selection, `socks_proxy_mode`,
  `trace_ids`, filename-backed parser inputs, and `fail_allocations`.

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

Other peers intentionally give those fields narrower meanings:

- WebSocket scenarios use a peer that generates the `101` handshake and
  accepts either raw chunks or structured `server_frames`. The WSS lane runs
  that same Upgrade, framing, callback, and manual-drive behavior after a
  verified in-process TLS handshake.
- The dedicated HTTPS peer encrypts connection-script bytes as HTTP
  application data. The compatibility target preserves its older behavior and
  treats HTTPS script bytes as raw TLS records.
- TELNET preloads a bounded response before entering curl's blocking protocol
  loop.
- FTP treats the primary connection as command-aligned control replies and
  follow-on connections as data streams.
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
  size.
- POP3 also uses command-aligned replies, but its `+OK`/`-ERR` status lines
  need no rewriting. Multi-line CAPA, LIST, and RETR replies include their
  terminating dot line and are written unchanged.
- MQTT treats the primary connection as a binary packet stream. The initial
  response is the CONNACK, while each readable chunk is an opaque
  server-initiated packet (for example PUBLISH followed by a server
  DISCONNECT) released after the peer acknowledges curl's SUBSCRIBE. Client
  packets are delimited by MQTT's fixed header and base-128 remaining length,
  not by newlines; the URL path becomes the publish/subscribe topic and
  `CURLOPT_POSTFIELDS` supplies the publish payload.
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
