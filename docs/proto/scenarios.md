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
data. `SetOption` entries use a generated `CURLOPT_*` identifier and a `oneof`
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
- Focused lanes: `api_plan`, `multi_plan`, `resolve_entries`, TLS certificate
  selection, `socks_proxy_mode`, `trace_ids`, and filename-backed parser
  inputs.

Read the comments in `schemas/curl_fuzzer.proto` for the complete field
contract. The checked-in file is a template: its `CurlOptionId` body is filled
during the build from `schemas/curl_fuzzer_supported_curlopts.txt` and the
selected curl checkout's `curl.h`. The expanded schema used to encode and
decode inputs is `build/schemas/curl_fuzzer.proto`.

## Peer scripts depend on the target

For the ordinary HTTP peer, `connection.initial_response` is sent when curl
opens the socket and each `on_readable` value is released on a later readable
turn. `subsequent_connections` supplies bounded scripts for redirects,
authentication retries, and other fresh HTTP sockets.

Other peers intentionally give those fields narrower meanings:

- Plain WebSocket scenarios use a peer that generates the `101` handshake and
  accepts either raw chunks or structured `server_frames`. The WSS lane covers
  secure setup under a fixed scheme; it does not promise post-handshake frame
  coverage.
- The dedicated HTTPS peer encrypts connection-script bytes as HTTP
  application data. The compatibility target preserves its older behavior and
  treats HTTPS script bytes as raw TLS records.
- TELNET preloads a bounded response before entering curl's blocking protocol
  loop.
- FTP treats the primary connection as command-aligned control replies and
  follow-on connections as data streams.
- TFTP preserves packet boundaries: the initial response and each readable
  chunk are separate datagrams.
- HTTP/2 origin and proxy lanes treat connection bytes as raw HTTP/2 frames
  after a fixed TLS/ALPN setup.
- HTTP/3 uses ordered `http3_plan` actions after a valid QUIC/TLS handshake;
  the ordinary connection script is discarded.

Use a seed already assigned to the intended target as the closest example.
A valid protobuf message can still be irrelevant to a lane if that lane's
policy removes the field or replaces its scheme.

## Add a seed

1. Put a descriptively named `.textproto` file in the closest protocol
   directory under `scenarios/curl_fuzzer_proto/`. Its filename stem must be
   unique across every source directory combined into the destination corpus,
   because generated corpora are flat.
2. Check the corpus declarations in `CMakeLists.txt`. Directory membership is
   not the complete assignment rule: the fast HTTP set is explicit, the deep
   and compatibility sets combine selected directories, and the timing set is
   selected by a `backpressure` filename pattern.
3. Build the destination target. CMake encodes the source with the expanded
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

`read_proto_corpus` wraps `protoc` and prints named textproto fields when it
can find the expanded build schema:

```shell
uv run read_proto_corpus path/to/crash-input
uv run read_proto_corpus \
  --proto-file build/schemas/curl_fuzzer.proto path/to/crash-input
```

The command requires `protoc` on `PATH`. It checks `--proto-file`, then
`CURL_FUZZER_PROTO`, then the checkout's `build/schemas/curl_fuzzer.proto`.
Without an expanded schema it falls back to wire-level field numbers; request
that form explicitly with `--raw`:

```shell
uv run read_proto_corpus --raw path/to/crash-input
```

Always decode with a schema generated for the relevant curl-fuzzer build when
investigating `CURLOPT_*` values.
