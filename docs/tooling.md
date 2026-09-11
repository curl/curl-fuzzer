# Python tools

The `curl-fuzzer-tools` package requires Python 3.10 or newer.

## Install with uv

```shell
uv sync
uv run read_corpus corpora/curl_fuzzer_http/test_url_http
```

Add the Python test extra when developing:

```shell
uv sync --extra python-tests
```

## Install with pip

```shell
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## Commands

| Command                    | Purpose                                                                                         |
|----------------------------|-------------------------------------------------------------------------------------------------|
| `read_corpus`              | Decode one legacy TLV input                                                                     |
| `read_proto_corpus`        | Decode one binary protobuf scenario using `protoc`                                              |
| `generate_corpus`          | Generate a legacy TLV testcase                                                                  |
| `tlv_to_proto`             | Convert a directory of legacy HTTP inputs to textproto                                          |
| `generate_decoder_html`    | Build the standalone browser decoder for legacy TLV and protobuf `Scenario` inputs              |
| `corpus_to_pcap`           | Convert response TLVs to a packet capture; requires Scapy from the development dependency group |
| `generate_matrix`          | Package built fuzzers into balanced artifact shards and produce the CI matrix                    |
| `prepare_fuzzer`           | Extract one fuzzer and its supporting files from a CI artifact shard                             |
| `generate_option_manifest` | Validate and stage the protobuf schema, then generate its C++ curl-option manifest              |

Run any command with `--help` for its complete interface.

## Browser decoder

The [published decoder](https://fuzz.curl.se/corpus-decoder/)
accepts legacy TLV and protobuf `Scenario` inputs. It detects the format
automatically, allows manual selection, and does not upload the selected file.
Empty, unknown-only, or damaged inputs may require selecting a format manually.
The generator bundles the locked protobuf.js runtime and the checked-in schema
into the HTML, so the resulting page does not load a decoder from a CDN.
Build the complete documentation site and decoder locally with:

```shell
npm ci --ignore-scripts --no-audit --no-fund
mdbook-mermaid install .
mdbook build
uv run generate_decoder_html --output _site/corpus-decoder/index.html
```

Then open `_site/index.html` for the book or
`_site/corpus-decoder/index.html` for the decoder. Build mdBook first because it
recreates the output directory.
