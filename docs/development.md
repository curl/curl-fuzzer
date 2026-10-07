# Development

## Run checks

Install the Python testing and development dependencies:

```shell
uv sync --extra python-tests
```

Run the Python tests and repository lint entrypoint:

```shell
uv run pytest tests/test_*.py
./lint.sh
```

`mainline.sh` builds the C++ tests and runs CTest for the normal AddressSanitizer
aggregate build. The MemorySanitizer lane compiles and links them but does not
execute against the host's uninstrumented C++ runtime.

## Documentation

Install the pinned mdBook and Mermaid preprocessor versions:

```shell
# renovate: datasource=crate depName=mdbook
MDBOOK_VERSION=0.5.4
# renovate: datasource=crate depName=mdbook-mermaid
MDBOOK_MERMAID_VERSION=0.17.1
cargo install mdbook --version "=${MDBOOK_VERSION}" --locked
cargo install mdbook-mermaid --version "=${MDBOOK_MERMAID_VERSION}" --locked
```

Install CMake and Doxygen for the [C++ reference](proto/cpp-reference.md), and
with Node.js 18 or newer, install the locked JavaScript dependencies used by
the browser decoder:

```shell
npm ci --ignore-scripts --no-audit --no-fund
```

Then generate Mermaid's JavaScript assets and build the documentation from the
repository root:

```shell
mdbook-mermaid install .
mdbook build
cmake -B build .
cmake --build build --target doxygen-docs
mkdir -p _site/api
cp -R build/proto_fuzzer_reference/html _site/api/proto_fuzzer
uv run generate_decoder_html --output _site/corpus-decoder/index.html
```

The Mermaid assets are generated and ignored by Git. Delete them before
rerunning the installer after an `mdbook-mermaid` upgrade because the installer
does not overwrite existing assets. For live editing, run
`mdbook serve --open`. The browser decoder and C++ reference are generated
separately and are therefore not refreshed by the mdBook development server.
Run their generation commands again after rebuilding the book. The
`doxygen-docs` target checks the source documentation before rendering HTML;
it does not compile curl or the fuzzers.

Run the optional browser tests for the guides, C++ reference, and decoder with:

```shell
uv sync --extra browser-tests
uv run playwright install chromium
uv run pytest tests/browser
```

The documentation CI builds the book, decoder, and C++ reference together. The
Pages workflow publishes `_site/` from `master` for <https://fuzz.curl.se/>, with
the reference at `/api/proto_fuzzer/`. `book.toml`
records the intended hostname, but the custom domain and HTTPS enforcement must
also be configured in the repository's Pages settings.

## Generated files

Do not commit `_site/`, `build/generated_corpora/`, staged schema copies under
`build/`, or downloaded public corpora. Commit the schema under `schemas/`,
authored Markdown under `docs/`, legacy binary seeds under `corpora/`, and
structured textproto seeds under `scenarios/curl_fuzzer_proto/`.
