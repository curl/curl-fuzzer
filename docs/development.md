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

Then generate Mermaid's JavaScript assets and build the documentation from the
repository root:

```shell
mdbook-mermaid install .
mdbook build
uv run generate_decoder_html --output _site/corpus-decoder/index.html
```

The Mermaid assets are generated and ignored by Git. Delete them before
rerunning the installer after an `mdbook-mermaid` upgrade because the installer
does not overwrite existing assets. For live editing, run
`mdbook serve --open`. The browser decoder is generated separately and is
therefore not refreshed by the mdBook development server.

Run its optional browser tests with:

```shell
uv sync --extra browser-tests
uv run playwright install chromium
uv run pytest tests/browser/test_corpus_decoder.py
```

The documentation CI builds the book and decoder together. The Pages workflow
publishes `_site/` from `master` for <https://fuzz.curl.se/>. `book.toml`
records the intended hostname, but the custom domain and HTTPS enforcement must
also be configured in the repository's Pages settings.

## Generated files

Do not commit `_site/`, `build/generated_corpora/`, expanded protobuf schemas,
or downloaded public corpora. Commit authored Markdown under `docs/`, legacy
binary seeds under `corpora/`, and structured textproto seeds under
`scenarios/curl_fuzzer_proto/`.
