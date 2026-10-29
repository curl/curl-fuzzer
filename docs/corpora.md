# Corpus management

## Checked-in seeds

Direct-fuzzer seeds are binary files under `corpora/<target>/`.
Structured seeds are authored as textproto under
`scenarios/curl_fuzzer_proto/<lane>/`; their generated binary form belongs in
the build tree and must not be checked in.

When the aggregate build runs, CMake writes a manifest for each generated
structured corpus. Packaging and coverage use that manifest so removed
scenarios cannot survive as stale build artifacts.

## Public OSS-Fuzz corpora

Download the current public corpus for every supported target with:

```shell
./scripts/download_public_corpus.sh
```

The script writes to `ossfuzz_corpus/<target>/`, skips targets whose public
archive is not available yet, and leaves an existing non-empty directory alone.
Force a refresh with:

```shell
./scripts/download_public_corpus.sh -f
```

OSS-Fuzz prefixes target names that do not already begin with `curl_`. The
download script owns this mapping; documentation should not maintain a parallel
list of storage URLs.

Downloaded corpora are ignored by Git. Coverage automatically includes eligible
corpora when present. Structured targets replay only their own corpus and exact
same-profile aliases such as the three HTTPS backend variants. Pre-cutover
generic-option bytes belong to the revision and target that produced them, and
cross-profile reuse is not inferred from parse success.

Automatic structured replay additionally requires this marker at the public
corpus root:

```text
ossfuzz_corpus/.structured-schema-owned-eligibility-v1
```

The download script intentionally does not create it: the public ZIP format
does not identify the schema that produced its entries. Only after the upstream
structured corpora have been replaced for the typed-option cutover, move any
existing local root aside, download a fresh root, and create the marker:

```shell
mv ossfuzz_corpus ossfuzz_corpus.pre-schema-owned-eligibility
./scripts/download_public_corpus.sh
touch ossfuzz_corpus/.structured-schema-owned-eligibility-v1
```

Coverage, benchmarking, profiling, and HTTP/2 default bootstrap discovery then
accept structured directories from that root. Explicit corpus overrides remain
explicit caller assertions. Do not mark a root that retains pre-cutover
structured directories.

## Seed archives

`scripts/create_zip.sh` is used by the OSS-Fuzz build to package seed corpora.
For structured targets it reads the generated manifest; for direct targets it
archives the corresponding checked-in corpus directory. Per-target runtime
settings live under `ossconfig/`.
