# Corpus management

## Checked-in seeds

Legacy and direct-fuzzer seeds are binary files under `corpora/<target>/`.
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

Downloaded corpora are ignored by Git. Coverage automatically includes them
when present. Some fixed structured lanes also replay compatible historical
`curl_fuzzer_proto` inputs, with their target policy normalizing the scenario
before execution.

## Seed archives

`scripts/create_zip.sh` is used by the OSS-Fuzz build to package seed corpora.
For structured targets it reads the generated manifest; for legacy and direct
targets it archives the corresponding checked-in corpus directory. Per-target
runtime settings and dictionaries live under `ossconfig/`.
