#!/usr/bin/env bash

# A breaking structured-schema cutover must select a new marker name. Public
# structured corpora are replayed only after an operator has replaced the old
# target directories and explicitly created this root sentinel.
STRUCTURED_CORPUS_EPOCH_MARKER=".structured-schema-owned-eligibility-v1"

fuzz_is_structured_target() {
    case "$1" in
        curl_fuzzer_proto|curl_fuzzer_proto_*) return 0 ;;
        *) return 1 ;;
    esac
}

fuzz_public_corpus_epoch_ready() {
    local target=$1
    local corpus_root=$2
    if ! fuzz_is_structured_target "${target}"; then
        return 0
    fi
    [[ -f "${corpus_root}/${STRUCTURED_CORPUS_EPOCH_MARKER}" ]]
}

# Return the generated corpus directory associated with a binary. Proto lane
# names normally match their directories. Backend variants reuse the protocol
# lane's generated seeds while OSS-Fuzz still sees a distinct binary basename.
fuzz_local_corpus_name() {
    case "$1" in
        curl_fuzzer_proto_https_gnutls|curl_fuzzer_proto_https_mbedtls)
            echo "curl_fuzzer_proto_https"
            ;;
        *)
            echo "$1"
            ;;
    esac
}

# Resolve the corpus directory produced for a target. A build-tree manifest is
# the authoritative signal that this is a generated proto corpus; legacy
# targets continue to use checked-in source corpora. Centralizing this choice
# keeps packaging, replay, and coverage from accidentally consulting stale
# source-tree artefacts left by an older build layout.
fuzz_local_corpus_dir() {
    local target=$1
    local source_root=$2
    local build_dir=$3
    local corpus_name
    corpus_name=$(fuzz_local_corpus_name "${target}")
    if [[ -f "${build_dir}/corpus_manifests/${corpus_name}.seed_manifest" ]]; then
        echo "${build_dir}/generated_corpora/${corpus_name}"
    else
        echo "${source_root}/corpora/${corpus_name}"
    fi
}

# List public corpus identities worth replaying for a target. Only binaries
# compiled against the exact same generated profile share corpus bytes. The
# old mixed Scenario format is wire-incompatible, and parse success does not
# make different generated profiles interchangeable.
fuzz_public_corpus_names() {
    echo "$1"
    case "$1" in
        curl_fuzzer_proto_https_gnutls|curl_fuzzer_proto_https_mbedtls)
            # Backend variants share the fast_https profile exactly. Once
            # OSS-Fuzz has a native backend corpus, the first name above picks
            # it up too.
            echo "curl_fuzzer_proto_https"
            ;;
    esac
}
