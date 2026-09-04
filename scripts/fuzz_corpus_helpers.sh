#!/usr/bin/env bash

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

# List public corpus identities worth replaying for a target. Fixed lanes whose
# response grammar remains compatible also inherit the original target's
# historical mixed protobuf corpus. The HTTP/2 proxy lane intentionally does
# not: interpreting its mostly-HTTP/1 response bytes as HTTP/2 frames would
# spend nearly every replay on the same decoder rejection before CONNECT.
fuzz_public_corpus_names() {
    echo "$1"
    case "$1" in
        curl_fuzzer_proto_https_gnutls|curl_fuzzer_proto_https_mbedtls)
            # Bootstrap the backend variant from the compatible HTTPS corpus as
            # well as the original mixed Scenario corpus. Once OSS-Fuzz has a
            # native backend corpus, the first name above picks it up too.
            echo "curl_fuzzer_proto_https"
            echo "curl_fuzzer_proto"
            ;;
        curl_fuzzer_proto_http3)
            # HTTP/3 has its own wire-response seeds, but ordinary HTTPS
            # scenarios still provide useful URL, request, and option state;
            # the fixed profile supplies a valid default H3 response plan.
            echo "curl_fuzzer_proto_https"
            echo "curl_fuzzer_proto"
            ;;
        curl_fuzzer_proto_http|curl_fuzzer_proto_http_deep|curl_fuzzer_proto_https|curl_fuzzer_proto_ws|curl_fuzzer_proto_wss|curl_fuzzer_proto_telnet|curl_fuzzer_proto_ftp|curl_fuzzer_proto_tftp|curl_fuzzer_proto_api|curl_fuzzer_proto_multi|curl_fuzzer_proto_timing)
            echo "curl_fuzzer_proto"
            ;;
    esac
}
