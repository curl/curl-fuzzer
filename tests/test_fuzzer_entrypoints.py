"""Checks that OSS-Fuzz can attribute every packaged target independently."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT_PATTERN = re.compile(r'extern\s+"C"\s+int\s+LLVMFuzzerTestOneInput\s*\(')
CUSTOM_MUTATOR_PATTERN = re.compile(
    r'extern\s+"C"\s+std::size_t\s+LLVMFuzzerCustomMutator\s*\('
)
CUSTOM_CROSSOVER_PATTERN = re.compile(
    r'extern\s+"C"\s+std::size_t\s+LLVMFuzzerCustomCrossOver\s*\('
)
PROTO_TARGET_PATTERN = re.compile(
    r"^\s*curl_add_proto_fuzzer\(\s*([a-z0-9_]+)", re.MULTILINE
)
STANDALONE_TARGETS = {
    "fuzz_bufq",
    "fuzz_doh",
    "fuzz_netrc",
    "fuzz_url",
}
PROTO_TARGET_TRAITS = {
    "curl_fuzzer_proto": ("compatibility", "CompatibilityTraits"),
    "curl_fuzzer_proto_http": ("fast_http", "FastHttpTraits"),
    "curl_fuzzer_proto_http_deep": ("deep_http", "DeepHttpTraits"),
    "curl_fuzzer_proto_http2": ("fast_http2", "FastHttp2Traits"),
    "curl_fuzzer_proto_https": ("fast_https", "FastHttpsTraits"),
    "curl_fuzzer_proto_https_h2": ("https_h2", "HttpsH2Traits"),
    "curl_fuzzer_proto_https_gnutls": ("fast_https", "FastHttpsTraits"),
    "curl_fuzzer_proto_https_mbedtls": ("fast_https", "FastHttpsTraits"),
    "curl_fuzzer_proto_http3": ("fast_http3", "FastHttp3Traits"),
    "curl_fuzzer_proto_h2_proxy": ("h2_proxy", "H2ProxyTraits"),
    "curl_fuzzer_proto_socks4": ("proxy_transport", "ProxyTransportTraits"),
    "curl_fuzzer_proto_resolver": ("resolver", "ResolverTraits"),
    "curl_fuzzer_proto_ws": ("fast_websocket", "FastWebSocketTraits"),
    "curl_fuzzer_proto_wss": (
        "fast_secure_websocket",
        "FastSecureWebSocketTraits",
    ),
    "curl_fuzzer_proto_telnet": ("fast_telnet", "FastTelnetTraits"),
    "curl_fuzzer_proto_ftp": ("fast_ftp", "FastFtpTraits"),
    "curl_fuzzer_proto_tftp": ("fast_tftp", "FastTftpTraits"),
    "curl_fuzzer_proto_smtp": ("fast_smtp", "FastSmtpTraits"),
    "curl_fuzzer_proto_imap": ("fast_imap", "FastImapTraits"),
    "curl_fuzzer_proto_pop3": ("fast_pop3", "FastPop3Traits"),
    "curl_fuzzer_proto_mqtt": ("fast_mqtt", "FastMqttTraits"),
    "curl_fuzzer_proto_dict": ("fast_dict", "FastDictTraits"),
    "curl_fuzzer_proto_file": ("fast_file", "FastFileTraits"),
    "curl_fuzzer_proto_ldap": ("fast_ldap", "FastLdapTraits"),
    "curl_fuzzer_proto_rtsp": ("fast_rtsp", "FastRtspTraits"),
    "curl_fuzzer_proto_ipfs": ("fast_ipfs", "FastIpfsTraits"),
    "curl_fuzzer_proto_gopher": ("fast_gopher", "FastGopherTraits"),
    "curl_fuzzer_proto_api": ("api", "ApiTraits"),
    "curl_fuzzer_proto_multi": ("multi", "MultiTraits"),
    "curl_fuzzer_proto_timing": ("timing", "TimingTraits"),
}
OPTIONAL_PROTO_TARGETS = {
    "curl_fuzzer_proto_https_gnutls",
    "curl_fuzzer_proto_https_mbedtls",
    "curl_fuzzer_proto_http3",
}
BASE_PROTO_TARGETS = set(PROTO_TARGET_TRAITS) - OPTIONAL_PROTO_TARGETS


def _packaged_targets(
    *,
    architecture: str = "x86_64",
    sanitizer: str = "address",
    selected_target: str | None = None,
) -> set[str]:
    environment = os.environ.copy()
    environment.pop("CURL_FUZZ_TARGET", None)
    environment["ARCHITECTURE"] = architecture
    environment["SANITIZER"] = sanitizer
    if selected_target is not None:
        environment["CURL_FUZZ_TARGET"] = selected_target
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; printf "%s\\n" $FUZZ_TARGETS',
            "entrypoint-test",
            str(REPO_ROOT / "scripts" / "fuzz_targets"),
        ],
        check=True,
        capture_output=True,
        encoding="utf-8",
        env=environment,
    )
    return set(result.stdout.splitlines())


def test_packaging_can_select_one_fuzzer() -> None:
    """Keep the CI-only build and packaging selection on one executable."""
    target = "curl_fuzzer_proto_multi"

    assert _packaged_targets(sanitizer="introspector", selected_target=target) == {
        target
    }


def test_optional_proto_targets_are_limited_to_supported_builds() -> None:
    """Keep packaging aligned with the CMake sanitizer/architecture gates."""
    assert OPTIONAL_PROTO_TARGETS <= _packaged_targets()
    assert OPTIONAL_PROTO_TARGETS.isdisjoint(_packaged_targets(sanitizer="memory"))
    assert OPTIONAL_PROTO_TARGETS.isdisjoint(_packaged_targets(architecture="i386"))


def test_base_proto_targets_are_packaged_for_i386_asan() -> None:
    """Keep the supported 32-bit build aligned with its CMake target suite."""
    assert BASE_PROTO_TARGETS <= _packaged_targets(
        architecture="i386", sanitizer="address"
    )


def _checked_in_cpp_sources() -> list[Path]:
    sources = list(REPO_ROOT.glob("*.cc"))
    sources.extend((REPO_ROOT / "fuzzer_entrypoints").glob("*.cc"))
    sources.extend((REPO_ROOT / "proto_fuzzer").glob("*.cc"))
    sources.extend((REPO_ROOT / "src").rglob("*.cc"))
    sources.extend((REPO_ROOT / "tests").glob("*.cc"))
    return sources


def test_packaged_fuzzers_have_unique_same_named_entrypoints() -> None:
    """Keep Introspector's source basenames aligned with coverage reports."""
    packaged = _packaged_targets(sanitizer="introspector")
    discovered: dict[str, list[Path]] = {}

    for source in _checked_in_cpp_sources():
        contents = source.read_text(encoding="utf-8")
        if ENTRYPOINT_PATTERN.search(contents):
            discovered.setdefault(source.stem, []).append(source)

    assert set(discovered) == packaged
    for target, sources in discovered.items():
        assert len(sources) == 1, (
            f"{target} has multiple checked-in libFuzzer entrypoints: {sources}"
        )


def test_cmake_builds_every_packaged_entrypoint() -> None:
    """Prevent packaging and CMake declarations from drifting."""
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    cmake_targets = set(PROTO_TARGET_PATTERN.findall(cmake))
    cmake_targets.update(STANDALONE_TARGETS)

    assert cmake_targets == _packaged_targets(sanitizer="coverage")
    assert cmake.count("fuzzer_entrypoints/${_name}.cc") == 1


def test_proto_entrypoints_bind_generated_traits_in_source() -> None:
    """Keep target behaviour and Introspector-visible calls in each wrapper."""
    for target, (slug, traits) in PROTO_TARGET_TRAITS.items():
        source = REPO_ROOT / "fuzzer_entrypoints" / f"{target}.cc"
        contents = source.read_text(encoding="utf-8")

        assert contents.count(f'"generated/{slug}/{slug}_traits.h"') == 1
        assert contents.count(f"proto_fuzzer::generated::{traits}") == 1
        assert contents.count("BindProfileFuzzer<Traits>()") == 1
        assert contents.count("proto_fuzzer::ProtoFuzzerTestOneInput(") == 1
        assert contents.count("proto_fuzzer::ProtoFuzzerCustomMutator(") == 1
        assert contents.count("proto_fuzzer::ProtoFuzzerCustomCrossOver(") == 1
        assert contents.count("kProfile)") == 3
        assert "Traits::kProfile" not in contents
        assert "LoadProfileInput<Traits>" not in contents
        assert "ProtoFuzzerCustomMutator<Traits>" not in contents
        assert "ProtoFuzzerCustomCrossOver<Traits>" not in contents
        assert "ProtoFuzzerEntrypoint" not in contents
        assert len(ENTRYPOINT_PATTERN.findall(contents)) == 1
        assert len(CUSTOM_MUTATOR_PATTERN.findall(contents)) == 1
        assert len(CUSTOM_CROSSOVER_PATTERN.findall(contents)) == 1

    shared_header = (REPO_ROOT / "proto_fuzzer" / "fuzzer_main.h").read_text(
        encoding="utf-8"
    )
    shared_main = (REPO_ROOT / "proto_fuzzer" / "fuzzer_main.cc").read_text(
        encoding="utf-8"
    )
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "ProtoFuzzerEntrypoint" not in shared_header
    assert "const ProfileFuzzerTraits& traits" in shared_header
    assert "ProtoFuzzerTestOneInput<Traits>" not in shared_header
    assert "ProtoFuzzerCustomMutator<Traits>" not in shared_header
    assert "ProtoFuzzerCustomCrossOver<Traits>" not in shared_header
    assert "ExecuteProfileScenario" not in shared_header
    assert "ExecuteProfileScenario" not in shared_main
    assert shared_main.count("int ProtoFuzzerTestOneInput(") == 1
    assert shared_main.count("std::size_t ProtoFuzzerCustomMutator(") == 1
    assert shared_main.count("std::size_t ProtoFuzzerCustomCrossOver(") == 1
    assert shared_main.count("proto_fuzzer::RunScenario(") == 1
    dispatcher = shared_main[shared_main.index("int ProtoFuzzerTestOneInput(") :]
    reset_before_load = dispatcher.index("allocation_fault_injection::Reset()")
    load = dispatcher.index("traits.load_input(data, size, &scenario)")
    normalize = dispatcher.index("NormalizeScenarioForExecution(&scenario)")
    configure = dispatcher.index("allocation_fault_injection::Configure(")
    arm = dispatcher.index("allocation_fault_injection::Arm()")
    run = dispatcher.index("proto_fuzzer::RunScenario(")
    reset_after_run = dispatcher.index("allocation_fault_injection::Reset()", run)
    assert (
        reset_before_load < load < normalize < configure < arm < run < reset_after_run
    )
    assert "RunModeFor(traits.profile)" in dispatcher
    assert "PROTO_FUZZER_TARGET_" not in shared_main
    assert "PROTO_FUZZER_TARGET_" not in cmake
