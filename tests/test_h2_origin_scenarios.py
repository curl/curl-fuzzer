"""Reachability checks for the dedicated HTTPS/HTTP2 origin lane."""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "https_h2"


def test_https_h2_seeds_preserve_protocol_valid_correlations() -> None:
    """Keep the ALPN-h2 seeds valid enough to reach their specialized APIs."""
    expected_tokens = {
        "https_h2_push_promise.textproto": (
            "PUSH_PROMISE",
            "\\x19\\x05\\x04",
            "\\x82\\x87\\x01\\x08tls.test\\x04\\x07/pushed",
        ),
        "https_h2_push_accepted.textproto": (
            "accept_h2_push: true",
            "promised stream 2",
            "\\x00\\x00\\x06\\x00\\x01\\x00\\x00\\x00\\x02pushed",
        ),
        "https_h2_push_reset_goaway.textproto": (
            "accept_h2_push: true",
            "RST_STREAM",
            "\\x04\\x03",
            "\\x08\\x07",
        ),
        "https_h2_push_flow_control.textproto": (
            "accept_h2_push: true",
            "CURLOPT_POSTFIELDS",
            "SETTINGS_INITIAL_WINDOW_SIZE=0",
            "\\x04\\x08",
        ),
        "https_h2_reuse_ping_upkeep.textproto": (
            "CURLOPT_FOLLOWLOCATION",
            "\\x08\\x06",
            "\\x00\\x00\\x00\\x03reused",
            "curl_easy_upkeep",
        ),
    }

    assert {path.name for path in SCENARIO_ROOT.glob("*.textproto")} == set(
        expected_tokens
    )
    for name, tokens in expected_tokens.items():
        scenario = (SCENARIO_ROOT / name).read_text(encoding="utf-8")
        assert "scheme: SCHEME_HTTPS" in scenario
        assert "CURLOPT_HTTP_VERSION" not in scenario
        assert all(token in scenario for token in tokens), name


def test_https_h2_does_not_replay_http1_public_corpora() -> None:
    """HTTP/1 response bytes must not swamp this lane's raw HTTP/2 grammar."""
    helper = REPO_ROOT / "scripts" / "fuzz_corpus_helpers.sh"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; fuzz_public_corpus_names curl_fuzzer_proto_https_h2',
            "h2-origin-corpus-test",
            str(helper),
        ],
        check=True,
        capture_output=True,
        encoding="utf-8",
    )

    assert result.stdout.splitlines() == ["curl_fuzzer_proto_https_h2"]
