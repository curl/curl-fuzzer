"""Reachability checks for correlated HTTPS/HTTP2 proxy scenarios."""

from __future__ import annotations

import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "h2_proxy"


def test_h2_proxy_seeds_preserve_connect_frame_correlations() -> None:
    """Keep valid outer frames paired with tunneled HTTP/1.1 traffic."""
    expected_tokens = {
        "h2_proxy_success.textproto": (
            "\\x00\\x00\\x00\\x04",
            "\\x01\\x88",
            "HTTP/1.1 200 OK",
        ),
        "h2_proxy_interim_headers_trailers.textproto": (
            "proxy-agent",
            "\\x31\\x30\\x30",
            "x\\x01y",
        ),
        "h2_proxy_refused.textproto": ("\\x34\\x30\\x33",),
        "h2_proxy_missing_status.textproto": ("\\x01x\\x01y",),
        "h2_proxy_reset.textproto": ("\\x04\\x03", "\\x00\\x00\\x00\\x08"),
        "h2_proxy_reset_after_connect.textproto": (
            "distinct error-to-EOF mapping",
            "HTTP/1.1 200 OK",
            "\\x00\\x00\\x00\\x08",
        ),
        "h2_proxy_control_frames.textproto": ("\\x04\\x08", "\\x08\\x07"),
        "h2_proxy_goaway_active_stream.textproto": (
            "last_stream_id=1",
            "HTTP/1.1 200 OK",
        ),
        "h2_proxy_clean_eof.textproto": (
            "No length or transfer coding",
            "zero-error reset",
            "close-delimited",
        ),
        "h2_proxy_flow_control_upload.textproto": (
            "CURLOPT_POSTFIELDS",
            "SETTINGS_INITIAL_WINDOW_SIZE=0",
            "\\x00\\xff\\xff",
        ),
    }

    assert {path.name for path in SCENARIO_ROOT.glob("*.textproto")} == set(
        expected_tokens
    )
    for name, tokens in expected_tokens.items():
        scenario = (SCENARIO_ROOT / name).read_text(encoding="utf-8")
        assert "scheme: SCHEME_HTTP" in scenario
        assert "CURLOPT_HTTP_VERSION" not in scenario
        assert all(token in scenario for token in tokens), name


def test_h2_proxy_does_not_replay_the_incompatible_mixed_public_corpus() -> None:
    """Ordinary HTTP/1 response seeds are not useful HTTP/2 proxy frames."""
    helper = REPO_ROOT / "scripts" / "fuzz_corpus_helpers.sh"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; fuzz_public_corpus_names curl_fuzzer_proto_h2_proxy',
            "h2-proxy-corpus-test",
            str(helper),
        ],
        check=True,
        capture_output=True,
        encoding="utf-8",
    )

    assert result.stdout.splitlines() == ["curl_fuzzer_proto_h2_proxy"]
