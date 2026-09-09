"""Reachability checks for the fixed SOCKS4/SOCKS4A coverage lane."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "socks4"


def test_socks4_seeds_cover_resolution_reply_and_fragmentation_modes() -> None:
    expected_tokens = {
        "socks4_success.textproto": (
            "SOCKS_PROXY_SOCKS4",
            'host_path: "localhost/socks4"',
            r'on_readable: "\000\132\000\120\177\000\000\001"',
            "HTTP/1.1 200 OK",
        ),
        "socks4a_fragmented.textproto": (
            "SOCKS_PROXY_SOCKS4A",
            'host_path: "socks.test/socks4a"',
            r'on_readable: "\000\132\000"',
            "HTTP/1.1 204 No Content",
        ),
        "socks4_rejected.textproto": (
            "SOCKS_PROXY_SOCKS4",
            r'on_readable: "\000\133\000\000\000\000\000\000"',
        ),
    }
    for name, tokens in expected_tokens.items():
        source = (SCENARIO_ROOT / name).read_text(encoding="utf-8")
        assert all(token in source for token in tokens), name
