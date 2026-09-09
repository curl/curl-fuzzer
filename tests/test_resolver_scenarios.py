"""Checks the resolver lane's source scenarios and isolation wiring."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "resolver"


def test_resolver_lane_has_localhost_and_structured_resolve_seeds() -> None:
    localhost = (SCENARIO_DIR / "localhost.textproto").read_text()
    structured = (SCENARIO_DIR / "resolve_entries.textproto").read_text()

    assert 'host_path: "localhost/' in localhost
    assert "resolve_entries:" not in localhost
    assert 'host_path: "resolve.test/' in structured
    assert 'resolve_entries: "+' in structured
    assert 'resolve_entries: "*:' in structured
    assert 'resolve_entries: "-' in structured
