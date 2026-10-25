"""Checks the shared-multi lane's correlated source scenarios."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_DIR = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "multi"


def test_multi_progress_ratelimit_seed_keeps_its_closed_profile() -> None:
    scenario = (SCENARIO_DIR / "multi_progress_ratelimit.textproto").read_text(
        encoding="utf-8"
    )

    assert "MULTI_STATE_PROBE_PROGRESS_RATE_LIMIT" in scenario
    assert 'accept_encoding: "identity"' in scenario
    assert "transfer_count: 2" in scenario
    assert scenario.count('initial_response: "HTTP/1.1 200 OK') == 2
    assert scenario.count("on_readable:") == 4
