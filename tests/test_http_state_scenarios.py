"""Safety and reachability invariants for HTTP state-machine proto seeds."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPPORTED_OPTIONS = REPO_ROOT / "schemas" / "curl_fuzzer_supported_curlopts.txt"
HTTP_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "http"


def _supported_options() -> set[str]:
    return {
        line
        for raw_line in SUPPORTED_OPTIONS.read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    }


def test_state_options_are_reachable_without_mutable_cache_paths() -> None:
    """Keep state parsers fuzzable without exposing filesystem path options."""
    supported = _supported_options()
    assert {
        "CURLOPT_COOKIE",
        "CURLOPT_COOKIELIST",
        "CURLOPT_COOKIESESSION",
        "CURLOPT_HTTPAUTH",
        "CURLOPT_USERPWD",
        "CURLOPT_USERNAME",
        "CURLOPT_PASSWORD",
        "CURLOPT_UNRESTRICTED_AUTH",
        "CURLOPT_XOAUTH2_BEARER",
        "CURLOPT_AWS_SIGV4",
        "CURLOPT_TIMECONDITION",
        "CURLOPT_TIMEVALUE_LARGE",
        "CURLOPT_ALTSVC_CTRL",
        "CURLOPT_HSTS_CTRL",
    } <= supported
    assert {
        "CURLOPT_COOKIEFILE",
        "CURLOPT_COOKIEJAR",
        "CURLOPT_ALTSVC",
        "CURLOPT_HSTS",
    }.isdisjoint(supported)


def test_seed_families_keep_their_high_value_wire_tokens() -> None:
    """Catch accidental simplification of parser-oriented response seeds."""
    cookie_dates = (HTTP_SCENARIOS / "http_cookie_dates.textproto").read_text()
    assert "Set-Cookie:" in cookie_dates
    assert "Last-Modified:" in cookie_dates
    assert "Retry-After:" in cookie_dates

    digest = (HTTP_SCENARIOS / "http_digest_auth_sha256_sess.textproto").read_text()
    assert "WWW-Authenticate: Digest" in digest
    assert "algorithm=SHA-256-SESS" in digest
    assert 'qop=\\"auth-int\\"' in digest

    transport = (HTTP_SCENARIOS / "http_altsvc_hsts.textproto").read_text()
    assert "Alt-Svc: clear" in transport
    assert "Strict-Transport-Security: max-age=0" in transport


def test_stateful_seeds_complete_bounded_follow_on_exchanges() -> None:
    """Keep redirects/auth retries exercising curl after the second open."""
    for name in (
        "post_with_redirect.textproto",
        "http_digest_auth_md5.textproto",
        "http_cross_host_cookie_redirect.textproto",
        "http_cross_host_auth_redirect.textproto",
    ):
        scenario = (HTTP_SCENARIOS / name).read_text(encoding="utf-8")
        assert "subsequent_connections {" in scenario
        assert scenario.count("subsequent_connections {") <= 3

    cookie = (HTTP_SCENARIOS / "http_cross_host_cookie_redirect.textproto").read_text()
    assert "Location: http://child.state.test/" in cookie
    assert "Domain=.state.test" in cookie

    auth = (HTTP_SCENARIOS / "http_cross_host_auth_redirect.textproto").read_text()
    assert "Location: http://auth-target.test/" in auth
    assert "CURLOPT_USERPWD" in auth


def test_early_upgrade_abort_stays_in_the_timing_lane() -> None:
    """Require real upload pressure without taxing fixed fast HTTP seeds."""
    scenario = (
        HTTP_SCENARIOS / "http_post_early_upgrade_backpressure.textproto"
    ).read_text(encoding="utf-8")
    assert "CURLOPT_UPLOAD bool_value: true" in scenario
    assert 'request_headers: "Connection: Upgrade"' in scenario
    assert 'request_headers: "Upgrade:' in scenario
    assert "101 Switching Protocols" in scenario
    assert "backpressure {" in scenario
