"""Safety and reachability invariants for HTTP state-machine proto seeds."""

from __future__ import annotations

from pathlib import Path

from curl_fuzzer_tools.generate_option_manifest import parse_proto_options

REPO_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_SCHEMA = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
HTTP_SCENARIOS = REPO_ROOT / "scenarios" / "curl_fuzzer_proto" / "http"


def _supported_options() -> set[str]:
    return {
        option.name
        for option in parse_proto_options(SCENARIO_SCHEMA.read_text(encoding="utf-8"))
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

    digest_sha512 = (
        HTTP_SCENARIOS / "http_digest_auth_sha512_256.textproto"
    ).read_text(encoding="utf-8")
    assert "WWW-Authenticate: Digest" in digest_sha512
    assert "algorithm=SHA-512-256" in digest_sha512
    assert "subsequent_connections {" in digest_sha512

    digest_sha512_sess = (
        HTTP_SCENARIOS / "http_digest_auth_sha512_256_sess.textproto"
    ).read_text(encoding="utf-8")
    assert "WWW-Authenticate: Digest" in digest_sha512_sess
    assert "algorithm=SHA-512-256-SESS" in digest_sha512_sess
    assert 'qop=\\"auth\\"' in digest_sha512_sess
    assert "subsequent_connections {" in digest_sha512_sess

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


def test_bearer_seed_requires_a_challenged_retry() -> None:
    """Keep Bearer parsing behind a real 401 exchange."""
    scenario = (HTTP_SCENARIOS / "http_auth_bearer.textproto").read_text(
        encoding="utf-8"
    )
    assert "WWW-Authenticate: Bearer" in scenario
    assert "Connection: close" in scenario
    assert "CURLOPT_XOAUTH2_BEARER" in scenario
    assert "subsequent_connections {" in scenario


def test_dead_connection_seed_prunes_a_reusable_redirect_socket() -> None:
    """Keep pool pruning behind a real dead idle HTTP/1.1 connection."""
    scenario = (
        HTTP_SCENARIOS / "http_redirect_reap_dead_connection.textproto"
    ).read_text(encoding="utf-8")
    assert "302 Found" in scenario
    assert "Location: /final" in scenario
    assert "CURLOPT_FOLLOWLOCATION uint_value: 1" in scenario
    assert "CURLOPT_FRESH_CONNECT bool_value: true" in scenario
    assert "Connection: close" not in scenario
    assert scenario.count("subsequent_connections {") == 1


def test_sigv4_seeds_compute_s3_and_generic_payload_hashes() -> None:
    """Do not let a supplied content hash bypass either signer path."""
    s3 = (HTTP_SCENARIOS / "http_auth_aws_sigv4.textproto").read_text(encoding="utf-8")
    service = (HTTP_SCENARIOS / "http_auth_aws_sigv4_service.textproto").read_text(
        encoding="utf-8"
    )

    assert "aws:amz:us-east-1:s3" in s3
    assert "CURLOPT_POSTFIELDS" in s3
    assert "X-Amz-Content-Sha256" not in s3
    assert "aws:amz:us-east-1:execute-api" in service
    assert "%20" in service
    assert "X-Amz-Content-Sha256" not in service


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
