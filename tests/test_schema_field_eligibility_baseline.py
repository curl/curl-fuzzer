"""Consistency checks for the pre-cutover Scenario-field eligibility capture."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "schema_eligibility"
    / "baseline_field_eligibility.json"
)

EXPECTED_PROFILES = {
    "compatibility",
    "fast_http",
    "deep_http",
    "fast_https",
    "https_h2",
    "fast_http2",
    "fast_http3",
    "h2_proxy",
    "proxy_transport",
    "resolver",
    "fast_websocket",
    "fast_secure_websocket",
    "fast_telnet",
    "fast_ftp",
    "fast_tftp",
    "fast_smtp",
    "fast_imap",
    "fast_pop3",
    "fast_mqtt",
    "fast_dict",
    "fast_gopher",
    "fast_file",
    "fast_ldap",
    "fast_rtsp",
    "fast_ipfs",
    "api",
    "multi",
    "timing",
}

BASELINE_REVISION = "f76d561e063fc80c1c30dde789f85adf7b57a1e3"
OLD_DESCRIPTOR_SHA256 = (
    "a611fcf2b53e596c09bc25482198d492a79bb5ab3ae0ec4fd77bacb064a9981e"
)


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _field(document: dict[str, Any], profile: str, path: str) -> dict[str, Any]:
    return next(
        field
        for field in document["profiles"][profile]["fields"]
        if field["path"] == path
    )


def _exception(field: dict[str, Any], variant: str) -> bool:
    return next(
        item["retained"] for item in field["exceptions"] if item["variant"] == variant
    )


def test_field_baseline_covers_profiles_and_reachable_closure() -> None:
    document = _fixture()
    assert document["format"] == 1
    assert document["baseline_revision"] == BASELINE_REVISION
    assert document["old_descriptor_sha256"] == OLD_DESCRIPTOR_SHA256
    assert set(document["profiles"]) == EXPECTED_PROFILES
    assert document["variants"][0] == "default"
    assert any(item.startswith("scheme=SCHEME_") for item in document["variants"])
    assert "h2_forward_proxy=true" in document["variants"]
    assert document["selector_audit"] == {
        "h2_forward_proxy": "included as an independent H2-proxy axis",
        "happy_eyeballs": (
            "no separate variant: it changes resolver execution, not field retention"
        ),
        "fail_allocations_with_mime": (
            "no field variant: it conditionally removes scalar options only"
        ),
        "probe_multi_pollset": (
            "no separate variant: its own leaf is probed directly and it gates no "
            "other field"
        ),
    }
    assert "happy_eyeballs=true" not in document["variants"]
    assert "fail_allocations_with_mime=true" not in document["variants"]
    assert "probe_multi_pollset=true" not in document["variants"]

    for profile, body in document["profiles"].items():
        paths = [field["path"] for field in body["fields"]]
        assert paths == sorted(paths), profile
        assert len(paths) == len(set(paths)), profile
        path_set = set(paths)
        for path in paths:
            components = path.split(".")
            for length in range(1, len(components)):
                assert ".".join(components[:length]) in path_set, (profile, path)
        for field in body["fields"]:
            variants = [item["variant"] for item in field["exceptions"]]
            assert len(variants) == len(set(variants)), (profile, field["path"])
            assert set(variants) <= set(document["variants"])


def test_field_baseline_records_conditional_unions_and_removals() -> None:
    document = _fixture()

    assert not _field(document, "deep_http", "connection.backpressure")["default"]
    assert _exception(
        _field(document, "deep_http", "connection.backpressure"),
        "http_transport_mode=HTTP_TRANSPORT_CONNECT_PROXY+haproxy_protocol=true",
    )
    assert _exception(
        _field(document, "fast_http3", "connection.initial_response"),
        "http3_plan.use_h1_connect_udp_proxy=true",
    )
    assert _exception(_field(document, "resolver", "http2_plan"), "doh_https_rr=true")
    assert not _exception(
        _field(document, "https_h2", "connection.initial_response"),
        "http2_plan=present",
    )
    assert not _exception(
        _field(document, "fast_ldap", "ldap_starttls"),
        "scheme=SCHEME_LDAPS",
    )
    assert _exception(
        _field(document, "api", "api_plan.repeat_mime_post"),
        "api_plan.repeat_mime_post=true+upload_callback",
    )
    assert not _exception(_field(document, "timing", "mime_post"), "scheme=SCHEME_WS")


def test_field_baseline_probes_normalized_values_and_correlated_siblings() -> None:
    document = _fixture()

    # One is folded to zero by the target policy; the four-valued probe proves
    # the field itself remains representable.
    assert _field(document, "fast_http3", "http3_plan.actions.goaway.id")["default"]

    # repeat_count survives only when the GeneratedBytes sibling pattern is
    # nonempty. Every profile retaining that local shape must therefore expose
    # both fields in the static union.
    for profile, body in document["profiles"].items():
        paths = {field["path"] for field in body["fields"]}
        for generated in (
            "mime_post.parts.generated_data",
            "mime_post.parts.subparts.parts.generated_data",
        ):
            if f"{generated}.pattern" in paths:
                assert f"{generated}.repeat_count" in paths, profile
    assert _field(document, "api", "mime_post.parts.generated_data.repeat_count")[
        "default"
    ]

    # This boolean is deliberately forced false for the initial SETTINGS
    # frame; sibling correlation must not turn that policy removal into a hit.
    fast_http2_paths = {
        field["path"] for field in document["profiles"]["fast_http2"]["fields"]
    }
    assert "http2_plan.initial_settings.ack" not in fast_http2_paths
