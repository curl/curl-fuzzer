"""Value-kind invariants for the generated proto CURLOPT surface."""

from __future__ import annotations

from curl_fuzzer_tools.generate_option_manifest import CurlOption, render_manifest


def _kind(name: str, type_token: str = "CURLOPTTYPE_LONG") -> str:
    return CurlOption(name=name, type_token=type_token, curl_value=0).kind


def test_true_flags_use_boolean_mutations() -> None:
    """Keep flag mutations concentrated on the two values curl consumes."""
    for name in (
        "CURLOPT_UPLOAD",
        "CURLOPT_SSL_VERIFYPEER",
        "CURLOPT_COOKIESESSION",
        "CURLOPT_UNRESTRICTED_AUTH",
        "CURLOPT_HTTP09_ALLOWED",
        "CURLOPT_CRLF",
        "CURLOPT_CERTINFO",
    ):
        assert _kind(name) == "bool"


def test_modes_and_bitmasks_retain_full_integer_values() -> None:
    """Do not collapse valid non-boolean modes into false/true."""
    for name in (
        "CURLOPT_FOLLOWLOCATION",
        "CURLOPT_CONNECT_ONLY",
        "CURLOPT_WS_OPTIONS",
        "CURLOPT_HTTPAUTH",
        "CURLOPT_ALTSVC_CTRL",
        "CURLOPT_HSTS_CTRL",
        "CURLOPT_TIMECONDITION",
        "CURLOPT_POSTREDIR",
    ):
        assert _kind(name) == "uint"


def test_manifest_generates_direct_switch_lookup() -> None:
    """Both runtime users should dispatch without scanning every option."""
    entries = [
        CurlOption(
            name="CURLOPT_POSTFIELDS",
            type_token="CURLOPTTYPE_OBJECTPOINT",
            curl_value=10015,
        ),
        CurlOption(
            name="CURLOPT_FOLLOWLOCATION",
            type_token="CURLOPTTYPE_LONG",
            curl_value=52,
        ),
    ]

    rendered = render_manifest(entries)

    assert "switch (id)" in rendered
    assert "case curl::fuzzer::proto::CURLOPT_POSTFIELDS:" in rendered
    assert "return &kOptionManifest[0];" in rendered
    assert "case curl::fuzzer::proto::CURLOPT_FOLLOWLOCATION:" in rendered
    assert "return &kOptionManifest[1];" in rendered
    assert "default:\n      return nullptr;" in rendered
    assert "kOptionManifestSize" not in rendered
    assert "for (" not in rendered
