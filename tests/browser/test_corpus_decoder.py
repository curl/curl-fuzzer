"""Playwright integration tests for the generated corpus decoder HTML."""

from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import pytest

sync_playwright: Any
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

from curl_fuzzer_tools.generate_decoder_html import generate_html


def _write_input(tmp_path: Path, name: str, data: bytes) -> Path:
    input_path = tmp_path / name
    input_path.write_bytes(data)
    return input_path


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _proto_varint(field_number: int, value: int) -> bytes:
    return _varint(field_number << 3) + _varint(value)


def _proto_bytes(field_number: int, value: bytes) -> bytes:
    return _varint((field_number << 3) | 2) + _varint(len(value)) + value


def _example_scenario() -> bytes:
    option = _proto_varint(59, 1)
    connection = _proto_bytes(1, b"HTTP/1.1 200 OK\r\n\r\n")
    return b"".join(
        (
            _proto_varint(1, 1),
            _proto_bytes(2, b"127.0.0.1/browser"),
            _proto_bytes(3, option),
            _proto_bytes(4, connection),
            _proto_varint(100, 7),
        )
    )


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_upload_protobuf_scenario_without_network_access(tmp_path: Path) -> None:
    """Decode named, nested, and unknown protobuf fields without network I/O."""
    html_path = tmp_path / "index.html"
    generate_html(html_path)
    scenario_path = _write_input(tmp_path, "browser.scenario", _example_scenario())

    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        external_requests: list[str] = []
        page_errors: list[str] = []

        def record_external_request(request: object) -> None:
            url = getattr(request, "url", "")
            if urlsplit(url).scheme in {"http", "https"}:
                external_requests.append(url)

        page.on("request", record_external_request)
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.goto(html_path.resolve().as_uri())
        assert page.evaluate("typeof protobuf.textformat.toText") == "function"
        assert page.evaluate("Boolean(protobuf.util.Long)") is True
        page.set_input_files("#corpus-input", str(scenario_path))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")

        assert (
            page.locator("#summary-format").inner_text().strip() == "Protobuf Scenario"
        )
        assert page.locator("#proto-results").is_visible()
        output = page.locator("#proto-output").inner_text()
        assert "scheme: SCHEME_HTTP" in output
        assert 'host_path: "127.0.0.1/browser"' in output
        assert "options {" in output
        assert "nobody: true" in output
        assert "connection {" in output
        assert "100: 7" in output
        assert "1 unknown field retained" in page.locator("#messages").inner_text()
        assert external_requests == []
        assert page_errors == []

        browser.close()


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_protobuf_integer_and_repeated_wire_forms(tmp_path: Path) -> None:
    """Render packed/unpacked integers, uint64 max, and an unknown option field."""
    html_path = tmp_path / "index.html"
    generate_html(html_path)
    packed_read_sizes = b"".join(_varint(value) for value in (1, 128, 16384))
    upload = _proto_bytes(2, packed_read_sizes) + _proto_varint(2, 7)
    max_uint_option = _proto_varint(6, 2**64 - 1)
    unknown_option = _proto_varint(123, 1)
    scenario_path = _write_input(
        tmp_path,
        "integer-forms.scenario",
        b"".join(
            (
                _proto_varint(1, 1),
                _proto_bytes(3, max_uint_option),
                _proto_bytes(3, unknown_option),
                _proto_bytes(8, upload),
            )
        ),
    )

    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.resolve().as_uri())
        page.set_input_files("#corpus-input", str(scenario_path))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")

        output = page.locator("#proto-output").inner_text()
        assert "buffersize: 18446744073709551615" in output
        assert "123: 1" in output
        assert [
            line.strip() for line in output.splitlines() if "read_sizes:" in line
        ] == [
            "read_sizes: 1",
            "read_sizes: 128",
            "read_sizes: 16384",
            "read_sizes: 7",
        ]

        browser.close()


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_protobuf_text_format_and_presence_semantics(tmp_path: Path) -> None:
    """Use protobuf semantics for bytes, defaults, duplicate fields, and wire types."""
    html_path = tmp_path / "index.html"
    generate_html(html_path)
    binary_bytes = _write_input(
        tmp_path,
        "binary-bytes.scenario",
        _proto_bytes(2, b'\0"\\\n\xffA'),
    )
    explicit_default = _write_input(
        tmp_path,
        "explicit-default.scenario",
        _proto_varint(1, 0),
    )
    duplicate_scalar = _write_input(
        tmp_path,
        "duplicate-scalar.scenario",
        _proto_varint(1, 1) + _proto_varint(1, 2),
    )
    wrong_wire = _write_input(tmp_path, "wrong-wire.scenario", b"\x10\x01")

    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.resolve().as_uri())

        page.set_input_files("#corpus-input", str(binary_bytes))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")
        assert (
            r'host_path: "\000\"\\\n\377A"'
            in page.locator("#proto-output").inner_text()
        )

        page.set_input_files("#corpus-input", str(explicit_default))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")
        assert page.locator("#summary-format").inner_text() == "Protobuf Scenario"
        assert "default-valued Scenario" in page.locator("#proto-output").inner_text()

        page.set_input_files("#corpus-input", str(duplicate_scalar))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")
        output = page.locator("#proto-output").inner_text()
        assert "scheme: SCHEME_HTTPS" in output
        assert "SCHEME_HTTP\n" not in output

        page.set_input_files("#corpus-input", str(wrong_wire))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")
        assert page.locator("#proto-output").inner_text().strip() == "2: 1"

        browser.close()


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_scenario_bytes_have_one_unambiguous_decoder(tmp_path: Path) -> None:
    """Decode Scenario bytes directly without a retired format selector."""
    html_path = tmp_path / "index.html"
    generate_html(html_path)
    scenario_path = _write_input(
        tmp_path, "zero-host.scenario", b"\x12\x04\x00\x00\x00\x00"
    )

    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.resolve().as_uri())
        page.set_input_files("#corpus-input", str(scenario_path))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")

        assert (
            page.locator("#summary-format").inner_text().strip() == "Protobuf Scenario"
        )
        assert (
            'host_path: "\\000\\000\\000\\000"'
            in page.locator("#proto-output").inner_text()
        )
        assert page.locator("#format-select").count() == 0

        browser.close()


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_malformed_input_reports_the_protobuf_decoder_error(tmp_path: Path) -> None:
    """Report malformed protobuf input without a format-selection round trip."""
    html_path = tmp_path / "index.html"
    generate_html(html_path)
    malformed_proto = _write_input(tmp_path, "malformed-proto", b"\x12\x04a")

    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.resolve().as_uri())

        page.set_input_files("#corpus-input", str(malformed_proto))
        page.wait_for_selector("text=Invalid protobuf Scenario:")
        assert (
            page.locator("#summary-format").inner_text().strip() == "Protobuf Scenario"
        )
        assert page.locator("#summary-errors").inner_text().strip() == "1"
        assert not page.locator("#proto-results").is_visible()

        browser.close()


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_unknown_only_and_empty_scenarios_are_inspectable(tmp_path: Path) -> None:
    """Render valid protobuf inputs even when they have no known fields."""
    html_path = tmp_path / "index.html"
    generate_html(html_path)
    unknown_path = _write_input(
        tmp_path, "unknown-only.scenario", _proto_varint(100, 7)
    )
    empty_path = _write_input(tmp_path, "empty.scenario", b"")

    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.resolve().as_uri())

        page.set_input_files("#corpus-input", str(unknown_path))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")
        assert "100: 7" in page.locator("#proto-output").inner_text()
        assert page.locator("#summary-count").inner_text().strip() == "0"

        page.set_input_files("#corpus-input", str(empty_path))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")
        assert (
            page.locator("#proto-output").inner_text().strip()
            == "# Empty or default-valued Scenario"
        )

        browser.close()


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_accessibility_after_upload_in_light_and_dark(
    tmp_path: Path, scheme: Literal["light", "dark"]
) -> None:
    """
    Basic accessibility smoke: after upload, key elements are visible in both schemes.

    This test toggles prefers-color-scheme and checks that:
    - The dark/light CSS actually applies (by inspecting body background color in dark)
    - Headings and summary items remain present
    - A coarse contrast check (>= 3.0) passes between body background and heading text
        to catch regressions where text becomes unreadable.
    """
    html_path = tmp_path / "index.html"
    generate_html(html_path)
    scenario_path = _write_input(tmp_path, "browser.scenario", _example_scenario())

    file_url = html_path.resolve().as_uri()

    if sync_playwright is None:
        pytest.skip("Playwright not installed")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.emulate_media(color_scheme=scheme)  # Apply requested color scheme
        page.goto(file_url)

        # Upload a Scenario and wait for summary
        page.set_input_files("#corpus-input", str(scenario_path))
        page.wait_for_selector("text=Decoded protobuf Scenario successfully.")

        # Verify headings and summary exist
        assert page.locator("header h1").count() == 1
        assert int(page.locator("#summary-count").inner_text().strip()) > 0

        # Page-wide contrast sweep over visible text nodes; collect failures (< 3.0)
        results = page.evaluate(
            r"""
            () => {
                function parseColor(c) {
                    const m = c.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([0-9.]+))?\)/);
                    if (!m) return {r:0,g:0,b:0,a:1};
                    return { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] };
                }
                function blend(top, bottom) {
                    // Alpha composite 'top' over 'bottom'; both are {r,g,b,a} with a in [0,1]
                    const a = top.a + bottom.a * (1 - top.a);
                    const r = Math.round((top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / (a || 1));
                    const g = Math.round((top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / (a || 1));
                    const b = Math.round((top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / (a || 1));
                    return { r, g, b, a: 1 };
                }
                function srgbToLin(v) {
                    v /= 255;
                    return v <= 0.04045 ? v/12.92 : Math.pow((v + 0.055)/1.055, 2.4);
                }
                function relLuma({r,g,b}) {
                    const R = srgbToLin(r), G = srgbToLin(g), B = srgbToLin(b);
                    return 0.2126*R + 0.7152*G + 0.0722*B;
                }
                function isVisible(el) {
                    const cs = getComputedStyle(el);
                    const rect = el.getBoundingClientRect();
                    return rect.width > 0 && rect.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity) > 0.05;
                }
                function bodyBg() {
                    let b = parseColor(getComputedStyle(document.body).backgroundColor);
                    if (b.a === 0) b = { r: 255, g: 255, b: 255, a: 1 };
                    return b;
                }
                function effectiveBackground(el) {
                    if (!el) return bodyBg();
                    const cs = getComputedStyle(el);
                    const bg = parseColor(cs.backgroundColor);
                    if (bg.a === 0) return effectiveBackground(el.parentElement);
                    const parentBg = effectiveBackground(el.parentElement);
                    if (bg.a >= 1) return bg;
                    return blend(bg, parentBg);
                }
                const nodes = Array.from(document.querySelectorAll('*'));
                const failures = [];
                let scanned = 0;
                for (const el of nodes) {
                    if (!isVisible(el)) continue;
                    const text = (el.textContent || '').trim();
                    if (!text) continue;
                    const cs = getComputedStyle(el);
                    let fg = parseColor(cs.color);
                    const bg = effectiveBackground(el);
                    if (fg.a === 0) continue; // fully transparent text
                    if (fg.a < 1) fg = blend(fg, bg);
                    const L1 = relLuma(fg);
                    const L2 = relLuma(bg);
                    const contrast = (Math.max(L1,L2)+0.05) / (Math.min(L1,L2)+0.05);
                    scanned += 1;
                    if (contrast < 3.0) {
                        failures.push({ tag: el.tagName.toLowerCase(), text: text.slice(0, 60), contrast: Math.round(contrast*100)/100 });
                    }
                }
                return { scanned, failures, minContrast: failures.length ? Math.min(...failures.map(f=>f.contrast)) : null };
            }
            """
        )
        assert results and isinstance(results, dict)
        assert results.get("scanned", 0) > 0
        failed = results.get("failures", [])
        assert not failed, (
            f"Low contrast elements in {scheme} mode: {failed[:3]}{(' …' if len(failed) > 3 else '')}"
        )

        browser.close()
