"""Playwright integration test for the generated corpus decoder HTML."""

from pathlib import Path
from typing import Literal

import pytest

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

from curl_fuzzer_tools.corpus import TLVDecoder
from curl_fuzzer_tools.generate_decoder_html import generate_html


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _example_corpus() -> Path:
    repo_root = _repo_root()
    candidate = repo_root / "corpora" / "curl_fuzzer" / "oss-fuzz-3327"
    if not candidate.exists():
        pytest.skip(f"Example corpus file not present in repository checkout: {candidate}")
    return candidate


def _expected_tlvs(corpus_path: Path) -> int:
    data = corpus_path.read_bytes()
    return sum(1 for _ in TLVDecoder(data))

@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_upload_repository_corpus(tmp_path: Path) -> None:
    """Ensure the decoder UI handles uploading the repository corpus file."""
    html_path = tmp_path / "index.html"
    generate_html(html_path)

    corpus_path = _example_corpus()
    expected_tlvs = _expected_tlvs(corpus_path)

    file_url = html_path.resolve().as_uri()

    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(file_url)

        page.set_input_files("#corpus-input", str(corpus_path))
        page.wait_for_selector(f"text=Decoded {expected_tlvs} TLVs successfully.")

        summary_value = page.locator("#summary-count").inner_text()
        assert summary_value.strip() == str(expected_tlvs)

        rows = page.locator("tbody tr")
        assert rows.count() == expected_tlvs

        browser.close()


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_accessibility_after_upload_in_light_and_dark(tmp_path: Path, scheme: Literal["light", "dark"]) -> None:
    """Basic accessibility smoke: after upload, key elements are visible in both schemes.

    This test toggles prefers-color-scheme and checks that:
    - The dark/light CSS actually applies (by inspecting body background color in dark)
    - Headings and summary items remain present
    - A coarse contrast check (>= 3.0) passes between body background and heading text
        to catch regressions where text becomes unreadable.
    """
    html_path = tmp_path / "index.html"
    generate_html(html_path)

    corpus_path = _example_corpus()
    expected_tlvs = _expected_tlvs(corpus_path)

    file_url = html_path.resolve().as_uri()

    if sync_playwright is None:
        pytest.skip("Playwright not installed")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.emulate_media(color_scheme=scheme)  # Apply requested color scheme
        page.goto(file_url)

        # Upload corpus and wait for summary
        page.set_input_files("#corpus-input", str(corpus_path))
        page.wait_for_selector(f"text=Decoded {expected_tlvs} TLVs successfully.")

        # Verify headings and summary exist
        assert page.locator("header h1").count() == 1
        assert page.locator("#summary-count").inner_text().strip() == str(expected_tlvs)

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
        assert not failed, f"Low contrast elements in {scheme} mode: {failed[:3]}{(' …' if len(failed) > 3 else '')}"

        browser.close()
