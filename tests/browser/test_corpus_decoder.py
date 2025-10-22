"""Playwright integration test for the generated corpus decoder HTML."""

from pathlib import Path

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
