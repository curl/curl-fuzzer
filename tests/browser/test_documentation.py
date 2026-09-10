"""Playwright smoke tests for the generated mdBook site."""

from pathlib import Path

import pytest

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_mermaid_diagram_renders() -> None:
    """Ensure the structured-fuzzer flowchart is rendered client-side."""
    overview = _repo_root() / "_site" / "proto" / "overview.html"
    assert overview.is_file(), "build the documentation with mdbook first"

    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(overview.resolve().as_uri())
        page.locator(".mermaid svg").wait_for(state="visible")

        assert page.locator(".mermaid svg").count() == 1

        browser.close()
