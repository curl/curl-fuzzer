"""Smoke-test the contributor reference published beside the mdBook guides."""

from collections.abc import Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@pytest.fixture
def reference_site_url() -> Iterator[str]:
    """Serve the assembled site so browser navigation uses deployment URLs."""
    site = Path(__file__).resolve().parents[2] / "_site"
    assert (site / "proto" / "cpp-reference.html").is_file(), (
        "build the documentation with mdbook first"
    )
    assert (site / "api" / "proto_fuzzer" / "index.html").is_file(), (
        "assemble the Doxygen reference into the documentation site first"
    )
    handler = partial(SimpleHTTPRequestHandler, directory=str(site))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.skipif(sync_playwright is None, reason="Playwright not installed")
def test_cpp_reference_links_to_implementation_contract(
    reference_site_url: str,
) -> None:
    """Follow the guide to a migrated contract and its implementation source."""
    if sync_playwright is None:
        pytest.skip("Playwright not installed")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(f"{reference_site_url}/proto/cpp-reference.html")
        errors: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.locator('a[href$="api/proto_fuzzer/index.html"]').click()
        assert page.url == f"{reference_site_url}/api/proto_fuzzer/index.html"

        page.locator("#nav-tree").get_by_role(
            "link", name="Classes", exact=True
        ).click()
        page.get_by_role("link", name="Class List", exact=True).click()
        page.locator(".directory").get_by_role(
            "link", name="ScenarioRequestData", exact=True
        ).click()
        constructor = page.locator(".memitem").filter(
            has_text="Construct and apply the protocol-specific pointer-valued fields"
        )
        contract = " ".join(constructor.inner_text().split())
        assert "easy must remain alive until this object is destroyed" in contract
        assert "Easy handle that will perform this scenario." in contract

        constructor.get_by_role("link", name="request_data.cc", exact=True).click()
        assert "_source.html" in page.url
        assert (
            "ScenarioRequestData::ScenarioRequestData"
            in page.locator(".fragment").inner_text()
        )
        assert errors == []
        browser.close()
