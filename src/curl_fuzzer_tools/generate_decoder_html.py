#!/usr/bin/env python3
"""Generate an interactive HTML page for decoding curl corpus files."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .corpus import BaseType
from .logger import common_logging
from .read_proto_corpus import SCENARIO_MESSAGE, find_proto_file

_TEMPLATE_NAME = "corpus_decoder.html"
_DEFAULT_OUTPUT = Path("_site/corpus-decoder/index.html")
_BUNDLE_ENTRY = Path(__file__).with_name("browser") / "protobuf_bundle.js"
_REQUIRED_MODULE_FILES = (
    Path("esbuild/bin/esbuild"),
    Path("long/package.json"),
    Path("protobufjs/package.json"),
)
_LICENSE_FILES = (
    ("long.js", Path("long/LICENSE")),
    ("protobuf.js", Path("protobufjs/LICENSE")),
    ("Google protobuf definitions", Path("protobufjs/google/LICENSE")),
)


def find_node_modules(explicit: Path | None) -> Path | None:
    """Find an npm installation containing the browser decoder dependencies."""

    def has_required_files(candidate: Path) -> bool:
        required = (*_REQUIRED_MODULE_FILES, *(path for _, path in _LICENSE_FILES))
        return all((candidate / path).is_file() for path in required)

    if explicit is not None:
        if not has_required_files(explicit):
            raise FileNotFoundError(
                f"--node-modules {explicit} does not contain the decoder dependencies"
            )
        return explicit

    search_roots: list[Path] = []
    for location in (Path.cwd(), Path(__file__).resolve().parent):
        for ancestor in (location, *location.parents):
            if ancestor not in search_roots:
                search_roots.append(ancestor)
    for root in search_roots:
        candidate = root / "node_modules"
        if has_required_files(candidate):
            return candidate
    return None


def _javascript_bundle(node_modules: Path) -> str:
    """Return browser dependencies as one safe inline script."""
    command = [
        "node",
        str(node_modules / "esbuild/bin/esbuild"),
        str(_BUNDLE_ENTRY),
        "--bundle",
        "--format=iife",
        "--legal-comments=none",
        "--log-level=warning",
        "--minify",
        "--platform=browser",
        "--target=es2020",
    ]
    environment = os.environ.copy()
    environment["NODE_PATH"] = str(node_modules)
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=environment,
            text=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError("node is required to bundle protobuf.js") from error
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(f"esbuild failed ({result.returncode}): {stderr}")
    return re.sub(r"</script", r"<\/script", result.stdout, flags=re.IGNORECASE)


def _third_party_licenses(node_modules: Path) -> str:
    """Return license notices for the JavaScript bundled into the page."""
    notices = []
    for project, relative_path in _LICENSE_FILES:
        license_text = (node_modules / relative_path).read_text(encoding="utf-8")
        notices.append(f"{project}\n{'=' * len(project)}\n\n{license_text.strip()}")
    return "\n\n".join(notices)


def _jinja_env() -> Environment:
    template_dir = Path(__file__).with_name("templates")
    if not template_dir.exists():
        raise FileNotFoundError(f"Template directory not found at {template_dir}")
    return Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _render_html(
    env: Environment,
    proto_source: str,
    javascript_bundle: str,
    third_party_licenses: str,
) -> str:
    template = env.get_template(_TEMPLATE_NAME)
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    typemap = {str(key): value for key, value in BaseType.TYPEMAP.items()}
    return template.render(
        generated_at=generated_at,
        scenario_message=SCENARIO_MESSAGE,
        typemap=typemap,
        proto_source=proto_source,
        javascript_bundle=javascript_bundle,
        third_party_licenses=third_party_licenses,
    )


def generate_html(
    output: Path,
    proto_file: Path | None = None,
    node_modules: Path | None = None,
) -> Path:
    """Generate the HTML decoder page to the provided output path."""
    resolved_proto = find_proto_file(proto_file)
    if resolved_proto is None:
        raise FileNotFoundError(
            "curl_fuzzer.proto was not found; run from a source checkout or "
            "pass --proto-file"
        )
    resolved_node_modules = find_node_modules(node_modules)
    if resolved_node_modules is None:
        raise FileNotFoundError(
            "protobuf.js browser dependencies were not found; run `npm ci` "
            "from a source checkout or pass --node-modules"
        )
    env = _jinja_env()
    html = _render_html(
        env,
        resolved_proto.read_text(encoding="utf-8"),
        _javascript_bundle(resolved_node_modules),
        _third_party_licenses(resolved_node_modules),
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    return output


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help=f"Target path for the generated HTML file (default: {_DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--proto-file",
        type=Path,
        default=None,
        help="Path to curl_fuzzer.proto (default: auto-detect from the checkout).",
    )
    parser.add_argument(
        "--node-modules",
        type=Path,
        default=None,
        help=(
            "Path to node_modules containing the decoder build dependencies "
            "(default: auto-detect after npm ci)."
        ),
    )
    return parser.parse_args()


def main() -> Path:
    """CLI entry point for generating the decoder HTML."""
    args = _parse_args()
    output_path = args.output
    generated_file = generate_html(output_path, args.proto_file, args.node_modules)
    print(f"Generated decoder HTML at {generated_file}")
    return generated_file


def run() -> None:
    """Set up logging before running the tool."""
    common_logging(__name__, __file__)
    main()


if __name__ == "__main__":
    run()
