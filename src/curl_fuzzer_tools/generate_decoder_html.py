"""Generate an interactive HTML page for decoding curl corpus files."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from collections.abc import Sequence
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .corpus import BaseType
from .logger import common_logging

_TEMPLATE_NAME = "corpus_decoder.html"
_DEFAULT_OUTPUT = Path("docs/corpus-decoder/index.html")


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


def _render_html(env: Environment) -> str:
    template = env.get_template(_TEMPLATE_NAME)
    generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    typemap = {str(key): value for key, value in BaseType.TYPEMAP.items()}
    return template.render(generated_at=generated_at, typemap=typemap)


def generate_html(output: Path) -> Path:
    """Generate the HTML decoder page to the provided output path."""
    env = _jinja_env()
    html = _render_html(env)

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
    return parser.parse_args()


def main() -> Path:
    """CLI entry point for generating the decoder HTML."""
    args = _parse_args()
    output_path = args.output
    generated_file = generate_html(output_path)
    print(f"Generated decoder HTML at {generated_file}")
    return generated_file


def run() -> None:
    """Wrapper to set up logging before running the tool."""
    common_logging(__name__, __file__)
    main()


if __name__ == "__main__":
    run()
