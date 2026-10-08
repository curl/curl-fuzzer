"""Tooling for the curl-fuzzer repository."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .generate_decoder_html import generate_html
    from .logger import common_logging

# Import * imports
__all__ = ["common_logging", "generate_html"]


def __getattr__(name: str) -> Any:
    """Load public helpers without importing unrelated tool modules eagerly."""
    if name == "common_logging":
        from .logger import common_logging

        return common_logging
    if name == "generate_html":
        from .generate_decoder_html import generate_html

        return generate_html
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
