"""Tooling for the curl-fuzzer repository."""

from .logger import common_logging
from .generate_decoder_html import generate_html

# Import * imports
__all__ = ["common_logging", "generate_html"]
