"""Tooling for the curl-fuzzer repository."""

from .generate_decoder_html import generate_html
from .logger import common_logging

# Import * imports
__all__ = ["common_logging", "generate_html"]
