"""Check that the installed Python Protobuf runtime is supported."""

from __future__ import annotations

import re
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version

MINIMUM_VERSION = (5, 29)
EXCLUSIVE_MAXIMUM_VERSION = (8, 0)
REQUIREMENT = "protobuf>=5.29,<8"
VERSION_PREFIX = re.compile(r"^(\d+)\.(\d+)(?:\.|$)")


def supports_version(version: str) -> bool:
    """Return whether a Protobuf version satisfies the tooling contract."""
    match = VERSION_PREFIX.match(version)
    if match is None:
        return False
    major_minor = (int(match.group(1)), int(match.group(2)))
    return MINIMUM_VERSION <= major_minor < EXCLUSIVE_MAXIMUM_VERSION


def main() -> int:
    """Report an absent or unsupported Protobuf runtime."""
    try:
        installed = package_version("protobuf")
    except PackageNotFoundError:
        print(f"Python {REQUIREMENT} is required; protobuf is not installed.", file=sys.stderr)
        return 1

    if supports_version(installed):
        return 0

    print(f"Python {REQUIREMENT} is required; found protobuf {installed}.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
