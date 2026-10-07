"""Keep out-of-line function documentation beside its implementation."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx"})
NON_DEFINITION_SUFFIX = re.compile(r"=\s*(?:default|delete)\s*$")
DESCRIPTION_ELEMENTS = (
    "briefdescription",
    "detaileddescription",
    "inbodydescription",
)


class DocumentationLocationError(RuntimeError):
    """Raised when Doxygen data is invalid."""


def normalize_argsstring(argsstring: str) -> str:
    """Make Doxygen's line wrapping irrelevant to a function identity."""
    return " ".join(argsstring.split())


def _element_text(element: ElementTree.Element | None) -> str:
    if element is None:
        return ""
    return "".join(element.itertext())


def _has_documentation(member: ElementTree.Element) -> bool:
    return any(
        _element_text(member.find(element_name)).strip()
        for element_name in DESCRIPTION_ELEMENTS
    )


def _stable_header_path(raw_path: str) -> str:
    """Remove a checkout prefix while retaining the repository path."""
    path = PurePosixPath(raw_path.replace("\\", "/"))
    parts = path.parts
    try:
        proto_index = len(parts) - 1 - tuple(reversed(parts)).index("proto_fuzzer")
    except ValueError:
        if path.is_absolute():
            raise DocumentationLocationError(
                "absolute Doxygen header path has no proto_fuzzer component: "
                f"{raw_path}"
            ) from None
        return path.as_posix().removeprefix("./")
    return PurePosixPath(*parts[proto_index:]).as_posix()


def _is_header_path(raw_path: str | None) -> bool:
    return raw_path is not None and Path(raw_path).suffix.lower() in HEADER_SUFFIXES


def _is_exempt_declaration(member: ElementTree.Element) -> bool:
    if member.get("virt") == "pure-virtual":
        return True

    argsstring = normalize_argsstring(_element_text(member.find("argsstring")))
    if NON_DEFINITION_SUFFIX.search(argsstring):
        return True

    location = member.find("location")
    if location is None:
        return False
    declaration_path = location.get("file")
    body_path = location.get("bodyfile")
    return (
        _is_header_path(declaration_path)
        and _is_header_path(body_path)
        and _stable_header_path(declaration_path or "")
        == _stable_header_path(body_path or "")
    )


def _member_key(member: ElementTree.Element) -> str:
    location = member.find("location")
    raw_path = None if location is None else location.get("file")
    if not _is_header_path(raw_path):
        raise DocumentationLocationError(
            "documented header function has no header declaration location"
        )
    assert raw_path is not None

    qualified_name = _element_text(member.find("qualifiedname")).strip()
    if not qualified_name:
        raise DocumentationLocationError(
            f"Doxygen function in {raw_path} has no qualified name"
        )
    argsstring = normalize_argsstring(_element_text(member.find("argsstring")))
    return f"{_stable_header_path(raw_path)}:{qualified_name}{argsstring}"


def find_header_documented_functions(xml_dir: Path) -> set[str]:
    """Find documented declarations that have no body in their header."""
    xml_dir = xml_dir.resolve()
    if not xml_dir.is_dir():
        raise DocumentationLocationError(
            f"Doxygen XML directory does not exist: {xml_dir}"
        )

    xml_paths = sorted(xml_dir.rglob("*.xml"))
    if not xml_paths:
        raise DocumentationLocationError(f"no Doxygen XML files found below {xml_dir}")

    documented: dict[str, str] = {}
    for xml_path in xml_paths:
        try:
            root = ElementTree.parse(xml_path).getroot()
        except (OSError, ElementTree.ParseError) as error:
            raise DocumentationLocationError(
                f"could not parse Doxygen XML {xml_path}: {error}"
            ) from error

        for member in root.findall('.//memberdef[@kind="function"]'):
            if not _has_documentation(member) or _is_exempt_declaration(member):
                continue
            key = _member_key(member)
            member_id = member.get("id", "")
            previous_id = documented.get(key)
            if previous_id is not None and previous_id != member_id:
                raise DocumentationLocationError(
                    f"multiple Doxygen functions have the same function key: {key}"
                )
            documented[key] = member_id

    return set(documented)


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml-dir", required=True, type=Path)
    return parser.parse_args(arguments)


def _print_violations(observed: set[str]) -> None:
    print(
        "Function documentation attached to out-of-line header declarations:",
        file=sys.stderr,
    )
    for entry in sorted(observed):
        print(f"  {entry}", file=sys.stderr)
    print(
        "Move function descriptions to their out-of-line definitions.", file=sys.stderr
    )


def main(arguments: Sequence[str] | None = None) -> int:
    """Reject documentation on out-of-line header declarations."""
    parsed = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        observed = find_header_documented_functions(parsed.xml_dir)
    except DocumentationLocationError as error:
        print(
            f"Could not check Doxygen documentation locations: {error}",
            file=sys.stderr,
        )
        return 2

    if not observed:
        return 0
    _print_violations(observed)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
