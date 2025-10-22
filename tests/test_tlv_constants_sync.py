"""Consistency checks between C and Python TLV definitions."""

from __future__ import annotations

import ast
import re
from pathlib import Path


_TLV_DEFINE_PATTERN = re.compile(r"#define\s+(TLV_TYPE_[A-Z0-9_]+)\s+([0-9]+)")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_header_constants(header_path: Path) -> dict[str, int]:
    constants: dict[str, int] = {}
    for line in header_path.read_text(encoding="utf-8").splitlines():
        match = _TLV_DEFINE_PATTERN.search(line)
        if not match:
            continue
        name = match.group(1)
        value = int(match.group(2))
        constants[name] = value
    return constants


def _parse_python_constants(module_path: Path) -> dict[str, int]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    constants: dict[str, int] = {}

    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "BaseType":
            for statement in node.body:
                if not isinstance(statement, ast.Assign):
                    continue
                if len(statement.targets) != 1:
                    continue
                target = statement.targets[0]
                if not isinstance(target, ast.Name):
                    continue
                value_node = statement.value
                value = _extract_int_constant(value_node)
                if value is None:
                    continue
                constants[target.id] = value
            break
    return constants


def _invert_map(constants: dict[str, int]) -> dict[int, str]:
    inverted: dict[int, str] = {}
    for name, value in constants.items():
        assert value not in inverted, (
            "Duplicate TLV numeric value detected: "
            f"{value} reused by {inverted[value]} and {name}"
        )
        inverted[value] = name
    return inverted


def _extract_int_constant(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, int):
            return node.value
        return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        operand = _extract_int_constant(node.operand)
        if operand is not None:
            return -operand
    return None


def test_tlv_constants_are_in_sync() -> None:
    """Ensure TLV IDs stay synchronized between C header and Python constants."""
    repo_root = _repo_root()
    header_constants = _parse_header_constants(repo_root / "curl_fuzzer.h")
    python_constants = _parse_python_constants(
        repo_root / "src" / "curl_fuzzer_tools" / "corpus.py"
    )

    assert header_constants, "No TLV constants found in curl_fuzzer.h"
    assert python_constants, "No TLV constants found in BaseType"

    header_by_value = _invert_map(header_constants)
    python_by_value = _invert_map(python_constants)

    header_values = set(header_by_value)
    python_values = set(python_by_value)

    missing_value_ids = sorted(header_values - python_values)
    assert not missing_value_ids, (
        "Python BaseType is missing TLV numeric IDs present in C: "
        + ", ".join(
            f"{header_by_value[value]} ({value})" for value in missing_value_ids
        )
    )

    extra_value_ids = sorted(python_values - header_values)
    assert not extra_value_ids, (
        "curl_fuzzer.h is missing TLV numeric IDs present in Python: "
        + ", ".join(
            f"{python_by_value[value]} ({value})" for value in extra_value_ids
        )
    )