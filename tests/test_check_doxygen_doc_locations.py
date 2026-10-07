"""Tests for the Doxygen function-documentation location checker."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_doxygen_doc_locations.py"


def _load_module():  # type: ignore[no-untyped-def]
    specification = importlib.util.spec_from_file_location(
        "check_doxygen_doc_locations", SCRIPT
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def _member(
    qualified_name: str,
    *,
    argsstring: str = "()",
    description: str = "",
    description_element: str = "briefdescription",
    bodyfile: str | None = None,
    virt: str | None = None,
    member_id: str | None = None,
) -> str:
    attributes = ' kind="function"'
    if virt is not None:
        attributes += f' virt="{virt}"'
    if member_id is not None:
        attributes += f' id="{member_id}"'
    body_attribute = "" if bodyfile is None else f' bodyfile="{bodyfile}"'
    descriptions = {
        element_name: description if element_name == description_element else ""
        for element_name in (
            "briefdescription",
            "detaileddescription",
            "inbodydescription",
        )
    }
    return f"""<memberdef{attributes}>
        <qualifiedname>{qualified_name}</qualifiedname>
        <argsstring>{argsstring}</argsstring>
        <briefdescription><para>{descriptions["briefdescription"]}</para></briefdescription>
        <detaileddescription><para>{descriptions["detaileddescription"]}</para></detaileddescription>
        <inbodydescription><para>{descriptions["inbodydescription"]}</para></inbodydescription>
        <location file="proto_fuzzer/example.h" line="10"{body_attribute}/>
      </memberdef>"""


def _write_xml(tmp_path: Path, members: list[str]) -> Path:
    xml_dir = tmp_path / "xml"
    xml_dir.mkdir()
    (xml_dir / "example.xml").write_text(
        """<?xml version="1.0"?>
<doxygen>
  <compounddef>
    <sectiondef>
      """
        + "\n".join(members)
        + """
    </sectiondef>
  </compounddef>
</doxygen>
""",
        encoding="utf-8",
    )
    return xml_dir


def test_detects_documentation_from_each_description_element(tmp_path: Path) -> None:
    module = _load_module()
    xml_dir = _write_xml(
        tmp_path,
        [
            _member("example::Brief", description="A brief description."),
            _member(
                "example::Detailed",
                argsstring="(int   value)",
                description="A detailed description.",
                description_element="detaileddescription",
            ),
            _member(
                "example::InBody",
                description="An in-body description.",
                description_element="inbodydescription",
            ),
        ],
    )

    assert module.find_header_documented_functions(xml_dir) == {
        "proto_fuzzer/example.h:example::Brief()",
        "proto_fuzzer/example.h:example::Detailed(int value)",
        "proto_fuzzer/example.h:example::InBody()",
    }


def test_empty_description_elements_are_accepted(tmp_path: Path) -> None:
    module = _load_module()
    xml_dir = _write_xml(tmp_path, [_member("example::Undocumented")])

    assert module.find_header_documented_functions(xml_dir) == set()


def test_header_bodied_function_is_accepted(tmp_path: Path) -> None:
    module = _load_module()
    xml_dir = _write_xml(
        tmp_path,
        [
            _member(
                "example::Inline",
                description="Documented next to its header body.",
                bodyfile="proto_fuzzer/example.h",
            )
        ],
    )

    assert module.find_header_documented_functions(xml_dir) == set()


def test_documentation_separate_from_a_definition_in_another_header_is_rejected(
    tmp_path: Path,
) -> None:
    module = _load_module()
    xml_dir = _write_xml(
        tmp_path,
        [
            _member(
                "example::Inline",
                description="Documentation separate from the definition.",
                bodyfile="proto_fuzzer/example_impl.h",
            )
        ],
    )

    assert module.find_header_documented_functions(xml_dir) == {
        "proto_fuzzer/example.h:example::Inline()"
    }


def test_pure_defaulted_and_deleted_declarations_are_accepted(
    tmp_path: Path,
) -> None:
    module = _load_module()
    xml_dir = _write_xml(
        tmp_path,
        [
            _member(
                "example::Interface::Run",
                argsstring="() = 0",
                description="A pure virtual contract.",
                virt="pure-virtual",
            ),
            _member(
                "example::Value::Value",
                argsstring="() = default",
                description="A defaulted constructor.",
            ),
            _member(
                "example::Value::operator=",
                argsstring="(const Value &amp;)   = delete",
                description="A deleted assignment operator.",
            ),
        ],
    )

    assert module.find_header_documented_functions(xml_dir) == set()


def test_exact_baseline_matches_and_update_writes_canonical_order(
    tmp_path: Path,
) -> None:
    module = _load_module()
    xml_dir = _write_xml(
        tmp_path,
        [_member("example::Run", description="Run one example.")],
    )
    baseline = tmp_path / "baseline.txt"
    expected = "proto_fuzzer/example.h:example::Run()"
    baseline.write_text(f"# reviewed debt\n{expected}\n", encoding="utf-8")
    arguments = [
        "--xml-dir",
        str(xml_dir),
        "--baseline",
        str(baseline),
    ]

    assert module.main(arguments) == 0
    baseline.write_text("obsolete\n", encoding="utf-8")
    assert module.main([*arguments, "--update-baseline"]) == 0
    assert baseline.read_text(encoding="utf-8") == f"{expected}\n"


def test_reports_both_unexpected_and_stale_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    xml_dir = _write_xml(
        tmp_path,
        [_member("example::Run", description="Run one example.")],
    )
    baseline = tmp_path / "baseline.txt"
    baseline.write_text("proto_fuzzer/old.h:example::Old()\n", encoding="utf-8")

    result = module.main(
        [
            "--xml-dir",
            str(xml_dir),
            "--baseline",
            str(baseline),
        ]
    )

    assert result == 1
    error = capsys.readouterr().err
    assert "Unexpected function documentation attached to header declarations" in error
    assert "+ proto_fuzzer/example.h:example::Run()" in error
    assert "Stale baseline entries no longer found" in error
    assert "- proto_fuzzer/old.h:example::Old()" in error


def test_rejects_colliding_function_keys(tmp_path: Path) -> None:
    module = _load_module()
    xml_dir = _write_xml(
        tmp_path,
        [
            _member(
                "example::Run",
                description="First overload.",
                member_id="first",
            ),
            _member(
                "example::Run",
                description="Constrained overload with the same key.",
                member_id="second",
            ),
        ],
    )

    with pytest.raises(
        module.DocumentationLocationError,
        match="multiple Doxygen functions have the same baseline key",
    ):
        module.find_header_documented_functions(xml_dir)


def test_rejects_duplicate_baseline_entries(tmp_path: Path) -> None:
    module = _load_module()
    baseline = tmp_path / "baseline.txt"
    entry = "proto_fuzzer/example.h:example::Run()"
    baseline.write_text(f"{entry}\n{entry}\n", encoding="utf-8")

    with pytest.raises(
        module.DocumentationLocationError,
        match="contains duplicate entries",
    ):
        module.read_baseline(baseline)
