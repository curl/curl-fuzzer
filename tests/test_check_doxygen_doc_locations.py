"""Tests for the Doxygen function-documentation location checker."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
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


def test_accepts_xml_with_no_header_function_descriptions(tmp_path: Path) -> None:
    module = _load_module()
    xml_dir = _write_xml(tmp_path, [_member("example::Run")])

    assert module.main(["--xml-dir", str(xml_dir)]) == 0


def test_reports_header_documentation_and_how_to_fix_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = _load_module()
    xml_dir = _write_xml(
        tmp_path,
        [_member("example::Run", description="Run one example.")],
    )
    result = module.main(["--xml-dir", str(xml_dir)])

    assert result == 1
    error = capsys.readouterr().err
    assert "Function documentation attached to out-of-line header declarations" in error
    assert "proto_fuzzer/example.h:example::Run()" in error
    assert "Move function descriptions to their out-of-line definitions" in error


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
        match="multiple Doxygen functions have the same function key",
    ):
        module.find_header_documented_functions(xml_dir)


@pytest.mark.parametrize("contents", [None, "invalid XML"])
def test_reports_invalid_xml_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], contents: str | None
) -> None:
    module = _load_module()
    xml_dir = tmp_path / "xml"
    if contents is not None:
        xml_dir.mkdir()
        (xml_dir / "example.xml").write_text(contents, encoding="utf-8")

    assert module.main(["--xml-dir", str(xml_dir)]) == 2
    assert "Could not check Doxygen documentation locations" in capsys.readouterr().err


def test_real_doxygen_preserves_docs_after_moving_them_to_definition(
    tmp_path: Path,
) -> None:
    doxygen = shutil.which("doxygen")
    if doxygen is None:
        pytest.skip("Doxygen is not installed")

    module = _load_module()
    source_dir = tmp_path / "proto_fuzzer"
    source_dir.mkdir()
    header = source_dir / "example.h"
    implementation = source_dir / "example.cc"
    description = """/// Run one example.
/// @param value The input value.
/// @return The input unchanged.
"""
    header.write_text(
        "/// @file\n\nnamespace proto_fuzzer {\n"
        + description
        + "int Run(int value);\n}\n",
        encoding="utf-8",
    )
    implementation.write_text(
        '/// @file\n\n#include "example.h"\nnamespace proto_fuzzer {\n'
        + "int Run(int value) { return value; }\n}\n",
        encoding="utf-8",
    )

    coverage_config = tmp_path / "Doxyfile"
    location_config = tmp_path / "Doxyfile.locations"
    warning_log = tmp_path / "warnings.log"
    substitutions = {
        "PROTO_FUZZER_SRC_DIR": str(source_dir),
        "DOXYGEN_OUTPUT_DIR": str(tmp_path / "coverage"),
        "DOXYGEN_WARN_LOG": str(warning_log),
        "DOXYFILE_OUT": str(coverage_config),
        "DOXYGEN_LOCATION_OUTPUT_DIR": str(tmp_path / "locations"),
    }
    for template, destination in (
        ("Doxyfile.in", coverage_config),
        ("Doxyfile.locations.in", location_config),
    ):
        configuration = (REPO_ROOT / "proto_fuzzer" / template).read_text(
            encoding="utf-8"
        )
        for name, value in substitutions.items():
            configuration = configuration.replace(f"@{name}@", f'"{value}"')
        destination.write_text(configuration, encoding="utf-8")

    subprocess.run([doxygen, str(location_config)], check=True, capture_output=True)
    xml_dir = tmp_path / "locations" / "xml"
    assert module.find_header_documented_functions(xml_dir) == {
        "proto_fuzzer/example.h:proto_fuzzer::Run(int value)"
    }

    header.write_text(
        "/// @file\n\nnamespace proto_fuzzer {\nint Run(int value);\n}\n",
        encoding="utf-8",
    )
    implementation.write_text(
        '/// @file\n\n#include "example.h"\nnamespace proto_fuzzer {\n'
        + description
        + "int Run(int value) { return value; }\n}\n",
        encoding="utf-8",
    )
    shutil.rmtree(xml_dir.parent)
    subprocess.run([doxygen, str(location_config)], check=True, capture_output=True)
    assert module.main(["--xml-dir", str(xml_dir)]) == 0

    # Coverage must still discover the description and its parameter/return docs.
    with coverage_config.open("a", encoding="utf-8") as config:
        config.write("\nGENERATE_XML = YES\n")
    subprocess.run([doxygen, str(coverage_config)], check=True, capture_output=True)
    assert warning_log.read_text(encoding="utf-8") == ""
    coverage_xml = tmp_path / "coverage" / "xml"
    members = [
        member
        for xml_path in coverage_xml.glob("*.xml")
        for member in module.ElementTree.parse(xml_path).findall(
            './/memberdef[@kind="function"]'
        )
        if member.findtext("name") == "Run"
    ]
    assert members
    for member in members:
        assert "Run one example." in module._element_text(
            member.find("briefdescription")
        )
        assert "The input value." in module._element_text(
            member.find("detaileddescription")
        )
        assert "The input unchanged." in module._element_text(
            member.find("detaileddescription")
        )
