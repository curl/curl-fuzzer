"""Shared descriptor-backed fixtures for the active annotated schema."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from curl_fuzzer_tools.schema_eligibility import FieldRule, load_schema_model

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas"


@pytest.fixture(scope="session")
def active_option_fields(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, FieldRule]:
    """Return active typed option fields keyed by their native CURLOPT name."""
    protoc = shutil.which("protoc")
    if protoc is None:
        pytest.skip("protoc unavailable")
    output = tmp_path_factory.mktemp("active-schema") / "active.desc"
    subprocess.run(
        [
            protoc,
            f"--proto_path={SCHEMA_DIR}",
            "--include_imports",
            f"--descriptor_set_out={output}",
            "curl_fuzzer.proto",
        ],
        check=True,
    )
    model = load_schema_model(output.read_bytes())
    return {
        field.native_name: field
        for field in model.fields.values()
        if field.native_name is not None
    }


@pytest.fixture(scope="session")
def active_option_names(
    active_option_fields: dict[str, FieldRule],
) -> frozenset[str]:
    """Return native CURLOPT names declared by typed SetOption fields."""
    return frozenset(active_option_fields)
