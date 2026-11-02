"""Tests for the LLVM coverage helpers used by direct CTest checks."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from coverage_test_support import (
    export_document,
    function_counts,
    merge_profiles,
    run_profiled_binary,
)


def _write_executable(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o755)


def test_profiled_run_and_merge_preserve_all_profiles(tmp_path: Path) -> None:
    argument_log = tmp_path / "target-arguments.json"
    target = tmp_path / "instrumented-target"
    _write_executable(
        target,
        f"""import json
import os
import sys
from pathlib import Path

profile = os.environ["LLVM_PROFILE_FILE"]
profile = profile.replace("%m", "module").replace("%p", str(os.getpid()))
Path(profile).write_bytes(b"first")
Path(profile.replace(".profraw", "-extra.profraw")).write_bytes(b"second")
Path({str(argument_log)!r}).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
""",
    )
    seed = tmp_path / "seed"
    seed.write_bytes(b"seed")
    profiles = run_profiled_binary(
        target,
        [seed],
        tmp_path / "profiles",
        "run",
        timeout=5,
        capture_output=True,
    )

    assert json.loads(argument_log.read_text(encoding="utf-8")) == [str(seed)]
    assert [profile.read_bytes() for profile in profiles] == [b"second", b"first"]

    merge_log = tmp_path / "merge-arguments.json"
    llvm_profdata = tmp_path / "llvm-profdata"
    _write_executable(
        llvm_profdata,
        f"""import json
import sys
from pathlib import Path

Path({str(merge_log)!r}).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
output = Path(sys.argv[sys.argv.index("-o") + 1])
output.write_bytes(b"merged")
""",
    )
    output = tmp_path / "run.profdata"

    assert merge_profiles(llvm_profdata, profiles, output) == output
    assert output.read_bytes() == b"merged"
    assert json.loads(merge_log.read_text(encoding="utf-8")) == [
        "merge",
        "-sparse",
        *map(str, profiles),
        "-o",
        str(output),
    ]


def test_profiled_run_rejects_missing_and_empty_profiles(tmp_path: Path) -> None:
    no_profile = tmp_path / "no-profile"
    _write_executable(no_profile, "pass\n")
    with pytest.raises(
        SystemExit, match="run emitted no nonempty raw coverage profile"
    ):
        run_profiled_binary(no_profile, [], tmp_path / "missing", "run")

    empty_profile = tmp_path / "empty-profile"
    _write_executable(
        empty_profile,
        """import os
from pathlib import Path

profile = os.environ["LLVM_PROFILE_FILE"].replace("%m", "module").replace("%p", "1")
Path(profile).write_bytes(b"")
""",
    )
    with pytest.raises(
        SystemExit, match="run emitted no nonempty raw coverage profile"
    ):
        run_profiled_binary(
            empty_profile,
            [],
            tmp_path / "empty",
            "run",
        )


def test_profiled_run_reports_captured_failure_output(tmp_path: Path) -> None:
    target = tmp_path / "failed-target"
    _write_executable(
        target,
        """import sys

print("stdout marker")
print("stderr marker", file=sys.stderr)
raise SystemExit(17)
""",
    )

    with pytest.raises(SystemExit) as raised:
        run_profiled_binary(
            target,
            [],
            tmp_path / "profiles",
            "profile",
            run_name="named run",
            capture_output=True,
        )

    message = str(raised.value)
    assert "named run exited with status 17" in message
    assert "stdout marker" in message
    assert "stderr marker" in message


def test_export_document_passes_sources_and_validates_json(tmp_path: Path) -> None:
    argument_log = tmp_path / "cov-arguments.json"
    llvm_cov = tmp_path / "llvm-cov"
    document = {"data": [{"functions": []}]}
    _write_executable(
        llvm_cov,
        f"""import json
import sys
from pathlib import Path

Path({str(argument_log)!r}).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
print({json.dumps(document)!r})
""",
    )
    binary = tmp_path / "binary"
    profdata = tmp_path / "run.profdata"
    sources = [tmp_path / "one.c", tmp_path / "two.c"]

    assert export_document(llvm_cov, binary, profdata, sources) == document
    assert json.loads(argument_log.read_text(encoding="utf-8")) == [
        "export",
        str(binary),
        f"-instr-profile={profdata}",
        "--sources",
        *map(str, sources),
    ]

    _write_executable(llvm_cov, 'print("[]")\n')
    with pytest.raises(SystemExit, match="did not produce an object"):
        export_document(llvm_cov, binary, profdata, sources)

    _write_executable(llvm_cov, "raise SystemExit(9)\n")
    with pytest.raises(subprocess.CalledProcessError):
        export_document(llvm_cov, binary, profdata, sources)


def test_function_counts_normalizes_names_and_keeps_maximum() -> None:
    document: dict[str, object] = {
        "data": [
            None,
            {
                "functions": [
                    "malformed",
                    {"name": "source.c:helper", "count": 2},
                    {"name": "source.c:helper", "count": 7},
                    {"name": "other", "count": "not an integer"},
                    {"name": 12, "count": 4},
                    {"name": "boolean", "count": True},
                    {"name": "negative", "count": -1},
                ]
            },
        ]
    }

    assert function_counts(
        document,
        name_normalizer=lambda name: (
            name.rsplit(":", maxsplit=1)[-1] if isinstance(name, str) else None
        ),
    ) == {"helper": 7}
