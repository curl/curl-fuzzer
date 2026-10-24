#!/usr/bin/env python3
"""Require the production queued-resolver seed to cover both curl callbacks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

REQUIRED_FUNCTIONS = {
    "asyn-thrdd.c:async_thrdd_match_item",
    "thrdqueue.c:thrdq_item_list_dtor",
}
REQUIRED_SOURCE_BY_FUNCTION = {
    "asyn-thrdd.c:async_thrdd_match_item": "lib/vdns/asyn-thrdd.c",
    "thrdqueue.c:thrdq_item_list_dtor": "lib/thrdqueue.c",
}
# The measured gap contained the matcher function region plus one region for
# each short-circuit operand, and one destructor function region. Discover the
# coordinates from the built curl so harmless upstream line movement does not
# invalidate the regression, but retain that minimum old-gap shape.
MINIMUM_OLD_GAP_REGIONS = {
    "asyn-thrdd.c:async_thrdd_match_item": 3,
    "thrdqueue.c:thrdq_item_list_dtor": 1,
}


def curl_relative_path(filename: object, source_root: Path) -> str | None:
    if not isinstance(filename, str):
        return None
    try:
        return Path(filename).resolve().relative_to(source_root.resolve()).as_posix()
    except ValueError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--llvm-profdata", type=Path, required=True)
    parser.add_argument("--llvm-cov", type=Path, required=True)
    parser.add_argument("--curl-source", type=Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="resolver-queued-cancel-") as raw_tmp:
        tmp = Path(raw_tmp)
        environment = os.environ.copy()
        environment["LLVM_PROFILE_FILE"] = str(tmp / "resolver-%m-%p.profraw")
        subprocess.run([str(args.binary), str(args.seed)], check=True, env=environment)

        profiles = sorted(tmp.glob("resolver-*.profraw"))
        if not profiles:
            raise SystemExit("queued resolver regression emitted no raw profile")
        profdata = tmp / "resolver.profdata"
        subprocess.run(
            [
                str(args.llvm_profdata),
                "merge",
                "-sparse",
                *map(str, profiles),
                "-o",
                str(profdata),
            ],
            check=True,
        )
        exported = subprocess.run(
            [
                str(args.llvm_cov),
                "export",
                str(args.binary),
                f"-instr-profile={profdata}",
                "--sources",
                str(args.curl_source / "lib/vdns/asyn-thrdd.c"),
                str(args.curl_source / "lib/thrdqueue.c"),
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )

    document = json.loads(exported.stdout)
    counts = {
        function["name"]: function["count"]
        for datum in document.get("data", [])
        for function in datum.get("functions", [])
        if function.get("name") in REQUIRED_FUNCTIONS
    }
    missing = sorted(
        name
        for name in REQUIRED_FUNCTIONS
        if not isinstance(counts.get(name), int) or counts[name] <= 0
    )
    if missing:
        rendered = ", ".join(
            f"{name}={counts.get(name, 'missing')}" for name in missing
        )
        raise SystemExit(f"queued resolver callbacks were not covered: {rendered}")

    observed_regions: set[tuple[str, str, int, int, int, int]] = set()
    covered_regions: set[tuple[str, str, int, int, int, int]] = set()
    for datum in document.get("data", []):
        for function in datum.get("functions", []):
            name = function.get("name")
            filenames = function.get("filenames")
            regions = function.get("regions")
            if name not in REQUIRED_FUNCTIONS or not isinstance(filenames, list):
                continue
            if not isinstance(regions, list):
                continue
            for region in regions:
                if not isinstance(region, list) or len(region) < 6:
                    continue
                coordinates = region[:4]
                count = region[4]
                file_id = region[5]
                kind = region[7] if len(region) >= 8 else 0
                if (
                    not all(isinstance(value, int) for value in coordinates)
                    or not isinstance(count, int)
                    or not isinstance(file_id, int)
                    or file_id < 0
                    or file_id >= len(filenames)
                    or kind != 0
                ):
                    continue
                relative = curl_relative_path(filenames[file_id], args.curl_source)
                if relative != REQUIRED_SOURCE_BY_FUNCTION[name]:
                    continue
                region_key = (relative, name, *coordinates)
                observed_regions.add(region_key)
                if count > 0:
                    covered_regions.add(region_key)

    malformed_shapes = {
        name: len([region for region in observed_regions if region[1] == name])
        for name, minimum in MINIMUM_OLD_GAP_REGIONS.items()
        if len([region for region in observed_regions if region[1] == name]) < minimum
    }
    if malformed_shapes:
        rendered = ", ".join(
            f"{name}={count}<{MINIMUM_OLD_GAP_REGIONS[name]}"
            for name, count in sorted(malformed_shapes.items())
        )
        raise SystemExit(f"queued resolver old-gap region shape changed: {rendered}")

    missing_regions = sorted(observed_regions - covered_regions)
    if missing_regions:
        rendered = ", ".join(
            f"{source}:{start_line}:{start_column}-{end_line}:{end_column}"
            for source, _name, start_line, start_column, end_line, end_column in missing_regions
        )
        raise SystemExit(f"queued resolver old-gap regions were not covered: {rendered}")

    function_summary = ", ".join(
        f"{name}={counts[name]}" for name in sorted(counts)
    )
    print(f"{function_summary}, old_gap_regions={len(covered_regions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
