"""Require each checked-in private-helper seed to reach its intended gaps."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

# Keep the expectation attached to the seed that supplies the input. Each seed
# is paired with a selector-only negative control, so the check rejects target
# functions reached by lane setup or a process-once probe rather than by the
# fuzz-controlled operation stream.
REQUIRED_FUNCTIONS_BY_SEED = {
    "ptrarray_sequence": (
        "lib/ptrarray.c",
        {
            "ptrarray_count",
            "ptrarray_get",
        },
    ),
    "dynhds_sequence": (
        "lib/dynhds.c",
        {
            "dynhds_contains",
            "dynhds_ccontains",
            "dynhds_count_name",
            "dynhds_ccount_name",
            "dynhds_remove",
            "dynhds_set",
            "dynhds_cremove",
        },
    ),
    "uint_spbset_sequence": (
        "lib/uint-spbset.c",
        {
            "uint32_spbset_empty_chunk",
            "uint32_spbset_unlink_empty",
            "uint32_spbset_insert_chunk",
            "uint32_spbset_chunk_first",
        },
    ),
    "memdebug_wrappers": (
        "lib/memdebug.c",
        {
            "curl_dbg_socketpair",
            "curl_dbg_accept",
            "curl_dbg_freopen",
            "curl_dbg_fdopen",
        },
    ),
    "cf_ip_happy_callbacks": (
        "lib/cf-ip-happy.c",
        {
            "cf_ip_ballers_shutdown",
            "cf_ip_ballers_pending",
            "cf_ip_ballers_min_reply_ms",
            "cf_ip_happy_shutdown",
            "cf_ip_happy_data_pending",
        },
    ),
}


def _short_function_name(name: object) -> str | None:
    """Remove llvm-cov's optional ``source.c:`` prefix for static C code."""
    if not isinstance(name, str):
        return None
    return name.rsplit(":", maxsplit=1)[-1]


def _export_document(
    llvm_cov: Path, binary: Path, profdata: Path, source: Path
) -> dict[str, object]:
    exported = subprocess.run(
        [
            str(llvm_cov),
            "export",
            str(binary),
            f"-instr-profile={profdata}",
            "--sources",
            str(source),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    document = json.loads(exported.stdout)
    if not isinstance(document, dict):
        raise SystemExit("llvm-cov export did not produce an object")
    return document


def _function_counts(document: dict[str, object]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for datum in document.get("data", []):
        if not isinstance(datum, dict):
            continue
        for function in datum.get("functions", []):
            if not isinstance(function, dict):
                continue
            name = _short_function_name(function.get("name"))
            count = function.get("count")
            if name is not None and isinstance(count, int):
                counts[name] = max(counts.get(name, 0), count)
    return counts


def _run_seed(
    *,
    binary: Path,
    seed: Path,
    raw_directory: Path,
    llvm_profdata: Path,
) -> Path:
    raw_directory.mkdir()
    environment = os.environ.copy()
    environment["LLVM_PROFILE_FILE"] = str(raw_directory / f"{seed.name}-%m-%p.profraw")
    completed = subprocess.run(
        [str(binary), str(seed)],
        check=False,
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
    )
    if completed.returncode != 0:
        details = "\n".join(
            part for part in (completed.stdout, completed.stderr) if part
        )
        raise SystemExit(
            f"{seed.name} exited with status {completed.returncode}"
            + (f":\n{details}" if details else "")
        )

    profiles = sorted(raw_directory.glob(f"{seed.name}-*.profraw"))
    if not profiles or any(profile.stat().st_size == 0 for profile in profiles):
        raise SystemExit(f"{seed.name} emitted no nonempty raw coverage profile")

    profdata = raw_directory / f"{seed.name}.profdata"
    subprocess.run(
        [
            str(llvm_profdata),
            "merge",
            "-sparse",
            *map(str, profiles),
            "-o",
            str(profdata),
        ],
        check=True,
    )
    return profdata


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--llvm-profdata", type=Path, required=True)
    parser.add_argument("--llvm-cov", type=Path, required=True)
    parser.add_argument("--curl-source", type=Path, required=True)
    args = parser.parse_args()

    missing_inputs = sorted(
        seed_name
        for seed_name in REQUIRED_FUNCTIONS_BY_SEED
        if not (args.corpus / seed_name).is_file()
    )
    if missing_inputs:
        raise SystemExit(
            "missing checked-in fuzz_private seeds: " + ", ".join(missing_inputs)
        )

    summaries: list[str] = []
    with tempfile.TemporaryDirectory(prefix="fuzz-private-coverage-") as raw_tmp:
        temporary = Path(raw_tmp)
        for seed_name, (
            relative_source,
            required_functions,
        ) in REQUIRED_FUNCTIONS_BY_SEED.items():
            seed = args.corpus / seed_name
            source = args.curl_source / relative_source
            if not source.is_file():
                raise SystemExit(f"curl source is missing: {source}")

            seed_bytes = seed.read_bytes()
            if not seed_bytes:
                raise SystemExit(f"checked-in seed is empty: {seed}")
            selector_only = temporary / f"{seed_name}.selector-only"
            selector_only.write_bytes(seed_bytes[:1])
            control_profdata = _run_seed(
                binary=args.binary,
                seed=selector_only,
                raw_directory=temporary / f"{seed_name}-control",
                llvm_profdata=args.llvm_profdata,
            )
            control_counts = _function_counts(
                _export_document(args.llvm_cov, args.binary, control_profdata, source)
            )
            setup_functions = sorted(
                name for name in required_functions if control_counts.get(name, 0) > 0
            )
            if setup_functions:
                raise SystemExit(
                    f"{relative_source} covered required functions without "
                    "fuzz operations: " + ", ".join(setup_functions)
                )

            profdata = _run_seed(
                binary=args.binary,
                seed=seed,
                raw_directory=temporary / seed_name,
                llvm_profdata=args.llvm_profdata,
            )
            counts = _function_counts(
                _export_document(args.llvm_cov, args.binary, profdata, source)
            )
            missing_functions = sorted(
                name for name in required_functions if counts.get(name, 0) <= 0
            )
            if missing_functions:
                rendered = ", ".join(
                    f"{name}={counts.get(name, 'missing')}"
                    for name in missing_functions
                )
                raise SystemExit(
                    f"{seed_name} did not cover required functions in "
                    f"{relative_source}: {rendered}"
                )

            summaries.append(
                f"{seed_name}:{relative_source}={len(required_functions)} functions"
            )

    print(", ".join(summaries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
