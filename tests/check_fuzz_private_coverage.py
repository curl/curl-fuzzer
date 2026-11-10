"""Require each checked-in private-helper seed to reach its intended gaps."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from coverage_test_support import (
    export_document,
    function_counts,
    merge_profiles,
    run_profiled_binary,
)

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
    "hostcheck_patterns": (
        "lib/vtls/hostcheck.c",
        {
            "pmatch",
            "hostmatch",
            "Curl_cert_hostcheck",
        },
    ),
}

COMPLETE_REGION_SEEDS = {"hostcheck_patterns"}


def _short_function_name(name: object) -> str | None:
    """Remove llvm-cov's optional ``source.c:`` prefix for static C code."""
    if not isinstance(name, str):
        return None
    return name.rsplit(":", maxsplit=1)[-1]


def _uncovered_region_count(document: dict[str, object]) -> int | None:
    """Return the first exported file's uncovered-region count."""
    data = document.get("data")
    if not isinstance(data, list):
        return None
    for datum in data:
        if not isinstance(datum, dict):
            continue
        files = datum.get("files")
        if not isinstance(files, list):
            continue
        for file_coverage in files:
            if not isinstance(file_coverage, dict):
                continue
            summary = file_coverage.get("summary")
            if not isinstance(summary, dict):
                continue
            regions = summary.get("regions")
            if not isinstance(regions, dict):
                continue
            uncovered = regions.get("notcovered")
            if isinstance(uncovered, int) and not isinstance(uncovered, bool):
                return uncovered
    return None


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
            control_directory = temporary / f"{seed_name}-control"
            control_profiles = run_profiled_binary(
                binary=args.binary,
                arguments=[selector_only],
                raw_directory=control_directory,
                profile_stem=selector_only.name,
                timeout=10,
                capture_output=True,
            )
            control_profdata = merge_profiles(
                args.llvm_profdata,
                control_profiles,
                control_directory / f"{selector_only.name}.profdata",
            )
            control_counts = function_counts(
                export_document(args.llvm_cov, args.binary, control_profdata, [source]),
                name_normalizer=_short_function_name,
            )
            setup_functions = sorted(
                name for name in required_functions if control_counts.get(name, 0) > 0
            )
            if setup_functions:
                raise SystemExit(
                    f"{relative_source} covered required functions without "
                    "fuzz operations: " + ", ".join(setup_functions)
                )

            seed_directory = temporary / seed_name
            profiles = run_profiled_binary(
                binary=args.binary,
                arguments=[seed],
                raw_directory=seed_directory,
                profile_stem=seed.name,
                timeout=10,
                capture_output=True,
            )
            profdata = merge_profiles(
                args.llvm_profdata,
                profiles,
                seed_directory / f"{seed.name}.profdata",
            )
            coverage = export_document(args.llvm_cov, args.binary, profdata, [source])
            counts = function_counts(
                coverage,
                name_normalizer=_short_function_name,
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
            if seed_name in COMPLETE_REGION_SEEDS:
                uncovered_regions = _uncovered_region_count(coverage)
                if uncovered_regions != 0:
                    raise SystemExit(
                        f"{seed_name} left {relative_source} with "
                        f"{uncovered_regions!r} uncovered regions"
                    )

            summaries.append(
                f"{seed_name}:{relative_source}={len(required_functions)} functions"
            )

    print(", ".join(summaries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
