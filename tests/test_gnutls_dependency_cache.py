"""Regression tests for GnuTLS dependency cache invalidation."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GNUTLS_DEPENDENCIES = REPO_ROOT / "cmake" / "GnuTLSDependencies.cmake"


def _replace_version(module: str, variable: str, version: str) -> str:
    module, replacements = re.subn(
        rf"set\({re.escape(variable)} [^)]+\)",
        f"set({variable} {version})",
        module,
        count=1,
    )
    assert replacements == 1
    return module


def _cache_names(
    tmp_path: Path, *, gmp_version: str | None = None, nettle_version: str | None = None
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    source_dir = tmp_path / "source"
    build_dir = tmp_path / "build"
    source_dir.mkdir(parents=True)

    module = GNUTLS_DEPENDENCIES.read_text(encoding="utf-8")
    if gmp_version is not None:
        module = _replace_version(module, "GNUTLS_GMP_VERSION", gmp_version)
    if nettle_version is not None:
        module = _replace_version(module, "GNUTLS_NETTLE_VERSION", nettle_version)
    (source_dir / "GnuTLSDependencies.cmake").write_text(module, encoding="utf-8")

    (source_dir / "CMakeLists.txt").write_text(
        """\
cmake_minimum_required(VERSION 3.24)
project(gnutls_cache_identity NONE)
include(${CMAKE_CURRENT_SOURCE_DIR}/GnuTLSDependencies.cmake)

file(WRITE ${CMAKE_BINARY_DIR}/cache-installs.txt "")
foreach(install_dir IN LISTS GNUTLS_CACHE_INSTALL_DIRS)
    get_filename_component(install_name ${install_dir} NAME)
    file(APPEND ${CMAKE_BINARY_DIR}/cache-installs.txt "${install_name}\\n")
endforeach()

file(WRITE ${CMAKE_BINARY_DIR}/cache-prefixes.txt "")
foreach(target IN ITEMS
        gnutls_gmp_external
        gnutls_nettle_external
        gnutls_external)
    get_property(prefix TARGET ${target} PROPERTY _EP_PREFIX)
    get_filename_component(prefix_name ${prefix} NAME)
    file(APPEND ${CMAKE_BINARY_DIR}/cache-prefixes.txt "${prefix_name}\\n")
endforeach()
""",
        encoding="utf-8",
    )

    subprocess.run(
        ["cmake", "-S", str(source_dir), "-B", str(build_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    return (
        tuple(
            (build_dir / "cache-installs.txt").read_text(encoding="utf-8").splitlines()
        ),
        tuple(
            (build_dir / "cache-prefixes.txt").read_text(encoding="utf-8").splitlines()
        ),
    )


def test_transitive_versions_are_part_of_gnutls_cache_identities(
    tmp_path: Path,
) -> None:
    """A restored upper-layer prefix must not survive a dependency bump."""
    baseline = _cache_names(tmp_path / "baseline")
    bumped_gmp = _cache_names(tmp_path / "bumped-gmp", gmp_version="99.1-cache-test")
    bumped_nettle = _cache_names(
        tmp_path / "bumped-nettle", nettle_version="99.2-cache-test"
    )

    for baseline_names, bumped_gmp_names, bumped_nettle_names in zip(
        baseline, bumped_gmp, bumped_nettle, strict=True
    ):
        assert (
            len(baseline_names)
            == len(bumped_gmp_names)
            == len(bumped_nettle_names)
            == 3
        )
        gmp, nettle, gnutls = range(3)

        assert bumped_gmp_names[gmp] != baseline_names[gmp]
        assert bumped_gmp_names[nettle] != baseline_names[nettle]
        assert bumped_gmp_names[gnutls] != baseline_names[gnutls]

        assert bumped_nettle_names[gmp] == baseline_names[gmp]
        assert bumped_nettle_names[nettle] != baseline_names[nettle]
        assert bumped_nettle_names[gnutls] != baseline_names[gnutls]
