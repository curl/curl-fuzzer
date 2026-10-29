"""Unit tests for the self-contained browser decoder generator."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from curl_fuzzer_tools import generate_decoder_html

REPO_ROOT = Path(__file__).resolve().parent.parent
PROTO_SOURCE = """syntax = "proto3";

package curl.fuzzer.proto;

// Exercise HTML raw-text escaping: </script><script id="injected">
message Scenario {
  bytes payload = 1;
}
"""
ANNOTATED_PROTO_SOURCE = PROTO_SOURCE.replace(
    "package curl.fuzzer.proto;\n",
    'package curl.fuzzer.proto;\n\nimport "eligibility_options.proto";\n',
)


def _embedded_json(document: str, element_id: str) -> object:
    match = re.search(
        rf'<script type="application/json" id="{element_id}">(.*?)</script>',
        document,
        flags=re.DOTALL,
    )
    assert match is not None
    return json.loads(match.group(1))


def _fake_node_modules(root: Path) -> Path:
    node_modules = root / "node_modules"
    files = {
        "esbuild/bin/esbuild": "#!/usr/bin/env node\n",
        "long/package.json": '{"name": "long"}\n',
        "long/LICENSE": "Long license <terms>\n",
        "protobufjs/package.json": '{"name": "protobufjs"}\n',
        "protobufjs/LICENSE": "Protobuf license & terms\n",
        "protobufjs/google/LICENSE": "Google definitions license\n",
    }
    for relative_path, contents in files.items():
        path = node_modules / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    return node_modules


def test_browser_bundle_entry_installs_long_and_text_format() -> None:
    entry = generate_decoder_html._BUNDLE_ENTRY.read_text()

    assert 'import Long from "long";' in entry
    assert 'import protobuf from "protobufjs";' in entry
    assert 'import textformat from "protobufjs/ext/textformat.js";' in entry
    assert "protobuf.util.Long = Long;" in entry
    assert "protobuf.configure();" in entry
    assert "textformat.install();" in entry
    assert "globalThis.protobuf = protobuf;" in entry
    assert "http://" not in entry
    assert "https://" not in entry


def test_javascript_dependencies_are_exactly_pinned() -> None:
    package = json.loads((REPO_ROOT / "package.json").read_text())
    dependencies = package["devDependencies"]

    assert set(dependencies) == {"esbuild", "long", "protobufjs"}
    for version in dependencies.values():
        assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)


def test_find_node_modules_accepts_an_explicit_complete_tree(tmp_path: Path) -> None:
    node_modules = _fake_node_modules(tmp_path)

    assert generate_decoder_html.find_node_modules(node_modules) == node_modules


def test_find_node_modules_rejects_an_incomplete_explicit_tree(
    tmp_path: Path,
) -> None:
    node_modules = _fake_node_modules(tmp_path)
    (node_modules / "protobufjs/LICENSE").unlink()

    with pytest.raises(FileNotFoundError, match="does not contain"):
        generate_decoder_html.find_node_modules(node_modules)


def test_find_node_modules_searches_working_directory_ancestors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node_modules = _fake_node_modules(tmp_path)
    working_directory = tmp_path / "one" / "two"
    working_directory.mkdir(parents=True)
    monkeypatch.chdir(working_directory)

    assert generate_decoder_html.find_node_modules(None) == node_modules


def test_find_node_modules_returns_none_when_dependencies_are_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    working_directory = tmp_path / "working"
    working_directory.mkdir()
    module = tmp_path / "installed" / "curl_fuzzer_tools" / "module.py"
    module.parent.mkdir(parents=True)
    module.touch()
    monkeypatch.chdir(working_directory)
    monkeypatch.setattr(generate_decoder_html, "__file__", str(module))

    assert generate_decoder_html.find_node_modules(None) is None


def test_browser_schema_keeps_an_explicit_metadata_free_schema(tmp_path: Path) -> None:
    schema = tmp_path / "curl_fuzzer.proto"
    schema.write_text(PROTO_SOURCE)

    assert generate_decoder_html.load_browser_proto_source(schema) == PROTO_SOURCE


def test_browser_schema_regenerates_annotated_source_even_when_stage_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "schemas" / "curl_fuzzer.proto"
    source.parent.mkdir()
    source.write_text(ANNOTATED_PROTO_SOURCE)
    staged = tmp_path / "build" / "schemas" / "curl_fuzzer.proto"
    staged.parent.mkdir(parents=True)
    staged.write_text("stale staged schema\n")
    monkeypatch.setattr(generate_decoder_html.shutil, "which", lambda _name: "protoc")
    monkeypatch.setattr(
        generate_decoder_html,
        "_generate_authoring_proto_source",
        lambda path, protoc: (
            PROTO_SOURCE
            if (path, protoc) == (source, "protoc")
            else pytest.fail("unexpected generator arguments")
        ),
    )

    assert generate_decoder_html.load_browser_proto_source(source) == PROTO_SOURCE


def test_browser_schema_uses_staged_authoring_view_when_protoc_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "schemas" / "curl_fuzzer.proto"
    source.parent.mkdir()
    source.write_text(ANNOTATED_PROTO_SOURCE)
    staged = tmp_path / "build" / "schemas" / "curl_fuzzer.proto"
    staged.parent.mkdir(parents=True)
    staged.write_text(PROTO_SOURCE)
    monkeypatch.setattr(generate_decoder_html.shutil, "which", lambda _name: None)

    assert generate_decoder_html.load_browser_proto_source(source) == PROTO_SOURCE


@pytest.mark.skipif(shutil.which("protoc") is None, reason="protoc unavailable")
def test_browser_schema_generates_an_authoring_view_without_a_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
    monkeypatch.setattr(
        generate_decoder_html, "_find_staged_authoring_schema", lambda _path: None
    )

    rendered = generate_decoder_html.load_browser_proto_source(source)

    assert 'import "eligibility_options.proto";' not in rendered
    assert "curl.fuzzer.schema" not in rendered
    assert "message SetOption" in rendered
    assert "bytes accept_encoding = 1;" in rendered


def test_browser_schema_reports_missing_protoc_without_a_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = REPO_ROOT / "schemas" / "curl_fuzzer.proto"
    monkeypatch.setattr(
        generate_decoder_html, "_find_staged_authoring_schema", lambda _path: None
    )
    monkeypatch.setattr(generate_decoder_html.shutil, "which", lambda _name: None)

    with pytest.raises(FileNotFoundError, match=r"protoc.*protobuf-compiler"):
        generate_decoder_html.load_browser_proto_source(source)


def test_javascript_bundle_invokes_esbuild_and_escapes_script_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node_modules = _fake_node_modules(tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="before</ScRiPt>after",
            stderr="",
        )

    monkeypatch.setattr(generate_decoder_html.subprocess, "run", fake_run)

    assert generate_decoder_html._javascript_bundle(node_modules) == (
        "before<\\/script>after"
    )
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:3] == [
        "node",
        str(node_modules / "esbuild/bin/esbuild"),
        str(generate_decoder_html._BUNDLE_ENTRY),
    ]
    assert "--bundle" in command
    assert "--platform=browser" in command
    assert kwargs["capture_output"] is True
    assert kwargs["check"] is False
    assert kwargs["text"] is True
    environment = kwargs["env"]
    assert isinstance(environment, dict)
    assert environment["NODE_PATH"] == str(node_modules)


def test_javascript_bundle_reports_missing_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node_modules = _fake_node_modules(tmp_path)

    def missing_node(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(generate_decoder_html.subprocess, "run", missing_node)

    with pytest.raises(RuntimeError, match="node is required"):
        generate_decoder_html._javascript_bundle(node_modules)


def test_javascript_bundle_reports_esbuild_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node_modules = _fake_node_modules(tmp_path)
    failed = subprocess.CompletedProcess(
        args=["node"],
        returncode=1,
        stdout="",
        stderr="could not resolve protobufjs\n",
    )
    monkeypatch.setattr(
        generate_decoder_html.subprocess,
        "run",
        lambda *_args, **_kwargs: failed,
    )

    with pytest.raises(
        RuntimeError,
        match=r"esbuild failed \(1\): could not resolve protobufjs",
    ):
        generate_decoder_html._javascript_bundle(node_modules)


def test_third_party_licenses_are_collected(tmp_path: Path) -> None:
    node_modules = _fake_node_modules(tmp_path)

    assert (
        generate_decoder_html._third_party_licenses(node_modules)
        == """long.js
=======

Long license <terms>

protobuf.js
===========

Protobuf license & terms

Google protobuf definitions
===========================

Google definitions license"""
    )


def test_generate_html_embeds_schema_bundle_and_licenses_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proto_file = tmp_path / "schema" / "curl_fuzzer.proto"
    proto_file.parent.mkdir()
    proto_file.write_text(PROTO_SOURCE)
    node_modules = _fake_node_modules(tmp_path)
    output = tmp_path / "site" / "decoder" / "index.html"
    monkeypatch.setattr(
        generate_decoder_html,
        "_javascript_bundle",
        lambda _node_modules: "globalThis.protobuf = { bundled: true };",
    )

    assert (
        generate_decoder_html.generate_html(output, proto_file, node_modules) == output
    )

    document = output.read_text()
    assert "<title>curl corpus decoder</title>" in document
    assert _embedded_json(document, "proto-source-data") == PROTO_SOURCE
    assert '</script><script id="injected">' not in document
    assert "globalThis.protobuf = { bundled: true };" in document
    assert not re.search(
        r'<script\b[^>]*\bsrc\s*=\s*["\']https?://',
        document,
        flags=re.IGNORECASE,
    )

    assert 'id="typemap-data"' not in document
    assert "Third-party licenses" in document
    assert "Long license &lt;terms&gt;" in document
    assert "Protobuf license &amp; terms" in document
    assert "Google definitions license" in document


def test_generate_html_requires_a_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(generate_decoder_html, "find_proto_file", lambda _path: None)

    with pytest.raises(FileNotFoundError, match="curl_fuzzer.proto was not found"):
        generate_decoder_html.generate_html(tmp_path / "index.html")


def test_generate_html_requires_browser_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proto_file = tmp_path / "curl_fuzzer.proto"
    proto_file.write_text(PROTO_SOURCE)
    monkeypatch.setattr(generate_decoder_html, "find_node_modules", lambda _path: None)

    with pytest.raises(FileNotFoundError, match=r"run `npm ci`"):
        generate_decoder_html.generate_html(tmp_path / "index.html", proto_file)
