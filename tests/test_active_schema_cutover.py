"""End-to-end checks for the schema-owned eligibility cutover."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from curl_fuzzer_tools.schema_eligibility import load_schema_model, project_profile

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "schema_eligibility"
BASELINE_REVISION = "f76d561e063fc80c1c30dde789f85adf7b57a1e3"
OLD_DESCRIPTOR_SHA256 = (
    "a611fcf2b53e596c09bc25482198d492a79bb5ab3ae0ec4fd77bacb064a9981e"
)


def _active_descriptor(tmp_path: Path) -> bytes:
    output = tmp_path / "active.pb"
    subprocess.run(
        [
            "protoc",
            f"--proto_path={SCHEMA_DIR}",
            "--include_imports",
            "--include_source_info",
            f"--descriptor_set_out={output}",
            "curl_fuzzer.proto",
        ],
        check=True,
    )
    return output.read_bytes()


def _profile_name(slug: str) -> str:
    return "TARGET_PROFILE_" + slug.upper()


def _projected_structured_paths(projection: object) -> set[str]:
    descriptor_set = descriptor_pb2.FileDescriptorSet.FromString(
        projection.descriptor_bytes
    )
    messages = {
        f"{file_proto.package}.{message.name}": message
        for file_proto in descriptor_set.file
        for message in file_proto.message_type
    }
    root = messages[projection.root_message]
    paths: set[str] = set()

    def visit(
        message: descriptor_pb2.DescriptorProto,
        prefix: str,
        active: tuple[str, ...],
    ) -> None:
        for field in message.field:
            if not prefix and field.name == "options":
                continue
            path = f"{prefix}.{field.name}" if prefix else field.name
            paths.add(path)
            if field.type != descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE:
                continue
            type_name = field.type_name.removeprefix(".")
            if type_name not in active:
                visit(messages[type_name], path, (*active, type_name))

    visit(root, "", (projection.root_message,))
    return paths


def _compile_generated_schemas(
    tmp_path: Path, schemas: dict[str, str], output_name: str
) -> None:
    root = tmp_path / output_name
    names: list[str] = []
    for name, contents in schemas.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        names.append(name)
    subprocess.run(
        [
            "protoc",
            f"--proto_path={root}",
            f"--descriptor_set_out={tmp_path / (output_name + '.pb')}",
            *names,
        ],
        check=True,
    )


def test_active_schema_matches_baselines_and_projects_all_profiles(
    tmp_path: Path,
) -> None:
    model = load_schema_model(_active_descriptor(tmp_path))
    options = json.loads(
        (FIXTURE_DIR / "baseline_option_eligibility.json").read_text(encoding="utf-8")
    )
    influence = json.loads(
        (FIXTURE_DIR / "derived_field_input_influence.json").read_text(encoding="utf-8")
    )

    assert options["baseline_revision"] == BASELINE_REVISION
    assert options["old_descriptor_sha256"] == OLD_DESCRIPTOR_SHA256
    assert influence["baseline_revision"] == BASELINE_REVISION
    assert influence["old_descriptor_sha256"] == OLD_DESCRIPTOR_SHA256

    expected_profiles = {_profile_name(profile) for profile in options["profiles"]}
    assert set(model.profiles) == expected_profiles

    kind_by_type = {
        descriptor_pb2.FieldDescriptorProto.TYPE_BYTES: "bytes",
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT64: "uint64",
        descriptor_pb2.FieldDescriptorProto.TYPE_BOOL: "bool",
    }
    typed_options = {
        field.native_name: field
        for field in model.fields.values()
        if field.native_name is not None
    }
    baseline_options = {option["name"] for option in options["options"]}
    assert set(typed_options) == baseline_options | {"CURLOPT_MAX_SEND_SPEED_LARGE"}
    for tag, option in enumerate(options["options"], 1):
        field = typed_options[option["name"]]
        assert field.number == tag
        assert kind_by_type[field.proto_type] == option["kind"]
        expected_profiles = {_profile_name(profile) for profile in option["profiles"]}
        if option["name"] == "CURLOPT_ECH":
            # The resolver's DoH HTTPS-RR lane deliberately extends the
            # pre-cutover baseline so TLS can observe a pending ECH record.
            expected_profiles.add("TARGET_PROFILE_RESOLVER")
        assert field.eligibility.profiles == expected_profiles

    max_send_speed = typed_options["CURLOPT_MAX_SEND_SPEED_LARGE"]
    assert max_send_speed.number == 106
    assert kind_by_type[max_send_speed.proto_type] == "uint64"
    assert max_send_speed.eligibility.profiles == {"TARGET_PROFILE_FAST_FILE"}

    ech = typed_options["CURLOPT_ECH"]
    assert [
        (guard.fact, guard.expected, guard.profiles) for guard in ech.eligibility.guards
    ] == [
        (
            "SELECTOR_FACT_RESOLVER_USES_DOH",
            True,
            frozenset({"TARGET_PROFILE_RESOLVER"}),
        )
    ]

    projections = {
        profile: project_profile(model, profile) for profile in sorted(model.profiles)
    }
    for slug, body in influence["profiles"].items():
        projection = projections[_profile_name(slug)]
        expected_fields = set(body["input_fields"])
        # Semantic protocol probes, mail recv-buffer pressure, and FILE's
        # harness-owned anonymous source are deliberate post-cutover changes.
        # Keep the historical fixture frozen and spell out only these reviewed
        # deltas here.
        if slug in {"compatibility", "fast_pop3"}:
            expected_fields.add("pop3_starttls_filter_allocation_failure")
        if slug in {"compatibility", "fast_gopher"}:
            expected_fields.add("gopher_probe_mode")
        if slug in {"fast_imap", "fast_pop3"}:
            expected_fields.update(
                {
                    "connection.backpressure",
                    "connection.backpressure.recv_buf_bytes",
                }
            )
        if slug == "fast_file":
            expected_fields.discard("host_path")
            expected_fields.add("file_source")
        assert _projected_structured_paths(projection) == expected_fields

    profile_schemas = {
        name: contents
        for projection in projections.values()
        for name, contents in projection.schema_files.items()
    }
    _compile_generated_schemas(tmp_path, profile_schemas, "profiles")
    first = next(iter(projections.values()))
    _compile_generated_schemas(
        tmp_path, dict(first.authoring_schema_files), "authoring"
    )
    _compile_generated_schemas(tmp_path, dict(first.runtime_schema_files), "runtime")


def test_active_schema_keeps_selector_regressions_explicit(tmp_path: Path) -> None:
    model = load_schema_model(_active_descriptor(tmp_path))

    used_guard_facts = {
        guard.fact
        for field in model.fields.values()
        for eligibility in (
            field.eligibility,
            *field.contextual_eligibility.values(),
        )
        for guard in eligibility.guards
    }
    assert used_guard_facts == {
        "SELECTOR_FACT_IMPLICIT_FTPS",
        "SELECTOR_FACT_RESOLVER_USES_DOH",
        "SELECTOR_FACT_TIMING_WEBSOCKET",
        "SELECTOR_FACT_HTTP3_CONNECT_UDP_PROXY",
        "SELECTOR_FACT_HTTP2_PLAN_PRESENT",
        "SELECTOR_FACT_H2_PROXY_HTTP2",
        "SELECTOR_FACT_IMPLICIT_LDAPS",
        "SELECTOR_FACT_RESOLVER_DEFAULT_MODE",
        "SELECTOR_FACT_RESOLVER_ACCEPTS_DOH_CONTROL",
        "SELECTOR_FACT_DEEP_HTTP_CONNECT_PROXY",
        "SELECTOR_FACT_DEEP_HTTP_DEFAULT_SOCKET_ROUTE",
        "SELECTOR_FACT_DEEP_HTTP_REWRITE_FILES_ALLOWED",
        "SELECTOR_FACT_API_MULTI_DRIVE",
        "SELECTOR_FACT_API_VALID_MIME_REPEAT",
    }

    scheme = model.fields["curl.fuzzer.proto.Scenario.scheme"]
    assert scheme.eligibility.profiles == {
        "TARGET_PROFILE_COMPATIBILITY",
        "TARGET_PROFILE_FAST_FTP",
        "TARGET_PROFILE_FAST_SMTP",
        "TARGET_PROFILE_FAST_IMAP",
        "TARGET_PROFILE_FAST_POP3",
        "TARGET_PROFILE_FAST_MQTT",
        "TARGET_PROFILE_FAST_GOPHER",
        "TARGET_PROFILE_FAST_LDAP",
        "TARGET_PROFILE_FAST_IPFS",
        "TARGET_PROFILE_TIMING",
    }
    primary_backpressure = model.fields["curl.fuzzer.proto.Connection.backpressure"]
    assert "TARGET_PROFILE_DEEP_HTTP" not in primary_backpressure.eligibility.profiles
    assert "TARGET_PROFILE_RESOLVER" not in primary_backpressure.eligibility.profiles
    assert primary_backpressure.contextual_eligibility["primary"].profiles == {
        "TARGET_PROFILE_FAST_HTTP3",
        "TARGET_PROFILE_FAST_IMAP",
        "TARGET_PROFILE_FAST_POP3",
    }
    recv_buffer = model.fields["curl.fuzzer.proto.BackpressureConfig.recv_buf_bytes"]
    assert {
        "TARGET_PROFILE_FAST_IMAP",
        "TARGET_PROFILE_FAST_POP3",
    } <= recv_buffer.eligibility.profiles
    drain_limit = model.fields["curl.fuzzer.proto.BackpressureConfig.drain_limit"]
    assert "TARGET_PROFILE_FAST_IMAP" not in drain_limit.eligibility.profiles
    assert "TARGET_PROFILE_FAST_POP3" not in drain_limit.eligibility.profiles

    gopher_probe = model.fields["curl.fuzzer.proto.Scenario.gopher_probe_mode"]
    assert gopher_probe.eligibility.profiles == {
        "TARGET_PROFILE_COMPATIBILITY",
        "TARGET_PROFILE_FAST_GOPHER",
    }

    settings_ack = model.fields["curl.fuzzer.proto.Http2Settings.ack"]
    assert settings_ack.eligibility.profiles == {"TARGET_PROFILE_COMPATIBILITY"}
    assert settings_ack.contextual_eligibility["action"].profiles == {
        "TARGET_PROFILE_HTTPS_H2",
        "TARGET_PROFILE_FAST_HTTP2",
        "TARGET_PROFILE_RESOLVER",
    }


def test_authoring_wire_bytes_parse_directly_as_a_restricted_profile(
    tmp_path: Path,
) -> None:
    """Plain protoc output is a valid profile input; no envelope is needed."""
    model = load_schema_model(_active_descriptor(tmp_path))
    projection = project_profile(model, "fast_http")

    authoring_set = descriptor_pb2.FileDescriptorSet.FromString(
        projection.authoring_descriptor_bytes
    )
    authoring_pool = descriptor_pool.DescriptorPool()
    for file_proto in authoring_set.file:
        authoring_pool.AddSerializedFile(file_proto.SerializeToString())
    authoring_class = message_factory.GetMessageClass(
        authoring_pool.FindMessageTypeByName("curl.fuzzer.proto.Scenario")
    )

    profile_set = descriptor_pb2.FileDescriptorSet.FromString(
        projection.descriptor_bytes
    )
    profile_pool = descriptor_pool.DescriptorPool()
    for file_proto in profile_set.file:
        profile_pool.AddSerializedFile(file_proto.SerializeToString())
    profile_class = message_factory.GetMessageClass(
        profile_pool.FindMessageTypeByName(projection.root_message)
    )

    authoring = authoring_class()
    authoring.host_path = b"plain-protoc.test/path"
    authoring.options.add().useragent = b"kept"
    authoring.options.add().tftp_blksize = 512

    profile = profile_class()
    profile.ParseFromString(authoring.SerializeToString(deterministic=True))

    assert profile.host_path == b"plain-protoc.test/path"
    assert len(profile.options) == 2
    assert profile.options[0].WhichOneof("setting") == "useragent"
    assert profile.options[0].useragent == b"kept"
    # The excluded option retains only unknown wire data inside an otherwise
    # known repeated SetOption. The generated postprocessor discards unknowns,
    # and fast_http's EMPTY_OPTION_POLICY_DISCARD then omits this empty entry
    # while lowering.
    assert profile.options[1].WhichOneof("setting") is None
    profile.DiscardUnknownFields()
    assert profile.options[1].WhichOneof("setting") is None


def test_every_checked_in_textproto_encodes_with_plain_protoc(tmp_path: Path) -> None:
    model = load_schema_model(_active_descriptor(tmp_path))
    projection = project_profile(model, "compatibility")
    schema_root = tmp_path / "authoring-seed-schema"
    for name, contents in projection.authoring_schema_files.items():
        path = schema_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    scenarios = sorted(
        (REPO_ROOT / "scenarios" / "curl_fuzzer_proto").rglob("*.textproto")
    )
    assert scenarios
    for scenario in scenarios:
        result = subprocess.run(
            [
                "protoc",
                f"--proto_path={schema_root}",
                "--encode=curl.fuzzer.proto.Scenario",
                "curl_fuzzer.proto",
            ],
            input=scenario.read_bytes(),
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, (
            f"{scenario.relative_to(REPO_ROOT)}:\n"
            f"{result.stderr.decode(errors='replace')}"
        )


def test_ossfuzz_isolates_schema_generator_dependencies() -> None:
    build_script = (REPO_ROOT / "ossfuzz.sh").read_text(encoding="utf-8")
    dependency_script = (REPO_ROOT / "scripts" / "ossfuzzdeps.sh").read_text(
        encoding="utf-8"
    )
    cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

    venv = "CURL_FUZZER_PYTHON_VENV:-/opt/curl-fuzzer-python"
    build_environment = 'UV_PROJECT_ENVIRONMENT="${PYTHON_VENV}"'
    build_sync = (
        "/usr/local/bin/uv sync --locked --no-dev --no-editable "
        '--project "${BUILD_ROOT}"'
    )
    dependency_sync = 'uv sync --locked --no-dev --no-editable --project "${REPO_ROOT}"'
    installer = '"https://astral.sh/uv/${UV_VERSION}/install.sh"'
    uninstall = "rm -f /usr/local/bin/uv /usr/local/bin/uvx"
    helper = "PROTOBUF_PYTHON_CHECK=${PYTHON_VENV}/bin/check_python_protobuf"
    helper_call = '"${PROTOBUF_PYTHON_CHECK}"'
    dependency_helper = '$SUDO "${PYTHON_VENV}/bin/check_python_protobuf"'
    helper_build = '${HELPER:-} == "True"'
    compile_target = '"${SCRIPTDIR}"/compile_target.sh "${FUZZ_BUILD_TARGET}"'

    assert venv in build_script
    assert venv in dependency_script
    assert build_environment in build_script
    assert build_environment in dependency_script
    assert installer in build_script
    assert installer in dependency_script
    assert uninstall in build_script
    assert build_sync in build_script
    assert dependency_sync in dependency_script
    assert helper in build_script
    assert helper_call in build_script
    assert helper_build in build_script
    assert dependency_helper in dependency_script
    assert "-DPython3_EXECUTABLE:FILEPATH=${CURL_FUZZER_PYTHON}" in build_script
    assert build_script.index(uninstall) < build_script.index(installer)
    assert build_script.index(installer) < build_script.index(build_sync)
    assert dependency_script.index(installer) < dependency_script.index(dependency_sync)
    assert build_script.index(build_sync) < build_script.index(compile_target)

    assert '"${Python3_BIN_DIR}/check_python_protobuf"' in cmake
    assert 'COMMAND "${PROTOBUF_PYTHON_CHECK}"' in cmake
    assert "src/curl_fuzzer_tools/check_python_protobuf.py" not in cmake
    assert "python3 -c" not in build_script
    assert "python3 -m venv" not in build_script
    assert "python3 -m venv" not in dependency_script
    assert "src/curl_fuzzer_tools/check_python_protobuf.py" not in build_script
    assert "src/curl_fuzzer_tools/check_python_protobuf.py" not in dependency_script
    assert " --break-system-packages" not in build_script
    assert " --break-system-packages" not in dependency_script
