"""Descriptor-driven schema eligibility generator tests."""

from __future__ import annotations

import dataclasses
import hashlib
import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import Any

import pytest
from google.protobuf import descriptor_pb2, descriptor_pool

from curl_fuzzer_tools.generate_option_manifest import parse_curl_header
from curl_fuzzer_tools.schema_eligibility import (
    FIELD_EXTENSION,
    OPTION_EXTENSION,
    REGISTRY_EXTENSION,
    SchemaEligibilityError,
    _build_pool,
    _dynamic_descriptor_set,
    load_schema_model,
    project_profile,
    run,
    validate_cpp_target_profiles,
    validate_native_options,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "schema_eligibility"


def _compile_fixture(tmp_path: Path) -> bytes:
    descriptor_set = tmp_path / "fixture.pb"
    subprocess.run(
        [
            "protoc",
            f"--proto_path={FIXTURE_DIR}",
            f"--proto_path={SCHEMA_DIR}",
            "--include_imports",
            f"--descriptor_set_out={descriptor_set}",
            "typed_tftp.proto",
        ],
        check=True,
    )
    return descriptor_set.read_bytes()


def _dynamic(data: bytes) -> tuple[Any, descriptor_pool.DescriptorPool]:
    raw = descriptor_pb2.FileDescriptorSet.FromString(data)
    pool = _build_pool(raw)
    return _dynamic_descriptor_set(data, pool), pool


def _registry(data: bytes) -> tuple[Any, Any]:
    dynamic, pool = _dynamic(data)
    extension = pool.FindExtensionByName(REGISTRY_EXTENSION)
    source = next(file for file in dynamic.file if file.name == "typed_tftp.proto")
    return dynamic, source.options.Extensions[extension]


def test_active_schema_has_no_nested_message_or_enum_declarations(
    tmp_path: Path,
) -> None:
    descriptor_set = tmp_path / "active.pb"
    subprocess.run(
        [
            "protoc",
            f"--proto_path={SCHEMA_DIR}",
            f"--descriptor_set_out={descriptor_set}",
            "curl_fuzzer.proto",
        ],
        check=True,
    )
    active = descriptor_pb2.FileDescriptorSet.FromString(descriptor_set.read_bytes())
    nested = [
        message.name
        for file_proto in active.file
        for message in file_proto.message_type
        if message.nested_type or message.enum_type
    ]
    assert nested == []


def test_loads_complete_registry_and_typed_metadata(tmp_path: Path) -> None:
    data = _compile_fixture(tmp_path)
    model = load_schema_model(data)

    assert len(model.profiles) == 28
    blksize = model.fields["curl.fuzzer.test.SetOption.tftp_blksize"]
    assert blksize.native_name == "CURLOPT_TFTP_BLKSIZE"
    assert blksize.eligibility.profiles >= {
        "TARGET_PROFILE_FAST_FTP",
        "TARGET_PROFILE_FAST_TFTP",
    }
    host_path = model.fields["curl.fuzzer.test.Scenario.host_path"]
    assert host_path.eligibility.guards[0].fact == "SELECTOR_FACT_IMPLICIT_FTPS"
    mixed = model.fields["curl.fuzzer.test.SharedState.mixed_membership"]
    assert mixed.eligibility.profiles == {
        "TARGET_PROFILE_COMPATIBILITY",
        "TARGET_PROFILE_TIMING",
    }
    assert mixed.contextual_eligibility["primary"].profiles == {
        "TARGET_PROFILE_DEEP_HTTP",
        "TARGET_PROFILE_FAST_HTTP3",
        "TARGET_PROFILE_FAST_TFTP",
        "TARGET_PROFILE_RESOLVER",
    }
    assert model.profiles["TARGET_PROFILE_FAST_TFTP"].cpp_target_profile == "kFastTftp"


def test_closed_selector_fact_vocabulary_has_runtime_predicates(tmp_path: Path) -> None:
    _, pool = _dynamic(_compile_fixture(tmp_path))
    selector_facts = pool.FindEnumTypeByName("curl.fuzzer.schema.SelectorFact")
    assert {value.name for value in selector_facts.values} == {
        "SELECTOR_FACT_UNSPECIFIED",
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


def test_projects_deterministic_metadata_free_tftp_descriptor(tmp_path: Path) -> None:
    data = _compile_fixture(tmp_path)
    model = load_schema_model(data)
    first = project_profile(model, "FAST_TFTP")
    second = project_profile(model, "TARGET_PROFILE_FAST_TFTP")

    assert first.descriptor_bytes == second.descriptor_bytes
    assert first.report_json() == second.report_json()
    assert first.report["input_descriptor_sha256"] == hashlib.sha256(data).hexdigest()
    assert first.report["retained_options"] == [
        "CURLOPT_RANGE",
        "CURLOPT_TFTP_BLKSIZE",
        "CURLOPT_TFTP_NO_OPTIONS",
    ]
    assert first.root_message == ("curl.fuzzer.generated.fast_tftp.FastTftpScenario")
    assert first.descriptor_sha256 == first.report["output_hashes"]["descriptor_sha256"]
    assert (
        first.adapter_sha256 == first.report["output_hashes"]["adapter_header_sha256"]
    )
    assert (
        first.runtime_descriptor_sha256
        == first.report["output_hashes"]["runtime_descriptor_sha256"]
    )
    assert (
        first.authoring_descriptor_sha256
        == first.report["output_hashes"]["authoring_descriptor_sha256"]
    )
    assert first.report_sha256 == second.report_sha256

    projected = descriptor_pb2.FileDescriptorSet.FromString(first.descriptor_bytes)
    assert [file.name for file in projected.file] == [
        "generated/fast_tftp/fast_tftp.proto"
    ]
    assert list(projected.file[0].dependency) == []

    pool = descriptor_pool.DescriptorPool()
    for file_proto in projected.file:
        pool.AddSerializedFile(file_proto.SerializeToString())
    root = pool.FindMessageTypeByName(first.root_message)
    assert [field.name for field in root.fields] == [
        "options",
        "connection",
        "host_path",
        "scheme",
        "primary_state",
        "secondary_state",
        "primary_state_again",
        "recursive",
        "choice_payload",
    ]
    set_option = pool.FindMessageTypeByName("curl.fuzzer.generated.fast_tftp.SetOption")
    assert [field.name for field in set_option.fields] == [
        "tftp_blksize",
        "tftp_no_options",
        "range",
    ]
    connection = pool.FindMessageTypeByName(
        "curl.fuzzer.generated.fast_tftp.Connection"
    )
    assert [field.name for field in connection.fields] == ["initial_response"]
    primary = root.fields_by_name["primary_state"].message_type
    secondary = root.fields_by_name["secondary_state"].message_type
    primary_again = root.fields_by_name["primary_state_again"].message_type
    assert primary.full_name != secondary.full_name
    assert primary.full_name == primary_again.full_name
    assert [field.name for field in primary.fields] == [
        "common",
        "primary_only",
        "mixed_membership",
    ]
    assert [field.name for field in secondary.fields] == [
        "common",
        "secondary_only",
    ]
    assert "secondary_only" not in primary.fields_by_name
    assert "primary_only" not in secondary.fields_by_name
    recursive = root.fields_by_name["recursive"].message_type
    assert (
        recursive.fields_by_name["child"].message_type.full_name == recursive.full_name
    )

    authoring = descriptor_pb2.FileDescriptorSet.FromString(
        first.authoring_descriptor_bytes
    )
    assert [file.name for file in authoring.file] == ["typed_tftp.proto"]
    assert list(authoring.file[0].dependency) == []
    authoring_source = first.authoring_schema_files["typed_tftp.proto"]
    assert "eligibility_options.proto" not in authoring_source
    assert "curl.fuzzer.schema" not in authoring_source
    authoring_pool = descriptor_pool.DescriptorPool()
    authoring_pool.AddSerializedFile(authoring.file[0].SerializeToString())
    authoring_root = authoring_pool.FindMessageTypeByName("curl.fuzzer.test.Scenario")
    assert authoring_root.full_name == "curl.fuzzer.test.Scenario"


def test_contextual_membership_is_profile_specific_without_shape_leakage(
    tmp_path: Path,
) -> None:
    model = load_schema_model(_compile_fixture(tmp_path))

    compatibility = project_profile(model, "COMPATIBILITY")
    compatibility_pool = descriptor_pool.DescriptorPool()
    compatibility_set = descriptor_pb2.FileDescriptorSet.FromString(
        compatibility.descriptor_bytes
    )
    compatibility_pool.AddSerializedFile(compatibility_set.file[0].SerializeToString())
    compatibility_root = compatibility_pool.FindMessageTypeByName(
        compatibility.root_message
    )
    compatibility_primary = compatibility_root.fields_by_name[
        "primary_state"
    ].message_type
    compatibility_secondary = compatibility_root.fields_by_name[
        "secondary_state"
    ].message_type
    assert compatibility_primary.full_name == compatibility_secondary.full_name
    assert [field.name for field in compatibility_primary.fields] == [
        "common",
        "mixed_membership",
    ]

    deep_http = project_profile(model, "DEEP_HTTP")
    deep_http_pool = descriptor_pool.DescriptorPool()
    deep_http_set = descriptor_pb2.FileDescriptorSet.FromString(
        deep_http.descriptor_bytes
    )
    deep_http_pool.AddSerializedFile(deep_http_set.file[0].SerializeToString())
    deep_http_root = deep_http_pool.FindMessageTypeByName(deep_http.root_message)
    deep_http_primary = deep_http_root.fields_by_name["primary_state"].message_type
    deep_http_secondary = deep_http_root.fields_by_name["secondary_state"].message_type
    assert deep_http_primary.full_name != deep_http_secondary.full_name
    assert [field.name for field in deep_http_primary.fields] == [
        "common",
        "mixed_membership",
    ]
    assert [field.name for field in deep_http_secondary.fields] == ["common"]


def test_rejects_duplicate_contextual_eligibility(tmp_path: Path) -> None:
    data = _compile_fixture(tmp_path)
    dynamic, pool = _dynamic(data)
    field_extension = pool.FindExtensionByName(FIELD_EXTENSION)
    source = next(file for file in dynamic.file if file.name == "typed_tftp.proto")
    shared = next(
        message for message in source.message_type if message.name == "SharedState"
    )
    mixed = next(field for field in shared.field if field.name == "mixed_membership")
    metadata = mixed.options.Extensions[field_extension]
    duplicate = metadata.contextual_eligibility.add()
    duplicate.CopyFrom(metadata.contextual_eligibility[0])
    with pytest.raises(SchemaEligibilityError, match="repeats projection context"):
        load_schema_model(dynamic.SerializeToString(deterministic=True))


def test_rejects_guard_when_selector_input_is_missing(tmp_path: Path) -> None:
    data = _compile_fixture(tmp_path)
    dynamic, pool = _dynamic(data)
    field_extension = pool.FindExtensionByName(FIELD_EXTENSION)
    source = next(file for file in dynamic.file if file.name == "typed_tftp.proto")
    scenario = next(
        message for message in source.message_type if message.name == "Scenario"
    )
    scheme = next(field for field in scenario.field if field.name == "scheme")
    eligibility = scheme.options.Extensions[field_extension].eligibility
    tftp = (
        pool.FindEnumTypeByName("curl.fuzzer.schema.TargetProfile")
        .values_by_name["TARGET_PROFILE_FAST_TFTP"]
        .number
    )
    eligibility.profiles.remove(tftp)

    with pytest.raises(
        SchemaEligibilityError,
        match=(
            "SELECTOR_FACT_IMPLICIT_FTPS applies to TARGET_PROFILE_FAST_TFTP, "
            "but selector input scheme is absent"
        ),
    ):
        load_schema_model(dynamic.SerializeToString(deterministic=True))


def test_authoring_profile_and_runtime_descriptors_coexist(tmp_path: Path) -> None:
    data = _compile_fixture(tmp_path)
    projection = project_profile(load_schema_model(data), "FAST_TFTP")
    authoring = descriptor_pb2.FileDescriptorSet.FromString(data)
    projected = descriptor_pb2.FileDescriptorSet.FromString(projection.descriptor_bytes)
    runtime = descriptor_pb2.FileDescriptorSet.FromString(
        projection.runtime_descriptor_bytes
    )

    pool = descriptor_pool.DescriptorPool()
    for descriptor_set in (authoring, projected, runtime):
        for file_proto in descriptor_set.file:
            pool.AddSerializedFile(file_proto.SerializeToString())

    assert pool.FindMessageTypeByName("curl.fuzzer.test.Scenario")
    generated = pool.FindMessageTypeByName(projection.root_message)
    assert generated.full_name == projection.root_message
    runtime_root = pool.FindMessageTypeByName("curl.fuzzer.proto.Scenario")
    assert runtime_root.full_name == "curl.fuzzer.proto.Scenario"
    scheme = generated.fields_by_name["scheme"]
    assert scheme.enum_type.full_name == "curl.fuzzer.generated.fast_tftp.Scheme"

    runtime_option = pool.FindMessageTypeByName("curl.fuzzer.proto.SetOption")
    assert [field.name for field in runtime_option.fields] == [
        "option_id",
        "string_value",
        "uint_value",
        "bool_value",
    ]
    runtime_ids = pool.FindEnumTypeByName("curl.fuzzer.proto.CurlOptionId")
    assert [value.name for value in runtime_ids.values] == [
        "CURL_OPTION_UNSPECIFIED",
        "CURLOPT_TFTP_BLKSIZE",
        "CURLOPT_TFTP_NO_OPTIONS",
        "CURLOPT_USERAGENT",
        "CURLOPT_RANGE",
    ]
    assert "OptionValueKind::kString" in projection.native_manifest
    assert "CURLOPT_RANGE" in projection.native_manifest
    assert "LookupOptionDescriptor(" in projection.native_manifest
    assert "return &kOptionManifest[0];" in projection.native_manifest
    assert "return nullptr;" in projection.native_manifest


def test_cli_writes_projected_descriptor_and_report(tmp_path: Path) -> None:
    descriptor = tmp_path / "fixture.pb"
    descriptor.write_bytes(_compile_fixture(tmp_path))
    projected = tmp_path / "projected.pb"
    report = tmp_path / "report.json"

    assert (
        run(
            [
                "--descriptor-set",
                str(descriptor),
                "--curl-header",
                str(FIXTURE_DIR / "curl.h"),
                "--target-profile-header",
                str(REPO_ROOT / "proto_fuzzer" / "target_profile.h"),
                "--profile",
                "FAST_TFTP",
                "--projected-descriptor-out",
                str(projected),
                "--report-out",
                str(report),
            ]
        )
        == 0
    )
    assert projected.is_file()
    assert report.is_file()


def test_cpp_profile_identity_is_required_and_unique(tmp_path: Path) -> None:
    model = load_schema_model(_compile_fixture(tmp_path))
    validate_cpp_target_profiles(model, REPO_ROOT / "proto_fuzzer" / "target_profile.h")

    dynamic, registry = _registry(_compile_fixture(tmp_path))
    registry.profiles[0].cpp_target_profile = ""
    with pytest.raises(SchemaEligibilityError, match="invalid C\\+\\+ TargetProfile"):
        load_schema_model(dynamic.SerializeToString(deterministic=True))

    dynamic, registry = _registry(_compile_fixture(tmp_path))
    registry.profiles[1].cpp_target_profile = registry.profiles[0].cpp_target_profile
    with pytest.raises(SchemaEligibilityError, match="mapped more than once"):
        load_schema_model(dynamic.SerializeToString(deterministic=True))

    dynamic, registry = _registry(_compile_fixture(tmp_path))
    registry.profiles[0].cpp_target_profile = "kNotARealProfile"
    wrong = load_schema_model(dynamic.SerializeToString(deterministic=True))
    with pytest.raises(SchemaEligibilityError, match="registry mismatch"):
        validate_cpp_target_profiles(
            wrong, REPO_ROOT / "proto_fuzzer" / "target_profile.h"
        )


def test_generated_cpp_adapter_round_trips_typed_values(tmp_path: Path) -> None:
    if shutil.which("c++") is None or shutil.which("protoc") is None:
        pytest.skip("C++ compiler and protoc are required")

    data = _compile_fixture(tmp_path)
    model = load_schema_model(data)
    projection = project_profile(model, "FAST_TFTP")
    compatibility = project_profile(model, "COMPATIBILITY")
    for generated in (projection, compatibility):
        for name, content in generated.schema_files.items():
            output = tmp_path / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content)
    for name, content in projection.runtime_schema_files.items():
        output = tmp_path / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content)
    (tmp_path / "curl_fuzzer_option_manifest.inc").write_text(
        projection.native_manifest
    )
    adapter = tmp_path / "generated" / "fast_tftp" / "fast_tftp_traits.h"
    adapter.write_text(projection.adapter_header)
    compatibility_adapter = (
        tmp_path / "generated" / "compatibility" / "compatibility_traits.h"
    )
    compatibility_adapter.write_text(compatibility.adapter_header)
    lpm_stub = (
        tmp_path / "libprotobuf-mutator" / "src" / "libfuzzer" / "libfuzzer_macro.h"
    )
    lpm_stub.parent.mkdir(parents=True, exist_ok=True)
    lpm_stub.write_text(
        textwrap.dedent(
            """
            #ifndef TEST_LPM_LIBFUZZER_MACRO_H_
            #define TEST_LPM_LIBFUZZER_MACRO_H_
            #include <cstddef>
            #include <cstdint>
            namespace protobuf_mutator::libfuzzer {
            template <typename Message>
            class PostProcessorRegistration {
             public:
              template <typename Callback>
              explicit PostProcessorRegistration(Callback) {}
            };
            template <typename Message>
            std::size_t CustomProtoMutator(bool, std::uint8_t*, std::size_t,
                                           std::size_t, unsigned int, Message*) {
              return 0;
            }
            template <typename Message>
            std::size_t CustomProtoCrossOver(bool, const std::uint8_t*, std::size_t,
                                             const std::uint8_t*, std::size_t,
                                             std::uint8_t*, std::size_t,
                                             unsigned int, Message*, Message*) {
              return 0;
            }
            template <typename Message>
            bool LoadProtoInput(bool, const std::uint8_t*, std::size_t, Message*) {
              return false;
            }
            }  // namespace protobuf_mutator::libfuzzer
            #endif
            """
        )
    )

    subprocess.run(
        [
            "protoc",
            f"--proto_path={FIXTURE_DIR}",
            f"--proto_path={SCHEMA_DIR}",
            f"--cpp_out={tmp_path}",
            "eligibility_options.proto",
            "typed_tftp.proto",
        ],
        check=True,
    )
    subprocess.run(
        [
            "protoc",
            f"--proto_path={tmp_path}",
            f"--cpp_out={tmp_path}",
            "curl_fuzzer.proto",
            "generated/compatibility/compatibility.proto",
            "generated/fast_tftp/fast_tftp.proto",
        ],
        check=True,
    )

    round_trip = tmp_path / "round_trip.cc"
    round_trip.write_text(
        textwrap.dedent(
            r"""
            #include <type_traits>

            #include <google/protobuf/descriptor.h>

            #include "generated/compatibility/compatibility_traits.h"
            #include "generated/fast_tftp/fast_tftp_traits.h"
            #include "proto_fuzzer/profile_fuzzer.h"
            #include "proto_fuzzer/option_model.h"
            #include "typed_tftp.pb.h"

            static constexpr int CURLOPT_TFTP_BLKSIZE = 1;
            static constexpr int CURLOPT_TFTP_NO_OPTIONS = 2;
            static constexpr int CURLOPT_USERAGENT = 3;
            static constexpr int CURLOPT_RANGE = 4;

            namespace proto_fuzzer::manifest_test {
            #include "curl_fuzzer_option_manifest.inc"
            }  // namespace proto_fuzzer::manifest_test

            using Traits = proto_fuzzer::generated::FastTftpTraits;
            using Message = Traits::Message;
            using Runtime = Traits::RuntimeScenario;
            using Hooks = proto_fuzzer::ProfileFuzzerHooks<Traits>;
            using CompatibilityTraits = proto_fuzzer::generated::CompatibilityTraits;
            using CompatibilityMessage = CompatibilityTraits::Message;

            static_assert(Traits::kProfile == proto_fuzzer::TargetProfile::kFastTftp);
            static_assert(std::is_same_v<
                          Message,
                          curl::fuzzer::generated::fast_tftp::FastTftpScenario>);
            static_assert(std::is_same_v<typename Hooks::Message, Message>);

            int main() {
              if (proto_fuzzer::manifest_test::LookupOptionDescriptor(
                      curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE) == nullptr ||
                  proto_fuzzer::manifest_test::LookupOptionDescriptor(
                      curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED) != nullptr) {
                return 15;
              }
              curl::fuzzer::test::Scenario authoring;
              authoring.set_host_path("authoring symbol is linked");

              Message input;
              input.add_options();
              input.add_options()->set_range("");
              input.add_options()->set_tftp_no_options(false);
              input.add_options()->set_tftp_blksize(0);
              input.add_options()->set_range("second");
              input.mutable_connection()->set_initial_response("");
              input.set_host_path("");
              input.set_scheme(curl::fuzzer::generated::fast_tftp::SCHEME_TFTP);
              input.mutable_primary_state()->set_common("p-common");
              input.mutable_primary_state()->set_primary_only("primary");
              input.mutable_primary_state()->set_mixed_membership("primary-mixed");
              input.mutable_secondary_state()->set_common("s-common");
              input.mutable_secondary_state()->set_secondary_only("secondary");
              input.mutable_recursive()->set_payload("level-1");
              input.mutable_recursive()->mutable_child()->set_payload("level-2");

              Runtime runtime;
              Traits::Lower(&input, &runtime);
              if (runtime.options_size() != 4 ||
                  runtime.options(0).value_case() !=
                      curl::fuzzer::proto::SetOption::kStringValue ||
                  !runtime.options(0).string_value().empty() ||
                  runtime.options(1).value_case() !=
                      curl::fuzzer::proto::SetOption::kBoolValue ||
                  runtime.options(1).bool_value() ||
                  runtime.options(2).value_case() !=
                      curl::fuzzer::proto::SetOption::kUintValue ||
                  runtime.options(2).uint_value() != 0 ||
                  runtime.options(3).string_value() != "second" ||
                  !runtime.has_connection() ||
                  runtime.primary_state().common() != "p-common" ||
                  runtime.primary_state().primary_only() != "primary" ||
                  runtime.primary_state().mixed_membership() != "primary-mixed" ||
                  !runtime.primary_state().secondary_only().empty() ||
                  runtime.secondary_state().common() != "s-common" ||
                  runtime.secondary_state().secondary_only() != "secondary" ||
                  !runtime.secondary_state().primary_only().empty() ||
                  runtime.recursive().payload() != "level-1" ||
                  runtime.recursive().child().payload() != "level-2") {
                return 1;
              }

              CompatibilityMessage preserve_input;
              preserve_input.add_options();
              preserve_input.add_options()->set_tftp_blksize(9);
              preserve_input.add_options();
              Runtime preserve_runtime;
              CompatibilityTraits::Lower(&preserve_input, &preserve_runtime);
              if (preserve_runtime.options_size() != 3 ||
                  preserve_runtime.options(0).option_id() !=
                      curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED ||
                  preserve_runtime.options(0).value_case() !=
                      curl::fuzzer::proto::SetOption::VALUE_NOT_SET ||
                  preserve_runtime.options(1).option_id() !=
                      curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE ||
                  preserve_runtime.options(1).uint_value() != 9 ||
                  preserve_runtime.options(2).option_id() !=
                      curl::fuzzer::proto::CURL_OPTION_UNSPECIFIED) {
                return 6;
              }

              Runtime preserve_lift_input;
              preserve_lift_input.add_options();
              preserve_lift_input.add_options()->set_option_id(
                  static_cast<curl::fuzzer::proto::CurlOptionId>(999999));
              auto* preserved_known = preserve_lift_input.add_options();
              preserved_known->set_option_id(
                  curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE);
              preserved_known->set_uint_value(11);
              CompatibilityMessage preserve_output;
              CompatibilityTraits::Lift(&preserve_lift_input, &preserve_output);
              if (preserve_output.options_size() != 3 ||
                  preserve_output.options(0).setting_case() !=
                      curl::fuzzer::generated::compatibility::SetOption::SETTING_NOT_SET ||
                  preserve_output.options(1).setting_case() !=
                      curl::fuzzer::generated::compatibility::SetOption::SETTING_NOT_SET ||
                  preserve_output.options(2).tftp_blksize() != 11) {
                return 7;
              }

              Runtime discard_lift_input;
              discard_lift_input.add_options();
              discard_lift_input.add_options()->set_option_id(
                  static_cast<curl::fuzzer::proto::CurlOptionId>(999999));
              auto* retained = discard_lift_input.add_options();
              retained->set_option_id(curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE);
              retained->set_uint_value(12);
              Message discard_output;
              Traits::Lift(&discard_lift_input, &discard_output);
              if (discard_output.options_size() != 1 ||
                  discard_output.options(0).tftp_blksize() != 12) {
                return 8;
              }

              Message output;
              Traits::Lift(&runtime, &output);
              if (output.options_size() != 4 ||
                  output.options(0).setting_case() !=
                      curl::fuzzer::generated::fast_tftp::SetOption::kRange ||
                  !output.options(0).range().empty() ||
                  output.options(1).setting_case() !=
                      curl::fuzzer::generated::fast_tftp::SetOption::kTftpNoOptions ||
                  output.options(1).tftp_no_options() ||
                  output.options(2).setting_case() !=
                      curl::fuzzer::generated::fast_tftp::SetOption::kTftpBlksize ||
                  output.options(2).tftp_blksize() != 0 ||
                  output.options(3).range() != "second" ||
                  !output.has_connection() ||
                  output.primary_state().common() != "p-common" ||
                  output.primary_state().primary_only() != "primary" ||
                  output.primary_state().mixed_membership() != "primary-mixed" ||
                  output.secondary_state().common() != "s-common" ||
                  output.secondary_state().secondary_only() != "secondary" ||
                  output.recursive().payload() != "level-1" ||
                  output.recursive().child().payload() != "level-2") {
                return 2;
              }

              input.mutable_choice_payload()->set_amount(0);
              Traits::Lower(&input, &runtime);
              if (runtime.choice_payload().choice_case() !=
                      curl::fuzzer::proto::ChoicePayload::kAmount ||
                  runtime.choice_payload().amount() != 0) {
                return 9;
              }
              Traits::Lift(&runtime, &output);
              if (output.choice_payload().choice_case() !=
                      curl::fuzzer::generated::fast_tftp::ChoicePayload::kAmount ||
                  output.choice_payload().amount() != 0) {
                return 10;
              }

              input.mutable_choice_payload()->set_selected_scheme(
                  curl::fuzzer::generated::fast_tftp::SCHEME_UNSPECIFIED);
              Traits::Lower(&input, &runtime);
              if (runtime.choice_payload().choice_case() !=
                      curl::fuzzer::proto::ChoicePayload::kSelectedScheme ||
                  runtime.choice_payload().selected_scheme() !=
                      curl::fuzzer::proto::SCHEME_UNSPECIFIED) {
                return 11;
              }
              Traits::Lift(&runtime, &output);
              if (output.choice_payload().choice_case() !=
                      curl::fuzzer::generated::fast_tftp::ChoicePayload::kSelectedScheme ||
                  output.choice_payload().selected_scheme() !=
                      curl::fuzzer::generated::fast_tftp::SCHEME_UNSPECIFIED) {
                return 12;
              }

              input.mutable_choice_payload()->mutable_node();
              Traits::Lower(&input, &runtime);
              if (runtime.choice_payload().choice_case() !=
                  curl::fuzzer::proto::ChoicePayload::kNode) {
                return 13;
              }
              Traits::Lift(&runtime, &output);
              if (output.choice_payload().choice_case() !=
                  curl::fuzzer::generated::fast_tftp::ChoicePayload::kNode) {
                return 14;
              }

              runtime.set_host_path("keep");
              runtime.set_scheme(curl::fuzzer::proto::SCHEME_TFTP);
              runtime.mutable_primary_state()->set_mixed_membership("primary-mixed");
              Traits::PruneConditionalEligibility(
                  &runtime, proto_fuzzer::TargetProfile::kFastTftp);
              if (runtime.host_path() != "keep" || runtime.options_size() != 4 ||
                  runtime.primary_state().mixed_membership() != "primary-mixed") {
                return 3;
              }
              runtime.set_scheme(curl::fuzzer::proto::SCHEME_FTPS);
              Traits::PruneConditionalEligibility(
                  &runtime, proto_fuzzer::TargetProfile::kFastTftp);
              if (!runtime.host_path().empty() ||
                  !runtime.primary_state().mixed_membership().empty() ||
                  runtime.options_size() != 2 ||
                  runtime.options(0).option_id() !=
                      curl::fuzzer::proto::CURLOPT_TFTP_NO_OPTIONS ||
                  runtime.options(1).option_id() !=
                      curl::fuzzer::proto::CURLOPT_TFTP_BLKSIZE) {
                return 4;
              }

              const auto* pool = google::protobuf::DescriptorPool::generated_pool();
              if (pool->FindMessageTypeByName("curl.fuzzer.test.Scenario") == nullptr ||
                  pool->FindMessageTypeByName(
                      "curl.fuzzer.generated.fast_tftp.FastTftpScenario") == nullptr ||
                  pool->FindMessageTypeByName("curl.fuzzer.proto.Scenario") == nullptr) {
                return 5;
              }
              return 0;
            }
            """
        )
    )
    executable = tmp_path / "round_trip"
    subprocess.run(
        [
            "c++",
            "-std=c++17",
            f"-I{tmp_path}",
            f"-I{REPO_ROOT}",
            str(round_trip),
            str(tmp_path / "eligibility_options.pb.cc"),
            str(tmp_path / "typed_tftp.pb.cc"),
            str(tmp_path / "curl_fuzzer.pb.cc"),
            str(tmp_path / "generated" / "compatibility" / "compatibility.pb.cc"),
            str(tmp_path / "generated" / "fast_tftp" / "fast_tftp.pb.cc"),
            "-lprotobuf",
            "-pthread",
            "-o",
            str(executable),
        ],
        check=True,
    )
    subprocess.run([str(executable)], check=True)


def test_validates_native_names_and_typed_value_families(tmp_path: Path) -> None:
    model = load_schema_model(_compile_fixture(tmp_path))
    header = parse_curl_header(FIXTURE_DIR / "curl.h")
    validate_native_options(model, header)

    wrong = dict(header)
    wrong["CURLOPT_USERAGENT"] = dataclasses.replace(
        wrong["CURLOPT_USERAGENT"], type_token="CURLOPTTYPE_LONG"
    )
    with pytest.raises(
        SchemaEligibilityError, match="does not match CURLOPT_USERAGENT"
    ):
        validate_native_options(model, wrong)

    del wrong["CURLOPT_TFTP_BLKSIZE"]
    with pytest.raises(SchemaEligibilityError, match="is not defined in curl.h"):
        validate_native_options(model, wrong)


def test_rejects_incomplete_profile_registry(tmp_path: Path) -> None:
    dynamic, registry = _registry(_compile_fixture(tmp_path))
    del registry.profiles[-1]

    with pytest.raises(SchemaEligibilityError, match="incomplete profile registry"):
        load_schema_model(dynamic.SerializeToString(deterministic=True))


@pytest.mark.parametrize("conflict", [False, True])
def test_rejects_missing_or_conflicting_field_metadata(
    tmp_path: Path, conflict: bool
) -> None:
    data = _compile_fixture(tmp_path)
    dynamic, pool = _dynamic(data)
    option_extension = pool.FindExtensionByName(OPTION_EXTENSION)
    field_extension = pool.FindExtensionByName(FIELD_EXTENSION)
    source = next(file for file in dynamic.file if file.name == "typed_tftp.proto")
    set_option = next(
        message for message in source.message_type if message.name == "SetOption"
    )
    field = next(item for item in set_option.field if item.name == "user_agent")
    if conflict:
        field.options.Extensions[field_extension].SetInParent()
        expected = "both option and field eligibility"
    else:
        field.options.ClearExtension(option_extension)
        expected = "no eligibility declaration"

    with pytest.raises(SchemaEligibilityError, match=expected):
        load_schema_model(dynamic.SerializeToString(deterministic=True))
