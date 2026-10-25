"""
Validate schema-owned eligibility and generate restricted profile schemas.

Custom options are decoded from an isolated descriptor pool, validated into
one model, and used to emit the metadata-free authoring, runtime, and profile
artifacts consumed by the structured fuzzers and corpus tools.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import pathlib
import re
import sys
from collections.abc import Iterable, Mapping
from typing import Any

from google.protobuf import (  # type: ignore[import-untyped]
    descriptor_pb2,
    descriptor_pool,
    message_factory,
)

from curl_fuzzer_tools.generate_option_manifest import CurlOption, parse_curl_header

GENERATOR_VERSION = "schema-eligibility-v1"
METADATA_FILE = "eligibility_options.proto"
REGISTRY_EXTENSION = "curl.fuzzer.schema.eligibility_registry"
OPTION_EXTENSION = "curl.fuzzer.schema.curl_option"
FIELD_EXTENSION = "curl.fuzzer.schema.scenario_field"
PROFILE_ENUM = "curl.fuzzer.schema.TargetProfile"
SELECTOR_FACT_ENUM = "curl.fuzzer.schema.SelectorFact"


class SchemaEligibilityError(ValueError):
    """The annotated schema does not describe one closed eligibility model."""


@dataclasses.dataclass(frozen=True)
class Guard:
    fact: str
    expected: bool
    profiles: frozenset[str]


@dataclasses.dataclass(frozen=True)
class EligibilityRule:
    profiles: frozenset[str]
    guards: tuple[Guard, ...]


@dataclasses.dataclass(frozen=True)
class ProfileDeclaration:
    profile: str
    cpp_target_profile: str
    root_message: str
    generated_root: str
    empty_option_policy: str


@dataclasses.dataclass(frozen=True)
class FieldRule:
    full_name: str
    containing_message: str
    name: str
    number: int
    proto_type: int
    label: int
    type_name: str
    oneof_index: int | None
    eligibility: EligibilityRule
    native_name: str | None
    contextual_eligibility: Mapping[str, EligibilityRule]
    child_context: str

    @property
    def is_option(self) -> bool:
        return self.native_name is not None


@dataclasses.dataclass(frozen=True)
class SchemaModel:
    descriptor_set: descriptor_pb2.FileDescriptorSet
    descriptor_sha256: str
    registry_file: str
    profiles: Mapping[str, ProfileDeclaration]
    fields: Mapping[str, FieldRule]
    message_files: Mapping[str, str]
    enum_files: Mapping[str, str]


@dataclasses.dataclass(frozen=True)
class Projection:
    profile: str
    root_message: str
    generated_package: str
    descriptor_bytes: bytes
    schema_files: Mapping[str, str]
    authoring_descriptor_bytes: bytes
    authoring_schema_files: Mapping[str, str]
    runtime_descriptor_bytes: bytes
    runtime_schema_files: Mapping[str, str]
    native_manifest: str
    adapter_header: str
    report: Mapping[str, Any]

    def report_json(self) -> str:
        """Render the stable, reviewable projection report."""
        return json.dumps(self.report, indent=2, sort_keys=True) + "\n"

    @property
    def descriptor_sha256(self) -> str:
        return hashlib.sha256(self.descriptor_bytes).hexdigest()

    @property
    def adapter_sha256(self) -> str:
        return hashlib.sha256(self.adapter_header.encode()).hexdigest()

    @property
    def runtime_descriptor_sha256(self) -> str:
        return hashlib.sha256(self.runtime_descriptor_bytes).hexdigest()

    @property
    def authoring_descriptor_sha256(self) -> str:
        return hashlib.sha256(self.authoring_descriptor_bytes).hexdigest()

    @property
    def report_sha256(self) -> str:
        return hashlib.sha256(self.report_json().encode()).hexdigest()


@dataclasses.dataclass(eq=False)
class _MessageOccurrence:
    source_name: str
    context: str
    path: tuple[str, ...]
    fields: list[FieldRule]
    children: dict[str, _MessageOccurrence]
    signature: tuple[Any, ...] = ()
    generated_name: str = ""
    generated_full_name: str = ""


def _enum_name(enum: Any, value: int, context: str) -> str:
    item = enum.values_by_number.get(value)
    if item is None:
        raise SchemaEligibilityError(f"{context} uses unknown enum value {value}")
    return str(item.name)


def _build_pool(
    raw: descriptor_pb2.FileDescriptorSet,
) -> descriptor_pool.DescriptorPool:
    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(descriptor_pb2.DESCRIPTOR.serialized_pb)
    remaining = {
        file_proto.name: file_proto
        for file_proto in raw.file
        if file_proto.name != "google/protobuf/descriptor.proto"
    }
    while remaining:
        progressed = False
        for name, file_proto in tuple(remaining.items()):
            if all(
                dependency == "google/protobuf/descriptor.proto"
                or dependency not in remaining
                for dependency in file_proto.dependency
            ):
                try:
                    pool.AddSerializedFile(file_proto.SerializeToString())
                except Exception as error:
                    raise SchemaEligibilityError(
                        f"could not load descriptor file {name}: {error}"
                    ) from error
                del remaining[name]
                progressed = True
        if not progressed:
            names = ", ".join(sorted(remaining))
            raise SchemaEligibilityError(
                f"descriptor dependencies are missing or cyclic: {names}"
            )
    return pool


def _dynamic_descriptor_set(data: bytes, pool: descriptor_pool.DescriptorPool) -> Any:
    descriptor = pool.FindMessageTypeByName("google.protobuf.FileDescriptorSet")
    message_class = message_factory.GetMessageClass(descriptor)
    result = message_class()
    result.ParseFromString(data)
    return result


def _messages(
    files: Iterable[Any],
) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
    messages: dict[str, Any] = {}
    message_files: dict[str, str] = {}
    enum_files: dict[str, str] = {}

    def visit(message: Any, prefix: str, file_name: str) -> None:
        full_name = f"{prefix}.{message.name}" if prefix else str(message.name)
        messages[full_name] = message
        message_files[full_name] = file_name
        for enum in message.enum_type:
            enum_files[f"{full_name}.{enum.name}"] = file_name
        for nested in message.nested_type:
            visit(nested, full_name, file_name)

    for file_proto in files:
        if file_proto.name in (METADATA_FILE, "google/protobuf/descriptor.proto"):
            continue
        prefix = str(file_proto.package)
        for enum in file_proto.enum_type:
            enum_name = f"{prefix}.{enum.name}" if prefix else str(enum.name)
            enum_files[enum_name] = str(file_proto.name)
        for message in file_proto.message_type:
            visit(message, prefix, str(file_proto.name))
    return messages, message_files, enum_files


def _parse_eligibility(
    eligibility: Any,
    *,
    context: str,
    profile_enum: Any,
    known_profiles: frozenset[str],
    allow_empty: bool = False,
) -> EligibilityRule:
    direct = {
        _enum_name(profile_enum, int(value), context) for value in eligibility.profiles
    }
    effective = set(direct)
    invalid = effective - known_profiles
    if invalid:
        raise SchemaEligibilityError(
            f"{context} uses invalid profiles: {', '.join(sorted(invalid))}"
        )
    if not effective and not allow_empty:
        raise SchemaEligibilityError(f"{context} has no eligible profiles")

    guards: list[Guard] = []
    for guard in eligibility.guards:
        fact_descriptor = guard.DESCRIPTOR.fields_by_name["fact"].enum_type
        fact = _enum_name(fact_descriptor, int(guard.fact), context)
        if fact == "SELECTOR_FACT_UNSPECIFIED":
            raise SchemaEligibilityError(f"{context} has an unspecified guard")
        guard_profiles = {
            _enum_name(profile_enum, int(value), context) for value in guard.profiles
        }
        if not guard_profiles:
            guard_profiles.update(effective)
        if not guard_profiles <= effective:
            invalid_guards = guard_profiles - effective
            raise SchemaEligibilityError(
                f"{context} guard escapes field membership: "
                f"{', '.join(sorted(invalid_guards))}"
            )
        guards.append(
            Guard(
                fact=fact,
                expected=bool(guard.expected),
                profiles=frozenset(guard_profiles),
            )
        )
    return EligibilityRule(
        profiles=frozenset(effective),
        guards=tuple(guards),
    )


def load_schema_model(data: bytes) -> SchemaModel:
    """Load and validate annotated descriptors without using the default pool."""
    raw = descriptor_pb2.FileDescriptorSet()
    try:
        raw.ParseFromString(data)
    except Exception as error:
        raise SchemaEligibilityError(f"invalid descriptor set: {error}") from error
    if not any(file_proto.name == METADATA_FILE for file_proto in raw.file):
        raise SchemaEligibilityError(
            f"descriptor set does not include {METADATA_FILE}; use --include_imports"
        )

    pool = _build_pool(raw)
    dynamic = _dynamic_descriptor_set(data, pool)
    registry_extension = pool.FindExtensionByName(REGISTRY_EXTENSION)
    option_extension = pool.FindExtensionByName(OPTION_EXTENSION)
    field_extension = pool.FindExtensionByName(FIELD_EXTENSION)
    profile_enum = pool.FindEnumTypeByName(PROFILE_ENUM)
    selector_fact_enum = pool.FindEnumTypeByName(SELECTOR_FACT_ENUM)
    selector_facts = {
        str(value.name)
        for value in selector_fact_enum.values
        if value.name != "SELECTOR_FACT_UNSPECIFIED"
    }
    runtime_facts = set(_GUARD_FACT_CPP)
    dependency_facts = set(_GUARD_FACT_INPUTS)
    if runtime_facts != dependency_facts:
        missing_dependencies = sorted(runtime_facts - dependency_facts)
        unexpected_dependencies = sorted(dependency_facts - runtime_facts)
        details = []
        if missing_dependencies:
            details.append(
                "missing selector inputs: " + ", ".join(missing_dependencies)
            )
        if unexpected_dependencies:
            details.append(
                "unknown selector inputs: " + ", ".join(unexpected_dependencies)
            )
        raise SchemaEligibilityError(
            "selector fact dependency mapping mismatch: " + "; ".join(details)
        )
    if selector_facts != runtime_facts:
        missing_predicates = sorted(selector_facts - runtime_facts)
        unexpected_predicates = sorted(runtime_facts - selector_facts)
        details = []
        if missing_predicates:
            details.append("missing C++ predicates: " + ", ".join(missing_predicates))
        if unexpected_predicates:
            details.append(
                "unknown C++ predicates: " + ", ".join(unexpected_predicates)
            )
        raise SchemaEligibilityError(
            "selector fact runtime mapping mismatch: " + "; ".join(details)
        )
    expected_profiles = frozenset(
        value.name for value in profile_enum.values if value.number != 0
    )

    registries = [
        file_proto
        for file_proto in dynamic.file
        if file_proto.options.HasExtension(registry_extension)
    ]
    if len(registries) != 1:
        raise SchemaEligibilityError(
            "descriptor set must contain exactly one eligibility registry; "
            f"found {len(registries)}"
        )
    registry_file = registries[0]
    registry = registry_file.options.Extensions[registry_extension]

    declarations: dict[str, ProfileDeclaration] = {}
    generated_roots: set[str] = set()
    cpp_target_profiles: set[str] = set()
    for declaration in registry.profiles:
        profile = _enum_name(profile_enum, int(declaration.profile), "profile registry")
        if profile == "TARGET_PROFILE_UNSPECIFIED":
            raise SchemaEligibilityError("profile registry contains UNSPECIFIED")
        if profile in declarations:
            raise SchemaEligibilityError(f"duplicate profile declaration {profile}")
        cpp_target_profile = str(declaration.cpp_target_profile)
        if not re.fullmatch(r"k[A-Z][A-Za-z0-9]*", cpp_target_profile):
            raise SchemaEligibilityError(
                f"{profile} has invalid C++ TargetProfile {cpp_target_profile!r}"
            )
        if cpp_target_profile in cpp_target_profiles:
            raise SchemaEligibilityError(
                f"C++ TargetProfile {cpp_target_profile} is mapped more than once"
            )
        cpp_target_profiles.add(cpp_target_profile)
        root_message = str(declaration.root_message).lstrip(".")
        generated_root = str(declaration.generated_root)
        if not root_message:
            raise SchemaEligibilityError(f"{profile} has no root message")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", generated_root):
            raise SchemaEligibilityError(
                f"{profile} has invalid generated root {generated_root!r}"
            )
        if generated_root in generated_roots:
            raise SchemaEligibilityError(
                f"generated root {generated_root} is used by more than one profile"
            )
        generated_roots.add(generated_root)
        policy_descriptor = declaration.DESCRIPTOR.fields_by_name[
            "empty_option_policy"
        ].enum_type
        policy = _enum_name(
            policy_descriptor,
            int(declaration.empty_option_policy),
            f"profile {profile}",
        )
        if policy == "EMPTY_OPTION_POLICY_UNSPECIFIED":
            raise SchemaEligibilityError(f"{profile} has no empty-option policy")
        declarations[profile] = ProfileDeclaration(
            profile=profile,
            cpp_target_profile=cpp_target_profile,
            root_message=root_message,
            generated_root=generated_root,
            empty_option_policy=policy,
        )
    missing = expected_profiles - declarations.keys()
    extra = declarations.keys() - expected_profiles
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"missing {', '.join(sorted(missing))}")
        if extra:
            parts.append(f"unexpected {', '.join(sorted(extra))}")
        raise SchemaEligibilityError("incomplete profile registry: " + "; ".join(parts))

    messages, message_files, enum_files = _messages(dynamic.file)
    for declaration in declarations.values():
        if declaration.root_message not in messages:
            raise SchemaEligibilityError(
                f"{declaration.profile} root message "
                f"{declaration.root_message} does not exist"
            )

    reachable: set[str] = set()
    pending = [declaration.root_message for declaration in declarations.values()]
    while pending:
        message_name = pending.pop()
        if message_name in reachable:
            continue
        message = messages.get(message_name)
        if message is None:
            continue
        reachable.add(message_name)
        for field in message.field:
            type_name = str(field.type_name).lstrip(".")
            if type_name in messages:
                pending.append(type_name)

    fields: dict[str, FieldRule] = {}
    native_names: dict[str, str] = {}
    for message_name in sorted(reachable):
        message = messages[message_name]
        for field in message.field:
            full_name = f"{message_name}.{field.name}"
            has_option = field.options.HasExtension(option_extension)
            has_field = field.options.HasExtension(field_extension)
            if has_option == has_field:
                state = "both option and field" if has_option else "no"
                raise SchemaEligibilityError(
                    f"{full_name} has {state} eligibility declaration"
                )
            native_name: str | None = None
            contextual_eligibility: dict[str, EligibilityRule] = {}
            child_context = ""
            if has_option:
                metadata = field.options.Extensions[option_extension]
                native_name = str(metadata.native_name)
                if not re.fullmatch(r"CURLOPT_[A-Z0-9_]+", native_name):
                    raise SchemaEligibilityError(
                        f"{full_name} has invalid native name {native_name!r}"
                    )
                previous = native_names.get(native_name)
                if previous is not None:
                    raise SchemaEligibilityError(
                        f"{native_name} is declared by both {previous} and {full_name}"
                    )
                native_names[native_name] = full_name
                if not field.HasField("oneof_index"):
                    raise SchemaEligibilityError(
                        f"typed option {full_name} is not a oneof member"
                    )
                eligibility_message = metadata.eligibility
            else:
                metadata = field.options.Extensions[field_extension]
                child_context = str(metadata.child_context)
                if child_context and not re.fullmatch(
                    r"[a-z][a-z0-9_]*", child_context
                ):
                    raise SchemaEligibilityError(
                        f"{full_name} has invalid projection context {child_context!r}"
                    )
                for override in metadata.contextual_eligibility:
                    projection_context = str(override.context)
                    if not re.fullmatch(r"[a-z][a-z0-9_]*", projection_context):
                        raise SchemaEligibilityError(
                            f"{full_name} has invalid projection context "
                            f"{projection_context!r}"
                        )
                    if projection_context in contextual_eligibility:
                        raise SchemaEligibilityError(
                            f"{full_name} repeats projection context "
                            f"{projection_context!r}"
                        )
                    contextual_eligibility[projection_context] = _parse_eligibility(
                        override.eligibility,
                        context=f"{full_name} context {projection_context}",
                        profile_enum=profile_enum,
                        known_profiles=expected_profiles,
                    )
                if (
                    child_context
                    and field.type != descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
                ):
                    raise SchemaEligibilityError(
                        f"{full_name} sets child_context on a non-message field"
                    )
                eligibility_message = metadata.eligibility
            eligibility = _parse_eligibility(
                eligibility_message,
                context=full_name,
                profile_enum=profile_enum,
                known_profiles=expected_profiles,
                allow_empty=bool(contextual_eligibility),
            )
            if not eligibility.profiles and not contextual_eligibility:
                raise SchemaEligibilityError(f"{full_name} has no eligible profiles")
            fields[full_name] = FieldRule(
                full_name=full_name,
                containing_message=message_name,
                name=str(field.name),
                number=int(field.number),
                proto_type=int(field.type),
                label=int(field.label),
                type_name=str(field.type_name).lstrip("."),
                oneof_index=int(field.oneof_index)
                if field.HasField("oneof_index")
                else None,
                eligibility=eligibility,
                native_name=native_name,
                contextual_eligibility=dict(sorted(contextual_eligibility.items())),
                child_context=child_context,
            )

    model = SchemaModel(
        descriptor_set=raw,
        descriptor_sha256=hashlib.sha256(data).hexdigest(),
        registry_file=str(registry_file.name),
        profiles=dict(sorted(declarations.items())),
        fields=dict(sorted(fields.items())),
        message_files=message_files,
        enum_files=enum_files,
    )
    _validate_guard_dependencies(model)
    return model


def validate_native_options(
    model: SchemaModel, header_options: Mapping[str, CurlOption]
) -> None:
    """Check native identity and typed protobuf values against curl.h."""
    allowed_types = {
        descriptor_pb2.FieldDescriptorProto.TYPE_BYTES: {"CURLOPTTYPE_STRINGPOINT"},
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT64: {
            "CURLOPTTYPE_LONG",
            "CURLOPTTYPE_VALUES",
            "CURLOPTTYPE_OFF_T",
        },
        descriptor_pb2.FieldDescriptorProto.TYPE_BOOL: {
            "CURLOPTTYPE_LONG",
            "CURLOPTTYPE_VALUES",
        },
    }
    byte_pointer_exceptions = {"CURLOPT_POSTFIELDS", "CURLOPT_COPYPOSTFIELDS"}
    for field in model.fields.values():
        if field.native_name is None:
            continue
        native = header_options.get(field.native_name)
        if native is None:
            raise SchemaEligibilityError(
                f"{field.full_name}: {field.native_name} is not defined in curl.h"
            )
        accepted = allowed_types.get(field.proto_type)
        if accepted is None:
            raise SchemaEligibilityError(
                f"{field.full_name}: unsupported typed option protobuf type "
                f"{field.proto_type}"
            )
        type_matches = native.type_token in accepted
        if (
            field.proto_type == descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
            and field.native_name in byte_pointer_exceptions
            and native.type_token == "CURLOPTTYPE_OBJECTPOINT"
        ):
            type_matches = True
        if not type_matches:
            raise SchemaEligibilityError(
                f"{field.full_name}: protobuf type does not match "
                f"{field.native_name} ({native.type_token})"
            )


def validate_cpp_target_profiles(model: SchemaModel, header: pathlib.Path) -> None:
    """Check the registry's explicit C++ identities against target_profile.h."""
    text = header.read_text()
    match = re.search(
        r"enum\s+class\s+TargetProfile\s*\{(?P<body>.*?)\};", text, re.DOTALL
    )
    if match is None:
        raise SchemaEligibilityError(f"TargetProfile enum not found in {header}")
    without_comments = re.sub(
        r"//[^\n]*|/\*.*?\*/", "", match.group("body"), flags=re.DOTALL
    )
    header_profiles = set(re.findall(r"\b(k[A-Z][A-Za-z0-9]*)\b", without_comments))
    registry_profiles = {
        declaration.cpp_target_profile for declaration in model.profiles.values()
    }
    if header_profiles != registry_profiles:
        missing = sorted(header_profiles - registry_profiles)
        unexpected = sorted(registry_profiles - header_profiles)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise SchemaEligibilityError(
            "C++ TargetProfile registry mismatch: " + "; ".join(details)
        )


def _profile_name(model: SchemaModel, requested: str) -> str:
    if requested in model.profiles:
        return requested
    prefixed = f"TARGET_PROFILE_{requested.upper()}"
    if prefixed in model.profiles:
        return prefixed
    raise SchemaEligibilityError(f"unknown target profile {requested}")


_SCALAR_PROTO_TYPES = {
    descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE: "double",
    descriptor_pb2.FieldDescriptorProto.TYPE_FLOAT: "float",
    descriptor_pb2.FieldDescriptorProto.TYPE_INT64: "int64",
    descriptor_pb2.FieldDescriptorProto.TYPE_UINT64: "uint64",
    descriptor_pb2.FieldDescriptorProto.TYPE_INT32: "int32",
    descriptor_pb2.FieldDescriptorProto.TYPE_FIXED64: "fixed64",
    descriptor_pb2.FieldDescriptorProto.TYPE_FIXED32: "fixed32",
    descriptor_pb2.FieldDescriptorProto.TYPE_BOOL: "bool",
    descriptor_pb2.FieldDescriptorProto.TYPE_STRING: "string",
    descriptor_pb2.FieldDescriptorProto.TYPE_BYTES: "bytes",
    descriptor_pb2.FieldDescriptorProto.TYPE_UINT32: "uint32",
    descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED32: "sfixed32",
    descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED64: "sfixed64",
    descriptor_pb2.FieldDescriptorProto.TYPE_SINT32: "sint32",
    descriptor_pb2.FieldDescriptorProto.TYPE_SINT64: "sint64",
}


def _render_enum(enum: descriptor_pb2.EnumDescriptorProto, indent: str) -> list[str]:
    lines = [f"{indent}enum {enum.name} {{"]
    lines.extend(f"{indent}  {value.name} = {value.number};" for value in enum.value)
    lines.append(f"{indent}}}")
    return lines


def _render_field(
    field: descriptor_pb2.FieldDescriptorProto,
    *,
    indent: str,
    syntax: str,
    in_oneof: bool,
) -> str:
    if field.type in (
        descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        descriptor_pb2.FieldDescriptorProto.TYPE_ENUM,
    ):
        type_name = str(field.type_name)
    else:
        type_name = _SCALAR_PROTO_TYPES[int(field.type)]
    label = ""
    if not in_oneof:
        if field.label == descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED:
            label = "repeated "
        elif syntax == "proto2":
            label = (
                "required "
                if field.label == descriptor_pb2.FieldDescriptorProto.LABEL_REQUIRED
                else "optional "
            )
        elif field.proto3_optional:
            label = "optional "
    options = []
    if field.options.packed:
        options.append("packed = true")
    if field.options.deprecated:
        options.append("deprecated = true")
    rendered_options = f" [{', '.join(options)}]" if options else ""
    return (
        f"{indent}{label}{type_name} {field.name} = {field.number}{rendered_options};"
    )


def _render_message(
    message: descriptor_pb2.DescriptorProto, *, indent: str, syntax: str
) -> list[str]:
    lines = [f"{indent}message {message.name} {{"]
    child_indent = indent + "  "
    for enum in message.enum_type:
        lines.extend(_render_enum(enum, child_indent))
    for nested in message.nested_type:
        lines.extend(_render_message(nested, indent=child_indent, syntax=syntax))
    oneof_fields: dict[int, list[descriptor_pb2.FieldDescriptorProto]] = {}
    for field in message.field:
        if field.HasField("oneof_index"):
            oneof_fields.setdefault(int(field.oneof_index), []).append(field)
        else:
            lines.append(
                _render_field(field, indent=child_indent, syntax=syntax, in_oneof=False)
            )
    for index, oneof in enumerate(message.oneof_decl):
        fields = oneof_fields.get(index, [])
        if not fields:
            continue
        lines.append(f"{child_indent}oneof {oneof.name} {{")
        lines.extend(
            (
                _render_field(
                    field,
                    indent=child_indent + "  ",
                    syntax=syntax,
                    in_oneof=True,
                )
            )
            for field in fields
        )
        lines.append(f"{child_indent}}}")
    lines.append(f"{indent}}}")
    return lines


def _render_schema_file(file_proto: descriptor_pb2.FileDescriptorProto) -> str:
    syntax = str(file_proto.syntax or "proto2")
    lines = [f'syntax = "{syntax}";', ""]
    if file_proto.package:
        lines.extend((f"package {file_proto.package};", ""))
    public = {int(index) for index in file_proto.public_dependency}
    weak = {int(index) for index in file_proto.weak_dependency}
    for index, dependency in enumerate(file_proto.dependency):
        qualifier = "public " if index in public else "weak " if index in weak else ""
        lines.append(f'import {qualifier}"{dependency}";')
    if file_proto.dependency:
        lines.append("")
    for enum in file_proto.enum_type:
        lines.extend(_render_enum(enum, ""))
        lines.append("")
    for message in file_proto.message_type:
        lines.extend(_render_message(message, indent="", syntax=syntax))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _cpp_type(full_name: str) -> str:
    return "::" + full_name.replace(".", "::")


def _cpp_case(field_name: str) -> str:
    return "k" + "".join(part[:1].upper() + part[1:] for part in field_name.split("_"))


def _render_structured_transfer(
    *,
    field: FieldRule,
    child: _MessageOccurrence | None,
    enum_symbol_map: Mapping[str, str],
    to_runtime: bool,
) -> list[str]:
    source = "source"
    destination = "destination"
    name = field.name
    repeated = field.label == descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED

    def preserve_presence(lines: list[str]) -> list[str]:
        if field.oneof_index is None:
            return lines
        return [
            f"    if ({source}->has_{name}()) {{",
            *("  " + line for line in lines),
            "    }",
        ]

    if field.proto_type == descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE:
        if child is None:
            raise SchemaEligibilityError(
                f"missing projected child for {field.full_name}"
            )
        helper = ("Lower" if to_runtime else "Lift") + child.generated_name
        if repeated:
            return [
                f"    for (auto& value : *{source}->mutable_{name}()) {{",
                f"      {helper}(&value, {destination}->add_{name}());",
                "    }",
            ]
        return [
            f"    if ({source}->has_{name}()) {{",
            f"      {helper}({source}->mutable_{name}(), {destination}->mutable_{name}());",
            "    }",
        ]
    if field.proto_type in (
        descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
        descriptor_pb2.FieldDescriptorProto.TYPE_BYTES,
    ):
        if repeated:
            return [
                f"    for (auto& value : *{source}->mutable_{name}()) {{",
                f"      {destination}->add_{name}(std::move(value));",
                "    }",
            ]
        return preserve_presence(
            [f"    {destination}->set_{name}(std::move(*{source}->mutable_{name}()));"]
        )
    if field.proto_type == descriptor_pb2.FieldDescriptorProto.TYPE_ENUM:
        target_type = (
            _cpp_type("curl.fuzzer.proto." + field.type_name.rsplit(".", 1)[-1])
            if to_runtime
            else _cpp_type(enum_symbol_map[field.type_name])
        )
        if repeated:
            return [
                f"    for (const auto value : {source}->{name}()) {{",
                f"      {destination}->add_{name}(static_cast<{target_type}>(value));",
                "    }",
            ]
        return preserve_presence(
            [
                f"    {destination}->set_{name}(static_cast<{target_type}>({source}->{name}()));"
            ]
        )
    if repeated:
        return [
            f"    for (const auto value : {source}->{name}()) {{",
            f"      {destination}->add_{name}(value);",
            "    }",
        ]
    return preserve_presence([f"    {destination}->set_{name}({source}->{name}());"])


_GUARD_FACT_CPP = {
    "SELECTOR_FACT_IMPLICIT_FTPS": "scenario->scheme() == ::curl::fuzzer::proto::SCHEME_FTPS",
    "SELECTOR_FACT_RESOLVER_USES_DOH": (
        "scenario->doh_https_rr() || scenario->resolver_mode() == "
        "::curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR"
    ),
    "SELECTOR_FACT_TIMING_WEBSOCKET": (
        "scenario->scheme() == ::curl::fuzzer::proto::SCHEME_WS || "
        "scenario->scheme() == ::curl::fuzzer::proto::SCHEME_WSS"
    ),
    "SELECTOR_FACT_HTTP3_CONNECT_UDP_PROXY": (
        "scenario->has_http3_plan() && "
        "scenario->http3_plan().use_h1_connect_udp_proxy()"
    ),
    "SELECTOR_FACT_HTTP2_PLAN_PRESENT": "scenario->has_http2_plan()",
    "SELECTOR_FACT_H2_PROXY_HTTP2": (
        "scenario->has_connection() && scenario->connection().proxy_protocol() == "
        "::curl::fuzzer::proto::PROXY_PROTOCOL_HTTP2"
    ),
    "SELECTOR_FACT_IMPLICIT_LDAPS": (
        "scenario->scheme() == ::curl::fuzzer::proto::SCHEME_LDAPS"
    ),
    "SELECTOR_FACT_RESOLVER_DEFAULT_MODE": (
        "scenario->resolver_mode() == ::curl::fuzzer::proto::RESOLVER_MODE_DEFAULT"
    ),
    "SELECTOR_FACT_RESOLVER_ACCEPTS_DOH_CONTROL": (
        "scenario->resolver_mode() == "
        "::curl::fuzzer::proto::RESOLVER_MODE_DEFAULT || "
        "scenario->resolver_mode() == "
        "::curl::fuzzer::proto::RESOLVER_MODE_DOH_ERROR"
    ),
    "SELECTOR_FACT_DEEP_HTTP_CONNECT_PROXY": (
        "scenario->http_transport_mode() == "
        "::curl::fuzzer::proto::HTTP_TRANSPORT_CONNECT_PROXY"
    ),
    "SELECTOR_FACT_DEEP_HTTP_DEFAULT_SOCKET_ROUTE": (
        "scenario->proxy_socket_option_mode() == "
        "::curl::fuzzer::proto::PROXY_SOCKET_OPTION_DEFAULT"
    ),
    "SELECTOR_FACT_DEEP_HTTP_REWRITE_FILES_ALLOWED": (
        "scenario->proxy_socket_option_mode() == "
        "::curl::fuzzer::proto::PROXY_SOCKET_OPTION_DEFAULT && "
        "scenario->http_transport_mode() == "
        "::curl::fuzzer::proto::HTTP_TRANSPORT_DIRECT"
    ),
    "SELECTOR_FACT_API_MULTI_DRIVE": (
        "scenario->has_api_plan() && "
        "(scenario->api_plan().drive_mode() == "
        "::curl::fuzzer::proto::API_DRIVE_MULTI_PERFORM || "
        "scenario->api_plan().drive_mode() == "
        "::curl::fuzzer::proto::API_DRIVE_MULTI_SOCKET)"
    ),
    "SELECTOR_FACT_API_VALID_MIME_REPEAT": (
        "scenario->has_api_plan() && "
        "scenario->api_plan().repeat_mime_post() && scenario->has_upload() && "
        "scenario->has_mime_post() && ([&]() { "
        "for (const auto& part : scenario->mime_post().parts()) { "
        "if (part.content_case() == "
        "::curl::fuzzer::proto::MimePart::kUploadCallback) { return true; } "
        "} return false; })()"
    ),
}

# Root-relative runtime fields read by each predicate above. Profile projection
# must retain every path until the one generated pruning window (after selector
# normalization and before shape bounds), or evaluating the fact would silently
# consult a protobuf default instead of the normalized selector. Every active
# fact has schema inputs; there are no policy-owned exceptions.
_GUARD_FACT_INPUTS: dict[str, tuple[tuple[str, ...], ...]] = {
    "SELECTOR_FACT_IMPLICIT_FTPS": (("scheme",),),
    "SELECTOR_FACT_RESOLVER_USES_DOH": (("doh_https_rr",), ("resolver_mode",)),
    "SELECTOR_FACT_TIMING_WEBSOCKET": (("scheme",),),
    "SELECTOR_FACT_HTTP3_CONNECT_UDP_PROXY": (
        ("http3_plan",),
        ("http3_plan", "use_h1_connect_udp_proxy"),
    ),
    "SELECTOR_FACT_HTTP2_PLAN_PRESENT": (("http2_plan",),),
    "SELECTOR_FACT_H2_PROXY_HTTP2": (
        ("connection",),
        ("connection", "proxy_protocol"),
    ),
    "SELECTOR_FACT_IMPLICIT_LDAPS": (("scheme",),),
    "SELECTOR_FACT_RESOLVER_DEFAULT_MODE": (("resolver_mode",),),
    "SELECTOR_FACT_RESOLVER_ACCEPTS_DOH_CONTROL": (("resolver_mode",),),
    "SELECTOR_FACT_DEEP_HTTP_CONNECT_PROXY": (("http_transport_mode",),),
    "SELECTOR_FACT_DEEP_HTTP_DEFAULT_SOCKET_ROUTE": (("proxy_socket_option_mode",),),
    "SELECTOR_FACT_DEEP_HTTP_REWRITE_FILES_ALLOWED": (
        ("proxy_socket_option_mode",),
        ("http_transport_mode",),
    ),
    "SELECTOR_FACT_API_MULTI_DRIVE": (
        ("api_plan",),
        ("api_plan", "drive_mode"),
    ),
    "SELECTOR_FACT_API_VALID_MIME_REPEAT": (
        ("api_plan",),
        ("api_plan", "repeat_mime_post"),
        ("upload",),
        ("mime_post",),
        ("mime_post", "parts"),
        ("mime_post", "parts", "upload_callback"),
    ),
}


def _field_for_context(
    field: FieldRule, context: str, profile: str
) -> FieldRule | None:
    """Resolve additive default and context-specific eligibility for a profile."""
    rules = [field.eligibility]
    override = field.contextual_eligibility.get(context)
    if override is not None:
        rules.append(override)
    applicable = [rule for rule in rules if profile in rule.profiles]
    if not applicable:
        return None
    return dataclasses.replace(
        field,
        eligibility=EligibilityRule(
            profiles=frozenset(
                candidate for rule in rules for candidate in rule.profiles
            ),
            guards=tuple(guard for rule in rules for guard in rule.guards),
        ),
    )


def _build_occurrences(
    model: SchemaModel, profile: str, root_message: str
) -> _MessageOccurrence:
    fields_by_message: dict[str, list[FieldRule]] = {}
    for field in model.fields.values():
        fields_by_message.setdefault(field.containing_message, []).append(field)

    memo: dict[tuple[str, str], _MessageOccurrence] = {}

    def build(
        source_name: str, context: str, path: tuple[str, ...]
    ) -> _MessageOccurrence:
        key = (source_name, context)
        existing = memo.get(key)
        if existing is not None:
            return existing
        fields = sorted(
            (
                resolved
                for field in fields_by_message.get(source_name, [])
                if (resolved := _field_for_context(field, context, profile)) is not None
            ),
            key=lambda field: field.number,
        )
        occurrence = _MessageOccurrence(
            source_name=source_name,
            context=context,
            path=path,
            fields=fields,
            children={},
        )
        memo[key] = occurrence
        for field in fields:
            if field.type_name in model.message_files:
                occurrence.children[field.full_name] = build(
                    field.type_name,
                    field.child_context,
                    (*path, field.name),
                )
        return occurrence

    root = build(root_message, "", (root_message.rsplit(".", 1)[-1],))
    occurrences = list(memo.values())
    base_signatures = {
        occurrence: (
            occurrence.source_name,
            tuple(
                (
                    field.number,
                    field.proto_type,
                    field.label,
                    field.type_name,
                    tuple(
                        (guard.fact, guard.expected)
                        for guard in field.eligibility.guards
                        if profile in guard.profiles
                    ),
                )
                for field in occurrence.fields
            ),
        )
        for occurrence in occurrences
    }

    def partition(
        signatures: Mapping[_MessageOccurrence, tuple[Any, ...]],
    ) -> dict[_MessageOccurrence, int]:
        unique = set(signatures.values())
        colors = {
            signature: index for index, signature in enumerate(sorted(unique, key=repr))
        }
        return {
            occurrence: colors[signature]
            for occurrence, signature in signatures.items()
        }

    colors = partition(base_signatures)
    for _ in range(len(occurrences) + 1):
        refined = {
            occurrence: (
                base_signatures[occurrence],
                tuple(
                    colors[occurrence.children[field.full_name]]
                    if field.full_name in occurrence.children
                    else None
                    for field in occurrence.fields
                ),
            )
            for occurrence in occurrences
        }
        next_colors = partition(refined)
        if next_colors == colors:
            break
        colors = next_colors
    else:
        raise SchemaEligibilityError("recursive shape partition did not converge")
    for occurrence in occurrences:
        occurrence.signature = (occurrence.source_name, colors[occurrence])
    return root


def _all_occurrences(root: _MessageOccurrence) -> list[_MessageOccurrence]:
    result: list[_MessageOccurrence] = []
    visited: set[int] = set()

    def visit(occurrence: _MessageOccurrence) -> None:
        if id(occurrence) in visited:
            return
        visited.add(id(occurrence))
        result.append(occurrence)
        for child in occurrence.children.values():
            visit(child)

    visit(root)
    return result


def _validate_guard_dependencies(model: SchemaModel) -> None:
    """Require every guard input in each profile shape that evaluates it."""
    for profile, declaration in model.profiles.items():
        root = _build_occurrences(model, profile, declaration.root_message)
        facts = {
            guard.fact
            for field in model.fields.values()
            for rule in (field.eligibility, *field.contextual_eligibility.values())
            for guard in rule.guards
            if profile in guard.profiles
        }
        for fact in sorted(facts):
            for path in _GUARD_FACT_INPUTS[fact]:
                occurrence = root
                for index, name in enumerate(path):
                    field = next(
                        (
                            candidate
                            for candidate in occurrence.fields
                            if candidate.name == name
                        ),
                        None,
                    )
                    if field is None:
                        raise SchemaEligibilityError(
                            f"guard fact {fact} applies to {profile}, but selector "
                            f"input {'.'.join(path)} is absent at the "
                            "post-normalization pruning window"
                        )
                    if index + 1 == len(path):
                        continue
                    child = occurrence.children.get(field.full_name)
                    if child is None:
                        raise SchemaEligibilityError(
                            f"guard fact {fact} applies to {profile}, but selector "
                            f"input {'.'.join(path)} is absent at the "
                            "post-normalization pruning window"
                        )
                    occurrence = child


def _assign_occurrence_names(
    root: _MessageOccurrence, generated_package: str, generated_root: str
) -> None:
    grouped: dict[str, dict[tuple[Any, ...], list[_MessageOccurrence]]] = {}
    for occurrence in _all_occurrences(root):
        grouped.setdefault(occurrence.source_name, {}).setdefault(
            occurrence.signature, []
        ).append(occurrence)

    used_names = {generated_root}
    root.generated_name = generated_root
    root.generated_full_name = f"{generated_package}.{generated_root}"
    for source_name in sorted(grouped):
        if source_name == root.source_name:
            continue
        signatures = grouped[source_name]
        for signature, members in sorted(
            signatures.items(), key=lambda item: min(member.path for member in item[1])
        ):
            base = source_name.rsplit(".", 1)[-1]
            if len(signatures) == 1:
                candidate = base
            else:
                representative = min(members, key=lambda member: member.path)
                suffix = "".join(
                    part[:1].upper() + part[1:]
                    for field_name in representative.path[1:]
                    for part in field_name.split("_")
                )
                candidate = f"{base}For{suffix}"
            if candidate in used_names:
                digest = hashlib.sha256(repr(signature).encode()).hexdigest()[:8]
                candidate = f"{candidate}{digest}"
            used_names.add(candidate)
            for member in members:
                member.generated_name = candidate
                member.generated_full_name = f"{generated_package}.{candidate}"


def _descriptor_messages(
    descriptor_set: descriptor_pb2.FileDescriptorSet,
) -> dict[str, descriptor_pb2.DescriptorProto]:
    result: dict[str, descriptor_pb2.DescriptorProto] = {}

    def visit(message: descriptor_pb2.DescriptorProto, prefix: str) -> None:
        full_name = f"{prefix}.{message.name}" if prefix else str(message.name)
        result[full_name] = message
        for nested in message.nested_type:
            visit(nested, full_name)

    for file_proto in descriptor_set.file:
        for message in file_proto.message_type:
            visit(message, str(file_proto.package))
    return result


def _contextual_profile_descriptor(
    *,
    model: SchemaModel,
    root: _MessageOccurrence,
    generated_package: str,
    generated_file: str,
) -> tuple[descriptor_pb2.FileDescriptorSet, Mapping[str, str]]:
    source_files = {
        file_proto.name: file_proto for file_proto in model.descriptor_set.file
    }
    source_file_names = {
        model.message_files[occurrence.source_name]
        for occurrence in _all_occurrences(root)
    }
    if source_file_names != {model.registry_file}:
        raise SchemaEligibilityError(
            "the contextual projection requires one annotated source file"
        )
    clean = descriptor_pb2.FileDescriptorSet()
    clean.CopyFrom(model.descriptor_set)
    clean.DiscardUnknownFields()
    source = next(
        file_proto
        for file_proto in clean.file
        if file_proto.name == model.registry_file
    )
    source_messages = _descriptor_messages(clean)

    output_file = descriptor_pb2.FileDescriptorProto()
    output_file.CopyFrom(source)
    output_file.name = generated_file
    output_file.package = generated_package
    output_file.ClearField("source_code_info")
    del output_file.message_type[:]
    del output_file.enum_type[:]
    del output_file.service[:]
    del output_file.extension[:]
    del output_file.dependency[:]
    del output_file.public_dependency[:]
    del output_file.weak_dependency[:]

    unique_occurrences: dict[tuple[Any, ...], _MessageOccurrence] = {}
    for occurrence in _all_occurrences(root):
        unique_occurrences.setdefault(occurrence.signature, occurrence)
    enum_names = {
        field.type_name
        for occurrence in unique_occurrences.values()
        for field in occurrence.fields
        if field.type_name in model.enum_files
    }
    enum_symbol_map = {
        name: f"{generated_package}.{name.rsplit('.', 1)[-1]}"
        for name in sorted(enum_names)
    }
    if len(set(enum_symbol_map.values())) != len(enum_symbol_map):
        raise SchemaEligibilityError("projected enum names collide")

    for occurrence in sorted(
        unique_occurrences.values(), key=lambda item: item.generated_name
    ):
        source_message = source_messages[occurrence.source_name]
        if source_message.nested_type or source_message.enum_type:
            raise SchemaEligibilityError(
                "the contextual projection requires top-level message types: "
                + occurrence.source_name
            )
        message = output_file.message_type.add()
        message.CopyFrom(source_message)
        message.name = occurrence.generated_name
        retained = {field.name: field for field in occurrence.fields}
        kept_fields = [field for field in message.field if field.name in retained]
        del message.field[:]
        message.field.extend(kept_fields)
        for field in message.field:
            rule = retained[str(field.name)]
            child = occurrence.children.get(rule.full_name)
            if child is not None:
                field.type_name = "." + child.generated_full_name
            elif rule.type_name in enum_symbol_map:
                field.type_name = "." + enum_symbol_map[rule.type_name]

    for enum_name in sorted(enum_names):
        file_name = model.enum_files[enum_name]
        file_proto = source_files[file_name]
        local_name = enum_name.removeprefix(str(file_proto.package) + ".")
        if "." in local_name:
            raise SchemaEligibilityError(
                "the contextual projection requires top-level enums: " + enum_name
            )
        source_enum = next(enum for enum in source.enum_type if enum.name == local_name)
        output_file.enum_type.add().CopyFrom(source_enum)

    projected = descriptor_pb2.FileDescriptorSet()
    projected.file.add().CopyFrom(output_file)
    return projected, enum_symbol_map


def _render_contextual_adapter(
    *,
    model: SchemaModel,
    profile: str,
    root: _MessageOccurrence,
    enum_symbol_map: Mapping[str, str],
    generated_header: str,
) -> str:
    declaration = model.profiles[profile]
    traits_name = declaration.generated_root.removesuffix("Scenario") + "Traits"
    unique_occurrences: dict[tuple[Any, ...], _MessageOccurrence] = {}
    for occurrence in _all_occurrences(root):
        unique_occurrences.setdefault(occurrence.signature, occurrence)
    option_occurrences = [
        occurrence
        for occurrence in unique_occurrences.values()
        if any(field.is_option for field in occurrence.fields)
    ]
    if len(option_occurrences) > 1:
        raise SchemaEligibilityError("typed options span more than one projected shape")
    option_occurrence = option_occurrences[0] if option_occurrences else None
    option_fields = (
        [field for field in option_occurrence.fields if field.is_option]
        if option_occurrence is not None
        else []
    )
    preserve_empty_options = (
        declaration.empty_option_policy == "EMPTY_OPTION_POLICY_PRESERVE_SLOT"
    )

    lines = [
        "// Generated by curl_fuzzer_tools.schema_eligibility.",
        "// Do not edit.",
        "#ifndef CURL_FUZZER_GENERATED_"
        + profile.removeprefix("TARGET_PROFILE_")
        + "_TRAITS_H_",
        "#define CURL_FUZZER_GENERATED_"
        + profile.removeprefix("TARGET_PROFILE_")
        + "_TRAITS_H_",
        "",
        "#include <utility>",
        "",
        '#include "curl_fuzzer.pb.h"',
        f'#include "{generated_header}"',
        '#include "proto_fuzzer/target_profile.h"',
        "",
        "namespace proto_fuzzer::generated {",
        "",
        f"struct {traits_name} {{",
        f"  using Message = {_cpp_type(root.generated_full_name)};",
        "  using RuntimeScenario = ::curl::fuzzer::proto::Scenario;",
        "  static constexpr TargetProfile kProfile =",
        f"      TargetProfile::{declaration.cpp_target_profile};",
        "",
    ]

    def render_option_transfer(to_runtime: bool) -> list[str]:
        if option_occurrence is None:
            return []
        projected_option_type = _cpp_type(option_occurrence.generated_full_name)
        result = ["    for (auto& source_option : *source->mutable_options()) {"]
        if to_runtime:
            result.append("      switch (source_option.setting_case()) {")
            for field in option_fields:
                value_setter = {
                    descriptor_pb2.FieldDescriptorProto.TYPE_BYTES: "string_value",
                    descriptor_pb2.FieldDescriptorProto.TYPE_UINT64: "uint_value",
                    descriptor_pb2.FieldDescriptorProto.TYPE_BOOL: "bool_value",
                }[field.proto_type]
                value = f"source_option.{field.name}()"
                if field.proto_type == descriptor_pb2.FieldDescriptorProto.TYPE_BYTES:
                    value = f"std::move(*source_option.mutable_{field.name}())"
                result.extend(
                    (
                        f"        case {projected_option_type}::{_cpp_case(field.name)}: {{",
                        "          auto* option = destination->add_options();",
                        f"          option->set_option_id(::curl::fuzzer::proto::{field.native_name});",
                        f"          option->set_{value_setter}({value});",
                        "          break;",
                        "        }",
                    )
                )
            result.append("        default:")
            if preserve_empty_options:
                result.append("          destination->add_options();")
            result.extend(("          break;", "      }"))
        else:
            result.append("      switch (source_option.option_id()) {")
            for field in option_fields:
                value_getter = {
                    descriptor_pb2.FieldDescriptorProto.TYPE_BYTES: "string_value",
                    descriptor_pb2.FieldDescriptorProto.TYPE_UINT64: "uint_value",
                    descriptor_pb2.FieldDescriptorProto.TYPE_BOOL: "bool_value",
                }[field.proto_type]
                value = f"source_option.{value_getter}()"
                if field.proto_type == descriptor_pb2.FieldDescriptorProto.TYPE_BYTES:
                    value = f"std::move(*source_option.mutable_{value_getter}())"
                result.extend(
                    (
                        f"        case ::curl::fuzzer::proto::{field.native_name}: {{",
                        "          auto* option = destination->add_options();",
                        f"          option->set_{field.name}({value});",
                        "          break;",
                        "        }",
                    )
                )
            result.append("        default:")
            if preserve_empty_options:
                result.append("          destination->add_options();")
            result.extend(("          break;", "      }"))
        result.extend(("    }", ""))
        return result

    for function_name, to_runtime in (("Lower", True), ("Lift", False)):
        source_type = "Message" if to_runtime else "RuntimeScenario"
        destination_type = "RuntimeScenario" if to_runtime else "Message"
        lines.extend(
            (
                f"  static void {function_name}({source_type}* source, {destination_type}* destination) {{",
                "    if (source == nullptr || destination == nullptr) {",
                "      return;",
                "    }",
                "    destination->Clear();",
            )
        )
        for field in root.fields:
            child = root.children.get(field.full_name)
            if child is option_occurrence:
                lines.extend(render_option_transfer(to_runtime))
            else:
                lines.extend(
                    _render_structured_transfer(
                        field=field,
                        child=child,
                        enum_symbol_map=enum_symbol_map,
                        to_runtime=to_runtime,
                    )
                )
        lines.extend(("  }", ""))

    structured_occurrences = [
        occurrence
        for occurrence in sorted(
            unique_occurrences.values(), key=lambda item: item.generated_name
        )
        if occurrence is not option_occurrence
    ]
    for occurrence in structured_occurrences:
        runtime_type = _cpp_type(
            "curl.fuzzer.proto." + occurrence.source_name.rsplit(".", 1)[-1]
        )
        lines.extend(
            (
                f"  static void PruneEligibility{occurrence.generated_name}(",
                f"      {runtime_type}* message, RuntimeScenario* scenario) {{",
                "    if (message == nullptr || scenario == nullptr) {",
                "      return;",
                "    }",
            )
        )
        for field in occurrence.fields:
            if field.is_option:
                continue
            for guard in field.eligibility.guards:
                if profile not in guard.profiles:
                    continue
                expression = _GUARD_FACT_CPP[guard.fact]
                expected = "true" if guard.expected else "false"
                lines.extend(
                    (
                        f"    if (({expression}) != {expected}) {{",
                        f"      message->clear_{field.name}();",
                        "    }",
                    )
                )
            child = occurrence.children.get(field.full_name)
            if child is None or child is option_occurrence:
                continue
            helper = f"PruneEligibility{child.generated_name}"
            if field.label == descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED:
                lines.extend(
                    (
                        f"    for (auto& value : *message->mutable_{field.name}()) {{",
                        f"      {helper}(&value, scenario);",
                        "    }",
                    )
                )
            else:
                lines.extend(
                    (
                        f"    if (message->has_{field.name}()) {{",
                        f"      {helper}(message->mutable_{field.name}(), scenario);",
                        "    }",
                    )
                )
        lines.extend(("  }", ""))

    lines.extend(
        (
            "  // The target-policy pipeline calls this after selector normalization",
            "  // and before shape bounds; moving it outside that window is incorrect.",
            "  static void PruneConditionalEligibility(RuntimeScenario* scenario,",
            "                                          TargetProfile profile) {",
            "    if (scenario == nullptr || profile != kProfile) {",
            "      return;",
            "    }",
            f"    PruneEligibility{root.generated_name}(scenario, scenario);",
        )
    )
    guarded_options = [
        field
        for field in option_fields
        if any(profile in guard.profiles for guard in field.eligibility.guards)
    ]
    if guarded_options:
        lines.extend(
            (
                "    auto* options = scenario->mutable_options();",
                "    int retained = 0;",
                "    const int original_size = options->size();",
                "    for (int index = 0; index < original_size; ++index) {",
                "      const auto& option = options->Get(index);",
                "      bool discard = false;",
            )
        )
        for field in guarded_options:
            for guard in field.eligibility.guards:
                if profile not in guard.profiles:
                    continue
                expression = _GUARD_FACT_CPP[guard.fact]
                expected = "true" if guard.expected else "false"
                lines.extend(
                    (
                        (
                            "      if (option.option_id() == "
                            f"::curl::fuzzer::proto::{field.native_name} &&"
                        ),
                        f"          ({expression}) != {expected}) {{",
                        "        discard = true;",
                        "      }",
                    )
                )
        lines.extend(
            (
                "      if (!discard) {",
                "        if (retained != index) {",
                "          options->SwapElements(retained, index);",
                "        }",
                "        ++retained;",
                "      }",
                "    }",
                "    if (retained != original_size) {",
                "      options->DeleteSubrange(retained, original_size - retained);",
                "    }",
            )
        )
    lines.extend(("  }", ""))

    for occurrence in sorted(
        unique_occurrences.values(), key=lambda item: item.generated_name
    ):
        if occurrence in (root, option_occurrence) or not occurrence.fields:
            continue
        projected_type = _cpp_type(occurrence.generated_full_name)
        runtime_type = _cpp_type(
            "curl.fuzzer.proto." + occurrence.source_name.rsplit(".", 1)[-1]
        )
        for function_name, source_type, destination_type, to_runtime in (
            ("Lower", projected_type, runtime_type, True),
            ("Lift", runtime_type, projected_type, False),
        ):
            lines.extend(
                (
                    f"  static void {function_name}{occurrence.generated_name}({source_type}* source,",
                    f"                                    {destination_type}* destination) {{",
                    "    if (source == nullptr || destination == nullptr) {",
                    "      return;",
                    "    }",
                    "    destination->Clear();",
                )
            )
            for field in occurrence.fields:
                lines.extend(
                    _render_structured_transfer(
                        field=field,
                        child=occurrence.children.get(field.full_name),
                        enum_symbol_map=enum_symbol_map,
                        to_runtime=to_runtime,
                    )
                )
            lines.extend(("  }", ""))
    lines.extend(
        (
            "};",
            "",
            "}  // namespace proto_fuzzer::generated",
            "",
            "#endif",
            "",
        )
    )
    return "\n".join(lines)


def _stripped_authoring_artifacts(
    model: SchemaModel,
) -> tuple[bytes, Mapping[str, str]]:
    """Emit the full typed authoring schema without generator-only metadata."""
    stripped = descriptor_pb2.FileDescriptorSet()
    stripped.CopyFrom(model.descriptor_set)
    stripped.DiscardUnknownFields()
    kept_files: list[descriptor_pb2.FileDescriptorProto] = []
    for file_proto in stripped.file:
        if file_proto.name in (METADATA_FILE, "google/protobuf/descriptor.proto"):
            continue
        dependency_map: dict[int, int] = {}
        dependencies: list[str] = []
        for old_index, dependency in enumerate(file_proto.dependency):
            if dependency == METADATA_FILE:
                continue
            dependency_map[old_index] = len(dependencies)
            dependencies.append(str(dependency))
        old_public = list(file_proto.public_dependency)
        old_weak = list(file_proto.weak_dependency)
        del file_proto.dependency[:]
        file_proto.dependency.extend(dependencies)
        del file_proto.public_dependency[:]
        file_proto.public_dependency.extend(
            dependency_map[index] for index in old_public if index in dependency_map
        )
        del file_proto.weak_dependency[:]
        file_proto.weak_dependency.extend(
            dependency_map[index] for index in old_weak if index in dependency_map
        )
        file_proto.ClearField("source_code_info")
        kept_files.append(file_proto)
    del stripped.file[:]
    stripped.file.extend(kept_files)
    descriptor_bytes = stripped.SerializeToString(deterministic=True)
    schema_files = {
        str(file_proto.name): _render_schema_file(file_proto)
        for file_proto in stripped.file
    }
    return descriptor_bytes, schema_files


def authoring_schema_files(model: SchemaModel) -> Mapping[str, str]:
    """Render metadata-free authoring proto sources from an annotated model."""
    return _stripped_authoring_artifacts(model)[1]


def _runtime_artifacts(
    model: SchemaModel,
) -> tuple[bytes, Mapping[str, str], str]:
    """Derive the generic internal Scenario interface from typed fields."""
    source_file_names = set(model.message_files.values()) | set(
        model.enum_files.values()
    )
    if source_file_names != {model.registry_file}:
        raise SchemaEligibilityError(
            "the runtime projection requires one annotated source file"
        )
    runtime_set = descriptor_pb2.FileDescriptorSet()
    runtime_set.CopyFrom(model.descriptor_set)
    runtime_set.DiscardUnknownFields()
    source = next(
        file_proto
        for file_proto in runtime_set.file
        if file_proto.name == model.registry_file
    )
    runtime_file = descriptor_pb2.FileDescriptorProto()
    runtime_file.CopyFrom(source)
    source_package = str(runtime_file.package)
    runtime_package = "curl.fuzzer.proto"
    runtime_file.name = "curl_fuzzer.proto"
    runtime_file.package = runtime_package
    runtime_file.ClearField("source_code_info")
    del runtime_file.service[:]
    del runtime_file.extension[:]

    dependency_map: dict[int, int] = {}
    dependencies: list[str] = []
    for old_index, dependency in enumerate(runtime_file.dependency):
        if dependency == METADATA_FILE:
            continue
        dependency_map[old_index] = len(dependencies)
        dependencies.append(str(dependency))
    old_public = list(runtime_file.public_dependency)
    old_weak = list(runtime_file.weak_dependency)
    del runtime_file.dependency[:]
    runtime_file.dependency.extend(dependencies)
    del runtime_file.public_dependency[:]
    runtime_file.public_dependency.extend(
        dependency_map[index] for index in old_public if index in dependency_map
    )
    del runtime_file.weak_dependency[:]
    runtime_file.weak_dependency.extend(
        dependency_map[index] for index in old_weak if index in dependency_map
    )

    symbol_map = {
        name: runtime_package
        + "."
        + (name.removeprefix(source_package + ".") if source_package else name)
        for name in (*model.message_files, *model.enum_files)
    }

    option_fields = sorted(
        (field for field in model.fields.values() if field.is_option),
        key=lambda field: field.number,
    )
    option_messages = {field.containing_message for field in option_fields}
    if len(option_messages) != 1:
        raise SchemaEligibilityError(
            "the generic runtime requires exactly one typed option message"
        )
    option_message_name = next(iter(option_messages))

    def rewrite_message(message: descriptor_pb2.DescriptorProto, prefix: str) -> None:
        full_name = f"{prefix}.{message.name}" if prefix else str(message.name)
        if full_name == option_message_name:
            del message.field[:]
            del message.oneof_decl[:]
            option_id = message.field.add()
            option_id.name = "option_id"
            option_id.number = 1
            option_id.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
            option_id.type = descriptor_pb2.FieldDescriptorProto.TYPE_ENUM
            option_id.type_name = f".{runtime_package}.CurlOptionId"
            oneof = message.oneof_decl.add()
            oneof.name = "value"
            for name, number, proto_type in (
                ("string_value", 10, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES),
                ("uint_value", 11, descriptor_pb2.FieldDescriptorProto.TYPE_UINT64),
                ("bool_value", 12, descriptor_pb2.FieldDescriptorProto.TYPE_BOOL),
            ):
                field = message.field.add()
                field.name = name
                field.number = number
                field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
                field.type = proto_type
                field.oneof_index = 0
        else:
            for field in message.field:
                original_type = str(field.type_name).lstrip(".")
                if original_type in symbol_map:
                    field.type_name = "." + symbol_map[original_type]
        for nested in message.nested_type:
            rewrite_message(nested, full_name)

    for message in runtime_file.message_type:
        rewrite_message(message, source_package)

    option_enum = runtime_file.enum_type.add()
    option_enum.name = "CurlOptionId"
    unspecified = option_enum.value.add()
    unspecified.name = "CURL_OPTION_UNSPECIFIED"
    unspecified.number = 0
    for field in option_fields:
        value = option_enum.value.add()
        value.name = str(field.native_name)
        value.number = field.number

    runtime_output = descriptor_pb2.FileDescriptorSet()
    runtime_output.file.add().CopyFrom(runtime_file)
    runtime_bytes = runtime_output.SerializeToString(deterministic=True)
    runtime_schema = {runtime_file.name: _render_schema_file(runtime_file)}

    kind_by_type = {
        descriptor_pb2.FieldDescriptorProto.TYPE_BYTES: "OptionValueKind::kString",
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT64: "OptionValueKind::kUint",
        descriptor_pb2.FieldDescriptorProto.TYPE_BOOL: "OptionValueKind::kBool",
    }
    manifest_lines = [
        "// Generated by curl_fuzzer_tools.schema_eligibility.",
        "// Do not edit. Included from the internal runtime option model.",
        "static constexpr OptionDescriptor kOptionManifest[] = {",
    ]
    manifest_lines.extend(
        (
            "    {curl::fuzzer::proto::"
            + str(field.native_name)
            + ", "
            + kind_by_type[field.proto_type]
            + ', "'
            + str(field.native_name)
            + '", '
            + str(field.native_name)
            + "},"
        )
        for field in option_fields
    )
    manifest_lines.extend(
        (
            "};",
            "",
            "static constexpr const OptionDescriptor* LookupOptionDescriptor(",
            "    curl::fuzzer::proto::CurlOptionId id) {",
            "  switch (id) {",
        )
    )
    for index, field in enumerate(option_fields):
        manifest_lines.extend(
            (
                f"    case curl::fuzzer::proto::{field.native_name}:",
                f"      return &kOptionManifest[{index}];",
            )
        )
    manifest_lines.extend(("    default:", "      return nullptr;", "  }", "}", ""))
    return runtime_bytes, runtime_schema, "\n".join(manifest_lines)


def project_profile(model: SchemaModel, requested_profile: str) -> Projection:
    """Produce a contextual, collision-free restricted profile and adapter."""
    profile = _profile_name(model, requested_profile)
    declaration = model.profiles[profile]
    slug = profile.removeprefix("TARGET_PROFILE_").lower()
    generated_package = f"curl.fuzzer.generated.{slug}"
    generated_file = f"generated/{slug}/{slug}.proto"

    root = _build_occurrences(model, profile, declaration.root_message)
    _assign_occurrence_names(root, generated_package, declaration.generated_root)
    projected, enum_symbol_map = _contextual_profile_descriptor(
        model=model,
        root=root,
        generated_package=generated_package,
        generated_file=generated_file,
    )
    descriptor_bytes = projected.SerializeToString(deterministic=True)
    schema_files = {
        str(file_proto.name): _render_schema_file(file_proto)
        for file_proto in projected.file
    }
    adapter_header = _render_contextual_adapter(
        model=model,
        profile=profile,
        root=root,
        enum_symbol_map=enum_symbol_map,
        generated_header=generated_file.removesuffix(".proto") + ".pb.h",
    )
    authoring_descriptor_bytes, authoring_schema_files = _stripped_authoring_artifacts(
        model
    )
    runtime_descriptor_bytes, runtime_schema_files, native_manifest = (
        _runtime_artifacts(model)
    )

    occurrences = _all_occurrences(root)
    retained_fields = sorted(
        {field.full_name for occurrence in occurrences for field in occurrence.fields}
    )
    retained_options = sorted(
        {
            str(field.native_name)
            for occurrence in occurrences
            for field in occurrence.fields
            if field.native_name is not None
        }
    )
    guarded = []
    for occurrence in occurrences:
        for field in occurrence.fields:
            applicable_guards = [
                guard for guard in field.eligibility.guards if profile in guard.profiles
            ]
            if not applicable_guards:
                continue
            guarded.append(
                {
                    "context": occurrence.context,
                    "field": field.full_name,
                    "guards": [
                        {
                            "expected": guard.expected,
                            "fact": guard.fact,
                            "profiles": sorted(guard.profiles),
                        }
                        for guard in applicable_guards
                    ],
                    "path": [*occurrence.path[1:], field.name],
                }
            )
    unique_shapes: dict[tuple[Any, ...], _MessageOccurrence] = {}
    for occurrence in occurrences:
        unique_shapes.setdefault(occurrence.signature, occurrence)
    shape_report = [
        {
            "context": occurrence.context,
            "fields": [field.full_name for field in occurrence.fields],
            "generated_type": occurrence.generated_full_name,
            "path": list(occurrence.path),
            "source_type": occurrence.source_name,
        }
        for occurrence in sorted(
            unique_shapes.values(), key=lambda item: item.generated_full_name
        )
    ]
    output_hashes = {
        "adapter_header_sha256": hashlib.sha256(adapter_header.encode()).hexdigest(),
        "authoring_descriptor_sha256": hashlib.sha256(
            authoring_descriptor_bytes
        ).hexdigest(),
        "authoring_schema_files": {
            name: hashlib.sha256(content.encode()).hexdigest()
            for name, content in sorted(authoring_schema_files.items())
        },
        "descriptor_sha256": hashlib.sha256(descriptor_bytes).hexdigest(),
        "native_manifest_sha256": hashlib.sha256(native_manifest.encode()).hexdigest(),
        "runtime_descriptor_sha256": hashlib.sha256(
            runtime_descriptor_bytes
        ).hexdigest(),
        "runtime_schema_files": {
            name: hashlib.sha256(content.encode()).hexdigest()
            for name, content in sorted(runtime_schema_files.items())
        },
        "schema_files": {
            name: hashlib.sha256(content.encode()).hexdigest()
            for name, content in sorted(schema_files.items())
        },
    }
    report: Mapping[str, Any] = {
        "conditional_guards": sorted(
            guarded, key=lambda item: (item["path"], item["field"])
        ),
        "cpp_target_profile": declaration.cpp_target_profile,
        "empty_option_policy": declaration.empty_option_policy,
        "generated_package": generated_package,
        "generator": GENERATOR_VERSION,
        "input_descriptor_sha256": model.descriptor_sha256,
        "output_hashes": output_hashes,
        "profile": profile,
        "projected_shapes": shape_report,
        "retained_fields": retained_fields,
        "retained_options": retained_options,
        "root_message": root.generated_full_name,
    }
    return Projection(
        profile=profile,
        root_message=root.generated_full_name,
        generated_package=generated_package,
        descriptor_bytes=descriptor_bytes,
        schema_files=schema_files,
        authoring_descriptor_bytes=authoring_descriptor_bytes,
        authoring_schema_files=authoring_schema_files,
        runtime_descriptor_bytes=runtime_descriptor_bytes,
        runtime_schema_files=runtime_schema_files,
        native_manifest=native_manifest,
        adapter_header=adapter_header,
        report=report,
    )


def _option_model_contract(
    model: SchemaModel,
) -> tuple[str, str, Mapping[str, FieldRule]]:
    option_fields = {
        field.full_name: field for field in model.fields.values() if field.is_option
    }
    option_messages = {field.containing_message for field in option_fields.values()}
    if len(option_messages) != 1:
        raise SchemaEligibilityError(
            "schema contracts require exactly one typed option message"
        )
    option_message = next(iter(option_messages))
    source_messages = _descriptor_messages(model.descriptor_set)
    descriptor = source_messages[option_message]
    oneof_indexes = {
        field.oneof_index
        for field in option_fields.values()
        if field.oneof_index is not None
    }
    if len(oneof_indexes) != 1 or any(
        field.oneof_index is None for field in option_fields.values()
    ):
        raise SchemaEligibilityError(
            "typed options must occupy exactly one option oneof"
        )
    oneof_index = next(iter(oneof_indexes))
    if oneof_index >= len(descriptor.oneof_decl):
        raise SchemaEligibilityError("typed option oneof index is out of range")
    return option_message, str(descriptor.oneof_decl[oneof_index].name), option_fields


def _root_options_field(
    model: SchemaModel, root_message: str, option_message: str
) -> FieldRule:
    candidates = [
        field
        for field in model.fields.values()
        if field.containing_message == root_message
        and field.type_name == option_message
        and field.label == descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
    ]
    if len(candidates) != 1:
        raise SchemaEligibilityError(
            f"{root_message} must have exactly one repeated typed-options field"
        )
    return candidates[0]


def _write_if_changed(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == data:
        return
    path.write_bytes(data)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor-set", required=True, type=pathlib.Path)
    parser.add_argument("--curl-header", required=True, type=pathlib.Path)
    parser.add_argument("--target-profile-header", required=True, type=pathlib.Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--projected-descriptor-out", required=True, type=pathlib.Path)
    parser.add_argument("--report-out", required=True, type=pathlib.Path)
    parser.add_argument("--schema-out-dir", type=pathlib.Path)
    parser.add_argument("--authoring-descriptor-out", type=pathlib.Path)
    parser.add_argument("--authoring-schema-out-dir", type=pathlib.Path)
    parser.add_argument("--runtime-descriptor-out", type=pathlib.Path)
    parser.add_argument("--runtime-schema-out-dir", type=pathlib.Path)
    parser.add_argument("--adapter-out", type=pathlib.Path)
    parser.add_argument("--native-manifest-out", type=pathlib.Path)
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    model = load_schema_model(args.descriptor_set.read_bytes())
    validate_native_options(model, parse_curl_header(args.curl_header))
    validate_cpp_target_profiles(model, args.target_profile_header)
    projection = project_profile(model, args.profile)
    _write_if_changed(args.projected_descriptor_out, projection.descriptor_bytes)
    _write_if_changed(args.report_out, projection.report_json().encode())
    if args.schema_out_dir is not None:
        for name, content in projection.schema_files.items():
            _write_if_changed(args.schema_out_dir / name, content.encode())
    if args.authoring_descriptor_out is not None:
        _write_if_changed(
            args.authoring_descriptor_out, projection.authoring_descriptor_bytes
        )
    if args.authoring_schema_out_dir is not None:
        for name, content in projection.authoring_schema_files.items():
            _write_if_changed(args.authoring_schema_out_dir / name, content.encode())
    if args.runtime_descriptor_out is not None:
        _write_if_changed(
            args.runtime_descriptor_out, projection.runtime_descriptor_bytes
        )
    if args.runtime_schema_out_dir is not None:
        for name, content in projection.runtime_schema_files.items():
            _write_if_changed(args.runtime_schema_out_dir / name, content.encode())
    if args.adapter_out is not None:
        _write_if_changed(args.adapter_out, projection.adapter_header.encode())
    if args.native_manifest_out is not None:
        _write_if_changed(args.native_manifest_out, projection.native_manifest.encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
