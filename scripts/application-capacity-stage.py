#!/usr/bin/env python3
"""Run and independently replay one host's 15 SourceV5 capacity calibrations.

The stage starts only source-pinned application binaries, verifies the actual
feedback-policy emitter before each capacity process, and seals a hash-chained
ledger before publishing a canonical completion overlay. Calibration remains
pre-confirmation evidence and is never qualification eligible.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, Callable


SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v5"
SPEC_SCHEMA = "allocatbelt.application-campaign-spec.v3"
PLAN_SCHEMA = "allocatbelt.application-campaign-plan.v3"
REQUEST_TEMPLATE_SCHEMA = "allocatbelt.application-capacity-request-template.v1"
CONTEXT_TEMPLATE_SCHEMA = "allocatbelt.application-capacity-context-template.v1"
HOST_CONTEXT_SCHEMA = "allocatbelt.application-capacity-host-context.v1"
CAPACITY_CONTEXT_SCHEMA = "allocatbelt.application-capacity-context.v1"
EXPECTATION_SCHEMA = "allocatbelt.application-feedback-expectation.v4"
EVENT_SCHEMA = "allocatbelt.application-capacity-stage-event.v1"
COMPLETION_SCHEMA = "allocatbelt.application-capacity-stage-completion.v1"
NONCE_SCHEMA = "allocatbelt.application-process-nonce-instantiation.v1"
STAGE_SOURCE_PATH = "scripts/application-capacity-stage.py"
CONTROLLER_PATH = "scripts/application-campaign.py"
INPUTS_PATH = "scripts/application-campaign-inputs.py"
FEEDBACK_READER_PATH = "scripts/application-feedback-readback.py"
CAPACITY_PRODUCER_PATH = "scripts/application-byte-capacity.py"

MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
MAX_PROBE_BYTES = 512 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 4 * 1024 * 1024
MAX_TRACE_FILE_BYTES = 1024 * 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_EVENT_LINE_BYTES = 2 * 1024 * 1024
MAX_EVENT_RECORDS = 256
MAX_PATH_BYTES = 4096
U64_MAX = (1 << 64) - 1
WORKLOADS = ("cpu", "memory", "http", "disk", "mixed")
PROFILES = {
    "cpu": ("steady", "burst", "oversubscribed"),
    "memory": ("steady", "burst", "oversubscribed"),
    "http": ("steady", "burst", "oversubscribed"),
    "disk": ("steady", "burst", "oversubscribed"),
    "mixed": ("mixed", "burst", "oversubscribed"),
}
JOB_EVENTS = (
    "probe_dispatch", "probe_completed", "probe_verified", "application_dispatch",
    "application_bound", "application_exited", "trace_captured", "feedback_verified",
    "bundle_verified",
)
JOB_EVENT_DETAIL_FIELDS = {
    "probe_dispatch": {
        "argv", "cwd", "environment", "expected_binary_sha256", "deadline_seconds",
        "stdout_path", "stderr_path",
    },
    "probe_completed": {
        "pid", "process_identity", "return_code", "status", "signal", "elapsed_ns",
        "stdout_path", "stdout_sha256", "stdout_size", "stderr_path", "stderr_sha256",
        "stderr_size", "stderr_empty",
    },
    "probe_verified": {
        "probe", "probe_sha256", "policy_sha256", "expectation_seed_sha256",
        "request_template_copy", "context_template_copy", "source_manifest",
    },
    "application_dispatch": {
        "argv", "cwd", "environment", "trace_directory", "tmpdir_path",
        "expected_binary_sha256", "process_deadline_seconds", "mode",
        "capacity_horizon_seconds", "external_pressure", "pressure_qualification",
        "storage_context", "network_context", "probe", "policy_sha256",
    },
    "application_bound": {
        "pid", "start_ticks", "executable_path", "executable_sha256", "nonce", "cwd",
        "cpu_affinity", "network_namespace_inode", "environment", "environment_sha256",
        "tmpdir_path", "trace_directory", "external_pressure", "pressure_qualification",
    },
    "application_exited": {
        "pid", "return_code", "status", "signal", "elapsed_ns", "stdout", "stderr",
        "stdout_sha256", "stderr_sha256", "stdout_size", "stderr_size", "process_seconds",
    },
    "trace_captured": {"traces", "trace_hashes", "trace_directory", "application_pid"},
    "feedback_verified": {
        "expectation", "expectation_sha256", "validation", "validation_sha256",
        "validator_sha256", "trace_hashes", "application_pid", "process_identity_sha256",
    },
    "bundle_verified": {
        "request", "expectation", "context", "traces", "validation", "artifact", "receipt",
        "probe", "actual_pid", "actual_start_ticks", "actual_executable_sha256",
        "producer_sha256", "feedback_reader_sha256", "qualification_eligible",
    },
}


class CapacityStageError(ValueError):
    """A frozen input, bounded process, trace, or completion failed validation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CapacityStageError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise CapacityStageError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value: object, label: str = "SHA-256") -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            f"{label} is malformed")
    return value


def token(value: object, label: str, maximum: int = 128) -> str:
    require(type(value) is str and 0 < len(value) <= maximum and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is not None,
            f"{label} is malformed")
    return value


def uint(value: object, label: str, *, positive: bool = False,
         maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} is not a bounded unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected field set")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise CapacityStageError(f"non-finite JSON value is forbidden: {value}")


def parse_object(raw: bytes, label: str, maximum: int, *, canonical: bool = False) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its finite size bound")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CapacityStageError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must be a JSON object")
    if canonical:
        require(canonical_bytes(value) == raw, f"{label} is not canonical JSON")
    return value


def _path_text(path: Path, label: str) -> str:
    text = str(path)
    require(path.is_absolute() and text == os.path.normpath(text) and len(os.fsencode(text)) <= MAX_PATH_BYTES,
            f"{label} must be a normalized bounded absolute path")
    require("\x00" not in text, f"{label} contains a NUL byte")
    return text


def _stat_key(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read_stable(path: Path, label: str, maximum: int, *, allow_proc: bool = False) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not allow_proc:
        flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CapacityStageError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(before_path),
                f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its finite size bound")
        chunks: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated during its stable read")
            count += len(block)
            chunks.append(block)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before) == _stat_key(after) == _stat_key(after_path) and
                count == before.st_size, f"{label} changed during its stable read")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def hash_stable(path: Path, label: str, maximum: int) -> tuple[int, str]:
    """Hash a bounded regular file in chunks and check its descriptor/path snapshot."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CapacityStageError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(before_path),
                f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its finite size bound")
        digestor = hashlib.sha256()
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated during its stable hash")
            count += len(block)
            digestor.update(block)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before) == _stat_key(after) == _stat_key(after_path) and
                count == before.st_size, f"{label} changed while hashing")
        return count, digestor.hexdigest()
    finally:
        os.close(descriptor)


def read_pin(pin: object, label: str, maximum: int, *, canonical: bool = False) -> tuple[dict[str, Any], bytes, str]:
    value = exact(pin, {"path", "sha256"}, f"{label} pin")
    path = Path(value["path"])
    _path_text(path, f"{label} path")
    expected = digest(value["sha256"], f"{label} raw SHA-256")
    raw, _info = read_stable(path, label, maximum)
    require(sha256_bytes(raw) == expected, f"{label} differs from its caller-pinned raw SHA-256")
    return parse_object(raw, label, maximum, canonical=canonical), raw, expected


def _safe_root(path: Path, label: str) -> Path:
    _path_text(path, label)
    try:
        before = path.lstat()
        require(stat.S_ISDIR(before.st_mode), f"{label} must be a real nonsymlink directory")
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CapacityStageError(f"{label} is unavailable: {error}") from error
    require(resolved == path, f"{label} path contains a symlink or alias")
    return resolved


def _relative(value: object, label: str) -> PurePosixPath:
    require(type(value) is str and value and "\\" not in value and "\x00" not in value,
            f"{label} is malformed")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            all(part not in ("", ".", "..") for part in path.parts),
            f"{label} must be a normalized relative path")
    require(not any(ord(character) < 32 or ord(character) == 127 for character in value),
            f"{label} contains a control character")
    return path


def _safe_child(root: Path, relative: object, label: str) -> Path:
    rel = _relative(relative, label)
    cursor = root
    for part in rel.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError as error:
            raise CapacityStageError(f"{label} is missing: {error}") from error
        require(not stat.S_ISLNK(info.st_mode), f"{label} traverses a symlink")
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise CapacityStageError(f"{label} is missing or escaped its root") from error
    return resolved


def _source_records(source: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = source.get("source", {}).get("files")
    require(type(records) is list and records, "SourceV5 typed inventory is missing")
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(records):
        require(type(value) is dict, f"SourceV5 inventory entry {index} is malformed")
        record = value
        relative = str(_relative(record.get("path"), f"SourceV5 inventory path {index}"))
        require(relative not in result, f"SourceV5 inventory repeats {relative}")
        result[relative] = record
    return result


def _source_file(
    source_root: Path, source: dict[str, Any], relative: str, label: str,
    maximum: int = MAX_SCRIPT_BYTES, harness_name: str | None = None,
) -> tuple[bytes, str, dict[str, Any]]:
    records = _source_records(source)
    record = exact(records.get(relative), {"path", "kind", "mode", "sha256", "size"},
                   f"{label} regular source inventory entry")
    require(record["path"] == relative and record["kind"] == "file" and
            record["mode"] in ("100644", "100755"),
            f"{label} is not a regular file inventory entry")
    expected_sha = digest(record["sha256"], f"{label} source SHA-256")
    size = uint(record["size"], f"{label} source size", maximum=maximum)
    if harness_name is not None:
        harness = source.get("qualification_harness")
        require(type(harness) is dict and harness_name in harness,
                f"SourceV5 harness has no {label} pin")
        pin = exact(harness[harness_name], {"path", "sha256"}, f"SourceV5 {label} harness pin")
        require(pin == {"path": relative, "sha256": expected_sha},
                f"SourceV5 {label} harness pin differs from its regular inventory entry")
    path = _safe_child(source_root, relative, f"pinned {label}")
    raw, info = read_stable(path, f"pinned {label}", maximum)
    mode = stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode)
    require(mode == int(record["mode"], 8) and len(raw) == size and sha256_bytes(raw) == expected_sha,
            f"pinned {label} bytes, mode, or size differ from SourceV5")
    return raw, expected_sha, record


def _load_module(raw: bytes, path: Path, label: str) -> types.ModuleType:
    module = types.ModuleType(f"capacity_stage_{path.stem.replace('-', '_')}_{sha256_bytes(raw)}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except Exception as error:
        raise CapacityStageError(f"captured {label} cannot be compiled: {error}") from error
    return module


def _capture_source_stack(
    source_root: Path, source: dict[str, Any], active_stage_path: Path,
) -> dict[str, Any]:
    require(source.get("schema") == SOURCE_SCHEMA, "capacity stage requires SourceV5")
    stage_raw, stage_sha, _stage_record = _source_file(
        source_root, source, STAGE_SOURCE_PATH, "capacity stage", maximum=MAX_SCRIPT_BYTES,
    )
    active_raw, _active_info = read_stable(active_stage_path, "active capacity stage", MAX_SCRIPT_BYTES)
    require(sha256_bytes(active_raw) == stage_sha and active_raw == stage_raw,
            "active capacity stage differs from its exact SourceV5 inventory entry")
    modules: dict[str, tuple[types.ModuleType, str]] = {}
    requested = (
        ("controller", CONTROLLER_PATH, "campaign_controller"),
        ("inputs", INPUTS_PATH, None),
        ("feedback_reader", FEEDBACK_READER_PATH, "feedback_validator"),
        ("capacity_producer", CAPACITY_PRODUCER_PATH, "byte_capacity_producer"),
    )
    for name, relative, harness_name in requested:
        raw, source_sha, _record = _source_file(
            source_root, source, relative, name.replace("_", " "),
            maximum=MAX_SOURCE_FILE_BYTES if name == "inputs" else MAX_SCRIPT_BYTES,
            harness_name=harness_name,
        )
        module = _load_module(raw, source_root / relative, name.replace("_", " "))
        modules[name] = (module, source_sha)
    controller, controller_sha = modules["controller"]
    inputs, inputs_sha = modules["inputs"]
    reader, reader_sha = modules["feedback_reader"]
    producer, producer_sha = modules["capacity_producer"]
    require(getattr(controller, "SOURCE_SCHEMA_V5", None) == SOURCE_SCHEMA and
            getattr(controller, "SPEC_SCHEMA_V3", None) == SPEC_SCHEMA and
            getattr(controller, "PLAN_SCHEMA_V3", None) == PLAN_SCHEMA and
            callable(getattr(controller, "verify_source_manifest", None)) and
            callable(getattr(controller, "validate_spec", None)) and
            callable(getattr(controller, "verify_plan", None)),
            "captured SourceV5 campaign controller contract is unsupported")
    require(getattr(inputs, "SOURCE_V5_SCHEMA", None) == SOURCE_SCHEMA and
            getattr(inputs, "SPEC_V3_SCHEMA", None) == SPEC_SCHEMA and
            getattr(inputs, "PLAN_V3_SCHEMA", None) == PLAN_SCHEMA and
            callable(getattr(inputs, "validate_qualification_plan_maps", None)),
            "captured SourceV5 campaign-inputs contract is unsupported")
    require(getattr(reader, "EXPECTATION_SCHEMA_V4", None) == EXPECTATION_SCHEMA and
            callable(getattr(reader, "validate_construction_probe", None)) and
            callable(getattr(reader, "verify_feedback", None)),
            "captured SourceV5 feedback reader lacks full V4 trace replay")
    require(getattr(producer, "REQUEST_SCHEMA", None) == "allocatbelt.application-byte-capacity-request.v1" and
            callable(getattr(producer, "verify_capacity_bundle", None)) and
            callable(getattr(producer, "publish_bundle", None)),
            "captured SourceV5 byte-capacity producer contract is unsupported")
    require(getattr(inputs, "NONCE_INSTANTIATION_SCHEMA", None) == NONCE_SCHEMA and
            getattr(inputs, "NONCE_INSTANTIATION_RULE", None) ==
            "sha256(template_nonce,campaign_id,job_run_id,pair_member,ordinal)",
            "captured SourceV5 nonce-instantiation contract is unsupported")
    harness = source.get("qualification_harness")
    require(type(harness) is dict and harness.get("campaign_controller", {}).get("sha256") == controller_sha and
            harness.get("feedback_validator", {}).get("sha256") == reader_sha and
            harness.get("byte_capacity_producer", {}).get("sha256") == producer_sha,
            "SourceV5 harness and captured source imports disagree")
    return {
        "controller": controller, "inputs": inputs, "feedback_reader": reader,
        "capacity_producer": producer,
        "stage_sha256": stage_sha, "controller_sha256": controller_sha,
        "inputs_sha256": inputs_sha, "feedback_reader_sha256": reader_sha,
        "capacity_producer_sha256": producer_sha,
    }


def _source_manifest_refs(spec: dict[str, Any], spec_path: Path) -> dict[str, tuple[Path, dict[str, Any], bytes, str]]:
    refs = spec.get("source_manifests")
    require(type(refs) is list and len(refs) == 3, "SourceV5 spec must bind all three host manifests")
    result: dict[str, tuple[Path, dict[str, Any], bytes, str]] = {}
    parent = spec_path.parent
    for index, ref_value in enumerate(refs):
        ref = exact(ref_value, {"host_id", "relative_path", "sha256"}, f"source manifest ref[{index}]")
        host_id = token(ref["host_id"], f"source manifest host[{index}]")
        require(host_id not in result, f"duplicate source manifest host {host_id}")
        relative = _relative(ref["relative_path"], f"source manifest path for {host_id}")
        path = _safe_child(parent, relative.as_posix(), f"{host_id} source manifest")
        raw, _info = read_stable(path, f"{host_id} source manifest", MAX_MANIFEST_BYTES)
        value = parse_object(raw, f"{host_id} source manifest", MAX_MANIFEST_BYTES, canonical=True)
        semantic = digest(ref["sha256"], f"{host_id} semantic source SHA-256")
        require(value.get("manifest_sha256") == semantic, f"{host_id} manifest semantic digest differs from its spec pin")
        result[host_id] = (path, value, raw, sha256_bytes(raw))
    return result


def _prepare_pins(
    plan_pin: object, spec_pin: object, source_root_arg: Path, input_root_arg: Path,
    host_id: str, observed_host_pin: object,
) -> dict[str, Any]:
    spec, spec_raw, spec_raw_sha = read_pin(spec_pin, "campaign spec", MAX_SPEC_BYTES, canonical=True)
    plan, plan_raw, plan_raw_sha = read_pin(plan_pin, "campaign plan", MAX_PLAN_BYTES, canonical=True)
    spec_path = Path(exact(spec_pin, {"path", "sha256"}, "campaign spec pin")["path"])
    plan_path = Path(exact(plan_pin, {"path", "sha256"}, "campaign plan pin")["path"])
    source_root = _safe_root(source_root_arg, "SourceV5 root")
    input_root = _safe_root(input_root_arg, "campaign input root")
    host_id = token(host_id, "host ID")
    require(not _is_within(source_root, input_root), "campaign input root must be outside SourceV5")
    refs = _source_manifest_refs(spec, spec_path)
    require(host_id in refs, "selected host has no SourceV5 source-manifest pin")
    sources = {name: value[1] for name, value in refs.items()}
    selected_source_path, selected_source, selected_source_raw, selected_source_raw_sha = refs[host_id]
    require(spec.get("schema") == SPEC_SCHEMA and plan.get("schema") == PLAN_SCHEMA,
            "capacity stage requires campaign spec V3 and plan V3")
    require(spec.get("campaign_id") == plan.get("campaign_id"), "spec and plan campaign IDs differ")
    require(plan.get("spec_sha256") == _controller_digest_object(spec),
            "plan semantic spec digest differs from the pinned campaign spec")
    require(plan.get("source_manifests") == {name: value[1]["manifest_sha256"] for name, value in refs.items()},
            "plan source-manifest pins differ from the raw spec host manifests")
    stack = _capture_source_stack(source_root, selected_source, Path(__file__).resolve())
    controller = stack["controller"]
    try:
        for other_host, source in sources.items():
            controller.verify_source_manifest(
                source,
                source_root if other_host == host_id else None,
                verify_artifacts=(other_host == host_id),
            )
    except Exception as error:
        if isinstance(error, CapacityStageError):
            raise
        raise CapacityStageError(f"captured SourceV5 full source-manifest verifier rejected an input: {error}") from error
    # Check imports for every SourceV5 host. The selected host's source tree is
    # independently rebuilt above; all hosts must name the same exact modules.
    for other_host, source in sources.items():
        other_stack = _capture_source_stack(source_root, source, Path(__file__).resolve())
        require(
            {name: other_stack[f"{name}_sha256"] for name in (
                "stage", "controller", "inputs", "feedback_reader", "capacity_producer",
            )} ==
            {name: stack[f"{name}_sha256"] for name in (
                "stage", "controller", "inputs", "feedback_reader", "capacity_producer",
            )},
            f"SourceV5 captured imports differ between hosts ({host_id} and {other_host})",
        )
    inputs_sha = controller.campaign_inputs_source_sha256(sources)
    require(inputs_sha == stack["inputs_sha256"], "campaign-inputs import differs from the common SourceV5 module pin")
    try:
        validation = controller.validate_spec(spec, sources, input_root)
        controller.verify_plan(plan, selected_source["runtime_readback_validator"]["sha256"], inputs_sha)
    except Exception as error:
        raise CapacityStageError(f"captured SourceV5 spec/plan validation failed: {error}") from error
    require(validation.get("plan_sha256") in (None, plan.get("plan_sha256")),
            "campaign spec validator returned an unexpected plan digest")
    require(host_id in plan.get("host_ids", []), "selected host is absent from the frozen plan")
    host_records = [item for item in spec.get("hosts", []) if type(item) is dict and item.get("host_id") == host_id]
    require(len(host_records) == 1, "selected host contract is missing or duplicated")
    host = host_records[0]
    observed, observed_raw, observed_raw_sha = read_pin(
        observed_host_pin, "observed host context", MAX_TEMPLATE_BYTES, canonical=True,
    )
    current_host = _verify_observed_host(observed, host, host_id)
    require(not _is_within(source_root, Path(exact(observed_host_pin, {"path", "sha256"}, "observed host pin")["path"])),
            "observed host context must be stored outside SourceV5")
    prepared = {
        "plan": plan, "plan_path": plan_path, "plan_raw": plan_raw,
        "plan_raw_sha256": plan_raw_sha, "plan_semantic_sha256": plan["plan_sha256"],
        "spec": spec, "spec_path": spec_path, "spec_raw": spec_raw,
        "spec_raw_sha256": spec_raw_sha, "spec_semantic_sha256": _controller_digest_object(spec),
        "source_root": source_root, "input_root": input_root, "host_id": host_id,
        "host": host, "host_context": observed, "host_context_raw": observed_raw,
        "host_context_raw_sha256": observed_raw_sha,
        "host_context_path": Path(exact(observed_host_pin, {"path", "sha256"}, "observed host pin")["path"]),
        "current_host": current_host, "sources": sources,
        "source": selected_source, "source_path": selected_source_path,
        "source_raw": selected_source_raw, "source_raw_sha256": selected_source_raw_sha,
        "source_semantic_sha256": selected_source["manifest_sha256"],
        "source_tree_sha256": selected_source["source"]["source_tree_sha256"],
        "stack": stack, "validation": validation,
    }
    _verify_captured_nonce_rule(derive_capacity_jobs(plan, host_id), prepared)
    return prepared


def _controller_digest_object(value: object) -> str:
    return sha256_bytes(canonical_bytes(value))


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _parse_cpu_set(value: object) -> list[int]:
    require(type(value) is str and value, "frozen host CPU set is malformed")
    parts = value.split(",")
    result: list[int] = []
    for part in parts:
        match = re.fullmatch(r"(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*))?", part)
        require(match is not None, "frozen host CPU set is not a canonical Linux CPU list")
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) is not None else low
        require(low <= high and high - low <= 65535, "frozen host CPU range is invalid or too large")
        result.extend(range(low, high + 1))
    require(result == sorted(set(result)), "frozen host CPU set repeats or reorders a CPU")
    return result


def _live_cpu_model() -> str:
    try:
        descriptor = os.open(
            "/proc/cpuinfo", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            chunks: list[bytes] = []
            count = 0
            while True:
                block = os.read(descriptor, min(1024 * 1024, 16 * 1024 * 1024 + 1 - count))
                if not block:
                    break
                count += len(block)
                require(count <= 16 * 1024 * 1024, "live CPU information exceeds its bound")
                chunks.append(block)
            raw = b"".join(chunks)
        finally:
            os.close(descriptor)
        text = raw.decode("utf-8")
    except (UnicodeError, OSError) as error:
        raise CapacityStageError(f"cannot read live CPU model: {error}") from error
    models = {
        line.split(":", 1)[1].strip()
        for line in text.splitlines()
        if line.lower().startswith("model name") and ":" in line
    }
    require(len(models) == 1, "live CPU model is missing or heterogeneous")
    return next(iter(models))


def _boot_id_sha256() -> str:
    try:
        raw = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
    except OSError as error:
        raise CapacityStageError(f"cannot read host boot identity: {error}") from error
    require(bool(raw) and b"\n" not in raw, "host boot identity is malformed")
    return sha256_bytes(raw)


def _verify_observed_host(value: dict[str, Any], host: dict[str, Any], host_id: str) -> dict[str, Any]:
    exact(value, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity", "network_namespace_inode",
    }, "observed host context")
    require(value["schema"] == HOST_CONTEXT_SCHEMA and value["host_id"] == host_id,
            "observed host context schema or host ID differs")
    digest(value["boot_id_sha256"], "observed boot ID SHA-256")
    controls = exact(host.get("controls"), {
        "cpu_model", "microcode_sha256", "kernel_release", "governor", "frequency_policy",
        "boost_policy", "cpu_set", "numa_policy", "cgroup_policy_sha256",
        "background_load_policy_sha256", "x86_64_v3_capability_sha256", "target_triple", "target_cpu",
    }, "frozen host controls")
    require(value["controls"] == controls and
            value["controls_sha256"] == host["host_fingerprint_sha256"] == sha256_bytes(canonical_bytes(controls)),
            "observed controls do not match the exact frozen host fingerprint")
    require(value["kernel_release"] == controls["kernel_release"] and
            value["cpu_model"] == controls["cpu_model"],
            "observed kernel or CPU model differs from frozen controls")
    cpu_values = value["cpu_affinity"]
    require(type(cpu_values) is list and cpu_values and
            all(type(item) is int and 0 <= item <= 65535 for item in cpu_values) and
            cpu_values == sorted(set(cpu_values)), "observed CPU affinity is malformed")
    expected_cpu_values = _parse_cpu_set(controls["cpu_set"])
    require(cpu_values == expected_cpu_values, "observed CPU affinity differs from the frozen host CPU set")
    uint(value["network_namespace_inode"], "observed network namespace inode", positive=True)
    current_affinity = sorted(os.sched_getaffinity(0))
    require(current_affinity == cpu_values, "live inherited CPU affinity differs from the pinned observed host")
    require(platform.release() == value["kernel_release"], "live kernel release differs from observed host context")
    require(_live_cpu_model() == value["cpu_model"], "live CPU model differs from observed host context")
    require(_boot_id_sha256() == value["boot_id_sha256"], "live boot identity differs from observed host context")
    current_netns = os.stat("/proc/self/ns/net").st_ino
    require(current_netns == value["network_namespace_inode"], "live network namespace differs from observed host context")
    return {
        "boot_id_sha256": value["boot_id_sha256"], "cpu_affinity": cpu_values,
        "kernel_release": value["kernel_release"], "cpu_model": value["cpu_model"],
        "network_namespace_inode": current_netns,
    }


def derive_capacity_jobs(plan: dict[str, Any], host_id: str) -> list[dict[str, Any]]:
    """Derive the exact 15 host jobs without reordering frozen plan templates."""
    require(type(plan) is dict and plan.get("schema") == PLAN_SCHEMA,
            "capacity scheduling requires plan V3")
    host_id = token(host_id, "host ID")
    templates = plan.get("capacity_process_templates")
    require(type(templates) is list and len(templates) == 45,
            "plan does not contain the frozen 45 capacity process templates")
    templates_sha = digest(plan.get("capacity_process_templates_sha256"), "capacity template schedule SHA-256")
    require(sha256_bytes(canonical_bytes(templates)) == templates_sha,
            "capacity template schedule digest differs from the plan")
    campaign_id = token(plan.get("campaign_id"), "campaign ID")
    selected: list[dict[str, Any]] = []
    observed_contexts: set[tuple[str, str]] = set()
    for index, value in enumerate(templates):
        require(type(value) is dict, f"capacity process template[{index}] is malformed")
        key = exact(value.get("capacity_key"), {"host_id", "workload", "profile", "calibration_id"},
                    f"capacity process template[{index}] key")
        if key["host_id"] != host_id:
            continue
        workload = token(key["workload"], f"capacity process template[{index}] workload")
        profile = token(key["profile"], f"capacity process template[{index}] profile")
        calibration_id = token(key["calibration_id"], f"capacity process template[{index}] calibration ID")
        require(workload in WORKLOADS and profile in PROFILES[workload],
                f"capacity template[{index}] is outside the frozen 15-context matrix")
        context_key = (workload, profile)
        require(context_key not in observed_contexts, f"capacity template repeats {context_key}")
        observed_contexts.add(context_key)
        body = {name: item for name, item in value.items() if name != "template_sha256"}
        template_sha = digest(value.get("template_sha256"), f"capacity template[{index}] SHA-256")
        require(sha256_bytes(canonical_bytes(body)) == template_sha,
                f"capacity template[{index}] digest differs from its fields")
        request_pin = exact(value.get("request_template"), {"relative_path", "raw_sha256"},
                            f"capacity template[{index}] request pin")
        context_pin = exact(value.get("context_template"), {"relative_path", "raw_sha256"},
                            f"capacity template[{index}] context pin")
        _relative(request_pin["relative_path"], "capacity request template relative path")
        _relative(context_pin["relative_path"], "capacity context template relative path")
        digest(request_pin["raw_sha256"], "capacity request template raw SHA-256")
        digest(context_pin["raw_sha256"], "capacity context template raw SHA-256")
        require(request_pin["relative_path"] != context_pin["relative_path"],
                "capacity request and context templates alias one file")
        calibrator = exact(value.get("calibrator"), {"allocator", "executor"},
                           f"capacity template[{index}] calibrator")
        allocator = token(calibrator["allocator"], "capacity allocator")
        executor = token(calibrator["executor"], "capacity executor")
        require(allocator in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system") and
                executor in ("bounded", "tokio"), "capacity calibrator role is unsupported")
        prospective_nonce = value.get("prospective_nonce")
        require(type(prospective_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", prospective_nonce),
                "capacity prospective nonce is malformed")
        nonce_material = {
            "template_nonce": prospective_nonce, "campaign_id": campaign_id,
            "job_run_id": "cap-" + sha256_bytes(canonical_bytes([
                campaign_id, host_id, calibration_id, template_sha,
            ]))[:48],
            "pair_member": "capacity", "ordinal": 1,
        }
        run_id = nonce_material["job_run_id"]
        nonce = sha256_bytes(
            (NONCE_SCHEMA + "\0").encode("ascii") + canonical_bytes(nonce_material)
        )[:32]
        nonce_record = {
            "schema": NONCE_SCHEMA, "template_nonce": prospective_nonce,
            "campaign_id": campaign_id, "job_run_id": run_id,
            "pair_member": "capacity", "ordinal": 1, "nonce": nonce,
        }
        require(value.get("nonce_instantiation_schema") == NONCE_SCHEMA and
                value.get("nonce_instantiation_rule") ==
                "sha256(template_nonce,campaign_id,job_run_id,pair_member,ordinal)" and
                value.get("nonce_scope") == "reusable_template",
                f"capacity template[{index}] nonce scope/rule differs from SourceV5")
        require(value.get("required_proofs") == [
            "capacity_artifact", "capacity_receipt", "pre_confirmation_stage_receipt",
        ], f"capacity template[{index}] proof roles differ from SourceV5")
        selected.append({
            "ordinal": 1, "template_index": index, "template": value,
            "capacity_key": key, "template_sha256": template_sha,
            "run_id": run_id, "nonce": nonce, "nonce_instantiation": nonce_record,
        })
    require(len(selected) == 15 and len(observed_contexts) == 15,
            f"selected host must have exactly 15 unique capacity contexts; found {len(selected)}")
    return selected


def _verify_captured_nonce_rule(jobs: list[dict[str, Any]], context: dict[str, Any]) -> None:
    inputs = context["stack"]["inputs"]
    require(getattr(inputs, "NONCE_INSTANTIATION_SCHEMA", None) == NONCE_SCHEMA and
            getattr(inputs, "NONCE_INSTANTIATION_RULE", None) ==
            "sha256(template_nonce,campaign_id,job_run_id,pair_member,ordinal)",
            "captured SourceV5 nonce-instantiation contract changed after preflight")
    for job in jobs:
        material = {
            "template_nonce": job["template"]["prospective_nonce"],
            "campaign_id": context["spec"]["campaign_id"],
            "job_run_id": job["run_id"],
            "pair_member": "capacity",
            "ordinal": 1,
        }
        expected = sha256_bytes(
            (NONCE_SCHEMA + "\0").encode("ascii") + canonical_bytes(material)
        )[:32]
        require(expected == job["nonce"],
                f"capacity job {job['run_id']} nonce differs from the captured SourceV5 v1 rule")


def _validate_templates(input_root: Path, job: dict[str, Any]) -> tuple[dict[str, Any], str, dict[str, Any], str]:
    template = job["template"]
    request_pin = template["request_template"]
    context_pin = template["context_template"]
    request_path = _safe_child(input_root, request_pin["relative_path"], "capacity request template")
    context_path = _safe_child(input_root, context_pin["relative_path"], "capacity context template")
    request_raw, _request_info = read_stable(request_path, "capacity request template", MAX_TEMPLATE_BYTES)
    context_raw, _context_info = read_stable(context_path, "capacity context template", MAX_TEMPLATE_BYTES)
    request_sha = sha256_bytes(request_raw)
    context_sha = sha256_bytes(context_raw)
    require(request_sha == request_pin["raw_sha256"] and context_sha == context_pin["raw_sha256"],
            "capacity request/context template bytes differ from the frozen plan pins")
    request = parse_object(request_raw, "capacity request template", MAX_TEMPLATE_BYTES, canonical=True)
    context = parse_object(context_raw, "capacity context template", MAX_TEMPLATE_BYTES, canonical=True)
    exact(request, {"schema", "minimum_interval_seconds"}, "capacity request template")
    require(request["schema"] == REQUEST_TEMPLATE_SCHEMA,
            "capacity request template schema is unsupported")
    minimum = uint(request["minimum_interval_seconds"], "capacity minimum interval", positive=True, maximum=30)
    require(10 <= minimum <= 30, "capacity minimum interval must remain within the producer's 10–30 second contract")
    exact(context, {"schema", "storage", "network"}, "capacity context template")
    require(context["schema"] == CONTEXT_TEMPLATE_SCHEMA,
            "capacity context template schema is unsupported")
    workload = job["capacity_key"]["workload"]
    storage_required = workload in ("disk", "mixed")
    network_required = workload in ("http", "mixed")
    if storage_required:
        storage = exact(context["storage"], {
            "scope", "root_path", "filesystem_type", "device_major_minor", "minimum_free_bytes",
        }, "capacity storage context template")
        require(storage["scope"] == "application_file_io",
                "capacity storage scope must describe application file I/O")
        root = Path(storage["root_path"])
        _path_text(root, "capacity storage root")
        require(storage["filesystem_type"] and type(storage["filesystem_type"]) is str and
                re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", storage["filesystem_type"]) is not None,
                "capacity storage filesystem type is malformed")
        require(type(storage["device_major_minor"]) is str and
                re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", storage["device_major_minor"]) is not None,
                "capacity storage device major/minor is malformed")
        uint(storage["minimum_free_bytes"], "capacity minimum free bytes", positive=True)
    else:
        require(context["storage"] is None,
                f"{workload} capacity template must not claim an application file-I/O context")
    if network_required:
        network = exact(context["network"], {
            "scope", "interface", "address", "namespace_inode",
        }, "capacity network context template")
        require(network == {
            "scope": "ipv4_loopback_application_bytes", "interface": "lo",
            "address": "127.0.0.1", "namespace_inode": network["namespace_inode"],
        }, "capacity network context must describe measured IPv4 loopback application bytes")
        uint(network["namespace_inode"], "capacity network namespace inode", positive=True)
    else:
        require(context["network"] is None,
                f"{workload} capacity template must not claim network application bytes")
    return request, request_sha, context, context_sha


def _mount_context(path: Path) -> tuple[str, str]:
    """Return observed filesystem type and major:minor for the longest mount."""
    target = str(path.resolve(strict=True))
    best: tuple[int, str, str] | None = None
    try:
        raw = Path("/proc/self/mountinfo").read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise CapacityStageError(f"cannot read mounted filesystem identity: {error}") from error
    for line in text.splitlines():
        fields = line.split(" ")
        try:
            separator = fields.index("-")
            mountpoint = fields[4]
            device = fields[2]
            filesystem = fields[separator + 1]
        except (ValueError, IndexError):
            continue
        mountpoint = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), mountpoint)
        prefix = mountpoint.rstrip("/") or "/"
        if prefix == "/" or target == prefix or target.startswith(prefix + "/"):
            candidate = (len(prefix), filesystem, device)
            if best is None or candidate[0] > best[0]:
                best = candidate
    require(best is not None, "storage root has no observed mount record")
    return best[1], best[2]


def _storage_snapshot(storage_template: dict[str, Any], source_root: Path,
                      tmpdir: Path) -> dict[str, Any]:
    root = _safe_root(Path(storage_template["root_path"]), "capacity storage root")
    require(not _is_within(source_root, root), "capacity storage root is inside SourceV5")
    require(_is_within(root, tmpdir), "application TMPDIR is outside its frozen storage root")
    observed_fs, observed_device = _mount_context(root)
    st = root.stat()
    device = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    require(observed_fs == storage_template["filesystem_type"] and
            device == storage_template["device_major_minor"] and
            observed_device == device,
            "observed storage filesystem/device differs from the typed capacity context")
    vfs = os.statvfs(root)
    available = vfs.f_bavail * vfs.f_frsize
    minimum = uint(storage_template["minimum_free_bytes"], "minimum free bytes", positive=True)
    require(available >= minimum, "observed storage free space is below the typed minimum")
    return {
        **storage_template, "root_path": str(root), "tmpdir_path": str(tmpdir),
        "available_bytes_at_launch": available,
    }


def _network_snapshot(network_template: dict[str, Any], host_context: dict[str, Any]) -> dict[str, Any]:
    netns = os.stat("/proc/self/ns/net").st_ino
    require(netns == host_context["network_namespace_inode"] == network_template["namespace_inode"],
            "observed network namespace differs from the pinned loopback context")
    interface_alias = Path("/sys/class/net/lo")
    try:
        interface = interface_alias.resolve(strict=True)
        interface.relative_to(Path("/sys"))
    except (OSError, ValueError) as error:
        raise CapacityStageError("IPv4 loopback interface is missing or escaped sysfs") from error
    require(interface.is_dir(), "IPv4 loopback interface is unavailable")
    try:
        ifindex_raw = (interface / "ifindex").read_text(encoding="ascii").strip()
        state = (interface / "operstate").read_text(encoding="ascii").strip()
        loopback = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            loopback.bind(("127.0.0.1", 0))
            address = loopback.getsockname()[0]
        finally:
            loopback.close()
    except (OSError, UnicodeError) as error:
        raise CapacityStageError(f"cannot observe the IPv4 loopback interface: {error}") from error
    require(re.fullmatch(r"[1-9][0-9]*", ifindex_raw) is not None and
            state in ("up", "unknown") and address == "127.0.0.1",
            "IPv4 loopback interface is down or its identity is malformed")
    return {**network_template, "ifindex": int(ifindex_raw)}


def _mkdir_private(path: Path, *, parents: bool = False) -> None:
    try:
        path.mkdir(mode=0o700, parents=parents, exist_ok=False)
    except FileExistsError as error:
        raise CapacityStageError(f"refusing to reuse existing private directory: {path}") from error
    except OSError as error:
        raise CapacityStageError(f"cannot create private directory {path}: {error}") from error
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
            info.st_uid == os.getuid(), f"private directory has unexpected owner or mode: {path}")


def _mkdir_components(path: Path) -> None:
    """Create missing output parents while checking each existing component."""
    _path_text(path, "private output directory")
    cursor = Path(path.anchor)
    for component in path.parts[1:]:
        cursor = cursor / component
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            try:
                cursor.mkdir(mode=0o700)
            except OSError as error:
                raise CapacityStageError(f"cannot create private output parent {cursor}: {error}") from error
            info = cursor.lstat()
        except OSError as error:
            raise CapacityStageError(f"cannot inspect private output parent {cursor}: {error}") from error
        require(stat.S_ISDIR(info.st_mode), f"private output parent is not a nonsymlink directory: {cursor}")
        require(cursor.resolve(strict=True) == cursor, f"private output parent contains a symlink: {cursor}")


def _write_exclusive(path: Path, raw: bytes, mode: int = 0o600) -> str:
    require(path.is_absolute(), "artifact output must be absolute")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, mode)
    except OSError as error:
        raise CapacityStageError(f"cannot create new artifact {path}: {error}") from error
    try:
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            require(written > 0, f"short write while creating {path.name}")
            offset += written
        os.fsync(fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode and
                info.st_uid == os.getuid() and info.st_size == len(raw),
                f"new artifact metadata differs after durable write: {path}")
    finally:
        os.close(fd)
    _fsync_directory(path.parent)
    return sha256_bytes(raw)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Ledger:
    def __init__(self, path: Path, context: dict[str, Any], jobs_sha: str):
        self.path = path
        self.context = context
        self.jobs_sha = jobs_sha
        self.sequence = 0
        self.previous = "0" * 64
        self.fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        os.fchmod(self.fd, 0o600)
        _fsync_directory(path.parent)

    def append(self, event: str, job: dict[str, Any] | None,
               details: dict[str, Any]) -> str:
        require(event in JOB_EVENTS or event in ("stage_failed", "stage_complete"),
                "unknown capacity stage ledger event")
        self.sequence += 1
        require(self.sequence <= MAX_EVENT_RECORDS, "capacity stage ledger exceeds its event cap")
        base = {
            "schema": EVENT_SCHEMA, "sequence": self.sequence, "event": event,
            "monotonic_ns": time.monotonic_ns(),
            "boot_id_sha256": self.context["current_host"]["boot_id_sha256"],
            "campaign_id": self.context["spec"]["campaign_id"],
            "host_id": self.context["host_id"],
            "spec_raw_sha256": self.context["spec_raw_sha256"],
            "spec_semantic_sha256": self.context["spec_semantic_sha256"],
            "plan_raw_sha256": self.context["plan_raw_sha256"],
            "plan_semantic_sha256": self.context["plan_semantic_sha256"],
            "source_manifest_raw_sha256": self.context["source_raw_sha256"],
            "source_manifest_semantic_sha256": self.context["source_semantic_sha256"],
            "source_tree_sha256": self.context["source_tree_sha256"],
            "capacity_schedule_sha256": self.jobs_sha,
            "observed_host_raw_sha256": self.context["host_context_raw_sha256"],
            "run_id": None if job is None else job["run_id"],
            "ordinal": None if job is None else job["ordinal"],
            "template_index": None if job is None else job["template_index"],
            "calibration_id": None if job is None else job["capacity_key"]["calibration_id"],
            "workload": None if job is None else job["capacity_key"]["workload"],
            "profile": None if job is None else job["capacity_key"]["profile"],
            "template_sha256": None if job is None else job["template_sha256"],
            "details": details,
        }
        unsigned = {"previous_sha256": self.previous, "record": base}
        record_sha = sha256_bytes(canonical_bytes(unsigned))
        envelope = {**unsigned, "record_sha256": record_sha}
        raw = canonical_bytes(envelope)
        require(len(raw) <= MAX_EVENT_LINE_BYTES, "capacity stage ledger event exceeds its line cap")
        require(os.fstat(self.fd).st_size + len(raw) <= MAX_LEDGER_BYTES,
                "capacity stage ledger exceeds its byte cap")
        offset = 0
        while offset < len(raw):
            written = os.write(self.fd, raw[offset:])
            require(written > 0, "capacity stage ledger stopped accepting bytes")
            offset += written
        os.fsync(self.fd)
        self.previous = record_sha
        return record_sha

    def seal(self) -> tuple[str, str]:
        os.fsync(self.fd)
        os.fchmod(self.fd, 0o400)
        os.fsync(self.fd)
        os.close(self.fd)
        self.fd = -1
        _fsync_directory(self.path.parent)
        raw, _info = read_stable(self.path, "sealed capacity stage ledger", MAX_LEDGER_BYTES)
        return sha256_bytes(raw), self.previous

    def close_failed(self) -> None:
        if self.fd >= 0:
            try:
                os.fsync(self.fd)
            finally:
                os.close(self.fd)
                self.fd = -1


def _check_new_directory(path: Path, label: str) -> None:
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700, f"{label} must be a private mode-0700 directory")


def _directory_names(path: Path) -> set[str]:
    with os.scandir(path) as entries:
        return {entry.name for entry in entries}


def _read_pid_identity(pid: int, expected_executable: Path,
                       expected_sha: str,
                       expected_environment: dict[str, str] | None = None) -> dict[str, Any]:
    require(type(pid) is int and 0 < pid <= (1 << 31) - 1, "child PID is outside its bound")
    proc = Path(f"/proc/{pid}")
    try:
        stat_text = (proc / "stat").read_text(encoding="ascii")
        tail = stat_text[stat_text.rfind(")") + 2:].split()
        start_ticks = int(tail[19])
        executable = Path(os.readlink(proc / "exe"))
        affinity = sorted(os.sched_getaffinity(pid))
        netns = os.stat(proc / "ns/net").st_ino
        environment_raw = (proc / "environ").read_bytes()
    except (OSError, UnicodeError, ValueError, IndexError) as error:
        raise CapacityStageError(f"cannot observe actual child process identity: {error}") from error
    if expected_environment and not environment_raw:
        # Linux can briefly expose an empty procfs environ while a newly exec'd
        # child is still completing its startup. The process deadline was
        # started before Popen, so this bounded visibility wait remains inside
        # the caller's frozen deadline.
        visibility_deadline = time.monotonic() + 0.5
        while not environment_raw and time.monotonic() < visibility_deadline:
            time.sleep(min(0.005, max(0.0, visibility_deadline - time.monotonic())))
            try:
                current_stat = (proc / "stat").read_text(encoding="ascii")
                current_tail = current_stat[current_stat.rfind(")") + 2:].split()
                require(int(current_tail[19]) == start_ticks,
                        "application PID changed while observing its startup environment")
                if current_tail[0] in ("Z", "X"):
                    break
                environment_raw = (proc / "environ").read_bytes()
            except (OSError, UnicodeError, ValueError, IndexError):
                break
    require(executable == expected_executable and " (deleted)" not in str(executable),
            "actual child executable path differs from the frozen application binary")
    require(len(environment_raw) <= 65_536, "actual child environment exceeds its bound")
    executable_raw, _info = read_stable(executable, "actual child executable", 1024 * 1024 * 1024)
    executable_sha = sha256_bytes(executable_raw)
    require(executable_sha == expected_sha, "actual child executable bytes differ from the SourceV5 binary pin")
    if expected_environment is not None:
        observed_environment: dict[str, str] = {}
        for item in environment_raw.split(b"\0"):
            if not item:
                continue
            key_raw, separator, value_raw = item.partition(b"=")
            require(bool(separator), "actual child environment contains a malformed entry")
            try:
                key, value = key_raw.decode("ascii"), value_raw.decode("utf-8")
            except UnicodeError as error:
                raise CapacityStageError("actual child environment is not bounded UTF-8") from error
            require(key not in observed_environment, "actual child environment repeats a key")
            observed_environment[key] = value
        if observed_environment != expected_environment:
            observed_keys, expected_keys = set(observed_environment), set(expected_environment)
            mismatched_values = sorted(
                key for key in observed_keys & expected_keys
                if observed_environment[key] != expected_environment[key]
            )
            raise CapacityStageError(
                "actual child environment differs from the exact application launch map "
                f"(missing={sorted(expected_keys - observed_keys)}, "
                f"extra={sorted(observed_keys - expected_keys)}, "
                f"value_mismatch={mismatched_values})"
            )
    require(affinity == sorted(os.sched_getaffinity(0)),
            "application child did not inherit the observed host affinity")
    return {
        "pid": pid, "start_ticks": uint(start_ticks, "child process start ticks", positive=True),
        "executable_path": str(executable), "executable_sha256": executable_sha,
        "cwd": str(Path(os.readlink(proc / "cwd"))), "cpu_affinity": affinity,
        "network_namespace_inode": netns,
        "environment": observed_environment if expected_environment is not None else None,
    }


def _process_group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _signal_process_group(group_id: int, signum: int) -> None:
    try:
        os.killpg(group_id, signum)
    except ProcessLookupError:
        pass


def _stop_process_group(process: subprocess.Popen[bytes], grace_seconds: float = 3.0) -> None:
    if _process_group_exists(process.pid):
        _signal_process_group(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + grace_seconds
        while _process_group_exists(process.pid) and time.monotonic() < deadline:
            process.poll()
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        if _process_group_exists(process.pid):
            _signal_process_group(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        _signal_process_group(process.pid, signal.SIGKILL)
        process.wait(timeout=2.0)


_PENDING_SIGNAL: int | None = None
_ACTIVE_PROCESS: subprocess.Popen[bytes] | None = None


def _install_signal_handlers() -> dict[int, Any]:
    previous: dict[int, Any] = {}
    if __import__("threading").current_thread() is not __import__("threading").main_thread():
        return previous

    def stop(signum: int, _frame: Any) -> None:
        global _PENDING_SIGNAL
        _PENDING_SIGNAL = signum
        active = _ACTIVE_PROCESS
        if active is not None:
            _signal_process_group(active.pid, signum)
        raise CapacityStageError(f"capacity stage received signal {signum}")

    for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, stop)
    return previous


def _restore_signal_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _spawn_bounded(
    argv: list[str], cwd: Path, environment: dict[str, str], stdout_path: Path,
    stderr_path: Path, timeout_seconds: int, expected_binary: Path,
    expected_binary_sha: str, *, capture_identity: bool = True,
    on_bound: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    global _ACTIVE_PROCESS
    require(type(timeout_seconds) is int and timeout_seconds > 0,
            "child process deadline must be positive")
    _path_text(cwd, "child cwd")
    stdout_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        stderr_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except BaseException:
        os.close(stdout_fd)
        raise
    process: subprocess.Popen[bytes] | None = None
    process_identity: dict[str, Any] | None = None
    return_code: int | None = None
    elapsed_ns: int | None = None
    started = time.monotonic()
    deadline = started + timeout_seconds
    status = "completed"
    caught_signal: int | None = None
    try:
        with os.fdopen(stdout_fd, "wb", buffering=0) as stdout_stream, \
             os.fdopen(stderr_fd, "wb", buffering=0) as stderr_stream:
            try:
                process = subprocess.Popen(
                    argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                    stdout=stdout_stream, stderr=stderr_stream, close_fds=True,
                    start_new_session=True,
                )
            except OSError as error:
                raise CapacityStageError(f"cannot start the source-pinned application: {error}") from error
            _ACTIVE_PROCESS = process
            if capture_identity:
                process_identity = _read_pid_identity(
                    process.pid, expected_binary, expected_binary_sha, environment,
                )
                if on_bound is not None:
                    on_bound(process_identity)
            try:
                while process.poll() is None:
                    if _PENDING_SIGNAL is not None:
                        caught_signal = _PENDING_SIGNAL
                        status = "interrupted"
                        break
                    if time.monotonic() >= deadline:
                        status = "timeout"
                        break
                    stdout_info = os.fstat(stdout_stream.fileno())
                    stderr_info = os.fstat(stderr_stream.fileno())
                    require(stdout_info.st_size <= MAX_STDOUT_BYTES and stderr_info.st_size <= MAX_STDERR_BYTES,
                            "application stdout or stderr exceeded its capture bound")
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            except CapacityStageError:
                if _PENDING_SIGNAL is None:
                    raise
                caught_signal = _PENDING_SIGNAL
                status = "interrupted"
            if status != "completed":
                _stop_process_group(process)
            return_code = process.wait()
            elapsed_ns = max(0, int((time.monotonic() - started) * 1e9))
            if status == "completed" and elapsed_ns > timeout_seconds * 1_000_000_000:
                status = "timeout"
            _stop_process_group(process, grace_seconds=0.0)
            stdout_stream.flush()
            stderr_stream.flush()
            os.fsync(stdout_stream.fileno())
            os.fsync(stderr_stream.fileno())
            stdout_info = os.fstat(stdout_stream.fileno())
            stderr_info = os.fstat(stderr_stream.fileno())
            require(stdout_info.st_size <= MAX_STDOUT_BYTES and stderr_info.st_size <= MAX_STDERR_BYTES,
                    "application stdout or stderr exceeded its capture bound")
    except BaseException:
        if process is not None:
            _stop_process_group(process)
        raise
    finally:
        _ACTIVE_PROCESS = None
    stdout_raw, _stdout_info = read_stable(stdout_path, "child stdout capture", MAX_STDOUT_BYTES)
    stderr_raw, _stderr_info = read_stable(stderr_path, "child stderr capture", MAX_STDERR_BYTES)
    return {
        "pid": process.pid if process is not None else None,
        "process_identity": process_identity if process is not None else None,
        "return_code": return_code if process is not None else None,
        "status": status, "signal": caught_signal,
        "elapsed_ns": elapsed_ns if elapsed_ns is not None else 0,
        "stdout_path": str(stdout_path), "stdout_sha256": sha256_bytes(stdout_raw),
        "stdout_size": len(stdout_raw), "stderr_path": str(stderr_path),
        "stderr_sha256": sha256_bytes(stderr_raw), "stderr_size": len(stderr_raw),
    }


def _application_environment(identity: dict[str, Any], trace_dir: Path,
                              tmpdir: Path) -> dict[str, str]:
    executor_env = identity["executor"]
    environment = {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(tmpdir),
        "ALLOCATBELT_APP_HOST_ID": identity["host_id"],
        "ALLOCATBELT_APP_RUN_ID": identity["run_id"],
        "ALLOCATBELT_APP_REPORT_NONCE": identity["report_nonce"],
        "ALLOCATBELT_APP_ALLOCATOR": identity["allocator"],
        "ALLOCATBELT_APP_EXECUTOR": executor_env,
        "ALLOCATBELT_APP_WORKLOAD": identity["workload"],
        "ALLOCATBELT_APP_PROFILE": identity["profile"],
        "ALLOCATBELT_APP_SOURCE_SHA256": identity["source_sha256"],
        "ALLOCATBELT_APP_BINARY_SHA256": identity["binary_sha256"],
        "ALLOCATBELT_APP_PRESSURE_QUALIFICATION": "false",
        "ALLOCATBELT_APP_FEEDBACK_TRACE_DIR": str(trace_dir),
    }
    require("ALLOCATBELT_APP_CAPACITY_CALIBRATION_FILE" not in environment and
            "ALLOCATBELT_APP_CAPACITY_CALIBRATION_SHA256" not in environment,
            "capacity calibration must not depend on a pre-existing capacity artifact")
    return environment


def _storage_tmpdir(storage: object, source_root: Path, job_dir: Path,
                    run_id: str) -> tuple[Path, dict[str, Any] | None]:
    if storage is None:
        tmpdir = job_dir / "tmp"
        _mkdir_private(tmpdir)
        return tmpdir, None
    typed = exact(storage, {
        "scope", "root_path", "filesystem_type", "device_major_minor", "minimum_free_bytes",
    }, "capacity storage template")
    root = _safe_root(Path(typed["root_path"]), "capacity storage root")
    require(not _is_within(source_root, root), "capacity storage root must be outside SourceV5")
    tmpdir = Path(tempfile.mkdtemp(prefix=f"allocatbelt-{run_id}-", dir=root))
    os.chmod(tmpdir, 0o700)
    _fsync_directory(root)
    info = tmpdir.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
            "new application TMPDIR is not private")
    return tmpdir, _storage_snapshot(typed, source_root, tmpdir)


def _make_policy(identity: dict[str, Any], source: dict[str, Any],
                 probe: dict[str, Any], reader: types.ModuleType) -> dict[str, Any]:
    feedback = source["feedback_policy"]["policy"]
    context = feedback["contexts"][f"{identity['workload']}/{identity['profile']}"]
    fixed = source["fixed_runtime_policy"]["policy"]
    fixed_workload = fixed["workloads"][identity["workload"]]
    workers = context["workers"]
    global_ceilings = dict(fixed_workload["domain_ceiling"])
    global_ceilings["cpu"] = workers
    collector = probe.get("collector")
    baseline = probe.get("baseline")
    exact(collector, {"control_charge_bytes", "task_lease_count"}, "feedback probe collector")
    exact(baseline, {"expected_global_control_baseline"}, "feedback probe baseline")
    return {
        "version": feedback["version"], **feedback["reader_contract"],
        "controls": context["controls"],
        "capacity_sources": {"disk": False, "download": False},
        "global_ceilings": global_ceilings,
        "tenant_ceilings": dict(global_ceilings),
        "scope_limits": {
            "managed_memory": fixed_workload["scope_limits"]["managed_memory_limit"],
            "disk_operations": fixed_workload["scope_limits"]["disk_operation_limit"],
            "network_operations": fixed_workload["scope_limits"]["network_operation_limit"],
        },
        "rate_buckets": {
            direction: {
                "ceiling_bytes_per_second": item["ceiling_bytes_per_second"],
                "ceiling_burst_bytes": item["ceiling_burst_bytes"],
                "max_reservations": item["max_reservations"],
            }
            for direction, item in fixed["byte_buckets"].items()
        },
        "meter_source_bounds": reader.meter_source_bounds_for_workload(identity["workload"]),
        "collector": {
            "task_lease_count": uint(collector["task_lease_count"], "probe collector task lease", positive=True),
            "control_charge_bytes": uint(collector["control_charge_bytes"], "probe Control charge", positive=True),
            "expected_global_control_baseline": uint(
                baseline["expected_global_control_baseline"], "probe Control baseline",
            ),
        },
    }


def _expectation_seed(identity: dict[str, Any], policy: dict[str, Any],
                      source_pin: dict[str, str], probe_pin: dict[str, str],
                      allocator: str, binary_sha: str, minimum: int) -> dict[str, Any]:
    # PID zero is an internal typed slot. The V4 reader rejects it; only the
    # actual Popen PID is inserted after the child is observed in /proc.
    return {
        "schema": EXPECTATION_SCHEMA, "mode": "capacity_calibration",
        "identity": {**identity, "process_id": 0},
        "policy": policy, "app_capacity_artifact_sha256": None,
        "construction_probe": {
            "path": probe_pin["path"], "raw_sha256": probe_pin["sha256"],
            "allocator": allocator, "binary_sha256": binary_sha,
        },
        "host_binding": {"path": source_pin["path"], "raw_sha256": source_pin["sha256"]},
        "external_pressure_proof": None, "final_runtime_binding": None,
        "minimum_production_seconds": 30, "minimum_pressure_overlap_seconds": 0,
        "minimum_interval_seconds": minimum,
    }


def _finish_expectation(seed: dict[str, Any], process_id: int,
                        reader: types.ModuleType) -> tuple[bytes, str, dict[str, Any]]:
    require(type(process_id) is int and process_id > 0, "actual application PID is not positive")
    value = json.loads(json.dumps(seed))
    identity = dict(value["identity"])
    identity["process_id"] = process_id
    value["identity"] = identity
    value.pop("minimum_interval_seconds")
    try:
        raw, raw_sha = reader.build_pressure_expectation_recipe(value)
    except Exception as error:
        raise CapacityStageError(f"captured SourceV5 reader rejected the instantiated V4 expectation: {error}") from error
    parsed = parse_object(raw, "instantiated V4 expectation", MAX_TEMPLATE_BYTES, canonical=True)
    require(parsed["identity"]["process_id"] == process_id,
            "captured V4 expectation did not preserve the observed application PID")
    return raw, raw_sha, parsed


def _probe_recipe(seed: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in seed.items() if key != "minimum_interval_seconds"}


def _verify_probe_output(
    probe_path: Path, expected_sha: str, seed: dict[str, Any],
    source: dict[str, Any], reader: types.ModuleType,
) -> tuple[dict[str, Any], str]:
    raw, _info = read_stable(probe_path, "application feedback policy probe", MAX_PROBE_BYTES)
    actual_sha = sha256_bytes(raw)
    require(actual_sha == expected_sha, "application feedback policy probe changed after capture")
    probe = parse_object(raw, "application feedback policy probe", MAX_PROBE_BYTES, canonical=True)
    try:
        probe_sha = reader.validate_construction_probe(_probe_recipe(seed), source)
    except Exception as error:
        raise CapacityStageError(f"captured SourceV5 reader rejected the application policy probe: {error}") from error
    require(probe_sha == actual_sha, "captured SourceV5 reader returned a different policy probe pin")
    try:
        reader._validate_v4_policy_source_projection(_probe_recipe(seed), source, probe)
    except Exception as error:
        raise CapacityStageError(f"SourceV5 numeric policy projection rejected the application probe: {error}") from error
    return probe, sha256_bytes(canonical_bytes(seed))


def _job_identity(job: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    key = job["capacity_key"]
    template = job["template"]
    return {
        "host_id": key["host_id"], "run_id": job["run_id"],
        "report_nonce": job["nonce"], "allocator": template["calibrator"]["allocator"],
        "executor": {"bounded": "allocatbelt", "tokio": "tokio-1.53.1"}[
            template["calibrator"]["executor"]
        ], "workload": key["workload"],
        "profile": key["profile"], "mode": "capacity",
        "source_sha256": source["source"]["source_tree_sha256"],
        "binary_sha256": template["binary_sha256"], "pressure_qualification": False,
    }


def _check_template_source_roles(job: dict[str, Any], source: dict[str, Any]) -> str:
    template = job["template"]
    require(template["source_manifest_sha256"] == source["manifest_sha256"] and
            template["source_sha256"] == source["source"]["source_tree_sha256"],
            "capacity template source manifest/tree roles differ from selected SourceV5")
    artifact = exact(source["artifacts"].get(template["calibrator"]["allocator"]),
                     {"path", "sha256"}, "selected capacity application artifact")
    require(artifact["sha256"] == template["binary_sha256"],
            "capacity template binary hash differs from the selected SourceV5 artifact")
    relative = _relative(artifact["path"], "capacity application binary path")
    return relative.as_posix()


def _find_template_template(job: dict[str, Any], input_root: Path,
                            context: dict[str, Any]) -> tuple[dict[str, Any], str, dict[str, Any], str]:
    request, request_sha, context_template, context_sha = _validate_templates(input_root, job)
    workload = job["capacity_key"]["workload"]
    storage = context_template["storage"]
    network = context_template["network"]
    if workload in ("disk", "mixed"):
        require(storage is not None, "disk capacity requires a typed storage context")
    if workload in ("http", "mixed"):
        require(network is not None, "HTTP capacity requires a typed IPv4 loopback context")
        require(network["namespace_inode"] == context["current_host"]["network_namespace_inode"],
                "capacity network namespace differs from the observed host context")
    if workload not in ("disk", "mixed"):
        require(storage is None, "non-disk capacity has an unexpected application file-I/O context")
    if workload not in ("http", "mixed"):
        require(network is None, "non-HTTP capacity has an unexpected network context")
    return request, request_sha, context_template, context_sha


def _atomic_json(path: Path, value: dict[str, Any]) -> tuple[str, bytes]:
    raw = canonical_bytes(value)
    raw_sha = _write_exclusive(path, raw)
    return raw_sha, raw


def _trace_pin_set(trace_dir: Path, hashes: dict[str, str]) -> dict[str, dict[str, str]]:
    return {
        role: {"path": str(trace_dir / filename), "sha256": hashes[role]}
        for role, filename in (
            ("manifest", "feedback-trace-manifest.tsv"),
            ("events", "feedback-events.jsonl"),
            ("samples", "resource-samples.tsv"),
        )
    }


def _make_capacity_context(identity: dict[str, Any], storage_snapshot: dict[str, Any] | None,
                           network_snapshot: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "schema": CAPACITY_CONTEXT_SCHEMA, "identity": identity,
        "stage": "pre_confirmation", "storage": storage_snapshot,
        "network": network_snapshot,
    }


def _expected_argv(binary: Path, job: dict[str, Any], spec: dict[str, Any]) -> list[str]:
    deadlines = exact(spec["deadlines"], {
        "setup_seconds", "trace_seconds", "drain_seconds", "shutdown_seconds",
        "process_seconds", "pair_validation_seconds", "outer_seconds", "soak_outer_seconds",
    }, "frozen campaign deadlines")
    argv = [
        str(binary), "--executor", job["template"]["calibrator"]["executor"],
        "--workload", job["capacity_key"]["workload"], "--profile",
        job["capacity_key"]["profile"], "--mode", "capacity",
        "--trace-deadline-seconds", str(deadlines["trace_seconds"]),
        "--drain-deadline-seconds", str(deadlines["drain_seconds"]),
        "--shutdown-deadline-seconds", str(deadlines["shutdown_seconds"]),
        "--process-deadline-seconds", str(deadlines["process_seconds"]),
    ]
    require(deadlines["setup_seconds"] == 120 and all(type(deadlines[key]) is int and deadlines[key] > 0 for key in deadlines),
            "capacity launch deadlines differ from the complete frozen finite deadline set")
    return argv


def _prepare_job_dir(stage_dir: Path, job: dict[str, Any]) -> Path:
    job_dir = stage_dir / "jobs" / job["run_id"]
    _mkdir_private(job_dir, parents=True)
    _check_new_directory(job_dir, "capacity job directory")
    _mkdir_private(job_dir / "trace")
    return job_dir


def _event_pin(path: Path, raw_sha: str) -> dict[str, str]:
    return {"path": str(path), "sha256": digest(raw_sha)}


def _write_template_copy(path: Path, raw: bytes, expected_sha: str, label: str) -> dict[str, str]:
    require(sha256_bytes(raw) == expected_sha, f"{label} source bytes changed before staging")
    _write_exclusive(path, raw)
    return {"path": str(path), "sha256": expected_sha}


def _verify_binary(source_root: Path, source: dict[str, Any], job: dict[str, Any]) -> tuple[Path, str]:
    relative = _check_template_source_roles(job, source)
    binary = _safe_child(source_root, relative, "capacity application executable")
    info = binary.stat(follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 != 0,
            "selected capacity application binary is not executable")
    raw, _info = read_stable(binary, "capacity application executable", 1024 * 1024 * 1024)
    expected = job["template"]["binary_sha256"]
    require(sha256_bytes(raw) == expected, "capacity application binary differs from its SourceV5 pin")
    return binary, expected


def _job_common(context: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    return {
        "campaign_id": context["spec"]["campaign_id"], "host_id": context["host_id"],
        "run_id": job["run_id"], "ordinal": 1,
        "capacity_key": job["capacity_key"], "template_index": job["template_index"],
        "template_sha256": job["template_sha256"],
        "capacity_process_templates_sha256": context["plan"]["capacity_process_templates_sha256"],
        "source_manifest_raw_sha256": context["source_raw_sha256"],
        "source_manifest_semantic_sha256": context["source_semantic_sha256"],
        "source_tree_sha256": context["source_tree_sha256"],
        "spec_raw_sha256": context["spec_raw_sha256"],
        "spec_semantic_sha256": context["spec_semantic_sha256"],
        "plan_raw_sha256": context["plan_raw_sha256"],
        "plan_semantic_sha256": context["plan_semantic_sha256"],
        "request_template": job["template"]["request_template"],
        "context_template": job["template"]["context_template"],
        "nonce_instantiation": job["nonce_instantiation"],
    }


def run_capacity_stage(
    plan_pin: dict[str, Any], spec_pin: dict[str, Any], source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: dict[str, Any],
    output_root: Path,
) -> dict[str, Any]:
    """Execute 15 bounded capacity contexts and publish one sealed completion."""
    global _PENDING_SIGNAL
    _PENDING_SIGNAL = None
    context = _prepare_pins(plan_pin, spec_pin, source_root, input_root, host_id, observed_host_pin)
    output_root = _safe_root(output_root, "capacity stage output root")
    require(not _is_within(context["source_root"], output_root),
            "capacity stage output must be outside SourceV5")
    jobs = derive_capacity_jobs(context["plan"], context["host_id"])
    jobs_sha = context["plan"]["capacity_process_templates_sha256"]
    campaign_root = output_root / context["spec"]["campaign_id"]
    _mkdir_components(campaign_root)
    _check_new_directory(campaign_root, "capacity campaign output directory")
    capacity_root = campaign_root / "capacity"
    _mkdir_components(capacity_root)
    _check_new_directory(capacity_root, "capacity stage parent directory")
    stage_dir = capacity_root / context["host_id"]
    _mkdir_private(stage_dir)
    _check_new_directory(stage_dir, "capacity stage directory")
    jobs_dir = stage_dir / "jobs"
    _mkdir_private(jobs_dir)
    ledger = Ledger(stage_dir / "controller-ledger.jsonl", context, jobs_sha)
    previous_handlers = _install_signal_handlers()
    completion_path = stage_dir / "capacity-stage-completion.json"
    completed_entries: list[dict[str, Any]] = []
    active_job: dict[str, Any] | None = None
    try:
        for job in jobs:
            active_job = job
            job_dir = _prepare_job_dir(stage_dir, job)
            common = _job_common(context, job)
            request_template, request_template_sha, context_template, context_template_sha = _find_template_template(
                job, context["input_root"], context,
            )
            binary, binary_sha = _verify_binary(context["source_root"], context["source"], job)
            template_raw_req, _ = read_stable(
                _safe_child(context["input_root"], job["template"]["request_template"]["relative_path"], "request template"),
                "request template", MAX_TEMPLATE_BYTES,
            )
            template_raw_ctx, _ = read_stable(
                _safe_child(context["input_root"], job["template"]["context_template"]["relative_path"], "context template"),
                "context template", MAX_TEMPLATE_BYTES,
            )
            request_template_file = _write_template_copy(
                job_dir / "request-template.json", template_raw_req, request_template_sha,
                "capacity request template",
            )
            context_template_file = _write_template_copy(
                job_dir / "context-template.json", template_raw_ctx, context_template_sha,
                "capacity context template",
            )
            identity = _job_identity(job, context["source"])
            trace_dir = job_dir / "trace"
            if job["capacity_key"]["workload"] in ("disk", "mixed"):
                tmpdir, storage_snapshot = _storage_tmpdir(
                    context_template["storage"], context["source_root"], job_dir,
                    job["run_id"],
                )
            else:
                tmpdir, storage_snapshot = _storage_tmpdir(
                    None, context["source_root"], job_dir, job["run_id"],
                )
            network_snapshot = None
            if context_template["network"] is not None:
                network_snapshot = _network_snapshot(context_template["network"], context["host_context"])
            probe_stdout = job_dir / "policy-probe.json"
            probe_stderr = job_dir / "policy-probe.stderr"
            probe_argv = [
                str(binary), "--emit-feedback-policy-only", "--workload",
                job["capacity_key"]["workload"], "--profile", job["capacity_key"]["profile"],
            ]
            probe_env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": str(tmpdir)}
            probe_dispatch = {
                **common, "argv": probe_argv, "cwd": str(job_dir), "environment": probe_env,
                "expected_binary_sha256": binary_sha,
                "deadline_seconds": min(context["spec"]["deadlines"]["setup_seconds"], 120),
                "stdout_path": str(probe_stdout), "stderr_path": str(probe_stderr),
            }
            ledger.append("probe_dispatch", job, probe_dispatch)
            child = _spawn_bounded(
                probe_argv, job_dir, probe_env, probe_stdout, probe_stderr,
                probe_dispatch["deadline_seconds"], binary, binary_sha,
                capture_identity=False,
            )
            probe_completed = {**common, **child, "stderr_empty": child["stderr_size"] == 0}
            ledger.append("probe_completed", job, probe_completed)
            require(child["status"] == "completed" and child["return_code"] == 0 and
                    child["stderr_size"] == 0,
                    f"application feedback policy probe failed for {job['run_id']}")
            probe_pin = _event_pin(probe_stdout, child["stdout_sha256"])
            source_pin = _event_pin(context["source_path"], context["source_raw_sha256"])
            seed_identity = dict(identity)
            seed = _expectation_seed(
                seed_identity, _make_policy(identity, context["source"],
                                             parse_object(probe_stdout.read_bytes(), "policy probe", MAX_PROBE_BYTES, canonical=True),
                                             context["stack"]["feedback_reader"]),
                source_pin, probe_pin, identity["allocator"], binary_sha,
                request_template["minimum_interval_seconds"],
            )
            probe, seed_sha = _verify_probe_output(
                probe_stdout, child["stdout_sha256"], seed,
                context["source"], context["stack"]["feedback_reader"],
            )
            ledger.append("probe_verified", job, {
                **common, "probe": probe_pin, "probe_sha256": probe_pin["sha256"],
                "policy_sha256": sha256_bytes(canonical_bytes(seed["policy"])),
                "expectation_seed_sha256": seed_sha,
                "request_template_copy": request_template_file,
                "context_template_copy": context_template_file,
                "source_manifest": source_pin,
            })
            if context_template["storage"] is not None:
                storage_snapshot = _storage_snapshot(
                    context_template["storage"], context["source_root"], tmpdir,
                )
            if context_template["network"] is not None:
                network_snapshot = _network_snapshot(context_template["network"], context["host_context"])
            seed["identity"] = {**identity, "process_id": 0}
            argv = _expected_argv(binary, job, context["spec"])
            environment = _application_environment(identity, trace_dir, tmpdir)
            application_dispatch = {
                **common, "argv": argv, "cwd": str(job_dir), "environment": environment,
                "trace_directory": str(trace_dir), "tmpdir_path": str(tmpdir),
                "expected_binary_sha256": binary_sha,
                "process_deadline_seconds": context["spec"]["deadlines"]["process_seconds"],
                "mode": "capacity", "capacity_horizon_seconds": 30,
                "external_pressure": False, "pressure_qualification": False,
                "storage_context": storage_snapshot, "network_context": network_snapshot,
                "probe": probe_pin, "policy_sha256": sha256_bytes(canonical_bytes(seed["policy"])),
            }
            ledger.append("application_dispatch", job, application_dispatch)
            app_stdout = job_dir / "application.stdout"
            app_stderr = job_dir / "application.stderr"
            observed_binding: dict[str, Any] = {}

            def bind_application(app_identity: dict[str, Any]) -> None:
                require(app_identity["pid"] > 0 and app_identity["executable_sha256"] == binary_sha and
                        app_identity["cpu_affinity"] == context["current_host"]["cpu_affinity"] and
                        app_identity["network_namespace_inode"] == context["current_host"]["network_namespace_inode"] and
                        app_identity["cwd"] == str(job_dir) and
                        app_identity["environment"] == environment,
                        "actual application PID/start/executable/cwd/affinity/environment binding differs")
                details = {
                    **common, "pid": app_identity["pid"], "start_ticks": app_identity["start_ticks"],
                    "executable_path": app_identity["executable_path"],
                    "executable_sha256": app_identity["executable_sha256"],
                    "nonce": identity["report_nonce"], "cwd": app_identity["cwd"],
                    "cpu_affinity": app_identity["cpu_affinity"],
                    "network_namespace_inode": app_identity["network_namespace_inode"],
                    "environment": app_identity["environment"],
                    "environment_sha256": sha256_bytes(canonical_bytes(app_identity["environment"])),
                    "tmpdir_path": str(tmpdir), "trace_directory": str(trace_dir),
                    "external_pressure": False, "pressure_qualification": False,
                }
                ledger.append("application_bound", job, details)
                observed_binding["details"] = details

            app_child = _spawn_bounded(
                argv, job_dir, environment, app_stdout, app_stderr,
                context["spec"]["deadlines"]["process_seconds"], binary, binary_sha,
                on_bound=bind_application,
            )
            app_identity = app_child["process_identity"]
            require(app_identity is not None, "application Popen did not bind a direct executable process")
            require(app_identity["pid"] == app_child["pid"] and
                    "details" in observed_binding,
                    "application Popen child differs from its immediately flushed process binding")
            bound = observed_binding["details"]
            app_exited = {
                **common, "pid": app_child["pid"], "return_code": app_child["return_code"],
                "status": app_child["status"], "signal": app_child["signal"],
                "elapsed_ns": app_child["elapsed_ns"],
                "stdout": _event_pin(Path(app_child["stdout_path"]), app_child["stdout_sha256"]),
                "stderr": _event_pin(Path(app_child["stderr_path"]), app_child["stderr_sha256"]),
                "stdout_sha256": app_child["stdout_sha256"],
                "stderr_sha256": app_child["stderr_sha256"],
                "stdout_size": app_child["stdout_size"], "stderr_size": app_child["stderr_size"],
                "process_seconds": context["spec"]["deadlines"]["process_seconds"],
            }
            ledger.append("application_exited", job, app_exited)
            require(app_child["status"] == "completed" and app_child["return_code"] == 0 and
                    app_child["stderr_size"] == 0,
                    f"application capacity process failed for {job['run_id']}")
            final_identity = dict(identity)
            final_identity["process_id"] = app_child["pid"]
            app_expectation_raw, expectation_sha, expectation = _finish_expectation(
                seed, app_child["pid"], context["stack"]["feedback_reader"],
            )
            require(expectation["identity"] == final_identity,
                    "instantiated V4 expectation changed a prelaunch identity field")
            expectation_path = job_dir / "feedback-expectation.json"
            _write_exclusive(expectation_path, app_expectation_raw)
            expectation_pin = _event_pin(expectation_path, expectation_sha)
            context_value = _make_capacity_context(final_identity, storage_snapshot, network_snapshot)
            context_path = job_dir / "capacity-context.json"
            context_sha = _write_exclusive(context_path, canonical_bytes(context_value))
            context_pin = _event_pin(context_path, context_sha)
            trace_hashes: dict[str, str] = {}
            trace_validation: dict[str, Any] | None = None
            trace_validation_raw: bytes | None = None
            # Validation is created only after the full trace reader has checked
            # all three raw trace members and the final process identity.
            trace_dir_names = _directory_names(trace_dir)
            expected_trace_names = {
                "feedback-trace-manifest.tsv", "feedback-events.jsonl", "resource-samples.tsv",
            }
            require(trace_dir_names == expected_trace_names,
                    "application trace output has missing or unexpected members")
            trace_hashes = {
                role: hash_stable(trace_dir / name, f"feedback {role}", MAX_TRACE_FILE_BYTES)[1]
                for role, name in (
                    ("manifest", "feedback-trace-manifest.tsv"),
                    ("events", "feedback-events.jsonl"),
                    ("samples", "resource-samples.tsv"),
                )
            }
            trace_pins = _trace_pin_set(trace_dir, trace_hashes)
            ledger.append("trace_captured", job, {
                **common, "traces": trace_pins, "trace_hashes": trace_hashes,
                "trace_directory": str(trace_dir), "application_pid": app_child["pid"],
            })
            try:
                trace_validation = context["stack"]["feedback_reader"].verify_feedback(
                    expectation_path, expectation_sha, trace_dir, trace_hashes,
                )
                trace_validation_raw = context["stack"]["feedback_reader"].canonical_bytes(trace_validation)
            except Exception as error:
                raise CapacityStageError(f"captured full SourceV5 reader rejected {job['run_id']} trace: {error}") from error
            require(type(trace_validation) is dict and trace_validation.get("validated") is True and
                    trace_validation.get("mode") == "capacity_calibration" and
                    trace_validation.get("qualification_eligible") is False and
                    trace_validation.get("expectation_raw_sha256") == expectation_sha and
                    trace_validation.get("raw_artifact_sha256") == trace_hashes,
                    "full SourceV5 reader returned a mismatched V4 calibration receipt")
            validation_path = job_dir / "feedback-validation.json"
            validation_sha = _write_exclusive(validation_path, trace_validation_raw)
            validation_pin = _event_pin(validation_path, validation_sha)
            ledger.append("feedback_verified", job, {
                **common, "expectation": expectation_pin,
                "expectation_sha256": expectation_sha,
                "validation": validation_pin, "validation_sha256": validation_sha,
                "validator_sha256": context["stack"]["feedback_reader_sha256"],
                "trace_hashes": trace_hashes,
                "application_pid": app_child["pid"],
                "process_identity_sha256": sha256_bytes(canonical_bytes(bound)),
            })
            request_value = {
                "schema": context["stack"]["capacity_producer"].REQUEST_SCHEMA,
                "calibration_id": job["capacity_key"]["calibration_id"],
                "identity": final_identity,
                "source_manifest": source_pin, "validation": validation_pin,
                "expectation": expectation_pin, "expectation_sha256": expectation_sha,
                "validator_sha256": context["source"]["qualification_harness"]["feedback_validator"]["sha256"],
                "trace_directory": str(trace_dir), "context": context_pin,
                "minimum_interval_seconds": request_template["minimum_interval_seconds"],
            }
            request_path = job_dir / "capacity-request.json"
            request_sha = _write_exclusive(request_path, canonical_bytes(request_value))
            request_pin = _event_pin(request_path, request_sha)
            producer = context["stack"]["capacity_producer"]
            try:
                artifact_raw, receipt_value = producer.produce(request_value, request_sha)
                producer.publish_bundle(job_dir / "capacity-bundle", artifact_raw, producer.canonical(receipt_value))
            except Exception as error:
                raise CapacityStageError(f"captured SourceV5 byte-capacity producer failed: {error}") from error
            artifact_path = job_dir / "capacity-bundle" / "application-byte-capacity.tsv"
            receipt_path = job_dir / "capacity-bundle" / "capacity-receipt.json"
            artifact_raw_sha = sha256_bytes(read_stable(artifact_path, "published capacity artifact", 4096)[0])
            receipt_raw_sha = sha256_bytes(read_stable(receipt_path, "published capacity receipt", MAX_METADATA_BYTES)[0])
            artifact_pin = _event_pin(artifact_path, artifact_raw_sha)
            receipt_pin = _event_pin(receipt_path, receipt_raw_sha)
            require(producer.verify_capacity_bundle(request_pin, artifact_pin, receipt_pin) is True,
                    "captured producer did not replay the published capacity bundle")
            bundle_details = {
                **common, "request": request_pin, "expectation": expectation_pin,
                "context": context_pin, "traces": trace_pins,
                "validation": validation_pin, "artifact": artifact_pin,
                "receipt": receipt_pin, "probe": probe_pin,
                "actual_pid": app_child["pid"], "actual_start_ticks": app_identity["start_ticks"],
                "actual_executable_sha256": app_identity["executable_sha256"],
                "producer_sha256": context["stack"]["capacity_producer_sha256"],
                "feedback_reader_sha256": context["stack"]["feedback_reader_sha256"],
                "qualification_eligible": False,
            }
            ledger.append("bundle_verified", job, bundle_details)
            completed_entries.append({
                "ordinal": 1, "template_index": job["template_index"],
                "run_id": job["run_id"], "calibration_id": job["capacity_key"]["calibration_id"],
                "workload": job["capacity_key"]["workload"], "profile": job["capacity_key"]["profile"],
                "template_sha256": job["template_sha256"], "nonce": job["nonce"],
                "probe": probe_pin, "expectation": expectation_pin,
                "context": context_pin, "request": request_pin, "traces": trace_pins,
                "validation": validation_pin, "artifact": artifact_pin, "receipt": receipt_pin,
                "actual_pid": app_child["pid"], "actual_start_ticks": app_identity["start_ticks"],
                "actual_executable_sha256": app_identity["executable_sha256"],
                "actual_affinity": app_identity["cpu_affinity"], "actual_cwd": app_identity["cwd"],
                "actual_environment_sha256": sha256_bytes(canonical_bytes(environment)),
            })
            active_job = None
        require(len(completed_entries) == 15, "capacity stage did not complete all 15 contexts")
        terminal = {
            "schema": COMPLETION_SCHEMA, "complete": True,
            "qualification_eligible": False,
            "controller_chronology_proven": False,
            "campaign_id": context["spec"]["campaign_id"], "host_id": context["host_id"],
            "spec": {"path": str(context["spec_path"]), "raw_sha256": context["spec_raw_sha256"],
                     "semantic_sha256": context["spec_semantic_sha256"]},
            "plan": {"path": str(context["plan_path"]), "raw_sha256": context["plan_raw_sha256"],
                     "semantic_sha256": context["plan_semantic_sha256"]},
            "source": {"path": str(context["source_path"]), "raw_sha256": context["source_raw_sha256"],
                       "semantic_sha256": context["source_semantic_sha256"],
                       "source_tree_sha256": context["source_tree_sha256"]},
            "observed_host": {"path": str(context["host_context_path"]),
                              "raw_sha256": context["host_context_raw_sha256"],
                              "boot_id_sha256": context["current_host"]["boot_id_sha256"],
                              "cpu_affinity": context["current_host"]["cpu_affinity"],
                              "network_namespace_inode": context["current_host"]["network_namespace_inode"]},
            "stage": {"path": str(context["source_root"] / STAGE_SOURCE_PATH),
                      "sha256": context["stack"]["stage_sha256"]},
            "controller": {"path": CONTROLLER_PATH, "sha256": context["stack"]["controller_sha256"]},
            "inputs": {"path": INPUTS_PATH, "sha256": context["stack"]["inputs_sha256"]},
            "feedback_reader": {"path": FEEDBACK_READER_PATH,
                                "sha256": context["stack"]["feedback_reader_sha256"]},
            "capacity_producer": {"path": CAPACITY_PRODUCER_PATH,
                                  "sha256": context["stack"]["capacity_producer_sha256"]},
            "capacity_process_templates_sha256": jobs_sha,
            "stage_directory": str(stage_dir),
            "ledger": {"path": str(ledger.path), "raw_sha256": None, "terminal_head": None},
            "entries": completed_entries,
        }
        ledger.append("stage_complete", None, {
            "completion_schema": COMPLETION_SCHEMA,
            "entry_count": len(completed_entries),
            "capacity_process_templates_sha256": jobs_sha,
            "qualification_eligible": False,
            "controller_chronology_proven": False,
        })
        ledger_raw_sha, terminal_head = ledger.seal()
        terminal["ledger"] = {
            "path": str(ledger.path), "raw_sha256": ledger_raw_sha,
            "terminal_head": terminal_head,
        }
        completion_raw_sha, _completion_raw = _atomic_json(completion_path, terminal)
        return {
            "completion": {"path": str(completion_path), "sha256": completion_raw_sha},
            "ledger": terminal["ledger"], "complete": True,
            "qualification_eligible": False, "entry_count": len(completed_entries),
            "controller_chronology_proven": False,
        }
    except BaseException as error:
        try:
            if ledger.fd >= 0:
                ledger.append("stage_failed", active_job, {
                    "error_type": type(error).__name__,
                    "error": str(error)[:2048],
                    "signal": _PENDING_SIGNAL,
                    "completed_entry_count": len(completed_entries),
                    "qualification_eligible": False,
                    "controller_chronology_proven": False,
                })
        except BaseException:
            pass
        ledger.close_failed()
        raise
    finally:
        _restore_signal_handlers(previous_handlers)


def _pin_path(path: object, label: str) -> Path:
    text = path
    require(type(text) is str, f"{label} path is malformed")
    result = Path(text)
    _path_text(result, label)
    return result


def _read_ledger(path: Path, expected_sha: str, expected_head: str) -> tuple[list[dict[str, Any]], str]:
    raw, info = read_stable(path, "sealed capacity stage ledger", MAX_LEDGER_BYTES)
    require(stat.S_IMODE(info.st_mode) == 0o400,
            "sealed capacity stage ledger must have mode 0400")
    require(sha256_bytes(raw) == expected_sha, "sealed capacity stage ledger raw SHA differs")
    lines = raw.splitlines(keepends=True)
    require(lines and all(line.endswith(b"\n") and b"\r" not in line for line in lines),
            "sealed capacity stage ledger is not LF framed")
    require(len(lines) <= MAX_EVENT_RECORDS, "sealed capacity stage ledger has too many events")
    previous = "0" * 64
    records: list[dict[str, Any]] = []
    previous_time = 0
    for sequence, line in enumerate(lines, 1):
        require(len(line) <= MAX_EVENT_LINE_BYTES, f"capacity ledger line {sequence} exceeds its bound")
        envelope = parse_object(line, f"capacity ledger line {sequence}", MAX_EVENT_LINE_BYTES, canonical=True)
        exact(envelope, {"previous_sha256", "record", "record_sha256"},
              f"capacity ledger envelope[{sequence}]")
        require(envelope["previous_sha256"] == previous,
                f"capacity ledger hash chain breaks at line {sequence}")
        record = envelope["record"]
        require(type(record) is dict, f"capacity ledger record {sequence} is malformed")
        expected = sha256_bytes(canonical_bytes({
            "previous_sha256": previous, "record": record,
        }))
        require(envelope["record_sha256"] == expected,
                f"capacity ledger record hash differs at line {sequence}")
        exact(record, {
            "schema", "sequence", "event", "monotonic_ns", "boot_id_sha256",
            "campaign_id", "host_id", "spec_raw_sha256", "spec_semantic_sha256",
            "plan_raw_sha256", "plan_semantic_sha256", "source_manifest_raw_sha256",
            "source_manifest_semantic_sha256", "source_tree_sha256",
            "capacity_schedule_sha256", "observed_host_raw_sha256", "run_id", "ordinal",
            "template_index", "calibration_id", "workload", "profile", "template_sha256", "details",
        }, f"capacity ledger record[{sequence}]")
        require(record["schema"] == EVENT_SCHEMA and record["sequence"] == sequence,
                f"capacity ledger record schema/sequence differs at line {sequence}")
        event = record["event"]
        require(event in JOB_EVENTS or event in ("stage_failed", "stage_complete"),
                f"unknown capacity ledger event at line {sequence}")
        monotonic = uint(record["monotonic_ns"], "capacity ledger monotonic timestamp", positive=True)
        require(monotonic > previous_time, "capacity ledger timestamps do not strictly advance")
        previous_time = monotonic
        for field in (
            "boot_id_sha256", "spec_raw_sha256", "spec_semantic_sha256", "plan_raw_sha256",
            "plan_semantic_sha256", "source_manifest_raw_sha256",
            "source_manifest_semantic_sha256", "source_tree_sha256",
            "capacity_schedule_sha256", "observed_host_raw_sha256",
        ):
            digest(record[field], f"capacity ledger {field}")
        require(type(record["details"]) is dict, f"capacity ledger details are malformed at line {sequence}")
        records.append(record)
        previous = expected
    require(previous == expected_head, "capacity ledger terminal head differs from its completion overlay")
    return records, sha256_bytes(raw)


def _validate_event_common(record: dict[str, Any], context: dict[str, Any],
                           job: dict[str, Any]) -> None:
    require(record["campaign_id"] == context["spec"]["campaign_id"] and
            record["host_id"] == context["host_id"] and
            record["run_id"] == job["run_id"] and record["ordinal"] == 1 and
            record["template_index"] == job["template_index"] and
            record["calibration_id"] == job["capacity_key"]["calibration_id"] and
            record["workload"] == job["capacity_key"]["workload"] and
            record["profile"] == job["capacity_key"]["profile"] and
            record["template_sha256"] == job["template_sha256"],
            f"capacity ledger event {record['event']} differs from the frozen template")
    require(record["spec_raw_sha256"] == context["spec_raw_sha256"] and
            record["spec_semantic_sha256"] == context["spec_semantic_sha256"] and
            record["plan_raw_sha256"] == context["plan_raw_sha256"] and
            record["plan_semantic_sha256"] == context["plan_semantic_sha256"] and
            record["source_manifest_raw_sha256"] == context["source_raw_sha256"] and
            record["source_manifest_semantic_sha256"] == context["source_semantic_sha256"] and
            record["source_tree_sha256"] == context["source_tree_sha256"] and
            record["capacity_schedule_sha256"] == context["plan"]["capacity_process_templates_sha256"] and
            record["observed_host_raw_sha256"] == context["host_context_raw_sha256"] and
            record["boot_id_sha256"] == context["current_host"]["boot_id_sha256"],
            f"capacity ledger event {record['event']} changed a source/spec/plan/host hash role")


def _read_evidence_pin(pin: object, label: str, maximum: int,
                       expected_root: Path) -> tuple[Path, bytes, str]:
    value = exact(pin, {"path", "sha256"}, f"{label} evidence pin")
    path = _pin_path(value["path"], f"{label} evidence path")
    require(_is_within(expected_root, path), f"{label} evidence path escaped its sealed stage directory")
    raw, _info = read_stable(path, label, maximum)
    raw_sha = sha256_bytes(raw)
    require(raw_sha == digest(value["sha256"], f"{label} raw SHA-256"),
            f"{label} bytes differ from their stage pin")
    return path, raw, raw_sha


def _hash_evidence_pin(pin: object, label: str, maximum: int,
                       expected_root: Path) -> tuple[Path, str]:
    value = exact(pin, {"path", "sha256"}, f"{label} evidence pin")
    path = _pin_path(value["path"], f"{label} evidence path")
    require(_is_within(expected_root, path), f"{label} evidence path escaped its sealed stage directory")
    _size, raw_sha = hash_stable(path, label, maximum)
    require(raw_sha == digest(value["sha256"], f"{label} raw SHA-256"),
            f"{label} bytes differ from their stage pin")
    return path, raw_sha


def _verify_job_records(
    records: list[dict[str, Any]], job: dict[str, Any], context: dict[str, Any],
    stage_dir: Path,
) -> dict[str, Any]:
    job_records = [item for item in records if item.get("run_id") == job["run_id"]]
    expected_transitions = list(JOB_EVENTS)
    require([item["event"] for item in job_records] == expected_transitions,
            f"capacity job {job['run_id']} has missing, duplicate, or out-of-order transitions")
    require(len(job_records) == len(expected_transitions),
            f"capacity job {job['run_id']} transition count differs")
    common = _job_common(context, job)
    for item in job_records:
        _validate_event_common(item, context, job)
        details = item["details"]
        require(all(details.get(key) == value for key, value in common.items()),
                f"capacity ledger event {item['event']} no longer links to its exact dispatch/template pins")
    by_event = {item["event"]: item["details"] for item in job_records}
    for event, extra_fields in JOB_EVENT_DETAIL_FIELDS.items():
        exact(by_event[event], set(common) | extra_fields,
              f"capacity ledger {event} detail schema")
    require(by_event["probe_dispatch"].get("argv", [None])[1:] == [
        "--emit-feedback-policy-only", "--workload", job["capacity_key"]["workload"],
        "--profile", job["capacity_key"]["profile"],
    ], "capacity probe dispatch argv differs from the frozen context")
    probe_dispatch = by_event["probe_dispatch"]
    expected_binary, expected_binary_sha = _verify_binary(context["source_root"], context["source"], job)
    probe_deadline = uint(probe_dispatch.get("deadline_seconds"),
                          "capacity policy probe deadline", positive=True)
    require(probe_dispatch["argv"][0] == str(expected_binary) and
            probe_dispatch["expected_binary_sha256"] == expected_binary_sha and
            probe_dispatch["cwd"] == str(stage_dir / "jobs" / job["run_id"]) and
            probe_deadline == min(context["spec"]["deadlines"]["setup_seconds"], 120) and
            probe_dispatch["stdout_path"] == str(stage_dir / "jobs" / job["run_id"] / "policy-probe.json") and
            probe_dispatch["stderr_path"] == str(stage_dir / "jobs" / job["run_id"] / "policy-probe.stderr"),
            "capacity probe dispatch is not directly bound to the frozen application binary")
    probe_completed = by_event["probe_completed"]
    probe_elapsed_ns = uint(probe_completed.get("elapsed_ns"), "capacity policy probe elapsed nanoseconds")
    require(probe_completed.get("signal") is None,
            "capacity policy probe recorded a signal on completed exit")
    require(probe_elapsed_ns <= probe_deadline * 1_000_000_000,
            "capacity policy probe elapsed time exceeds its frozen setup deadline")
    require(probe_completed.get("status") == "completed" and
            type(probe_completed.get("return_code")) is int and probe_completed["return_code"] == 0 and
            uint(probe_completed.get("pid"), "capacity policy probe PID", positive=True,
                 maximum=(1 << 31) - 1) > 0 and
            probe_completed.get("process_identity") is None and
            probe_completed.get("stderr_empty") is True and
            uint(probe_completed.get("stdout_size"), "capacity policy probe stdout size") <= MAX_STDOUT_BYTES and
            uint(probe_completed.get("stderr_size"), "capacity policy probe stderr size") == 0,
            "capacity policy probe did not complete successfully")
    probe_stderr = _pin_path(probe_completed.get("stderr_path"), "capacity probe stderr path")
    require(probe_stderr == stage_dir / "jobs" / job["run_id"] / "policy-probe.stderr",
            "capacity probe stderr path differs from the fresh job directory")
    probe_stdout_event_sha = digest(probe_completed.get("stdout_sha256"),
                                    "capacity policy probe stdout SHA-256")
    probe_stderr_event_sha = digest(probe_completed.get("stderr_sha256"),
                                    "capacity policy probe stderr SHA-256")
    probe_stderr_raw, _probe_stderr_info = read_stable(probe_stderr, "capacity probe stderr", MAX_STDERR_BYTES)
    require(not probe_stderr_raw and probe_stderr_event_sha == sha256_bytes(probe_stderr_raw),
            "capacity policy probe stderr is nonempty or differs from its exit record")
    probe_pin = exact(by_event["probe_verified"].get("probe"), {"path", "sha256"}, "verified policy probe pin")
    probe_path, probe_raw, probe_sha = _read_evidence_pin(probe_pin, "policy probe output", MAX_PROBE_BYTES, stage_dir)
    require(probe_completed.get("stdout_path") == str(probe_path) and
            probe_stdout_event_sha == probe_sha and
            probe_completed.get("stdout_size") == len(probe_raw),
            "policy probe completion and verified output pins differ")
    probe_verified = by_event["probe_verified"]
    source_pin = _event_pin(context["source_path"], context["source_raw_sha256"])
    require(probe_verified.get("probe_sha256") == probe_sha and
            probe_verified.get("source_manifest") == source_pin,
            "verified policy probe source/output pins differ from captured source evidence")
    request_template, request_template_sha, context_template, context_template_sha = _find_template_template(
        job, context["input_root"], context,
    )
    request_copy = exact(probe_verified.get("request_template_copy"), {"path", "sha256"},
                         "staged capacity request template copy")
    context_copy = exact(probe_verified.get("context_template_copy"), {"path", "sha256"},
                         "staged capacity context template copy")
    request_copy_path, request_copy_raw, request_copy_sha = _read_evidence_pin(
        request_copy, "staged capacity request template", MAX_TEMPLATE_BYTES, stage_dir,
    )
    context_copy_path, context_copy_raw, context_copy_sha = _read_evidence_pin(
        context_copy, "staged capacity context template", MAX_TEMPLATE_BYTES, stage_dir,
    )
    require(request_copy_path == stage_dir / "jobs" / job["run_id"] / "request-template.json" and
            context_copy_path == stage_dir / "jobs" / job["run_id"] / "context-template.json" and
            request_copy_raw == canonical_bytes(request_template) and
            context_copy_raw == canonical_bytes(context_template) and
            request_copy_sha == request_template_sha and context_copy_sha == context_template_sha,
            "copied request/context templates differ from their source-pinned canonical values")
    require(request_template_sha == job["template"]["request_template"]["raw_sha256"] and
            context_template_sha == job["template"]["context_template"]["raw_sha256"],
            "capacity templates drifted after the plan was frozen")
    probe = parse_object(probe_raw, "policy probe output", MAX_PROBE_BYTES, canonical=True)
    seed = _expectation_seed(
        _job_identity(job, context["source"]),
        _make_policy(_job_identity(job, context["source"]),
                     context["source"], probe, context["stack"]["feedback_reader"]),
        source_pin, probe_pin, job["template"]["calibrator"]["allocator"],
        expected_binary_sha, request_template["minimum_interval_seconds"],
    )
    seed["identity"] = {**seed["identity"], "process_id": 0}
    checked_probe, seed_sha = _verify_probe_output(
        probe_path, probe_sha, seed, context["source"], context["stack"]["feedback_reader"],
    )
    require(probe_verified.get("expectation_seed_sha256") == seed_sha and
            probe_verified.get("policy_sha256") == sha256_bytes(canonical_bytes(seed["policy"])),
            "policy/probe pin changed before application dispatch")
    app_dispatch = by_event["application_dispatch"]
    application_argv = _expected_argv(expected_binary, job, context["spec"])
    probe_environment = exact(probe_dispatch.get("environment"), {"PATH", "LC_ALL", "TMPDIR"},
                              "capacity probe launch environment")
    expected_probe_environment = {
        "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": app_dispatch["tmpdir_path"],
    }
    application_probe_pin = exact(app_dispatch.get("probe"), {"path", "sha256"},
                                  "application dispatch policy probe pin")
    dispatch_process_deadline = uint(app_dispatch.get("process_deadline_seconds"),
                                     "capacity dispatch process deadline", positive=True)
    environment = _application_environment(
        _job_identity(job, context["source"]),
        Path(app_dispatch.get("trace_directory", "/invalid")),
        Path(app_dispatch.get("tmpdir_path", "/invalid")),
    )
    require(probe_environment == expected_probe_environment and
            app_dispatch.get("argv") == application_argv and
            app_dispatch.get("environment") == environment and
            app_dispatch.get("expected_binary_sha256") == expected_binary_sha and
            application_probe_pin == probe_pin and
            app_dispatch.get("policy_sha256") == sha256_bytes(canonical_bytes(seed["policy"])) and
            app_dispatch.get("mode") == "capacity" and
            app_dispatch.get("capacity_horizon_seconds") == 30 and
            app_dispatch.get("external_pressure") is False and
            app_dispatch.get("pressure_qualification") is False and
            dispatch_process_deadline == context["spec"]["deadlines"]["process_seconds"],
            "capacity application dispatch differs from the frozen workload/profile/executor/deadlines")
    require(app_dispatch.get("trace_directory") == str(stage_dir / "jobs" / job["run_id"] / "trace") and
            app_dispatch.get("cwd") == str(stage_dir / "jobs" / job["run_id"]),
            "capacity application trace/TMPDIR/cwd is not fresh under the private stage")
    require("ALLOCATBELT_APP_CAPACITY_CALIBRATION_FILE" not in environment and
            "ALLOCATBELT_APP_CAPACITY_CALIBRATION_SHA256" not in environment,
            "capacity application inherited a prior capacity artifact")
    bound = by_event["application_bound"]
    pid = uint(bound.get("pid"), "actual application PID", positive=True, maximum=(1 << 31) - 1)
    feedback_verified = by_event["feedback_verified"]
    require(feedback_verified.get("process_identity_sha256") ==
            sha256_bytes(canonical_bytes(bound)),
            "feedback verification process-identity pin differs from the actual application-bound record")
    require(bound.get("nonce") == job["nonce"] and bound.get("executable_sha256") == expected_binary_sha and
            bound.get("executable_path") == str(expected_binary) and
            bound.get("environment") == environment and
            bound.get("environment_sha256") == sha256_bytes(canonical_bytes(environment)) and
            bound.get("tmpdir_path") == app_dispatch["tmpdir_path"] == environment["TMPDIR"] and
            bound.get("trace_directory") == app_dispatch["trace_directory"] == environment["ALLOCATBELT_APP_FEEDBACK_TRACE_DIR"] and
            bound.get("external_pressure") is False and bound.get("pressure_qualification") is False and
            bound.get("cpu_affinity") == context["current_host"]["cpu_affinity"] and
            bound.get("network_namespace_inode") == context["current_host"]["network_namespace_inode"] and
            bound.get("cwd") == str(stage_dir / "jobs" / job["run_id"]),
            "actual application PID/start/executable/nonce/cwd/affinity/environment binding differs")
    uint(bound.get("start_ticks"), "actual application start ticks", positive=True)
    app_exit = by_event["application_exited"]
    process_deadline = uint(context["spec"]["deadlines"]["process_seconds"],
                            "capacity process deadline", positive=True)
    exit_process_deadline = uint(app_exit.get("process_seconds"),
                                 "capacity exit process deadline", positive=True)
    app_elapsed_ns = uint(app_exit.get("elapsed_ns"), "capacity application elapsed nanoseconds")
    require(app_exit.get("signal") is None,
            "capacity application recorded a signal on completed exit")
    require(app_elapsed_ns <= process_deadline * 1_000_000_000,
            "capacity application elapsed time exceeds its frozen process deadline")
    require(app_exit.get("pid") == pid and app_exit.get("status") == "completed" and
            type(app_exit.get("return_code")) is int and app_exit["return_code"] == 0 and
            uint(app_exit.get("stderr_size"), "capacity stderr size", maximum=MAX_STDERR_BYTES) == 0 and
            exit_process_deadline == process_deadline,
            "capacity application did not exit successfully within its frozen deadline")
    app_stdout_pin = exact(app_exit.get("stdout"), {"path", "sha256"}, "capacity application stdout pin")
    app_stderr_pin = exact(app_exit.get("stderr"), {"path", "sha256"}, "capacity application stderr pin")
    expected_stdout_path = stage_dir / "jobs" / job["run_id"] / "application.stdout"
    expected_stderr_path = stage_dir / "jobs" / job["run_id"] / "application.stderr"
    require(app_stdout_pin["path"] == str(expected_stdout_path) and
            app_stderr_pin["path"] == str(expected_stderr_path),
            "capacity application exit captures differ from the fresh job directory")
    stdout_path, stdout_raw, stdout_sha = _read_evidence_pin(
        app_stdout_pin, "capacity application stdout", MAX_STDOUT_BYTES, stage_dir,
    )
    stderr_path, stderr_raw, stderr_sha = _read_evidence_pin(
        app_stderr_pin, "capacity application stderr", MAX_STDERR_BYTES, stage_dir,
    )
    require(stdout_path == expected_stdout_path and stderr_path == expected_stderr_path and
            len(stdout_raw) == uint(app_exit.get("stdout_size"), "capacity stdout size", maximum=MAX_STDOUT_BYTES) and
            len(stderr_raw) == uint(app_exit.get("stderr_size"), "capacity stderr size", maximum=MAX_STDERR_BYTES) == 0 and
            digest(app_exit.get("stderr_sha256"), "capacity stderr SHA-256") == stderr_sha and
            digest(app_exit.get("stdout_sha256"), "capacity stdout SHA-256") == stdout_sha and
            app_exit["stderr"]["sha256"] == stderr_sha and app_exit["stdout"]["sha256"] == stdout_sha,
            "capacity application stdout/stderr bytes differ from the actual exit record")
    expectation_pin = exact(by_event["feedback_verified"].get("expectation"),
                            {"path", "sha256"}, "feedback expectation pin")
    bundle_verified = by_event["bundle_verified"]
    require(feedback_verified.get("expectation_sha256") == expectation_pin["sha256"] and
            bundle_verified.get("expectation") == expectation_pin and
            bundle_verified.get("probe") == probe_pin,
            "feedback/bundle expectation or probe pins differ from their captured source roles")
    expectation_path, expectation_raw, expectation_sha = _read_evidence_pin(
        expectation_pin, "feedback expectation", MAX_TEMPLATE_BYTES, stage_dir,
    )
    expectation_value = parse_object(expectation_raw, "feedback expectation", MAX_TEMPLATE_BYTES, canonical=True)
    expected_expectation_raw, expected_expectation_sha, expected_expectation = _finish_expectation(
        seed, pid, context["stack"]["feedback_reader"],
    )
    require(expectation_raw == expected_expectation_raw and expectation_sha == expected_expectation_sha and
            expectation_value == expected_expectation,
            "V4 expectation is not the fixed prelaunch seed with only the actual PID instantiated")
    trace_details = by_event["trace_captured"]
    trace_dir = Path(app_dispatch["trace_directory"])
    require(trace_details.get("trace_directory") == str(trace_dir) and
            trace_details.get("application_pid") == pid,
            "captured trace directory/PID differs from the validated application dispatch")
    traces = exact(trace_details.get("traces"), {"manifest", "events", "samples"}, "captured trace pins")
    trace_hashes: dict[str, str] = {}
    for role, filename in (
        ("manifest", "feedback-trace-manifest.tsv"),
        ("events", "feedback-events.jsonl"),
        ("samples", "resource-samples.tsv"),
    ):
        pin = exact(traces[role], {"path", "sha256"}, f"captured trace {role} pin")
        expected_path = trace_dir / filename
        require(pin["path"] == str(expected_path), f"captured trace {role} path differs")
        _path, raw_sha = _hash_evidence_pin(pin, f"captured trace {role}", MAX_TRACE_FILE_BYTES, stage_dir)
        trace_hashes[role] = raw_sha
    require(trace_details.get("trace_hashes") == trace_hashes and trace_details.get("application_pid") == pid,
            "captured trace hashes/PID differ from application dispatch")
    require(_directory_names(trace_dir) == {
        "feedback-trace-manifest.tsv", "feedback-events.jsonl", "resource-samples.tsv",
    }, "captured trace directory has missing or unexpected members")
    validation_pin = exact(by_event["feedback_verified"].get("validation"),
                            {"path", "sha256"}, "feedback validation pin")
    validation_path, validation_raw, validation_sha = _read_evidence_pin(
        validation_pin, "feedback validation", MAX_METADATA_BYTES, stage_dir,
    )
    try:
        validation, expected_validation_raw_sha = context["stack"]["feedback_reader"].verify_feedback(
            expectation_path, expectation_sha, trace_dir, trace_hashes,
        ), None
        expected_validation_raw = context["stack"]["feedback_reader"].canonical_bytes(validation)
        expected_validation_raw_sha = sha256_bytes(expected_validation_raw)
    except Exception as error:
        raise CapacityStageError(f"captured feedback reader replay failed during completion verification: {error}") from error
    require(validation_raw == expected_validation_raw and validation_sha == expected_validation_raw_sha and
            validation.get("validated") is True and validation.get("qualification_eligible") is False and
            validation.get("expectation_raw_sha256") == expectation_sha and
            validation.get("raw_artifact_sha256") == trace_hashes,
            "feedback validation receipt differs from full SourceV5 reader replay")
    require(feedback_verified.get("validation_sha256") == validation_sha and
            bundle_verified.get("validation") == validation_pin and
            bundle_verified.get("traces") == traces,
            "feedback/bundle validation or trace pins differ from their captured evidence roles")
    require(feedback_verified.get("validator_sha256") == context["stack"]["feedback_reader_sha256"] and
            feedback_verified.get("trace_hashes") == trace_hashes and
            feedback_verified.get("application_pid") == pid,
            "feedback verification event has mismatched source/trace/process pins")
    context_pin = exact(by_event["bundle_verified"].get("context"), {"path", "sha256"}, "capacity context pin")
    context_path, context_raw, context_sha = _read_evidence_pin(
        context_pin, "capacity context", MAX_TEMPLATE_BYTES, stage_dir,
    )
    context_value = parse_object(context_raw, "capacity context", MAX_TEMPLATE_BYTES, canonical=True)
    storage_template = context_template["storage"]
    network_template = context_template["network"]
    if storage_template is None:
        expected_storage = None
        expected_tmpdir = stage_dir / "jobs" / job["run_id"] / "tmp"
        require(app_dispatch["tmpdir_path"] == bound["tmpdir_path"] == environment["TMPDIR"] ==
                str(expected_tmpdir),
                "application dispatch/bound TMPDIR differs from the fresh stage-local context")
        tmpdir_path = _safe_root(Path(expected_tmpdir), "capacity process TMPDIR")
        _check_new_directory(tmpdir_path, "capacity process TMPDIR")
    else:
        expected_storage = exact(context_value.get("storage"), {
            "scope", "root_path", "filesystem_type", "device_major_minor", "minimum_free_bytes",
            "tmpdir_path", "available_bytes_at_launch",
        }, "observed capacity storage context")
        require({key: expected_storage[key] for key in storage_template} == storage_template and
                _is_within(Path(storage_template["root_path"]), Path(expected_storage["tmpdir_path"])) and
                uint(expected_storage["available_bytes_at_launch"], "observed free bytes") >= storage_template["minimum_free_bytes"],
                "capacity storage context differs from its typed template or observed free-space bound")
        tmpdir_path = _safe_root(Path(expected_storage["tmpdir_path"]), "capacity application TMPDIR")
        require(tmpdir_path.parent == Path(storage_template["root_path"]),
                "capacity application TMPDIR is not a fresh child of the frozen storage root")
        require(app_dispatch["tmpdir_path"] == bound["tmpdir_path"] == environment["TMPDIR"] ==
                str(tmpdir_path),
                "application dispatch/bound TMPDIR differs from the validated storage context")
        _check_new_directory(tmpdir_path, "capacity application TMPDIR")
        live_storage = _storage_snapshot(storage_template, context["source_root"], tmpdir_path)
        require(live_storage["filesystem_type"] == expected_storage["filesystem_type"] and
                live_storage["device_major_minor"] == expected_storage["device_major_minor"],
                "capacity application TMPDIR filesystem/device changed after the observed launch")
    if network_template is None:
        expected_network = None
    else:
        expected_network = exact(context_value.get("network"), {
            "scope", "interface", "address", "namespace_inode", "ifindex",
        }, "observed capacity network context")
        require({key: expected_network[key] for key in network_template} == network_template and
                expected_network["namespace_inode"] == context["current_host"]["network_namespace_inode"] and
                type(expected_network["ifindex"]) is int and expected_network["ifindex"] > 0,
                "capacity network context differs from the observed loopback namespace")
        require(_network_snapshot(network_template, context["host_context"]) == expected_network,
                "capacity network namespace/interface identity changed after the observed launch")
    expected_context = {
        "schema": CAPACITY_CONTEXT_SCHEMA, "identity": expected_expectation["identity"],
        "stage": "pre_confirmation", "storage": expected_storage,
        "network": expected_network,
    }
    require(context_value == expected_context,
            "capacity producer context differs from the exact typed observed host context")
    require(app_dispatch.get("storage_context") == expected_storage and
            app_dispatch.get("network_context") == expected_network,
            "application dispatch storage/network observations differ from the producer context")
    request_pin = exact(by_event["bundle_verified"].get("request"), {"path", "sha256"}, "capacity request pin")
    request_path, request_raw, request_sha = _read_evidence_pin(
        request_pin, "capacity request", MAX_TEMPLATE_BYTES, stage_dir,
    )
    request_value = parse_object(request_raw, "capacity request", MAX_TEMPLATE_BYTES, canonical=True)
    expected_request = {
        "schema": context["stack"]["capacity_producer"].REQUEST_SCHEMA,
        "calibration_id": job["capacity_key"]["calibration_id"],
        "identity": expected_expectation["identity"],
        "source_manifest": source_pin, "validation": validation_pin,
        "expectation": expectation_pin, "expectation_sha256": expectation_sha,
        "validator_sha256": context["source"]["qualification_harness"]["feedback_validator"]["sha256"],
        "trace_directory": str(trace_dir), "context": context_pin,
        "minimum_interval_seconds": request_template["minimum_interval_seconds"],
    }
    require(request_value == expected_request,
            "instantiated capacity request differs from the strict template and observed trace pins")
    artifact_pin = exact(by_event["bundle_verified"].get("artifact"), {"path", "sha256"}, "capacity artifact pin")
    receipt_pin = exact(by_event["bundle_verified"].get("receipt"), {"path", "sha256"}, "capacity receipt pin")
    artifact_path, _artifact_raw, artifact_sha = _read_evidence_pin(
        artifact_pin, "capacity TSV artifact", 4096, stage_dir,
    )
    receipt_path, _receipt_raw, receipt_sha = _read_evidence_pin(
        receipt_pin, "capacity receipt", MAX_METADATA_BYTES, stage_dir,
    )
    require(artifact_path == stage_dir / "jobs" / job["run_id"] / "capacity-bundle" / "application-byte-capacity.tsv" and
            receipt_path == stage_dir / "jobs" / job["run_id"] / "capacity-bundle" / "capacity-receipt.json",
            "capacity bundle paths differ from the atomic producer publication directory")
    try:
        replayed = context["stack"]["capacity_producer"].verify_capacity_bundle(
            request_pin, artifact_pin, receipt_pin,
        )
    except Exception as error:
        raise CapacityStageError(f"captured SourceV5 capacity producer replay failed: {error}") from error
    require(replayed is True and by_event["bundle_verified"].get("producer_sha256") ==
            context["stack"]["capacity_producer_sha256"] and
            by_event["bundle_verified"].get("feedback_reader_sha256") ==
            context["stack"]["feedback_reader_sha256"] and
            by_event["bundle_verified"].get("actual_pid") == pid and
            by_event["bundle_verified"].get("actual_start_ticks") == bound["start_ticks"] and
            by_event["bundle_verified"].get("actual_executable_sha256") == expected_binary_sha and
            by_event["bundle_verified"].get("qualification_eligible") is False,
            "capacity bundle replay event differs from the captured source stack or actual process")
    del common, checked_probe, context_path, context_sha, request_path, request_sha, receipt_sha, artifact_sha
    return {
        "ordinal": 1, "template_index": job["template_index"],
        "run_id": job["run_id"], "calibration_id": job["capacity_key"]["calibration_id"],
        "workload": job["capacity_key"]["workload"], "profile": job["capacity_key"]["profile"],
        "template_sha256": job["template_sha256"], "nonce": job["nonce"],
        "probe": probe_pin, "expectation": expectation_pin, "context": context_pin,
        "request": request_pin, "traces": traces, "validation": validation_pin,
        "artifact": artifact_pin, "receipt": receipt_pin,
        "actual_pid": pid, "actual_start_ticks": bound["start_ticks"],
        "actual_executable_sha256": expected_binary_sha,
        "actual_affinity": bound["cpu_affinity"], "actual_cwd": bound["cwd"],
        "actual_environment_sha256": sha256_bytes(canonical_bytes(environment)),
    }


def verify_capacity_completion(
    plan_pin: dict[str, Any], spec_pin: dict[str, Any], source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: dict[str, Any],
    output_root: Path, completion_pin: dict[str, Any],
) -> dict[str, Any]:
    """Reconstruct the schedule, audit exact ledger transitions, and replay all bundles."""
    context = _prepare_pins(plan_pin, spec_pin, source_root, input_root, host_id, observed_host_pin)
    output_root = _safe_root(output_root, "capacity stage output root")
    require(not _is_within(context["source_root"], output_root),
            "capacity stage output must be outside SourceV5")
    completion, completion_raw, completion_raw_sha = read_pin(
        completion_pin, "capacity completion overlay", MAX_METADATA_BYTES, canonical=True,
    )
    completion_info = Path(exact(completion_pin, {"path", "sha256"}, "completion pin")["path"]).stat(follow_symlinks=False)
    require(stat.S_ISREG(completion_info.st_mode) and stat.S_IMODE(completion_info.st_mode) == 0o600 and
            completion_info.st_uid == os.getuid(),
            "capacity completion overlay must be a private mode-0600 regular file")
    exact(completion, {
        "schema", "complete", "qualification_eligible", "campaign_id", "host_id",
        "controller_chronology_proven",
        "spec", "plan", "source", "observed_host", "stage", "controller", "inputs",
        "feedback_reader", "capacity_producer", "capacity_process_templates_sha256",
        "stage_directory", "ledger", "entries",
    }, "capacity completion overlay")
    require(completion["schema"] == COMPLETION_SCHEMA and completion["complete"] is True and
            completion["qualification_eligible"] is False and
            completion["controller_chronology_proven"] is False,
            "capacity completion overlay does not assert an ineligible complete stage")
    require(completion["campaign_id"] == context["spec"]["campaign_id"] and
            completion["host_id"] == context["host_id"],
            "capacity completion campaign/host differs from its source inputs")
    expected_raw_pins = {
        "spec": {"path": str(context["spec_path"]), "raw_sha256": context["spec_raw_sha256"],
                 "semantic_sha256": context["spec_semantic_sha256"]},
        "plan": {"path": str(context["plan_path"]), "raw_sha256": context["plan_raw_sha256"],
                 "semantic_sha256": context["plan_semantic_sha256"]},
        "source": {"path": str(context["source_path"]), "raw_sha256": context["source_raw_sha256"],
                   "semantic_sha256": context["source_semantic_sha256"],
                   "source_tree_sha256": context["source_tree_sha256"]},
        "observed_host": {"path": str(context["host_context_path"]),
                          "raw_sha256": context["host_context_raw_sha256"],
                          "boot_id_sha256": context["current_host"]["boot_id_sha256"],
                          "cpu_affinity": context["current_host"]["cpu_affinity"],
                          "network_namespace_inode": context["current_host"]["network_namespace_inode"]},
        "stage": {"path": str(context["source_root"] / STAGE_SOURCE_PATH),
                  "sha256": context["stack"]["stage_sha256"]},
        "controller": {"path": CONTROLLER_PATH, "sha256": context["stack"]["controller_sha256"]},
        "inputs": {"path": INPUTS_PATH, "sha256": context["stack"]["inputs_sha256"]},
        "feedback_reader": {"path": FEEDBACK_READER_PATH,
                            "sha256": context["stack"]["feedback_reader_sha256"]},
        "capacity_producer": {"path": CAPACITY_PRODUCER_PATH,
                              "sha256": context["stack"]["capacity_producer_sha256"]},
    }
    for role, expected in expected_raw_pins.items():
        require(completion[role] == expected,
                f"capacity completion {role} raw/semantic pin differs from caller inputs")
    jobs = derive_capacity_jobs(context["plan"], context["host_id"])
    schedule_sha = context["plan"]["capacity_process_templates_sha256"]
    require(completion["capacity_process_templates_sha256"] == schedule_sha,
            "capacity completion schedule digest differs from the frozen plan")
    stage_dir = _pin_path(completion["stage_directory"], "capacity stage directory")
    expected_stage_dir = output_root / context["spec"]["campaign_id"] / "capacity" / context["host_id"]
    require(stage_dir == expected_stage_dir and _is_within(output_root, stage_dir) and
            not _is_within(context["source_root"], stage_dir),
            "capacity completion stage directory is outside its required private output layout")
    _check_new_directory(stage_dir, "capacity completion stage directory")
    require(completion_pin["path"] == str(stage_dir / "capacity-stage-completion.json"),
            "capacity completion overlay path differs from its stage directory")
    ledger_value = exact(completion["ledger"], {"path", "raw_sha256", "terminal_head"},
                         "sealed capacity ledger pin")
    ledger_path = _pin_path(ledger_value["path"], "capacity ledger path")
    require(ledger_path == stage_dir / "controller-ledger.jsonl" and
            _is_within(stage_dir, ledger_path), "capacity ledger path escaped the sealed stage directory")
    records, _ledger_raw_sha = _read_ledger(
        ledger_path, digest(ledger_value["raw_sha256"], "ledger raw SHA-256"),
        digest(ledger_value["terminal_head"], "ledger terminal head"),
    )
    require(len(records) == 15 * len(JOB_EVENTS) + 1,
            "successful capacity ledger has an incomplete or unexpected transition count")
    expected_global_events = [event for _job in jobs for event in JOB_EVENTS] + ["stage_complete"]
    require([record["event"] for record in records] == expected_global_events,
            "capacity stage ledger does not preserve the original plan template order")
    require([item["event"] for item in records[-1:]] == ["stage_complete"] and
            all(item["event"] != "stage_failed" for item in records),
            "capacity ledger terminal event does not seal a successful stage")
    for record in records:
        require(record["campaign_id"] == context["spec"]["campaign_id"] and
                record["host_id"] == context["host_id"] and
                record["spec_raw_sha256"] == context["spec_raw_sha256"] and
                record["spec_semantic_sha256"] == context["spec_semantic_sha256"] and
                record["plan_raw_sha256"] == context["plan_raw_sha256"] and
                record["plan_semantic_sha256"] == context["plan_semantic_sha256"] and
                record["source_manifest_raw_sha256"] == context["source_raw_sha256"] and
                record["source_manifest_semantic_sha256"] == context["source_semantic_sha256"] and
                record["source_tree_sha256"] == context["source_tree_sha256"] and
                record["capacity_schedule_sha256"] == schedule_sha and
                record["observed_host_raw_sha256"] == context["host_context_raw_sha256"] and
                record["boot_id_sha256"] == context["current_host"]["boot_id_sha256"],
                f"capacity completion ledger record {record['sequence']} changed pinned provenance")
    reconstructed = [
        _verify_job_records(records, job, context, stage_dir)
        for job in jobs
    ]
    require(type(completion["entries"]) is list and len(completion["entries"]) == 15,
            "capacity completion overlay must have exactly 15 entries")
    require(canonical_bytes(completion["entries"]) == canonical_bytes(reconstructed),
            "capacity completion overlay entries differ from reconstructed verified bundles")
    terminal = records[-1]
    require(terminal["run_id"] is None and terminal["ordinal"] is None and
            terminal["details"] == {
                "completion_schema": COMPLETION_SCHEMA,
                "entry_count": 15,
                "capacity_process_templates_sha256": schedule_sha,
                "qualification_eligible": False,
                "controller_chronology_proven": False,
            }, "capacity ledger successful terminal record is malformed")
    return {
        "completion_raw_sha256": completion_raw_sha,
        "ledger_raw_sha256": ledger_value["raw_sha256"],
        "terminal_head": ledger_value["terminal_head"],
        "complete": True, "qualification_eligible": False,
        "controller_chronology_proven": False,
        "entry_count": 15, "capacity_process_templates_sha256": schedule_sha,
    }


def _cli_pin(path: Path, raw_sha: str) -> dict[str, str]:
    return {"path": str(path), "sha256": raw_sha}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "verify"):
        command = commands.add_parser(name, help=f"{name} one host's pinned capacity stage")
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--plan-sha256", required=True)
        command.add_argument("--spec", type=Path, required=True)
        command.add_argument("--spec-sha256", required=True)
        command.add_argument("--source-root", type=Path, required=True)
        command.add_argument("--input-root", type=Path, required=True)
        command.add_argument("--host-id", required=True)
        command.add_argument("--observed-host", type=Path, required=True)
        command.add_argument("--observed-host-sha256", required=True)
        command.add_argument("--output-root", type=Path, required=True)
        if name == "verify":
            command.add_argument("--completion", type=Path, required=True)
            command.add_argument("--completion-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan_pin = _cli_pin(args.plan, args.plan_sha256)
        spec_pin = _cli_pin(args.spec, args.spec_sha256)
        observed_pin = _cli_pin(args.observed_host, args.observed_host_sha256)
        if args.command == "run":
            result = run_capacity_stage(
                plan_pin, spec_pin, args.source_root, args.input_root, args.host_id,
                observed_pin, args.output_root,
            )
        else:
            completion_pin = _cli_pin(args.completion, args.completion_sha256)
            result = verify_capacity_completion(
                plan_pin, spec_pin, args.source_root, args.input_root, args.host_id,
                observed_pin, args.output_root, completion_pin,
            )
        sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except (CapacityStageError, OSError, subprocess.SubprocessError, ValueError,
            TypeError, KeyError, UnicodeError) as error:
        print(f"application capacity stage: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
