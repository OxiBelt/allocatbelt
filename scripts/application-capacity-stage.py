#!/usr/bin/env python3
"""Run and independently replay one host's 15 SourceV5 capacity calibrations.

The stage starts only source-pinned application binaries, verifies the actual
feedback-policy emitter before each capacity process, and seals a hash-chained
ledger before publishing a canonical completion overlay. Calibration remains
pre-confirmation evidence and is never qualification eligible.
"""
from __future__ import annotations

import argparse
import errno
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
PREPARATION_INTENT_SCHEMA = "allocatbelt.application-source5-preparation.v1"
PREPARATION_EVENT_SCHEMA = "allocatbelt.application-capacity-preparation-event.v1"
PREPARATION_COMPLETION_SCHEMA = "allocatbelt.application-capacity-preparation-completion.v1"
PREPARATION_BOUNDED_EVENT_SCHEMA = "allocatbelt.application-capacity-preparation-event.v2"
PREPARATION_BOUNDED_COMPLETION_SCHEMA = "allocatbelt.application-capacity-preparation-completion.v2"
NONCE_SCHEMA = "allocatbelt.application-process-nonce-instantiation.v1"
STAGE_SOURCE_PATH = "scripts/application-capacity-stage.py"
CONTROLLER_PATH = "scripts/application-campaign.py"
INPUTS_PATH = "scripts/application-campaign-inputs.py"
FEEDBACK_READER_PATH = "scripts/application-feedback-readback.py"
CAPACITY_PRODUCER_PATH = "scripts/application-byte-capacity.py"
PREPARATION_HELPER_PATH = "scripts/application-source5-input-preparation.py"
PREPARATION_NONCE_SCHEMA = "allocatbelt.application-source5-capacity-nonce.v1"
EVIDENCE_PATH_MAP_SCHEMA = "allocatbelt.application-pressure-evidence-path-map.v1"
PREPARATION_VERIFICATION_SCHEMA = "allocatbelt.application-capacity-preparation-verification.v1"
PREPARATION_BOUNDED_VERIFICATION_SCHEMA = "allocatbelt.application-capacity-preparation-verification.v2"
PREPARATION_RESOURCE_BUDGET_SCHEMA = "allocatbelt.application-source5-preparation-resource-budget.v1"
PREPARATION_RESOURCE_MONITOR_SCHEMA = "allocatbelt.application-capacity-preparation-resource-monitor.v1"
DIRECT_OWNER_RETURN_FAILURE_SCHEMA = "allocatbelt.application-capacity-direct-owner-return-failure.v1"
PREPARATION_FIXED_PAIR_R4_WALKER_SHA256 = "8e607dec6ef2ea93398eaec5dc6e3d9f048aabf335df64634fa149402c8c0fe1"
OWNED_PROCESS_CAPTURE_SCHEMA = "allocatbelt.application-capacity-stage-owned-process-capture.v1"
OWNED_POLICY_PROBE_START_SCHEMA = "allocatbelt.application-capacity-stage-owned-policy-probe-start.v1"
OWNED_POLICY_PROBE_CAPTURE_SCHEMA = "allocatbelt.application-capacity-stage-owned-policy-probe-capture.v1"
PREPARATION_PROCESS_OWNER_SCHEMA = "allocatbelt.application-capacity-preparation-process-owner.v1"

MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_SYMLINK_BYTES = 4 * 1024
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
MAX_PROBE_BYTES = 512 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_OWNED_PROCESS_SIGNAL_RECORDS = 2048
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 4 * 1024 * 1024
MAX_TRACE_FILE_BYTES = 1024 * 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_EVENT_LINE_BYTES = 2 * 1024 * 1024
MAX_EVENT_RECORDS = 256
MAX_PATH_BYTES = 4096
U64_MAX = (1 << 64) - 1
MAX_PREPARATION_JOB_OUTPUT_INODES = MAX_EVENT_RECORDS
MAX_PREPARATION_GENERATION_INODES = 15 * MAX_PREPARATION_JOB_OUTPUT_INODES + MAX_EVENT_RECORDS
MAX_PREPARATION_JOB_OUTPUT_BYTES = (
    3 * MAX_TRACE_FILE_BYTES + MAX_STDOUT_BYTES + MAX_PROBE_BYTES +
    2 * MAX_STDERR_BYTES + 12 * MAX_METADATA_BYTES + 2 * MAX_TEMPLATE_BYTES + 4096
)
MAX_PREPARATION_GENERATION_BYTES = (
    15 * MAX_PREPARATION_JOB_OUTPUT_BYTES + MAX_LEDGER_BYTES + 2 * MAX_METADATA_BYTES
)
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
OWNED_PROCESS_EVENT_FIELDS = {
    "direct_process_start", "direct_process_capture",
    "direct_process_runner_sha256", "process_identity_helper_sha256",
}
OWNED_PROCESS_START_EVENT_FIELDS = {
    "direct_process_start", "direct_process_runner_sha256", "process_identity_helper_sha256",
}


class CapacityStageError(ValueError):
    """A frozen input, bounded process, trace, or completion failed validation."""


class DirectOwnerPostReturnError(CapacityStageError):
    """A returned FixedR8 result was preserved before later validation failed."""

    def __init__(self, message: str, owner_return_pin: dict[str, str],
                 failure_pin: dict[str, str] | None):
        super().__init__(message)
        self.owner_return_pin = owner_return_pin
        self.failure_pin = failure_pin


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


def _source_inventory_symlink_target(
    item_value: object, records: dict[str, dict[str, Any]], label: str,
) -> tuple[str, bytes]:
    """Validate one literal SourceInventory terminal link without following it."""
    item = exact(item_value, {
        "path", "kind", "mode", "sha256", "size", "target",
    }, label)
    relative = _relative(item["path"], f"{label} path")
    require(item["kind"] == "symlink" and item["mode"] == "120000" and
            type(item["target"]) is str,
            f"{label} is not a typed terminal symlink")
    try:
        target_bytes = item["target"].encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise CapacityStageError(f"{label} target is not UTF-8 text") from error
    expected_sha = digest(item["sha256"], f"{label} literal target SHA-256")
    require(0 < len(target_bytes) <= MAX_SOURCE_SYMLINK_BYTES and
            type(item["size"]) is int and item["size"] == len(target_bytes) and
            sha256_bytes(target_bytes) == expected_sha and
            not item["target"].startswith("/") and
            "\\" not in item["target"] and "\n" not in item["target"] and
            "\r" not in item["target"] and "\x00" not in item["target"],
            f"{label} literal target hash, size, or bounded text differs")
    target_parts = item["target"].split("/")
    require(all(target_parts), f"{label} target is not a normalized relative path")
    resolved = list(relative.parts[:-1])
    for index, part in enumerate(target_parts):
        if part == ".":
            continue
        if part == "..":
            require(bool(resolved), f"{label} target escapes SourceRoot")
            resolved.pop()
        else:
            resolved.append(part)
            if index < len(target_parts) - 1:
                require("/".join(resolved) not in records,
                        f"{label} target traverses an inventoried non-directory")
    target_relative = "/".join(resolved)
    target_record = records.get(target_relative)
    require(target_record is not None and target_record.get("kind") == "file",
            f"{label} target is not one direct regular Source.files member")
    exact(target_record, {"path", "kind", "mode", "sha256", "size"},
          f"{label} direct target inventory record")
    require(target_record["path"] == target_relative and
            target_record["mode"] in {"100644", "100755"} and
            0 <= uint(target_record["size"], f"{label} target file size",
                      maximum=MAX_SOURCE_FILE_BYTES) <= MAX_SOURCE_FILE_BYTES,
            f"{label} target inventory member is not a bounded regular file")
    digest(target_record["sha256"], f"{label} direct target file SHA-256")
    return target_relative, target_bytes


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
    require(type(refs) is list and len(refs) in (2, 3),
            "SourceV5 spec must bind a complete supported host manifest set")
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
    host_ids = plan.get("host_ids")
    require(type(host_ids) is list and len(host_ids) in (2, 3) and
            all(type(item) is str and item for item in host_ids) and
            len(set(host_ids)) == len(host_ids) and host_id in host_ids,
            "capacity plan does not bind the selected host to a complete supported cohort")
    templates = plan.get("capacity_process_templates")
    expected_template_count = len(host_ids) * 15
    require(type(templates) is list and len(templates) == expected_template_count,
            "plan does not contain every host's frozen 15 capacity process templates")
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


class PreparationLedger(Ledger):
    """Hash-chained preparation ledger with no fabricated SpecV3/PlanV3 pins."""

    def __init__(self, path: Path, context: dict[str, Any], jobs_sha: str,
                 resource_budget_pin: dict[str, Any] | None = None):
        self.resource_budget_pin = resource_budget_pin
        super().__init__(path, context, jobs_sha)

    def append(self, event: str, job: dict[str, Any] | None,
               details: dict[str, Any]) -> str:
        require(event in JOB_EVENTS or event in ("stage_failed", "preparation_complete"),
                "unknown capacity preparation ledger event")
        self.sequence += 1
        require(self.sequence <= MAX_EVENT_RECORDS, "capacity preparation ledger exceeds its event cap")
        base = {
            "schema": PREPARATION_BOUNDED_EVENT_SCHEMA if self.resource_budget_pin is not None else PREPARATION_EVENT_SCHEMA,
            "sequence": self.sequence,
            "event": event, "monotonic_ns": time.monotonic_ns(),
            "boot_id_sha256": self.context["current_host"]["boot_id_sha256"],
            "campaign_id": self.context["spec"]["campaign_id"],
            "host_id": self.context["host_id"],
            "preparation_raw_sha256": self.context["preparation_raw_sha256"],
            "preparation_semantic_sha256": self.context["preparation_semantic_sha256"],
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
        if self.resource_budget_pin is not None:
            base["resource_budget"] = self.resource_budget_pin
        unsigned = {"previous_sha256": self.previous, "record": base}
        record_sha = sha256_bytes(canonical_bytes(unsigned))
        raw = canonical_bytes({**unsigned, "record_sha256": record_sha})
        require(len(raw) <= MAX_EVENT_LINE_BYTES, "capacity preparation ledger event exceeds its line cap")
        require(os.fstat(self.fd).st_size + len(raw) <= MAX_LEDGER_BYTES,
                "capacity preparation ledger exceeds its byte cap")
        offset = 0
        while offset < len(raw):
            written = os.write(self.fd, raw[offset:])
            require(written > 0, "capacity preparation ledger stopped accepting bytes")
            offset += written
        os.fsync(self.fd)
        self.previous = record_sha
        return record_sha


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


def _owned_process_requested_dispatch(
    argv: list[str], cwd: Path, environment: dict[str, str],
    expected_binary: Path, expected_binary_sha: str,
    requested_cpu_affinity: list[int], expected_network_namespace_inode: int,
) -> dict[str, Any]:
    return {
        "argv": argv,
        "argv_sha256": sha256_bytes(canonical_bytes(argv)),
        "environment_sha256": sha256_bytes(canonical_bytes(environment)),
        "cwd": str(cwd),
        "expected_binary_path": str(expected_binary),
        "expected_binary_sha256": expected_binary_sha,
        "requested_cpu_affinity": requested_cpu_affinity,
        "expected_network_namespace_inode": expected_network_namespace_inode,
    }


def _finish_source5_owner_capture(
    context: dict[str, Any], argv: list[str], cwd: Path,
    environment: dict[str, str], stdout_path: Path, stderr_path: Path,
    timeout_seconds: int, expected_binary: Path, expected_binary_sha: str,
    ownership_capture_path: Path, ownership_start_path: Path,
    start_proof: dict[str, Any] | None, start_pin: dict[str, str] | None,
    requested_dispatch: dict[str, Any], stdout_maximum: int,
    is_policy_probe: bool, capture: dict[str, Any],
    owner_return_pin: dict[str, str] | None,
) -> dict[str, Any]:
    """Validate outputs and seal the descriptive receipt after the raw owner return."""
    global _PENDING_SIGNAL
    stack = context["stack"]
    require(start_proof is not None and start_pin is not None and
            capture.get("start") == start_proof,
            "FixedR8 returned without its exact durable start callback")
    stdout_raw, _stdout_info = read_stable(
        stdout_path, "owned child stdout capture", stdout_maximum,
    )
    stderr_raw, _stderr_info = read_stable(
        stderr_path, "owned child stderr capture", MAX_STDERR_BYTES,
    )
    if is_policy_probe:
        capture_record = {
            "schema": OWNED_POLICY_PROBE_CAPTURE_SCHEMA,
            "role": "source5_policy_probe",
            "runner_sha256": stack["fixed_pair_sha256"],
            "identity_helper_sha256": stack["process_identity_helper_sha256"],
            "dispatch": requested_dispatch,
            "start": start_proof,
            "open_executable": {
                "path": capture["binary_path"], "sha256": capture["binary_sha256"],
                "device": capture["binary_device"], "inode": capture["binary_inode"],
                "size": capture["binary_size"],
            },
            "runner_capture": capture,
            "stdout": {"path": str(stdout_path), "raw_sha256": sha256_bytes(stdout_raw),
                       "size": len(stdout_raw)},
            "stderr": {"path": str(stderr_path), "raw_sha256": sha256_bytes(stderr_raw),
                       "size": len(stderr_raw)},
        }
    else:
        capture_record = {
            "schema": OWNED_PROCESS_CAPTURE_SCHEMA,
            "runner_sha256": stack["fixed_pair_sha256"],
            "identity_helper_sha256": stack["process_identity_helper_sha256"],
            "runner_capture": capture,
            "stdout": {"path": str(stdout_path), "raw_sha256": sha256_bytes(stdout_raw),
                       "size": len(stdout_raw)},
            "stderr": {"path": str(stderr_path), "raw_sha256": sha256_bytes(stderr_raw),
                       "size": len(stderr_raw)},
        }
    capture_raw = canonical_bytes(capture_record)
    require(len(capture_raw) <= MAX_METADATA_BYTES,
            "FixedR8 process capture exceeds the finite preparation receipt bound")
    capture_sha = _write_exclusive(ownership_capture_path, capture_raw)
    capture_pin = _event_pin(ownership_capture_path, capture_sha)
    supervision = exact(capture.get("supervision"), {
        "leader_info", "child_return_code", "timed_out", "artifact_budget_exceeded",
        "received_signal", "term_grace_seconds", "kill_reap_seconds", "signals",
        "leader_unreaped_during_group_signals", "group_signal_after_leader_reap_count",
        "leader_reaped", "remaining_session_members", "cleanup_errors", "cleanup_status",
    }, "FixedR8 owned-process cleanup record")
    require(type(capture.get("timing")) is dict and
            type(capture["timing"].get("elapsed_ns")) is int and
            capture["timing"]["elapsed_ns"] >= 0,
            "FixedR8 owned-process timing record is malformed")
    if supervision["received_signal"] is not None and _PENDING_SIGNAL is None:
        _PENDING_SIGNAL = supervision["received_signal"]
    if supervision["timed_out"]:
        status = "timeout"
    elif supervision["artifact_budget_exceeded"]:
        status = "output_limit"
    elif supervision["received_signal"] is not None:
        status = "interrupted"
    elif supervision["child_return_code"] is not None and supervision["cleanup_status"] == "verified":
        status = "completed"
    elif supervision["child_return_code"] is not None:
        status = "failed"
    else:
        status = "failed"
    direct_process = {
        "capture": capture_pin,
        "start": start_pin,
        "runner_sha256": stack["fixed_pair_sha256"],
        "identity_helper_sha256": stack["process_identity_helper_sha256"],
    }
    if owner_return_pin is not None:
        direct_process["owner_return"] = owner_return_pin
    return {
        "pid": start_proof["pid"], "process_identity": start_proof,
        "return_code": supervision["child_return_code"], "status": status,
        "signal": supervision["received_signal"],
        "elapsed_ns": capture["timing"]["elapsed_ns"],
        "stdout_path": str(stdout_path), "stdout_sha256": sha256_bytes(stdout_raw),
        "stdout_size": len(stdout_raw), "stderr_path": str(stderr_path),
        "stderr_sha256": sha256_bytes(stderr_raw), "stderr_size": len(stderr_raw),
        "direct_process": direct_process,
    }


def _spawn_with_source5_owner(
    context: dict[str, Any], argv: list[str], cwd: Path, environment: dict[str, str],
    stdout_path: Path, stderr_path: Path, timeout_seconds: int, expected_binary: Path,
    expected_binary_sha: str, ownership_capture_path: Path,
    ownership_start_path: Path, *, on_bound: Callable[[dict[str, Any]], None] | None = None,
    resource_monitor: Callable[[], bool] | None = None,
    owner_return_path: Path | None = None,
) -> dict[str, Any]:
    """Launch one Source5 preparation child through the captured FixedR8 owner."""
    global _PENDING_SIGNAL
    stack = context["stack"]
    fixed = stack.get("fixed_pair")
    helper = stack.get("process_identity_helper")
    require(callable(getattr(fixed, "_run_direct_process", None)) and
            callable(getattr(fixed, "_require_waitable_sigchld", None)) and
            callable(getattr(helper, "_proc_start_ticks", None)),
            "Source5 preparation has no captured owned-process implementation")
    require(type(timeout_seconds) is int and timeout_seconds > 0,
            "owned child process deadline must be positive")
    require(type(argv) is list and argv and argv[0] == str(expected_binary) and
            all(type(item) is str and "\x00" not in item for item in argv),
            "owned child argv differs from its exact executable dispatch")
    fixed._require_waitable_sigchld()
    is_policy_probe = argv[1:2] == ["--emit-feedback-policy-only"]
    requested_dispatch = _owned_process_requested_dispatch(
        argv, cwd, environment, expected_binary, expected_binary_sha,
        context["current_host"]["cpu_affinity"],
        context["current_host"]["network_namespace_inode"],
    )
    stdout_maximum = MAX_PROBE_BYTES if is_policy_probe else MAX_STDOUT_BYTES
    start_proof: dict[str, Any] | None = None
    start_artifact: dict[str, Any] | None = None
    start_pin: dict[str, str] | None = None

    def capture_started(proof: dict[str, Any]) -> None:
        nonlocal start_proof, start_artifact, start_pin
        if is_policy_probe:
            minimal = exact(proof, {
                "pid", "start_ticks", "requested_argv", "requested_argv_sha256",
                "environment_sha256",
            }, "FixedR8 fast policy-probe start proof")
            require(type(minimal["pid"]) is int and minimal["pid"] > 0 and
                    type(minimal["start_ticks"]) is int and minimal["start_ticks"] > 0 and
                    minimal["requested_argv"] == argv and
                    minimal["requested_argv_sha256"] == requested_dispatch["argv_sha256"] and
                    minimal["environment_sha256"] == requested_dispatch["environment_sha256"],
                    "FixedR8 minimal probe start proof differs from the requested dispatch")
            start_proof = minimal
            start_artifact = {
                "schema": OWNED_POLICY_PROBE_START_SCHEMA,
                "role": "source5_policy_probe",
                "runner_sha256": stack["fixed_pair_sha256"],
                "identity_helper_sha256": stack["process_identity_helper_sha256"],
                "dispatch": requested_dispatch,
                "start": minimal,
            }
        else:
            require(type(proof) is dict and proof.get("pid", 0) > 0 and
                    proof.get("start_ticks", 0) > 0 and
                    proof.get("executable_path") == str(expected_binary) and
                    proof.get("executable_sha256") == expected_binary_sha and
                    proof.get("requested_argv") == argv and
                    proof.get("executed_argv") == argv and
                    proof.get("environment") == environment and
                    proof.get("cwd") == str(cwd) and
                    proof.get("tmpdir") == environment["TMPDIR"] and
                    proof.get("cpu_affinity") == context["current_host"]["cpu_affinity"] and
                    proof.get("network_namespace_inode") == context["current_host"]["network_namespace_inode"],
                    "FixedR8 APP start proof differs from the exact dispatch and observed host")
            start_proof = proof
            start_artifact = proof
        require(type(start_artifact) is dict and start_proof is not None,
                "FixedR8 start callback produced no typed preparation sidecar")
        start_raw = canonical_bytes(start_artifact)
        require(len(start_raw) <= MAX_METADATA_BYTES,
                "FixedR8 start proof exceeds the finite preparation receipt bound")
        start_sha = _write_exclusive(ownership_start_path, start_raw)
        start_pin = _event_pin(ownership_start_path, start_sha)
        if on_bound is not None:
            on_bound(proof)

    capture = fixed._run_direct_process(
        argv, expected_binary, expected_binary_sha, cwd, environment,
        context["current_host"]["cpu_affinity"], stdout_path, stderr_path,
        stdout_maximum,
        MAX_STDERR_BYTES,
        float(timeout_seconds), helper,
        expected_tmpdir=Path(environment["TMPDIR"]),
        expected_network_inode=context["current_host"]["network_namespace_inode"],
        on_started=capture_started, capture_identity=not is_policy_probe,
        resource_monitor=resource_monitor,
    )
    owner_return_pin: dict[str, str] | None = None
    if owner_return_path is not None:
        # The raw FixedR8 return contains the original waitid, timeout/output
        # stop and cleanup facts. Persist it before touching any callback or
        # output validation so a later failure cannot erase that evidence.
        owner_return_raw = canonical_bytes(capture)
        owner_return_sha = _write_exclusive(owner_return_path, owner_return_raw)
        owner_return_pin = _event_pin(owner_return_path, owner_return_sha)
        try:
            require(len(owner_return_raw) <= MAX_METADATA_BYTES,
                    "FixedR8 raw owner return exceeds its finite receipt bound")
            return _finish_source5_owner_capture(
                context, argv, cwd, environment, stdout_path, stderr_path,
                timeout_seconds, expected_binary, expected_binary_sha,
                ownership_capture_path, ownership_start_path, start_proof,
                start_pin, requested_dispatch, stdout_maximum, is_policy_probe,
                capture, owner_return_pin,
            )
        except BaseException as error:
            failure_path = owner_return_path.with_name(
                owner_return_path.stem + ".post-return-failure.json",
            )
            failure = {
                "schema": DIRECT_OWNER_RETURN_FAILURE_SCHEMA,
                "role": "policy_probe" if is_policy_probe else "application",
                "owner_return": owner_return_pin,
                "error_type": type(error).__name__,
                "error": str(error)[:2048],
                "complete": False,
                "qualification_eligible": False,
            }
            failure_pin = None
            try:
                failure_sha = _write_exclusive(failure_path, canonical_bytes(failure))
                failure_pin = _event_pin(failure_path, failure_sha)
            except BaseException as failure_error:
                message = (
                    f"post-return validation failed ({type(error).__name__}); raw owner return "
                    f"is preserved at {owner_return_pin['path']}; failure receipt could not be sealed "
                    f"({type(failure_error).__name__})"
                )
                raise DirectOwnerPostReturnError(
                    message, owner_return_pin, None,
                ) from error
            raise DirectOwnerPostReturnError(
                f"post-return validation failed; owner return and failure receipt are pinned at "
                f"{owner_return_pin['path']} and {failure_pin['path']}",
                owner_return_pin, failure_pin,
            ) from error
    return _finish_source5_owner_capture(
        context, argv, cwd, environment, stdout_path, stderr_path,
        timeout_seconds, expected_binary, expected_binary_sha,
        ownership_capture_path, ownership_start_path, start_proof,
        start_pin, requested_dispatch, stdout_maximum, is_policy_probe,
        capture, None,
    )


def _application_environment(identity: dict[str, Any], trace_dir: Path,
                              tmpdir: Path, *,
                              source5_preparation: bool = False) -> dict[str, str]:
    require(type(source5_preparation) is bool,
            "Source5 preparation runtime-mode selector must be Boolean")
    if source5_preparation:
        require(identity.get("mode") == "capacity" and
                identity.get("pressure_qualification") is False,
                "Source5 preparation feedback mode must remain a non-qualifying capacity run")
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
    if source5_preparation:
        # Rust only starts the feedback collector in external_pressure mode.
        # This selects that runtime mode for capacity metering; it does not
        # assert external-pressure evidence or qualification.
        environment["ALLOCATBELT_APP_COMPARISON_FAMILY"] = "external_pressure"
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


def _storage_tmpdir_bounded(
    storage: object, source_root: Path, job_dir: Path, run_id: str,
    output_root: Path,
) -> tuple[Path, dict[str, Any] | None]:
    if storage is not None:
        tmpdir, snapshot = _storage_tmpdir(storage, source_root, job_dir, run_id)
    else:
        # Keep each no-storage TMPDIR a direct sibling of the generation. Its
        # root inode and contents belong to the TMPDIR budget; no unaccounted
        # intermediate directories are created outside the generation/job
        # and TMPDIR accounting roots.
        tmpdir = output_root / f"capacity-preparation-tmp-{run_id}"
        try:
            os.mkdir(tmpdir, 0o700)
        except OSError as error:
            raise CapacityStageError(f"cannot create fresh bounded capacity TMPDIR: {error}") from error
        _fsync_directory(output_root)
        _check_new_directory(tmpdir, "bounded capacity preparation TMPDIR")
        snapshot = None
    try:
        tmpdir.relative_to(job_dir)
        inside_job = True
    except ValueError:
        inside_job = False
    require(not inside_job, "bounded TMPDIR must be outside its output job tree")
    return tmpdir, snapshot


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
    common = {
        "campaign_id": context["spec"]["campaign_id"], "host_id": context["host_id"],
        "run_id": job["run_id"], "ordinal": 1,
        "capacity_key": job["capacity_key"], "template_index": job["template_index"],
        "template_sha256": job["template_sha256"],
        "source_manifest_raw_sha256": context["source_raw_sha256"],
        "source_manifest_semantic_sha256": context["source_semantic_sha256"],
        "source_tree_sha256": context["source_tree_sha256"],
        "request_template": job["template"]["request_template"],
        "context_template": job["template"]["context_template"],
        "nonce_instantiation": job["nonce_instantiation"],
    }
    if context.get("preparation_mode") is True:
        common.update({
            "preparation_raw_sha256": context["preparation_raw_sha256"],
            "preparation_semantic_sha256": context["preparation_semantic_sha256"],
            "capacity_preparation_templates_sha256": context["plan"]["capacity_process_templates_sha256"],
        })
    else:
        common.update({
            "capacity_process_templates_sha256": context["plan"]["capacity_process_templates_sha256"],
            "spec_raw_sha256": context["spec_raw_sha256"],
            "spec_semantic_sha256": context["spec_semantic_sha256"],
            "plan_raw_sha256": context["plan_raw_sha256"],
            "plan_semantic_sha256": context["plan_semantic_sha256"],
        })
    return common


def derive_capacity_preparation_jobs(intent: dict[str, Any], host_id: str) -> list[dict[str, Any]]:
    """Select the 15 prospective jobs in the original intent array order."""
    require(type(intent) is dict and intent.get("schema") == PREPARATION_INTENT_SCHEMA,
            "capacity preparation scheduling requires the separate Source5 intent")
    host_id = token(host_id, "preparation host ID")
    core = intent.get("core")
    hosts = core.get("hosts") if type(core) is dict else None
    require(type(hosts) is list and len(hosts) in (2, 3) and
            all(type(item) is dict for item in hosts),
            "preparation intent does not preserve a complete supported host core")
    host_ids = [item.get("host_id") for item in hosts]
    require(all(type(item) is str and item for item in host_ids) and
            len(set(host_ids)) == len(host_ids) and host_id in host_ids,
            "preparation intent does not bind the selected host to a complete supported cohort")
    templates = intent.get("capacity_templates")
    expected_template_count = len(host_ids) * 15
    require(type(templates) is list and len(templates) == expected_template_count,
            "preparation intent does not contain each host's complete 15-context matrix")
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, template_value in enumerate(templates):
        require(type(template_value) is dict, f"preparation capacity template[{index}] is malformed")
        if template_value.get("host_id") != host_id:
            continue
        template = template_value
        key = exact(template.get("capacity_key"), {"host_id", "workload", "profile", "calibration_id"},
                    f"preparation capacity template[{index}] key") if "capacity_key" in template else {
                        "host_id": template.get("host_id"), "workload": template.get("workload"),
                        "profile": template.get("profile"), "calibration_id": template.get("calibration_id"),
                    }
        workload = token(key["workload"], f"preparation template[{index}] workload")
        profile = token(key["profile"], f"preparation template[{index}] profile")
        calibration_id = token(key["calibration_id"], f"preparation template[{index}] calibration ID")
        require(workload in WORKLOADS and profile in PROFILES[workload],
                f"preparation capacity template[{index}] is outside the fixed 15-context matrix")
        context_key = (workload, profile)
        require(context_key not in seen, f"preparation intent repeats context {context_key} for {host_id}")
        seen.add(context_key)
        template_body = {name: value for name, value in template.items() if name != "template_sha256"}
        template_sha = digest(template.get("template_sha256"), f"preparation capacity template[{index}] digest")
        require(template_sha == sha256_bytes(canonical_bytes(template_body)) and template.get("template_index") == index,
                f"preparation capacity template[{index}] identity digest/index changed")
        run_id = token(template.get("run_id"), f"preparation capacity template[{index}] run ID")
        nonce = template.get("prospective_nonce")
        require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) is not None,
                f"preparation capacity template[{index}] nonce is malformed")
        calibrator = exact(template.get("calibrator"), {"allocator", "executor"},
                           f"preparation capacity template[{index}] calibrator")
        require(calibrator["allocator"] in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system") and
                calibrator["executor"] in ("bounded", "tokio"),
                f"preparation capacity template[{index}] calibrator is unsupported")
        request = exact(template.get("request_template"), {"relative_path", "raw_sha256"},
                        f"preparation request template[{index}]")
        context = exact(template.get("context_template"), {"relative_path", "raw_sha256"},
                        f"preparation context template[{index}]")
        nonce_record = {
            "schema": PREPARATION_NONCE_SCHEMA,
            "preparation_raw_sha256": intent["preparation_raw_sha256"],
            "preparation_semantic_sha256": intent["preparation_sha256"],
            "template_index": index, "run_id": run_id,
            "prospective_nonce": nonce,
        }
        selected.append({
            "ordinal": 1, "template_index": index, "template": template,
            "capacity_key": {**key, "host_id": host_id}, "template_sha256": template_sha,
            "run_id": run_id, "nonce": nonce, "nonce_instantiation": nonce_record,
        })
    require(len(selected) == 15 and seen == {(workload, profile) for workload, profiles in PROFILES.items() for profile in profiles},
            f"selected preparation host requires exactly 15 unique contexts; found {len(selected)}")
    return selected


def _verify_observed_host_static(value: dict[str, Any], host: dict[str, Any], host_id: str) -> dict[str, Any]:
    """Validate frozen host facts without comparing them to this coordinator."""
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
            cpu_values == sorted(set(cpu_values)) and cpu_values == _parse_cpu_set(controls["cpu_set"]),
            "observed CPU affinity is malformed or differs from the frozen host CPU set")
    netns = uint(value["network_namespace_inode"], "observed network namespace inode", positive=True)
    return {
        "boot_id_sha256": value["boot_id_sha256"], "cpu_affinity": cpu_values,
        "kernel_release": value["kernel_release"], "cpu_model": value["cpu_model"],
        "network_namespace_inode": netns,
    }


def _validate_evidence_path_map(
    value: object, *, allow_source_inventory_symlinks: bool = False,
) -> list[tuple[Path, Path]]:
    mapping = exact(value, {"schema", "entries"}, "offline evidence path map")
    require(mapping["schema"] == EVIDENCE_PATH_MAP_SCHEMA and
            type(mapping["entries"]) is list and 1 <= len(mapping["entries"]) <= 4096,
            "offline evidence path map schema or entry count is invalid")
    result: list[tuple[Path, Path]] = []
    origins: set[Path] = set()
    locals_seen: set[Path] = set()
    for index, item_value in enumerate(mapping["entries"]):
        item = exact(item_value, {"origin", "local"}, f"offline evidence path map entry[{index}]")
        require(type(item["origin"]) is str and type(item["local"]) is str,
                f"offline evidence path map entry[{index}] paths must be strings")
        origin = Path(item["origin"])
        local = Path(item["local"])
        _path_text(origin, f"offline evidence origin[{index}]")
        _path_text(local, f"offline evidence local[{index}]")
        require(origin.is_absolute() and str(origin) == os.path.normpath(str(origin)) and
                local.is_absolute() and str(local) == os.path.normpath(str(local)),
                f"offline evidence path map entry[{index}] paths must be normalized and absolute")
        require(origin == local,
                "offline evidence path map must preserve every original absolute path")
        require(origin not in origins and local not in locals_seen,
                "offline evidence path map repeats an origin or local root")
        origins.add(origin)
        locals_seen.add(local)
        try:
            local_info = local.lstat()
            kind_ok = (stat.S_ISDIR(local_info.st_mode) or
                       stat.S_ISREG(local_info.st_mode) or
                       (allow_source_inventory_symlinks and
                        stat.S_ISLNK(local_info.st_mode)))
            require(kind_ok and
                    (stat.S_ISLNK(local_info.st_mode) or
                     local.resolve(strict=True) == local),
                    f"offline evidence local path[{index}] is an alias or special file")
            if stat.S_ISREG(local_info.st_mode):
                require(local_info.st_nlink == 1,
                        f"offline evidence local file[{index}] has a hard-link alias")
            if stat.S_ISLNK(local_info.st_mode):
                require(local_info.st_nlink == 1,
                        f"offline evidence local symlink[{index}] has a hard-link alias")
        except OSError as error:
            raise CapacityStageError(f"offline evidence local path[{index}] is unavailable: {error}") from error
        result.append((origin, local))
    require([str(origin) for origin, _local in result] == sorted(str(origin) for origin, _local in result),
            "offline evidence path map entries are not sorted by origin path")
    for index, (origin, local) in enumerate(result):
        for other_origin, other_local in result[index + 1:]:
            if other_origin.is_relative_to(origin):
                require(other_local.is_relative_to(local) and
                        local / other_origin.relative_to(origin) == other_local,
                        "nested offline evidence roots do not preserve their relative layout")
            elif origin.is_relative_to(other_origin):
                require(local.is_relative_to(other_local) and
                        other_local / origin.relative_to(other_origin) == local,
                        "nested offline evidence roots do not preserve their relative layout")
    return sorted(result, key=lambda pair: len(pair[0].parts), reverse=True)


def _map_evidence_path(
    path_value: str | Path, mapping: list[tuple[Path, Path]], *,
    exact: bool = False,
) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        return path
    if exact:
        origins = [local for origin, local in mapping if origin == path]
        require(len(origins) == 1,
                f"offline evidence path lacks one exact origin/local membership: {path}")
        return origins[0]
    for origin, local in mapping:
        if _is_within(origin, path):
            return local / path.relative_to(origin)
    return path


_ABSOLUTE_EVIDENCE_PATH_KEYS = {
    "path", "source_root", "cwd", "output_root", "trace_directory",
    "tmpdir", "tmpdir_path", "stdout_path", "stderr_path",
    "executable_path", "binary_path", "expected_binary_path",
    "host_context_path",
}
_PATH_ENVIRONMENT_KEYS = {
    "TMPDIR", "ALLOCATBELT_APP_FEEDBACK_TRACE_DIR",
    "ALLOCATBELT_APP_ID_REPORT", "ALLOCATBELT_APP_FAMILY_REPORT",
    "ALLOCATBELT_APP_RUNTIME_REPORT", "ALLOCATBELT_APP_SHUTDOWN_REPORT",
}


def _offline_local_fingerprint(path: Path, label: str) -> dict[str, Any]:
    try:
        info = path.lstat()
    except OSError as error:
        raise CapacityStageError(f"offline local evidence is unavailable at {path}: {error}") from error
    if stat.S_ISDIR(info.st_mode):
        kind = "directory"
        target = None
    elif stat.S_ISREG(info.st_mode):
        require(info.st_nlink == 1,
                f"{label} local copy has a hard-link alias")
        kind = "file"
        target = None
    elif stat.S_ISLNK(info.st_mode):
        require(info.st_nlink == 1,
                f"{label} local symlink has a hard-link alias")
        kind = "symlink"
        try:
            target = os.readlink(path)
        except OSError as error:
            raise CapacityStageError(f"cannot read offline symlink {path}: {error}") from error
    else:
        raise CapacityStageError(f"{label} local copy has a special-file member")
    return {
        "kind": kind, "device": info.st_dev, "inode": info.st_ino,
        "type": stat.S_IFMT(info.st_mode), "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid, "nlink": info.st_nlink,
        "size": info.st_size, "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns, "target": target,
    }


def _offline_path_references(value: Any) -> set[str]:
    found: set[str] = set()

    def visit(current: Any, key: str | None = None,
              argv_context: bool = False) -> None:
        if type(current) is str:
            if (key in _ABSOLUTE_EVIDENCE_PATH_KEYS or argv_context) and current.startswith("/"):
                found.add(current)
            return
        if type(current) is list:
            for item in current:
                visit(item, argv_context=argv_context)
            return
        if type(current) is dict:
            for child_key, item in current.items():
                if child_key == "environment" and type(item) is dict:
                    for env_key, env_value in item.items():
                        if env_key in _PATH_ENVIRONMENT_KEYS and type(env_value) is str and env_value.startswith("/"):
                            found.add(env_value)
                    continue
                if child_key in {"argv", "requested_argv", "executed_argv"}:
                    visit(item, argv_context=True)
                else:
                    visit(item, key=child_key)

    visit(value)
    return found


def _scan_offline_local_tree(
    root: Path, label: str, fingerprints: dict[str, dict[str, Any]],
) -> set[Path]:
    root_identity = _offline_local_fingerprint(root, label)
    require(root_identity["kind"] == "directory" and
            root.resolve(strict=True) == root,
            f"{label} root is not a real local directory")
    observed: set[Path] = {root}
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    child = current / entry.name
                    require(child not in observed and len(observed) < 4096,
                            f"{label} local tree is repeated or exceeds its finite map bound")
                    fingerprint = _offline_local_fingerprint(child, label)
                    require(fingerprint["kind"] != "symlink",
                            f"{label} local tree contains an undeclared symlink")
                    fingerprints[str(child)] = fingerprint
                    observed.add(child)
                    if fingerprint["kind"] == "directory":
                        require(child.resolve(strict=True) == child,
                                f"{label} local directory traverses an alias")
                        pending.append(child)
        except OSError as error:
            raise CapacityStageError(f"cannot enumerate {label} local tree {current}: {error}") from error
    return observed


def _read_offline_raw_pin(
    pin_value: object, label: str, maximum: int,
    path_map: list[tuple[Path, Path]],
) -> tuple[dict[str, Any], bytes, Path]:
    pin_fields = {"path", "sha256"}
    if type(pin_value) is dict and "semantic_sha256" in pin_value:
        pin_fields.add("semantic_sha256")
    pin = exact(pin_value, pin_fields, f"{label} offline raw pin")
    origin_path = _pin_path(pin["path"], f"{label} offline path")
    local_path = _map_evidence_path(origin_path, path_map, exact=True)
    raw, _info = read_stable(local_path, label, maximum)
    require(sha256_bytes(raw) == digest(pin["sha256"], f"{label} offline raw SHA-256"),
            f"{label} local copy differs from its original raw host pin")
    return pin, raw, local_path


def _preflight_bounded_offline_copy(
    preparation_pin: object, resource_budget_pin: object,
    source_root_value: Path, input_root_value: Path, host_id: str,
    observed_host_pin: object, output_root_value: Path, completion_pin: object,
    host_verification_pin: object, path_map_value: object,
    expected_preparation_semantic_sha256: str | None = None,
) -> dict[str, Any]:
    """Close every copied evidence path before loading captured SourceV5 code."""
    path_map = _validate_evidence_path_map(
        path_map_value, allow_source_inventory_symlinks=True,
    )
    local_members = {local for _origin, local in path_map}
    fingerprints = {
        str(local): _offline_local_fingerprint(local, "offline evidence map")
        for local in local_members
    }

    def local_argument(path_value: Path, label: str) -> Path:
        return _map_evidence_path(path_value, path_map, exact=True)

    source_root = local_argument(Path(source_root_value), "offline SourceV5 root")
    input_root = local_argument(Path(input_root_value), "offline preparation input root")
    output_root = local_argument(Path(output_root_value), "offline preparation output root")
    require(source_root in local_members and input_root in local_members and
            output_root in local_members,
            "bounded offline map must contain the exact copied SourceV5/input/output roots")
    for path, label in ((source_root, "SourceV5 root"),
                        (input_root, "preparation input root"),
                        (output_root, "preparation output root")):
        fingerprint = fingerprints.get(str(path))
        require(type(fingerprint) is dict and fingerprint["kind"] == "directory",
                f"bounded offline {label} is not an explicit mapped directory")
    require(not source_root.is_relative_to(input_root) and
            not input_root.is_relative_to(source_root) and
            output_root.is_relative_to(input_root) and
            not output_root.is_relative_to(source_root) and
            not source_root.is_relative_to(output_root),
            "bounded offline SourceV5/input/output roots violate the original nested-root contract")

    # SourceV5's typed inventory, read below, defines the exact source member
    # set. Do not recursively enumerate the repository root: it also contains
    # unrelated .git, build and workspace files. Before opening any declared
    # metadata or source bytes, close every other mapped directory recursively.
    source_members = {
        local for local in local_members
        if local == source_root or local.is_relative_to(source_root)
    }
    other_members = local_members - source_members
    mapped_directories = {
        local for local in other_members
        if fingerprints[str(local)]["kind"] == "directory"
    }
    scan_roots = {
        local for local in mapped_directories
        if not any(parent in mapped_directories for parent in local.parents)
    }
    require(bool(scan_roots),
            "bounded offline map has no explicit local input/output/TMPDIR root")
    preflight_members: set[Path] = set()
    for scan_root in scan_roots:
        preflight_members.update(_scan_offline_local_tree(
            scan_root, "bounded offline exact-map preflight", fingerprints,
        ))
    require(preflight_members == other_members,
            "bounded offline exact origin/local membership is not the complete recursive input/output/TMPDIR membership")

    preparation_ref, preparation_raw, preparation_path = _read_offline_raw_pin(
        preparation_pin, "Source5 preparation intent", MAX_SOURCE_FILE_BYTES,
        path_map,
    )
    budget_ref, budget_raw, budget_path = _read_offline_raw_pin(
        resource_budget_pin, "bounded Source5 resource budget", MAX_METADATA_BYTES,
        path_map,
    )
    observed_ref, observed_raw, observed_path = _read_offline_raw_pin(
        observed_host_pin, "observed host context", MAX_TEMPLATE_BYTES, path_map,
    )
    completion_ref, completion_raw, completion_path = _read_offline_raw_pin(
        completion_pin, "bounded capacity preparation completion",
        MAX_METADATA_BYTES, path_map,
    )
    receipt_ref = exact(host_verification_pin, {
        "path", "raw_sha256", "receipt_sha256",
    }, "bounded host verification receipt pin")
    receipt_path = _map_evidence_path(
        _pin_path(receipt_ref["path"], "bounded host verification receipt path"),
        path_map, exact=True,
    )
    receipt_raw, _receipt_info = read_stable(
        receipt_path, "bounded host verification receipt", MAX_METADATA_BYTES,
    )
    require(sha256_bytes(receipt_raw) == digest(
        receipt_ref["raw_sha256"], "bounded host verification receipt raw SHA-256",
    ), "bounded host verification receipt copy differs from its original raw pin")
    preparation = parse_object(preparation_raw, "offline Source5 preparation intent",
                               MAX_SOURCE_FILE_BYTES, canonical=True)
    budget = parse_object(budget_raw, "offline bounded resource budget",
                          MAX_METADATA_BYTES, canonical=True)
    observed = parse_object(observed_raw, "offline observed host context",
                            MAX_TEMPLATE_BYTES, canonical=True)
    completion = parse_object(completion_raw, "offline bounded completion",
                              MAX_METADATA_BYTES, canonical=True)
    host_receipt = parse_object(receipt_raw, "offline bounded host verification receipt",
                                MAX_METADATA_BYTES, canonical=True)
    receipt_body = {key: value for key, value in host_receipt.items()
                    if key != "receipt_sha256"}
    require(host_receipt.get("receipt_sha256") == receipt_ref["receipt_sha256"] ==
            sha256_bytes(canonical_bytes(receipt_body)) and
            host_receipt.get("schema") == PREPARATION_BOUNDED_VERIFICATION_SCHEMA and
            host_receipt.get("complete") is True and
            host_receipt.get("qualification_eligible") is False and
            host_receipt.get("controller_chronology_proven") is False,
            "offline host receipt raw/semantic digest or readiness flags are invalid")
    require(preparation.get("schema") == PREPARATION_INTENT_SCHEMA and
            budget.get("schema") == PREPARATION_RESOURCE_BUDGET_SCHEMA and
            completion.get("schema") == PREPARATION_BOUNDED_COMPLETION_SCHEMA and
            completion.get("resource_budget") == {
                "path": budget_ref["path"],
                "raw_sha256": budget_ref["sha256"],
                "semantic_sha256": budget.get("resource_budget_sha256"),
            } and host_receipt.get("resource_budget") == completion["resource_budget"] and
            host_receipt.get("completion_raw_sha256") == completion_ref["sha256"] and
            host_receipt.get("completion_sha256") == completion.get("completion_sha256"),
            "offline origin-host budget/completion/verification snapshots disagree")
    if "semantic_sha256" in preparation_ref:
        require(preparation_ref["semantic_sha256"] ==
                preparation.get("preparation_sha256"),
                "offline preparation semantic pin differs from its raw original")
    if expected_preparation_semantic_sha256 is not None:
        require(expected_preparation_semantic_sha256 ==
                preparation.get("preparation_sha256"),
                "offline preparation semantic pin differs from its raw original")
    require(type(observed) is dict and observed.get("host_id") == host_id,
            "offline observed-host receipt differs from the selected original host")

    source_root_pair = [(origin, local) for origin, local in path_map
                        if local == source_root]
    input_root_pair = [(origin, local) for origin, local in path_map
                       if local == input_root]
    output_root_pair = [(origin, local) for origin, local in path_map
                        if local == output_root]
    require(len(source_root_pair) == len(input_root_pair) == len(output_root_pair) == 1,
            "bounded offline root mapping is ambiguous")
    source_origin_root = source_root_pair[0][0]
    input_origin_root = input_root_pair[0][0]
    output_origin_root = output_root_pair[0][0]
    stage_origin = _pin_path(completion.get("stage_directory"),
                             "offline completion stage directory")
    stage_dir = _map_evidence_path(stage_origin, path_map, exact=True)
    expected_stage = output_root / preparation["core"]["campaign_id"] / "capacity-preparation" / host_id
    require(stage_dir == expected_stage and
            stage_origin == output_origin_root / preparation["core"]["campaign_id"] /
            "capacity-preparation" / host_id,
            "offline copied generation root differs from its raw origin output identity")
    require(completion_path == stage_dir / "capacity-preparation-bounded-completion.json" and
            receipt_path.parent == stage_dir and
            preparation_path.is_relative_to(input_root) and
            budget_path.is_relative_to(input_root) and observed_path.is_relative_to(input_root),
            "offline raw preparation/budget/host/completion receipts are outside their exact roots")

    ledger_pin = exact(completion["ledger"], {
        "path", "raw_sha256", "terminal_head",
    }, "offline bounded ledger pin")
    ledger_origin = _pin_path(ledger_pin["path"], "offline bounded ledger path")
    ledger_path = _map_evidence_path(ledger_origin, path_map, exact=True)
    ledger_raw, _ledger_info = read_stable(ledger_path, "offline bounded ledger", MAX_LEDGER_BYTES)
    require(sha256_bytes(ledger_raw) == digest(ledger_pin["raw_sha256"],
                                               "offline bounded ledger raw SHA"),
            "offline copied ledger differs from its original raw host pin")
    ledger_records: list[dict[str, Any]] = []
    for index, line in enumerate(ledger_raw.splitlines(keepends=True)):
        envelope = exact(
            parse_object(line, f"offline bounded ledger line[{index}]",
                         MAX_EVENT_LINE_BYTES, canonical=True),
            {"previous_sha256", "record", "record_sha256"},
            f"offline bounded ledger envelope[{index}]",
        )
        record = envelope["record"]
        require(type(record) is dict,
                f"offline bounded ledger envelope[{index}] has no nested record object")
        ledger_records.append(record)
    offline_scheduling_intent = {
        **preparation, "preparation_raw_sha256": sha256_bytes(preparation_raw),
    }
    offline_jobs = derive_capacity_preparation_jobs(offline_scheduling_intent, host_id)
    require(len(ledger_records) == len(offline_jobs) * len(JOB_EVENTS) + 1 and
            len(completion.get("entries", [])) == 15,
            "offline bounded completion/ledger does not preserve all 15 original ordinals")
    require(len(offline_jobs) == len(completion["entries"]) == 15,
            "offline bounded schedule does not bind the complete original 15-context matrix")
    application_dispatches = [record for record in ledger_records
                              if record.get("event") == "application_dispatch"]
    require(len(application_dispatches) == len(offline_jobs),
            "offline bounded ledger does not contain one application dispatch per original context")
    application_dispatch_by_run: dict[str, dict[str, Any]] = {}
    for record in application_dispatches:
        run_id = record.get("run_id")
        require(type(run_id) is str and run_id not in application_dispatch_by_run,
                "offline application dispatch run ID is missing or duplicated")
        application_dispatch_by_run[run_id] = record
    expected_tmpdir_by_run: dict[str, Path] = {}
    for index, (job, entry) in enumerate(zip(offline_jobs, completion["entries"])):
        run_id = job["run_id"]
        require(entry.get("run_id") == run_id and
                entry.get("template_index") == job["template_index"] and
                entry.get("workload") == job["capacity_key"]["workload"] and
                entry.get("profile") == job["capacity_key"]["profile"],
                f"offline completion entry[{index}] differs from the original ordered schedule")
        app_record = application_dispatch_by_run.get(run_id)
        require(type(app_record) is dict and
                app_record.get("template_index") == job["template_index"] and
                app_record.get("workload") == job["capacity_key"]["workload"] and
                app_record.get("profile") == job["capacity_key"]["profile"] and
                app_record.get("template_sha256") == job["template_sha256"],
                f"offline application dispatch for {run_id} differs from its original template identity")
        details = app_record.get("details")
        require(type(details) is dict and
                details.get("context_template") == job["template"]["context_template"],
                f"offline application dispatch for {run_id} changed its caller-pinned context template")
        tmpdir_text = details.get("tmpdir_path")
        require(type(tmpdir_text) is str and Path(tmpdir_text).is_absolute() and
                str(Path(tmpdir_text)) == tmpdir_text,
                f"offline application dispatch for {run_id} has a noncanonical TMPDIR path")
        expected_tmpdir_by_run[run_id] = Path(tmpdir_text)
    require(len(set(expected_tmpdir_by_run.values())) == len(offline_jobs),
            "offline bounded dispatches alias their per-run TMPDIR roots")

    monitor_reports: list[dict[str, Any]] = []
    monitor_paths: set[Path] = set()
    for entry in completion["entries"]:
        run_id = entry.get("run_id")
        monitors = exact(entry.get("resource_monitors"), {"policy_probe", "application"},
                         f"offline {run_id} resource monitor pins")
        for role, pin_value in monitors.items():
            pin = exact(pin_value, {"path", "sha256"},
                        f"offline {run_id} {role} monitor pin")
            origin = _pin_path(pin["path"], f"offline {run_id} {role} monitor path")
            local = _map_evidence_path(origin, path_map, exact=True)
            raw, _info = read_stable(local, f"offline {run_id} {role} monitor report",
                                     MAX_METADATA_BYTES)
            require(sha256_bytes(raw) == digest(pin["sha256"],
                                                f"offline {run_id} {role} monitor raw SHA"),
                    f"offline {run_id} {role} monitor differs from its original raw host receipt")
            report = parse_object(raw, f"offline {run_id} {role} monitor report",
                                  MAX_METADATA_BYTES, canonical=True)
            monitor_reports.append(report)
            monitor_paths.add(local)
    require(len(monitor_reports) == 30,
            "offline bounded receipt snapshot does not contain the 30 original monitor reports")

    source_manifests: list[dict[str, Any]] = []
    source_map = exact(preparation.get("source_pins"),
                       {item["host_id"] for item in preparation["core"]["hosts"]},
                       "offline preparation SourceV5 pin map")
    source_inventory_paths: set[Path] = {source_root}
    source_directory_paths: set[Path] = {source_root}
    source_file_checks: list[tuple[str, Path, Path, dict[str, Any]]] = []
    source_artifact_checks: list[tuple[str, Path, Path, dict[str, Any]]] = []
    common_source_files: list[dict[str, Any]] | None = None
    for source_host, source_pin_value in source_map.items():
        manifest_pin = exact(source_pin_value.get("manifest"), {
            "relative_path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
        }, f"offline {source_host} SourceV5 manifest pin")
        manifest_local = _safe_child(input_root, manifest_pin["relative_path"],
                                     f"offline {source_host} SourceV5 manifest")
        manifest_origin = input_origin_root / PurePosixPath(
            manifest_pin["relative_path"],
        )
        require(_map_evidence_path(manifest_origin, path_map, exact=True) ==
                manifest_local,
                f"offline {source_host} SourceV5 manifest is not an exact mapped input")
        raw, _info = read_stable(manifest_local,
                                 f"offline {source_host} SourceV5 manifest",
                                 MAX_MANIFEST_BYTES)
        require(sha256_bytes(raw) == digest(manifest_pin["raw_sha256"],
                                             f"offline {source_host} SourceV5 raw SHA"),
                f"offline {source_host} SourceV5 manifest differs from its original raw pin")
        source_manifest = parse_object(raw, f"offline {source_host} SourceV5 manifest",
                                       MAX_MANIFEST_BYTES, canonical=True)
        require(source_manifest.get("manifest_sha256") == manifest_pin["semantic_sha256"] and
                source_manifest.get("source", {}).get("source_tree_sha256") ==
                    manifest_pin["source_tree_sha256"],
                f"offline {source_host} SourceV5 semantic/tree digest changed")
        source_manifests.append(source_manifest)
        source_files = source_manifest.get("source", {}).get("files")
        require(type(source_files) is list and source_files,
                f"offline {source_host} SourceV5 typed inventory is missing")
        if common_source_files is None:
            common_source_files = source_files
        else:
            require(source_files == common_source_files,
                    "offline SourceV5 host manifests disagree on the shared Source.files inventory")
        source_records = _source_records(source_manifest)
        for item in source_manifest["source"]["files"]:
            relative = _relative(item["path"],
                                 f"offline {source_host} SourceV5 inventory path")
            if item["kind"] == "symlink":
                _source_inventory_symlink_target(
                    item, source_records,
                    f"offline {source_host} SourceV5 symlink {relative.as_posix()}",
                )
            else:
                item = exact(item, {"path", "kind", "mode", "sha256", "size"},
                             f"offline {source_host} SourceV5 regular inventory entry")
                require(item["kind"] == "file" and
                        item["mode"] in {"100644", "100755"},
                        f"offline {source_host} SourceV5 member is not a typed regular file: {relative}")
                digest(item["sha256"],
                       f"offline {source_host} SourceV5 file SHA: {relative}")
                uint(item["size"], f"offline {source_host} SourceV5 file size: {relative}",
                     maximum=MAX_SOURCE_FILE_BYTES)
            local = source_root.joinpath(*relative.parts)
            origin = source_origin_root.joinpath(*relative.parts)
            require(_map_evidence_path(origin, path_map, exact=True) == local,
                    f"offline SourceV5 source file is absent from exact identity membership: {origin}")
            for parent in local.parents:
                if parent == source_root.parent:
                    break
                source_inventory_paths.add(parent)
                source_directory_paths.add(parent)
            source_inventory_paths.add(local)
            source_file_checks.append((source_host, origin, local, item))
        artifact_items = [*source_manifest["artifacts"].values(),
                          *source_manifest["soak_artifacts"].values(),
                          source_manifest["analysis_artifact"],
                          source_manifest["resource_domain_calibration"]["binary"],
                          source_manifest["resource_domain_calibration"]["output"]]
        for item in artifact_items:
            artifact = exact(item, {"path", "sha256"},
                             f"offline {source_host} SourceV5 artifact pin")
            relative = _relative(item["path"],
                                 f"offline {source_host} SourceV5 artifact path")
            local = source_root.joinpath(*relative.parts)
            origin = source_origin_root.joinpath(*relative.parts)
            require(_map_evidence_path(origin, path_map, exact=True) == local,
                    f"offline SourceV5 artifact is absent from exact identity membership: {origin}")
            source_inventory_paths.add(local)
            for parent in local.parents:
                if parent == source_root.parent:
                    break
                source_inventory_paths.add(parent)
                source_directory_paths.add(parent)
            source_artifact_checks.append((source_host, origin, local, artifact))

    input_members = _scan_offline_local_tree(
        input_root, "bounded offline input", fingerprints,
    )
    output_members = _scan_offline_local_tree(
        output_root, "bounded offline output", fingerprints,
    )
    require(stage_dir in output_members and source_root in local_members and
            source_inventory_paths <= local_members,
            "bounded offline map omits a copied source/input/output membership root")

    input_storage_tmpdirs: set[Path] = set()
    canonical_tmpdirs: set[Path] = set()
    for job in offline_jobs:
        run_id = job["run_id"]
        context_pin = exact(job["template"]["context_template"],
                            {"relative_path", "raw_sha256"},
                            f"offline {run_id} caller-pinned context template")
        relative = _relative(context_pin["relative_path"],
                             f"offline {run_id} context template path")
        context_origin = input_origin_root.joinpath(*relative.parts)
        context_local = input_root.joinpath(*relative.parts)
        require(_map_evidence_path(context_origin, path_map, exact=True) == context_local and
                context_local in input_members and
                fingerprints.get(str(context_local), {}).get("kind") == "file",
                f"offline {run_id} context template is not a declared regular input member")
        context_raw, _context_info = read_stable(
            context_local, f"offline {run_id} caller-pinned context template",
            MAX_TEMPLATE_BYTES,
        )
        require(sha256_bytes(context_raw) == digest(
            context_pin["raw_sha256"], f"offline {run_id} context template raw SHA",
        ), f"offline {run_id} context template differs from its caller-frozen raw pin")
        context_template = parse_object(
            context_raw, f"offline {run_id} caller-pinned context template",
            MAX_TEMPLATE_BYTES, canonical=True,
        )
        exact(context_template, {"schema", "storage", "network"},
              f"offline {run_id} context template")
        require(context_template["schema"] == CONTEXT_TEMPLATE_SCHEMA,
                f"offline {run_id} context template schema is unsupported")

        dispatch = application_dispatch_by_run[run_id]["details"]
        tmpdir_path = expected_tmpdir_by_run[run_id]
        storage_template = context_template["storage"]
        require(not tmpdir_path.is_relative_to(source_root) and
                not source_root.is_relative_to(tmpdir_path) and
                not tmpdir_path.is_relative_to(stage_dir) and
                not stage_dir.is_relative_to(tmpdir_path),
                f"offline {run_id} TMPDIR overlaps SourceV5 or the stage/job generation")
        if storage_template is None:
            canonical_tmpdir = output_root / f"capacity-preparation-tmp-{run_id}"
            require(tmpdir_path == canonical_tmpdir and
                    dispatch.get("storage_context") is None,
                    f"offline {run_id} storage-none TMPDIR differs from its canonical path")
            canonical_tmpdirs.add(tmpdir_path)
            continue

        storage = exact(storage_template, {
            "scope", "root_path", "filesystem_type", "device_major_minor",
            "minimum_free_bytes",
        }, f"offline {run_id} explicit storage template")
        storage_root_text = storage["root_path"]
        require(type(storage_root_text) is str and Path(storage_root_text).is_absolute() and
                str(Path(storage_root_text)) == storage_root_text and
                ".." not in Path(storage_root_text).parts,
                f"offline {run_id} explicit storage root is not a canonical absolute path")
        storage_root = Path(storage_root_text)
        observed_storage = exact(dispatch.get("storage_context"), {
            "scope", "root_path", "filesystem_type", "device_major_minor",
            "minimum_free_bytes", "tmpdir_path", "available_bytes_at_launch",
        }, f"offline {run_id} original explicit storage observation")
        require({key: observed_storage[key] for key in storage} == storage and
                observed_storage["root_path"] == storage_root_text and
                observed_storage["tmpdir_path"] == str(tmpdir_path) and
                tmpdir_path.parent == storage_root,
                f"offline {run_id} TMPDIR is not the direct child of its caller-pinned storage root")
        if storage_root == input_root or storage_root.is_relative_to(input_root):
            require(storage_root in input_members and
                    fingerprints.get(str(storage_root), {}).get("kind") == "directory" and
                    tmpdir_path.is_relative_to(input_root) and
                    not storage_root.is_relative_to(source_root) and
                    not tmpdir_path.is_relative_to(source_root),
                    f"offline {run_id} input-root storage TMPDIR is not covered by the exact input tree")
            input_storage_tmpdirs.add(tmpdir_path)
        else:
            require(not tmpdir_path.is_relative_to(input_root),
                    f"offline {run_id} TMPDIR is inside input_root but its storage root is outside it")

    tmp_roots: set[Path] = set()
    for report in monitor_reports:
        roots = exact(report.get("roots"), {
            "generation", "job_output", "trace", "tmpdirs",
        }, "offline monitor root inventory")
        for value in (roots["generation"], roots["job_output"], roots["trace"]):
            root = exact(value, {"path", "device", "inode"},
                         "offline monitor original root pin")
            origin = _pin_path(root["path"], "offline monitor origin root")
            local = _map_evidence_path(origin, path_map, exact=True)
            require(local == stage_dir or local.is_relative_to(stage_dir),
                    "offline monitor output root is outside its mapped generation")
        for value in roots["tmpdirs"]:
            root = exact(value, {"path", "device", "inode"},
                         "offline monitor original TMPDIR pin")
            origin = _pin_path(root["path"], "offline monitor TMPDIR origin")
            local = _map_evidence_path(origin, path_map, exact=True)
            require(local not in {source_root, input_root, output_root} and
                    not local.is_relative_to(source_root) and
                    (not local.is_relative_to(input_root) or
                     local in canonical_tmpdirs or local in input_storage_tmpdirs) and
                    not _is_within(local, output_root),
                    "offline TMPDIR path is not a canonical or caller-declared disjoint storage root")
            tmp_roots.add(local)
    require(tmp_roots == set(expected_tmpdir_by_run.values()) and
            len(tmp_roots) == len(offline_jobs),
            "offline monitor TMPDIR roots differ from the exact 15 original dispatches")
    external_tmp_roots = {
        root for root in tmp_roots if not root.is_relative_to(input_root)
    }
    require(scan_roots == {input_root, *external_tmp_roots} and
            output_root.is_relative_to(input_root) and output_root in input_members and
            all(root in input_members or root in preflight_members for root in tmp_roots),
            "bounded offline exact-map roots differ from original input/output/TMPDIR roots")
    tmp_members: set[Path] = set()
    for root in tmp_roots:
        members = _scan_offline_local_tree(
            root, "bounded offline TMPDIR", fingerprints,
        )
        tmp_members.update(members)

    expected_local = set(input_members) | set(output_members) | set(tmp_members)
    expected_local.update(source_inventory_paths)
    expected_local.update((source_root, input_root, output_root))
    for local in (preparation_path, budget_path, observed_path, completion_path,
                  receipt_path, ledger_path, *monitor_paths):
        expected_local.add(local)
    path_refs: set[str] = set()
    origin_documents = [preparation, budget, observed, completion, host_receipt,
                        *ledger_records, *monitor_reports]
    for document in origin_documents:
        document_refs = _offline_path_references(document)
        path_refs.update(document_refs)
        for rendered in document_refs:
            _map_evidence_path(rendered, path_map, exact=True)
    covered_members = (set(input_members) | set(output_members) | set(tmp_members) |
                       source_inventory_paths)
    for rendered in path_refs:
        local = _map_evidence_path(rendered, path_map, exact=True)
        require(local in covered_members,
                f"offline evidence path is outside its typed source/root membership: {rendered}")
        expected_local.add(local)
    require({local for _origin, local in path_map} == expected_local,
            "bounded offline map is not the complete exact input/output/source/TMPDIR file membership")

    # Only explicit receipt pins declare canonical JSON evidence. Source and
    # TMPDIR payloads are opaque raw files regardless of their suffix.
    declared_json_pins: list[tuple[object, str, int]] = []
    for index, entry in enumerate(completion["entries"]):
        for role, maximum in (
            ("probe", MAX_PROBE_BYTES), ("expectation", MAX_TEMPLATE_BYTES),
            ("context", MAX_TEMPLATE_BYTES), ("request", MAX_TEMPLATE_BYTES),
            ("validation", MAX_METADATA_BYTES), ("receipt", MAX_METADATA_BYTES),
        ):
            require(role in entry,
                    f"offline completion entry[{index}] omits declared JSON pin {role}")
            declared_json_pins.append((entry[role],
                                       f"offline completion entry[{index}] {role}",
                                       maximum))
    event_json_roles = {
        "probe_completed": {
            "direct_process_start": MAX_METADATA_BYTES,
            "direct_process_capture": MAX_METADATA_BYTES,
            "direct_process_owner_return": MAX_METADATA_BYTES,
        },
        "probe_verified": {
            "probe": MAX_PROBE_BYTES,
            "request_template_copy": MAX_TEMPLATE_BYTES,
            "context_template_copy": MAX_TEMPLATE_BYTES,
        },
        "application_bound": {"direct_process_start": MAX_METADATA_BYTES},
        "application_exited": {
            "direct_process_start": MAX_METADATA_BYTES,
            "direct_process_capture": MAX_METADATA_BYTES,
            "direct_process_owner_return": MAX_METADATA_BYTES,
        },
        "feedback_verified": {
            "expectation": MAX_TEMPLATE_BYTES,
            "validation": MAX_METADATA_BYTES,
        },
        "bundle_verified": {
            "context": MAX_TEMPLATE_BYTES, "request": MAX_TEMPLATE_BYTES,
            "receipt": MAX_METADATA_BYTES, "expectation": MAX_TEMPLATE_BYTES,
            "validation": MAX_METADATA_BYTES, "probe": MAX_PROBE_BYTES,
        },
    }
    for index, record in enumerate(ledger_records):
        event = record.get("event")
        if event not in event_json_roles:
            continue
        details = record.get("details")
        require(type(details) is dict,
                f"offline ledger event[{index}] JSON evidence details are malformed")
        for role, maximum in event_json_roles[event].items():
            require(role in details,
                    f"offline ledger event[{index}] omits declared JSON pin {role}")
            declared_json_pins.append((details[role],
                                       f"offline ledger event[{index}] {role}",
                                       maximum))
        if event == "probe_completed":
            require("stdout_path" in details and "stdout_sha256" in details,
                    f"offline ledger event[{index}] omits its policy-probe JSON output pin")
            declared_json_pins.append((
                {"path": details["stdout_path"], "sha256": details["stdout_sha256"]},
                f"offline ledger event[{index}] policy-probe stdout", MAX_PROBE_BYTES,
            ))

    parsed_evidence: dict[Path, tuple[bytes, Any, str]] = {}
    for pin_value, label, maximum in declared_json_pins:
        pin = exact(pin_value, {"path", "sha256"}, f"{label} declared JSON pin")
        origin = _pin_path(pin["path"], f"{label} path")
        local = _map_evidence_path(origin, path_map, exact=True)
        require(local in expected_local and
                fingerprints.get(str(local), {}).get("kind") == "file",
                f"{label} is not a declared regular member of the exact evidence map")
        expected_sha = digest(pin["sha256"], f"{label} raw SHA-256")
        existing = parsed_evidence.get(local)
        if existing is None:
            raw, _info = read_stable(local, label, maximum)
            require(sha256_bytes(raw) == expected_sha,
                    f"{label} bytes differ from their original raw pin")
            value = parse_object(raw, label, maximum, canonical=True)
            parsed_evidence[local] = (raw, value, expected_sha)
        else:
            raw, value, prior_sha = existing
            require(prior_sha == expected_sha and len(raw) <= maximum,
                    f"{label} aliases JSON evidence under another pin")
        for rendered in _offline_path_references(value):
            local_reference = _map_evidence_path(rendered, path_map, exact=True)
            require(local_reference in covered_members,
                    f"{label} references a path outside its typed source/root membership: {rendered}")

    # The exact source file/artifact set is bound by typed descriptors. Hash
    # those bytes only after both local root membership and every nested pin
    # membership have closed; `.json` never selects a parser.
    fingerprints.update({str(path): _offline_local_fingerprint(
        path, "offline SourceV5 inventory",
    ) for path in source_inventory_paths})
    require(all(fingerprints[str(path)]["kind"] == "directory"
                for path in source_directory_paths),
            "offline SourceV5 inventory traverses an untyped symlink directory")
    for source_host, origin, local, item in source_file_checks:
        fingerprint = fingerprints[str(local)]
        expected_kind = item["kind"]
        require((expected_kind == "file" and fingerprint["kind"] == "file") or
                (expected_kind == "symlink" and fingerprint["kind"] == "symlink" and
                 fingerprint["target"] == item.get("target")),
                f"offline SourceV5 member type/target differs from its pinned inventory: {origin}")
        if expected_kind == "symlink":
            target_bytes = item["target"].encode("utf-8", "strict")
            require(item["mode"] == "120000" and
                    0 < len(target_bytes) <= MAX_SOURCE_SYMLINK_BYTES and
                    item["size"] == len(target_bytes) == fingerprint["size"] and
                    sha256_bytes(target_bytes) == digest(
                        item["sha256"], f"offline {source_host} SourceV5 symlink SHA",
                    ), f"offline SourceV5 symlink literal bytes/mode/size differ: {origin}")
        else:
            require(fingerprint["mode"] == (int(item["mode"], 8) & 0o777) and
                    fingerprint["size"] == item["size"] and
                    hash_stable(local, f"offline {source_host} SourceV5 file",
                                MAX_SOURCE_FILE_BYTES)[1] == item["sha256"],
                    f"offline SourceV5 source bytes/mode differ from their raw inventory: {origin}")
    for source_host, origin, local, artifact in source_artifact_checks:
        fingerprint = fingerprints[str(local)]
        require(fingerprint["kind"] == "file" and
                hash_stable(local, f"offline {source_host} SourceV5 artifact",
                            1024 * 1024 * 1024)[1] == digest(
                                artifact["sha256"],
                                f"offline {source_host} artifact SHA-256",
                            ),
                f"offline SourceV5 artifact bytes differ from their raw inventory: {origin}")

    # Reuse the exact SourceV5-pinned campaign/source-inventory verifier only
    # after the complete original Source.files/artifact membership and local
    # byte fingerprints have closed. The campaign module loads its inventory
    # reader from this same copied SourceRoot and checks the captured module pin.
    require(len(source_manifests) == len(source_map) and bool(source_manifests),
            "offline SourceV5 manifest closure is incomplete")
    controller_raw, _controller_sha, _controller_record = _source_file(
        source_root, source_manifests[0], CONTROLLER_PATH,
        "offline captured campaign/source-inventory verifier",
        maximum=MAX_SCRIPT_BYTES,
    )
    captured_controller = _load_module(
        controller_raw, source_root / CONTROLLER_PATH,
        "offline captured campaign/source-inventory verifier",
    )
    verify_manifest = getattr(captured_controller, "verify_source_manifest", None)
    require(callable(verify_manifest),
            "captured campaign controller has no typed source-inventory verifier")
    for source_host, source_manifest in zip(source_map, source_manifests, strict=True):
        try:
            verify_manifest(source_manifest, verify_artifacts=False)
        except Exception as error:
            raise CapacityStageError(
                f"exact captured SourceInventory module rejected offline host {source_host}: "
                f"{type(error).__name__}: {error}"
            ) from error

    for path_text, before in fingerprints.items():
        path = Path(path_text)
        after = _offline_local_fingerprint(path, "offline evidence stability")
        require(after == before,
                f"offline local evidence fingerprint changed during preflight: {path}")

    normalized_pins = {
        "preparation": {"path": str(preparation_path), "sha256": preparation_ref["sha256"]},
        "resource_budget": {"path": str(budget_path), "sha256": budget_ref["sha256"]},
        "observed_host": {"path": str(observed_path), "sha256": observed_ref["sha256"]},
        "completion": {"path": str(completion_path), "sha256": completion_ref["sha256"]},
        "host_verification": {
            "path": str(receipt_path), "raw_sha256": receipt_ref["raw_sha256"],
            "receipt_sha256": receipt_ref["receipt_sha256"],
        },
    }
    return {
        "path_map": path_map, "source_root": source_root,
        "input_root": input_root, "output_root": output_root,
        "stage_dir": stage_dir, "pins": normalized_pins,
        "preparation": preparation, "resource_budget": budget,
        "completion": completion, "host_verification": host_receipt,
        "local_fingerprints": fingerprints,
        "origin_source_root": source_origin_root,
        "origin_input_root": input_origin_root,
        "origin_output_root": output_origin_root,
    }


def _bounded_preparation_reader_pin(
    preparation_pin: object,
) -> tuple[dict[str, str], str | None]:
    """Adapt the bounded raw/semantic pin to the existing raw-file reader."""
    if type(preparation_pin) is dict and set(preparation_pin) == {
        "path", "raw_sha256", "semantic_sha256",
    }:
        pin = exact(preparation_pin, {
            "path", "raw_sha256", "semantic_sha256",
        }, "bounded preparation raw/semantic pin")
        require(type(pin["path"]) is str,
                "bounded preparation path must be an absolute string")
        _path_text(Path(pin["path"]), "bounded preparation path")
        raw_sha = digest(pin["raw_sha256"], "bounded preparation raw SHA-256")
        semantic_sha = digest(pin["semantic_sha256"],
                              "bounded preparation semantic SHA-256")
        return {"path": pin["path"], "sha256": raw_sha}, semantic_sha
    pin = exact(preparation_pin, {"path", "sha256"},
                "bounded preparation legacy raw pin")
    require(type(pin["path"]) is str,
            "bounded preparation path must be an absolute string")
    _path_text(Path(pin["path"]), "bounded preparation path")
    digest(pin["sha256"], "bounded preparation raw SHA-256")
    return {"path": pin["path"], "sha256": pin["sha256"]}, None


def _prepare_capacity_preparation_pins(
    preparation_pin: object, source_root_arg: Path, input_root_arg: Path,
    host_id: str, observed_host_pin: object, *, live_host: bool = True,
    offline_copy: bool = False,
    expected_preparation_semantic_sha256: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    preparation, preparation_raw, preparation_raw_sha = read_pin(
        preparation_pin, "Source5 preparation intent", MAX_SOURCE_FILE_BYTES, canonical=True,
    )
    if expected_preparation_semantic_sha256 is not None:
        require(preparation.get("preparation_sha256") ==
                expected_preparation_semantic_sha256,
                "preparation intent differs from its bounded caller-pinned semantic digest")
    preparation_path = Path(exact(preparation_pin, {"path", "sha256"}, "preparation intent pin")["path"])
    source_root = _safe_root(source_root_arg, "SourceV5 root")
    input_root = _safe_root(input_root_arg, "preparation input root")
    require(not _is_within(source_root, input_root), "preparation input root must be outside SourceV5")
    require(not _is_within(source_root, preparation_path), "preparation intent must be stored outside SourceV5")
    host_id = token(host_id, "preparation host ID")
    require(preparation.get("schema") == PREPARATION_INTENT_SCHEMA,
            "capacity preparation requires the separate Source5 preparation schema")
    sources_map = preparation.get("source_pins")
    require(type(sources_map) is dict and set(sources_map) == {
        host["host_id"] for host in preparation.get("core", {}).get("hosts", []) if type(host) is dict
    }, "preparation source pins do not cover exactly the frozen host set")
    require(host_id in sources_map, "selected preparation host is not frozen in the intent")
    host_records = [host for host in preparation["core"]["hosts"] if host["host_id"] == host_id]
    require(len(host_records) == 1, "preparation selected host contract is missing or duplicated")
    host = host_records[0]

    refs: dict[str, tuple[Path, dict[str, Any], bytes, str]] = {}
    for other_host, source_pin in sources_map.items():
        manifest_pin = exact(source_pin.get("manifest"), {
            "relative_path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
        }, f"preparation {other_host} SourceV5 pin")
        manifest_path = _safe_child(input_root, manifest_pin["relative_path"], f"preparation {other_host} SourceV5 manifest")
        raw, _info = read_stable(manifest_path, f"preparation {other_host} SourceV5 manifest", MAX_MANIFEST_BYTES)
        require(sha256_bytes(raw) == digest(manifest_pin["raw_sha256"], f"{other_host} source manifest raw SHA"),
                f"preparation {other_host} source manifest raw bytes changed")
        value = parse_object(raw, f"preparation {other_host} SourceV5 manifest", MAX_MANIFEST_BYTES, canonical=True)
        require(value.get("schema") == SOURCE_SCHEMA and
                value.get("manifest_sha256") == digest(manifest_pin["semantic_sha256"], f"{other_host} semantic source SHA") and
                value.get("source", {}).get("source_tree_sha256") == digest(manifest_pin["source_tree_sha256"], f"{other_host} source tree SHA"),
                f"preparation {other_host} source manifest raw/semantic/tree pins differ")
        refs[other_host] = (manifest_path, value, raw, sha256_bytes(raw))
    sources = {name: value[1] for name, value in refs.items()}
    source = sources[host_id]
    stack = _capture_source_stack(source_root, source, Path(__file__).resolve())
    controller = stack["controller"]
    for other_host, other_source in sources.items():
        try:
            controller.verify_source_manifest(
                other_source,
                (source_root if other_host == host_id and not offline_copy else None),
                verify_artifacts=(other_host == host_id and not offline_copy),
            )
        except Exception as error:
            raise CapacityStageError(f"captured SourceV5 source verifier rejected preparation host {other_host}: {error}") from error
        other_stack = _capture_source_stack(source_root, other_source, Path(__file__).resolve())
        require({name: other_stack[f"{name}_sha256"] for name in (
            "stage", "controller", "inputs", "feedback_reader", "capacity_producer",
        )} == {name: stack[f"{name}_sha256"] for name in (
            "stage", "controller", "inputs", "feedback_reader", "capacity_producer",
        )}, f"preparation SourceV5 execution imports differ between hosts ({host_id} and {other_host})")

    inputs = stack["inputs"]
    require(getattr(inputs, "SOURCE5_PREPARATION_SCHEMA", None) == PREPARATION_INTENT_SCHEMA and
            callable(getattr(inputs, "validate_preparation_intent", None)) and
            getattr(inputs, "PREPARATION_MODULE_PATHS", None) is not None,
            "captured campaign-inputs module lacks pre-Spec preparation validation")
    source_runtime_sha = source["runtime_readback_validator"]["sha256"]
    try:
        for index, cell in enumerate(preparation["core"]["cells"]):
            expected_limits = controller.fixed_resource_limits_for_cell(
                cell["workload"], cell["profile"], source_runtime_sha,
            )
            require(canonical_bytes(expected_limits) == canonical_bytes(cell["resource_limits"]) and
                    sha256_bytes(canonical_bytes(expected_limits)) == cell["resource_ceiling_sha256"],
                    f"preparation core cell[{index}] changed its fixed runtime resource limits")
    except Exception as error:
        if isinstance(error, CapacityStageError):
            raise
        raise CapacityStageError(f"captured SourceV5 controller could not replay core resource limits: {error}") from error
    module_pins = sources_map[host_id]["modules"]
    context_helper_sha256: str | None = None
    captured_process_modules: dict[str, tuple[types.ModuleType, str]] = {}
    for role, source_path in inputs.PREPARATION_MODULE_PATHS.items():
        module_pin = exact(module_pins.get(role), {"path", "sha256"}, f"preparation module {role} pin")
        raw, source_sha, _record = _source_file(source_root, source, source_path, f"preparation module {role}")
        require(module_pin == {"path": source_path, "sha256": source_sha},
                f"preparation module {role} differs from the frozen intent pin")
        if role == "preparation_helper":
            context_helper_sha256 = source_sha
            active_raw, _active_info = read_stable(Path(__file__).with_name("application-source5-input-preparation.py"),
                                                     "active Source5 preparation helper", MAX_SCRIPT_BYTES)
            require(active_raw == raw and sha256_bytes(active_raw) == source_sha,
                    "active Source5 preparation helper differs from its SourceV5 typed inventory entry")
        elif role in ("fixed_pair", "soak_readback"):
            module = _load_module(raw, source_root / source_path,
                                  "accepted FixedR8 direct process owner" if role == "fixed_pair" else
                                  "captured Soak process identity helper")
            sys.modules[module.__name__] = module
            captured_process_modules[role] = (module, source_sha)
    require(context_helper_sha256 is not None, "SourceV5 preparation helper module pin is missing")
    require(set(captured_process_modules) == {"fixed_pair", "soak_readback"},
            "pre-Spec capacity preparation requires both typed process-owner modules")
    fixed_owner, fixed_owner_sha = captured_process_modules["fixed_pair"]
    process_identity_helper, process_identity_helper_sha = captured_process_modules["soak_readback"]
    require(callable(getattr(fixed_owner, "_run_direct_process", None)) and
            callable(getattr(fixed_owner, "_require_waitable_sigchld", None)) and
            callable(getattr(process_identity_helper, "_hash_open_executable", None)) and
            callable(getattr(process_identity_helper, "_fingerprint", None)) and
            callable(getattr(process_identity_helper, "_proc_start_ticks", None)),
            "captured FixedR8/Soak modules do not expose the accepted owned-process API")
    try:
        validation = inputs.validate_preparation_intent(preparation, sources, input_root)
    except Exception as error:
        raise CapacityStageError(f"captured pre-Spec preparation validator rejected the intent: {error}") from error
    require(preparation["preparation_sha256"] == validation["preparation_sha256"],
            "preparation semantic digest changed during SourceV5 replay")

    observed_entry = exact(preparation["observed_hosts"].get(host_id),
                           {"relative_path", "raw_sha256"}, "selected observed-host preparation pin")
    observed_path = _safe_child(input_root, observed_entry["relative_path"], "preparation observed-host context")
    observed, observed_raw, observed_raw_sha = read_pin(
        observed_host_pin, "observed host context", MAX_TEMPLATE_BYTES, canonical=True,
    )
    supplied_path = Path(exact(observed_host_pin, {"path", "sha256"}, "observed-host pin")["path"])
    require(supplied_path.resolve(strict=True) == observed_path and
            observed_raw_sha == observed_entry["raw_sha256"],
            "selected observed-host file differs from the preparation intent's original raw pin")
    current_host = (_verify_observed_host(observed, host, host_id) if live_host else
                    _verify_observed_host_static(observed, host, host_id))
    source_path, source_value, source_raw, source_raw_sha = refs[host_id]
    schedule_sha = sha256_bytes(canonical_bytes(preparation["capacity_templates"]))
    context = {
        "preparation_mode": True,
        "preparation": preparation,
        "preparation_path": preparation_path,
        "preparation_raw": preparation_raw,
        "preparation_raw_sha256": preparation_raw_sha,
        "preparation_semantic_sha256": preparation["preparation_sha256"],
        "preparation_helper_sha256": context_helper_sha256,
        "spec": preparation["core"],
        "plan": {"capacity_process_templates_sha256": schedule_sha},
        "source_root": source_root, "input_root": input_root,
        "host_id": host_id, "host": host,
        "host_context": observed, "host_context_raw": observed_raw,
        "host_context_raw_sha256": observed_raw_sha,
        "host_context_path": supplied_path, "current_host": current_host,
        "sources": sources, "source": source_value, "source_path": source_path,
        "source_raw": source_raw, "source_raw_sha256": source_raw_sha,
        "source_semantic_sha256": source_value["manifest_sha256"],
        "source_tree_sha256": source_value["source"]["source_tree_sha256"],
        "stack": {
            **stack,
            "fixed_pair": fixed_owner, "fixed_pair_sha256": fixed_owner_sha,
            "fixed_pair_path": inputs.PREPARATION_MODULE_PATHS["fixed_pair"],
            "process_identity_helper": process_identity_helper,
            "process_identity_helper_sha256": process_identity_helper_sha,
            "process_identity_helper_path": inputs.PREPARATION_MODULE_PATHS["soak_readback"],
        },
        "validation": validation,
    }
    scheduling_intent = {
        **preparation, "preparation_raw_sha256": preparation_raw_sha,
    }
    jobs = derive_capacity_preparation_jobs(scheduling_intent, host_id)
    return context, jobs, schedule_sha


def _preparation_resource_monitor_sample_count(
    ceilings: dict[str, Any], fixed: types.ModuleType,
) -> int:
    interval_ns = ceilings["monitor_sample_interval_milliseconds"] * 1_000_000
    overrun_seconds = int(getattr(fixed, "TERM_GRACE_SECONDS", 3.0) +
                          getattr(fixed, "KILL_REAP_SECONDS", 1.0))
    runtime_ns = (ceilings["process_deadline_seconds"] + overrun_seconds) * 1_000_000_000
    return (runtime_ns + interval_ns - 1) // interval_ns + 3


def _estimate_preparation_resource_monitor_report_bytes(
    ceilings: dict[str, Any], fixed: types.ModuleType, *, tmpdir_root_count: int,
) -> int:
    sample_count = _preparation_resource_monitor_sample_count(ceilings, fixed)
    fake_root = {"path": "x" * MAX_PATH_BYTES, "device": U64_MAX, "inode": U64_MAX}
    sample = {
        "monotonic_ns": U64_MAX, "job_output_bytes": U64_MAX,
        "job_output_inodes": U64_MAX, "generation_bytes": U64_MAX,
        "generation_inodes": U64_MAX, "tmpdir_bytes": U64_MAX,
        "tmpdir_inodes": U64_MAX,
        "tmpdir_by_device": {
            str(U64_MAX - index): {"bytes": U64_MAX, "inodes": U64_MAX}
            for index in range(min(16, tmpdir_root_count))
        },
        "monitor_report_count_before": U64_MAX,
        "job_monitor_report_count_before": U64_MAX,
        "generation_receipt_reserve_bytes": U64_MAX,
        "generation_receipt_reserve_inodes": U64_MAX,
        "job_monitor_receipt_reserve_bytes": U64_MAX,
        "trace_files": {name: U64_MAX for name in PreparationResourceMonitor.TRACE_NAMES},
        "filesystems": [
            {"device": U64_MAX, "available_bytes": U64_MAX,
             "available_inodes": U64_MAX, "required_bytes": U64_MAX,
             "required_inodes": U64_MAX, "tmpdir_bytes": U64_MAX,
             "tmpdir_inodes": U64_MAX}
            for _ in range(tmpdir_root_count + 1)
        ],
    }
    report = {
        "schema": PREPARATION_RESOURCE_MONITOR_SCHEMA, "role": "application",
        "resource_budget": {"path": "x" * MAX_PATH_BYTES,
                            "raw_sha256": "f" * 64, "semantic_sha256": "e" * 64},
        "fixed_pair_sha256": "d" * 64,
        "sample_interval_milliseconds": ceilings["monitor_sample_interval_milliseconds"],
        "roots": {"generation": fake_root, "job_output": fake_root,
                  "trace": fake_root, "tmpdirs": [fake_root] * tmpdir_root_count},
        "started_monotonic_ns": U64_MAX, "ended_monotonic_ns": U64_MAX,
        "sample_count": sample_count,
        "high_water": {key: U64_MAX for key in (
            "job_output_bytes", "job_output_inodes", "generation_bytes",
            "generation_inodes", "tmpdir_bytes", "tmpdir_inodes",
        )},
        "stop_reason": "x" * 512, "monitor_error": "x" * 1024,
        "samples": [],
    }
    return len(canonical_bytes(report)) + sample_count * (len(canonical_bytes(sample)) + 1)


def _prepare_capacity_resource_budget_context(
    context: dict[str, Any], resource_budget_pin: dict[str, Any], *,
    monitor_report_count: int,
) -> dict[str, Any]:
    """Validate the caller-frozen budget and its exact captured monitor owner."""
    pin = exact(resource_budget_pin, {"path", "sha256"}, "preparation resource budget raw pin")
    path = _pin_path(pin["path"], "preparation resource budget path")
    require(_is_within(context["input_root"], path) and
            not _is_within(context["source_root"], path),
            "preparation resource budget must stay in the private input root outside SourceV5")
    relative = path.relative_to(context["input_root"]).as_posix()
    require(_safe_child(context["input_root"], relative, "preparation resource budget") == path,
            "preparation resource budget traverses an alias or symlink")
    raw, info = read_stable(path, "preparation resource budget", MAX_METADATA_BYTES)
    raw_sha = sha256_bytes(raw)
    require(raw_sha == digest(pin["sha256"], "preparation resource budget raw SHA-256"),
            "preparation resource budget bytes differ from the caller's exact raw pin")
    value = parse_object(raw, "preparation resource budget", MAX_METADATA_BYTES, canonical=True)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o600,
            "preparation resource budget must be an owned mode-0600 regular file")
    inputs = context["stack"]["inputs"]
    validate = getattr(inputs, "validate_preparation_resource_budget", None)
    require(getattr(inputs, "SOURCE5_PREPARATION_RESOURCE_BUDGET_SCHEMA", None) ==
            PREPARATION_RESOURCE_BUDGET_SCHEMA and callable(validate),
            "captured campaign-inputs module lacks the bounded preparation budget contract")
    preparation_pin = {
        "path": str(context["preparation_path"]),
        "raw_sha256": context["preparation_raw_sha256"],
        "semantic_sha256": context["preparation_semantic_sha256"],
    }
    try:
        normalized = validate(value, context["preparation"], preparation_pin)
    except Exception as error:
        raise CapacityStageError(f"captured Source5 budget validator rejected the raw contract: {error}") from error
    fixed = context["stack"]["fixed_pair"]
    fixed_hash = context["stack"]["fixed_pair_sha256"]
    expected_fixed = context["preparation"]["source_pins"][context["host_id"]]["modules"]["fixed_pair"]
    require(context["stack"]["fixed_pair_path"] == expected_fixed["path"] == "scripts/application-fixed-pair.py" and
            fixed_hash == expected_fixed["sha256"] == PREPARATION_FIXED_PAIR_R4_WALKER_SHA256 and
            callable(getattr(fixed, "_tmpdir_usage_snapshot", None)) and
            callable(getattr(fixed, "_open_tmpdir_absolute_directory", None)) and
            callable(getattr(fixed, "_run_direct_process", None)),
            "bounded preparation requires the exact typed FixedPair R4 walker and owner")
    ceilings = normalized["ceilings"]
    require(type(monitor_report_count) is int and monitor_report_count == 30,
            "bounded preparation monitor schedule must cover all 15 original jobs and both owned processes")
    report_bound = _estimate_preparation_resource_monitor_report_bytes(
        ceilings, fixed, tmpdir_root_count=monitor_report_count // 2,
    )
    # A successful generation still has to append the final hash-chain record,
    # seal the ledger, and publish both the completion and host verification
    # receipt after the last live monitor sample.  Reserve their existing hard
    # maxima so a late receipt cannot consume bytes promised to monitor reports.
    required_receipt_bytes = (monitor_report_count * report_bound + MAX_LEDGER_BYTES +
                              2 * MAX_METADATA_BYTES)
    require(report_bound <= MAX_METADATA_BYTES and
            ceilings["maximum_job_output_bytes"] <= MAX_PREPARATION_JOB_OUTPUT_BYTES and
            ceilings["maximum_job_output_inodes"] <= MAX_PREPARATION_JOB_OUTPUT_INODES and
            ceilings["maximum_generation_bytes"] <= MAX_PREPARATION_GENERATION_BYTES and
            ceilings["maximum_generation_inodes"] <= MAX_PREPARATION_GENERATION_INODES and
            ceilings["maximum_tmpdir_bytes"] <= getattr(fixed, "MAX_TMPDIR_BYTES", -1) and
            ceilings["maximum_tmpdir_inodes"] <= getattr(fixed, "MAX_TMPDIR_INODES", -1) and
            ceilings["maximum_trace_file_bytes"] <= MAX_TRACE_FILE_BYTES and
            ceilings["durable_receipt_reserve_bytes"] >= required_receipt_bytes and
            ceilings["durable_receipt_reserve_inodes"] >= 32,
            "resource budget exceeds captured TMPDIR/trace caps or cannot reserve durable receipts")
    resource_pin = {
        "path": str(path), "raw_sha256": raw_sha,
        "semantic_sha256": normalized["resource_budget_sha256"],
    }
    return {
        "value": value, "raw": raw, "path": path, "raw_sha256": raw_sha,
        "semantic_sha256": normalized["resource_budget_sha256"],
        "normalized": normalized, "ceilings": ceilings,
        "pin": resource_pin, "fixed_pair_sha256": fixed_hash,
        "monitor_report_max_bytes": report_bound,
        "monitor_report_max_samples": _preparation_resource_monitor_sample_count(ceilings, fixed),
        "required_durable_receipt_bytes": required_receipt_bytes,
        "monitor_report_count": monitor_report_count,
    }


def _bounded_root_identity(fixed: types.ModuleType, path: Path, label: str) -> dict[str, Any]:
    opener = getattr(fixed, "_open_tmpdir_absolute_directory", None)
    require(callable(opener), "captured FixedPair R4 module lacks dirfd-root opening")
    descriptor = opener(path)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700,
                f"{label} must be an owned mode-0700 directory")
        return {"path": str(path), "device": info.st_dev, "inode": info.st_ino}
    finally:
        os.close(descriptor)


def _bounded_statvfs(
    fixed: types.ModuleType, root: dict[str, Any], label: str,
) -> os.statvfs_result:
    """Read filesystem capacity through a held root FD and recheck its name."""
    path = Path(root["path"])
    descriptor = fixed._open_tmpdir_absolute_directory(path)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700 and
                (info.st_dev, info.st_ino) == (root["device"], root["inode"]),
                f"{label} held filesystem root changed identity or privacy")
        proc_path = Path("/proc/self/fd") / str(descriptor)
        try:
            snapshot = os.statvfs(proc_path)
        except OSError as error:
            raise CapacityStageError(f"cannot read {label} capacity through its held directory FD: {error}") from error
        require(_bounded_root_identity(fixed, path, label) == root,
                f"{label} named root changed during free-space sampling")
        return snapshot
    finally:
        os.close(descriptor)


class PreparationResourceMonitor:
    """Sample bounded preparation roots through the source-pinned FixedPair R4 walker."""

    TRACE_NAMES = (
        "feedback-trace-manifest.tsv", "feedback-events.jsonl", "resource-samples.tsv",
    )

    def __init__(
        self, context: dict[str, Any], budget: dict[str, Any],
        stage_dir: Path, job_dir: Path, trace_dir: Path,
        tmpdir_roots: list[dict[str, Any]], progress: dict[str, Any],
        expected_stage_root: dict[str, Any], expected_job_root: dict[str, Any],
        expected_trace_root: dict[str, Any],
    ):
        self.context = context
        self.budget = budget
        self.ceilings = budget["ceilings"]
        self.maximum_report_bytes = budget["monitor_report_max_bytes"]
        self.fixed = context["stack"]["fixed_pair"]
        self.fixed_sha256 = context["stack"]["fixed_pair_sha256"]
        self.stage_dir = stage_dir
        self.job_dir = job_dir
        self.trace_dir = trace_dir
        self.stage_root = _bounded_root_identity(self.fixed, stage_dir, "bounded generation root")
        self.job_root = _bounded_root_identity(self.fixed, job_dir, "bounded job output root")
        self.trace_root = _bounded_root_identity(self.fixed, trace_dir, "bounded trace root")
        require(self.stage_root == expected_stage_root and self.job_root == expected_job_root and
                self.trace_root == expected_trace_root,
                "bounded generation/job/trace root changed after its initial private binding")
        self.tmpdir_roots = [dict(item) for item in tmpdir_roots]
        self.root_pins = {
            "generation": dict(self.stage_root), "job_output": dict(self.job_root),
            "trace": dict(self.trace_root), "tmpdirs": [dict(item) for item in self.tmpdir_roots],
        }
        self.progress = progress
        self.maximum_report_bytes = budget["monitor_report_max_bytes"]
        self.interval_ns = self.ceilings["monitor_sample_interval_milliseconds"] * 1_000_000
        fixed_overrun_seconds = int(getattr(self.fixed, "TERM_GRACE_SECONDS", 3.0) +
                                    getattr(self.fixed, "KILL_REAP_SECONDS", 1.0))
        maximum_runtime_ns = (
            self.ceilings["process_deadline_seconds"] + fixed_overrun_seconds
        ) * 1_000_000_000
        self.maximum_samples = (maximum_runtime_ns + self.interval_ns - 1) // self.interval_ns + 3
        self.high_water = {key: 0 for key in (
            "job_output_bytes", "job_output_inodes", "generation_bytes",
            "generation_inodes", "tmpdir_bytes", "tmpdir_inodes",
        )}
        self.role = ""
        self.samples: list[dict[str, Any]] = []
        self.last_sample_ns = 0
        self.started_monotonic_ns = 0
        self.ended_monotonic_ns = 0
        self.stop_reason: str | None = None
        self.monitor_error: str | None = None
        self.sealed_roles: set[str] = set()
        self._check_report_size_bound()
        opener = self.fixed._open_tmpdir_absolute_directory
        self.job_fd = opener(job_dir)
        self.trace_fd = -1
        try:
            trace_fd = os.open(
                "trace", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self.job_fd,
            )
            trace_info = os.fstat(trace_fd)
            require((trace_info.st_dev, trace_info.st_ino) ==
                    (self.trace_root["device"], self.trace_root["inode"]) and
                    stat.S_IMODE(trace_info.st_mode) == 0o700 and trace_info.st_uid == os.getuid(),
                    "bounded trace root changed while opening its parent-relative descriptor")
            self.trace_fd = trace_fd
        except BaseException:
            os.close(self.job_fd)
            raise

    def begin(self, role: str) -> None:
        require(role in ("policy_probe", "application"), "bounded monitor role is unsupported")
        require(role not in self.sealed_roles,
                "bounded monitor role cannot be replayed or resealed")
        self.role = role
        self.samples = []
        self.last_sample_ns = 0
        self.started_monotonic_ns = time.monotonic_ns()
        self.ended_monotonic_ns = 0
        self.stop_reason = None
        self.monitor_error = None

    def _check_report_size_bound(self) -> None:
        sample_template = {
            "monotonic_ns": U64_MAX, "job_output_bytes": U64_MAX,
            "job_output_inodes": U64_MAX, "generation_bytes": U64_MAX,
            "generation_inodes": U64_MAX, "tmpdir_bytes": U64_MAX,
            "tmpdir_inodes": U64_MAX,
            "tmpdir_by_device": {
                str(U64_MAX - index): {"bytes": U64_MAX, "inodes": U64_MAX}
                for index in range(16)
            },
            "monitor_report_count_before": U64_MAX,
            "job_monitor_report_count_before": U64_MAX,
            "generation_receipt_reserve_bytes": U64_MAX,
            "generation_receipt_reserve_inodes": U64_MAX,
            "job_monitor_receipt_reserve_bytes": U64_MAX,
            "trace_files": {name: U64_MAX for name in self.TRACE_NAMES},
            "filesystems": [
                {"device": U64_MAX, "available_bytes": U64_MAX,
                 "available_inodes": U64_MAX, "required_bytes": U64_MAX,
                 "required_inodes": U64_MAX, "tmpdir_bytes": U64_MAX,
                 "tmpdir_inodes": U64_MAX}
                for _ in range(len(self.tmpdir_roots) + 1)
            ],
        }
        prefix = {
            "schema": PREPARATION_RESOURCE_MONITOR_SCHEMA,
            "role": "application", "resource_budget": self.budget["pin"],
            "fixed_pair_sha256": self.fixed_sha256,
            "sample_interval_milliseconds": self.ceilings["monitor_sample_interval_milliseconds"],
            "roots": {
                **self.root_pins,
            },
            "started_monotonic_ns": U64_MAX, "ended_monotonic_ns": U64_MAX,
            "sample_count": self.maximum_samples,
            "high_water": {key: U64_MAX for key in self.high_water},
            "stop_reason": "x" * 512, "monitor_error": "x" * 1024,
            "samples": [],
        }
        base_bytes = len(canonical_bytes(prefix))
        sample_bytes = len(canonical_bytes(sample_template)) + 1
        actual_report_bound = base_bytes + self.maximum_samples * sample_bytes
        require(actual_report_bound <= self.maximum_report_bytes <= MAX_METADATA_BYTES,
                "caller-frozen sample period cannot fit its bounded monitor receipt")

    def _scan_tree(self, root: dict[str, Any], inode_ceiling: int) -> dict[str, int]:
        return _fixed_directory_usage(
            self.fixed, root, inode_ceiling, live=True,
        )

    def _trace_file_size(self, name: str) -> int | None:
        try:
            before = os.stat(name, dir_fd=self.trace_fd, follow_symlinks=False)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return None
            raise
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                before.st_dev == self.trace_root["device"] and before.st_nlink == 1 and
                before.st_size >= 0,
                f"bounded trace member {name} is unowned, linked, special, or cross-device")
        file_flags = (getattr(os, "O_PATH", os.O_RDONLY | os.O_NONBLOCK) |
                      os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            file_fd = os.open(name, file_flags, dir_fd=self.trace_fd)
        except OSError as error:
            if error.errno == errno.ENOENT:
                return before.st_size
            raise
        try:
            opened = os.fstat(file_fd)
            require((opened.st_dev, opened.st_ino, opened.st_uid, stat.S_IFMT(opened.st_mode)) ==
                    (before.st_dev, before.st_ino, before.st_uid, stat.S_IFMT(before.st_mode)) and
                    stat.S_ISREG(opened.st_mode) and opened.st_nlink in (0, 1) and opened.st_size >= 0,
                    f"bounded trace member {name} changed between stat and open")
            after = os.fstat(file_fd)
            require((after.st_dev, after.st_ino, after.st_uid, stat.S_IFMT(after.st_mode)) ==
                    (opened.st_dev, opened.st_ino, opened.st_uid, stat.S_IFMT(opened.st_mode)) and
                    after.st_nlink in (0, 1) and after.st_size >= 0,
                    f"bounded trace member {name} identity changed while sampling")
            try:
                named = os.stat(name, dir_fd=self.trace_fd, follow_symlinks=False)
            except OSError as error:
                if error.errno == errno.ENOENT:
                    return max(before.st_size, opened.st_size, after.st_size)
                raise
            require((named.st_dev, named.st_ino, named.st_uid, stat.S_IFMT(named.st_mode)) ==
                    (opened.st_dev, opened.st_ino, opened.st_uid, stat.S_IFMT(opened.st_mode)) and
                    stat.S_ISREG(named.st_mode) and named.st_nlink in (0, 1) and named.st_size >= 0,
                    f"bounded trace member {name} name changed while sampling")
            return max(before.st_size, opened.st_size, after.st_size, named.st_size)
        finally:
            os.close(file_fd)

    def _sample(self, *, force: bool = False) -> bool:
        if self.stop_reason is not None:
            return True
        now = time.monotonic_ns()
        if not force and self.last_sample_ns and now - self.last_sample_ns < self.interval_ns:
            return False
        if len(self.samples) >= self.maximum_samples:
            self.stop_reason = "monitor_sample_bound"
            return True
        try:
            generation = self._scan_tree(self.stage_root, self.ceilings["maximum_generation_inodes"])
            job_output = self._scan_tree(self.job_root, self.ceilings["maximum_job_output_inodes"])
            tmpdir_bytes = 0
            tmpdir_inodes = 0
            tmpdir_by_device: dict[int, dict[str, int]] = {}
            for root in self.tmpdir_roots:
                remaining_inodes = max(0, self.ceilings["maximum_tmpdir_inodes"] - tmpdir_inodes)
                usage = self._scan_tree(root, remaining_inodes)
                tmpdir_bytes += usage["bytes_used"]
                tmpdir_inodes += usage["inode_count"]
                per_device = tmpdir_by_device.setdefault(root["device"], {"bytes": 0, "inodes": 0})
                per_device["bytes"] += usage["bytes_used"]
                per_device["inodes"] += usage["inode_count"]
            traces = {name: self._trace_file_size(name) for name in self.TRACE_NAMES}
            stage_device = self.stage_root["device"]
            roots_by_device: dict[int, dict[str, Any]] = {stage_device: self.stage_root}
            for root in self.tmpdir_roots:
                roots_by_device.setdefault(root["device"], root)
            filesystems: list[dict[str, int]] = []
            over: list[str] = []
            for device in sorted(roots_by_device):
                root_pin = roots_by_device[device]
                vfs = _bounded_statvfs(self.fixed, root_pin,
                                       "bounded storage filesystem root")
                available_bytes = vfs.f_bavail * vfs.f_frsize
                available_inodes = vfs.f_favail
                generation_remaining = (max(0, self.ceilings["maximum_generation_bytes"] - generation["bytes_used"])
                                        if device == stage_device else 0)
                generation_inode_remaining = (max(0, self.ceilings["maximum_generation_inodes"] - generation["inode_count"])
                                              if device == stage_device else 0)
                tmp_usage = tmpdir_by_device.get(device, {"bytes": 0, "inodes": 0})
                tmp_remaining = (max(0, self.ceilings["maximum_tmpdir_bytes"] - tmp_usage["bytes"])
                                 if device in tmpdir_by_device else 0)
                tmp_inode_remaining = (max(0, self.ceilings["maximum_tmpdir_inodes"] - tmp_usage["inodes"])
                                       if device in tmpdir_by_device else 0)
                required_bytes = (self.ceilings["minimum_free_bytes"] + generation_remaining +
                                  tmp_remaining)
                required_inodes = (self.ceilings["minimum_free_inodes"] + generation_inode_remaining +
                                   tmp_inode_remaining)
                filesystems.append({
                    "device": device, "available_bytes": available_bytes,
                    "available_inodes": available_inodes,
                    "required_bytes": required_bytes, "required_inodes": required_inodes,
                    "tmpdir_bytes": tmp_usage["bytes"],
                    "tmpdir_inodes": tmp_usage["inodes"],
                })
                if available_bytes < required_bytes:
                    over.append("minimum_free_bytes_or_receipt_reserve")
                if available_inodes < required_inodes:
                    over.append("minimum_free_inodes_or_receipt_reserve")
            if job_output["bytes_used"] > self.ceilings["maximum_job_output_bytes"]:
                over.append("job_output_bytes")
            if job_output["inode_count"] > self.ceilings["maximum_job_output_inodes"]:
                over.append("job_output_inodes")
            if generation["bytes_used"] > self.ceilings["maximum_generation_bytes"]:
                over.append("generation_bytes")
            if generation["inode_count"] > self.ceilings["maximum_generation_inodes"]:
                over.append("generation_inodes")
            monitor_report_count_before = self.progress["monitor_report_count"]
            future_reports = max(
                0, self.progress["expected_monitor_report_count"] - monitor_report_count_before,
            )
            remaining_report_bytes = (future_reports * self.maximum_report_bytes +
                                      MAX_LEDGER_BYTES + 2 * MAX_METADATA_BYTES)
            remaining_report_inodes = future_reports + 2
            generation_receipt_reserve_bytes = max(
                remaining_report_bytes, self.ceilings["durable_receipt_reserve_bytes"],
            )
            generation_receipt_reserve_inodes = max(
                remaining_report_inodes, self.ceilings["durable_receipt_reserve_inodes"],
            )
            if generation["bytes_used"] + generation_receipt_reserve_bytes > self.ceilings["maximum_generation_bytes"]:
                over.append("generation_receipt_reserve_bytes")
            if generation["inode_count"] + generation_receipt_reserve_inodes > self.ceilings["maximum_generation_inodes"]:
                over.append("generation_receipt_reserve_inodes")
            job_monitor_report_count_before = self.progress["job_monitor_report_counts"].get(
                self.job_dir.name, 0,
            )
            job_reports_remaining = max(0, 2 - job_monitor_report_count_before)
            job_monitor_receipt_reserve_bytes = job_reports_remaining * self.maximum_report_bytes
            if job_output["bytes_used"] + job_monitor_receipt_reserve_bytes > self.ceilings["maximum_job_output_bytes"]:
                over.append("job_output_receipt_reserve_bytes")
            if job_output["inode_count"] + job_reports_remaining > self.ceilings["maximum_job_output_inodes"]:
                over.append("job_output_receipt_reserve_inodes")
            if tmpdir_bytes > self.ceilings["maximum_tmpdir_bytes"]:
                over.append("tmpdir_bytes")
            if tmpdir_inodes > self.ceilings["maximum_tmpdir_inodes"]:
                over.append("tmpdir_inodes")
            if any(size is not None and size > self.ceilings["maximum_trace_file_bytes"]
                   for size in traces.values()):
                over.append("trace_member_bytes")
            sample = {
                "monotonic_ns": now,
                "job_output_bytes": job_output["bytes_used"],
                "job_output_inodes": job_output["inode_count"],
                "generation_bytes": generation["bytes_used"],
                "generation_inodes": generation["inode_count"],
                "tmpdir_bytes": tmpdir_bytes, "tmpdir_inodes": tmpdir_inodes,
                "tmpdir_by_device": {
                    str(device): dict(usage) for device, usage in sorted(tmpdir_by_device.items())
                },
                "monitor_report_count_before": monitor_report_count_before,
                "job_monitor_report_count_before": job_monitor_report_count_before,
                "generation_receipt_reserve_bytes": generation_receipt_reserve_bytes,
                "generation_receipt_reserve_inodes": generation_receipt_reserve_inodes,
                "job_monitor_receipt_reserve_bytes": job_monitor_receipt_reserve_bytes,
                "trace_files": traces, "filesystems": filesystems,
            }
            self.samples.append(sample)
            self.last_sample_ns = now
            for field in self.high_water:
                self.high_water[field] = max(self.high_water[field], sample[field])
            self.progress["high_water"] = {
                field: max(self.progress["high_water"][field], sample[field])
                for field in self.high_water
            }
            if over:
                self.stop_reason = ",".join(sorted(set(over)))
                return True
            return False
        except BaseException as error:
            self.stop_reason = "monitor_error"
            self.monitor_error = f"{type(error).__name__}: {error}"[:1024]
            return True

    def preflight(self) -> None:
        require(bool(self.role), "bounded resource monitor role was not selected")
        require(not self._sample(force=True),
                "preparation resource budget failed before child launch")

    def __call__(self) -> bool:
        return self._sample()

    def finish(self) -> dict[str, Any]:
        if self.stop_reason is None:
            self._sample(force=True)
        self.ended_monotonic_ns = time.monotonic_ns()
        return {
            "schema": PREPARATION_RESOURCE_MONITOR_SCHEMA,
            "role": self.role,
            "resource_budget": self.budget["pin"],
            "fixed_pair_sha256": self.fixed_sha256,
            "sample_interval_milliseconds": self.ceilings["monitor_sample_interval_milliseconds"],
            "roots": {
                **self.root_pins,
            },
            "started_monotonic_ns": self.started_monotonic_ns,
            "ended_monotonic_ns": self.ended_monotonic_ns,
            "sample_count": len(self.samples),
            "high_water": dict(self.high_water),
            "stop_reason": self.stop_reason, "monitor_error": self.monitor_error,
            "samples": list(self.samples),
        }

    def close(self) -> None:
        for descriptor in (self.trace_fd, self.job_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self.trace_fd = -1
        self.job_fd = -1


def _fixed_directory_usage(
    fixed: types.ModuleType, root: dict[str, Any], inode_ceiling: int, *, live: bool,
) -> dict[str, int]:
    require(type(inode_ceiling) is int and inode_ceiling >= 0,
            "bounded directory inode ceiling is malformed")
    # The pinned FixedPair walker counts descendants only.  Its separate
    # directory root is inode one in this preparation contract.
    scan_inode_limit = max(0, inode_ceiling - 1)
    scan_byte_limit = U64_MAX
    usage = fixed._tmpdir_usage_snapshot(
        Path(root["path"]), scan_byte_limit, scan_inode_limit,
        (root["device"], root["inode"]), allow_descendant_enoent=live,
    )
    return {"bytes_used": usage["bytes_used"], "inode_count": usage["inode_count"] + 1}


def _check_bounded_preparation_final_usage(
    context: dict[str, Any], budget: dict[str, Any],
    stage_dir: Path, progress: dict[str, Any], jobs: list[dict[str, Any]],
    *, receipt_reserve_bytes: int | None = None,
    receipt_reserve_inodes: int | None = None,
) -> dict[str, Any]:
    """Strictly re-account the quiescent generation and every original TMPDIR."""
    fixed = context["stack"]["fixed_pair"]
    offline_copy = context.get("offline_host_replay") is True
    ceilings = budget["ceilings"]
    if receipt_reserve_bytes is None:
        receipt_reserve_bytes = ceilings["durable_receipt_reserve_bytes"]
    if receipt_reserve_inodes is None:
        receipt_reserve_inodes = ceilings["durable_receipt_reserve_inodes"]
    uint(receipt_reserve_bytes, "bounded final receipt byte reserve")
    uint(receipt_reserve_inodes, "bounded final receipt inode reserve")
    require(progress["monitor_report_count"] == 2 * len(jobs) and
            len(progress["tmpdir_roots"]) == len(jobs) and
            len(progress["job_roots"]) == len(jobs),
            "bounded preparation lacks one probe/application monitor and TMPDIR per original job")
    def local_walk_root(origin_pin: dict[str, Any], label: str) -> dict[str, Any]:
        if not offline_copy:
            return origin_pin
        local_identity = context.get("_verified_local_roots", {}).get(
            origin_pin["path"],
        )
        if local_identity is None:
            local_identity = _bounded_root_identity(
                fixed, Path(origin_pin["path"]), label,
            )
            fingerprint = context.get("offline_local_fingerprints", {}).get(
                origin_pin["path"],
            )
            require(type(fingerprint) is dict and
                    fingerprint.get("kind") == "directory" and
                    fingerprint.get("device") == local_identity["device"] and
                    fingerprint.get("inode") == local_identity["inode"] and
                    fingerprint.get("mode") == 0o700 and
                    fingerprint.get("uid") == os.getuid(),
                    f"{label} local-copy fingerprint changed after offline preflight")
        return local_identity

    generation_walk_root = local_walk_root(progress["stage_root"],
                                           "bounded final generation root")
    generation = _fixed_directory_usage(
        fixed, generation_walk_root, ceilings["maximum_generation_inodes"], live=False,
    )
    require(generation["bytes_used"] + receipt_reserve_bytes <=
            ceilings["maximum_generation_bytes"] and
            generation["inode_count"] + receipt_reserve_inodes <=
            ceilings["maximum_generation_inodes"],
            "bounded preparation generation cannot retain its frozen terminal receipt reserve")
    job_usage: dict[str, dict[str, int]] = {}
    for job in jobs:
        root = progress["job_roots"][job["run_id"]]
        walk_root = local_walk_root(root, "bounded final job output root")
        usage = _fixed_directory_usage(
            fixed, walk_root, ceilings["maximum_job_output_inodes"], live=False,
        )
        require(usage["bytes_used"] <= ceilings["maximum_job_output_bytes"] and
                usage["inode_count"] <= ceilings["maximum_job_output_inodes"],
                f"bounded preparation job {job['run_id']} exceeds its frozen byte/inode ceiling")
        job_usage[job["run_id"]] = usage
        trace_root = progress["trace_roots"][job["run_id"]]
        trace_walk_root = local_walk_root(trace_root, "bounded final trace root")
        trace_fd = fixed._open_tmpdir_absolute_directory(Path(trace_root["path"]))
        try:
            for name in PreparationResourceMonitor.TRACE_NAMES:
                info = os.stat(name, dir_fd=trace_fd, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                        info.st_dev == trace_walk_root["device"] and info.st_nlink == 1 and
                        0 <= info.st_size <= ceilings["maximum_trace_file_bytes"],
                        f"bounded final trace member {name} violates its frozen type/link/size bound")
        finally:
            os.close(trace_fd)
    tmpdir_bytes = 0
    tmpdir_inodes = 0
    tmpdir_by_device: dict[int, dict[str, int]] = {}
    for root in progress["tmpdir_roots"]:
        remaining_inodes = max(0, ceilings["maximum_tmpdir_inodes"] - tmpdir_inodes)
        walk_root = local_walk_root(root, "bounded final TMPDIR root")
        usage = _fixed_directory_usage(fixed, walk_root, remaining_inodes, live=False)
        tmpdir_bytes += usage["bytes_used"]
        tmpdir_inodes += usage["inode_count"]
        per_device = tmpdir_by_device.setdefault(root["device"], {"bytes": 0, "inodes": 0})
        per_device["bytes"] += usage["bytes_used"]
        per_device["inodes"] += usage["inode_count"]
    require(tmpdir_bytes <= ceilings["maximum_tmpdir_bytes"] and
            tmpdir_inodes <= ceilings["maximum_tmpdir_inodes"],
            "bounded preparation TMPDIR generation exceeds its frozen byte/inode ceilings")
    if not offline_copy:
        generation_device = progress["stage_root"]["device"]
        roots_by_device: dict[int, dict[str, Any]] = {generation_device: progress["stage_root"]}
        for root in progress["tmpdir_roots"]:
            roots_by_device.setdefault(root["device"], root)
        for device, root_pin in roots_by_device.items():
            vfs = _bounded_statvfs(fixed, root_pin, "bounded final storage filesystem root")
            available_bytes = vfs.f_bavail * vfs.f_frsize
            available_inodes = vfs.f_favail
            generation_remaining = (max(0, ceilings["maximum_generation_bytes"] - generation["bytes_used"])
                                   if device == generation_device else 0)
            generation_inode_remaining = (max(0, ceilings["maximum_generation_inodes"] - generation["inode_count"])
                                          if device == generation_device else 0)
            tmp_usage = tmpdir_by_device.get(device, {"bytes": 0, "inodes": 0})
            tmp_remaining = (max(0, ceilings["maximum_tmpdir_bytes"] - tmp_usage["bytes"])
                             if device in tmpdir_by_device else 0)
            tmp_inode_remaining = (max(0, ceilings["maximum_tmpdir_inodes"] - tmp_usage["inodes"])
                                   if device in tmpdir_by_device else 0)
            require(available_bytes >= ceilings["minimum_free_bytes"] + generation_remaining + tmp_remaining and
                    available_inodes >= ceilings["minimum_free_inodes"] + generation_inode_remaining + tmp_inode_remaining,
                    "bounded preparation final filesystem reserve fell below its caller-frozen floor")
    return {
        "generation": generation, "jobs": job_usage,
        "tmpdir_bytes": tmpdir_bytes, "tmpdir_inodes": tmpdir_inodes,
        "tmpdir_by_device": {
            str(device): dict(usage) for device, usage in sorted(tmpdir_by_device.items())
        },
        "tmpdir_roots": [dict(item) for item in progress["tmpdir_roots"]],
        "monitor_high_water": dict(progress["high_water"]),
        "monitor_report_count": progress["monitor_report_count"],
    }


def _seal_preparation_resource_monitor(
    monitor: PreparationResourceMonitor, job_dir: Path, role: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    require(monitor.role in ("policy_probe", "application") and
            monitor.role not in monitor.sealed_roles and
            role == ("policy-probe" if monitor.role == "policy_probe" else "application"),
            "preparation monitor report role was already sealed or changed")
    report = monitor.finish()
    raw = canonical_bytes(report)
    require(len(raw) <= MAX_METADATA_BYTES,
            "preparation resource monitor report exceeds its frozen metadata cap")
    path = job_dir / f"{role}.resource-monitor.json"
    digest_value = _write_exclusive(path, raw)
    monitor.sealed_roles.add(monitor.role)
    monitor.progress["monitor_report_count"] += 1
    counts = monitor.progress["job_monitor_report_counts"]
    counts[job_dir.name] = counts.get(job_dir.name, 0) + 1
    return report, {"path": str(path), "sha256": digest_value}


def run_capacity_stage(
    plan_pin: dict[str, Any], spec_pin: dict[str, Any], source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: dict[str, Any],
    output_root: Path,
) -> dict[str, Any]:
    """Execute 15 bounded capacity contexts and publish one sealed completion."""
    global _PENDING_SIGNAL
    _PENDING_SIGNAL = None
    context = _prepare_pins(plan_pin, spec_pin, source_root, input_root, host_id, observed_host_pin)
    jobs = derive_capacity_jobs(context["plan"], context["host_id"])
    return _run_capacity_schedule(
        context, jobs, context["plan"]["capacity_process_templates_sha256"], output_root,
        preparation=False,
    )


def run_capacity_preparation(
    preparation_pin: dict[str, Any], source_root: Path, input_root: Path,
    host_id: str, observed_host_pin: dict[str, Any], output_root: Path,
) -> dict[str, Any]:
    """Run the intent-pinned 15 APP capacity contexts before SpecV3/PlanV3."""
    global _PENDING_SIGNAL
    _PENDING_SIGNAL = None
    context, jobs, schedule_sha = _prepare_capacity_preparation_pins(
        preparation_pin, source_root, input_root, host_id, observed_host_pin,
    )
    return _run_capacity_schedule(context, jobs, schedule_sha, output_root, preparation=True)


def run_capacity_preparation_bounded(
    preparation_pin: dict[str, Any], resource_budget_pin: dict[str, Any],
    source_root: Path, input_root: Path, host_id: str,
    observed_host_pin: dict[str, Any], output_root: Path,
) -> dict[str, Any]:
    """Run the original 15 contexts under a separate caller-frozen live budget."""
    global _PENDING_SIGNAL
    _PENDING_SIGNAL = None
    reader_pin, expected_preparation_semantic_sha256 = (
        _bounded_preparation_reader_pin(preparation_pin)
    )
    context, jobs, schedule_sha = _prepare_capacity_preparation_pins(
        reader_pin, source_root, input_root, host_id, observed_host_pin,
        expected_preparation_semantic_sha256=expected_preparation_semantic_sha256,
    )
    budget = _prepare_capacity_resource_budget_context(
        context, resource_budget_pin, monitor_report_count=2 * len(jobs),
    )
    require(len(jobs) == 15 and schedule_sha == budget["normalized"]["capacity_preparation_templates_sha256"],
            "bounded preparation budget does not bind the exact original 15-template schedule")
    context["resource_budget"] = budget
    return _run_capacity_schedule(
        context, jobs, schedule_sha, output_root, preparation=True,
        resource_budget=budget,
    )


def _run_capacity_schedule(
    context: dict[str, Any], jobs: list[dict[str, Any]], jobs_sha: str,
    output_root: Path, *, preparation: bool,
    resource_budget: dict[str, Any] | None = None,
) -> dict[str, Any]:
    global _PENDING_SIGNAL
    _PENDING_SIGNAL = None
    bounded_preparation = preparation and resource_budget is not None
    require(resource_budget is None or preparation,
            "live preparation resource budget cannot be applied to an archived SpecV3 stage")
    context["preparation_mode"] = preparation
    output_root = _safe_root(output_root, "capacity stage output root")
    if preparation:
        output_info = output_root.stat(follow_symlinks=False)
        require(stat.S_IMODE(output_info.st_mode) == 0o700 and output_info.st_uid == os.getuid(),
                "capacity preparation output root must be an owned mode-0700 directory")
        require(_is_within(context["input_root"], output_root),
                "capacity preparation output root must remain under the pinned private input root for exact evidence registration")
    require(not _is_within(context["source_root"], output_root),
            "capacity stage output must be outside SourceV5")
    campaign_root = output_root / context["spec"]["campaign_id"]
    _mkdir_components(campaign_root)
    _check_new_directory(campaign_root, "capacity campaign output directory")
    capacity_root = campaign_root / ("capacity-preparation" if preparation else "capacity")
    _mkdir_components(capacity_root)
    _check_new_directory(capacity_root, "capacity preparation parent directory" if preparation else "capacity stage parent directory")
    stage_dir = capacity_root / context["host_id"]
    _mkdir_private(stage_dir)
    _check_new_directory(stage_dir, "capacity preparation directory" if preparation else "capacity stage directory")
    jobs_dir = stage_dir / "jobs"
    _mkdir_private(jobs_dir)
    if bounded_preparation:
        ledger_path = stage_dir / "capacity-preparation-bounded-ledger.jsonl"
    else:
        ledger_path = stage_dir / ("capacity-preparation-ledger.jsonl" if preparation else "controller-ledger.jsonl")
    ledger = PreparationLedger(
        ledger_path, context, jobs_sha,
        resource_budget["pin"] if bounded_preparation else None,
    ) if preparation else Ledger(ledger_path, context, jobs_sha)
    previous_handlers = _install_signal_handlers()
    if bounded_preparation:
        completion_path = stage_dir / "capacity-preparation-bounded-completion.json"
    else:
        completion_path = stage_dir / ("capacity-preparation-completion.json" if preparation else "capacity-stage-completion.json")
    completed_entries: list[dict[str, Any]] = []
    active_job: dict[str, Any] | None = None
    resource_monitors: list[PreparationResourceMonitor] = []
    resource_progress = {
        "expected_monitor_report_count": 2 * len(jobs),
        "tmpdir_roots": [],
        "job_roots": {},
        "trace_roots": {},
        "monitor_report_count": 0,
        "job_monitor_report_counts": {},
        "high_water": {key: 0 for key in (
            "job_output_bytes", "job_output_inodes", "generation_bytes",
            "generation_inodes", "tmpdir_bytes", "tmpdir_inodes",
        )},
    }
    if bounded_preparation:
        resource_progress["stage_root"] = _bounded_root_identity(
            context["stack"]["fixed_pair"], stage_dir, "bounded generation root",
        )
    try:
        for job in jobs:
            active_job = job
            job_dir = _prepare_job_dir(stage_dir, job)
            if bounded_preparation:
                resource_progress["job_roots"][job["run_id"]] = _bounded_root_identity(
                    context["stack"]["fixed_pair"], job_dir, "bounded job output root",
                )
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
                if bounded_preparation:
                    tmpdir, storage_snapshot = _storage_tmpdir_bounded(
                        context_template["storage"], context["source_root"], job_dir,
                        job["run_id"], output_root,
                    )
                else:
                    tmpdir, storage_snapshot = _storage_tmpdir(
                        context_template["storage"], context["source_root"], job_dir,
                        job["run_id"],
                    )
            else:
                if bounded_preparation:
                    tmpdir, storage_snapshot = _storage_tmpdir_bounded(
                        None, context["source_root"], job_dir, job["run_id"],
                        output_root,
                    )
                else:
                    tmpdir, storage_snapshot = _storage_tmpdir(
                        None, context["source_root"], job_dir, job["run_id"],
                    )
            resource_monitor: PreparationResourceMonitor | None = None
            if bounded_preparation:
                _check_new_directory(trace_dir, "bounded capacity preparation trace directory")
                trace_root_identity = _bounded_root_identity(
                    context["stack"]["fixed_pair"], trace_dir, "bounded trace root",
                )
                resource_progress["trace_roots"][job["run_id"]] = trace_root_identity
                require(not _is_within(stage_dir, tmpdir) and not _is_within(tmpdir, stage_dir),
                        "bounded TMPDIR must be disjoint from the output generation tree")
                tmpdir_root = _bounded_root_identity(
                    context["stack"]["fixed_pair"], tmpdir, "bounded TMPDIR root",
                )
                resource_progress["tmpdir_roots"].append(tmpdir_root)
                resource_monitor = PreparationResourceMonitor(
                    context, resource_budget, stage_dir, job_dir, trace_dir,
                    resource_progress["tmpdir_roots"], resource_progress,
                    resource_progress["stage_root"],
                    resource_progress["job_roots"][job["run_id"]],
                    trace_root_identity,
                )
                resource_monitors.append(resource_monitor)
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
            probe_deadline_seconds = min(context["spec"]["deadlines"]["setup_seconds"], 120)
            if bounded_preparation:
                probe_deadline_seconds = min(
                    probe_deadline_seconds,
                    resource_budget["ceilings"]["process_deadline_seconds"],
                )
            probe_dispatch = {
                **common, "argv": probe_argv, "cwd": str(job_dir), "environment": probe_env,
                "expected_binary_sha256": binary_sha,
                "deadline_seconds": probe_deadline_seconds,
                "stdout_path": str(probe_stdout), "stderr_path": str(probe_stderr),
            }
            if resource_monitor is not None:
                probe_dispatch["resource_roots"] = resource_monitor.root_pins
            ledger.append("probe_dispatch", job, probe_dispatch)
            if resource_monitor is not None:
                resource_monitor.begin("policy_probe")
                resource_monitor.preflight()
            if preparation:
                child = _spawn_with_source5_owner(
                    context, probe_argv, job_dir, probe_env, probe_stdout, probe_stderr,
                    probe_dispatch["deadline_seconds"], binary, binary_sha,
                    job_dir / "policy-probe.process-capture.json",
                    job_dir / "policy-probe.process-start.json",
                    resource_monitor=resource_monitor,
                    owner_return_path=(job_dir / "policy-probe.owner-return.json"
                                       if bounded_preparation else None),
                )
            else:
                child = _spawn_bounded(
                    probe_argv, job_dir, probe_env, probe_stdout, probe_stderr,
                    probe_dispatch["deadline_seconds"], binary, binary_sha,
                    capture_identity=False,
                )
            probe_completed = {
                **common,
                **{key: value for key, value in child.items() if key != "direct_process"},
                "stderr_empty": child["stderr_size"] == 0,
            }
            probe_monitor_report: dict[str, Any] | None = None
            probe_monitor_pin: dict[str, str] | None = None
            if resource_monitor is not None:
                probe_monitor_report, probe_monitor_pin = _seal_preparation_resource_monitor(
                    resource_monitor, job_dir, "policy-probe",
                )
                probe_completed["resource_monitor"] = probe_monitor_pin
            probe_completed["process_identity"] = None
            if preparation:
                direct_process_fields = {
                    "capture", "start", "runner_sha256", "identity_helper_sha256",
                }
                if bounded_preparation:
                    direct_process_fields.add("owner_return")
                direct_process = exact(child.get("direct_process"),
                                       direct_process_fields,
                                       "Source5 policy-probe owner receipt")
                probe_completed["process_identity"] = None
                probe_completed.update({
                    "direct_process_start": direct_process["start"],
                    "direct_process_capture": direct_process["capture"],
                    "direct_process_runner_sha256": direct_process["runner_sha256"],
                    "process_identity_helper_sha256": direct_process["identity_helper_sha256"],
                })
                if bounded_preparation:
                    probe_completed["direct_process_owner_return"] = direct_process[
                        "owner_return"
                    ]
            ledger.append("probe_completed", job, probe_completed)
            require(child["status"] == "completed" and child["return_code"] == 0 and
                    child["stderr_size"] == 0 and
                    (probe_monitor_report is None or probe_monitor_report["stop_reason"] is None),
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
            environment = _application_environment(
                identity, trace_dir, tmpdir, source5_preparation=preparation,
            )
            process_deadline_seconds = (
                min(context["spec"]["deadlines"]["process_seconds"],
                    resource_budget["ceilings"]["process_deadline_seconds"])
                if bounded_preparation else context["spec"]["deadlines"]["process_seconds"]
            )
            application_dispatch = {
                **common, "argv": argv, "cwd": str(job_dir), "environment": environment,
                "trace_directory": str(trace_dir), "tmpdir_path": str(tmpdir),
                "expected_binary_sha256": binary_sha,
                "process_deadline_seconds": process_deadline_seconds,
                "mode": "capacity", "capacity_horizon_seconds": 30,
                "external_pressure": False, "pressure_qualification": False,
                "storage_context": storage_snapshot, "network_context": network_snapshot,
                "probe": probe_pin, "policy_sha256": sha256_bytes(canonical_bytes(seed["policy"])),
            }
            if resource_monitor is not None:
                application_dispatch["resource_roots"] = resource_monitor.root_pins
            ledger.append("application_dispatch", job, application_dispatch)
            if resource_monitor is not None:
                resource_monitor.begin("application")
                resource_monitor.preflight()
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
                if preparation:
                    details.update({
                        "direct_process_start": _event_pin(
                            job_dir / "application.process-start.json",
                            sha256_bytes(canonical_bytes(app_identity)),
                        ),
                        "direct_process_runner_sha256": context["stack"]["fixed_pair_sha256"],
                        "process_identity_helper_sha256": context["stack"]["process_identity_helper_sha256"],
                    })
                ledger.append("application_bound", job, details)
                observed_binding["details"] = details

            if preparation:
                app_child = _spawn_with_source5_owner(
                    context, argv, job_dir, environment, app_stdout, app_stderr,
                    process_deadline_seconds, binary, binary_sha,
                    job_dir / "application.process-capture.json",
                    job_dir / "application.process-start.json",
                    on_bound=bind_application,
                    resource_monitor=resource_monitor,
                    owner_return_path=(job_dir / "application.owner-return.json"
                                       if bounded_preparation else None),
                )
            else:
                app_child = _spawn_bounded(
                    argv, job_dir, environment, app_stdout, app_stderr,
                    process_deadline_seconds, binary, binary_sha,
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
                "process_seconds": process_deadline_seconds,
            }
            app_monitor_report: dict[str, Any] | None = None
            app_monitor_pin: dict[str, str] | None = None
            if resource_monitor is not None:
                app_monitor_report, app_monitor_pin = _seal_preparation_resource_monitor(
                    resource_monitor, job_dir, "application",
                )
                app_exited["resource_monitor"] = app_monitor_pin
            if preparation:
                direct_process_fields = {
                    "capture", "start", "runner_sha256", "identity_helper_sha256",
                }
                if bounded_preparation:
                    direct_process_fields.add("owner_return")
                direct_process = exact(app_child.get("direct_process"),
                                       direct_process_fields,
                                       "Source5 application owner receipt")
                app_exited.update({
                    "direct_process_start": direct_process["start"],
                    "direct_process_capture": direct_process["capture"],
                    "direct_process_runner_sha256": direct_process["runner_sha256"],
                    "process_identity_helper_sha256": direct_process["identity_helper_sha256"],
                })
                if bounded_preparation:
                    app_exited["direct_process_owner_return"] = direct_process[
                        "owner_return"
                    ]
            ledger.append("application_exited", job, app_exited)
            if resource_monitor is not None:
                resource_monitor.close()
            require(app_child["status"] == "completed" and app_child["return_code"] == 0 and
                    app_child["stderr_size"] == 0 and
                    (app_monitor_report is None or app_monitor_report["stop_reason"] is None),
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
            completed_entry = {
                "ordinal": 1, "template_index": job["template_index"],
                "run_id": job["run_id"], "calibration_id": job["capacity_key"]["calibration_id"],
                "capacity_key": job["capacity_key"],
                "workload": job["capacity_key"]["workload"], "profile": job["capacity_key"]["profile"],
                "template_sha256": job["template_sha256"], "nonce": job["nonce"],
                "probe": probe_pin, "expectation": expectation_pin,
                "context": context_pin, "request": request_pin, "traces": trace_pins,
                "validation": validation_pin, "artifact": artifact_pin, "receipt": receipt_pin,
                "actual_pid": app_child["pid"], "actual_start_ticks": app_identity["start_ticks"],
                "actual_executable_sha256": app_identity["executable_sha256"],
                "actual_affinity": app_identity["cpu_affinity"], "actual_cwd": app_identity["cwd"],
                "actual_environment_sha256": sha256_bytes(canonical_bytes(environment)),
            }
            if bounded_preparation:
                require(probe_monitor_pin is not None and app_monitor_pin is not None,
                        "bounded preparation job omitted a durable monitor report")
                completed_entry["resource_monitors"] = {
                    "policy_probe": probe_monitor_pin,
                    "application": app_monitor_pin,
                }
            if not preparation:
                completed_entry.pop("capacity_key")
            completed_entries.append(completed_entry)
            active_job = None
        require(len(completed_entries) == 15, "capacity stage did not complete all 15 contexts")
        bounded_final_usage: dict[str, Any] | None = None
        if bounded_preparation:
            bounded_final_usage = _check_bounded_preparation_final_usage(
                context, resource_budget, stage_dir, resource_progress, jobs,
            )
            resource_progress["high_water"]["generation_bytes"] = max(
                resource_progress["high_water"]["generation_bytes"],
                bounded_final_usage["generation"]["bytes_used"],
            )
            resource_progress["high_water"]["generation_inodes"] = max(
                resource_progress["high_water"]["generation_inodes"],
                bounded_final_usage["generation"]["inode_count"],
            )
            resource_progress["high_water"]["job_output_bytes"] = max(
                resource_progress["high_water"]["job_output_bytes"],
                max(usage["bytes_used"] for usage in bounded_final_usage["jobs"].values()),
            )
            resource_progress["high_water"]["job_output_inodes"] = max(
                resource_progress["high_water"]["job_output_inodes"],
                max(usage["inode_count"] for usage in bounded_final_usage["jobs"].values()),
            )
            resource_progress["high_water"]["tmpdir_bytes"] = max(
                resource_progress["high_water"]["tmpdir_bytes"],
                bounded_final_usage["tmpdir_bytes"],
            )
            resource_progress["high_water"]["tmpdir_inodes"] = max(
                resource_progress["high_water"]["tmpdir_inodes"],
                bounded_final_usage["tmpdir_inodes"],
            )
            bounded_final_usage["monitor_high_water"] = dict(resource_progress["high_water"])
        if preparation:
            terminal = {
                "schema": (PREPARATION_BOUNDED_COMPLETION_SCHEMA if bounded_preparation
                           else PREPARATION_COMPLETION_SCHEMA),
                "completion_sha256": "0" * 64,
                "complete": True, "qualification_eligible": False,
                "campaign_id": context["spec"]["campaign_id"], "host_id": context["host_id"],
                "preparation": {
                    "path": str(context["preparation_path"]),
                    "raw_sha256": context["preparation_raw_sha256"],
                    "semantic_sha256": context["preparation_semantic_sha256"],
                },
                "source": {"path": str(context["source_path"]), "raw_sha256": context["source_raw_sha256"],
                           "semantic_sha256": context["source_semantic_sha256"],
                           "source_tree_sha256": context["source_tree_sha256"]},
                "observed_host": {"path": str(context["host_context_path"]),
                                  "raw_sha256": context["host_context_raw_sha256"],
                                  "boot_id_sha256": context["current_host"]["boot_id_sha256"],
                                  "cpu_affinity": context["current_host"]["cpu_affinity"],
                                  "network_namespace_inode": context["current_host"]["network_namespace_inode"]},
                "modules": {
                    "capacity_stage": {"path": STAGE_SOURCE_PATH, "sha256": context["stack"]["stage_sha256"]},
                    "source5_preparation_helper": {"path": PREPARATION_HELPER_PATH, "sha256": context["preparation_helper_sha256"]},
                    "campaign_controller": {"path": CONTROLLER_PATH, "sha256": context["stack"]["controller_sha256"]},
                    "campaign_inputs": {"path": INPUTS_PATH, "sha256": context["stack"]["inputs_sha256"]},
                    "feedback_reader": {"path": FEEDBACK_READER_PATH, "sha256": context["stack"]["feedback_reader_sha256"]},
                    "capacity_producer": {"path": CAPACITY_PRODUCER_PATH, "sha256": context["stack"]["capacity_producer_sha256"]},
                    "owned_process": {
                        "schema": PREPARATION_PROCESS_OWNER_SCHEMA,
                        "fixed_pair": {
                            "path": context["stack"]["fixed_pair_path"],
                            "sha256": context["stack"]["fixed_pair_sha256"],
                        },
                        "process_identity_helper": {
                            "path": context["stack"]["process_identity_helper_path"],
                            "sha256": context["stack"]["process_identity_helper_sha256"],
                        },
                    },
                },
                "capacity_preparation_templates_sha256": jobs_sha,
                "stage_directory": str(stage_dir),
                "ledger": {"path": str(ledger.path), "raw_sha256": None, "terminal_head": None},
                "entries": completed_entries,
            }
            if bounded_preparation:
                require(bounded_final_usage is not None,
                        "bounded preparation omitted its strict final storage inventory")
                terminal.update({
                    "resource_budget": resource_budget["pin"],
                    "resource_monitor": {
                        "schema": PREPARATION_RESOURCE_MONITOR_SCHEMA,
                        "fixed_pair_sha256": resource_budget["fixed_pair_sha256"],
                        "report_count": resource_progress["monitor_report_count"],
                        "high_water": dict(resource_progress["high_water"]),
                        "final_usage": bounded_final_usage,
                    },
                })
            terminal_details = {
                "completion_schema": (PREPARATION_BOUNDED_COMPLETION_SCHEMA if bounded_preparation
                                       else PREPARATION_COMPLETION_SCHEMA),
                "entry_count": len(completed_entries),
                "capacity_preparation_templates_sha256": jobs_sha,
                "preparation_raw_sha256": context["preparation_raw_sha256"],
                "preparation_semantic_sha256": context["preparation_semantic_sha256"],
                "qualification_eligible": False,
            }
            if bounded_preparation:
                terminal_details.update({
                    "resource_monitor_report_count": resource_progress["monitor_report_count"],
                    "resource_monitor_high_water": dict(resource_progress["high_water"]),
                })
            ledger.append("preparation_complete", None, terminal_details)
        else:
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
        if preparation:
            terminal_body = {key: value for key, value in terminal.items() if key != "completion_sha256"}
            terminal["completion_sha256"] = sha256_bytes(canonical_bytes(terminal_body))
        completion_raw_sha, _completion_raw = _atomic_json(completion_path, terminal)
        return {
            "completion": {"path": str(completion_path), "sha256": completion_raw_sha},
            "ledger": terminal["ledger"], "complete": True,
            "qualification_eligible": False, "entry_count": len(completed_entries),
            **({"completion_sha256": terminal["completion_sha256"]} if preparation else {"controller_chronology_proven": False}),
        }
    except BaseException as error:
        failure_monitor_pin: dict[str, str] | None = None
        if bounded_preparation and resource_monitors:
            current_monitor = resource_monitors[-1]
            if current_monitor.role and current_monitor.role not in current_monitor.sealed_roles:
                try:
                    monitor_role = ("policy-probe" if current_monitor.role == "policy_probe"
                                    else "application")
                    _failure_report, failure_monitor_pin = _seal_preparation_resource_monitor(
                        current_monitor, current_monitor.job_dir, monitor_role,
                    )
                except BaseException:
                    failure_monitor_pin = None
        try:
            if ledger.fd >= 0:
                failure_details = {
                    "error_type": type(error).__name__,
                    "error": str(error)[:2048],
                    "signal": _PENDING_SIGNAL,
                    "completed_entry_count": len(completed_entries),
                    "qualification_eligible": False,
                    "controller_chronology_proven": False,
                }
                if failure_monitor_pin is not None:
                    failure_details["resource_monitor_failure"] = failure_monitor_pin
                if isinstance(error, DirectOwnerPostReturnError):
                    failure_details["direct_owner_return_failure"] = {
                        "owner_return": error.owner_return_pin,
                        "failure": error.failure_pin,
                    }
                ledger.append("stage_failed", active_job, failure_details)
        except BaseException:
            pass
        ledger.close_failed()
        raise
    finally:
        for monitor in resource_monitors:
            monitor.close()
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


def _read_preparation_ledger(
    path: Path, expected_sha: str, expected_head: str,
    resource_budget_pin: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    raw, info = read_stable(path, "sealed capacity preparation ledger", MAX_LEDGER_BYTES)
    require(stat.S_IMODE(info.st_mode) == 0o400, "sealed capacity preparation ledger must have mode 0400")
    require(sha256_bytes(raw) == expected_sha, "capacity preparation ledger raw SHA differs")
    lines = raw.splitlines(keepends=True)
    require(lines and all(line.endswith(b"\n") and b"\r" not in line for line in lines),
            "capacity preparation ledger is not LF framed")
    require(len(lines) <= MAX_EVENT_RECORDS, "capacity preparation ledger has too many events")
    previous = "0" * 64
    previous_time = 0
    records: list[dict[str, Any]] = []
    fields = {
        "schema", "sequence", "event", "monotonic_ns", "boot_id_sha256", "campaign_id", "host_id",
        "preparation_raw_sha256", "preparation_semantic_sha256", "source_manifest_raw_sha256",
        "source_manifest_semantic_sha256", "source_tree_sha256", "capacity_schedule_sha256",
        "observed_host_raw_sha256", "run_id", "ordinal", "template_index", "calibration_id",
        "workload", "profile", "template_sha256", "details",
    }
    if resource_budget_pin is not None:
        fields.add("resource_budget")
    for sequence, line in enumerate(lines, 1):
        require(len(line) <= MAX_EVENT_LINE_BYTES, f"capacity preparation ledger line {sequence} exceeds its bound")
        envelope = parse_object(line, f"capacity preparation ledger line {sequence}", MAX_EVENT_LINE_BYTES, canonical=True)
        exact(envelope, {"previous_sha256", "record", "record_sha256"}, f"capacity preparation ledger envelope[{sequence}]")
        require(envelope["previous_sha256"] == previous, f"capacity preparation hash chain breaks at line {sequence}")
        record = exact(envelope["record"], fields, f"capacity preparation record[{sequence}]")
        expected = sha256_bytes(canonical_bytes({"previous_sha256": previous, "record": record}))
        require(envelope["record_sha256"] == expected, f"capacity preparation ledger record hash differs at line {sequence}")
        expected_schema = (PREPARATION_BOUNDED_EVENT_SCHEMA if resource_budget_pin is not None
                           else PREPARATION_EVENT_SCHEMA)
        require(record["schema"] == expected_schema and record["sequence"] == sequence,
                f"capacity preparation event schema/sequence differs at line {sequence}")
        if resource_budget_pin is not None:
            require(record["resource_budget"] == resource_budget_pin,
                    f"capacity preparation event budget pin differs at line {sequence}")
        require(record["event"] in JOB_EVENTS or record["event"] in ("stage_failed", "preparation_complete"),
                f"unknown capacity preparation event at line {sequence}")
        monotonic = uint(record["monotonic_ns"], "capacity preparation monotonic timestamp", positive=True)
        require(monotonic > previous_time, "capacity preparation event timestamps do not advance")
        previous_time = monotonic
        for name in ("boot_id_sha256", "preparation_raw_sha256", "preparation_semantic_sha256",
                     "source_manifest_raw_sha256", "source_manifest_semantic_sha256", "source_tree_sha256",
                     "capacity_schedule_sha256", "observed_host_raw_sha256"):
            digest(record[name], f"capacity preparation {name}")
        require(type(record["details"]) is dict, f"capacity preparation event details are malformed at line {sequence}")
        records.append(record)
        previous = expected
    require(previous == expected_head, "capacity preparation terminal ledger head differs")
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
    if context.get("preparation_mode") is True:
        require(record["preparation_raw_sha256"] == context["preparation_raw_sha256"] and
                record["preparation_semantic_sha256"] == context["preparation_semantic_sha256"] and
                record["source_manifest_raw_sha256"] == context["source_raw_sha256"] and
                record["source_manifest_semantic_sha256"] == context["source_semantic_sha256"] and
                record["source_tree_sha256"] == context["source_tree_sha256"] and
                record["capacity_schedule_sha256"] == context["plan"]["capacity_process_templates_sha256"] and
                record["observed_host_raw_sha256"] == context["host_context_raw_sha256"] and
                record["boot_id_sha256"] == context["current_host"]["boot_id_sha256"],
                f"capacity preparation event {record['event']} changed an intent/source/host hash role")
        if context.get("resource_budget_pin") is not None:
            require(record.get("resource_budget") == context["resource_budget_pin"],
                    f"bounded capacity preparation event {record['event']} changed the caller-frozen budget pin")
        return
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


def _verify_owned_process_start(
    context: dict[str, Any], job: dict[str, Any], stage_dir: Path,
    start_pin: object, argv: list[str], environment: dict[str, str],
    binary: Path, binary_sha: str, pid: object,
) -> dict[str, Any]:
    """Verify the durable R8 start callback without consulting current /proc."""
    value = exact(start_pin, {"path", "sha256"}, "owned-process start pin")
    job_dir = stage_dir / "jobs" / job["run_id"]
    expected_path = job_dir / (
        "policy-probe.process-start.json" if argv[1:2] == ["--emit-feedback-policy-only"]
        else "application.process-start.json"
    )
    path, raw, raw_sha = _read_evidence_pin(
        value, "owned-process start proof", MAX_METADATA_BYTES, stage_dir,
    )
    info = path.stat(follow_symlinks=False)
    require(path == expected_path and stat.S_IMODE(info.st_mode) == 0o600 and
            info.st_uid == os.getuid(),
            "owned-process start proof is not the expected private per-job sidecar")
    proof = parse_object(raw, "owned-process start proof", MAX_METADATA_BYTES, canonical=True)
    if argv[1:2] == ["--emit-feedback-policy-only"]:
        proof = exact(proof, {
            "schema", "role", "runner_sha256", "identity_helper_sha256", "dispatch", "start",
        }, "Source5 policy-probe start sidecar")
        dispatch = _owned_process_requested_dispatch(
            argv, job_dir, environment, binary, binary_sha,
            context["current_host"]["cpu_affinity"],
            context["current_host"]["network_namespace_inode"],
        )
        start = exact(proof["start"], {
            "pid", "start_ticks", "requested_argv", "requested_argv_sha256",
            "environment_sha256",
        }, "Source5 policy-probe minimal PID/start proof")
        require(proof["schema"] == OWNED_POLICY_PROBE_START_SCHEMA and
                proof["role"] == "source5_policy_probe" and
                proof["runner_sha256"] == context["stack"]["fixed_pair_sha256"] and
                proof["identity_helper_sha256"] == context["stack"]["process_identity_helper_sha256"] and
                proof["dispatch"] == dispatch and
                type(start["pid"]) is int and start["pid"] > 0 and
                uint(start["pid"], "policy-probe PID", positive=True, maximum=(1 << 31) - 1) == pid and
                type(start["start_ticks"]) is int and start["start_ticks"] > 0 and
                start["requested_argv"] == argv and
                start["requested_argv_sha256"] == dispatch["argv_sha256"] and
                start["environment_sha256"] == dispatch["environment_sha256"],
                "Source5 policy-probe minimal start proof differs from its exact requested dispatch")
        require(raw_sha == value["sha256"], "owned-process start proof raw digest changed")
        return start
    exact(proof, {
        "schema", "role", "pid", "start_ticks", "executable_path", "executable_sha256",
        "executable_device", "executable_inode", "executable_size", "requested_argv",
        "requested_argv_sha256", "executed_argv", "executed_argv_sha256", "environment",
        "environment_sha256", "cwd", "tmpdir", "cpu_affinity", "network_namespace_inode",
        "identity_sha256",
    }, "owned-process start proof")
    unsigned = {key: item for key, item in proof.items() if key != "identity_sha256"}
    expected_affinity = context["current_host"]["cpu_affinity"]
    expected_network = context["current_host"]["network_namespace_inode"]
    require(proof["schema"] == context["stack"]["fixed_pair"].APP_STARTED_SCHEMA and
            proof["role"] == "fixed_application_member" and
            digest(proof["identity_sha256"], "owned-process start identity digest") ==
            sha256_bytes(canonical_bytes(unsigned)) and
            uint(proof["pid"], "owned-process PID", positive=True, maximum=(1 << 31) - 1) == pid and
            uint(proof["start_ticks"], "owned-process start ticks", positive=True) > 0 and
            proof["executable_path"] == str(binary) and
            proof["executable_sha256"] == binary_sha and
            proof["requested_argv"] == argv and proof["executed_argv"] == argv and
            proof["requested_argv_sha256"] == sha256_bytes(canonical_bytes(argv)) and
            proof["executed_argv_sha256"] == sha256_bytes(canonical_bytes(argv)) and
            proof["environment"] == environment and
            proof["environment_sha256"] == sha256_bytes(canonical_bytes(environment)) and
            proof["cwd"] == str(job_dir) and proof["tmpdir"] == environment["TMPDIR"] and
            proof["cpu_affinity"] == expected_affinity and
            proof["network_namespace_inode"] == expected_network,
            "owned-process start identity differs from the exact APP/probe dispatch")
    uint(proof["executable_device"], "owned-process executable device")
    uint(proof["executable_inode"], "owned-process executable inode", positive=True)
    uint(proof["executable_size"], "owned-process executable size", positive=True)
    require(raw_sha == value["sha256"], "owned-process start proof raw digest changed")
    return proof


def _verify_owned_process_supervision(
    supervision_value: object, start: dict[str, Any], fixed: Any,
) -> None:
    supervision = exact(supervision_value, {
        "leader_info", "child_return_code", "timed_out", "artifact_budget_exceeded",
        "received_signal", "term_grace_seconds", "kill_reap_seconds", "signals",
        "leader_unreaped_during_group_signals", "group_signal_after_leader_reap_count",
        "leader_reaped", "remaining_session_members", "cleanup_errors", "cleanup_status",
    }, "owned-process supervision")
    require(type(supervision["term_grace_seconds"]) is float and
            supervision["term_grace_seconds"] == fixed.TERM_GRACE_SECONDS and
            type(supervision["kill_reap_seconds"]) is float and
            supervision["kill_reap_seconds"] == fixed.KILL_REAP_SECONDS,
            "owned-process grace/reap deadlines differ from the captured FixedR8 constants")
    require(type(supervision["child_return_code"]) is int and
            supervision["child_return_code"] == 0 and
            type(supervision["timed_out"]) is bool and supervision["timed_out"] is False and
            type(supervision["artifact_budget_exceeded"]) is bool and
            supervision["artifact_budget_exceeded"] is False and
            supervision["received_signal"] is None and
            type(supervision["cleanup_status"]) is str and
            supervision["cleanup_status"] == "verified" and
            type(supervision["leader_reaped"]) is bool and supervision["leader_reaped"] is True and
            type(supervision["leader_unreaped_during_group_signals"]) is bool and
            supervision["leader_unreaped_during_group_signals"] is True and
            type(supervision["group_signal_after_leader_reap_count"]) is int and
            supervision["group_signal_after_leader_reap_count"] == 0 and
            type(supervision["remaining_session_members"]) is list and
            supervision["remaining_session_members"] == [] and
            type(supervision["cleanup_errors"]) is list and supervision["cleanup_errors"] == [],
            "owned-process completion does not prove the successful bounded cleanup result")
    leader_info = exact(supervision["leader_info"], {"si_code", "si_status", "si_pid"},
                        "owned-process waitid completion")
    require(type(leader_info["si_code"]) is int and
            leader_info["si_code"] == getattr(os, "CLD_EXITED", 1) and
            type(leader_info["si_status"]) is int and leader_info["si_status"] == 0 and
            type(leader_info["si_pid"]) is int and leader_info["si_pid"] == start["pid"],
            "owned-process waitid record is not the successful exit of the captured leader")

    signals = supervision["signals"]
    require(type(signals) is list and len(signals) <= MAX_OWNED_PROCESS_SIGNAL_RECORDS,
            "owned-process signal transcript exceeds its finite schema bound")
    allowed_signals = {int(signal.SIGTERM), int(signal.SIGKILL)}
    for signal_record_value in signals:
        record = exact(signal_record_value, {
            "group_signal", "group_error", "pidfd_signals", "scan_error", "members",
        }, "owned-process signal record")
        group_signal = exact(record["group_signal"], {
            "signal", "leader_pid", "leader_start_ticks", "leader_unreaped",
        }, "owned-process group-signal identity")
        require(type(group_signal["signal"]) is int and group_signal["signal"] in allowed_signals and
                type(group_signal["leader_pid"]) is int and group_signal["leader_pid"] == start["pid"] and
                type(group_signal["leader_start_ticks"]) is int and
                group_signal["leader_start_ticks"] == start["start_ticks"] and
                type(group_signal["leader_unreaped"]) is bool and
                group_signal["leader_unreaped"] is True,
                "owned-process group signal is not an R8 TERM/KILL against its unreaped original leader")
        for field in ("group_error", "scan_error"):
            error_value = record[field]
            if error_value is not None:
                require(type(error_value) is str and 0 < len(error_value) <= MAX_METADATA_BYTES and
                        "\x00" not in error_value,
                        f"owned-process {field} does not match its bounded captured error schema")
                require(re.match(
                    r"^(?:pid [1-9][0-9]*: )?[A-Za-z_][A-Za-z0-9_]*: ", error_value,
                ) is not None,
                    f"owned-process {field} lacks the captured exception-name/message shape")

        members_value = record["members"]
        member_by_pid: dict[int, dict[str, Any]] = {}
        if members_value is None:
            require(type(record["scan_error"]) is str and not record["pidfd_signals"],
                    "owned-process null member inventory lacks the captured scan error")
        else:
            require(type(members_value) is list and len(members_value) <= fixed.MAX_PROC_ENTRIES,
                    "owned-process member inventory exceeds the captured /proc bound")
            for member_value in members_value:
                member = exact(member_value, {
                    "pid", "state", "parent_pid", "process_group", "session_id", "start_ticks",
                }, "owned-process session member")
                pid = uint(member["pid"], "owned session member PID", positive=True, maximum=(1 << 31) - 1)
                require(pid not in member_by_pid and type(member["state"]) is str and
                        len(member["state"]) == 1 and member["state"] in "RSDZTtXxKWPI",
                        "owned-process session member PID/state is repeated or malformed")
                uint(member["parent_pid"], "owned session member parent PID", maximum=(1 << 31) - 1)
                uint(member["process_group"], "owned session member process group", positive=True,
                     maximum=(1 << 31) - 1)
                require(uint(member["session_id"], "owned session member session", positive=True,
                             maximum=(1 << 31) - 1) == start["pid"],
                        "owned-process member escaped its captured session")
                uint(member["start_ticks"], "owned session member start ticks", positive=True)
                member_by_pid[pid] = member
            leader = member_by_pid.get(start["pid"])
            require(leader is not None and leader["start_ticks"] == start["start_ticks"] and
                    leader["process_group"] == start["pid"] and leader["session_id"] == start["pid"],
                    "owned-process member inventory omitted or changed the unreaped original leader")

        pidfd_signals = record["pidfd_signals"]
        require(type(pidfd_signals) is list and
                len(pidfd_signals) <= (0 if members_value is None else len(members_value)),
                "owned-process pidfd signal list exceeds its captured member set")
        pidfd_pids: set[int] = set()
        for pidfd_value in pidfd_signals:
            pidfd_record = exact(pidfd_value, {"pid", "start_ticks", "signal", "sent"},
                                 "owned-process pidfd signal")
            pid = uint(pidfd_record["pid"], "owned pidfd PID", positive=True, maximum=(1 << 31) - 1)
            start_ticks = uint(pidfd_record["start_ticks"], "owned pidfd start ticks", positive=True)
            require(pid not in pidfd_pids and type(pidfd_record["signal"]) is int and
                    pidfd_record["signal"] == group_signal["signal"] and
                    type(pidfd_record["sent"]) is bool,
                    "owned-process pidfd signal identity/value is duplicate or inconsistent")
            member = member_by_pid.get(pid)
            require(member is not None and member["start_ticks"] == start_ticks and
                    member["session_id"] == start["pid"] and
                    member["process_group"] != start["pid"] and
                    member["state"] not in ("Z", "X"),
                    "owned-process pidfd signal is not bound to a live escaped-group member")
            pidfd_pids.add(pid)
        if members_value is not None and record["scan_error"] is None:
            escaped_live = {
                pid for pid, member in member_by_pid.items()
                if pid != start["pid"] and member["process_group"] != start["pid"] and
                member["state"] not in ("Z", "X")
            }
            require(escaped_live <= pidfd_pids,
                    "owned-process signal omitted a live escaped-group member without a captured pidfd attempt")


def _verify_owned_process_capture(
    context: dict[str, Any], job: dict[str, Any], stage_dir: Path,
    capture_pin: object, start: dict[str, Any], argv: list[str],
    environment: dict[str, str], binary: Path, binary_sha: str,
    timeout_seconds: int, elapsed_ns: int, output_details: dict[str, Any],
    *, owner_return_pin: object | None = None,
) -> None:
    """Replay the captured FixedR8 completion and its unreaped-leader cleanup proof."""
    value = exact(capture_pin, {"path", "sha256"}, "owned-process capture pin")
    job_dir = stage_dir / "jobs" / job["run_id"]
    label = "policy-probe" if argv[1:2] == ["--emit-feedback-policy-only"] else "application"
    expected_path = job_dir / f"{label}.process-capture.json"
    path, raw, raw_sha = _read_evidence_pin(
        value, "owned-process capture", MAX_METADATA_BYTES, stage_dir,
    )
    info = path.stat(follow_symlinks=False)
    require(path == expected_path and stat.S_IMODE(info.st_mode) == 0o600 and
            info.st_uid == os.getuid(),
            "owned-process capture is not the expected private per-job sidecar")
    capture_record = parse_object(raw, "owned-process capture", MAX_METADATA_BYTES, canonical=True)
    is_policy_probe = argv[1:2] == ["--emit-feedback-policy-only"]
    requested_dispatch = _owned_process_requested_dispatch(
        argv, job_dir, environment, binary, binary_sha,
        context["current_host"]["cpu_affinity"],
        context["current_host"]["network_namespace_inode"],
    )
    if is_policy_probe:
        capture_record = exact(capture_record, {
            "schema", "role", "runner_sha256", "identity_helper_sha256", "dispatch",
            "start", "open_executable", "runner_capture", "stdout", "stderr",
        }, "Source5 policy-probe capture receipt")
        executable = exact(capture_record["open_executable"], {
            "path", "sha256", "device", "inode", "size",
        }, "Source5 policy-probe open executable descriptor")
        require(capture_record["schema"] == OWNED_POLICY_PROBE_CAPTURE_SCHEMA and
                capture_record["role"] == "source5_policy_probe" and
                capture_record["dispatch"] == requested_dispatch and
                capture_record["start"] == start and
                executable["path"] == str(binary) and executable["sha256"] == binary_sha,
                "Source5 policy-probe capture receipt differs from its exact role/dispatch/start")
    else:
        capture_record = exact(capture_record, {
            "schema", "runner_sha256", "identity_helper_sha256", "runner_capture", "stdout", "stderr",
        }, "owned-process stage capture receipt")
        require(capture_record["schema"] == OWNED_PROCESS_CAPTURE_SCHEMA,
                "owned-process capture receipt has an unsupported schema")
    require(capture_record["runner_sha256"] == context["stack"]["fixed_pair_sha256"] and
            capture_record["identity_helper_sha256"] == context["stack"]["process_identity_helper_sha256"],
            "owned-process capture receipt differs from the captured SourceV5 owner modules")
    for stream in ("stdout", "stderr"):
        expected_output_path = job_dir / (
            "policy-probe.json" if label == "policy-probe" and stream == "stdout" else
            "policy-probe.stderr" if label == "policy-probe" else
            "application.stdout" if stream == "stdout" else "application.stderr"
        )
        if f"{stream}_path" in output_details:
            detail_path = output_details[f"{stream}_path"]
            detail_sha = output_details[f"{stream}_sha256"]
            detail_size = output_details[f"{stream}_size"]
        else:
            detail_pin = exact(output_details.get(stream), {"path", "sha256"},
                               f"owned-process {stream} event pin")
            detail_path = detail_pin["path"]
            detail_sha = detail_pin["sha256"]
            detail_size = output_details[f"{stream}_size"]
        output_path, output_raw, output_sha = _read_evidence_pin(
            {"path": detail_path, "sha256": detail_sha},
            f"owned-process {stream}",
            MAX_PROBE_BYTES if label == "policy-probe" and stream == "stdout" else
            MAX_STDOUT_BYTES if stream == "stdout" else MAX_STDERR_BYTES,
            stage_dir,
        )
        expected_output = {
            "path": str(expected_output_path), "raw_sha256": output_sha, "size": len(output_raw),
        }
        require(output_path == expected_output_path and len(output_raw) == detail_size and
                capture_record[stream] == expected_output,
                f"owned-process {stream} sidecar differs from the stage event bytes")
    capture = capture_record["runner_capture"]
    require(type(capture) is dict, "owned-process runner capture is malformed")
    if owner_return_pin is not None:
        return_value = exact(owner_return_pin, {"path", "sha256"},
                             "bounded raw direct-owner return pin")
        expected_return_path = job_dir / f"{label}.owner-return.json"
        return_path, return_raw, return_sha = _read_evidence_pin(
            return_value, "bounded raw direct-owner return",
            MAX_METADATA_BYTES, stage_dir,
        )
        return_info = return_path.stat(follow_symlinks=False)
        raw_return = parse_object(
            return_raw, "bounded raw direct-owner return", MAX_METADATA_BYTES,
            canonical=True,
        )
        require(return_path == expected_return_path and
                stat.S_IMODE(return_info.st_mode) == 0o600 and
                return_info.st_uid == os.getuid() and
                return_sha == return_value["sha256"] and
                raw_return == capture and
                canonical_bytes(raw_return) == return_raw,
                "bounded raw direct-owner return differs from its descriptive success receipt")
    exact(capture, {
        "status", "child_return_code", "start", "binary_path", "binary_sha256",
        "binary_device", "binary_inode", "binary_size", "requested_argv",
        "requested_argv_sha256", "environment", "environment_sha256", "cwd",
        "cpu_affinity", "network_namespace_inode", "received_signal", "supervision",
        "timing", "started_monotonic_ns", "ended_monotonic_ns",
    }, "owned-process capture")
    fixed = context["stack"]["fixed_pair"]
    require(capture["status"] == 0 and capture["child_return_code"] == 0 and
            capture["start"] == start and capture["binary_path"] == str(binary) and
            capture["binary_sha256"] == binary_sha and
            capture["requested_argv"] == argv and
            capture["requested_argv_sha256"] == sha256_bytes(canonical_bytes(argv)) and
            capture["environment"] == environment and
            capture["environment_sha256"] == sha256_bytes(canonical_bytes(environment)) and
            capture["cwd"] == str(job_dir) and
            capture["cpu_affinity"] == requested_dispatch["requested_cpu_affinity"] and
            capture["network_namespace_inode"] == requested_dispatch["expected_network_namespace_inode"] and
            capture["received_signal"] is None,
            "owned-process capture differs from its successful frozen dispatch/start proof")
    for name in ("binary_device", "binary_inode", "binary_size"):
        uint(capture[name], f"owned-process {name}", positive=name != "binary_device")
    if is_policy_probe:
        opened = capture_record["open_executable"]
        require(uint(opened["device"], "policy-probe executable device") == capture["binary_device"] and
                uint(opened["inode"], "policy-probe executable inode", positive=True) == capture["binary_inode"] and
                uint(opened["size"], "policy-probe executable size", positive=True) == capture["binary_size"] and
                capture["binary_path"] == opened["path"] == str(binary) and
                capture["binary_sha256"] == opened["sha256"] == binary_sha,
                "policy-probe open executable descriptor differs from the captured FixedR8 file descriptor")
    else:
        require(capture["binary_device"] == start["executable_device"] and
                capture["binary_inode"] == start["executable_inode"] and
                capture["binary_size"] == start["executable_size"],
                "owned-process opened executable identity differs from the actual APP start proof")
    _verify_owned_process_supervision(capture["supervision"], start, fixed)
    timing = exact(capture["timing"], {
        "schema", "time_source", "pid", "started_monotonic_ns", "ended_monotonic_ns",
        "elapsed_ns", "exit_code", "child_return_code", "timed_out",
        "artifact_budget_exceeded", "cleanup_status",
    }, "owned-process monotonic timing")
    started_ns = uint(capture["started_monotonic_ns"], "owned-process start time", positive=True)
    ended_ns = uint(capture["ended_monotonic_ns"], "owned-process end time", positive=True)
    capture_elapsed = uint(timing["elapsed_ns"], "owned-process elapsed nanoseconds")
    require(timing["schema"] == fixed.DIRECT_TIME_SCHEMA and
            timing["time_source"] == "monotonic_direct_supervisor" and
            timing["pid"] == start["pid"] and timing["started_monotonic_ns"] == started_ns and
            timing["ended_monotonic_ns"] == ended_ns and ended_ns >= started_ns and
            timing["exit_code"] == 0 and timing["child_return_code"] == 0 and
            timing["timed_out"] is False and timing["artifact_budget_exceeded"] is False and
            timing["cleanup_status"] == "verified" and capture_elapsed == ended_ns - started_ns and
            capture_elapsed == elapsed_ns and capture_elapsed <= timeout_seconds * 1_000_000_000,
            "owned-process monotonic time/status differs from the frozen stage deadline")
    require(raw_sha == value["sha256"], "owned-process capture raw digest changed")


def _verify_preparation_resource_monitor_report(
    context: dict[str, Any], jobs: list[dict[str, Any]], records: list[dict[str, Any]],
    job: dict[str, Any], stage_dir: Path, role: str, monitor_pin: object,
    dispatch_roots: object,
) -> dict[str, Any]:
    require(context.get("resource_budget") is not None,
            "resource monitor report is not attached to a bounded preparation")
    budget_context = context["resource_budget"]
    ceilings = budget_context["ceilings"]
    roots = exact(dispatch_roots, {"generation", "job_output", "trace", "tmpdirs"},
                  f"{role} resource root identities")
    index_matches = [index for index, item in enumerate(jobs) if item["run_id"] == job["run_id"]]
    require(len(index_matches) == 1, "resource monitor job is outside the frozen order")
    job_index = index_matches[0]
    role_ordinal = 0 if role == "policy_probe" else 1
    expected_report_before = 2 * job_index + role_ordinal
    expected_job_report_before = role_ordinal
    earlier_tmpdirs: list[str] = []
    for previous_job in jobs[:job_index]:
        previous_dispatch = [record for record in records
                             if record.get("run_id") == previous_job["run_id"] and
                             record.get("event") == "probe_dispatch"]
        require(len(previous_dispatch) == 1,
                "resource monitor replay lacks an earlier original TMPDIR dispatch")
        previous_environment = exact(previous_dispatch[0]["details"].get("environment"),
                                     {"PATH", "LC_ALL", "TMPDIR"},
                                     "earlier preparation probe environment")
        earlier_tmpdirs.append(previous_environment["TMPDIR"])
    current_dispatch = [record for record in records
                        if record.get("run_id") == job["run_id"] and
                        record.get("event") == ("probe_dispatch" if role == "policy_probe"
                                                 else "application_dispatch")]
    require(len(current_dispatch) == 1,
            f"{role} resource monitor has no unique frozen dispatch")
    current_details = current_dispatch[0]["details"]
    current_tmpdir = (exact(current_details.get("environment"), {"PATH", "LC_ALL", "TMPDIR"},
                            "policy probe environment")["TMPDIR"] if role == "policy_probe"
                      else current_details.get("tmpdir_path"))
    expected_tmpdir_paths = earlier_tmpdirs + [current_tmpdir]
    require(type(roots["generation"]) is dict and
            roots["generation"].get("path") == str(stage_dir) and
            type(roots["job_output"]) is dict and
            roots["job_output"].get("path") == str(stage_dir / "jobs" / job["run_id"]) and
            type(roots["trace"]) is dict and
            roots["trace"].get("path") == str(stage_dir / "jobs" / job["run_id"] / "trace") and
            type(roots["tmpdirs"]) is list and
            [item.get("path") for item in roots["tmpdirs"] if type(item) is dict] ==
            expected_tmpdir_paths,
            f"{role} resource monitor roots differ from original preparation paths")
    expected_roots_by_name = (
        ("generation", stage_dir),
        ("job_output", stage_dir / "jobs" / job["run_id"]),
        ("trace", stage_dir / "jobs" / job["run_id"] / "trace"),
    )
    fixed = context["stack"]["fixed_pair"]
    offline_copy = context.get("offline_host_replay") is True

    def verify_current_root(root_value: dict[str, Any], expected_path: Path,
                            label: str) -> dict[str, Any]:
        current = _bounded_root_identity(fixed, expected_path, label)
        if offline_copy:
            fingerprint = context.get("offline_local_fingerprints", {}).get(
                str(expected_path),
            )
            require(type(fingerprint) is dict and
                    fingerprint.get("kind") == "directory" and
                    fingerprint.get("device") == current["device"] and
                    fingerprint.get("inode") == current["inode"] and
                    fingerprint.get("mode") == 0o700 and
                    fingerprint.get("uid") == os.getuid(),
                    f"{label} local-copy fingerprint changed after offline preflight")
            return current
        require(current == root_value,
                f"{label} root device/inode changed since dispatch")
        return current

    context.setdefault("_verified_local_roots", {})
    for name, expected_path in expected_roots_by_name:
        root_value = exact(roots[name], {"path", "device", "inode"},
                           f"{role} {name} root identity")
        uint(root_value["device"], f"{role} {name} device")
        uint(root_value["inode"], f"{role} {name} inode", positive=True)
        require(root_value["path"] == str(expected_path),
                f"{role} {name} root path differs from its original dispatch")
        current_root = verify_current_root(
            root_value, expected_path, f"{role} {name} root",
        )
        context["_verified_local_roots"][str(expected_path)] = current_root
    normalized_tmp_roots: list[dict[str, Any]] = []
    for index, root_value in enumerate(roots["tmpdirs"]):
        root = exact(root_value, {"path", "device", "inode"},
                     f"{role} TMPDIR root identity[{index}]")
        uint(root["device"], f"{role} TMPDIR device[{index}]")
        uint(root["inode"], f"{role} TMPDIR inode[{index}]", positive=True)
        require(root["path"] == expected_tmpdir_paths[index],
                f"{role} TMPDIR path differs from its original dispatch")
        current_root = verify_current_root(
            root, Path(root["path"]), f"{role} TMPDIR[{index}]",
        )
        context["_verified_local_roots"][root["path"]] = current_root
        normalized_tmp_roots.append(root)
    pin = exact(monitor_pin, {"path", "sha256"}, f"{role} resource monitor report pin")
    report_path, report_raw, report_sha = _read_evidence_pin(
        pin, f"{role} resource monitor report", MAX_METADATA_BYTES, stage_dir,
    )
    expected_report_path = stage_dir / "jobs" / job["run_id"] / (
        "policy-probe.resource-monitor.json" if role == "policy_probe" else
        "application.resource-monitor.json"
    )
    report_info = report_path.stat(follow_symlinks=False)
    require(report_path == expected_report_path and stat.S_ISREG(report_info.st_mode) and
            stat.S_IMODE(report_info.st_mode) == 0o600 and report_info.st_uid == os.getuid(),
            f"{role} resource monitor report is not its owned private sidecar")
    report = parse_object(report_raw, f"{role} resource monitor report", MAX_METADATA_BYTES, canonical=True)
    exact(report, {
        "schema", "role", "resource_budget", "fixed_pair_sha256",
        "sample_interval_milliseconds", "roots", "started_monotonic_ns",
        "ended_monotonic_ns", "sample_count", "high_water", "stop_reason",
        "monitor_error", "samples",
    }, f"{role} resource monitor report")
    uint(report["sample_interval_milliseconds"],
         f"{role} monitor sample interval", positive=True)
    require(report["schema"] == PREPARATION_RESOURCE_MONITOR_SCHEMA and
            report["role"] == role and report["resource_budget"] == budget_context["pin"] and
            report["fixed_pair_sha256"] == context["stack"]["fixed_pair_sha256"] and
            report["sample_interval_milliseconds"] == ceilings["monitor_sample_interval_milliseconds"] and
            report["roots"] == roots and report["stop_reason"] is None and
            report["monitor_error"] is None,
            f"{role} resource monitor report changed its source/budget/root/stop binding")
    started = uint(report["started_monotonic_ns"], f"{role} monitor start", positive=True)
    ended = uint(report["ended_monotonic_ns"], f"{role} monitor end", positive=True)
    fixed_overrun_seconds = int(getattr(fixed, "TERM_GRACE_SECONDS", 3.0) +
                                getattr(fixed, "KILL_REAP_SECONDS", 1.0))
    dispatch_deadline = (uint(current_details.get("deadline_seconds"),
                               f"{role} monitor dispatch deadline", positive=True)
                         if role == "policy_probe" else
                         uint(current_details.get("process_deadline_seconds"),
                              f"{role} monitor dispatch deadline", positive=True))
    require(ended >= started and
            ended - started <= (dispatch_deadline + fixed_overrun_seconds + 1) * 1_000_000_000,
            f"{role} monitor interval outlasts the frozen process/owner cleanup deadline")
    completed_event = "probe_completed" if role == "policy_probe" else "application_exited"
    completed_records = [item for item in records
                         if item.get("run_id") == job["run_id"] and
                         item.get("event") == completed_event]
    require(len(completed_records) == 1 and
            uint(current_dispatch[0].get("monotonic_ns"), f"{role} dispatch time", positive=True) <= started <=
            ended <= uint(completed_records[0].get("monotonic_ns"), f"{role} owner receipt time", positive=True),
            f"{role} monitor interval is outside its flushed dispatch/owner receipt window")
    sample_count = uint(report["sample_count"], f"{role} monitor sample count", positive=True)
    samples = report["samples"]
    require(type(samples) is list and len(samples) == sample_count and
            sample_count >= 2 and
            sample_count <= budget_context["monitor_report_max_samples"],
            f"{role} resource monitor sample list/count exceeds its caller-frozen bound")
    samples_high: dict[str, int] = {key: 0 for key in (
        "job_output_bytes", "job_output_inodes", "generation_bytes",
        "generation_inodes", "tmpdir_bytes", "tmpdir_inodes",
    )}
    previous_time = 0
    sample_fields = {
        "monotonic_ns", "job_output_bytes", "job_output_inodes",
        "generation_bytes", "generation_inodes", "tmpdir_bytes", "tmpdir_inodes",
        "tmpdir_by_device", "monitor_report_count_before", "job_monitor_report_count_before",
        "generation_receipt_reserve_bytes", "generation_receipt_reserve_inodes",
        "job_monitor_receipt_reserve_bytes", "trace_files", "filesystems",
    }
    expected_filesystems = {roots["generation"]["device"],
                            *(item["device"] for item in normalized_tmp_roots)}
    for sample_index, sample_value in enumerate(samples):
        sample = exact(sample_value, sample_fields,
                       f"{role} monitor sample[{sample_index}]")
        monotonic = uint(sample["monotonic_ns"], f"{role} sample timestamp", positive=True)
        require(started <= monotonic <= ended and monotonic > previous_time,
                f"{role} monitor sample timestamps are outside their strict sequence")
        previous_time = monotonic
        values: dict[str, int] = {}
        for field in samples_high:
            values[field] = uint(sample[field], f"{role} sample {field}")
            samples_high[field] = max(samples_high[field], values[field])
        require(values["job_output_bytes"] <= ceilings["maximum_job_output_bytes"] and
                values["job_output_inodes"] <= ceilings["maximum_job_output_inodes"] and
                values["generation_bytes"] <= ceilings["maximum_generation_bytes"] and
                values["generation_inodes"] <= ceilings["maximum_generation_inodes"] and
                values["tmpdir_bytes"] <= ceilings["maximum_tmpdir_bytes"] and
                values["tmpdir_inodes"] <= ceilings["maximum_tmpdir_inodes"],
                f"{role} monitor sample exceeds its frozen byte/inode budget")
        require(sample["monitor_report_count_before"] == expected_report_before and
                sample["job_monitor_report_count_before"] == expected_job_report_before,
                f"{role} monitor sample report-reserve sequence differs from original ordinal order")
        uint(sample["monitor_report_count_before"], f"{role} monitor report count before")
        uint(sample["job_monitor_report_count_before"], f"{role} job report count before")
        future_reports = budget_context["monitor_report_count"] - expected_report_before
        expected_generation_reserve = max(
            future_reports * budget_context["monitor_report_max_bytes"] + MAX_LEDGER_BYTES +
            2 * MAX_METADATA_BYTES,
            ceilings["durable_receipt_reserve_bytes"],
        )
        expected_generation_inode_reserve = max(
            future_reports + 2, ceilings["durable_receipt_reserve_inodes"],
        )
        expected_job_reserve = (2 - expected_job_report_before) * budget_context["monitor_report_max_bytes"]
        require(sample["generation_receipt_reserve_bytes"] == expected_generation_reserve and
                sample["generation_receipt_reserve_inodes"] == expected_generation_inode_reserve and
                sample["job_monitor_receipt_reserve_bytes"] == expected_job_reserve and
                values["generation_bytes"] + expected_generation_reserve <= ceilings["maximum_generation_bytes"] and
                values["generation_inodes"] + expected_generation_inode_reserve <= ceilings["maximum_generation_inodes"] and
                values["job_output_bytes"] + expected_job_reserve <= ceilings["maximum_job_output_bytes"] and
                values["job_output_inodes"] + (2 - expected_job_report_before) <= ceilings["maximum_job_output_inodes"],
                f"{role} monitor sample cannot reserve its frozen future monitor/terminal receipts")
        for reserve_name in (
            "generation_receipt_reserve_bytes", "generation_receipt_reserve_inodes",
            "job_monitor_receipt_reserve_bytes",
        ):
            uint(sample[reserve_name], f"{role} {reserve_name}")
        trace_files = exact(sample["trace_files"], set(PreparationResourceMonitor.TRACE_NAMES),
                            f"{role} trace size sample")
        require(all(size is None or
                    (type(size) is int and 0 <= size <= ceilings["maximum_trace_file_bytes"])
                    for size in trace_files.values()),
                f"{role} trace size sample exceeds its frozen per-file cap")
        expected_tmp_devices = {root["device"] for root in normalized_tmp_roots}
        tmp_by_device = exact(sample["tmpdir_by_device"],
                              {str(item) for item in expected_tmp_devices},
                              f"{role} TMPDIR per-device usage")
        tmp_values: dict[str, dict[str, int]] = {}
        for device_key, value in tmp_by_device.items():
            typed = exact(value, {"bytes", "inodes"}, f"{role} TMPDIR device usage")
            tmp_values[device_key] = {
                "bytes": uint(typed["bytes"], f"{role} TMPDIR device bytes"),
                "inodes": uint(typed["inodes"], f"{role} TMPDIR device inodes"),
            }
        require(sum(value["bytes"] for value in tmp_values.values()) == values["tmpdir_bytes"] and
                sum(value["inodes"] for value in tmp_values.values()) == values["tmpdir_inodes"],
                f"{role} TMPDIR per-device totals differ from aggregate accounting")
        file_systems = sample["filesystems"]
        require(type(file_systems) is list and
                [item.get("device") for item in file_systems if type(item) is dict] ==
                sorted(expected_filesystems),
                f"{role} storage sample does not cover its exact device set")
        for filesystem in file_systems:
            exact(filesystem, {
                "device", "available_bytes", "available_inodes", "required_bytes",
                "required_inodes", "tmpdir_bytes", "tmpdir_inodes",
            }, f"{role} filesystem sample")
            device = uint(filesystem["device"], f"{role} filesystem device")
            uint(filesystem["tmpdir_bytes"], f"{role} filesystem TMPDIR bytes")
            uint(filesystem["tmpdir_inodes"], f"{role} filesystem TMPDIR inodes")
            uint(filesystem["required_bytes"], f"{role} required free bytes")
            uint(filesystem["required_inodes"], f"{role} required free inodes")
            temp_value = tmp_values.get(str(device), {"bytes": 0, "inodes": 0})
            require(filesystem["tmpdir_bytes"] == temp_value["bytes"] and
                    filesystem["tmpdir_inodes"] == temp_value["inodes"],
                    f"{role} filesystem TMPDIR sample differs by device")
            generation_remaining = (max(0, ceilings["maximum_generation_bytes"] - values["generation_bytes"])
                                    if device == roots["generation"]["device"] else 0)
            generation_inode_remaining = (max(0, ceilings["maximum_generation_inodes"] - values["generation_inodes"])
                                          if device == roots["generation"]["device"] else 0)
            tmp_remaining = (max(0, ceilings["maximum_tmpdir_bytes"] - temp_value["bytes"])
                             if str(device) in tmp_values else 0)
            tmp_inode_remaining = (max(0, ceilings["maximum_tmpdir_inodes"] - temp_value["inodes"])
                                   if str(device) in tmp_values else 0)
            required_bytes = ceilings["minimum_free_bytes"] + generation_remaining + tmp_remaining
            required_inodes = ceilings["minimum_free_inodes"] + generation_inode_remaining + tmp_inode_remaining
            require(uint(filesystem["available_bytes"], f"{role} available bytes") >= required_bytes and
                    uint(filesystem["available_inodes"], f"{role} available inodes") >= required_inodes and
                    filesystem["required_bytes"] == required_bytes and
                    filesystem["required_inodes"] == required_inodes,
                    f"{role} free-space sample does not preserve its frozen reserve")
    high_water = exact(report["high_water"], set(samples_high), f"{role} monitor high-water")
    require(all(uint(high_water[field], f"{role} monitor high-water {field}") == samples_high[field]
                for field in samples_high),
            f"{role} monitor high-water differs from its ordered live samples")
    context.setdefault("_verified_resource_monitor_reports", {})[(job["run_id"], role)] = report
    return report


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
        expected_fields = set(common) | extra_fields
        if context.get("preparation_mode") is True:
            if event in ("probe_completed", "application_exited"):
                expected_fields |= OWNED_PROCESS_EVENT_FIELDS
            elif event == "application_bound":
                expected_fields |= OWNED_PROCESS_START_EVENT_FIELDS
        if context.get("resource_budget") is not None:
            if event in ("probe_dispatch", "application_dispatch"):
                expected_fields.add("resource_roots")
            elif event in ("probe_completed", "application_exited"):
                expected_fields.add("resource_monitor")
                expected_fields.add("direct_process_owner_return")
        exact(by_event[event], expected_fields,
              f"capacity ledger {event} detail schema")
    require(by_event["probe_dispatch"].get("argv", [None])[1:] == [
        "--emit-feedback-policy-only", "--workload", job["capacity_key"]["workload"],
        "--profile", job["capacity_key"]["profile"],
    ], "capacity probe dispatch argv differs from the frozen context")
    probe_dispatch = by_event["probe_dispatch"]
    probe_monitor_report: dict[str, Any] | None = None
    expected_binary, expected_binary_sha = _verify_binary(context["source_root"], context["source"], job)
    probe_deadline = uint(probe_dispatch.get("deadline_seconds"),
                          "capacity policy probe deadline", positive=True)
    expected_probe_deadline = min(context["spec"]["deadlines"]["setup_seconds"], 120)
    if context.get("resource_budget") is not None:
        expected_probe_deadline = min(
            expected_probe_deadline,
            context["resource_budget"]["ceilings"]["process_deadline_seconds"],
        )
    require(probe_dispatch["argv"][0] == str(expected_binary) and
            probe_dispatch["expected_binary_sha256"] == expected_binary_sha and
            probe_dispatch["cwd"] == str(stage_dir / "jobs" / job["run_id"]) and
            probe_deadline == expected_probe_deadline and
            probe_dispatch["stdout_path"] == str(stage_dir / "jobs" / job["run_id"] / "policy-probe.json") and
            probe_dispatch["stderr_path"] == str(stage_dir / "jobs" / job["run_id"] / "policy-probe.stderr"),
            "capacity probe dispatch is not directly bound to the frozen application binary")
    probe_completed = by_event["probe_completed"]
    if context.get("resource_budget") is not None:
        probe_monitor_report = _verify_preparation_resource_monitor_report(
            context, derive_capacity_preparation_jobs(
                {**context["preparation"],
                 "preparation_raw_sha256": context["preparation_raw_sha256"]},
                context["host_id"],
            ),
            records, job, stage_dir, "policy_probe", probe_completed["resource_monitor"],
            probe_dispatch["resource_roots"],
        )
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
    if context.get("preparation_mode") is True:
        require(probe_completed["direct_process_runner_sha256"] ==
                context["stack"]["fixed_pair_sha256"] and
                probe_completed["process_identity_helper_sha256"] ==
                context["stack"]["process_identity_helper_sha256"],
                "Source5 probe owner hashes differ from the exact SourceV5 typed inventory modules")
        probe_start = _verify_owned_process_start(
            context, job, stage_dir, probe_completed["direct_process_start"],
            probe_dispatch["argv"], probe_dispatch["environment"],
            expected_binary, expected_binary_sha, probe_completed["pid"],
        )
        _verify_owned_process_capture(
            context, job, stage_dir, probe_completed["direct_process_capture"],
            probe_start, probe_dispatch["argv"], probe_dispatch["environment"],
            expected_binary, expected_binary_sha, probe_deadline,
            probe_elapsed_ns, probe_completed,
            owner_return_pin=(probe_completed["direct_process_owner_return"]
                              if context.get("resource_budget") is not None else None),
        )
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
    expected_process_deadline = context["spec"]["deadlines"]["process_seconds"]
    if context.get("resource_budget") is not None:
        expected_process_deadline = min(
            expected_process_deadline,
            context["resource_budget"]["ceilings"]["process_deadline_seconds"],
        )
    environment = _application_environment(
        _job_identity(job, context["source"]),
        Path(app_dispatch.get("trace_directory", "/invalid")),
        Path(app_dispatch.get("tmpdir_path", "/invalid")),
        source5_preparation=context.get("preparation_mode") is True,
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
            dispatch_process_deadline == expected_process_deadline,
            "capacity application dispatch differs from the frozen workload/profile/executor/deadlines")
    require(app_dispatch.get("trace_directory") == str(stage_dir / "jobs" / job["run_id"] / "trace") and
            app_dispatch.get("cwd") == str(stage_dir / "jobs" / job["run_id"]),
            "capacity application trace/TMPDIR/cwd is not fresh under the private stage")
    require("ALLOCATBELT_APP_CAPACITY_CALIBRATION_FILE" not in environment and
            "ALLOCATBELT_APP_CAPACITY_CALIBRATION_SHA256" not in environment,
            "capacity application inherited a prior capacity artifact")
    bound = by_event["application_bound"]
    pid = uint(bound.get("pid"), "actual application PID", positive=True, maximum=(1 << 31) - 1)
    if context.get("preparation_mode") is True:
        require(bound["direct_process_runner_sha256"] == context["stack"]["fixed_pair_sha256"] and
                bound["process_identity_helper_sha256"] ==
                context["stack"]["process_identity_helper_sha256"],
                "Source5 application owner hashes differ from the exact SourceV5 typed inventory modules")
        app_start = _verify_owned_process_start(
            context, job, stage_dir, bound["direct_process_start"],
            app_dispatch["argv"], app_dispatch["environment"],
            expected_binary, expected_binary_sha, pid,
        )
        require(app_start["start_ticks"] == bound["start_ticks"],
                "Source5 application start sidecar differs from its flushed application binding")
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
    app_monitor_report: dict[str, Any] | None = None
    if context.get("resource_budget") is not None:
        app_monitor_report = _verify_preparation_resource_monitor_report(
            context, derive_capacity_preparation_jobs(
                {**context["preparation"],
                 "preparation_raw_sha256": context["preparation_raw_sha256"]},
                context["host_id"],
            ),
            records, job, stage_dir, "application", app_exit["resource_monitor"],
            app_dispatch["resource_roots"],
        )
    process_deadline = uint(expected_process_deadline,
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
    if context.get("preparation_mode") is True:
        require(app_exit["direct_process_runner_sha256"] ==
                context["stack"]["fixed_pair_sha256"] and
                app_exit["process_identity_helper_sha256"] ==
                context["stack"]["process_identity_helper_sha256"] and
                app_exit["direct_process_start"] == bound["direct_process_start"],
                "Source5 application exit changed its direct owner start/module pins")
        _verify_owned_process_capture(
            context, job, stage_dir, app_exit["direct_process_capture"], app_start,
            app_dispatch["argv"], app_dispatch["environment"], expected_binary,
            expected_binary_sha, process_deadline, app_elapsed_ns, app_exit,
            owner_return_pin=(app_exit["direct_process_owner_return"]
                              if context.get("resource_budget") is not None else None),
        )
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
    if context.get("resource_budget") is not None:
        require(expectation_raw == expected_expectation_raw and
                expectation_sha == expected_expectation_sha and
                expectation_value == expected_expectation,
                "bounded V4 expectation differs from its exact original launch bytes")
    else:
        require((context.get("offline_host_replay") is True or
                 expectation_raw == expected_expectation_raw) and
                (context.get("offline_host_replay") is True or
                 expectation_sha == expected_expectation_sha) and
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
        if context.get("resource_budget") is not None:
            trace_info = Path(pin["path"]).stat(follow_symlinks=False)
            require(trace_info.st_size <=
                    context["resource_budget"]["ceilings"]["maximum_trace_file_bytes"],
                    f"captured trace {role} exceeds its caller-frozen live byte ceiling")
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
        validation = context["stack"]["feedback_reader"].verify_feedback(
            expectation_path, expectation_sha, trace_dir, trace_hashes,
        )
        expected_validation_raw_sha = None
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
    origin_context_value = context_value
    storage_template = context_template["storage"]
    network_template = context_template["network"]
    if storage_template is None:
        expected_storage = None
        if context.get("resource_budget") is not None:
            expected_tmpdir = stage_dir.parents[2] / (
                f"capacity-preparation-tmp-{job['run_id']}"
            )
        else:
            expected_tmpdir = stage_dir / "jobs" / job["run_id"] / "tmp"
        require(app_dispatch["tmpdir_path"] == bound["tmpdir_path"] == environment["TMPDIR"] ==
                str(expected_tmpdir),
                "application dispatch/bound TMPDIR differs from its canonical original schedule path")
        if context.get("offline_host_replay") is not True:
            tmpdir_path = _safe_root(Path(expected_tmpdir), "capacity process TMPDIR")
            _check_new_directory(tmpdir_path, "capacity process TMPDIR")
    else:
        expected_storage = exact(context_value.get("storage"), {
            "scope", "root_path", "filesystem_type", "device_major_minor", "minimum_free_bytes",
            "tmpdir_path", "available_bytes_at_launch",
        }, "observed capacity storage context")
        require({key: expected_storage[key] for key in storage_template} == storage_template and
                (context.get("offline_host_replay") is True or
                 _is_within(Path(storage_template["root_path"]),
                            Path(expected_storage["tmpdir_path"]))) and
                uint(expected_storage["available_bytes_at_launch"], "observed free bytes") >= storage_template["minimum_free_bytes"],
                "capacity storage context differs from its typed template or observed free-space bound")
        tmpdir_path = Path(expected_storage["tmpdir_path"])
        if context.get("offline_host_replay") is True:
            origin_storage = exact(origin_context_value.get("storage"), {
                "scope", "root_path", "filesystem_type", "device_major_minor",
                "minimum_free_bytes", "tmpdir_path", "available_bytes_at_launch",
            }, "origin-host capacity storage snapshot")
            origin_tmpdir = Path(origin_storage["tmpdir_path"])
            require(origin_tmpdir.parent == Path(origin_storage["root_path"]) and
                    _map_evidence_path(origin_tmpdir, context["evidence_path_map"],
                                       exact=True) == tmpdir_path,
                    "offline copied TMPDIR differs from its exact origin-host storage receipt")
        else:
            require(tmpdir_path.parent == Path(storage_template["root_path"]),
                    "capacity application TMPDIR is not a fresh child of the frozen storage root")
        require(app_dispatch["tmpdir_path"] == bound["tmpdir_path"] == environment["TMPDIR"] ==
                str(tmpdir_path),
                "application dispatch/bound TMPDIR differs from the validated storage context")
        if context.get("offline_host_replay") is not True:
            _safe_root(tmpdir_path, "capacity application TMPDIR")
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
        if context.get("offline_host_replay") is not True:
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
    verified_entry = {
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
    if context.get("preparation_mode") is True:
        verified_entry["capacity_key"] = job["capacity_key"]
    if context.get("resource_budget") is not None:
        require(probe_monitor_report is not None and app_monitor_report is not None,
                "bounded preparation job has no independently replayed probe/application monitor reports")
        verified_entry["resource_monitors"] = {
            "policy_probe": by_event["probe_completed"]["resource_monitor"],
            "application": app_exit["resource_monitor"],
        }
    return verified_entry


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


def verify_capacity_preparation(
    preparation_pin: dict[str, Any], source_root: Path, input_root: Path,
    host_id: str, observed_host_pin: dict[str, Any], output_root: Path,
    completion_pin: dict[str, Any], *, evidence_path_map: object | None = None,
    host_verification_pin: object | None = None,
    resource_budget_pin: dict[str, Any] | None = None,
    offline_copy: bool = False,
) -> dict[str, Any]:
    """Replay one host's pre-Spec schedule, ledger, APP proofs, traces and TSVs.

    Without optional path-map arguments this is the strict host-local verifier.
    The additive bounded offline path replays evidence at its original absolute
    names and compares it with the strict host receipt. An isolated namespace
    may provide different local inode/device identities at those names; it
    never rewrites launch/evidence strings or samples coordinator host facts.
    """
    bounded_preparation = resource_budget_pin is not None
    require(type(offline_copy) is bool and
            (not offline_copy or bounded_preparation),
            "copied offline verification is a separate bounded-only API")
    expected_preparation_semantic_sha256 = None
    if bounded_preparation:
        preparation_pin, expected_preparation_semantic_sha256 = (
            _bounded_preparation_reader_pin(preparation_pin)
        )
    offline_preflight = None
    if offline_copy:
        offline_preflight = _preflight_bounded_offline_copy(
            preparation_pin, resource_budget_pin,
            source_root, input_root, host_id, observed_host_pin,
            output_root, completion_pin, host_verification_pin,
            evidence_path_map,
            expected_preparation_semantic_sha256=expected_preparation_semantic_sha256,
        )
        path_map = offline_preflight["path_map"]
        preparation_pin = offline_preflight["pins"]["preparation"]
        resource_budget_pin = offline_preflight["pins"]["resource_budget"]
        observed_host_pin = offline_preflight["pins"]["observed_host"]
        completion_pin = offline_preflight["pins"]["completion"]
        host_verification_pin = offline_preflight["pins"]["host_verification"]
        source_root = offline_preflight["source_root"]
        input_root = offline_preflight["input_root"]
        output_root = offline_preflight["output_root"]
    else:
        path_map = (None if evidence_path_map is None else
                    _validate_evidence_path_map(evidence_path_map))
    require(not (bounded_preparation and path_map is not None) or offline_copy,
            "bounded offline evidence must use the explicit recursive verifier")
    require((path_map is None) == (host_verification_pin is None),
            "offline capacity replay requires both an evidence path map and a strict host receipt")
    context, jobs, schedule_sha = _prepare_capacity_preparation_pins(
        preparation_pin, source_root, input_root, host_id, observed_host_pin,
        live_host=path_map is None,
        offline_copy=offline_copy,
        expected_preparation_semantic_sha256=expected_preparation_semantic_sha256,
    )
    context["preparation_mode"] = True
    budget_context: dict[str, Any] | None = None
    if bounded_preparation:
        budget_context = _prepare_capacity_resource_budget_context(
            context, resource_budget_pin, monitor_report_count=2 * len(jobs),
        )
        require(len(jobs) == 15 and schedule_sha ==
                budget_context["normalized"]["capacity_preparation_templates_sha256"],
                "bounded verification budget does not bind the exact original 15-template schedule")
        context["resource_budget"] = budget_context
        context["resource_budget_pin"] = budget_context["pin"]
    if path_map is not None:
        mapped_roots = {origin for origin, _local in path_map}
        if offline_copy:
            require(any(local == context["source_root"] for _origin, local in path_map) and
                    any(local == context["input_root"] for _origin, local in path_map),
                    "bounded offline map must name the exact copied SourceV5 and preparation input roots")
        else:
            require(context["source_root"] in mapped_roots and context["input_root"] in mapped_roots,
                    "offline capacity path map must name the exact SourceV5 and preparation input roots")
        context["offline_host_replay"] = True
        context["evidence_path_map"] = path_map
        if offline_preflight is not None:
            context["offline_local_fingerprints"] = offline_preflight["local_fingerprints"]
            context["offline_origin_host_receipt"] = offline_preflight["host_verification"]
            context["offline_origin_resource_budget"] = offline_preflight["resource_budget"]
            context["offline_origin_completion"] = offline_preflight["completion"]
    output_root = _safe_root(output_root, "capacity preparation output root")
    require(not _is_within(context["source_root"], output_root),
            "capacity preparation output must be outside SourceV5")
    completion, _completion_raw, completion_raw_sha = read_pin(
        completion_pin, "capacity preparation completion", MAX_METADATA_BYTES, canonical=True,
    )
    completion_path = Path(exact(completion_pin, {"path", "sha256"}, "preparation completion pin")["path"])
    completion_info = completion_path.stat(follow_symlinks=False)
    require(stat.S_ISREG(completion_info.st_mode) and stat.S_IMODE(completion_info.st_mode) == 0o600 and
            completion_info.st_uid == os.getuid(),
            "capacity preparation completion must be an owned mode-0600 regular file")
    completion_fields = {
        "schema", "completion_sha256", "complete", "qualification_eligible", "campaign_id", "host_id",
        "preparation", "source", "observed_host", "modules", "capacity_preparation_templates_sha256",
        "stage_directory", "ledger", "entries",
    }
    if bounded_preparation:
        completion_fields |= {"resource_budget", "resource_monitor"}
    exact(completion, completion_fields, "capacity preparation completion")
    completion_body = {key: value for key, value in completion.items() if key != "completion_sha256"}
    expected_completion_schema = (PREPARATION_BOUNDED_COMPLETION_SCHEMA if bounded_preparation
                                  else PREPARATION_COMPLETION_SCHEMA)
    require(completion["schema"] == expected_completion_schema and
            digest(completion["completion_sha256"], "capacity preparation semantic digest") ==
            sha256_bytes(canonical_bytes(completion_body)) and completion["complete"] is True and
            completion["qualification_eligible"] is False,
            "capacity preparation completion digest/schema/eligibility is invalid")
    require(completion["campaign_id"] == context["spec"]["campaign_id"] and
            completion["host_id"] == context["host_id"],
            "capacity preparation completion campaign/host differs from its source intent")
    expected_pins = {
        "preparation": {
            "path": str(context["preparation_path"]),
            "raw_sha256": context["preparation_raw_sha256"],
            "semantic_sha256": context["preparation_semantic_sha256"],
        },
        "source": {
            "path": str(context["source_path"]), "raw_sha256": context["source_raw_sha256"],
            "semantic_sha256": context["source_semantic_sha256"],
            "source_tree_sha256": context["source_tree_sha256"],
        },
        "observed_host": {
            "path": str(context["host_context_path"]),
            "raw_sha256": context["host_context_raw_sha256"],
            "boot_id_sha256": context["current_host"]["boot_id_sha256"],
            "cpu_affinity": context["current_host"]["cpu_affinity"],
            "network_namespace_inode": context["current_host"]["network_namespace_inode"],
        },
        "modules": {
            "capacity_stage": {"path": STAGE_SOURCE_PATH, "sha256": context["stack"]["stage_sha256"]},
            "source5_preparation_helper": {"path": PREPARATION_HELPER_PATH, "sha256": context["preparation_helper_sha256"]},
            "campaign_controller": {"path": CONTROLLER_PATH, "sha256": context["stack"]["controller_sha256"]},
            "campaign_inputs": {"path": INPUTS_PATH, "sha256": context["stack"]["inputs_sha256"]},
            "feedback_reader": {"path": FEEDBACK_READER_PATH, "sha256": context["stack"]["feedback_reader_sha256"]},
            "capacity_producer": {"path": CAPACITY_PRODUCER_PATH, "sha256": context["stack"]["capacity_producer_sha256"]},
            "owned_process": {
                "schema": PREPARATION_PROCESS_OWNER_SCHEMA,
                "fixed_pair": {
                    "path": context["stack"]["fixed_pair_path"],
                    "sha256": context["stack"]["fixed_pair_sha256"],
                },
                "process_identity_helper": {
                    "path": context["stack"]["process_identity_helper_path"],
                    "sha256": context["stack"]["process_identity_helper_sha256"],
                },
            },
        },
    }
    for role, expected in expected_pins.items():
        require(completion[role] == expected,
                f"capacity preparation completion {role} raw/semantic/source pin differs")
    require(completion["capacity_preparation_templates_sha256"] == schedule_sha,
            "capacity preparation completion schedule differs from the original intent array")
    if bounded_preparation:
        require(budget_context is not None and completion["resource_budget"] == budget_context["pin"],
                "bounded capacity completion changed its raw/semantic caller-frozen resource budget pin")
    stage_dir = _pin_path(completion["stage_directory"], "capacity preparation stage directory")
    if path_map is not None:
        mapped_stage_roots = ({local for _origin, local in path_map}
                              if offline_copy else
                              {origin for origin, _local in path_map})
        require(stage_dir in mapped_stage_roots,
                "offline capacity path map must name the exact host stage evidence directory")
    expected_stage_dir = output_root / context["spec"]["campaign_id"] / "capacity-preparation" / context["host_id"]
    require(stage_dir == expected_stage_dir and _is_within(output_root, stage_dir) and
            not _is_within(context["source_root"], stage_dir),
            "capacity preparation output escaped its private generation directory")
    _check_new_directory(stage_dir, "capacity preparation completion directory")
    expected_completion_name = ("capacity-preparation-bounded-completion.json" if bounded_preparation
                                else "capacity-preparation-completion.json")
    require(completion_path == stage_dir / expected_completion_name,
            "capacity preparation completion path differs from its stage directory")
    ledger_value = exact(completion["ledger"], {"path", "raw_sha256", "terminal_head"},
                         "sealed capacity preparation ledger pin")
    ledger_path = _pin_path(ledger_value["path"], "capacity preparation ledger path")
    expected_ledger_name = ("capacity-preparation-bounded-ledger.jsonl" if bounded_preparation
                             else "capacity-preparation-ledger.jsonl")
    require(ledger_path == stage_dir / expected_ledger_name and _is_within(stage_dir, ledger_path),
            "capacity preparation ledger escaped the private stage directory")
    ledger_budget_pin = (None if budget_context is None else budget_context["pin"])
    if offline_copy and offline_preflight is not None:
        ledger_budget_pin = offline_preflight["completion"]["resource_budget"]
    records, ledger_raw_sha = _read_preparation_ledger(
        ledger_path, digest(ledger_value["raw_sha256"], "capacity preparation ledger raw SHA"),
        digest(ledger_value["terminal_head"], "capacity preparation ledger head"),
        ledger_budget_pin,
    )
    require(len(records) == len(jobs) * len(JOB_EVENTS) + 1,
            "capacity preparation ledger has an incomplete transition set")
    expected_events = [event for _job in jobs for event in JOB_EVENTS] + ["preparation_complete"]
    require([record["event"] for record in records] == expected_events,
            "capacity preparation ledger does not preserve the original intent order")
    require(all(record["event"] != "stage_failed" for record in records),
            "capacity preparation ledger contains a failed terminal event")
    jobs_by_run_id = {job["run_id"]: job for job in jobs}
    for record in records:
        if record["run_id"] is not None:
            job = jobs_by_run_id.get(record["run_id"])
            require(job is not None, "capacity preparation ledger names an unknown run ID")
            _validate_event_common(record, context, job)
    reconstructed = [_verify_job_records(records, job, context, stage_dir) for job in jobs]
    require(type(completion["entries"]) is list and len(completion["entries"]) == 15 and
            canonical_bytes(completion["entries"]) == canonical_bytes(reconstructed),
            "capacity preparation completion entries differ from full process/trace/producer replay")
    terminal = records[-1]
    terminal_details = {
        "completion_schema": expected_completion_schema,
        "entry_count": 15,
        "capacity_preparation_templates_sha256": schedule_sha,
        "preparation_raw_sha256": context["preparation_raw_sha256"],
        "preparation_semantic_sha256": context["preparation_semantic_sha256"],
        "qualification_eligible": False,
    }
    if bounded_preparation:
        terminal_details.update({
            "resource_monitor_report_count": 2 * len(jobs),
            "resource_monitor_high_water": completion["resource_monitor"].get("high_water"),
        })
    require(terminal["run_id"] is None and terminal["ordinal"] is None and terminal["template_index"] is None and
            terminal["details"] == terminal_details,
            "capacity preparation terminal ledger event is malformed")
    final_usage: dict[str, Any] | None = None
    if bounded_preparation:
        require(budget_context is not None and type(completion["resource_monitor"]) is dict,
                "bounded capacity completion omits its terminal resource monitor receipt")
        monitor_summary = exact(completion["resource_monitor"], {
            "schema", "fixed_pair_sha256", "report_count", "high_water", "final_usage",
        }, "bounded preparation terminal monitor summary")
        require(monitor_summary["schema"] == PREPARATION_RESOURCE_MONITOR_SCHEMA and
                monitor_summary["fixed_pair_sha256"] == budget_context["fixed_pair_sha256"] and
                monitor_summary["report_count"] == 2 * len(jobs),
                "bounded preparation terminal monitor summary changed its source or report count")
        verified_reports = context.get("_verified_resource_monitor_reports", {})
        require(set(verified_reports) == {
            (job["run_id"], role) for job in jobs
            for role in ("policy_probe", "application")
        }, "bounded preparation replay did not verify every original live monitor report")
        roots_by_job = {
            job["run_id"]: verified_reports[(job["run_id"], "application")]["roots"]
            for job in jobs
        }
        last_roots = roots_by_job[jobs[-1]["run_id"]]
        replay_high_water = {
            field: max(
                report["high_water"][field] for report in verified_reports.values()
            ) for field in (
                "job_output_bytes", "job_output_inodes", "generation_bytes",
                "generation_inodes", "tmpdir_bytes", "tmpdir_inodes",
            )
        }
        host_receipt_bytes = 0
        host_receipt_inodes = 0
        remaining_receipt_bytes = 0 if path_map is not None else MAX_METADATA_BYTES
        remaining_receipt_inodes = 0 if path_map is not None else 1
        if path_map is not None:
            raw_receipt_pin = exact(host_verification_pin, {
                "path", "raw_sha256", "receipt_sha256",
            }, "capacity host-local verification receipt pin")
            receipt_candidate = _pin_path(
                raw_receipt_pin["path"], "capacity host-local verification receipt path",
            )
            if any(_is_within(origin, receipt_candidate) for origin, _local in path_map):
                receipt_candidate = _map_evidence_path(
                    receipt_candidate, path_map, exact=offline_copy,
                )
            require(not _is_within(stage_dir, receipt_candidate) or
                    receipt_candidate.parent == stage_dir,
                    "bounded host receipt inside the generation must be a direct child")
            if _is_within(stage_dir, receipt_candidate):
                _receipt_raw, _receipt_info = read_stable(
                    receipt_candidate, "bounded host verification receipt", MAX_METADATA_BYTES,
                )
                host_receipt_bytes = len(_receipt_raw)
                host_receipt_inodes = 1
        final_usage = _check_bounded_preparation_final_usage(
            context, budget_context, stage_dir,
            {
                "stage_root": last_roots["generation"],
                "tmpdir_roots": [exact(root, {"path", "device", "inode"},
                                        "bounded replay TMPDIR root")
                                 for root in last_roots["tmpdirs"]],
                "job_roots": {
                    job["run_id"]: roots_by_job[job["run_id"]]["job_output"]
                    for job in jobs
                },
                "trace_roots": {
                    job["run_id"]: roots_by_job[job["run_id"]]["trace"]
                    for job in jobs
                },
                "monitor_report_count": monitor_summary["report_count"],
                "high_water": replay_high_water,
            }, jobs,
            receipt_reserve_bytes=remaining_receipt_bytes,
            receipt_reserve_inodes=remaining_receipt_inodes,
        )
        claimed_final_usage = exact(monitor_summary["final_usage"], {
            "generation", "jobs", "tmpdir_bytes", "tmpdir_inodes", "tmpdir_by_device",
            "tmpdir_roots", "monitor_high_water", "monitor_report_count",
        }, "bounded preparation preterminal final inventory")
        ledger_raw, _ledger_info = read_stable(
            ledger_path, "bounded preparation terminal ledger", MAX_LEDGER_BYTES,
        )
        require(sha256_bytes(ledger_raw) == ledger_raw_sha,
                "bounded preparation terminal ledger changed during inventory replay")
        ledger_lines = ledger_raw.splitlines(keepends=True)
        require(ledger_lines and ledger_lines[-1].endswith(b"\n"),
                "bounded preparation terminal ledger has no complete final event")
        terminal_line_bytes = len(ledger_lines[-1])
        completion_file_bytes = len(_completion_raw)
        generation_claim = exact(claimed_final_usage["generation"],
                                 {"bytes_used", "inode_count"},
                                 "bounded preterminal generation inventory")
        generation_observed = final_usage["generation"]
        expected_generation_bytes = (
            generation_observed["bytes_used"] - terminal_line_bytes -
            completion_file_bytes - host_receipt_bytes
        )
        expected_generation_inodes = (
            generation_observed["inode_count"] - 1 - host_receipt_inodes
        )
        require(expected_generation_bytes >= 0 and expected_generation_inodes >= 0 and
                generation_claim["bytes_used"] == expected_generation_bytes and
                generation_claim["inode_count"] == expected_generation_inodes,
                "bounded preterminal inventory differs after exact terminal ledger/completion/host receipt accounting")
        claimed_job_usage = exact(claimed_final_usage["jobs"],
                                  {job["run_id"] for job in jobs},
                                  "bounded preterminal job inventories")
        require(claimed_job_usage == final_usage["jobs"] and
                claimed_final_usage["tmpdir_bytes"] == final_usage["tmpdir_bytes"] and
                claimed_final_usage["tmpdir_inodes"] == final_usage["tmpdir_inodes"] and
                claimed_final_usage["tmpdir_by_device"] == final_usage["tmpdir_by_device"] and
                claimed_final_usage["tmpdir_roots"] == final_usage["tmpdir_roots"] and
                claimed_final_usage["monitor_report_count"] == final_usage["monitor_report_count"],
                "bounded preterminal job/TMPDIR inventory differs from strict quiescent replay")
        final_usage_high_water = {
            "generation_bytes": generation_claim["bytes_used"],
            "generation_inodes": generation_claim["inode_count"],
            "job_output_bytes": max(
                value["bytes_used"] for value in claimed_job_usage.values()
            ),
            "job_output_inodes": max(
                value["inode_count"] for value in claimed_job_usage.values()
            ),
            "tmpdir_bytes": claimed_final_usage["tmpdir_bytes"],
            "tmpdir_inodes": claimed_final_usage["tmpdir_inodes"],
        }
        expected_high_water = {
            field: max(replay_high_water[field], final_usage_high_water[field])
            for field in replay_high_water
        }
        high_water_limits = {
            "generation_bytes": budget_context["ceilings"]["maximum_generation_bytes"],
            "generation_inodes": budget_context["ceilings"]["maximum_generation_inodes"],
            "job_output_bytes": budget_context["ceilings"]["maximum_job_output_bytes"],
            "job_output_inodes": budget_context["ceilings"]["maximum_job_output_inodes"],
            "tmpdir_bytes": budget_context["ceilings"]["maximum_tmpdir_bytes"],
            "tmpdir_inodes": budget_context["ceilings"]["maximum_tmpdir_inodes"],
        }
        require(all(expected_high_water[field] <= high_water_limits[field]
                    for field in expected_high_water),
                "bounded replayed sample/final high-water exceeds its frozen ceiling")
        summary_high_water = exact(monitor_summary["high_water"],
                                   set(expected_high_water),
                                   "bounded completion high-water summary")
        require(all(uint(summary_high_water[field],
                         f"bounded completion high-water {field}") == expected_high_water[field]
                    for field in expected_high_water) and
                claimed_final_usage["monitor_high_water"] == expected_high_water,
                "bounded preparation completion high-water differs from independently replayed samples/final tree")
        require(final_usage["generation"]["bytes_used"] +
                remaining_receipt_bytes <=
                budget_context["ceilings"]["maximum_generation_bytes"] and
                final_usage["generation"]["inode_count"] +
                remaining_receipt_inodes <=
                budget_context["ceilings"]["maximum_generation_inodes"],
                "bounded postterminal generation no longer fits its frozen durable receipt reserve")
        require(claimed_final_usage["monitor_report_count"] == 2 * len(jobs),
                "bounded preparation final output/TMPDIR/free-space inventory differs from independent replay")
    result_body = {
        "schema": (PREPARATION_BOUNDED_VERIFICATION_SCHEMA if bounded_preparation
                   else PREPARATION_VERIFICATION_SCHEMA),
        "preparation_raw_sha256": context["preparation_raw_sha256"],
        "preparation_semantic_sha256": context["preparation_semantic_sha256"],
        "source_manifest_raw_sha256": context["source_raw_sha256"],
        "source_manifest_semantic_sha256": context["source_semantic_sha256"],
        "source_tree_sha256": context["source_tree_sha256"],
        "host_id": context["host_id"], "capacity_key_count": 15,
        "capacity_preparation_templates_sha256": schedule_sha,
        "completion_raw_sha256": completion_raw_sha,
        "completion_sha256": completion["completion_sha256"],
        "ledger_raw_sha256": ledger_raw_sha,
        "terminal_head": ledger_value["terminal_head"],
        "entries": reconstructed,
        "complete": True, "qualification_eligible": False,
        "controller_chronology_proven": False,
        "host_verification": {
            "schema": ("allocatbelt.application-capacity-preparation-host-verification.v2"
                       if bounded_preparation else
                       "allocatbelt.application-capacity-preparation-host-verification.v1"),
            "host_id": host_id,
            "boot_id_sha256": context["current_host"]["boot_id_sha256"],
            "kernel_release": context["current_host"]["kernel_release"],
            "allowed_cpu_affinity": context["current_host"]["cpu_affinity"],
            "network_namespace_inode": context["current_host"]["network_namespace_inode"],
            "observed_host_raw_sha256": context["host_context_raw_sha256"],
            "host_verification_sha256": "",
        },
    }
    if bounded_preparation:
        result_body["resource_budget"] = budget_context["pin"]
        result_body["resource_monitor"] = completion["resource_monitor"]
    host_verification_body = {
        key: value for key, value in result_body["host_verification"].items()
        if key != "host_verification_sha256"
    }
    result_body["host_verification"]["host_verification_sha256"] = sha256_bytes(canonical_bytes(host_verification_body))
    receipt = {**result_body, "receipt_sha256": sha256_bytes(canonical_bytes(result_body))}
    if path_map is not None:
        receipt_pin = exact(host_verification_pin, {"path", "raw_sha256", "receipt_sha256"},
                            "capacity host-local verification receipt pin")
        receipt_origin_path = _pin_path(
            receipt_pin["path"], "capacity host-local verification receipt path",
        )
        origin_match = any(
            origin == receipt_origin_path if offline_copy else
            _is_within(origin, receipt_origin_path)
            for origin, _local in path_map
        )
        local_match = any(
            local == receipt_origin_path if offline_copy else
            _is_within(local, receipt_origin_path)
            for _origin, local in path_map
        )
        require(origin_match or local_match,
                "offline capacity path map omits the host-local verification receipt")
        receipt_path = (_map_evidence_path(receipt_origin_path, path_map,
                                           exact=offline_copy)
                        if origin_match else receipt_origin_path)
        host_receipt, _host_raw, host_raw_sha = read_pin(
            {"path": str(receipt_path), "sha256": receipt_pin["raw_sha256"]},
            "capacity host-local verification receipt", MAX_METADATA_BYTES, canonical=True,
        )
        receipt_info = receipt_path.stat(follow_symlinks=False)
        require(stat.S_ISREG(receipt_info.st_mode) and stat.S_IMODE(receipt_info.st_mode) == 0o600 and
                receipt_info.st_uid == os.getuid(),
                "capacity host-local verification receipt must be an owned mode-0600 regular file")
        exact(host_receipt, set(receipt), "capacity host-local verification receipt")
        host_body = {key: value for key, value in host_receipt.items() if key != "receipt_sha256"}
        expected_verification_schema = (PREPARATION_BOUNDED_VERIFICATION_SCHEMA if bounded_preparation
                                        else PREPARATION_VERIFICATION_SCHEMA)
        require(host_receipt.get("schema") == expected_verification_schema and
                host_receipt.get("receipt_sha256") == receipt_pin["receipt_sha256"] == sha256_bytes(canonical_bytes(host_body)) and
                host_receipt.get("complete") is True and host_receipt.get("qualification_eligible") is False and
                host_receipt.get("controller_chronology_proven") is False,
                "capacity host-local verification receipt schema/digest/flags are invalid")
        normalized_host_receipt = dict(host_receipt)
        normalized_host_receipt.pop("receipt_sha256", None)
        replay_receipt = dict(receipt)
        replay_receipt.pop("receipt_sha256", None)
        require(normalized_host_receipt == replay_receipt and host_raw_sha == receipt_pin["raw_sha256"],
                "capacity host-local receipt differs from the independent central ledger/trace/producer replay")
    if offline_preflight is not None:
        for path_text, before in offline_preflight["local_fingerprints"].items():
            path = Path(path_text)
            after = _offline_local_fingerprint(path, "offline evidence final stability")
            require(after == before,
                    f"offline local evidence changed during full replay: {path}")
    return receipt


def _cli_pin(path: Path, raw_sha: str) -> dict[str, str]:
    return {"path": str(path), "sha256": raw_sha}


def verify_capacity_preparation_offline(
    preparation_pin: dict[str, Any], source_root: Path, input_root: Path,
    host_id: str, observed_host_pin: dict[str, Any], output_root: Path,
    completion_pin: dict[str, Any], evidence_path_map: object,
    host_verification_pin: object,
) -> dict[str, Any]:
    """Replay copied capacity evidence and compare the strict host receipt."""
    return verify_capacity_preparation(
        preparation_pin, source_root, input_root, host_id, observed_host_pin,
        output_root, completion_pin, evidence_path_map=evidence_path_map,
        host_verification_pin=host_verification_pin,
    )


def verify_capacity_preparation_bounded(
    preparation_pin: dict[str, Any], resource_budget_pin: dict[str, Any],
    source_root: Path, input_root: Path, host_id: str,
    observed_host_pin: dict[str, Any], output_root: Path,
    completion_pin: dict[str, Any],
) -> dict[str, Any]:
    """Strict host-local replay of one caller-budgeted preparation generation."""
    return verify_capacity_preparation(
        preparation_pin, source_root, input_root, host_id, observed_host_pin,
        output_root, completion_pin, resource_budget_pin=resource_budget_pin,
    )


def verify_capacity_preparation_bounded_offline(
    preparation_pin: dict[str, Any], resource_budget_pin: dict[str, Any],
    source_root: Path, input_root: Path, host_id: str,
    observed_host_pin: dict[str, Any], output_root: Path,
    completion_pin: dict[str, Any], evidence_path_map: object,
    host_verification_pin: object,
) -> dict[str, Any]:
    """Replay bounded copied evidence without sampling coordinator host facts."""
    return verify_capacity_preparation(
        preparation_pin, source_root, input_root, host_id, observed_host_pin,
        output_root, completion_pin, evidence_path_map=evidence_path_map,
        host_verification_pin=host_verification_pin,
        resource_budget_pin=resource_budget_pin, offline_copy=True,
    )


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
    for name in ("run-preparation", "verify-preparation"):
        command = commands.add_parser(name, help=f"{name} the separate pre-Spec 15-context capacity preparation")
        command.add_argument("--preparation", type=Path, required=True)
        command.add_argument("--preparation-sha256", required=True)
        command.add_argument("--source-root", type=Path, required=True)
        command.add_argument("--input-root", type=Path, required=True)
        command.add_argument("--host-id", required=True)
        command.add_argument("--observed-host", type=Path, required=True)
        command.add_argument("--observed-host-sha256", required=True)
        command.add_argument("--output-root", type=Path, required=True)
        if name == "verify-preparation":
            command.add_argument("--completion", type=Path, required=True)
            command.add_argument("--completion-sha256", required=True)
            command.add_argument("--verification-receipt", type=Path)
    for name in ("run-preparation-bounded", "verify-preparation-bounded",
                 "verify-preparation-bounded-offline"):
        command = commands.add_parser(
            name, help=f"{name} the caller-budgeted original pre-Spec 15-context schedule",
        )
        command.add_argument("--preparation", type=Path, required=True)
        command.add_argument("--preparation-sha256", required=True)
        command.add_argument("--resource-budget", type=Path, required=True)
        command.add_argument("--resource-budget-sha256", required=True)
        command.add_argument("--source-root", type=Path, required=True)
        command.add_argument("--input-root", type=Path, required=True)
        command.add_argument("--host-id", required=True)
        command.add_argument("--observed-host", type=Path, required=True)
        command.add_argument("--observed-host-sha256", required=True)
        command.add_argument("--output-root", type=Path, required=True)
        if name != "run-preparation-bounded":
            command.add_argument("--completion", type=Path, required=True)
            command.add_argument("--completion-sha256", required=True)
        if name == "verify-preparation-bounded":
            command.add_argument("--verification-receipt", type=Path)
        if name == "verify-preparation-bounded-offline":
            command.add_argument("--evidence-path-map", type=Path, required=True)
            command.add_argument("--evidence-path-map-sha256", required=True)
            command.add_argument("--host-verification-receipt", type=Path, required=True)
            command.add_argument("--host-verification-raw-sha256", required=True)
            command.add_argument("--host-verification-receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in ("run-preparation-bounded", "verify-preparation-bounded",
                            "verify-preparation-bounded-offline"):
            preparation_pin = _cli_pin(args.preparation, args.preparation_sha256)
            budget_pin = _cli_pin(args.resource_budget, args.resource_budget_sha256)
            observed_pin = _cli_pin(args.observed_host, args.observed_host_sha256)
            if args.command == "run-preparation-bounded":
                result = run_capacity_preparation_bounded(
                    preparation_pin, budget_pin, args.source_root, args.input_root,
                    args.host_id, observed_pin, args.output_root,
                )
            else:
                completion_pin = _cli_pin(args.completion, args.completion_sha256)
                if args.command == "verify-preparation-bounded-offline":
                    map_value, _map_raw, _map_sha = read_pin(
                        {"path": str(args.evidence_path_map),
                         "sha256": args.evidence_path_map_sha256},
                        "bounded preparation evidence path map", MAX_METADATA_BYTES, canonical=True,
                    )
                    receipt_pin = {
                        "path": str(args.host_verification_receipt),
                        "raw_sha256": args.host_verification_raw_sha256,
                        "receipt_sha256": args.host_verification_receipt_sha256,
                    }
                    result = verify_capacity_preparation_bounded_offline(
                        preparation_pin, budget_pin, args.source_root, args.input_root,
                        args.host_id, observed_pin, args.output_root, completion_pin,
                        map_value, receipt_pin,
                    )
                else:
                    result = verify_capacity_preparation_bounded(
                        preparation_pin, budget_pin, args.source_root, args.input_root,
                        args.host_id, observed_pin, args.output_root, completion_pin,
                    )
                if (args.command == "verify-preparation-bounded" and
                        args.verification_receipt is not None):
                    receipt_parent = _safe_root(args.verification_receipt.parent,
                                                "bounded verification receipt parent")
                    completion_parent = _safe_root(args.completion.parent,
                                                   "bounded completion parent")
                    require(receipt_parent == completion_parent,
                            "bounded host receipt must be stored beside its original completion")
                    _check_new_directory(receipt_parent, "bounded verification receipt parent")
                    receipt_raw = canonical_bytes(result)
                    receipt_sha = _write_exclusive(args.verification_receipt, receipt_raw)
                    result = {
                        "result": result,
                        "verification_receipt_pin": {
                            "path": str(args.verification_receipt),
                            "raw_sha256": receipt_sha,
                            "receipt_sha256": result["receipt_sha256"],
                        },
                    }
            sys.stdout.buffer.write(canonical_bytes(result))
            return 0
        if args.command in ("run-preparation", "verify-preparation"):
            preparation_pin = _cli_pin(args.preparation, args.preparation_sha256)
            observed_pin = _cli_pin(args.observed_host, args.observed_host_sha256)
            if args.command == "run-preparation":
                result = run_capacity_preparation(
                    preparation_pin, args.source_root, args.input_root, args.host_id,
                    observed_pin, args.output_root,
                )
            else:
                completion_pin = _cli_pin(args.completion, args.completion_sha256)
                result = verify_capacity_preparation(
                    preparation_pin, args.source_root, args.input_root, args.host_id,
                    observed_pin, args.output_root, completion_pin,
                )
                if args.verification_receipt is not None:
                    receipt_parent = _safe_root(args.verification_receipt.parent,
                                                "capacity verification receipt parent")
                    completion_parent = _safe_root(args.completion.parent,
                                                   "capacity completion parent")
                    require(receipt_parent == completion_parent,
                            "capacity verification receipt must be stored beside its original completion")
                    _check_new_directory(receipt_parent, "capacity verification receipt parent")
                    receipt_raw = canonical_bytes(result)
                    receipt_sha = _write_exclusive(args.verification_receipt, receipt_raw)
                    result = {
                        "result": result,
                        "verification_receipt_pin": {
                            "path": str(args.verification_receipt),
                            "raw_sha256": receipt_sha,
                            "receipt_sha256": result["receipt_sha256"],
                        },
                    }
            sys.stdout.buffer.write(canonical_bytes(result))
            return 0
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
