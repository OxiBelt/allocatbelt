#!/usr/bin/env python3
"""Independently validate one bounded external-application pressure session.

This reader does not accept the driver's claimed pass as evidence. The caller
supplies the frozen recipe digest and expected artifact digests separately;
the reader then rechecks canonical bytes, samples, readiness, overlap and live
process cleanup from the raw event stream.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import contextvars
import hashlib
import importlib.machinery
import json
import os
import re
import signal
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
import types
from typing import Any, Iterator


RECIPE_SCHEMA = "allocatbelt.application-pressure-recipe.v1"
RECIPE_SCHEMA_V2 = "allocatbelt.application-pressure-recipe.v2"
LAUNCH_SCHEMA = "allocatbelt.application-pressure-launch-binding.v1"
PROCESS_BINDING_SCHEMA = "allocatbelt.application-pressure-process-binding.v1"
EVENT_SCHEMA = "allocatbelt.application-pressure-event.v1"
RUN_SCHEMA = "allocatbelt.application-pressure-run.v1"
READBACK_SCHEMA = "allocatbelt.application-pressure-readback.v1"
READBACK_SCHEMA_V2 = "allocatbelt.application-pressure-readback.v2"
CALIBRATION_SCHEMA_V1 = "allocatbelt.application-pressure-contention-calibration.v1"
CALIBRATION_SCHEMA_V2 = "allocatbelt.application-pressure-contention-calibration.v2"
CALIBRATION_REQUEST_SCHEMA_V2 = "allocatbelt.application-pressure-calibration-request.v2"
CALIBRATION_SCOPE_SCHEMA_V2 = "allocatbelt.application-pressure-calibration-scope.v2"
CALIBRATION_SCOPE_RECEIPT_SCHEMA_V2 = "allocatbelt.application-pressure-calibration-scope-readback.v2"
CALIBRATION_HOST_VERIFICATION_SCHEMA_V2 = "allocatbelt.application-pressure-calibration-host-verification.v1"
EVIDENCE_PATH_MAP_SCHEMA_V1 = "allocatbelt.application-pressure-evidence-path-map.v1"
PRESSURE_PAIR_HOST_VERIFICATION_SCHEMA = "allocatbelt.application-pressure-pair-host-verification.v1"
SOURCE5_SOAK_HOST_VERIFICATION_SCHEMA_V2 = "allocatbelt.application-source5-soak-host-verification.v2"
SOURCE5_SOAK_HOST_VERIFICATION_SCHEMA_V3 = "allocatbelt.application-source5-soak-host-verification.v3"
PRESSURE_PAIR_ORIGIN_FACTS_SCHEMA = "allocatbelt.application-pressure-pair-origin-facts.v1"
CAPACITY_BUNDLE_PIN_SCHEMA_V2 = "allocatbelt.application-pressure-capacity-bundle-pin.v2"
CONTEXT_POLICY_BUNDLE_SCHEMA_V2 = "allocatbelt.application-pressure-context-policy-bundle.v2"
CALIBRATION_BINDING_SCHEMA_V2 = "allocatbelt.application-pressure-calibration-binding.v2"
SOURCE5_PRESSURE_CONDITION_SCHEMA = "allocatbelt.application-source5-pressure-condition.v1"
SOURCE5_MANIFEST_SCHEMA = "allocatbelt.application-source-manifest.v5"
SOURCE5_PRESSURE_POLICY_SCHEMA = "allocatbelt.application-pressure-pair-policy.v1"
SOURCE5_COMPOSED_POLICY_SCHEMA = "allocatbelt.application-feedback-resolved-policy.v1"
SOURCE5_CAPACITY_BUNDLE_SCHEMA = "allocatbelt.application-byte-capacity-request.v1"
SOURCE5_INVENTORY_SCHEMA = "allocatbelt.application-source-inventory.v1"
PRESSURE_IO_SCHEMA = "allocatbelt.application-pressure-io-window.v1"
OWNERSHIP_PROTOCOL = "allocatbelt.pressure-worker-ownership.v1"
SOURCE5_PRESSURE_READINESS_RULE_V1 = "allocatbelt.application-source5-pressure-readiness-threshold-rule.v1"
PRESSURE_THRESHOLD_KEYS_V2 = frozenset({
    "cpu_busy_min_basis_points", "disk_write_min_bytes_per_second",
    "disk_queue_or_stall_min_microseconds", "loopback_requests_min_per_second",
    "loopback_latency_p99_max_nanoseconds", "loopback_tx_min_bytes_per_second",
    "loopback_rx_min_bytes_per_second",
})
CAMPAIGN_READINESS_KEYS_V1 = frozenset({
    "minimum_overlap_seconds", "minimum_ready_samples", "maximum_sample_gap_ms",
})
MAX_RECIPE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_LAUNCH_BYTES = 256 * 1024
MAX_EVENTS_BYTES = 512 * 1024 * 1024
MAX_EVENT_LINE_BYTES = 2 * 1024 * 1024
EVENT_TERMINAL_RESERVE_BYTES = 2 * 1024 * 1024
MAX_DURATION_SECONDS = 12000
MAX_SAMPLE_COUNT = 120000
MAX_EVENT_COUNT = 120006
MAX_WORKER_STDERR_RAW_BYTES = 8192
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_OFFLINE_JSON_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_POLICY_BYTES = 8 * 1024 * 1024
MAX_SOURCE_MODULE_BYTES = 16 * 1024 * 1024
MAX_CONTEXT_POLICY_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_SCOPE_RECEIPT_BYTES = 8 * 1024 * 1024
MAX_PRESSURE_PROOF_BYTES = 256 * 1024
MAX_CAPACITY_CONTEXT_BYTES = 1 * 1024 * 1024
MAX_SOURCE5_SOAK_HOST_RECEIPT_BYTES = 32 * 1024 * 1024
MAX_SOURCE5_SOAK_INVENTORY_ENTRIES = 250_000
U64_MAX = (1 << 64) - 1
BLOCK_BYTES = 4096
DRIVER_PATH = Path(__file__).with_name("application-pressure-driver.py")
_EVIDENCE_PATH_MAP_CONTEXT: contextvars.ContextVar[tuple[dict[str, str], set[str]] | None] = contextvars.ContextVar(
    "allocatbelt_pressure_evidence_path_map", default=None,
)
_PRESSURE_OFFLINE_REPLAY_CONTEXT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "allocatbelt_pressure_offline_replay_context", default=None,
)


class ReadbackError(ValueError):
    """A recipe or pressure artifact fails independent validation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReadbackError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ReadbackError(f"value cannot be canonically encoded: {error}") from error
    return (text + "\n").encode("ascii")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_object(value: object) -> str:
    return sha256_bytes(canonical_bytes(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadbackError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReadbackError(f"non-finite JSON constant is forbidden: {value}")


def parse_object(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its finite byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReadbackError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must be one JSON object")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected shape")
    return value


def uint(value: object, label: str, *, positive: bool = False, maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} must be a finite unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def text(value: object, label: str, maximum: int = 4096) -> str:
    require(type(value) is str and 0 < len(value) <= maximum, f"{label} must be a bounded string")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), f"{label} contains a control character")
    return value


def sha256(value: object, label: str) -> str:
    result = text(value, label, 64)
    require(re.fullmatch(r"[0-9a-f]{64}", result) is not None, f"{label} is not lowercase SHA-256")
    return result


def token(value: object, label: str, maximum: int = 128) -> str:
    result = text(value, label, maximum)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", result) is not None,
            f"{label} is not a canonical token")
    return result


def absolute_path(value: object, label: str) -> Path:
    raw = text(value, label)
    path = Path(raw)
    require(path.is_absolute() and str(path) == raw and ".." not in PurePosixPath(raw).parts, f"{label} must be a normalized absolute path")
    return path


def _require_evidence_path_mapped(path: Path | str) -> None:
    context = _EVIDENCE_PATH_MAP_CONTEXT.get()
    if context is None:
        return
    mapping, directory_origins = context
    value = str(Path(path))
    trusted_code_paths = {str(DRIVER_PATH.resolve()), str(Path(__file__).resolve())}
    if value in trusted_code_paths:
        return
    require(
        value in mapping or any(value.startswith(origin + "/") for origin in directory_origins),
        "offline SourceV5 evidence path is absent from the explicit identity path map",
    )


def _require_absolute_evidence_paths_mapped(value: object) -> None:
    """Close over every absolute path passed to SourceV5 replay helpers."""
    if type(value) is dict:
        for item in value.values():
            _require_absolute_evidence_paths_mapped(item)
    elif type(value) is list:
        for item in value:
            _require_absolute_evidence_paths_mapped(item)
    elif type(value) is str and Path(value).is_absolute():
        _require_evidence_path_mapped(value)


def _preflight_capacity_request_paths_v2(request: dict[str, Any]) -> None:
    """Close the capacity producer's nested canonical references before replay."""
    if _EVIDENCE_PATH_MAP_CONTEXT.get() is None:
        return
    _require_absolute_evidence_paths_mapped(request)
    source_pin = exact(request.get("source_manifest"), {"path", "sha256"}, "capacity request SourceV5 manifest pin")
    _require_evidence_path_mapped(absolute_path(source_pin["path"], "capacity request SourceV5 manifest path"))
    context_pin = exact(request.get("context"), {"path", "sha256"}, "capacity request context pin")
    context_path = absolute_path(context_pin["path"], "capacity request context path")
    _require_evidence_path_mapped(context_path)
    context, _context_raw, context_sha = read_canonical(
        context_path, "preflighted capacity context", MAX_CAPACITY_CONTEXT_BYTES,
    )
    require(context_sha == sha256(context_pin["sha256"], "capacity context raw SHA-256"), "preflighted capacity context pin differs")
    _require_absolute_evidence_paths_mapped(context)
    validation_pin = exact(request.get("validation"), {"path", "sha256"}, "capacity request validation pin")
    validation_path = absolute_path(validation_pin["path"], "capacity request validation path")
    _require_evidence_path_mapped(validation_path)
    validation, _validation_raw, validation_sha = read_canonical(
        validation_path, "preflighted capacity validation", 16 * 1024 * 1024,
    )
    require(validation_sha == sha256(validation_pin["sha256"], "capacity validation raw SHA-256"), "preflighted capacity validation pin differs")
    _require_absolute_evidence_paths_mapped(validation)
    expectation_pin = exact(request.get("expectation"), {"path", "sha256"}, "capacity request expectation pin")
    expectation_path = absolute_path(expectation_pin["path"], "capacity request expectation path")
    _require_evidence_path_mapped(expectation_path)
    expectation, _expectation_raw, expectation_sha = read_canonical(
        expectation_path, "preflighted capacity expectation", 2 * 1024 * 1024,
    )
    expected_sha = sha256(expectation_pin["sha256"], "capacity expectation raw SHA-256")
    require(expectation_sha == expected_sha == sha256(request.get("expectation_sha256"), "capacity expectation request SHA-256"), "preflighted capacity expectation pin differs")
    _require_absolute_evidence_paths_mapped(expectation)
    probe_value = expectation.get("construction_probe")
    if probe_value is not None:
        probe = exact(probe_value, {"path", "raw_sha256", "allocator", "binary_sha256"}, "capacity expectation construction-probe pin")
        probe_path = absolute_path(probe["path"], "capacity expectation construction-probe path")
        _require_evidence_path_mapped(probe_path)
        probe_pin = {"path": str(probe_path), "raw_sha256": sha256(probe["raw_sha256"], "capacity construction-probe raw SHA-256")}
        construction_probe, _probe_raw, _probe_sha = _read_raw_pin(
            probe_pin, "preflighted capacity construction probe", 512 * 1024,
        )
        _require_absolute_evidence_paths_mapped(construction_probe)


def _preflight_context_policy_bundle_paths_v2(context_policy_pin_value: object) -> None:
    """Close all composer request/probe/output paths before SourceV5 replay."""
    if _EVIDENCE_PATH_MAP_CONTEXT.get() is None:
        return
    _, bundle, _bundle_raw, _bundle_sha = _read_raw_pin(
        context_policy_pin_value, "preflighted context-policy bundle", MAX_CONTEXT_POLICY_BUNDLE_BYTES,
    )
    exact(bundle, {"schema", "artifact", "members"}, "preflighted context-policy bundle")
    _require_absolute_evidence_paths_mapped(bundle)
    _, shared_policy, _policy_raw, _policy_sha = _read_raw_pin(
        bundle["artifact"], "preflighted shared numeric policy", MAX_POLICY_BYTES,
    )
    _require_absolute_evidence_paths_mapped(shared_policy)
    members = bundle["members"]
    require(type(members) is list and len(members) == 2, "preflighted context-policy bundle must contain two members")
    for index, member_value in enumerate(members):
        member = exact(member_value, {
            "descriptor", "request", "construction_probe", "resolved_policy", "composition_receipt",
        }, f"preflighted context-policy member[{index}]")
        _, request, _request_raw, _request_sha = _read_raw_pin(
            member["request"], f"preflighted composer request[{index}]", 1 * 1024 * 1024,
        )
        _require_absolute_evidence_paths_mapped(request)
        request_probe = exact(request.get("construction_probe"), {
            "path", "raw_sha256", "allocator", "binary_sha256",
        }, f"preflighted composer request[{index}] construction probe")
        member_probe = exact(member["construction_probe"], {
            "path", "raw_sha256", "allocator", "binary_sha256",
        }, f"preflighted context-policy member[{index}] construction probe")
        for label, probe in (("request", request_probe), ("member", member_probe)):
            probe_path = absolute_path(probe["path"], f"preflighted {label} construction probe[{index}] path")
            _require_evidence_path_mapped(probe_path)
        require(request_probe == member_probe, f"preflighted composer request[{index}] and member construction-probe pins differ")
        probe_pin = {
            "path": str(absolute_path(member_probe["path"], f"preflighted member construction probe[{index}] path")),
            "raw_sha256": sha256(member_probe["raw_sha256"], f"preflighted member construction probe[{index}] SHA-256"),
        }
        construction_probe, _probe_raw, _probe_sha = _read_raw_pin(
            probe_pin, f"preflighted composer construction probe[{index}]", 512 * 1024,
        )
        _require_absolute_evidence_paths_mapped(construction_probe)
        for role in ("resolved_policy", "composition_receipt"):
            _, document, _document_raw, _document_sha = _read_raw_pin(
                member[role], f"preflighted composer {role}[{index}]", MAX_CONTEXT_POLICY_BUNDLE_BYTES,
            )
            _require_absolute_evidence_paths_mapped(document)


def _preflight_scope_replay_paths_v2(
    calibration_scope: dict[str, Any], context_policy_pin: object,
    capacity_bundle_pins: object, observed_host_pin: object,
) -> None:
    """Authorize all canonical replay inputs before loading SourceV5 helpers."""
    if _EVIDENCE_PATH_MAP_CONTEXT.get() is None:
        return
    _require_evidence_path_mapped(absolute_path(calibration_scope["source_root"], "preflighted SourceV5 source root"))
    for value, label, maximum in (
        (calibration_scope["condition"], "Source5 pressure condition", 1 * 1024 * 1024),
        (calibration_scope["source_manifest"], "SourceV5 manifest", MAX_SOURCE_BYTES),
        (observed_host_pin, "observed Source5 host", 1 * 1024 * 1024),
    ):
        _, document, _raw, _sha = _read_raw_pin(value, f"preflighted {label}", maximum)
        _require_absolute_evidence_paths_mapped(document)
    capacity = exact(capacity_bundle_pins, {
        "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
    }, "preflighted capacity bundle")
    _require_absolute_evidence_paths_mapped(capacity)
    request_pin = _raw_pin(capacity["request"], "preflighted capacity producer request")
    _, request, _request_raw, _request_sha = _read_raw_pin(
        request_pin, "preflighted capacity producer request", 2 * 1024 * 1024,
    )
    _preflight_capacity_request_paths_v2(request)
    _preflight_context_policy_bundle_paths_v2(calibration_scope["context_policy_bundle"])
    _preflight_context_policy_bundle_paths_v2(context_policy_pin)


def _checked_evidence_path(path: Path | str) -> Path:
    original = Path(path)
    _require_evidence_path_mapped(original)
    return original


def _normalize_evidence_path_map(value: object, source_root_value: object) -> tuple[dict[str, str], set[str]]:
    path_map = exact(value, {"schema", "entries"}, "pressure evidence path map")
    require(path_map["schema"] == EVIDENCE_PATH_MAP_SCHEMA_V1, "unsupported pressure evidence path map schema")
    entries = path_map["entries"]
    require(type(entries) is list and 1 <= len(entries) <= 4096, "pressure evidence path map is empty or oversized")
    normalized: dict[str, str] = {}
    local_paths: set[str] = set()
    directory_origins: set[str] = set()
    previous_origin = ""
    for index, entry in enumerate(entries):
        row = exact(entry, {"origin", "local"}, f"pressure evidence path map[{index}]")
        origin = str(absolute_path(row["origin"], f"evidence origin path[{index}]"))
        local = str(absolute_path(row["local"], f"evidence local path[{index}]"))
        require(origin == local, "non-identity evidence paths are unsupported because SourceV5 pins absolute paths in canonical requests")
        require(origin > previous_origin, "pressure evidence path map origins are not sorted and unique")
        previous_origin = origin
        require(origin not in normalized and local not in local_paths, "pressure evidence path map repeats an origin or aliases local paths")
        local_path = Path(local)
        try:
            local_info = local_path.lstat()
            require(local_path.resolve(strict=True) == local_path and not stat.S_ISLNK(local_info.st_mode), f"evidence local path[{index}] is a symlink or alias")
            require(stat.S_ISREG(local_info.st_mode) or stat.S_ISDIR(local_info.st_mode), f"evidence local path[{index}] is not a regular file or directory")
        except OSError as error:
            raise ReadbackError(f"evidence local path[{index}] is unavailable: {error}") from error
        normalized[origin] = local
        local_paths.add(local)
        if stat.S_ISDIR(local_info.st_mode):
            directory_origins.add(origin)
    normalized_source_root = str(source_root_value) if isinstance(source_root_value, Path) else source_root_value
    source_root = str(absolute_path(normalized_source_root, "offline SourceV5 origin root"))
    require(source_root in normalized and source_root in directory_origins, "pressure evidence map omits its SourceV5 origin root directory")
    return normalized, directory_origins


def _stat_key(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    path = _checked_evidence_path(path)
    try:
        require(path.resolve(strict=True) == path, f"{label} path traverses a symlink or alias")
        path_info = path.lstat()
        require(stat.S_ISREG(path_info.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise ReadbackError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(path_info), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its hard byte cap")
        parts: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(block, f"{label} was truncated during readback")
            parts.append(block)
            count += len(block)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before) == _stat_key(after_fd) == _stat_key(after_path) and count == before.st_size, f"{label} changed during readback")
        raw = b"".join(parts)
        return raw, sha256_bytes(raw)
    finally:
        os.close(descriptor)


def read_canonical(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], bytes, str]:
    raw, digest = read_stable(path, label, maximum)
    value = parse_object(raw, label, maximum)
    require(raw == canonical_bytes(value), f"{label} is not canonical JSON")
    return value, raw, digest


def _validate_recipe(value: object, expected_sha: str) -> dict[str, Any]:
    base_keys = {
        "schema", "identity", "files", "process", "host", "storage", "network",
        "schedule", "artifact_budget", "pressure_calibration", "readiness_thresholds", "script_hashes",
        "condition_sha256", "recipe_sha256",
    }
    require(type(value) is dict, "frozen pressure recipe must be an object")
    recipe_schema = value.get("schema")
    if recipe_schema == RECIPE_SCHEMA:
        recipe = exact(value, base_keys, "frozen pressure recipe")
    elif recipe_schema == RECIPE_SCHEMA_V2:
        recipe = exact(value, base_keys | {"calibration_scope_v2"}, "frozen pressure recipe v2")
    else:
        raise ReadbackError("unsupported pressure recipe schema")
    body = {key: value for key, value in recipe.items() if key != "recipe_sha256"}
    calculated = digest_object(body)
    require(sha256(recipe["recipe_sha256"], "recipe SHA-256") == calculated == expected_sha, "recipe differs from the separately supplied frozen SHA-256")
    identity = exact(recipe["identity"], {"host_id", "run_id", "pair_id", "condition_id", "member", "nonce", "allocator", "executor", "phase"}, "recipe identity")
    require(identity["phase"] == "external_pressure" and re.fullmatch(r"[0-9a-f]{32}", text(identity["nonce"], "recipe nonce", 32)) is not None, "recipe is not bound to one external-pressure process")
    files = exact(recipe["files"], {"source_manifest", "application_binary", "policy", "application_capacity_calibration"}, "recipe raw input files")
    for label, record in files.items():
        record = exact(record, {"path", "raw_sha256"} | ({"mode", "size"} if label == "application_binary" else set()), f"recipe input {label}")
        absolute_path(record["path"], f"recipe {label} path")
        sha256(record["raw_sha256"], f"recipe {label} raw SHA-256")
    require(files["application_capacity_calibration"]["raw_sha256"] != recipe["pressure_calibration"]["raw_sha256"], "app-byte calibration and pressure-contention calibration hashes were conflated")
    process = exact(recipe["process"], {"executable_path", "application_tmpdir_path"}, "expected application process")
    require(process["executable_path"] == files["application_binary"]["path"], "application executable path differs from pinned binary")
    app_tmpdir = str(absolute_path(process["application_tmpdir_path"], "application TMPDIR path"))
    schedule = exact(recipe["schedule"], {
        "seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds",
        "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds",
        "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points",
        "pressure_cpu_affinity", "application_cpu_affinity", "disk_bytes_per_second",
        "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes",
    }, "recipe schedule")
    duration = uint(schedule["duration_seconds"], "pressure duration", positive=True, maximum=MAX_DURATION_SECONDS)
    interval_ms = uint(schedule["sample_interval_ms"], "sample interval", positive=True, maximum=1000)
    require(interval_ms >= 100 and duration * 1000 % interval_ms == 0, "recipe sample schedule is invalid")
    count = duration * 1000 // interval_ms
    require(count <= MAX_SAMPLE_COUNT, "recipe sample schedule exceeds the reader cap")
    uint(schedule["total_deadline_seconds"], "total deadline", positive=True, maximum=14400)
    uint(schedule["startup_deadline_seconds"], "startup deadline", positive=True, maximum=10)
    uint(schedule["term_deadline_seconds"], "TERM deadline", positive=True, maximum=30)
    uint(schedule["kill_deadline_seconds"], "KILL deadline", positive=True, maximum=15)
    uint(schedule["minimum_overlap_seconds"], "minimum overlap", positive=True, maximum=duration)
    uint(schedule["startup_ready_windows"], "startup ready windows", positive=True, maximum=10)
    require(schedule["total_deadline_seconds"] >= schedule["startup_deadline_seconds"] + duration + schedule["term_deadline_seconds"] + schedule["kill_deadline_seconds"], "recipe total deadline omits a bounded phase")
    for key in ("cpu_duty_basis_points", "disk_bytes_per_second", "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes", "seed"):
        uint(schedule[key], f"schedule {key}", positive=True)
    require(schedule["cpu_duty_basis_points"] <= 10000 and schedule["scratch_file_bytes"] <= 1024 * 1024 * 1024, "recipe pressure intensity exceeds its bound")
    require(schedule["scratch_file_bytes"] >= BLOCK_BYTES and schedule["scratch_file_bytes"] % BLOCK_BYTES == 0, "recipe scratch size is not block aligned")
    require(schedule["disk_bytes_per_second"] <= 512 * 1024 * 1024, "recipe disk pressure exceeds its per-second bound")
    disk_target_per_window = schedule["disk_bytes_per_second"] * interval_ms // 1000
    require(disk_target_per_window >= BLOCK_BYTES, "recipe disk rate is too sparse for its sample cadence")
    disk_actual_per_window = ((disk_target_per_window + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES
    require(disk_actual_per_window * count <= 64 * 1024**3, "rounded per-window pressure writes exceed the 64 GiB schedule bound")
    require(schedule["network_requests_per_second"] <= 100000 and schedule["network_payload_bytes"] <= 65536 and schedule["network_payload_bytes"] >= 16, "recipe loopback intensity exceeds its per-request bound")
    require(schedule["network_requests_per_second"] * interval_ms >= 1000, "recipe loopback request rate is too sparse for its sample cadence")
    require(schedule["network_requests_per_second"] * schedule["network_payload_bytes"] * 2 <= 64 * 1024**2 and schedule["network_requests_per_second"] * schedule["network_payload_bytes"] * 2 * duration <= 64 * 1024**3, "recipe loopback traffic exceeds its cumulative bound")
    cpu_pressure = _cpu_list(schedule["pressure_cpu_affinity"], "pressure CPU affinity")
    cpu_application = _cpu_list(schedule["application_cpu_affinity"], "application CPU affinity")
    host = exact(recipe["host"], {
        "kernel_release", "boot_id_sha256", "allowed_cpu_affinity", "pressure_cpu_affinity",
        "application_cpu_affinity", "application_storage", "pressure_scratch", "network",
    }, "host binding")
    text(host["kernel_release"], "frozen kernel release", 256)
    sha256(host["boot_id_sha256"], "frozen boot identity hash")
    allowed = host["allowed_cpu_affinity"]
    require(type(allowed) is list and 1 <= len(allowed) <= 4096, "captured host CPU affinity is empty or oversized")
    allowed = [uint(cpu, "captured host CPU", maximum=65535) for cpu in allowed]
    require(allowed == sorted(set(allowed)), "captured host CPU affinity is not canonical")
    require(host["allowed_cpu_affinity"] == allowed, "captured host CPU affinity is malformed")
    require(host["pressure_cpu_affinity"] == cpu_pressure and host["application_cpu_affinity"] == cpu_application, "host CPU affinity differs from the frozen schedule")
    require(set(cpu_pressure) <= set(allowed) and set(cpu_application) <= set(allowed), "frozen CPU sets exceed captured host affinity")
    storage = exact(recipe["storage"], {
        "application_io_paths", "pressure_scratch_path", "output_minimum_free_bytes",
        "application_device", "application_mount_id", "backing_chain", "non_tmpfs",
    }, "storage binding")
    require(storage["non_tmpfs"] is True and storage["application_device"] != "0:0", "application disk pressure is not bound to a real non-tmpfs device")
    app_paths = storage["application_io_paths"]
    require(type(app_paths) is list and 1 <= len(app_paths) <= 16, "frozen application I/O path set is sparse or oversized")
    app_paths = [str(absolute_path(value, "frozen application I/O path")) for value in app_paths]
    require(len(set(app_paths)) == len(app_paths), "frozen application I/O paths repeat")
    require(app_tmpdir in app_paths, "frozen application TMPDIR is absent from application storage paths")
    scratch_path = str(absolute_path(storage["pressure_scratch_path"], "frozen pressure scratch path"))
    require(uint(storage["output_minimum_free_bytes"], "frozen free-space floor", positive=True) > 0, "frozen free-space floor is invalid")
    chain = _device_chain(storage["backing_chain"], storage["application_device"])
    artifact_budget = exact(recipe["artifact_budget"], {
        "sample_count", "maximum_sample_line_bytes", "sample_events_bytes",
        "terminal_reserve_bytes", "maximum_event_bytes",
    }, "recipe event artifact budget")
    require(artifact_budget == _artifact_budget(schedule, chain), "frozen event artifact budget differs from independently recomputed bounds")
    require(type(host["application_storage"]) is list and len(host["application_storage"]) == len(app_paths), "application storage inventory is sparse")
    for index, item in enumerate(host["application_storage"]):
        _validate_storage_record(item, app_paths[index], storage["application_device"], storage["application_mount_id"], chain, f"application storage[{index}]")
    scratch_record = _validate_storage_record(host["pressure_scratch"], scratch_path, storage["application_device"], storage["application_mount_id"], chain, "pressure scratch storage")
    require(scratch_record["filesystem_type"] not in ("tmpfs", "ramfs", "overlay"), "pressure scratch is on an in-memory/overlay filesystem")
    network = exact(recipe["network"], {
        "address_family", "destination", "source", "interface", "ifindex", "route",
        "network_namespace_inode", "shared_kernel", "physical_nic_claimed", "claim",
    }, "network binding")
    require(network["address_family"] == "AF_INET" and network["destination"] == "127.0.0.1" and network["source"] == "127.0.0.1" and network["interface"] == "lo", "network witness is not IPv4 loopback")
    require(network["shared_kernel"] is True and network["physical_nic_claimed"] is False and network["claim"] == "ipv4_loopback_shared_kernel_only", "network recipe claims physical NIC pressure")
    require(network["network_namespace_inode"] == host["network"]["network_namespace_inode"], "host and network namespace identities differ")
    require(network == host["network"], "host and process network route evidence differs")
    route = network["route"]
    exact(route, {"dst", "dev", "source"}, "IPv4 loopback route")
    require(route.get("dst") == "127.0.0.1" and route.get("dev") == "lo" and route.get("source") == "127.0.0.1", "frozen route does not target IPv4 loopback on lo")
    uint(network["ifindex"], "loopback ifindex", positive=True)
    uint(network["network_namespace_inode"], "network namespace inode", positive=True)
    calibration = exact(recipe["pressure_calibration"], {"path", "raw_sha256"}, "pressure-contention calibration binding")
    absolute_path(calibration["path"], "pressure-contention calibration path")
    calibration_sha = sha256(calibration["raw_sha256"], "pressure-contention calibration raw SHA-256")
    calibration_scope_v2 = None
    if recipe_schema == RECIPE_SCHEMA_V2:
        calibration_scope_v2 = exact(recipe["calibration_scope_v2"], {
            "schema", "scope_receipt", "validator_sha256", "condition", "context_policy", "capacity_bundle_pins",
            "observed_host", "context_policy_sha256",
        }, "context calibration v2 recipe binding")
        require(calibration_scope_v2["schema"] == CALIBRATION_BINDING_SCHEMA_V2, "unsupported context calibration v2 recipe binding")
        calibration_scope_v2["scope_receipt"] = _scope_receipt_pin_v2(calibration_scope_v2["scope_receipt"], "context calibration scope receipt")
        calibration_scope_v2["condition"] = _raw_pin(calibration_scope_v2["condition"], "Source5 pressure condition")
        calibration_scope_v2["context_policy"] = _raw_pin(calibration_scope_v2["context_policy"], "per-job context policy bundle")
        calibration_scope_v2["observed_host"] = _raw_pin(calibration_scope_v2["observed_host"], "observed Source5 host")
        calibration_scope_v2["context_policy_sha256"] = sha256(calibration_scope_v2["context_policy_sha256"], "numeric context policy digest")
        calibration_scope_v2["validator_sha256"] = sha256(calibration_scope_v2["validator_sha256"], "recipe scope validator SHA-256")
        capacity_pin = exact(calibration_scope_v2["capacity_bundle_pins"], {
            "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
        }, "context calibration v2 capacity bundle")
        require(capacity_pin["schema"] == CAPACITY_BUNDLE_PIN_SCHEMA_V2, "unsupported pressure capacity bundle pin schema")
        source_bundle_pin = _raw_pin(capacity_pin["source_manifest"], "capacity bundle SourceV5 manifest")
        artifact_bundle_pin = _raw_pin(capacity_pin["artifact"], "capacity bundle prepared TSV")
        require(source_bundle_pin["path"] == files["source_manifest"]["path"] and source_bundle_pin["raw_sha256"] == files["source_manifest"]["raw_sha256"], "capacity bundle uses different SourceV5 manifest bytes")
        require(artifact_bundle_pin["path"] == files["application_capacity_calibration"]["path"] and artifact_bundle_pin["raw_sha256"] == files["application_capacity_calibration"]["raw_sha256"], "capacity bundle TSV differs from the exact application capacity input")
        calibration_scope_v2["capacity_bundle_pins"] = capacity_pin
        policy_bundle, _, policy_bundle_rawsha = read_canonical(
            Path(calibration_scope_v2["context_policy"]["path"]), "per-job context policy bundle", MAX_CONTEXT_POLICY_BUNDLE_BYTES,
        )
        require(policy_bundle_rawsha == calibration_scope_v2["context_policy"]["raw_sha256"], "per-job context policy bundle changed")
        exact(policy_bundle, {"schema", "artifact", "members"}, "per-job context policy bundle")
        require(policy_bundle["schema"] == CONTEXT_POLICY_BUNDLE_SCHEMA_V2, "unsupported per-job context policy bundle schema")
        policy_artifact_pin = _raw_pin(policy_bundle["artifact"], "per-job shared policy artifact")
        require(policy_artifact_pin["path"] == files["policy"]["path"] and policy_artifact_pin["raw_sha256"] == files["policy"]["raw_sha256"], "recipe policy file differs from the context-policy bundle artifact")
    thresholds = exact(recipe["readiness_thresholds"], {
        "cpu_busy_min_basis_points", "disk_write_min_bytes_per_second",
        "disk_queue_or_stall_min_microseconds", "loopback_requests_min_per_second",
        "loopback_latency_p99_max_nanoseconds", "loopback_tx_min_bytes_per_second",
        "loopback_rx_min_bytes_per_second",
    }, "numeric readiness thresholds")
    for key, value in thresholds.items():
        uint(value, f"readiness threshold {key}", positive=True)
    require(thresholds["cpu_busy_min_basis_points"] <= 10000, "CPU busy threshold exceeds 100 percent")
    hashes = exact(recipe["script_hashes"], {"driver_sha256", "reader_sha256"}, "script hashes")
    sha256(hashes["driver_sha256"], "driver SHA-256")
    sha256(hashes["reader_sha256"], "reader SHA-256")
    if calibration_scope_v2 is not None:
        require(calibration_scope_v2["validator_sha256"] == hashes["reader_sha256"], "recipe calibration scope validator differs from its pinned reader")
    condition_material = {
        "host_id": identity["host_id"],
        "condition_id": identity["condition_id"],
        "source_manifest_sha256": files["source_manifest"]["raw_sha256"],
        "policy_sha256": files["policy"]["raw_sha256"],
        "application_capacity_calibration_sha256": files["application_capacity_calibration"]["raw_sha256"],
        "host": {
            "kernel_release": host["kernel_release"],
            "boot_id_sha256": host["boot_id_sha256"],
            "allowed_cpu_affinity": host["allowed_cpu_affinity"],
            "pressure_cpu_affinity": host["pressure_cpu_affinity"],
            "application_cpu_affinity": host["application_cpu_affinity"],
        },
        "storage": {
            "device": storage["application_device"],
            "mount_id": storage["application_mount_id"],
            "backing_chain": chain,
        },
        "network": host["network"],
        "schedule": schedule,
        "pressure_calibration_sha256": calibration_sha,
        "readiness_thresholds": thresholds,
    }
    condition = sha256(recipe["condition_sha256"], "condition SHA-256")
    require(condition == digest_object(condition_material), "condition digest does not bind the immutable schedule and host/storage/network controls")
    result = {"identity": identity, "schedule": schedule, "storage": storage, "network": network, "thresholds": thresholds, "artifact_budget": artifact_budget, "files": files, "calibration_sha256": calibration_sha, "condition_sha256": condition, "script_hashes": hashes}
    if calibration_scope_v2 is not None:
        result["calibration_scope_v2"] = calibration_scope_v2
    return result


def _cpu_list(value: object, label: str) -> list[int]:
    require(type(value) is list and 1 <= len(value) <= 64, f"{label} is empty or exceeds its bound")
    result = [uint(item, label, maximum=65535) for item in value]
    require(result == sorted(set(result)), f"{label} is not sorted and unique")
    return result


def _artifact_budget(schedule: dict[str, Any], backing_chain: list[dict[str, Any]]) -> dict[str, int]:
    interval_ns = schedule["sample_interval_ms"] * 1_000_000
    minimum_interval_ns = interval_ns - max(1_000_000, interval_ns // 100)
    cpus = schedule["pressure_cpu_affinity"]
    cpu_max = U64_MAX
    maximum_aggregate_cpu = cpu_max * len(cpus)
    maximum_requests = (schedule["network_requests_per_second"] * schedule["sample_interval_ms"] + 999) // 1000 + 2
    maximum_rate = U64_MAX * 1_000_000_000 // minimum_interval_ns
    maximum_disk_rate = U64_MAX * 512 * 1_000_000_000 // minimum_interval_ns
    maximum_loopback_rate = maximum_requests * 1_000_000_000 // minimum_interval_ns
    maximum_disk_window = max(
        BLOCK_BYTES,
        ((schedule["disk_bytes_per_second"] * schedule["sample_interval_ms"] // 1000 + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES,
    )
    cpu_counters = [
        {
            "cpu": cpu,
            "total_ticks": cpu_max,
            "idle_ticks": cpu_max,
            "busy_ticks": cpu_max,
            "busy_basis_points": 10000,
        }
        for cpu in cpus
    ]
    cpu_generators = [
        {
            "cpu": cpu,
            "thread_cpu_time_ns": cpu_max,
            "spin_witness": cpu_max,
            "start_monotonic_ns": cpu_max,
            "end_monotonic_ns": cpu_max,
        }
        for cpu in cpus
    ]
    worker_io = {
        **{f"cpu:{cpu}": {"write_bytes_delta": cpu_max, "syscw_delta": cpu_max} for cpu in cpus},
        "disk": {"write_bytes_delta": cpu_max, "syscw_delta": cpu_max},
        "loopback": {"write_bytes_delta": cpu_max, "syscw_delta": cpu_max},
    }
    sample = {
        "schema": EVENT_SCHEMA,
        "kind": "sample",
        "sequence": MAX_SAMPLE_COUNT - 1,
        "interval_start_monotonic_ns": cpu_max,
        "interval_end_monotonic_ns": cpu_max,
        "app_active": True,
        "cpu": {
            "per_cpu": cpu_counters,
            "total_ticks": maximum_aggregate_cpu,
            "idle_ticks": maximum_aggregate_cpu,
            "busy_basis_points": 10000,
        },
        "cpu_psi_delta_microseconds": cpu_max,
        "block": {
            "writes_completed": cpu_max,
            "sectors_written": cpu_max,
            "write_milliseconds": cpu_max,
            "io_milliseconds": cpu_max,
            "weighted_io_milliseconds": cpu_max,
            "in_flight": cpu_max,
            "write_bytes": cpu_max * 512,
        },
        "io_psi_delta_microseconds": cpu_max,
        "block_device_chain": backing_chain,
        "loopback_counters": {
            key: cpu_max for key in (
                "rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
                "tx_bytes", "tx_packets", "tx_errors", "tx_dropped",
            )
        },
        "loopback": {
            "schema": PRESSURE_IO_SCHEMA,
            "role": "loopback",
            "recipe_sha256": "f" * 64,
            "sequence": MAX_SAMPLE_COUNT - 1,
            "start_monotonic_ns": cpu_max,
            "end_monotonic_ns": cpu_max,
            "requests_completed": maximum_requests,
            "bytes_on_wire": maximum_requests * schedule["network_payload_bytes"] * 2,
            "latency_histogram": [maximum_requests] * 64,
            "p99_upper_latency_nanoseconds": 1 << 63,
        },
        "pressure_generators": {
            "cpu": cpu_generators,
            "disk": {
                "write_bytes": maximum_disk_window,
                "write_mode": "o_direct",
                "fdatasync_count": 1,
                "fdatasync_time_nanoseconds": cpu_max,
                "start_monotonic_ns": cpu_max,
                "end_monotonic_ns": cpu_max,
            },
        },
        "worker_process_io": worker_io,
        "readiness": {
            "cpu_ready": True,
            "disk_ready": True,
            "loopback_ready": True,
            "all_ready": True,
            "cpu_busy_basis_points": 10000,
            "disk_write_bytes_per_second": maximum_disk_rate,
            "disk_queue_or_stall_microseconds": cpu_max * 1001,
            "loopback_requests_per_second": maximum_loopback_rate,
            "loopback_latency_p99_upper_nanoseconds": 1 << 63,
            "loopback_tx_bytes_per_second": maximum_rate,
            "loopback_rx_bytes_per_second": maximum_rate,
        },
    }
    maximum_sample_line_bytes = len(canonical_bytes(sample))
    require(maximum_sample_line_bytes <= MAX_EVENT_LINE_BYTES, "sample row exceeds the reader's event-line bound")
    sample_count = schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"]
    sample_events_bytes = sample_count * maximum_sample_line_bytes
    maximum_event_bytes = sample_events_bytes + EVENT_TERMINAL_RESERVE_BYTES
    require(maximum_event_bytes <= MAX_EVENTS_BYTES, "frozen pressure schedule exceeds the 512 MiB event and terminal-evidence budget")
    return {
        "sample_count": sample_count,
        "maximum_sample_line_bytes": maximum_sample_line_bytes,
        "sample_events_bytes": sample_events_bytes,
        "terminal_reserve_bytes": EVENT_TERMINAL_RESERVE_BYTES,
        "maximum_event_bytes": maximum_event_bytes,
    }


def _validate_storage_record(
    value: object, expected_path: str, expected_device: str,
    expected_mount_id: int, expected_chain: list[dict[str, Any]], label: str,
) -> dict[str, Any]:
    record = exact(value, {"path", "device", "mount", "backing_chain", "filesystem_type", "tmpfs"}, label)
    path = str(absolute_path(record["path"], f"{label} path"))
    require(path == expected_path, f"{label} path differs from the frozen I/O path")
    require(record["device"] == expected_device and record["backing_chain"] == expected_chain, f"{label} device/backing chain differs")
    require(record["tmpfs"] is False and record["filesystem_type"] not in ("tmpfs", "ramfs", "overlay"), f"{label} is on an in-memory/overlay filesystem")
    mount = exact(record["mount"], {
        "mount_id", "parent_mount_id", "device", "root", "mountpoint", "mount_options",
        "filesystem", "source", "super_options",
    }, f"{label} mount record")
    require(uint(mount["mount_id"], f"{label} mount id", positive=True) == expected_mount_id, f"{label} mount id differs from frozen storage")
    uint(mount["parent_mount_id"], f"{label} parent mount id", positive=True)
    require(mount["device"] == expected_device and mount["filesystem"] == record["filesystem_type"], f"{label} mount device/filesystem differs")
    mountpoint = str(absolute_path(mount["mountpoint"], f"{label} mountpoint"))
    require(path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/"), f"{label} path is outside its frozen mountpoint")
    text(mount["root"], f"{label} mount root", 4096)
    text(mount["source"], f"{label} mount source", 4096)
    for key in ("mount_options", "super_options"):
        options = mount[key]
        require(type(options) is list and options and all(type(item) is str and item for item in options), f"{label} {key} are malformed")
    return record


def _device_chain(value: object, device: str) -> list[dict[str, Any]]:
    require(type(value) is list and 1 <= len(value) <= 32, "block backing chain is sparse or oversized")
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        require(type(item) is dict, f"block chain[{index}] must be an object")
        record = exact(item, {"device", "name", "sysfs_path", "partition"} if "partition" in item else {"device", "name", "sysfs_path"}, f"block chain[{index}]")
        current = text(record["device"], "block device identity", 32)
        require(re.fullmatch(r"[0-9]+:[0-9]+", current) is not None and current not in seen, "block backing chain repeats or malforms a device")
        seen.add(current)
        text(record["name"], "block kernel name", 256)
        path = text(record["sysfs_path"], "block sysfs path", 4096)
        require(path.startswith("/sys/devices/"), "block sysfs path is outside /sys/devices")
        if "partition" in record:
            uint(record["partition"], "block partition number", positive=True)
        result.append(record)
    require(device in seen, "application block device is absent from its backing chain")
    require(result == sorted(result, key=lambda item: item["device"]), "block backing chain is not canonical")
    return result


def _validate_calibration(recipe: dict[str, Any], *, offline_context: dict[str, Any] | None = None) -> dict[str, str] | None:
    if recipe["schema"] == RECIPE_SCHEMA_V2:
        return _validate_calibration_v2_recipe(recipe, offline_context=offline_context)
    binding = recipe["pressure_calibration"]
    path = Path(binding["path"])
    value, _, raw_sha = read_canonical(path, "pressure contention calibration", 64 * 1024 * 1024)
    require(raw_sha == binding["raw_sha256"], "pressure contention calibration raw digest differs from frozen recipe")
    exact(value, {
        "schema", "identity", "schedule_sha256", "raw_inputs", "driver_sha256", "host", "storage",
        "network", "worker_sessions", "samples", "summary", "suggested_readiness_thresholds",
        "worker_cleanup", "scratch_file_removed", "start_monotonic_ns", "finish_monotonic_ns", "deadlines",
        "calibration_sha256",
    }, "pressure contention calibration")
    require(value["schema"] == "allocatbelt.application-pressure-contention-calibration.v1", "unsupported pressure calibration schema")
    calibration_body = {key: item for key, item in value.items() if key != "calibration_sha256"}
    require(sha256(value["calibration_sha256"], "calibration digest") == digest_object(calibration_body), "pressure calibration internal digest is invalid")
    require(value["identity"]["host_id"] == recipe["identity"]["host_id"] and value["identity"]["condition_id"] == recipe["identity"]["condition_id"], "pressure calibration host/condition differs from recipe")
    identity = exact(value["identity"], {"host_id", "pair_id", "condition_id", "phase"}, "pressure calibration identity")
    require(identity["phase"] == "calibration" and identity["pair_id"] == recipe["identity"]["pair_id"], "pressure calibration pair identity differs from recipe")
    require(sha256(value["driver_sha256"], "calibration driver hash") == recipe["script_hashes"]["driver_sha256"], "pressure calibration came from different driver bytes")
    profile_keys = (
        "seed", "sample_interval_ms", "startup_deadline_seconds", "term_deadline_seconds",
        "kill_deadline_seconds", "cpu_duty_basis_points", "pressure_cpu_affinity",
        "application_cpu_affinity", "disk_bytes_per_second", "scratch_file_bytes",
        "network_requests_per_second", "network_payload_bytes",
    )
    profile = {key: recipe["schedule"][key] for key in profile_keys}
    require(value["schedule_sha256"] == digest_object(profile), "pressure calibration intensity differs from frozen recipe")
    files = recipe["files"]
    require(value["raw_inputs"] == {
        "source_manifest_sha256": files["source_manifest"]["raw_sha256"],
        "policy_sha256": files["policy"]["raw_sha256"],
        "application_capacity_calibration_sha256": files["application_capacity_calibration"]["raw_sha256"],
    }, "pressure calibration raw inputs differ or app-byte calibration was conflated")
    host = value["host"]
    expected_host = recipe["host"]
    require(
        host["kernel_release"] == expected_host["kernel_release"]
        and host["boot_id_sha256"] == expected_host["boot_id_sha256"]
        and host["allowed_cpu_affinity"] == expected_host["allowed_cpu_affinity"]
        and host["pressure_cpu_affinity"] == expected_host["pressure_cpu_affinity"]
        and host["application_cpu_affinity"] == expected_host["application_cpu_affinity"],
        "pressure calibration was measured on a different host/kernel/CPU set",
    )
    require(value["network"] == expected_host["network"], "pressure calibration loopback route/namespace differs from frozen recipe")
    require(value["storage"] == {
        "application_device": recipe["storage"]["application_device"],
        "mount_id": recipe["storage"]["application_mount_id"],
        "backing_chain": recipe["storage"]["backing_chain"],
    }, "pressure calibration application block device differs from frozen recipe")
    _validate_calibration_samples(value["samples"], recipe, value)
    sessions = value["worker_sessions"]
    cleanup = value["worker_cleanup"]
    require(type(sessions) is list and len(sessions) == len(recipe["schedule"]["pressure_cpu_affinity"]) + 2 and type(cleanup) is list and len(cleanup) == len(sessions), "pressure calibration worker cleanup is sparse")
    session_by_key: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in sessions:
        worker = exact(item, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id"}, "calibration worker session")
        role = text(worker["role"], "calibration worker role", 16)
        cpu = uint(worker["cpu"], "calibration worker CPU", maximum=65535) if role == "cpu" else None
        require(role in ("cpu", "disk", "loopback") and (role != "cpu" or cpu in recipe["schedule"]["pressure_cpu_affinity"]), "calibration worker session role/CPU differs")
        pid = uint(worker["pid"], "calibration worker PID", positive=True, maximum=(1 << 31) - 1)
        ticks = uint(worker["start_ticks"], "calibration worker start ticks", positive=True)
        require(worker["pgid"] == pid and worker["session_id"] == pid, "calibration worker was not isolated in its own session")
        key = (role, cpu)
        require(key not in session_by_key, "calibration repeats a worker session")
        session_by_key[key] = {**worker, "pid": pid, "start_ticks": ticks}
    expected_sessions = {("cpu", cpu) for cpu in recipe["schedule"]["pressure_cpu_affinity"]} | {("disk", None), ("loopback", None)}
    require(set(session_by_key) == expected_sessions, "calibration worker set differs from frozen pressure resources")
    cleanup_by_key: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in cleanup:
        record = exact(item, {
            "role", "cpu", "pid", "start_ticks", "pgid", "session_id", "exit_code",
            "cleanup_started_monotonic_ns", "term_deadline_monotonic_ns", "kill_deadline_monotonic_ns",
            "term_error", "kill_error", "reap_error", "alive_after_cleanup",
            "term_sent_monotonic_ns", "kill_sent_monotonic_ns", "reaped_monotonic_ns", "stderr_output",
            "stderr_raw_base64", "stderr_raw_sha256", "stderr_raw_bytes", "stderr_raw_truncated", "stderr_read_error",
        }, "calibration worker cleanup")
        key = (record["role"], record["cpu"])
        require(key in session_by_key and key not in cleanup_by_key, "calibration cleanup invents or duplicates a worker")
        session = session_by_key[key]
        require(all(record[field] == session[field] for field in ("pid", "start_ticks", "pgid", "session_id")), "calibration cleanup PID/start identity differs")
        raw_stderr = _validate_worker_stderr_capture(record, "calibration worker")
        require(_worker_exit_status_valid(record) and record["alive_after_cleanup"] is False and all(record[field] is None for field in ("term_error", "kill_error", "reap_error")) and raw_stderr == b"", "calibration worker cleanup failed")
        cleanup_started = uint(record["cleanup_started_monotonic_ns"], "calibration cleanup start", positive=True)
        term_deadline = uint(record["term_deadline_monotonic_ns"], "calibration TERM deadline", positive=True)
        kill_deadline = uint(record["kill_deadline_monotonic_ns"], "calibration KILL deadline", positive=True)
        reaped = uint(record["reaped_monotonic_ns"], "calibration reap time", positive=True)
        require(term_deadline == cleanup_started + recipe["schedule"]["term_deadline_seconds"] * 1_000_000_000, "calibration TERM deadline differs from recipe")
        if record["term_sent_monotonic_ns"] is not None:
            require(uint(record["term_sent_monotonic_ns"], "calibration TERM send time", positive=True) <= term_deadline, "calibration TERM deadline was exceeded")
        if record["kill_sent_monotonic_ns"] is not None:
            killed = uint(record["kill_sent_monotonic_ns"], "calibration KILL send time", positive=True)
            require(killed >= term_deadline and killed <= kill_deadline, "calibration KILL escalation deadline is invalid")
        require(reaped <= kill_deadline, "calibration worker reap exceeded its cleanup deadline")
        _require_pid_reaped(record["pid"], record["start_ticks"], "calibration worker")
        cleanup_by_key[key] = record
    require(set(cleanup_by_key) == expected_sessions and value["scratch_file_removed"] is True, "pressure calibration omitted worker cleanup or scratch removal")
    calibration_start = uint(value["start_monotonic_ns"], "calibration start", positive=True)
    calibration_end = uint(value["finish_monotonic_ns"], "calibration finish", positive=True)
    deadlines = exact(value["deadlines"], {"startup_seconds", "total_seconds", "term_seconds", "kill_seconds"}, "pressure calibration deadlines")
    require(deadlines["startup_seconds"] == recipe["schedule"]["startup_deadline_seconds"] and deadlines["term_seconds"] == recipe["schedule"]["term_deadline_seconds"] and deadlines["kill_seconds"] == recipe["schedule"]["kill_deadline_seconds"], "pressure calibration startup/cleanup deadlines differ from frozen profile")
    calibration_duration = len(value["samples"]) * recipe["schedule"]["sample_interval_ms"] * 1_000_000
    require(3_000_000_000 <= calibration_duration <= 120_000_000_000, "pressure calibration is outside the finite 3..120 second window")
    require(uint(deadlines["total_seconds"], "calibration total deadline", positive=True, maximum=200) * 1_000_000_000 >= calibration_duration + (deadlines["startup_seconds"] + deadlines["term_seconds"] + deadlines["kill_seconds"]) * 1_000_000_000, "pressure calibration total deadline omits a bounded phase")
    require(calibration_end >= calibration_start and calibration_end - calibration_start <= deadlines["total_seconds"] * 1_000_000_000, "pressure calibration exceeded its finite total deadline")
    # Recompute the threshold proposal from every raw measurement. The
    # selected recipe thresholds are numeric readiness limits only.
    summary = _measurement_summary(value["samples"])
    require(summary == value["summary"], "pressure calibration summary differs from raw measured windows")
    proposed = _propose(summary)
    require(proposed == value["suggested_readiness_thresholds"], "pressure calibration threshold proposal differs from its measured windows")
    chosen = recipe["readiness_thresholds"]
    for lower_key in (
        "cpu_busy_min_basis_points", "disk_write_min_bytes_per_second",
        "disk_queue_or_stall_min_microseconds", "loopback_requests_min_per_second",
        "loopback_tx_min_bytes_per_second", "loopback_rx_min_bytes_per_second",
    ):
        require(chosen[lower_key] <= proposed[lower_key], f"selected readiness threshold {lower_key} exceeds measured calibration")
    require(chosen["loopback_latency_p99_max_nanoseconds"] >= proposed["loopback_latency_p99_max_nanoseconds"], "selected loopback readiness threshold is stricter than calibration")


def _median(values: list[int]) -> int:
    require(values, "cannot summarize an empty measured series")
    values = sorted(values)
    middle = len(values) // 2
    return values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) // 2


def _derive_readiness(sample: dict[str, Any], thresholds: dict[str, int]) -> dict[str, Any]:
    start = uint(sample["interval_start_monotonic_ns"], "sample start", positive=True)
    end = uint(sample["interval_end_monotonic_ns"], "sample end", positive=True)
    interval = end - start
    require(interval > 0, "pressure sample interval is empty")
    cpu = sample["cpu"]
    busy = cpu["busy_basis_points"]
    cpu_ready = busy >= thresholds["cpu_busy_min_basis_points"]
    block = sample["block"]
    disk_bps = block["write_bytes"] * 1_000_000_000 // interval
    disk_stall_us = block["weighted_io_milliseconds"] * 1000 + sample["io_psi_delta_microseconds"]
    disk_evidence = block["in_flight"] > 0 or disk_stall_us >= thresholds["disk_queue_or_stall_min_microseconds"]
    disk_ready = disk_bps >= thresholds["disk_write_min_bytes_per_second"] and block["writes_completed"] > 0 and disk_evidence
    loop = sample["loopback"]
    reqs = loop["requests_completed"]
    rps = reqs * 1_000_000_000 // interval
    tx = sample["loopback_counters"]["tx_bytes"] * 1_000_000_000 // interval
    rx = sample["loopback_counters"]["rx_bytes"] * 1_000_000_000 // interval
    net_ready = (
        rps >= thresholds["loopback_requests_min_per_second"]
        and loop["p99_upper_latency_nanoseconds"] <= thresholds["loopback_latency_p99_max_nanoseconds"]
        and tx >= thresholds["loopback_tx_min_bytes_per_second"]
        and rx >= thresholds["loopback_rx_min_bytes_per_second"]
        and sample["loopback_counters"]["rx_errors"] == 0
        and sample["loopback_counters"]["tx_errors"] == 0
        and sample["loopback_counters"]["rx_dropped"] == 0
        and sample["loopback_counters"]["tx_dropped"] == 0
    )
    return {
        "cpu_ready": cpu_ready, "disk_ready": disk_ready, "loopback_ready": net_ready,
        "all_ready": cpu_ready and disk_ready and net_ready,
        "cpu_busy_basis_points": busy,
        "disk_write_bytes_per_second": disk_bps,
        "disk_queue_or_stall_microseconds": disk_stall_us,
        "loopback_requests_per_second": rps,
        "loopback_latency_p99_upper_nanoseconds": loop["p99_upper_latency_nanoseconds"],
        "loopback_tx_bytes_per_second": tx,
        "loopback_rx_bytes_per_second": rx,
    }


def _validate_sample(sample: dict[str, Any], recipe: dict[str, Any], sequence: int) -> dict[str, Any]:
    exact(sample, {
        "schema", "kind", "sequence", "interval_start_monotonic_ns", "interval_end_monotonic_ns",
        "app_active", "cpu", "cpu_psi_delta_microseconds", "block", "io_psi_delta_microseconds",
        "block_device_chain", "loopback_counters", "loopback", "pressure_generators",
        "worker_process_io", "readiness",
    }, f"sample[{sequence}]")
    require(sample["schema"] == EVENT_SCHEMA and sample["kind"] == "sample" and sample["sequence"] == sequence, "sample schema/kind/sequence differs")
    start = uint(sample["interval_start_monotonic_ns"], "sample start", positive=True)
    end = uint(sample["interval_end_monotonic_ns"], "sample end", positive=True)
    require(end > start, "sample interval is empty")
    require(type(sample["app_active"]) is bool, "sample application activity is not boolean")
    cpu = exact(sample["cpu"], {"per_cpu", "total_ticks", "idle_ticks", "busy_basis_points"}, "CPU sample")
    per_cpu = cpu["per_cpu"]
    require(type(per_cpu) is list and len(per_cpu) == len(recipe["schedule"]["pressure_cpu_affinity"]), "CPU counter sample is sparse")
    cpu_total = 0
    cpu_idle = 0
    for index, item in enumerate(per_cpu):
        row = exact(item, {"cpu", "total_ticks", "idle_ticks", "busy_ticks", "busy_basis_points"}, f"CPU counter[{index}]")
        require(row["cpu"] == recipe["schedule"]["pressure_cpu_affinity"][index], "CPU counter affinity/order differs from recipe")
        total = uint(row["total_ticks"], "CPU total ticks", positive=True)
        idle = uint(row["idle_ticks"], "CPU idle ticks")
        busy_ticks = uint(row["busy_ticks"], "CPU busy ticks")
        require(idle <= total and busy_ticks == total - idle and row["busy_basis_points"] == busy_ticks * 10000 // total, "CPU counter arithmetic is inconsistent")
        cpu_total += total
        cpu_idle += idle
    require(cpu["total_ticks"] == cpu_total and cpu["idle_ticks"] == cpu_idle and cpu["busy_basis_points"] == (cpu_total - cpu_idle) * 10000 // cpu_total, "aggregate CPU counters are inconsistent")
    uint(sample["cpu_psi_delta_microseconds"], "CPU PSI delta")
    uint(sample["io_psi_delta_microseconds"], "I/O PSI delta")
    block = exact(sample["block"], {
        "writes_completed", "sectors_written", "write_milliseconds", "io_milliseconds",
        "weighted_io_milliseconds", "in_flight", "write_bytes",
    }, "block device counters")
    for key in block:
        uint(block[key], f"block counter {key}")
    require(block["write_bytes"] == block["sectors_written"] * 512, "block bytes differ from the kernel sectors counter")
    require(block["writes_completed"] > 0 and block["write_bytes"] > 0, "application block device made no write progress")
    require(sample["block_device_chain"] == recipe["storage"]["backing_chain"], "sample block backing chain differs from frozen recipe")
    loop_counters = exact(sample["loopback_counters"], {"rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"}, "loopback interface counters")
    for key in loop_counters:
        uint(loop_counters[key], f"loopback counter {key}")
    require(loop_counters["rx_bytes"] > 0 and loop_counters["tx_bytes"] > 0, "lo counters show no IPv4 loopback traffic")
    loop = exact(sample["loopback"], {
        "schema", "role", "recipe_sha256", "sequence", "start_monotonic_ns", "end_monotonic_ns",
        "requests_completed", "bytes_on_wire", "latency_histogram", "p99_upper_latency_nanoseconds",
    }, "loopback pressure witness")
    require(loop["schema"] == PRESSURE_IO_SCHEMA and loop["role"] == "loopback" and loop["sequence"] == sequence, "loopback worker witness identity differs")
    require(loop["recipe_sha256"] == recipe["recipe_sha256"], "loopback generator witness belongs to another recipe")
    uint(loop["start_monotonic_ns"], "loopback worker start", positive=True)
    uint(loop["end_monotonic_ns"], "loopback worker end", positive=True)
    requests = uint(loop["requests_completed"], "loopback completed requests", positive=True)
    maximum_requests = (recipe["schedule"]["network_requests_per_second"] * recipe["schedule"]["sample_interval_ms"] + 999) // 1000 + 2
    require(requests <= maximum_requests, "loopback request count exceeds the frozen per-window intensity bound")
    payload_bytes = recipe["schedule"]["network_payload_bytes"] * 2
    require(loop["bytes_on_wire"] == requests * payload_bytes, "loopback bytes do not match the frozen payload/count")
    histogram = loop["latency_histogram"]
    require(type(histogram) is list and len(histogram) == 64 and sum(uint(item, "latency bucket") for item in histogram) == requests, "loopback latency histogram differs from successful requests")
    wanted = (requests * 99 + 99) // 100
    cumulative = 0
    p99 = None
    for index, count in enumerate(histogram):
        cumulative += count
        if cumulative >= wanted:
            p99 = 1 << index
            break
    require(p99 is not None and loop["p99_upper_latency_nanoseconds"] == p99, "loopback p99 latency is not supported by the histogram")
    generators = exact(sample["pressure_generators"], {"cpu", "disk"}, "pressure generator evidence")
    cpu_generators = generators["cpu"]
    require(type(cpu_generators) is list and len(cpu_generators) == len(recipe["schedule"]["pressure_cpu_affinity"]), "CPU generator witnesses are sparse")
    for index, item in enumerate(cpu_generators):
        cpu_event = exact(item, {"cpu", "thread_cpu_time_ns", "spin_witness", "start_monotonic_ns", "end_monotonic_ns"}, f"CPU generator[{index}]")
        require(cpu_event["cpu"] == recipe["schedule"]["pressure_cpu_affinity"][index], "CPU generator affinity differs from frozen set")
        uint(cpu_event["thread_cpu_time_ns"], "CPU generator time", positive=True)
        uint(cpu_event["spin_witness"], "CPU generator spin witness")
        worker_start = uint(cpu_event["start_monotonic_ns"], "CPU generator sample start", positive=True)
        worker_end = uint(cpu_event["end_monotonic_ns"], "CPU generator sample end", positive=True)
        require(worker_end > worker_start and worker_start <= end and worker_end >= start, "CPU generator interval does not overlap its independent CPU sample")
    disk_generator = exact(generators["disk"], {
        "write_bytes", "write_mode", "fdatasync_count", "fdatasync_time_nanoseconds", "start_monotonic_ns", "end_monotonic_ns",
    }, "disk generator evidence")
    disk_generated = uint(disk_generator["write_bytes"], "disk generator bytes", positive=True)
    require(disk_generated % BLOCK_BYTES == 0 and disk_generator["write_mode"] == "o_direct" and disk_generator["fdatasync_count"] == 1, "disk generator did not issue one directly synchronized bounded window")
    uint(disk_generator["fdatasync_time_nanoseconds"], "disk generator sync time")
    disk_start = uint(disk_generator["start_monotonic_ns"], "disk generator sample start", positive=True)
    disk_end = uint(disk_generator["end_monotonic_ns"], "disk generator sample end", positive=True)
    require(disk_end > disk_start and disk_start <= end and disk_end >= start, "disk generator interval does not overlap its independent block sample")
    expected_worker_labels = {*(f"cpu:{cpu_id}" for cpu_id in recipe["schedule"]["pressure_cpu_affinity"]), "disk", "loopback"}
    worker_io = exact(sample["worker_process_io"], expected_worker_labels, "independent worker /proc I/O counters")
    disk_io = exact(worker_io["disk"], {"write_bytes_delta", "syscw_delta"}, "disk worker I/O counter")
    require(uint(disk_io["write_bytes_delta"], "disk worker write bytes", positive=True) > 0 and uint(disk_io["syscw_delta"], "disk worker write syscalls", positive=True) > 0, "disk worker /proc counters show no write progress")
    for label, item in worker_io.items():
        exact(item, {"write_bytes_delta", "syscw_delta"}, f"{label} worker I/O counters")
        uint(item["write_bytes_delta"], f"{label} write bytes")
        uint(item["syscw_delta"], f"{label} write syscalls")
    recomputed = _derive_readiness(sample, recipe["readiness_thresholds"])
    require(recomputed == sample["readiness"], "driver readiness claim differs from independent numeric recomputation")
    return {"start": start, "end": end, "app_active": sample["app_active"], "readiness": recomputed}


def _validate_calibration_samples(samples: object, recipe: dict[str, Any], calibration: dict[str, Any]) -> None:
    require(type(samples) is list and len(samples) >= 3, "pressure calibration measurements are sparse")
    cpus = recipe["schedule"]["pressure_cpu_affinity"]
    expected_worker_io = {*(f"cpu:{cpu_id}" for cpu_id in cpus), "disk", "loopback"}
    sample_ns = recipe["schedule"]["sample_interval_ms"] * 1_000_000
    prior_end: int | None = None
    prior_cpu_time: dict[int, int] = {}
    saw_block_pressure = False
    for sequence, sample in enumerate(samples):
        exact(sample, {
            "schema", "sequence", "interval_start_monotonic_ns", "interval_end_monotonic_ns",
            "app_active", "cpu", "cpu_psi_delta_microseconds", "block", "io_psi_delta_microseconds",
            "block_device_chain", "loopback_counters", "loopback", "pressure_generators", "worker_process_io",
        }, f"calibration sample[{sequence}]")
        require(sample["schema"] == EVENT_SCHEMA and sample["sequence"] == sequence and sample["app_active"] is False, "calibration sample identity/phase differs")
        start = uint(sample["interval_start_monotonic_ns"], "calibration sample start", positive=True)
        end = uint(sample["interval_end_monotonic_ns"], "calibration sample end", positive=True)
        cadence_tolerance_ns = max(1_000_000, sample_ns // 100)
        require(sample_ns - cadence_tolerance_ns <= end - start <= sample_ns + max(500_000_000, sample_ns), "calibration sample cadence is sparse")
        require(prior_end is None or start == prior_end, "calibration samples have a gap or overlap")
        prior_end = end
        io_psi = uint(sample["io_psi_delta_microseconds"], "calibration I/O PSI delta")
        uint(sample["cpu_psi_delta_microseconds"], "calibration CPU PSI delta")
        cpu = exact(sample["cpu"], {"per_cpu", "total_ticks", "idle_ticks", "busy_basis_points"}, "calibration CPU counters")
        require(type(cpu["per_cpu"]) is list and len(cpu["per_cpu"]) == len(cpus), "calibration CPU counters are sparse")
        total_ticks = 0
        idle_ticks = 0
        for index, row in enumerate(cpu["per_cpu"]):
            counter = exact(row, {"cpu", "total_ticks", "idle_ticks", "busy_ticks", "busy_basis_points"}, f"calibration CPU counter[{index}]")
            require(counter["cpu"] == cpus[index], "calibration CPU counter affinity differs")
            total = uint(counter["total_ticks"], "calibration CPU ticks", positive=True)
            idle = uint(counter["idle_ticks"], "calibration CPU idle ticks")
            busy = uint(counter["busy_ticks"], "calibration CPU busy ticks")
            require(idle <= total and busy == total - idle and counter["busy_basis_points"] == busy * 10000 // total, "calibration CPU counter arithmetic differs")
            total_ticks += total
            idle_ticks += idle
        require(cpu["total_ticks"] == total_ticks and cpu["idle_ticks"] == idle_ticks and cpu["busy_basis_points"] == (total_ticks - idle_ticks) * 10000 // total_ticks, "calibration CPU aggregate differs")
        block = exact(sample["block"], {"writes_completed", "sectors_written", "write_milliseconds", "io_milliseconds", "weighted_io_milliseconds", "in_flight", "write_bytes"}, "calibration block counters")
        for key, value in block.items():
            uint(value, f"calibration block {key}")
        require(block["write_bytes"] == block["sectors_written"] * 512 and block["write_bytes"] > 0 and block["writes_completed"] > 0, "calibration block counters show no writes")
        saw_block_pressure = saw_block_pressure or block["in_flight"] > 0 or block["weighted_io_milliseconds"] > 0 or io_psi > 0
        require(sample["block_device_chain"] == calibration["storage"]["backing_chain"], "calibration sample block chain differs")
        counters = exact(sample["loopback_counters"], {"rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"}, "calibration lo counters")
        for key, value in counters.items():
            uint(value, f"calibration lo {key}")
        require(counters["rx_bytes"] > 0 and counters["tx_bytes"] > 0 and all(counters[key] == 0 for key in ("rx_errors", "rx_dropped", "tx_errors", "tx_dropped")), "calibration loopback counters show no clean traffic")
        loop = exact(sample["loopback"], {"schema", "role", "recipe_sha256", "sequence", "start_monotonic_ns", "end_monotonic_ns", "requests_completed", "bytes_on_wire", "latency_histogram", "p99_upper_latency_nanoseconds"}, "calibration loopback witness")
        require(loop["schema"] == PRESSURE_IO_SCHEMA and loop["role"] == "loopback" and loop["sequence"] == sequence, "calibration loopback witness identity differs")
        sha256(loop["recipe_sha256"], "calibration worker recipe SHA")
        requests = uint(loop["requests_completed"], "calibration loopback requests", positive=True)
        require(loop["bytes_on_wire"] == requests * recipe["schedule"]["network_payload_bytes"] * 2, "calibration loopback byte count differs")
        histogram = loop["latency_histogram"]
        require(type(histogram) is list and len(histogram) == 64 and sum(uint(item, "calibration latency bucket") for item in histogram) == requests, "calibration latency histogram is incomplete")
        wanted = (requests * 99 + 99) // 100
        cumulative = 0
        p99 = None
        for index, count in enumerate(histogram):
            cumulative += count
            if cumulative >= wanted:
                p99 = 1 << index
                break
        require(p99 == loop["p99_upper_latency_nanoseconds"], "calibration p99 differs from its histogram")
        generators = exact(sample["pressure_generators"], {"cpu", "disk"}, "calibration generators")
        require(type(generators["cpu"]) is list and len(generators["cpu"]) == len(cpus), "calibration CPU worker evidence is sparse")
        for index, item in enumerate(generators["cpu"]):
            worker = exact(item, {"cpu", "thread_cpu_time_ns", "spin_witness", "start_monotonic_ns", "end_monotonic_ns"}, f"calibration CPU generator[{index}]")
            require(worker["cpu"] == cpus[index], "calibration CPU worker used an unexpected CPU")
            cpu_time = uint(worker["thread_cpu_time_ns"], "calibration worker CPU time", positive=True)
            require(cpu_time > prior_cpu_time.get(cpus[index], 0), "calibration CPU worker made no progress")
            prior_cpu_time[cpus[index]] = cpu_time
            uint(worker["spin_witness"], "calibration CPU spin witness")
        disk_worker = exact(generators["disk"], {"write_bytes", "write_mode", "fdatasync_count", "fdatasync_time_nanoseconds", "start_monotonic_ns", "end_monotonic_ns"}, "calibration disk generator")
        require(uint(disk_worker["write_bytes"], "calibration disk generator bytes", positive=True) % BLOCK_BYTES == 0 and disk_worker["write_mode"] == "o_direct" and disk_worker["fdatasync_count"] == 1, "calibration disk generator is incomplete")
        uint(disk_worker["fdatasync_time_nanoseconds"], "calibration disk sync time")
        worker_io = exact(sample["worker_process_io"], expected_worker_io, "calibration worker /proc I/O")
        for label, item in worker_io.items():
            counters = exact(item, {"write_bytes_delta", "syscw_delta"}, f"calibration {label} I/O")
            uint(counters["write_bytes_delta"], f"calibration {label} bytes")
            uint(counters["syscw_delta"], f"calibration {label} syscalls")
        require(worker_io["disk"]["write_bytes_delta"] > 0 and worker_io["disk"]["syscw_delta"] > 0, "calibration disk process counters show no writes")
    require(saw_block_pressure, "calibration contains no independent block queue/stall witness")


def _measurement_summary(samples: object) -> dict[str, int]:
    require(type(samples) is list and len(samples) >= 3, "calibration windows are sparse")
    cpu: list[int] = []
    disk: list[int] = []
    stall: list[int] = []
    requests: list[int] = []
    latency: list[int] = []
    tx: list[int] = []
    rx: list[int] = []
    for item in samples:
        block = item["block"]
        interval = item["interval_end_monotonic_ns"] - item["interval_start_monotonic_ns"]
        require(interval > 0, "pressure calibration interval is empty")
        cpu.append(item["cpu"]["busy_basis_points"])
        disk.append(block["write_bytes"] * 1_000_000_000 // interval)
        stall.append(block["weighted_io_milliseconds"] * 1000 + item["io_psi_delta_microseconds"])
        requests.append(item["loopback"]["requests_completed"] * 1_000_000_000 // interval)
        latency.append(item["loopback"]["p99_upper_latency_nanoseconds"])
        tx.append(item["loopback_counters"]["tx_bytes"] * 1_000_000_000 // interval)
        rx.append(item["loopback_counters"]["rx_bytes"] * 1_000_000_000 // interval)
    return {
        "sample_count": len(samples),
        "cpu_busy_basis_points_median": _median(cpu),
        "disk_write_bytes_per_second_median": _median(disk),
        "disk_queue_or_stall_microseconds_median": _median(stall),
        "loopback_requests_per_second_median": _median(requests),
        "loopback_latency_p99_upper_nanoseconds_median": _median(latency),
        "loopback_tx_bytes_per_second_median": _median(tx),
        "loopback_rx_bytes_per_second_median": _median(rx),
    }


def _propose(summary: dict[str, int]) -> dict[str, int]:
    result = {
        "cpu_busy_min_basis_points": summary["cpu_busy_basis_points_median"] * 8000 // 10000,
        "disk_write_min_bytes_per_second": summary["disk_write_bytes_per_second_median"] * 8000 // 10000,
        "disk_queue_or_stall_min_microseconds": max(1, summary["disk_queue_or_stall_microseconds_median"] * 5000 // 10000),
        "loopback_requests_min_per_second": summary["loopback_requests_per_second_median"] * 8000 // 10000,
        "loopback_latency_p99_max_nanoseconds": summary["loopback_latency_p99_upper_nanoseconds_median"] * 20000 // 10000,
        "loopback_tx_min_bytes_per_second": summary["loopback_tx_bytes_per_second_median"] * 8000 // 10000,
        "loopback_rx_min_bytes_per_second": summary["loopback_rx_bytes_per_second_median"] * 8000 // 10000,
    }
    require(all(type(item) is int and item > 0 for item in result.values()), "pressure calibration did not produce positive numeric readiness values")
    return result


def _raw_pin(value: object, label: str) -> dict[str, Any]:
    pin = exact(value, {"path", "raw_sha256"}, f"{label} raw pin")
    path = absolute_path(pin["path"], f"{label} path")
    _require_evidence_path_mapped(path)
    digest = sha256(pin["raw_sha256"], f"{label} raw SHA-256")
    return {"path": str(path), "raw_sha256": digest}


def _scope_receipt_pin_v2(value: object, label: str) -> dict[str, Any]:
    pin = exact(value, {"path", "raw_sha256", "scope_sha256"}, f"{label} pin")
    normalized = _raw_pin({"path": pin["path"], "raw_sha256": pin["raw_sha256"]}, label)
    normalized["scope_sha256"] = sha256(pin["scope_sha256"], f"{label} scope digest")
    return normalized


def _read_raw_pin(value: object, label: str, maximum: int) -> tuple[dict[str, Any], dict[str, Any], bytes, str]:
    pin = _raw_pin(value, label)
    parsed, raw, actual = read_canonical(Path(pin["path"]), label, maximum)
    require(actual == pin["raw_sha256"], f"{label} bytes differ from their raw pin")
    return pin, parsed, raw, actual


def _source_record(source: dict[str, Any], relative: str, label: str) -> dict[str, Any]:
    records = source.get("source", {}).get("files")
    require(type(records) is list, "SourceV5 typed source inventory is missing")
    matches = [item for item in records if type(item) is dict and item.get("path") == relative]
    require(len(matches) == 1, f"SourceV5 inventory must contain one {label} entry")
    record = exact(matches[0], {"path", "kind", "mode", "sha256", "size"}, f"SourceV5 {label} inventory entry")
    require(record["path"] == relative and record["kind"] == "file" and record["mode"] in ("100644", "100755"), f"SourceV5 {label} must be a regular typed source file")
    sha256(record["sha256"], f"SourceV5 {label} source SHA-256")
    uint(record["size"], f"SourceV5 {label} source size", maximum=MAX_SOURCE_MODULE_BYTES)
    return record


def _load_source_module(source_root: Path, source: dict[str, Any], relative: str, label: str) -> tuple[Any, str]:
    record = _source_record(source, relative, label)
    rel = PurePosixPath(relative)
    require(not rel.is_absolute() and ".." not in rel.parts and "\\" not in relative, f"SourceV5 {label} path is unsafe")
    path = source_root.joinpath(*rel.parts)
    try:
        require(path.resolve(strict=True) == path, f"SourceV5 {label} path is a symlink or alias")
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == (0o755 if record["mode"] == "100755" else 0o644), f"SourceV5 {label} physical mode differs from inventory")
        raw, actual = read_stable(path, f"SourceV5 {label}", MAX_SOURCE_MODULE_BYTES)
    except OSError as error:
        raise ReadbackError(f"cannot read SourceV5 {label}: {error}") from error
    require(actual == record["sha256"] and len(raw) == record["size"], f"SourceV5 {label} bytes differ from typed inventory")
    module_name = f"allocatbelt_source5_{label.replace('-', '_')}_{actual[:16]}"
    spec = importlib.machinery.ModuleSpec(module_name, loader=None, origin=str(path))
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    module.__loader__ = None
    module.__spec__ = spec
    sys.modules[module_name] = module
    try:
        captured_code = compile(raw, str(path), "exec", dont_inherit=True)
        exec(captured_code, module.__dict__)
    except Exception as error:
        sys.modules.pop(module_name, None)
        raise ReadbackError(f"verified SourceV5 {label} bytes could not be executed: {type(error).__name__}") from error
    return module, actual



def _capture_offline_typed_inventory(
    source_root: Path, records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Hash declared SourceV5 members without Git, /proc, or child processes."""
    actual: list[dict[str, Any]] = []
    for index, entry_value in enumerate(records):
        entry = exact(entry_value, {"path", "kind", "mode", "sha256", "size"},
                      f"offline SourceV5 inventory[{index}]")
        relative = PurePosixPath(text(entry["path"], "offline SourceV5 inventory path", 4096))
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == entry["path"] and entry["kind"] == "file" and
                entry["mode"] in ("100644", "100755"),
                "offline SourceV5 inventory contains an unsafe or non-regular path")
        path = source_root.joinpath(*relative.parts)
        try:
            require(path.resolve(strict=True) == path,
                    "offline SourceV5 inventory member traverses an alias")
            info = path.lstat()
            actual_mode = stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode)
            require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                    actual_mode == int(entry["mode"], 8),
                    "offline SourceV5 inventory member mode/type differs")
        except OSError as error:
            raise ReadbackError(f"offline SourceV5 inventory member is unavailable: {error}") from error
        raw, actual_sha = read_stable(path, "offline SourceV5 inventory member",
                                      MAX_SOURCE_MODULE_BYTES)
        require(len(raw) == entry["size"] and actual_sha == entry["sha256"],
                "offline SourceV5 inventory member bytes differ from the original typed pin")
        actual.append(dict(entry))
    return actual


def _source5_stack(
    source_pin_value: object, source_root_value: object, *, verify_git_commit: bool = True,
) -> dict[str, Any]:
    source_pin, source, source_raw, source_raw_sha = _read_raw_pin(
        source_pin_value, "SourceV5 manifest", MAX_SOURCE_BYTES,
    )
    _require_absolute_evidence_paths_mapped(source)
    require(source.get("schema") == SOURCE5_MANIFEST_SCHEMA, "context calibration requires the exact SourceV5 manifest schema")
    source_semantic = sha256(source.get("manifest_sha256"), "SourceV5 semantic manifest SHA-256")
    source_body = {key: value for key, value in source.items() if key != "manifest_sha256"}
    require(source_semantic == sha256_bytes(canonical_bytes(source_body)), "SourceV5 semantic manifest digest is invalid")
    source_identity = exact(source.get("source"), {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "SourceV5 source identity")
    source_tree = sha256(source_identity["source_tree_sha256"], "SourceV5 source tree SHA-256")
    commit = text(source_identity["git_commit"], "SourceV5 Git commit", 64)
    require(re.fullmatch(r"[0-9a-f]{40,64}", commit) is not None, "SourceV5 Git commit is malformed")
    source_root = absolute_path(source_root_value, "SourceV5 source root")
    source_root_access = _checked_evidence_path(source_root)
    try:
        require(source_root_access.resolve(strict=True) == source_root_access and stat.S_ISDIR(source_root_access.lstat().st_mode), "SourceV5 source root is a symlink or non-directory")
    except OSError as error:
        raise ReadbackError(f"SourceV5 source root is unavailable: {error}") from error
    inventory_module, inventory_sha = _load_source_module(
        source_root_access, source, "scripts/application-source-inventory.py", "source-inventory",
    )
    try:
        records = inventory_module.validate_records({"schema": SOURCE5_INVENTORY_SCHEMA, "entries": source_identity["files"]})
        require(records == source_identity["files"] and inventory_module.digest_records(records) == source_tree, "SourceV5 typed source inventory digest is invalid")
        if verify_git_commit:
            actual_inventory = inventory_module.inventory(source_root_access, timeout_seconds=120.0)
            require(actual_inventory.get("entries") == records and inventory_module.digest_inventory(actual_inventory) == source_tree, "live SourceV5 source tree differs from its complete typed inventory")
        else:
            actual_records = _capture_offline_typed_inventory(source_root_access, records)
            require(actual_records == records and inventory_module.digest_records(actual_records) == source_tree,
                    "offline SourceV5 raw source members differ from the complete typed inventory")
    except Exception as error:
        if isinstance(error, ReadbackError):
            raise
        raise ReadbackError(f"SourceV5 source inventory replay failed: {type(error).__name__}: {error}") from error
    if verify_git_commit:
        try:
            result = subprocess.run(
                ["git", "-C", str(source_root_access), "rev-parse", "HEAD"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReadbackError(f"cannot verify SourceV5 Git commit: {error}") from error
        require(result.returncode == 0 and result.stdout.decode("ascii", errors="strict").strip() == commit, "live SourceV5 Git commit differs from its manifest")
    harness = exact(source.get("qualification_harness"), {
        "campaign_controller", "feedback_validator", "byte_capacity_producer", "pressure_driver",
        "pressure_validator", "soak_recipe_builder", "soak_validator", "soak_runner",
    }, "SourceV5 qualification harness")
    expected_paths = {
        "campaign_controller": "scripts/application-campaign.py",
        "feedback_validator": "scripts/application-feedback-readback.py",
        "byte_capacity_producer": "scripts/application-byte-capacity.py",
        "pressure_driver": "scripts/application-pressure-driver.py",
        "pressure_validator": "scripts/application-pressure-readback.py",
        "soak_recipe_builder": "scripts/application-soak-recipe.py",
        "soak_validator": "scripts/application-soak-readback.py",
        "soak_runner": "scripts/run-application-soak.sh",
    }
    harness_values = {}
    for name, relative in expected_paths.items():
        pin = exact(harness[name], {"path", "sha256"}, f"SourceV5 harness {name}")
        require(pin["path"] == relative, f"SourceV5 harness {name} path changed")
        harness_values[name] = sha256(pin["sha256"], f"SourceV5 harness {name} SHA-256")
        record = _source_record(source, relative, name)
        require(record["sha256"] == harness_values[name], f"SourceV5 harness {name} pin differs from inventory")
    require(harness_values["pressure_driver"] == read_stable(DRIVER_PATH, "pressure driver", MAX_SOURCE_MODULE_BYTES)[1], "SourceV5 pressure driver pin differs from the active driver bytes")
    require(harness_values["pressure_validator"] == read_stable(Path(__file__).resolve(), "pressure validator", MAX_SOURCE_MODULE_BYTES)[1], "SourceV5 pressure validator pin differs from the active reader bytes")
    producer, producer_sha = _load_source_module(
        source_root_access, source, "scripts/application-byte-capacity.py", "byte-capacity-producer",
    )
    feedback_reader, feedback_reader_sha = _load_source_module(
        source_root_access, source, "scripts/application-feedback-readback.py", "feedback-validator",
    )
    composer, composer_sha = _load_source_module(
        source_root_access, source, "scripts/application-feedback-composition.py", "feedback-composer",
    )
    require(harness_values["byte_capacity_producer"] == producer_sha and harness_values["feedback_validator"] == feedback_reader_sha, "SourceV5 producer/feedback reader differs from its harness pins")
    return {
        "source_pin": source_pin, "source": source, "source_raw": source_raw,
        "source_raw_sha256": source_raw_sha, "source_semantic_sha256": source_semantic,
        "source_tree_sha256": source_tree, "source_root": source_root,
        "source_root_access": source_root_access,
        "inventory_sha256": inventory_sha, "producer": producer,
        "producer_sha256": producer_sha, "feedback_reader": feedback_reader,
        "feedback_reader_sha256": feedback_reader_sha, "composer": composer,
        "composer_sha256": composer_sha,
    }


def _capacity_key_v2(value: object, label: str = "pressure capacity key") -> dict[str, str]:
    key = exact(value, {"host_id", "workload", "profile", "calibration_id"}, label)
    result = {field: text(key[field], f"{label} {field}", 96) for field in ("host_id", "workload", "profile", "calibration_id")}
    require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", item) is not None for item in result.values()), f"{label} has a malformed token")
    return result


def _verify_capacity_bundle_v2(
    source_stack: dict[str, Any], capacity_bundle_pins_value: object,
    expected_source_pin: dict[str, Any], observed_host: dict[str, Any],
) -> dict[str, Any]:
    bundle = exact(capacity_bundle_pins_value, {
        "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
    }, "context calibration capacity bundle")
    require(bundle["schema"] == CAPACITY_BUNDLE_PIN_SCHEMA_V2, "unsupported context calibration capacity bundle schema")
    key = _capacity_key_v2(bundle["capacity_key"])
    pins = {name: _raw_pin(bundle[name], f"capacity bundle {name}") for name in ("source_manifest", "request", "artifact", "receipt")}
    require(pins["source_manifest"] == expected_source_pin == source_stack["source_pin"], "capacity bundle does not bind the exact SourceV5 manifest file")
    request, request_raw, request_sha = read_canonical(Path(pins["request"]["path"]), "capacity producer request", 2 * 1024 * 1024)
    require(request_sha == pins["request"]["raw_sha256"], "capacity producer request raw digest differs")
    for pin in pins.values():
        _require_evidence_path_mapped(pin["path"])
    _preflight_capacity_request_paths_v2(request)
    identity = exact(request.get("identity"), {
        "host_id", "run_id", "report_nonce", "process_id", "allocator", "executor", "workload", "profile",
        "mode", "source_sha256", "binary_sha256", "pressure_qualification",
    }, "capacity producer identity")
    require(request.get("schema") == SOURCE5_CAPACITY_BUNDLE_SCHEMA and request.get("calibration_id") == key["calibration_id"], "capacity request schema/calibration ID differs from its context key")
    require(identity["host_id"] == key["host_id"] and identity["workload"] == key["workload"] and identity["profile"] == key["profile"], "capacity producer identity differs from its context key")
    require(identity["source_sha256"] == source_stack["source_tree_sha256"] and identity["mode"] == "capacity" and identity["pressure_qualification"] is False, "capacity request source/mode/eligibility differs from SourceV5 context")
    request_source = exact(request.get("source_manifest"), {"path", "sha256"}, "capacity producer source manifest pin")
    require(request_source == {"path": pins["source_manifest"]["path"], "sha256": pins["source_manifest"]["raw_sha256"]}, "capacity producer request uses a different SourceV5 raw manifest")
    context_pin = exact(request.get("context"), {"path", "sha256"}, "capacity producer context pin")
    context, context_raw, context_sha = read_canonical(Path(context_pin["path"]), "capacity producer context", MAX_CAPACITY_CONTEXT_BYTES)
    _require_evidence_path_mapped(context_pin["path"])
    _require_absolute_evidence_paths_mapped(context)
    require(context_sha == context_pin["sha256"], "capacity producer context raw digest differs")
    exact(context, {"schema", "identity", "stage", "storage", "network"}, "capacity producer context")
    require(context["schema"] == "allocatbelt.application-capacity-context.v1" and context["identity"] == identity and context["stage"] == "pre_confirmation", "capacity producer context identity/stage differs")
    if context["network"] is not None:
        network = exact(context["network"], {"scope", "interface", "address", "namespace_inode", "ifindex"}, "capacity producer network context")
        require(network["interface"] == "lo" and network["address"] == "127.0.0.1" and network["namespace_inode"] == observed_host["network_namespace_inode"], "capacity network context differs from the observed host namespace")
    if context["storage"] is not None:
        storage = exact(context["storage"], {
            "scope", "root_path", "filesystem_type", "device_major_minor", "minimum_free_bytes",
            "tmpdir_path", "available_bytes_at_launch",
        }, "capacity producer storage context")
        require(storage["scope"] == "application_file_io" and re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", storage["device_major_minor"]) is not None, "capacity producer storage identity is malformed")
        uint(storage["minimum_free_bytes"], "capacity storage free-space floor", positive=True)
        uint(storage["available_bytes_at_launch"], "capacity storage observed free bytes")
    producer_request_pin = {"path": pins["request"]["path"], "sha256": pins["request"]["raw_sha256"]}
    producer_artifact_pin = {"path": pins["artifact"]["path"], "sha256": pins["artifact"]["raw_sha256"]}
    producer_receipt_pin = {"path": pins["receipt"]["path"], "sha256": pins["receipt"]["raw_sha256"]}
    try:
        replayed = source_stack["producer"].verify_capacity_bundle(producer_request_pin, producer_artifact_pin, producer_receipt_pin)
    except Exception as error:
        raise ReadbackError(f"pinned SourceV5 capacity producer replay failed: {type(error).__name__}: {error}") from error
    require(replayed is True, "pinned SourceV5 capacity producer rejected its complete bundle")
    feedback_artifact_pin = {
        "path": pins["artifact"]["path"],
        "raw_sha256": pins["artifact"]["raw_sha256"],
    }
    capacity_fields, capacity_sha = source_stack["feedback_reader"]._read_capacity_artifact_v5(feedback_artifact_pin)
    require(capacity_sha == pins["artifact"]["raw_sha256"], "capacity TSV bytes differ from the producer bundle pin")
    require(
        capacity_fields["host_id"] == key["host_id"] and capacity_fields["workload"] == key["workload"]
        and capacity_fields["profile"] == key["profile"] and capacity_fields["calibration_id"] == key["calibration_id"]
        and capacity_fields["source_sha256"] == source_stack["source_tree_sha256"],
        "prepared capacity TSV identity differs from its exact context/source key",
    )
    capacity_receipt, _, capacity_receipt_sha = read_canonical(Path(pins["receipt"]["path"]), "capacity producer receipt", 2 * 1024 * 1024)
    require(capacity_receipt_sha == pins["receipt"]["raw_sha256"] and capacity_receipt.get("qualification_eligible") is False, "capacity producer receipt pin/eligibility differs")
    require(capacity_receipt.get("identity") == identity and capacity_receipt.get("calibration_id") == key["calibration_id"] and capacity_receipt.get("source_manifest_raw_sha256") == pins["source_manifest"]["raw_sha256"] and capacity_receipt.get("capacity_artifact_raw_sha256") == capacity_sha, "capacity producer receipt does not bind the exact request/TSV/source")
    return {
        "capacity_key": key, "pins": {"schema": bundle["schema"], "capacity_key": key, **pins},
        "request": request, "request_raw_sha256": request_sha, "context": context,
        "context_raw_sha256": context_sha, "context_raw": context_raw,
        "capacity_fields": capacity_fields, "capacity_tsv_raw_sha256": capacity_sha,
        "capacity_receipt": capacity_receipt, "capacity_receipt_raw_sha256": capacity_receipt_sha,
    }


def _context_policy_numeric_projection_digest_v2(value: object) -> str:
    shared = exact(value, {
        "schema", "source_manifest", "context", "capacity_bundle", "base_policy_artifact_sha256",
        "base_policy_sha256", "base_context_sha256", "resolution_rule_version", "numeric_policy",
        "baseline", "hard_ceilings", "normalization_denominators", "member_resolutions", "policy_sha256",
    }, "shared numeric context policy projection")
    projection = {key: item for key, item in shared.items() if key not in ("member_resolutions", "policy_sha256")}
    return digest_object({
        "schema": "allocatbelt.application-pressure-numeric-context-projection.v2",
        "policy": projection,
    })


def _source5_capacity_floor_policy_id(source_stack: dict[str, Any]) -> str | None:
    artifact = exact(source_stack["source"]["feedback_policy"], {
        "schema", "policy", "policy_sha256",
    }, "SourceV5 feedback policy artifact for pressure replay")
    body_keys = {
        "schema", "version", "reader_contract", "algorithm", "contexts", "source_pins",
    }
    if artifact["schema"] == "allocatbelt.application-feedback-policy-artifact.v2":
        body_keys.add("capacity_floor_policy")
    body = exact(artifact["policy"], body_keys,
                 "SourceV5 feedback policy body for pressure replay")
    require(body["schema"] == artifact["schema"] and
            sha256(artifact["policy_sha256"], "SourceV5 feedback policy digest") ==
            digest_object(body),
            "SourceV5 feedback policy schema/hash differs in pressure replay")
    if artifact["schema"] == "allocatbelt.application-feedback-policy-artifact.v1":
        return None
    require(artifact["schema"] == "allocatbelt.application-feedback-policy-artifact.v2",
            "unsupported SourceV5 pressure feedback policy artifact")
    descriptor = source_stack["feedback_reader"]._validate_capacity_floor_policy_descriptor(
        body["capacity_floor_policy"],
    )
    require(descriptor["policy_id"] == source_stack["feedback_reader"].CAPACITY_FLOOR_POLICY_ID,
            "SourceV5 pressure feedback policy ID differs from the independent reader")
    return descriptor["policy_id"]


def _verify_context_policy_bundle_v2(
    source_stack: dict[str, Any], context_policy_pin_value: object,
    capacity: dict[str, Any], expected_source_pin: dict[str, Any],
) -> dict[str, Any]:
    context_pin, context_bundle, context_bundle_raw, context_bundle_sha = _read_raw_pin(
        context_policy_pin_value, "context-policy bundle", MAX_CONTEXT_POLICY_BUNDLE_BYTES,
    )
    exact(context_bundle, {"schema", "artifact", "members"}, "context-policy bundle")
    _preflight_context_policy_bundle_paths_v2(context_policy_pin_value)
    _require_absolute_evidence_paths_mapped(context_bundle)
    require(context_bundle["schema"] == CONTEXT_POLICY_BUNDLE_SCHEMA_V2, "unsupported context-policy bundle schema")
    policy_pin = _raw_pin(context_bundle["artifact"], "shared numeric context policy")
    policy, policy_raw, policy_raw_sha = read_canonical(Path(policy_pin["path"]), "shared numeric context policy", MAX_POLICY_BYTES)
    require(policy_raw_sha == policy_pin["raw_sha256"], "shared numeric context policy raw digest differs")
    exact(policy, {
        "schema", "source_manifest", "context", "capacity_bundle", "base_policy_artifact_sha256",
        "base_policy_sha256", "base_context_sha256", "resolution_rule_version", "numeric_policy",
        "baseline", "hard_ceilings", "normalization_denominators", "member_resolutions", "policy_sha256",
    }, "shared numeric context policy")
    require(policy["schema"] == SOURCE5_PRESSURE_POLICY_SCHEMA, "unsupported shared pressure policy schema")
    policy_body = {key: value for key, value in policy.items() if key != "policy_sha256"}
    require(sha256(policy["policy_sha256"], "shared policy digest") == digest_object(policy_body), "shared numeric policy self digest is invalid")
    source_pin = _raw_pin(policy["source_manifest"], "shared policy SourceV5 manifest")
    require(source_pin == expected_source_pin == source_stack["source_pin"], "shared policy refers to a different SourceV5 raw manifest")
    selected_floor_policy_id = _source5_capacity_floor_policy_id(source_stack)
    shared_context_keys = {"host_id", "workload", "profile", "calibration_id"}
    if selected_floor_policy_id is not None:
        shared_context_keys.add("capacity_floor_policy_id")
    context = exact(policy["context"], shared_context_keys, "shared policy context")
    require({key: context[key] for key in capacity["capacity_key"]} ==
            capacity["capacity_key"],
            "shared policy context differs from the capacity key")
    if selected_floor_policy_id is not None:
        require(context["capacity_floor_policy_id"] == selected_floor_policy_id,
                "shared policy context lost the SourceV5 capacity-floor selector")
    policy_capacity = exact(policy["capacity_bundle"], {"request", "artifact", "receipt"}, "shared policy capacity bundle")
    expected_capacity = {name: capacity["pins"][name] for name in ("request", "artifact", "receipt")}
    require(policy_capacity == expected_capacity, "shared policy does not pin the exact prepared capacity producer bundle")
    sha256(policy["base_policy_artifact_sha256"], "SourceV5 base policy artifact SHA-256")
    sha256(policy["base_policy_sha256"], "SourceV5 base numeric policy SHA-256")
    sha256(policy["base_context_sha256"], "SourceV5 base context SHA-256")
    text(policy["resolution_rule_version"], "SourceV5 capacity resolution rule version", 128)
    resolutions = policy["member_resolutions"]
    require(type(resolutions) is list and len(resolutions) == 2, "shared policy must bind exactly the two original pressure members")
    members = context_bundle["members"]
    require(type(members) is list and len(members) == 2, "context-policy bundle must pin exactly two original pressure members")
    replayed_members = []
    for index, item in enumerate(members):
        member = exact(item, {"descriptor", "request", "construction_probe", "resolved_policy", "composition_receipt"}, f"context-policy member[{index}]")
        descriptor = exact(member["descriptor"], {"pair", "executor", "allocator"}, f"context-policy member[{index}] descriptor")
        pair = text(descriptor["pair"], f"context-policy member[{index}] pair", 128)
        executor = text(descriptor["executor"], f"context-policy member[{index}] executor", 32)
        allocator = text(descriptor["allocator"], f"context-policy member[{index}] allocator", 64)
        require(executor in ("bounded", "tokio") and allocator in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"), f"context-policy member[{index}] role is unsupported")
        request_pin, request, request_raw, request_sha = _read_raw_pin(member["request"], f"context-policy member[{index}] composer request", 1 * 1024 * 1024)
        _require_absolute_evidence_paths_mapped(request)
        probe_pin = exact(member["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, f"context-policy member[{index}] construction probe")
        probe_pin = {
            "path": str(absolute_path(probe_pin["path"], f"context-policy member[{index}] construction probe path")),
            "raw_sha256": sha256(probe_pin["raw_sha256"], f"context-policy member[{index}] construction probe SHA-256"),
            "allocator": text(probe_pin["allocator"], f"context-policy member[{index}] construction probe allocator", 64),
            "binary_sha256": sha256(probe_pin["binary_sha256"], f"context-policy member[{index}] construction probe binary SHA-256"),
        }
        _require_evidence_path_mapped(probe_pin["path"])
        require(probe_pin["allocator"] == allocator, f"context-policy member[{index}] probe allocator differs from its descriptor")
        resolved_pin = _raw_pin(member["resolved_policy"], f"context-policy member[{index}] resolved policy")
        resolved_policy, resolved_raw, resolved_sha = read_canonical(Path(resolved_pin["path"]), f"context-policy member[{index}] resolved policy", MAX_CONTEXT_POLICY_BUNDLE_BYTES)
        require(resolved_sha == resolved_pin["raw_sha256"], f"context-policy member[{index}] resolved policy raw digest differs")
        composition_pin = _raw_pin(member["composition_receipt"], f"context-policy member[{index}] composition receipt")
        composition_receipt, composition_raw, composition_sha = read_canonical(Path(composition_pin["path"]), f"context-policy member[{index}] composition receipt", MAX_CONTEXT_POLICY_BUNDLE_BYTES)
        require(composition_sha == composition_pin["raw_sha256"], f"context-policy member[{index}] composition receipt raw digest differs")
        expected_request_schema = (
            source_stack["composer"].REQUEST_SCHEMA_V2
            if selected_floor_policy_id is not None else
            source_stack["composer"].REQUEST_SCHEMA
        )
        require(type(request) is dict and request.get("schema") == expected_request_schema,
                f"context-policy member[{index}] has an unsupported composer request")
        if selected_floor_policy_id is None:
            require("capacity_floor_policy_id" not in request,
                    f"context-policy member[{index}] static request contains a floor selector")
        else:
            require(request.get("capacity_floor_policy_id") == selected_floor_policy_id,
                    f"context-policy member[{index}] request differs from the SourceV5 floor selector")
        require(request.get("source_root") == str(source_stack["source_root"]), f"context-policy member[{index}] composer source root differs")
        request_source = _raw_pin(request.get("source_manifest"), f"context-policy member[{index}] composer SourceV5 manifest")
        require(request_source == expected_source_pin, f"context-policy member[{index}] composer request uses different SourceV5 bytes")
        request_context = exact(request.get("context"), {"host_id", "workload", "profile", "calibration_id"}, f"context-policy member[{index}] composer context")
        require(request_context == capacity["capacity_key"], f"context-policy member[{index}] composer context differs from the capacity key")
        request_probe = exact(request.get("construction_probe"), {"path", "raw_sha256", "allocator", "binary_sha256"}, f"context-policy member[{index}] composer probe pin")
        _require_evidence_path_mapped(request_probe["path"])
        require(request_probe == probe_pin, f"context-policy member[{index}] composer request differs from its genuine construction-probe pin")
        construction_probe, _probe_raw, _probe_sha = _read_raw_pin(
            {"path": probe_pin["path"], "raw_sha256": probe_pin["raw_sha256"]},
            f"context-policy member[{index}] preflighted construction probe", 512 * 1024,
        )
        _require_absolute_evidence_paths_mapped(construction_probe)
        request_capacity = exact(request.get("capacity_bundle"), {"request", "artifact", "receipt"}, f"context-policy member[{index}] composer capacity bundle")
        require(request_capacity == expected_capacity, f"context-policy member[{index}] composer request uses different prepared capacity bytes")
        try:
            resolved_replayed, receipt_replayed = source_stack["composer"].compose_calibrated_policy_v5(request, request_sha)
        except Exception as error:
            raise ReadbackError(f"pinned SourceV5 composer replay failed for member[{index}]: {type(error).__name__}: {error}") from error
        require(canonical_bytes(resolved_replayed) == resolved_raw and canonical_bytes(receipt_replayed) == composition_raw, f"context-policy member[{index}] resolved policy/receipt differs from full SourceV5 composer replay")
        resolved_context_keys = {
            "host_id", "workload", "profile", "calibration_id", "allocator",
        }
        if selected_floor_policy_id is not None:
            resolved_context_keys.add("capacity_floor_policy_id")
        resolved_context = exact(resolved_policy.get("context"), resolved_context_keys,
                                 f"context-policy member[{index}] resolved context")
        require({key: resolved_context[key] for key in capacity["capacity_key"]} == capacity["capacity_key"] and resolved_context["allocator"] == allocator, f"context-policy member[{index}] resolved policy identity differs")
        if selected_floor_policy_id is not None:
            require(resolved_context["capacity_floor_policy_id"] == selected_floor_policy_id,
                    f"context-policy member[{index}] resolved policy lost the SourceV5 floor selector")
        replayed_members.append({
            "pair": pair, "executor": executor, "allocator": allocator,
            "binary_sha256": probe_pin["binary_sha256"],
            "probe_raw_sha256": probe_pin["raw_sha256"],
            "request_raw_sha256": request_sha,
            "resolved_policy_raw_sha256": resolved_sha,
            "resolved_policy_sha256": sha256(resolved_policy.get("policy_sha256"), f"member[{index}] resolved policy digest"),
            "composition_receipt_raw_sha256": composition_sha,
            "policy": resolved_policy,
        })
    first = replayed_members[0]["policy"]
    first_context = first["context"]
    for index, row in enumerate(replayed_members[1:], start=1):
        other = row["policy"]
        require(other["policy"] == first["policy"], f"context-policy members resolve different numeric policy at member[{index}]")
        for field in (
            "source_manifest_raw_sha256", "source_manifest_sha256", "source_tree_sha256", "build_sha256",
            "base_policy_artifact_sha256", "base_policy_sha256", "base_context_sha256",
            "capacity_request_raw_sha256", "capacity_artifact_raw_sha256", "capacity_receipt_raw_sha256",
            "resolution_rule_version",
        ):
            require(other[field] == first[field], f"context-policy members differ at stable field {field}")
        require({name: value for name, value in other["context"].items() if name != "allocator"} == {name: value for name, value in first_context.items() if name != "allocator"}, f"context-policy members differ in non-allocator context at member[{index}]")
    require([{
        key: row[key] for key in (
            "pair", "executor", "allocator", "binary_sha256", "probe_raw_sha256",
            "request_raw_sha256", "resolved_policy_raw_sha256", "resolved_policy_sha256",
            "composition_receipt_raw_sha256",
        )
    } for row in replayed_members] == resolutions, "shared policy member-resolution references differ from composer-replayed inputs")
    numeric = first["policy"]
    expected_shared_context = {
        key: first_context[key]
        for key in ("host_id", "workload", "profile", "calibration_id")
    }
    if selected_floor_policy_id is not None:
        expected_shared_context["capacity_floor_policy_id"] = selected_floor_policy_id
    expected_shared = {
        "schema": SOURCE5_PRESSURE_POLICY_SCHEMA,
        "source_manifest": expected_source_pin,
        "context": expected_shared_context,
        "capacity_bundle": expected_capacity,
        "base_policy_artifact_sha256": first["base_policy_artifact_sha256"],
        "base_policy_sha256": first["base_policy_sha256"],
        "base_context_sha256": first["base_context_sha256"],
        "resolution_rule_version": first["resolution_rule_version"],
        "numeric_policy": numeric,
        "baseline": numeric["collector"]["expected_global_control_baseline"],
        "hard_ceilings": {"global": numeric["global_ceilings"], "tenant": numeric["tenant_ceilings"]},
        "normalization_denominators": {
            "capacity_sources": numeric["capacity_sources"],
            "scope_limits": numeric["scope_limits"],
            "rate_buckets": numeric["rate_buckets"],
        },
        "member_resolutions": resolutions,
    }
    expected_shared["policy_sha256"] = digest_object(expected_shared)
    require(policy == expected_shared, "shared policy document differs from the two pinned SourceV5 composer replays")
    context_sha = _context_policy_numeric_projection_digest_v2(expected_shared)
    return {
        "pin": context_pin, "raw_sha256": context_bundle_sha,
        "policy_pin": policy_pin, "policy": policy, "policy_raw_sha256": policy_raw_sha,
        "numeric_context_policy_sha256": context_sha,
        "members": replayed_members,
        "capacity_bundle_pins_sha256": digest_object(capacity["pins"]),
    }


def _verify_observed_host_pin_v2(value: object, expected_host_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    pin, observed, _raw, raw_sha = _read_raw_pin(value, "observed Source5 host", 1 * 1024 * 1024)
    exact(observed, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity", "network_namespace_inode",
    }, "observed Source5 host context")
    require(observed["schema"] == "allocatbelt.application-capacity-host-context.v1" and observed["host_id"] == expected_host_id, "observed Source5 host schema/identity differs")
    controls = exact(observed["controls"], {
        "cpu_model", "microcode_sha256", "kernel_release", "governor", "frequency_policy", "boost_policy",
        "cpu_set", "numa_policy", "cgroup_policy_sha256", "background_load_policy_sha256",
        "x86_64_v3_capability_sha256", "target_triple", "target_cpu",
    }, "observed Source5 host controls")
    require(sha256(observed["controls_sha256"], "observed controls SHA-256") == digest_object(controls), "observed Source5 host controls digest is invalid")
    require(observed["kernel_release"] == controls["kernel_release"] and observed["cpu_model"] == controls["cpu_model"], "observed Source5 host model/kernel differs from controls")
    cpus = observed["cpu_affinity"]
    require(type(cpus) is list and cpus and all(type(cpu) is int and 0 <= cpu <= 65535 for cpu in cpus) and cpus == sorted(set(cpus)), "observed Source5 CPU affinity is malformed")
    set_parts = controls["cpu_set"].split(",") if type(controls["cpu_set"]) is str else []
    parsed_cpus: list[int] = []
    for part in set_parts:
        if re.fullmatch(r"[0-9]+", part):
            parsed_cpus.append(int(part))
        elif re.fullmatch(r"[0-9]+-[0-9]+", part):
            low, high = (int(item) for item in part.split("-", 1))
            require(low <= high and high <= 65535 and high - low <= 65535, "observed Source5 CPU range is malformed")
            parsed_cpus.extend(range(low, high + 1))
        else:
            raise ReadbackError("observed Source5 CPU set is malformed")
    require(cpus == sorted(set(parsed_cpus)), "observed Source5 CPU affinity differs from its frozen controls")
    uint(observed["network_namespace_inode"], "observed Source5 network namespace", positive=True)
    return pin, observed


def _pressure_thresholds_v2(value: object, label: str) -> dict[str, int]:
    thresholds = exact(value, set(PRESSURE_THRESHOLD_KEYS_V2), label)
    normalized = {
        key: uint(
            thresholds[key], f"{label} {key}", positive=True,
            maximum=10000 if key == "cpu_busy_min_basis_points" else U64_MAX,
        )
        for key in sorted(PRESSURE_THRESHOLD_KEYS_V2)
    }
    return normalized


def _campaign_readiness_thresholds_v1(value: object, label: str) -> dict[str, int]:
    thresholds = exact(value, set(CAMPAIGN_READINESS_KEYS_V1), label)
    return {
        key: uint(thresholds[key], f"{label} {key}", positive=True)
        for key in sorted(CAMPAIGN_READINESS_KEYS_V1)
    }


def _validate_samples_meet_pressure_thresholds_v2(samples: list[dict[str, Any]], thresholds: dict[str, int]) -> None:
    require(type(samples) is list and samples, "context calibration has no pressure samples")
    for index, sample in enumerate(samples):
        readiness = _derive_readiness(sample, thresholds)
        require(readiness["all_ready"], f"context calibration sample[{index}] fails its prospectively frozen pressure thresholds")


def _verify_condition_file_v2(pin_value: object, capacity_key: dict[str, str], condition_id: str, schedule: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    pin, condition, _raw, _raw_sha = _read_raw_pin(pin_value, "Source5 pressure condition", 1 * 1024 * 1024)
    exact(condition, {
        "schema", "host_id", "condition_id", "capacity_key", "pressure_calibration_id",
        "readiness_threshold_rule", "readiness_thresholds", "pressure_thresholds", "schedule",
    }, "Source5 pressure condition")
    require(condition["schema"] == SOURCE5_PRESSURE_CONDITION_SCHEMA and condition["host_id"] == capacity_key["host_id"] and condition["condition_id"] == condition_id, "Source5 pressure condition identity differs")
    require(_capacity_key_v2(condition["capacity_key"], "Source5 pressure condition capacity key") == capacity_key, "Source5 pressure condition capacity key differs")
    pressure_calibration_id = text(condition["pressure_calibration_id"], "Source5 pressure calibration ID", 96)
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", pressure_calibration_id) is not None
        and pressure_calibration_id not in (condition_id, capacity_key["calibration_id"]),
        "Source5 pressure calibration ID is malformed or aliases another condition/calibration identity",
    )
    require(condition["readiness_threshold_rule"] == SOURCE5_PRESSURE_READINESS_RULE_V1, "Source5 pressure condition uses an unsupported prospective-threshold rule")
    condition_schedule = _validate_condition_schedule_v2(condition["schedule"])
    require(
        _pressure_profile_v2(condition_schedule) == _pressure_profile_v2(schedule),
        "Source5 pressure condition intensity differs from the measured calibration profile",
    )
    thresholds = _campaign_readiness_thresholds_v1(condition["readiness_thresholds"], "Source5 pressure condition campaign readiness thresholds")
    require(thresholds["minimum_overlap_seconds"] >= 30 and thresholds["minimum_overlap_seconds"] == condition_schedule["minimum_overlap_seconds"], "Source5 condition changes its frozen minimum overlap gate")
    require(condition_schedule["sample_interval_ms"] == 100, "Source5 pressure condition readiness cadence differs from the frozen 100 ms campaign cadence")
    require(thresholds["maximum_sample_gap_ms"] <= 200, "Source5 condition permits a sparse readiness window")
    required_ready_samples = thresholds["minimum_overlap_seconds"] * 1000 // condition_schedule["sample_interval_ms"]
    require(thresholds["minimum_ready_samples"] >= required_ready_samples, "Source5 condition readiness sample count weakens its full overlap gate")
    require(thresholds["minimum_ready_samples"] <= condition_schedule["duration_seconds"] * 1000 // condition_schedule["sample_interval_ms"], "Source5 condition readiness count exceeds its full pressure schedule")
    pressure_thresholds = _pressure_thresholds_v2(condition["pressure_thresholds"], "Source5 pressure condition numeric thresholds")
    condition["readiness_thresholds"] = {key: thresholds[key] for key in sorted(CAMPAIGN_READINESS_KEYS_V1)}
    condition["pressure_thresholds"] = pressure_thresholds
    return pin, condition


def _pressure_profile_v2(schedule: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "seed", "sample_interval_ms", "startup_deadline_seconds", "term_deadline_seconds",
        "kill_deadline_seconds", "cpu_duty_basis_points", "pressure_cpu_affinity",
        "application_cpu_affinity", "disk_bytes_per_second", "scratch_file_bytes",
        "network_requests_per_second", "network_payload_bytes",
    )
    return {key: schedule[key] for key in keys}


def _validate_condition_schedule_v2(value: object) -> dict[str, Any]:
    """Validate the full SourceV5 horizon, independently of finite calibration bounds."""
    schedule = exact(value, {
        "seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds",
        "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds",
        "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points",
        "pressure_cpu_affinity", "application_cpu_affinity", "disk_bytes_per_second",
        "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes",
    }, "Source5 full pressure condition schedule")
    duration = uint(schedule["duration_seconds"], "Source5 condition duration", positive=True, maximum=MAX_DURATION_SECONDS)
    interval_ms = uint(schedule["sample_interval_ms"], "Source5 condition sample interval", positive=True, maximum=1000)
    require(interval_ms >= 100 and duration * 1000 % interval_ms == 0, "Source5 condition sample schedule is invalid")
    count = duration * 1000 // interval_ms
    require(count <= MAX_SAMPLE_COUNT, "Source5 condition sample schedule exceeds the full reader cap")
    uint(schedule["total_deadline_seconds"], "Source5 condition total deadline", positive=True, maximum=14400)
    uint(schedule["startup_deadline_seconds"], "Source5 condition startup deadline", positive=True, maximum=10)
    uint(schedule["term_deadline_seconds"], "Source5 condition TERM deadline", positive=True, maximum=30)
    uint(schedule["kill_deadline_seconds"], "Source5 condition KILL deadline", positive=True, maximum=15)
    uint(schedule["minimum_overlap_seconds"], "Source5 condition overlap", positive=True, maximum=duration)
    uint(schedule["startup_ready_windows"], "Source5 condition startup windows", positive=True, maximum=10)
    require(
        schedule["total_deadline_seconds"] >= schedule["startup_deadline_seconds"] + duration
        + schedule["term_deadline_seconds"] + schedule["kill_deadline_seconds"],
        "Source5 condition total deadline omits a bounded phase",
    )
    uint(schedule["seed"], "Source5 condition seed", positive=True, maximum=(1 << 63) - 1)
    duty = uint(schedule["cpu_duty_basis_points"], "Source5 condition CPU duty", positive=True, maximum=10000)
    require(duty >= 100, "Source5 condition CPU duty is below the supported minimum")
    pressure_cpus = _cpu_list(schedule["pressure_cpu_affinity"], "Source5 condition pressure affinity")
    app_cpus = _cpu_list(schedule["application_cpu_affinity"], "Source5 condition application affinity")
    require(pressure_cpus and app_cpus, "Source5 condition CPU affinity is empty")
    disk_rate = uint(schedule["disk_bytes_per_second"], "Source5 condition disk rate", positive=True, maximum=512 * 1024 * 1024)
    disk_target_per_window = disk_rate * interval_ms // 1000
    require(disk_target_per_window >= BLOCK_BYTES, "Source5 condition disk rate is too sparse for its sample cadence")
    disk_actual_per_window = ((disk_target_per_window + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES
    require(disk_actual_per_window * count <= 64 * 1024**3, "Source5 condition disk pressure exceeds its cumulative bound")
    scratch = uint(schedule["scratch_file_bytes"], "Source5 condition scratch bytes", positive=True, maximum=1024 * 1024 * 1024)
    require(scratch >= BLOCK_BYTES and scratch % BLOCK_BYTES == 0, "Source5 condition scratch bytes are not block aligned")
    net_rate = uint(schedule["network_requests_per_second"], "Source5 condition loopback rate", positive=True, maximum=100000)
    payload = uint(schedule["network_payload_bytes"], "Source5 condition loopback payload", positive=True, maximum=65536)
    require(payload >= 16 and net_rate * interval_ms >= 1000, "Source5 condition loopback schedule is too sparse or small")
    require(
        net_rate * payload * 2 <= 64 * 1024**2
        and net_rate * payload * 2 * duration <= 64 * 1024**3,
        "Source5 condition loopback pressure exceeds its cumulative bound",
    )
    return schedule


def _validate_calibration_schedule_v2(value: object) -> dict[str, Any]:
    schedule = exact(value, {
        "seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds",
        "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds",
        "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points",
        "pressure_cpu_affinity", "application_cpu_affinity", "disk_bytes_per_second",
        "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes",
    }, "context calibration schedule")
    duration = uint(schedule["duration_seconds"], "context calibration duration", positive=True, maximum=120)
    interval = uint(schedule["sample_interval_ms"], "context calibration sample interval", positive=True, maximum=1000)
    require(100 <= interval and duration * 1000 % interval == 0, "context calibration sample schedule is invalid")
    require(duration * 1000 // interval <= MAX_SAMPLE_COUNT, "context calibration sample count exceeds the readback bound")
    uint(schedule["seed"], "context calibration seed", positive=True, maximum=(1 << 63) - 1)
    uint(schedule["startup_deadline_seconds"], "context calibration startup deadline", positive=True, maximum=10)
    total = uint(schedule["total_deadline_seconds"], "context calibration total deadline", positive=True, maximum=200)
    term = uint(schedule["term_deadline_seconds"], "context calibration TERM deadline", positive=True, maximum=30)
    kill = uint(schedule["kill_deadline_seconds"], "context calibration KILL deadline", positive=True, maximum=15)
    require(total >= schedule["startup_deadline_seconds"] + duration + term + kill, "context calibration total deadline omits a bounded phase")
    require(uint(schedule["minimum_overlap_seconds"], "context calibration overlap", positive=True, maximum=duration) <= duration, "context calibration overlap exceeds its finite horizon")
    uint(schedule["startup_ready_windows"], "context calibration ready windows", positive=True, maximum=10)
    duty = uint(schedule["cpu_duty_basis_points"], "context calibration CPU duty", positive=True, maximum=10000)
    require(100 <= duty <= 10000, "context calibration CPU duty is outside the supported range")
    pressure_cpus = _cpu_list(schedule["pressure_cpu_affinity"], "context calibration pressure affinity")
    app_cpus = _cpu_list(schedule["application_cpu_affinity"], "context calibration application affinity")
    require(bool(pressure_cpus) and bool(app_cpus), "context calibration CPU affinity is empty")
    disk_rate = uint(schedule["disk_bytes_per_second"], "context calibration disk rate", positive=True, maximum=512 * 1024 * 1024)
    require(disk_rate * interval // 1000 >= BLOCK_BYTES, "context calibration disk rate is sparse at its sample cadence")
    scratch = uint(schedule["scratch_file_bytes"], "context calibration scratch bytes", positive=True, maximum=1024 * 1024 * 1024)
    require(scratch >= BLOCK_BYTES and scratch % BLOCK_BYTES == 0, "context calibration scratch file is not block aligned")
    net_rate = uint(schedule["network_requests_per_second"], "context calibration loopback rate", positive=True, maximum=100000)
    payload = uint(schedule["network_payload_bytes"], "context calibration loopback payload", positive=True, maximum=65536)
    require(net_rate * interval >= 1000 and payload >= 16, "context calibration loopback schedule is too sparse or too small")
    return schedule


def _validate_calibration_cleanup_v2(
    calibration: dict[str, Any], schedule: dict[str, Any], *, require_local_reap: bool = False,
) -> None:
    sessions = calibration["worker_sessions"]
    cleanup = calibration["worker_cleanup"]
    cpus = schedule["pressure_cpu_affinity"]
    expected = {("cpu", cpu) for cpu in cpus} | {("disk", None), ("loopback", None)}
    require(type(sessions) is list and len(sessions) == len(expected) and type(cleanup) is list and len(cleanup) == len(sessions), "context calibration worker session/cleanup list is sparse")
    session_by_key: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in sessions:
        worker = exact(item, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id"}, "context calibration worker session")
        role = text(worker["role"], "context calibration worker role", 16)
        cpu = uint(worker["cpu"], "context calibration worker CPU", maximum=65535) if role == "cpu" else None
        require(role in ("cpu", "disk", "loopback") and (role != "cpu" or cpu in cpus), "context calibration worker role/CPU differs from the schedule")
        pid = uint(worker["pid"], "context calibration worker PID", positive=True, maximum=(1 << 31) - 1)
        ticks = uint(worker["start_ticks"], "context calibration worker start ticks", positive=True)
        require(worker["pgid"] == pid and worker["session_id"] == pid, "context calibration worker was not isolated in its own process group/session")
        key = (role, cpu)
        require(key not in session_by_key, "context calibration worker sessions contain a duplicate")
        session_by_key[key] = {**worker, "pid": pid, "start_ticks": ticks}
    require(set(session_by_key) == expected, "context calibration worker sessions differ from frozen resources")
    cleanup_by_key: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in cleanup:
        record = exact(item, {
            "role", "cpu", "pid", "start_ticks", "pgid", "session_id", "exit_code",
            "cleanup_started_monotonic_ns", "term_deadline_monotonic_ns", "kill_deadline_monotonic_ns",
            "term_error", "kill_error", "reap_error", "alive_after_cleanup",
            "term_sent_monotonic_ns", "kill_sent_monotonic_ns", "reaped_monotonic_ns", "stderr_output",
            "stderr_raw_base64", "stderr_raw_sha256", "stderr_raw_bytes", "stderr_raw_truncated", "stderr_read_error",
        }, "context calibration worker cleanup")
        key = (record["role"], record["cpu"])
        require(key in session_by_key and key not in cleanup_by_key, "context calibration cleanup invents or duplicates a worker")
        session = session_by_key[key]
        require(all(record[name] == session[name] for name in ("pid", "start_ticks", "pgid", "session_id")), "context calibration cleanup PID/start/session differs")
        raw_stderr = _validate_worker_stderr_capture(record, "context calibration worker")
        require(_worker_exit_status_valid(record) and record["alive_after_cleanup"] is False and all(record[name] is None for name in ("term_error", "kill_error", "reap_error")) and raw_stderr == b"", "context calibration worker cleanup failed")
        start = uint(record["cleanup_started_monotonic_ns"], "context calibration cleanup start", positive=True)
        term_deadline = uint(record["term_deadline_monotonic_ns"], "context calibration TERM deadline", positive=True)
        kill_deadline = uint(record["kill_deadline_monotonic_ns"], "context calibration KILL deadline", positive=True)
        reaped = uint(record["reaped_monotonic_ns"], "context calibration reap time", positive=True)
        require(term_deadline == start + schedule["term_deadline_seconds"] * 1_000_000_000, "context calibration TERM deadline differs from the frozen schedule")
        if record["term_sent_monotonic_ns"] is not None:
            require(start <= uint(record["term_sent_monotonic_ns"], "context calibration TERM sent", positive=True) <= term_deadline, "context calibration TERM escalation exceeded its bound")
        if record["kill_sent_monotonic_ns"] is not None:
            killed = uint(record["kill_sent_monotonic_ns"], "context calibration KILL sent", positive=True)
            require(term_deadline <= killed <= kill_deadline, "context calibration KILL escalation exceeded its bound")
        require(reaped <= kill_deadline, "context calibration worker reap exceeded its bound")
        if require_local_reap:
            _require_pid_reaped(record["pid"], record["start_ticks"], "context calibration worker")
        cleanup_by_key[key] = record
    require(set(cleanup_by_key) == expected and calibration["scratch_file_removed"] is True, "context calibration omitted a clean worker reap or scratch removal")


def _validate_calibration_v2_body(
    calibration_value: object, *, require_local_reap: bool = False,
) -> dict[str, Any]:
    calibration = exact(calibration_value, {
        "schema", "identity", "schedule", "schedule_sha256", "scope", "raw_inputs", "driver_sha256", "reader_sha256",
        "host", "storage", "network", "worker_sessions", "samples", "summary",
        "suggested_readiness_thresholds", "worker_cleanup", "scratch_file_removed",
        "start_monotonic_ns", "finish_monotonic_ns", "deadlines", "calibration_sha256",
    }, "context-scoped pressure calibration v2")
    require(calibration["schema"] == CALIBRATION_SCHEMA_V2, "unsupported context pressure calibration schema")
    body = {key: value for key, value in calibration.items() if key != "calibration_sha256"}
    require(sha256(calibration["calibration_sha256"], "context calibration self digest") == digest_object(body), "context calibration self digest is invalid")
    identity = exact(calibration["identity"], {"host_id", "run_id", "condition_id", "nonce", "phase"}, "context calibration identity")
    require(identity["phase"] == "calibration", "context calibration has the wrong phase")
    text(identity["host_id"], "context calibration host", 96)
    text(identity["run_id"], "context calibration run ID", 96)
    text(identity["condition_id"], "context calibration condition ID", 96)
    require(re.fullmatch(r"[0-9a-f]{32}", text(identity["nonce"], "context calibration nonce", 32)) is not None, "context calibration nonce is malformed")
    schedule = _validate_calibration_schedule_v2(calibration["schedule"])
    require(sha256(calibration["schedule_sha256"], "context calibration intensity SHA-256") == digest_object(_pressure_profile_v2(schedule)), "context calibration intensity digest differs from its full schedule")
    sha256(calibration["driver_sha256"], "context calibration driver hash")
    sha256(calibration["reader_sha256"], "context calibration reader hash")
    scope = exact(calibration["scope"], {
        "schema", "condition", "condition_id", "pressure_calibration_id", "capacity_key", "source_root",
        "source_manifest", "source_manifest_semantic_sha256", "source_tree_sha256",
        "capacity_bundle_pins", "context_policy_bundle", "context_policy_sha256",
        "readiness_thresholds", "pressure_thresholds",
        "observed_host", "host_sha256", "storage_sha256", "network_sha256",
        "pressure_profile_sha256",
    }, "context calibration scope")
    require(scope["schema"] == CALIBRATION_SCOPE_SCHEMA_V2 and scope["condition_id"] == identity["condition_id"], "context calibration scope schema/condition differs")
    key = _capacity_key_v2(scope["capacity_key"])
    require(key["host_id"] == identity["host_id"], "context calibration host differs from its capacity key")
    pressure_calibration_id = text(scope["pressure_calibration_id"], "context calibration pressure calibration ID", 96)
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", pressure_calibration_id) is not None
        and pressure_calibration_id not in (identity["condition_id"], key["calibration_id"]),
        "context calibration pressure calibration ID aliases another identity",
    )
    absolute_path(scope["source_root"], "context calibration SourceV5 root")
    for field in ("source_manifest_semantic_sha256", "source_tree_sha256", "context_policy_sha256", "host_sha256", "storage_sha256", "network_sha256", "pressure_profile_sha256"):
        sha256(scope[field], f"context calibration {field}")
    source_pin = _raw_pin(scope["source_manifest"], "context calibration SourceV5 manifest")
    context_policy_pin = _raw_pin(scope["context_policy_bundle"], "context calibration context-policy bundle")
    observed_pin = _raw_pin(scope["observed_host"], "context calibration observed host")
    capacity_bundle = exact(scope["capacity_bundle_pins"], {
        "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
    }, "context calibration capacity producer bundle")
    require(_capacity_key_v2(capacity_bundle["capacity_key"]) == key and _raw_pin(capacity_bundle["source_manifest"], "capacity SourceV5 manifest") == source_pin, "context calibration source/capacity key pins differ")
    require(scope["pressure_profile_sha256"] == digest_object(_pressure_profile_v2(schedule)), "context calibration pressure intensity digest differs from its full schedule")
    condition_pin, condition = _verify_condition_file_v2(scope["condition"], key, identity["condition_id"], schedule)
    scope["condition"] = condition_pin
    require(scope["pressure_calibration_id"] == condition["pressure_calibration_id"], "context calibration pressure calibration ID differs from the pinned Source5 condition")
    scope["readiness_thresholds"] = _campaign_readiness_thresholds_v1(
        scope["readiness_thresholds"], "context calibration campaign readiness thresholds",
    )
    scope["pressure_thresholds"] = _pressure_thresholds_v2(
        scope["pressure_thresholds"], "context calibration numeric pressure thresholds",
    )
    require(
        scope["readiness_thresholds"] == condition["readiness_thresholds"]
        and scope["pressure_thresholds"] == condition["pressure_thresholds"],
        "context calibration thresholds differ from the prospective Source5 condition bytes",
    )
    raw_inputs = exact(calibration["raw_inputs"], {
        "source_manifest_raw_sha256", "policy_artifact_raw_sha256", "application_capacity_calibration_sha256",
        "capacity_bundle_pins_sha256", "context_policy_bundle_raw_sha256", "condition_raw_sha256", "observed_host_raw_sha256",
    }, "context calibration raw input digests")
    for field, pin in (
        ("source_manifest_raw_sha256", source_pin), ("context_policy_bundle_raw_sha256", context_policy_pin),
        ("condition_raw_sha256", condition_pin), ("observed_host_raw_sha256", observed_pin),
    ):
        require(sha256(raw_inputs[field], f"context calibration {field}") == pin["raw_sha256"], f"context calibration {field} differs from its scope pin")
    sha256(raw_inputs["policy_artifact_raw_sha256"], "context calibration shared policy raw SHA-256")
    sha256(raw_inputs["application_capacity_calibration_sha256"], "context calibration prepared TSV raw SHA-256")
    sha256(raw_inputs["capacity_bundle_pins_sha256"], "context calibration capacity bundle digest")
    require(raw_inputs["capacity_bundle_pins_sha256"] == digest_object(capacity_bundle), "context calibration capacity bundle digest differs")
    require(calibration["driver_sha256"] == read_stable(DRIVER_PATH, "pressure driver", MAX_SOURCE_MODULE_BYTES)[1], "context calibration was produced by different driver bytes")
    require(calibration["reader_sha256"] == read_stable(Path(__file__).resolve(), "pressure validator", MAX_SOURCE_MODULE_BYTES)[1], "context calibration was read by different validator bytes")
    host = exact(calibration["host"], {
        "kernel_release", "boot_id_sha256", "allowed_cpu_affinity", "pressure_cpu_affinity",
        "application_cpu_affinity", "application_storage", "pressure_scratch", "network",
    }, "context calibration host observation")
    text(host["kernel_release"], "context calibration kernel release", 256)
    sha256(host["boot_id_sha256"], "context calibration boot ID")
    require(host["pressure_cpu_affinity"] == schedule["pressure_cpu_affinity"] and host["application_cpu_affinity"] == schedule["application_cpu_affinity"], "context calibration host affinity differs from schedule")
    allowed = host["allowed_cpu_affinity"]
    require(type(allowed) is list and allowed and allowed == sorted(set(uint(cpu, "context calibration allowed CPU", maximum=65535) for cpu in allowed)), "context calibration allowed CPU affinity is malformed")
    require(set(schedule["pressure_cpu_affinity"]) <= set(allowed) and set(schedule["application_cpu_affinity"]) <= set(allowed), "context calibration schedule exceeds the observed host affinity")
    require(scope["host_sha256"] == digest_object(host), "context calibration host digest differs")
    storage = exact(calibration["storage"], {"application_device", "mount_id", "backing_chain"}, "context calibration storage identity")
    device = text(storage["application_device"], "context calibration application device", 32)
    require(re.fullmatch(r"[0-9]+:[0-9]+", device) is not None, "context calibration application device is malformed")
    mount_id = uint(storage["mount_id"], "context calibration application mount ID", positive=True)
    chain = _device_chain(storage["backing_chain"], device)
    require(type(host["application_storage"]) is list and 1 <= len(host["application_storage"]) <= 16, "context calibration application storage records are sparse")
    for index, item in enumerate(host["application_storage"]):
        require(type(item) is dict, f"context calibration application storage[{index}] is malformed")
        _validate_storage_record(item, item.get("path"), device, mount_id, chain, f"context calibration application storage[{index}]")
    require(type(host["pressure_scratch"]) is dict, "context calibration scratch storage record is missing")
    scratch = _validate_storage_record(host["pressure_scratch"], host["pressure_scratch"].get("path"), device, mount_id, chain, "context calibration pressure scratch")
    require(scratch["filesystem_type"] not in ("tmpfs", "ramfs", "overlay"), "context calibration scratch storage is in-memory or overlay")
    require(scope["storage_sha256"] == digest_object(storage), "context calibration storage digest differs")
    network = exact(calibration["network"], {
        "address_family", "destination", "source", "interface", "ifindex", "route",
        "network_namespace_inode", "shared_kernel", "physical_nic_claimed", "claim",
    }, "context calibration network identity")
    require(network["address_family"] == "AF_INET" and network["destination"] == "127.0.0.1" and network["source"] == "127.0.0.1" and network["interface"] == "lo", "context calibration network identity is not IPv4 loopback")
    uint(network["ifindex"], "context calibration loopback ifindex", positive=True)
    uint(network["network_namespace_inode"], "context calibration network namespace", positive=True)
    route = exact(network["route"], {"dst", "dev", "source"}, "context calibration loopback route")
    require(route == {"dst": "127.0.0.1", "dev": "lo", "source": "127.0.0.1"}, "context calibration loopback route differs")
    require(network["shared_kernel"] is True and network["physical_nic_claimed"] is False and network["claim"] == "ipv4_loopback_shared_kernel_only", "context calibration makes an unsupported loopback claim")
    require(network == host["network"] and scope["network_sha256"] == digest_object(network), "context calibration loopback network digest differs")
    require(network["claim"] == "ipv4_loopback_shared_kernel_only" and network["physical_nic_claimed"] is False, "context calibration makes an unsupported physical network claim")
    samples = calibration["samples"]
    require(type(samples) is list and len(samples) == schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"], "context calibration sample count differs from its full schedule")
    _validate_calibration_samples(samples, {"schedule": schedule, "storage": storage}, calibration)
    _validate_samples_meet_pressure_thresholds_v2(samples, scope["pressure_thresholds"])
    _validate_calibration_cleanup_v2(calibration, schedule, require_local_reap=require_local_reap)
    start = uint(calibration["start_monotonic_ns"], "context calibration start", positive=True)
    finish = uint(calibration["finish_monotonic_ns"], "context calibration finish", positive=True)
    deadlines = exact(calibration["deadlines"], {"startup_seconds", "total_seconds", "term_seconds", "kill_seconds"}, "context calibration deadlines")
    require(deadlines == {
        "startup_seconds": schedule["startup_deadline_seconds"],
        "total_seconds": schedule["total_deadline_seconds"],
        "term_seconds": schedule["term_deadline_seconds"],
        "kill_seconds": schedule["kill_deadline_seconds"],
    }, "context calibration deadlines differ from the request schedule")
    calibration_ns = len(samples) * schedule["sample_interval_ms"] * 1_000_000
    require(3_000_000_000 <= calibration_ns <= 120_000_000_000 and finish >= start and finish - start <= deadlines["total_seconds"] * 1_000_000_000, "context calibration duration exceeds its finite bound")
    summary = _measurement_summary(samples)
    require(summary == calibration["summary"], "context calibration summary differs from every raw sample")
    proposed = _propose(summary)
    require(proposed == calibration["suggested_readiness_thresholds"], "context calibration threshold proposal differs from its measured samples")
    exact(calibration["suggested_readiness_thresholds"], {
        "cpu_busy_min_basis_points", "disk_write_min_bytes_per_second", "disk_queue_or_stall_min_microseconds",
        "loopback_requests_min_per_second", "loopback_latency_p99_max_nanoseconds",
        "loopback_tx_min_bytes_per_second", "loopback_rx_min_bytes_per_second",
    }, "context calibration proposed readiness thresholds")
    return calibration


def _source5_observation_matches(calibration: dict[str, Any], observed_host_pin_value: object) -> tuple[dict[str, Any], dict[str, Any]]:
    scope = calibration["scope"]
    key = scope["capacity_key"]
    pin, observed = _verify_observed_host_pin_v2(observed_host_pin_value, key["host_id"])
    require(pin == scope["observed_host"], "context calibration observed-host pin differs from its scope")
    host = calibration["host"]
    network = calibration["network"]
    require(
        observed["boot_id_sha256"] == host["boot_id_sha256"]
        and observed["kernel_release"] == host["kernel_release"]
        and observed["cpu_affinity"] == host["allowed_cpu_affinity"]
        and observed["network_namespace_inode"] == network["network_namespace_inode"],
        "context calibration host/boot/affinity/netns differs from the pinned observed Source5 host",
    )
    return pin, observed


def _host_verification_v2(
    calibration: dict[str, Any], observed_pin: dict[str, Any], observed: dict[str, Any],
    *, require_live: bool,
) -> dict[str, Any]:
    host = calibration["host"]
    network = calibration["network"]
    if require_live:
        require(os.name == "posix" and sys.platform.startswith("linux"), "strict SourceV5 host verification requires Linux")
        require(os.uname().release == observed["kernel_release"] == host["kernel_release"], "live kernel differs from the observed SourceV5 host")
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip().decode("ascii")
        except (OSError, UnicodeError) as error:
            raise ReadbackError(f"cannot read live boot identity: {error}") from error
        require(re.fullmatch(r"[0-9a-f-]{36}", boot_id) is not None, "live boot identity is malformed")
        require(sha256_bytes(boot_id.encode("ascii")) == observed["boot_id_sha256"] == host["boot_id_sha256"], "live boot identity differs from the observed SourceV5 host")
        affinity = sorted(os.sched_getaffinity(0))
        require(affinity == observed["cpu_affinity"] == host["allowed_cpu_affinity"], "live CPU affinity differs from the observed SourceV5 host")
        descriptor = os.open("/proc/cpuinfo", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            cpu_raw = bytearray()
            while True:
                block = os.read(descriptor, min(1024 * 1024, 16 * 1024 * 1024 + 1 - len(cpu_raw)))
                if not block:
                    break
                cpu_raw.extend(block)
                require(len(cpu_raw) <= 16 * 1024 * 1024, "live CPU model source exceeds its finite bound")
        finally:
            os.close(descriptor)
        try:
            models = {
                line.split(":", 1)[1].strip()
                for line in bytes(cpu_raw).decode("utf-8").splitlines()
                if line.lower().startswith("model name") and ":" in line
            }
        except UnicodeError as error:
            raise ReadbackError("live CPU model source is not UTF-8") from error
        require(len(models) == 1 and next(iter(models)) == observed["cpu_model"], "live CPU model differs from the observed SourceV5 host")
        namespace = os.stat("/proc/self/ns/net").st_ino
        require(namespace == observed["network_namespace_inode"] == network["network_namespace_inode"], "live network namespace differs from the observed SourceV5 host")
    body = {
        "schema": CALIBRATION_HOST_VERIFICATION_SCHEMA_V2,
        "host_id": observed["host_id"],
        "boot_id_sha256": observed["boot_id_sha256"],
        "kernel_release": observed["kernel_release"],
        "allowed_cpu_affinity": observed["cpu_affinity"],
        "network_namespace_inode": observed["network_namespace_inode"],
        "observed_host_raw_sha256": observed_pin["raw_sha256"],
        "owned_worker_pids_reaped": True,
    }
    return {**body, "host_verification_sha256": digest_object(body)}


def _replay_calibration_scope_v2(
    calibration_pin: object, context_policy_pin: object,
    capacity_bundle_pins: object, observed_host_pin: object, *, require_local_host: bool,
    expected_source_root: Path | None = None,
) -> dict[str, Any]:
    """Replay one v2 calibration; strict mode additionally checks its live host."""
    calibration_file_pin = _raw_pin(calibration_pin, "context calibration artifact")
    calibration_value, calibration_raw, calibration_raw_sha = read_canonical(
        Path(calibration_file_pin["path"]), "context calibration artifact", 64 * 1024 * 1024,
    )
    require(calibration_raw_sha == calibration_file_pin["raw_sha256"], "context calibration artifact raw digest differs")
    calibration = _validate_calibration_v2_body(calibration_value, require_local_reap=require_local_host)
    scope = calibration["scope"]
    require(
        expected_source_root is None or scope["source_root"] == str(expected_source_root),
        "offline SourceV5 source root differs from the original calibration bytes",
    )
    capacity_pins = exact(capacity_bundle_pins, {
        "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
    }, "context calibration capacity bundle input")
    require(capacity_pins == scope["capacity_bundle_pins"], "context calibration capacity bundle differs from its independently supplied pin")
    _preflight_scope_replay_paths_v2(scope, context_policy_pin, capacity_pins, observed_host_pin)
    source_stack = _source5_stack(
        scope["source_manifest"], scope["source_root"],
        verify_git_commit=require_local_host,
    )
    require(
        source_stack["source_raw_sha256"] == scope["source_manifest"]["raw_sha256"]
        and source_stack["source_semantic_sha256"] == scope["source_manifest_semantic_sha256"]
        and source_stack["source_tree_sha256"] == scope["source_tree_sha256"],
        "context calibration source raw/semantic/tree pins differ from the live typed SourceV5 tree",
    )
    observed_pin, observed = _source5_observation_matches(calibration, observed_host_pin)
    host_verification = _host_verification_v2(
        calibration, observed_pin, observed, require_live=require_local_host,
    )
    capacity = _verify_capacity_bundle_v2(source_stack, capacity_pins, scope["source_manifest"], observed)
    require(capacity["capacity_key"] == scope["capacity_key"], "prepared capacity key differs from calibration scope")
    require(capacity["capacity_tsv_raw_sha256"] == calibration["raw_inputs"]["application_capacity_calibration_sha256"], "prepared capacity TSV differs from the exact calibration input bytes")
    calibration_policy = _verify_context_policy_bundle_v2(
        source_stack, scope["context_policy_bundle"], capacity, scope["source_manifest"],
    )
    require(
        calibration_policy["numeric_context_policy_sha256"] == scope["context_policy_sha256"]
        and calibration_policy["raw_sha256"] == calibration["raw_inputs"]["context_policy_bundle_raw_sha256"]
        and calibration_policy["policy_raw_sha256"] == calibration["raw_inputs"]["policy_artifact_raw_sha256"],
        "calibration context-policy bundle differs from its independently pinned raw inputs",
    )
    policy_replay = _verify_context_policy_bundle_v2(source_stack, context_policy_pin, capacity, scope["source_manifest"])
    require(
        policy_replay["numeric_context_policy_sha256"] == calibration_policy["numeric_context_policy_sha256"],
        "current per-job context-policy projection differs from the calibrated numeric policy",
    )
    condition_pin, condition = _verify_condition_file_v2(scope["condition"], scope["capacity_key"], scope["condition_id"], calibration["schedule"])
    require(condition_pin["raw_sha256"] == calibration["raw_inputs"]["condition_raw_sha256"], "Source5 pressure-condition bytes differ from the calibration raw input")
    sample_raw_sha = digest_object(calibration["samples"])
    cleanup_sha = digest_object(calibration["worker_cleanup"])
    receipt_body = {
        "schema": CALIBRATION_SCOPE_RECEIPT_SCHEMA_V2,
        "replay_success": True,
        "validated": True,
        "execution_ready": False,
        "qualification_eligible": False,
        "controller_chronology_proven": False,
        "calibration_raw_sha256": calibration_raw_sha,
        "calibration_sha256": calibration["calibration_sha256"],
        "scope_sha256": digest_object(scope),
        "condition_id": calibration["identity"]["condition_id"],
        "pressure_calibration_id": condition["pressure_calibration_id"],
        "capacity_key": scope["capacity_key"],
        "condition_sha256": condition_pin["raw_sha256"],
        "source_manifest_sha256": source_stack["source_raw_sha256"],
        "source_manifest_semantic_sha256": source_stack["source_semantic_sha256"],
        "source_tree_sha256": source_stack["source_tree_sha256"],
        "context_policy_bundle_raw_sha256": policy_replay["raw_sha256"],
        "context_policy_artifact_raw_sha256": policy_replay["policy_raw_sha256"],
        "context_policy_sha256": policy_replay["numeric_context_policy_sha256"],
        "capacity_bundle_pins_sha256": digest_object(capacity_pins),
        "capacity_tsv_raw_sha256": capacity["capacity_tsv_raw_sha256"],
        "observed_host_raw_sha256": observed_pin["raw_sha256"],
        "host_verification": host_verification,
        "driver_sha256": calibration["driver_sha256"],
        "reader_sha256": calibration["reader_sha256"],
        "capacity_producer_sha256": source_stack["producer_sha256"],
        "feedback_composer_sha256": source_stack["composer_sha256"],
        "feedback_reader_sha256": source_stack["feedback_reader_sha256"],
        "sample_count": len(calibration["samples"]),
        "samples_sha256": sample_raw_sha,
        "summary": calibration["summary"],
        "pressure_thresholds": condition["pressure_thresholds"],
        "readiness_thresholds": condition["readiness_thresholds"],
        "suggested_readiness_thresholds": calibration["suggested_readiness_thresholds"],
        "worker_cleanup_sha256": cleanup_sha,
        "worker_session_count": len(calibration["worker_sessions"]),
        "scratch_file_removed": calibration["scratch_file_removed"],
    }
    return {**receipt_body, "receipt_sha256": digest_object(receipt_body)}


def verify_calibration_scope_v2(
    calibration_pin: object, context_policy_pin: object,
    capacity_bundle_pins: object, observed_host_pin: object,
) -> dict[str, Any]:
    """Replay the calibration and verify that its pinned host is still live locally."""
    return _replay_calibration_scope_v2(
        calibration_pin, context_policy_pin, capacity_bundle_pins, observed_host_pin,
        require_local_host=True,
    )


def verify_calibration_scope_v2_offline(
    calibration_pin: object, context_policy_pin: object,
    capacity_bundle_pins: object, observed_host_pin: object, *,
    source_root: object, evidence_path_map: object, host_verification_pin: object,
) -> dict[str, Any]:
    """Replay raw evidence off-host under a checked identity path map.

    SourceV5 producer and composer requests contain absolute path strings in
    their canonical bytes. The first supported offline path map therefore
    requires identity mappings: stage each peer file at its original absolute
    path. Non-identity translations are rejected instead of changing a
    producer/composer input or normalizing a changed canonical receipt.
    """
    source_root_path = absolute_path(source_root, "offline SourceV5 source root")
    mapping, directories = _normalize_evidence_path_map(evidence_path_map, str(source_root_path))
    token = _EVIDENCE_PATH_MAP_CONTEXT.set((mapping, directories))
    try:
        result = _replay_calibration_scope_v2(
            calibration_pin, context_policy_pin, capacity_bundle_pins, observed_host_pin,
            require_local_host=False, expected_source_root=source_root_path,
        )
        stored_pin = _scope_receipt_pin_v2(host_verification_pin, "strict host verification receipt")
        require(stored_pin["scope_sha256"] == result["scope_sha256"], "host verification receipt pin names a different calibration scope")
        stored_value, _, stored_raw_sha = read_canonical(
            Path(stored_pin["path"]), "strict host verification receipt", MAX_SCOPE_RECEIPT_BYTES,
        )
        require(stored_raw_sha == stored_pin["raw_sha256"], "strict host verification receipt raw digest differs")
        stored = _validate_scope_receipt_v2(stored_value, result["calibration_raw_sha256"])
        require(
            _scope_receipts_match_replay_v2(stored, result),
            "offline SourceV5 replay differs from the strict host verification receipt",
        )
        require(
            stored["host_verification"] == result["host_verification"]
            and stored["scope_sha256"] == stored_pin["scope_sha256"],
            "strict host verification identity differs from the offline calibration evidence",
        )
        return stored
    finally:
        _EVIDENCE_PATH_MAP_CONTEXT.reset(token)


def _validate_scope_receipt_v2(value: object, expected_calibration_raw_sha: str) -> dict[str, Any]:
    receipt = exact(value, {
        "schema", "replay_success", "validated", "execution_ready", "qualification_eligible", "controller_chronology_proven",
        "calibration_raw_sha256", "calibration_sha256", "scope_sha256", "condition_id", "pressure_calibration_id",
        "capacity_key", "condition_sha256",
        "source_manifest_sha256", "source_manifest_semantic_sha256", "source_tree_sha256",
        "context_policy_bundle_raw_sha256", "context_policy_artifact_raw_sha256",
        "context_policy_sha256", "capacity_bundle_pins_sha256", "capacity_tsv_raw_sha256",
        "observed_host_raw_sha256", "host_verification", "driver_sha256", "reader_sha256",
        "capacity_producer_sha256", "feedback_composer_sha256", "feedback_reader_sha256",
        "sample_count", "samples_sha256", "summary", "pressure_thresholds", "readiness_thresholds",
        "suggested_readiness_thresholds",
        "worker_cleanup_sha256", "worker_session_count", "scratch_file_removed", "receipt_sha256",
    }, "context calibration independent receipt")
    require(receipt["schema"] == CALIBRATION_SCOPE_RECEIPT_SCHEMA_V2, "unsupported context calibration receipt schema")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    require(sha256(receipt["receipt_sha256"], "context calibration receipt digest") == digest_object(body), "context calibration independent receipt digest is invalid")
    require(receipt["replay_success"] is True and receipt["validated"] is True and receipt["execution_ready"] is False and receipt["qualification_eligible"] is False and receipt["controller_chronology_proven"] is False, "context calibration receipt makes an unsupported readiness/eligibility claim")
    require(receipt["calibration_raw_sha256"] == expected_calibration_raw_sha, "context calibration receipt refers to different artifact bytes")
    capacity_key = _capacity_key_v2(receipt["capacity_key"], "context calibration receipt capacity key")
    condition_id = text(receipt["condition_id"], "context calibration receipt condition ID", 96)
    pressure_calibration_id = text(receipt["pressure_calibration_id"], "context calibration receipt pressure calibration ID", 96)
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", pressure_calibration_id) is not None
        and pressure_calibration_id not in (condition_id, capacity_key["calibration_id"]),
        "context calibration receipt pressure calibration ID aliases another identity",
    )
    host_verification = exact(receipt["host_verification"], {
        "schema", "host_id", "boot_id_sha256", "kernel_release", "allowed_cpu_affinity",
        "network_namespace_inode", "observed_host_raw_sha256", "owned_worker_pids_reaped",
        "host_verification_sha256",
    }, "context calibration host verification")
    require(host_verification["schema"] == CALIBRATION_HOST_VERIFICATION_SCHEMA_V2, "unsupported context calibration host-verification schema")
    host_verification_body = {key: value for key, value in host_verification.items() if key != "host_verification_sha256"}
    require(
        sha256(host_verification["host_verification_sha256"], "context calibration host-verification digest")
        == digest_object(host_verification_body),
        "context calibration host-verification self digest is invalid",
    )
    require(
        host_verification["host_id"] == capacity_key["host_id"]
        and host_verification["owned_worker_pids_reaped"] is True
        and host_verification["observed_host_raw_sha256"] == receipt["observed_host_raw_sha256"],
        "context calibration host verification differs from its host pin or cleanup proof",
    )
    sha256(host_verification["boot_id_sha256"], "host verification boot ID hash")
    text(host_verification["kernel_release"], "host verification kernel release", 256)
    affinity = host_verification["allowed_cpu_affinity"]
    require(
        type(affinity) is list and 1 <= len(affinity) <= 4096
        and affinity == sorted(set(uint(cpu, "host verification CPU", maximum=65535) for cpu in affinity)),
        "context calibration host verification CPU affinity is malformed",
    )
    uint(host_verification["network_namespace_inode"], "host verification network namespace", positive=True)
    for field in (
        "calibration_sha256", "scope_sha256", "condition_sha256", "source_manifest_sha256",
        "context_policy_bundle_raw_sha256",
        "context_policy_artifact_raw_sha256", "context_policy_sha256",
        "capacity_bundle_pins_sha256", "capacity_tsv_raw_sha256",
        "source_manifest_semantic_sha256", "source_tree_sha256", "observed_host_raw_sha256",
        "driver_sha256", "reader_sha256", "capacity_producer_sha256",
        "feedback_composer_sha256", "feedback_reader_sha256", "samples_sha256", "worker_cleanup_sha256",
    ):
        sha256(receipt[field], f"context calibration receipt {field}")
    _pressure_thresholds_v2(receipt["pressure_thresholds"], "context calibration receipt pressure thresholds")
    _campaign_readiness_thresholds_v1(receipt["readiness_thresholds"], "context calibration receipt campaign readiness thresholds")
    uint(receipt["sample_count"], "context calibration receipt sample count", positive=True, maximum=MAX_SAMPLE_COUNT)
    uint(receipt["worker_session_count"], "context calibration receipt worker session count", positive=True)
    require(receipt["scratch_file_removed"] is True, "context calibration receipt omits scratch removal")
    return receipt


def _scope_receipts_match_replay_v2(stored: dict[str, Any], replayed: dict[str, Any]) -> bool:
    # Per-job composer references may change; all stable calibration evidence
    # and the independently replayed numeric context must remain identical.
    reference_dependent = {
        "context_policy_bundle_raw_sha256", "context_policy_artifact_raw_sha256", "receipt_sha256",
    }
    return (
        {key: value for key, value in stored.items() if key not in reference_dependent}
        == {key: value for key, value in replayed.items() if key not in reference_dependent}
    )


def _validate_calibration_v2_recipe(recipe: dict[str, Any], *, offline_context: dict[str, Any] | None = None) -> dict[str, Any]:
    binding = recipe["calibration_scope_v2"]
    calibration_pin = {"path": recipe["pressure_calibration"]["path"], "raw_sha256": recipe["pressure_calibration"]["raw_sha256"]}
    calibration_value, _, calibration_raw_sha = read_canonical(Path(calibration_pin["path"]), "frozen context calibration v2", 64 * 1024 * 1024)
    require(calibration_raw_sha == calibration_pin["raw_sha256"], "frozen context calibration v2 raw digest differs")
    calibration = _validate_calibration_v2_body(calibration_value)
    require(calibration["identity"]["host_id"] == recipe["identity"]["host_id"] and calibration["identity"]["condition_id"] == recipe["identity"]["condition_id"], "context calibration host/condition differs from the actual pressure recipe")
    scope = calibration["scope"]
    key = scope["capacity_key"]
    require(key["host_id"] == recipe["identity"]["host_id"], "context calibration host differs from the actual pressure recipe")
    require(scope["condition"] == binding["condition"], "actual pressure recipe refers to different Source5 condition bytes than the calibration")
    require(recipe["files"]["source_manifest"] == scope["source_manifest"], "context calibration SourceV5 pin differs from the actual pressure recipe")
    require(recipe["files"]["application_capacity_calibration"]["raw_sha256"] == scope["capacity_bundle_pins"]["artifact"]["raw_sha256"], "context calibration prepared TSV differs from the actual pressure recipe")
    require(digest_object(_pressure_profile_v2(recipe["schedule"])) == scope["pressure_profile_sha256"], "actual pressure recipe intensity differs from context calibration")
    require(digest_object(_pressure_profile_v2(recipe["schedule"])) == calibration["schedule_sha256"], "actual pressure recipe intensity differs from calibration samples")
    cal_host = calibration["host"]
    recipe_host = recipe["host"]
    require(
        cal_host["kernel_release"] == recipe_host["kernel_release"]
        and cal_host["boot_id_sha256"] == recipe_host["boot_id_sha256"]
        and cal_host["allowed_cpu_affinity"] == recipe_host["allowed_cpu_affinity"]
        and cal_host["pressure_cpu_affinity"] == recipe_host["pressure_cpu_affinity"]
        and cal_host["application_cpu_affinity"] == recipe_host["application_cpu_affinity"],
        "context calibration host/kernel/affinity differs from the actual pressure recipe",
    )
    require(calibration["network"] == recipe_host["network"], "context calibration loopback route/network namespace differs from the actual pressure recipe")
    require(calibration["storage"] == {
        "application_device": recipe["storage"]["application_device"],
        "mount_id": recipe["storage"]["application_mount_id"],
        "backing_chain": recipe["storage"]["backing_chain"],
    }, "context calibration block device/mount/backing chain differs from the actual pressure recipe")
    condition_pin, condition = _verify_condition_file_v2(binding["condition"], key, recipe["identity"]["condition_id"], recipe["schedule"])
    require(condition_pin == scope["condition"], "actual recipe Source5 condition pin differs from the context calibration")
    require(
        recipe["schedule"]["minimum_overlap_seconds"] == condition["readiness_thresholds"]["minimum_overlap_seconds"]
        and recipe["schedule"]["sample_interval_ms"] == 100,
        "actual pressure recipe schedule weakens the Source5 campaign readiness window",
    )
    require(
        condition["readiness_thresholds"]["minimum_ready_samples"]
        <= recipe["schedule"]["duration_seconds"] * 1000 // recipe["schedule"]["sample_interval_ms"],
        "actual pressure recipe is too short for the Source5 minimum ready-sample count",
    )
    require(recipe["readiness_thresholds"] == condition["pressure_thresholds"], "actual pressure recipe numeric thresholds differ from the prospective Source5 condition")
    receipt_pin = binding["scope_receipt"]
    require(receipt_pin["scope_sha256"] == digest_object(scope), "scope receipt pin names a different calibration scope digest")
    receipt_value, _, receipt_raw_sha = read_canonical(Path(receipt_pin["path"]), "stored context calibration scope receipt", MAX_SCOPE_RECEIPT_BYTES)
    require(receipt_raw_sha == receipt_pin["raw_sha256"], "stored context calibration scope receipt raw digest differs")
    receipt = _validate_scope_receipt_v2(receipt_value, calibration_raw_sha)
    require(
        receipt["calibration_sha256"] == calibration["calibration_sha256"]
        and receipt["scope_sha256"] == digest_object(scope)
        and receipt["capacity_key"] == scope["capacity_key"]
        and receipt["condition_sha256"] == binding["condition"]["raw_sha256"]
        and receipt["source_manifest_sha256"] == recipe["files"]["source_manifest"]["raw_sha256"]
        and receipt["context_policy_sha256"] == binding["context_policy_sha256"] == scope["context_policy_sha256"]
        and receipt["reader_sha256"] == binding["validator_sha256"]
        and receipt["capacity_bundle_pins_sha256"] == digest_object(binding["capacity_bundle_pins"])
        and receipt["capacity_tsv_raw_sha256"] == recipe["files"]["application_capacity_calibration"]["raw_sha256"]
        and receipt["observed_host_raw_sha256"] == binding["observed_host"]["raw_sha256"]
        and receipt["condition_sha256"] == scope["condition"]["raw_sha256"]
        and receipt["pressure_thresholds"] == condition["pressure_thresholds"]
        and receipt["readiness_thresholds"] == condition["readiness_thresholds"],
        "stored independent scope receipt differs from the frozen calibration/context pins",
    )
    if offline_context is None:
        replay = verify_calibration_scope_v2(
            calibration_pin, binding["context_policy"], binding["capacity_bundle_pins"], binding["observed_host"],
        )
    else:
        replay = verify_calibration_scope_v2_offline(
            calibration_pin, binding["context_policy"], binding["capacity_bundle_pins"],
            binding["observed_host"], source_root=offline_context["source_root"],
            evidence_path_map=offline_context["evidence_path_map"],
            host_verification_pin=binding["scope_receipt"],
        )
    require(
        _scope_receipts_match_replay_v2(receipt, replay),
        "current per-job SourceV5 context no longer matches the independently verified calibration receipt",
    )
    return {
        "calibration_sha256": calibration["calibration_sha256"],
        "scope_receipt_sha256": receipt_raw_sha,
        "scope_sha256": receipt["scope_sha256"],
        "context_policy_sha256": receipt["context_policy_sha256"],
        "capacity_bundle_pins_sha256": receipt["capacity_bundle_pins_sha256"],
        "minimum_ready_samples": condition["readiness_thresholds"]["minimum_ready_samples"],
    }


def _iter_events(
    path: Path, expected_sha: str, expected_bytes: int, maximum_bytes: int,
    state: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    try:
        require(path.resolve(strict=True) == path, "pressure events path traverses a symlink or alias")
        path_info = path.lstat()
        require(stat.S_ISREG(path_info.st_mode), "pressure events must be a regular nonsymlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise ReadbackError(f"cannot safely open pressure events: {error}") from error
    stream = os.fdopen(descriptor, "rb", buffering=0)
    try:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(path_info), "pressure events changed while opening")
        require(0 <= before.st_size <= maximum_bytes and before.st_size == expected_bytes, "pressure event size differs from its frozen budget/receipt")
        digest = hashlib.sha256()
        total = 0
        event_count = 0
        while True:
            line = stream.readline(MAX_EVENT_LINE_BYTES + 1)
            if not line:
                break
            require(len(line) <= MAX_EVENT_LINE_BYTES and line.endswith(b"\n"), f"pressure event line {event_count} is sparse or oversized")
            require(b"\r" not in line and b"\0" not in line, f"pressure event line {event_count} has invalid framing")
            total += len(line)
            require(total <= maximum_bytes and total <= expected_bytes, "pressure event stream exceeded its frozen byte budget")
            digest.update(line)
            value = parse_object(line[:-1], f"pressure event[{event_count}]", MAX_EVENT_LINE_BYTES)
            require(line == canonical_bytes(value), f"pressure event line {event_count} is not canonical")
            event_count += 1
            require(event_count <= MAX_EVENT_COUNT, "pressure event count exceeds its hard bound")
            state["event_count"] = event_count
            yield value
        after_fd = os.fstat(stream.fileno())
        after_path = path.lstat()
        require(_stat_key(before) == _stat_key(after_fd) == _stat_key(after_path) and total == before.st_size == expected_bytes, "pressure event file changed during streaming verification")
        actual = digest.hexdigest()
        require(actual == expected_sha, "pressure events differ from separately supplied raw digest")
        require(1 <= event_count <= MAX_EVENT_COUNT, "pressure event count is outside its hard bound")
        state["events_sha256"] = actual
        state["events_bytes"] = total
    finally:
        stream.close()


def _validate_worker_ownership(value: object, recipe: dict[str, Any]) -> tuple[dict[tuple[str, int | None], dict[str, Any]], str, int]:
    event = exact(value, {
        "schema", "kind", "recipe_sha256", "nonce", "monotonic_ns", "workers", "ownership_sha256",
    }, "durable pressure worker ownership event")
    require(event["schema"] == EVENT_SCHEMA and event["kind"] == "worker_ownership", "worker ownership event identity differs")
    require(event["recipe_sha256"] == recipe["recipe_sha256"] and event["nonce"] == recipe["identity"]["nonce"], "worker ownership event recipe/nonce differs")
    ownership_time = uint(event["monotonic_ns"], "worker ownership journal time", positive=True)
    body = {key: item for key, item in event.items() if key != "ownership_sha256"}
    ownership_sha = sha256(event["ownership_sha256"], "worker ownership journal digest")
    require(digest_object(body) == ownership_sha, "worker ownership journal self digest differs")
    rows = event["workers"]
    require(type(rows) is list and len(rows) == len(recipe["schedule"]["pressure_cpu_affinity"]) + 2, "worker ownership journal is sparse")
    result: dict[tuple[str, int | None], dict[str, Any]] = {}
    seen_pids: set[int] = set()
    for row_value in rows:
        row = exact(row_value, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id", "nonce"}, "durable pressure worker identity")
        role = text(row["role"], "owned worker role", 16)
        cpu = row["cpu"]
        if role == "cpu":
            cpu = uint(cpu, "owned pressure worker CPU", maximum=65535)
            require(cpu in recipe["schedule"]["pressure_cpu_affinity"], "owned pressure worker CPU is outside the frozen affinity")
        else:
            require(cpu is None and role in ("disk", "loopback"), "durable worker ownership role is unsupported")
        pid = uint(row["pid"], "owned worker PID", positive=True, maximum=(1 << 31) - 1)
        require(pid not in seen_pids, "durable worker ownership journal duplicates a worker PID")
        seen_pids.add(pid)
        ticks = uint(row["start_ticks"], "owned worker start ticks", positive=True)
        pgid = uint(row["pgid"], "owned worker PGID", positive=True, maximum=(1 << 31) - 1)
        sid = uint(row["session_id"], "owned worker session", positive=True, maximum=(1 << 31) - 1)
        require(row["nonce"] == recipe["identity"]["nonce"] and pgid == pid and sid == pid, "durable worker ownership identity differs from its isolated session/nonce")
        key = (role, cpu)
        require(key not in result, "durable worker ownership journal duplicates a role")
        result[key] = {**row, "pid": pid, "start_ticks": ticks, "pgid": pgid, "session_id": sid}
    expected = {("cpu", cpu) for cpu in recipe["schedule"]["pressure_cpu_affinity"]} | {("disk", None), ("loopback", None)}
    require(set(result) == expected, "durable worker ownership set differs from its frozen recipe")
    return result, ownership_sha, ownership_time


def _validate_workers_authorized(
    value: object, recipe: dict[str, Any], ownership_rows: dict[tuple[str, int | None], dict[str, Any]],
    ownership_sha256: str,
) -> tuple[str, int]:
    event = exact(value, {
        "schema", "kind", "recipe_sha256", "nonce", "ownership_sha256", "monotonic_ns",
        "workers", "authorization_sha256",
    }, "durable pressure worker authorization event")
    require(event["schema"] == EVENT_SCHEMA and event["kind"] == "workers_authorized", "worker authorization event identity differs")
    require(event["recipe_sha256"] == recipe["recipe_sha256"] and event["nonce"] == recipe["identity"]["nonce"], "worker authorization event recipe/nonce differs")
    require(event["ownership_sha256"] == ownership_sha256, "worker authorization event names a different ownership journal")
    authorization_time = uint(event["monotonic_ns"], "worker authorization journal time", positive=True)
    body = {key: item for key, item in event.items() if key != "authorization_sha256"}
    authorization_sha = sha256(event["authorization_sha256"], "worker authorization journal digest")
    require(digest_object(body) == authorization_sha, "worker authorization journal self digest differs")
    rows = event["workers"]
    require(type(rows) is list and len(rows) == len(ownership_rows), "worker authorization ACK set is sparse")
    acknowledgements: dict[tuple[str, int | None], dict[str, Any]] = {}
    for row_value in rows:
        ack = exact(row_value, {
            "schema", "event", "recipe_sha256", "nonce", "ownership_sha256", "role", "cpu",
            "pid", "start_ticks", "pgid", "session_id", "ack_sha256",
        }, "worker ownership acknowledgement row")
        role = text(ack["role"], "ownership ACK role", 16)
        cpu = uint(ack["cpu"], "ownership ACK CPU", maximum=65535) if role == "cpu" else None
        key = (role, cpu)
        require(key in ownership_rows and key not in acknowledgements, "worker authorization repeats or invents a role")
        owner = ownership_rows[key]
        ack_body = {name: item for name, item in ack.items() if name != "ack_sha256"}
        require(
            ack["schema"] == "allocatbelt.application-pressure-worker-ownership-ack.v1"
            and ack["event"] == "ownership_ack"
            and ack["recipe_sha256"] == recipe["recipe_sha256"]
            and ack["nonce"] == recipe["identity"]["nonce"]
            and ack["ownership_sha256"] == ownership_sha256
            and all(ack[name] == owner[name] for name in ("role", "cpu", "pid", "start_ticks", "pgid", "session_id", "nonce"))
            and sha256(ack["ack_sha256"], "worker ownership ACK self digest") == digest_object(ack_body),
            "worker ACK differs from the durable ownership row",
        )
        acknowledgements[key] = ack
    require(set(acknowledgements) == set(ownership_rows), "worker authorization ACK set differs from the durable ownership set")
    return authorization_sha, authorization_time


def _validate_worker_start(
    value: object, recipe: dict[str, Any], ownership_sha256: str | None = None,
    authorization_sha256: str | None = None,
) -> dict[tuple[str, int | None], dict[str, Any]]:
    keys = {
        "schema", "kind", "sequence", "recipe_sha256", "monotonic_ns", "workers",
        "storage_device", "network_namespace_inode",
    }
    strong = ownership_sha256 is not None or authorization_sha256 is not None
    if strong:
        keys |= {"nonce", "ownership_sha256", "authorization_sha256"}
    start = exact(value, keys, "pressure start event")
    require(start["schema"] == EVENT_SCHEMA and start["kind"] == "pressure_start" and start["sequence"] == -1, "pressure start event identity differs")
    require(start["recipe_sha256"] == recipe["recipe_sha256"], "pressure start event belongs to another recipe")
    if strong:
        require(start["nonce"] == recipe["identity"]["nonce"] and start["ownership_sha256"] == ownership_sha256 and start["authorization_sha256"] == authorization_sha256, "pressure start event is not bound to its durable ownership/authorization journals")
    uint(start["monotonic_ns"], "pressure start time", positive=True)
    require(start["storage_device"] == recipe["storage"]["application_device"], "pressure start device differs from recipe")
    require(start["network_namespace_inode"] == recipe["network"]["network_namespace_inode"], "pressure start network namespace differs")
    workers = start["workers"]
    require(type(workers) is list and len(workers) == len(recipe["schedule"]["pressure_cpu_affinity"]) + 2, "pressure start worker set is sparse")
    output: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in workers:
        worker = exact(item, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id"}, "pressure worker identity")
        role = text(worker["role"], "worker role", 16)
        cpu = worker["cpu"]
        if role == "cpu":
            cpu = uint(cpu, "worker CPU", maximum=65535)
            require(cpu in recipe["schedule"]["pressure_cpu_affinity"], "worker CPU is outside frozen pressure affinity")
        else:
            require(cpu is None and role in ("disk", "loopback"), "unknown pressure worker role")
        pid = uint(worker["pid"], "worker PID", positive=True, maximum=(1 << 31) - 1)
        ticks = uint(worker["start_ticks"], "worker start ticks", positive=True)
        pgid = uint(worker["pgid"], "worker process group", positive=True, maximum=(1 << 31) - 1)
        sid = uint(worker["session_id"], "worker session", positive=True, maximum=(1 << 31) - 1)
        require(pgid == pid and sid == pid, "pressure worker was not isolated in its own session")
        key = (role, cpu)
        require(key not in output, "pressure worker set contains a duplicate role")
        output[key] = {**worker, "pid": pid, "start_ticks": ticks}
    expected = {("cpu", cpu) for cpu in recipe["schedule"]["pressure_cpu_affinity"]} | {("disk", None), ("loopback", None)}
    require(set(output) == expected, "pressure worker set differs from frozen resource schedule")
    if strong:
        require(ownership_sha256 is not None and authorization_sha256 is not None, "strong pressure start omitted its ownership protocol digests")
    return output


def _validate_launch(value: object, recipe: dict[str, Any], expected_sha: str) -> dict[str, Any]:
    launch = exact(value, {"schema", "recipe_sha256", "nonce", "process", "launch_binding_sha256"}, "application launch binding")
    require(launch["schema"] == LAUNCH_SCHEMA and launch["recipe_sha256"] == recipe["recipe_sha256"] and launch["nonce"] == recipe["identity"]["nonce"], "application launch binding identity differs")
    body = {key: value for key, value in launch.items() if key != "launch_binding_sha256"}
    require(sha256(launch["launch_binding_sha256"], "launch binding digest") == digest_object(body), "application launch binding self digest is invalid")
    process = exact(launch["process"], {"pid", "start_ticks", "executable_path", "executable_sha256", "cwd", "tmpdir_path", "cpu_affinity", "network_namespace_inode"}, "application process identity")
    uint(process["pid"], "application PID", positive=True, maximum=(1 << 31) - 1)
    uint(process["start_ticks"], "application process start ticks", positive=True)
    require(process["executable_path"] == recipe["process"]["executable_path"] and process["executable_sha256"] == recipe["files"]["application_binary"]["raw_sha256"], "application process binary differs from frozen recipe")
    require(process["cwd"] in recipe["storage"]["application_io_paths"], "application cwd differs from frozen I/O path set")
    require(process["tmpdir_path"] == recipe["process"]["application_tmpdir_path"] and process["tmpdir_path"] in recipe["storage"]["application_io_paths"], "application TMPDIR differs from frozen I/O path set")
    require(process["cpu_affinity"] == recipe["schedule"]["application_cpu_affinity"], "application CPU affinity differs from frozen recipe")
    require(process["network_namespace_inode"] == recipe["network"]["network_namespace_inode"], "application network namespace differs from frozen recipe")
    return process


def _validate_run(value: object, expected: dict[str, str]) -> dict[str, Any]:
    run = exact(value, {
        "schema", "status", "failure", "recipe_sha256", "condition_sha256", "events_sha256",
        "events_bytes", "event_count", "sample_count", "process_binding_sha256",
        "launch_record_sha256", "readiness_marker_sha256", "application_overlap_nanoseconds",
        "worker_cleanup", "cleanup_ok", "start_monotonic_ns", "finish_monotonic_ns",
        "deadlines", "scratch_file_removed", "run_sha256",
    }, "pressure run receipt")
    require(run["schema"] == RUN_SCHEMA and run["status"] == "complete" and run["failure"] is None, "pressure driver did not report a complete run")
    body = {key: value for key, value in run.items() if key != "run_sha256"}
    require(sha256(run["run_sha256"], "run receipt digest") == digest_object(body), "run receipt self digest is invalid")
    require(run["recipe_sha256"] == expected["recipe"] and run["events_sha256"] == expected["events"], "run receipt is not bound to supplied recipe/events digests")
    require(run["process_binding_sha256"] == expected["process_binding"] and run["launch_record_sha256"] == expected["launch"], "run receipt process binding differs from supplied artifacts")
    require(run["readiness_marker_sha256"] == expected["ready"], "run receipt readiness marker differs from supplied artifact digest")
    require(run["cleanup_ok"] is True and run["scratch_file_removed"] is True, "pressure cleanup or scratch removal is incomplete")
    uint(run["events_bytes"], "event bytes", positive=True, maximum=MAX_EVENTS_BYTES)
    uint(run["event_count"], "event count", positive=True, maximum=MAX_EVENT_COUNT)
    uint(run["sample_count"], "sample count", positive=True, maximum=MAX_SAMPLE_COUNT)
    uint(run["start_monotonic_ns"], "run start", positive=True)
    uint(run["finish_monotonic_ns"], "run finish", positive=True)
    require(run["finish_monotonic_ns"] >= run["start_monotonic_ns"], "run end precedes its start")
    deadlines = exact(run["deadlines"], {"startup_seconds", "total_seconds", "term_seconds", "kill_seconds"}, "run deadlines")
    for key, value in deadlines.items():
        uint(value, f"run deadline {key}", positive=True)
    require(run["finish_monotonic_ns"] - run["start_monotonic_ns"] <= deadlines["total_seconds"] * 1_000_000_000, "pressure run exceeded its frozen total deadline")
    uint(run["application_overlap_nanoseconds"], "application overlap", positive=True)
    return run


def _pid_same(pid: int, start_ticks: int) -> bool:
    offline_context = _PRESSURE_OFFLINE_REPLAY_CONTEXT.get()
    if offline_context is not None:
        return (pid, start_ticks) not in offline_context["origin_absent_identities"]
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        text_value = raw.decode("ascii").strip()
        closing = text_value.rfind(")")
        fields = text_value[closing + 1:].strip().split()
        return len(fields) >= 20 and int(fields[19]) == start_ticks and fields[0] != "Z"
    except (OSError, UnicodeError, ValueError):
        return False


def _worker_exit_status_valid(record: dict[str, Any]) -> bool:
    code = record.get("exit_code")
    if code == 0:
        return True
    if code == -signal.SIGTERM:
        return record.get("term_sent_monotonic_ns") is not None and record.get("kill_sent_monotonic_ns") is None
    if code == -signal.SIGKILL:
        return record.get("kill_sent_monotonic_ns") is not None
    return False


def _require_pid_reaped(pid: int, start_ticks: int, label: str) -> None:
    pid = uint(pid, f"{label} PID", positive=True, maximum=(1 << 31) - 1)
    start_ticks = uint(start_ticks, f"{label} start ticks", positive=True)
    require(not _pid_same(pid, start_ticks), f"{label} PID/start identity is still alive after cleanup")


def _validate_worker_stderr_capture(record: dict[str, Any], label: str) -> bytes:
    encoded = record["stderr_raw_base64"]
    require(type(encoded) is str and len(encoded) <= ((MAX_WORKER_STDERR_RAW_BYTES + 2) // 3) * 4, f"{label} raw stderr capture exceeds its bound")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ReadbackError(f"{label} raw stderr capture is not canonical base64: {error}") from error
    require(len(raw) == uint(record["stderr_raw_bytes"], f"{label} stderr byte count", maximum=MAX_WORKER_STDERR_RAW_BYTES), f"{label} raw stderr byte count differs")
    require(sha256_bytes(raw) == sha256(record["stderr_raw_sha256"], f"{label} stderr SHA-256"), f"{label} raw stderr digest differs")
    require(type(record["stderr_raw_truncated"]) is bool and record["stderr_raw_truncated"] is False, f"{label} raw stderr capture was truncated")
    require(record["stderr_read_error"] is None, f"{label} raw stderr could not be completely read")
    excerpt = raw.decode("utf-8", errors="replace")[:4096].strip()
    require(record["stderr_output"] == excerpt, f"{label} stderr excerpt differs from its raw capture")
    return raw


def _validate_cleanup(run: dict[str, Any], workers: dict[tuple[str, int | None], dict[str, Any]], recipe: dict[str, Any]) -> None:
    records = run["worker_cleanup"]
    require(type(records) is list and len(records) == len(workers), "worker cleanup report is sparse")
    seen: set[tuple[str, int | None]] = set()
    for item in records:
        record = exact(item, {
            "role", "cpu", "pid", "start_ticks", "pgid", "session_id", "exit_code",
            "cleanup_started_monotonic_ns", "term_deadline_monotonic_ns", "kill_deadline_monotonic_ns",
            "term_error", "kill_error", "reap_error", "alive_after_cleanup",
            "term_sent_monotonic_ns", "kill_sent_monotonic_ns", "reaped_monotonic_ns", "stderr_output",
            "stderr_raw_base64", "stderr_raw_sha256", "stderr_raw_bytes", "stderr_raw_truncated", "stderr_read_error",
        }, "worker cleanup record")
        key = (record["role"], record["cpu"])
        require(key in workers and key not in seen, "worker cleanup identity is duplicated or unrecognized")
        seen.add(key)
        expected = workers[key]
        for field in ("pid", "start_ticks", "pgid", "session_id"):
            require(record[field] == expected[field], f"worker cleanup {field} differs from pressure start")
        require(_worker_exit_status_valid(record) and record["alive_after_cleanup"] is False, "pressure worker did not exit cleanly and get reaped")
        raw_stderr = _validate_worker_stderr_capture(record, "pressure worker")
        require(record["term_error"] is None and record["kill_error"] is None and record["reap_error"] is None and raw_stderr == b"", "pressure worker cleanup reported an error")
        cleanup_started = uint(record["cleanup_started_monotonic_ns"], "worker cleanup start", positive=True)
        term_deadline = uint(record["term_deadline_monotonic_ns"], "worker TERM deadline", positive=True)
        kill_deadline = uint(record["kill_deadline_monotonic_ns"], "worker KILL deadline", positive=True)
        require(term_deadline == cleanup_started + recipe["schedule"]["term_deadline_seconds"] * 1_000_000_000, "worker TERM deadline differs from frozen schedule")
        reaped = uint(record["reaped_monotonic_ns"], "worker reap time", positive=True)
        if record["term_sent_monotonic_ns"] is not None:
            sent = uint(record["term_sent_monotonic_ns"], "TERM time", positive=True)
            require(cleanup_started <= sent <= term_deadline, "TERM time is outside its finite deadline")
        if record["kill_sent_monotonic_ns"] is not None:
            sent = uint(record["kill_sent_monotonic_ns"], "KILL time", positive=True)
            require(term_deadline <= sent <= kill_deadline, "KILL escalation is outside its finite deadline")
        require(reaped <= kill_deadline and reaped <= run["finish_monotonic_ns"], "pressure worker was not reaped by its KILL deadline")
        _require_pid_reaped(record["pid"], record["start_ticks"], "pressure worker")
    require(seen == set(workers), "worker cleanup report omitted a session")


def _verify_script_hashes(recipe_info: dict[str, Any]) -> None:
    script_dir = Path(__file__).resolve().parent
    driver = script_dir / "application-pressure-driver.py"
    reader = Path(__file__).resolve()
    for label, path, expected in (
        ("pressure driver", driver, recipe_info["script_hashes"]["driver_sha256"]),
        ("pressure reader", reader, recipe_info["script_hashes"]["reader_sha256"]),
    ):
        _, actual = read_stable(path, label, 4 * 1024 * 1024)
        require(actual == expected, f"{label} bytes differ from the frozen recipe")


def _verify_raw_inputs(recipe_info: dict[str, Any]) -> None:
    for label, spec in recipe_info["files"].items():
        maximum = MAX_BINARY_BYTES if label == "application_binary" else MAX_SOURCE_BYTES if label == "source_manifest" else MAX_POLICY_BYTES
        _, actual = read_stable(Path(spec["path"]), f"raw input {label}", maximum)
        require(actual == spec["raw_sha256"], f"raw input {label} changed since recipe freeze")


def verify_pressure(
    recipe_path: Path, expected_recipe_sha: str, artifacts: Path,
    expected: dict[str, str],
) -> dict[str, Any]:
    recipe_value, _, recipe_raw_sha = read_canonical(recipe_path, "frozen pressure recipe", MAX_RECIPE_BYTES)
    recipe_info = _validate_recipe(recipe_value, expected_recipe_sha)
    recipe = recipe_value
    _verify_script_hashes(recipe_info)
    _verify_raw_inputs(recipe_info)
    calibration_scope_readback = _validate_calibration(recipe, offline_context=_PRESSURE_OFFLINE_REPLAY_CONTEXT.get())
    try:
        dir_info = artifacts.lstat()
        require(stat.S_ISDIR(dir_info.st_mode) and artifacts.resolve(strict=True) == artifacts, "artifact directory is a symlink or alias")
    except OSError as error:
        raise ReadbackError(f"artifact directory is unavailable: {error}") from error
    required = {"events.jsonl", "process-binding.json", "launch-record.json", "run.json", "pressure-ready.json"}
    names = {path.name for path in artifacts.iterdir()}
    require(names == required, "pressure artifact directory has missing or unexpected files")
    launch, _, launch_sha = read_canonical(artifacts / "launch-record.json", "launch record", MAX_LAUNCH_BYTES)
    require(launch_sha == expected["launch"], "launch record raw digest differs from the separately supplied expected hash")
    process = _validate_launch(launch, recipe, expected["launch"])
    process_binding, _, process_binding_sha = read_canonical(artifacts / "process-binding.json", "process binding", MAX_LAUNCH_BYTES)
    require(process_binding_sha == expected["process_binding"], "process binding raw digest differs from the separately supplied expected hash")
    binding = exact(process_binding, {
        "schema", "recipe_sha256", "launch_record_sha256", "identity", "observed_monotonic_ns",
        "pressure_ready_monotonic_ns", "readiness_snapshot", "application_capacity_calibration_sha256",
        "pressure_contention_calibration_sha256", "process_binding_sha256",
    }, "pressure process binding")
    require(binding["schema"] == PROCESS_BINDING_SCHEMA and binding["recipe_sha256"] == expected_recipe_sha, "process binding recipe identity differs")
    binding_body = {key: value for key, value in binding.items() if key != "process_binding_sha256"}
    require(sha256(binding["process_binding_sha256"], "process binding self digest") == digest_object(binding_body), "process binding self digest is invalid")
    require(binding["launch_record_sha256"] == launch_sha, "process binding does not bind the copied launch record")
    require(binding["application_capacity_calibration_sha256"] == recipe_info["files"]["application_capacity_calibration"]["raw_sha256"], "app-byte capacity calibration hash was changed")
    require(binding["pressure_contention_calibration_sha256"] == recipe_info["calibration_sha256"], "pressure-contention calibration hash was changed")
    observed_process = exact(binding["identity"], {
        "pid", "start_ticks", "nonce", "executable_sha256", "tmpdir_path", "cpu_affinity", "network_namespace_inode",
    }, "bound process identity")
    require(observed_process["pid"] == process["pid"] and observed_process["start_ticks"] == process["start_ticks"] and observed_process["nonce"] == recipe_info["identity"]["nonce"], "bound PID/start/nonce differ from launch record")
    require(observed_process["executable_sha256"] == recipe_info["files"]["application_binary"]["raw_sha256"] and observed_process["tmpdir_path"] == recipe["process"]["application_tmpdir_path"] and observed_process["cpu_affinity"] == recipe_info["schedule"]["application_cpu_affinity"] and observed_process["network_namespace_inode"] == recipe_info["network"]["network_namespace_inode"], "bound process executable/TMPDIR/affinity/network identity differs")
    uint(binding["observed_monotonic_ns"], "application observation time", positive=True)
    ready_at = uint(binding["pressure_ready_monotonic_ns"], "pressure ready time", positive=True)
    require(ready_at <= binding["observed_monotonic_ns"], "application was observed before measured readiness")
    ready, _, ready_sha = read_canonical(artifacts / "pressure-ready.json", "pressure ready marker", 64 * 1024)
    require(ready_sha == expected["ready"], "pressure ready marker raw digest differs from separately supplied expected hash")
    ready_keys = {
        "schema", "recipe_sha256", "condition_sha256", "nonce", "pressure_ready_monotonic_ns", "readiness", "ready_sha256",
    }
    strong_ready = "ownership_protocol" in ready
    if strong_ready:
        ready_keys |= {"ownership_protocol", "worker_ownership_sha256", "worker_authorization_sha256"}
    ready = exact(ready, ready_keys, "pressure ready marker")
    ready_body = {key: value for key, value in ready.items() if key != "ready_sha256"}
    require(ready["schema"] == "allocatbelt.application-pressure-ready.v1" and ready["recipe_sha256"] == expected_recipe_sha and ready["condition_sha256"] == recipe_info["condition_sha256"] and ready["nonce"] == recipe_info["identity"]["nonce"], "pressure ready marker identity differs")
    require(sha256(ready["ready_sha256"], "pressure ready digest") == digest_object(ready_body), "pressure ready marker self digest is invalid")
    if strong_ready:
        require(ready["ownership_protocol"] == OWNERSHIP_PROTOCOL, "pressure readiness marker does not identify the required durable worker protocol")
        sha256(ready["worker_ownership_sha256"], "ready worker ownership journal digest")
        sha256(ready["worker_authorization_sha256"], "ready worker authorization journal digest")
    require(ready["pressure_ready_monotonic_ns"] == ready_at and ready["readiness"] == binding["readiness_snapshot"], "pressure ready marker differs from the process binding")
    run_value, _, run_sha = read_canonical(artifacts / "run.json", "pressure run receipt", MAX_MANIFEST_BYTES)
    require(run_sha == expected["run"], "run receipt raw digest differs from separately supplied expected hash")
    run = _validate_run(run_value, {**expected, "recipe": expected_recipe_sha})
    require(run["condition_sha256"] == recipe_info["condition_sha256"], "run receipt condition differs from frozen recipe")
    event_state: dict[str, Any] = {"event_count": 0}
    events = _iter_events(
        artifacts / "events.jsonl", expected["events"], run["events_bytes"],
        recipe_info["artifact_budget"]["maximum_event_bytes"], event_state,
    )
    first_event = next(events, None)
    require(type(first_event) is dict, "pressure event stream is empty")
    if first_event.get("kind") == "worker_ownership":
        owner_rows, ownership_sha, ownership_time = _validate_worker_ownership(first_event, recipe)
        authorization_event = next(events, None)
        require(type(authorization_event) is dict, "pressure event stream omits the worker authorization journal")
        authorization_sha, authorization_time = _validate_workers_authorized(authorization_event, recipe, owner_rows, ownership_sha)
        start_event = next(events, None)
        require(type(start_event) is dict and start_event.get("kind") == "pressure_start", "pressure event stream omits its post-authorization start record")
        workers = _validate_worker_start(start_event, recipe, ownership_sha, authorization_sha)
        start_time = uint(start_event["monotonic_ns"], "pressure start time", positive=True)
        require(ownership_time <= authorization_time <= start_time, "durable pressure ownership and authorization records are out of order")
        require(
            all(
                (role, cpu) in owner_rows
                and all(start_workers[name] == owner_rows[(role, cpu)][name] for name in ("pid", "start_ticks", "pgid", "session_id"))
                for (role, cpu), start_workers in workers.items()
            ),
            "pressure start workers differ from the durable pre-ACK ownership set",
        )
        require(strong_ready and ready["worker_ownership_sha256"] == ownership_sha and ready["worker_authorization_sha256"] == authorization_sha, "pressure readiness marker does not bind the durable worker ownership/ACK journals")
    else:
        require(first_event.get("kind") == "pressure_start", "legacy pressure event stream does not start with pressure worker identities")
        require(not strong_ready, "strong pressure readiness marker is paired with a legacy event stream")
        start_event = first_event
        workers = _validate_worker_start(start_event, recipe)
    require(all(item["pid"] != process["pid"] for item in workers.values()), "application PID is also listed as a pressure worker")
    _validate_cleanup(run, workers, recipe)
    minimum_ready_samples = None if calibration_scope_readback is None else calibration_scope_readback["minimum_ready_samples"]
    timeline = _validate_event_timeline(
        events, start_event, recipe, process, binding, run, workers,
        minimum_ready_samples,
    )
    if calibration_scope_readback is not None:
        calibration_scope_readback = {
            key: value for key, value in calibration_scope_readback.items() if key != "minimum_ready_samples"
        }
    require(event_state.get("event_count") == run["event_count"] and event_state.get("events_sha256") == run["events_sha256"] == expected["events"] and event_state.get("events_bytes") == run["events_bytes"], "run receipt event count/digest differs from streamed raw event file")
    scratch_path = Path(recipe["storage"]["pressure_scratch_path"]) / f".allocatbelt-pressure-{recipe_info['identity']['nonce']}.bin"
    require(not scratch_path.exists() and not scratch_path.is_symlink(), "bounded block-I/O scratch file remains after pressure cleanup")
    run_ns = run["finish_monotonic_ns"] - run["start_monotonic_ns"]
    require(run_ns <= recipe_info["schedule"]["total_deadline_seconds"] * 1_000_000_000, "pressure run exceeded its total deadline")
    result_body = {
        "schema": READBACK_SCHEMA_V2 if calibration_scope_readback is not None else READBACK_SCHEMA,
        "status": "valid",
        "recipe_sha256": expected_recipe_sha,
        "recipe_raw_sha256": recipe_raw_sha,
        "validator_sha256": recipe_info["script_hashes"]["reader_sha256"],
        "condition_sha256": recipe_info["condition_sha256"],
        "identity": {
            key: recipe_info["identity"][key]
            for key in ("host_id", "run_id", "pair_id", "condition_id", "member", "nonce", "allocator", "executor", "phase")
        },
        "run_sha256": expected["run"],
        "events_sha256": expected["events"],
        "launch_record_sha256": expected["launch"],
        "process_binding_sha256": expected["process_binding"],
        "readiness_marker_sha256": expected["ready"],
        "sample_count": run["sample_count"],
        "application_overlap_nanoseconds": run["application_overlap_nanoseconds"],
        "application_process": {
            "pid": process["pid"],
            "start_ticks": process["start_ticks"],
            "nonce": observed_process["nonce"],
            "executable_sha256": observed_process["executable_sha256"],
        },
        "application_window": timeline["application_window"],
        "continuous_ready_window": timeline["continuous_ready_window"],
        "readiness_windows_passed": True,
        "cleanup_rechecked": True,
        "physical_nic_claimed": False,
    }
    if calibration_scope_readback is not None:
        result_body["calibration_scope_v2"] = calibration_scope_readback
    return {**result_body, "readback_sha256": digest_object(result_body)}


def _advance_app_sample_continuity(
    *, app_started: bool, live_seen: bool, terminal_inactive_seen: bool,
    app_active: bool, readiness_ok: bool, complete_overlap_window: bool,
) -> tuple[bool, bool]:
    if not app_started:
        require(not app_active, "application was live before its authenticated start event")
        return live_seen, terminal_inactive_seen
    require(not terminal_inactive_seen, "application pressure trace has an inactive hole or process revival")
    if app_active:
        if complete_overlap_window:
            require(readiness_ok, "readiness failed inside a complete application-overlap window")
        return True, False
    return live_seen, True


def _validate_event_timeline(
    events: Iterator[dict[str, Any]], start_event: dict[str, Any], recipe: dict[str, Any], process: dict[str, Any],
    binding: dict[str, Any], run: dict[str, Any], workers: dict[tuple[str, int | None], dict[str, Any]],
    minimum_ready_samples: int | None = None,
) -> dict[str, dict[str, int]]:
    start_ns = uint(start_event["monotonic_ns"], "pressure start time", positive=True)
    interval_ns = recipe["schedule"]["sample_interval_ms"] * 1_000_000
    previous_end: int | None = None
    sample_count = 0
    last_sample: dict[str, Any] | None = None
    first_live_sequence: int | None = None
    last_live_sample: dict[str, Any] | None = None
    live_seen = False
    terminal_inactive_seen = False
    startup_ready: list[bool] = []
    active_readiness_windows = 0
    active_readiness_ok = True
    app_start_ns: int | None = None
    app_exit_ns: int | None = None
    cleanup_seen = False
    cleanup_count = 0
    app_start_count = 0
    app_exit_count = 0
    continuous_ready_start_ns: int | None = None
    continuous_ready_end_ns: int | None = None
    continuous_ready_broken = False
    for event in events:
        require(event.get("schema") == EVENT_SCHEMA, "pressure event has unknown schema")
        kind = event.get("kind")
        if kind == "sample":
            require(app_exit_ns is None and not cleanup_seen, "pressure samples continue after application exit or cleanup")
            sequence = sample_count
            result = _validate_sample(event, recipe, sequence)
            start = result["start"]
            end = result["end"]
            cadence_tolerance_ns = max(1_000_000, interval_ns // 100)
            require(interval_ns - cadence_tolerance_ns <= end - start <= interval_ns + max(500_000_000, interval_ns), "sample interval is shorter/sparser than frozen cadence")
            if previous_end is not None:
                require(start == previous_end, "pressure sample intervals have a gap or overlap")
            previous_end = end
            live_seen, terminal_inactive_seen = _advance_app_sample_continuity(
                app_started=app_start_ns is not None,
                live_seen=live_seen,
                terminal_inactive_seen=terminal_inactive_seen,
                app_active=result["app_active"],
                readiness_ok=result["readiness"]["all_ready"],
                complete_overlap_window=app_start_ns is not None and start >= app_start_ns,
            )
            if app_start_ns is None:
                startup_ready.append(result["readiness"]["all_ready"])
                del startup_ready[:-recipe["schedule"]["startup_ready_windows"]]
            else:
                ready_barrier_ns = binding["pressure_ready_monotonic_ns"]
                require(start >= ready_barrier_ns, "pressure sample precedes the authenticated readiness barrier")
                sample_ready = result["readiness"]["all_ready"]
                if sample_ready:
                    if continuous_ready_start_ns is None:
                        continuous_ready_start_ns = start
                        require(
                            continuous_ready_start_ns >= ready_barrier_ns,
                            "continuous ready pressure interval precedes its readiness barrier",
                        )
                    if not continuous_ready_broken:
                        continuous_ready_end_ns = end
                elif continuous_ready_start_ns is not None:
                    continuous_ready_broken = True
            if result["app_active"]:
                require(app_start_ns is not None, "application was live before its authenticated start event")
                active_readiness_windows += 1
                active_readiness_ok = active_readiness_ok and result["readiness"]["all_ready"]
                require(result["readiness"]["all_ready"], "pressure window overlapping the live application is unready")
                if first_live_sequence is None:
                    first_live_sequence = sequence
                last_live_sample = {
                    "sequence": sequence,
                    "start": start,
                    "end": end,
                    "readiness": result["readiness"],
                }
            last_sample = {
                "sequence": sequence,
                "start": start,
                "end": end,
                "app_active": result["app_active"],
                "readiness": result["readiness"],
            }
            sample_count += 1
        elif kind == "application_start":
            app_start_count += 1
            require(app_start_count == 1 and app_exit_count == 0 and cleanup_count == 0, "pressure event stream repeats or reorders application start")
            require(last_sample is not None, "application start appears before a complete readiness sample")
            start_exact = exact(event, {"schema", "kind", "sequence", "monotonic_ns", "pid", "start_ticks", "launch_record_sha256"}, "application start event")
            require(start_exact["sequence"] == last_sample["sequence"] and start_exact["pid"] == process["pid"] and start_exact["start_ticks"] == process["start_ticks"] and start_exact["launch_record_sha256"] == binding["launch_record_sha256"], "application start event differs from launch binding")
            app_start_ns = uint(start_exact["monotonic_ns"], "application start observation", positive=True)
            require(app_start_ns == binding["observed_monotonic_ns"] and last_sample["end"] <= app_start_ns, "application start does not follow its measured readiness window")
            require(app_start_ns >= start_ns, "application start precedes pressure worker startup")
            ready_count = recipe["schedule"]["startup_ready_windows"]
            require(len(startup_ready) >= ready_count and all(startup_ready[-ready_count:]), "measured startup readiness windows are missing or failed")
            require(last_sample["end"] == binding["pressure_ready_monotonic_ns"] and last_sample["readiness"] == binding["readiness_snapshot"], "ready marker does not match the last complete startup sample")
        elif kind == "application_exit":
            app_exit_count += 1
            require(app_exit_count == 1 and app_start_ns is not None and cleanup_count == 0, "pressure event stream repeats or reorders application exit")
            exit_exact = exact(event, {"schema", "kind", "sequence", "monotonic_ns", "pid", "start_ticks", "exit_observed"}, "application exit event")
            require(exit_exact["pid"] == process["pid"] and exit_exact["start_ticks"] == process["start_ticks"] and exit_exact["exit_observed"] is True, "application exit event does not match launch PID/start")
            require(last_live_sample is not None and exit_exact["sequence"] == last_live_sample["sequence"], "application exit does not name its last independently live sample")
            app_exit_ns = uint(exit_exact["monotonic_ns"], "application exit observation", positive=True)
            require(app_exit_ns == last_live_sample["end"] and app_exit_ns > app_start_ns, "application exit is not bounded by its final live sample")
            if terminal_inactive_seen:
                require(last_sample is not None and not last_sample["app_active"] and last_sample["sequence"] + 1 == sample_count, "inactive observation is not the single trailing death window")
            else:
                require(last_sample is not None and last_sample["sequence"] == last_live_sample["sequence"], "application live window was followed by an unrecorded sample")
        elif kind == "pressure_cleanup":
            cleanup_count += 1
            require(cleanup_count == 1 and app_exit_ns is not None, "pressure cleanup is duplicated or precedes application exit")
            cleanup = exact(event, {"schema", "kind", "monotonic_ns", "workers", "scratch_file_removed", "cleanup_ok"}, "pressure cleanup event")
            cleanup_ns = uint(cleanup["monotonic_ns"], "pressure cleanup time", positive=True)
            require(cleanup["cleanup_ok"] is True and cleanup["scratch_file_removed"] is True and cleanup_ns <= run["finish_monotonic_ns"], "pressure cleanup event is incomplete")
            require(cleanup["workers"] == run["worker_cleanup"] and len(workers) == len(run["worker_cleanup"]), "cleanup event differs from worker start identities or run receipt")
            require(app_exit_ns <= cleanup_ns, "pressure workers were cleaned before the application exited")
            cleanup_seen = True
        elif kind == "pressure_failure":
            raise ReadbackError("pressure event stream contains a failure record")
        else:
            raise ReadbackError(f"unknown pressure event kind: {kind}")
    require(sample_count == run["sample_count"] and last_sample is not None, "sample event count differs from run receipt")
    require(app_start_count == 1 and app_exit_count == 1 and cleanup_count == 1, "pressure event stream omits its application interval or cleanup")
    require(first_live_sequence is not None and last_live_sample is not None, "pressure trace contains no independently live application window")
    require(
        minimum_ready_samples is None or active_readiness_windows >= minimum_ready_samples,
        "pressure trace does not meet the Source5 minimum ready-sample count",
    )
    overlap = app_exit_ns - app_start_ns
    require(overlap >= recipe["schedule"]["minimum_overlap_seconds"] * 1_000_000_000 and overlap == run["application_overlap_nanoseconds"], "application overlap differs from the frozen minimum or receipt")
    require(active_readiness_windows > 0 and active_readiness_ok, "readiness failed or application was not live through a complete pressure window")
    _require_pid_reaped(process["pid"], process["start_ticks"], "application")
    require(
        continuous_ready_start_ns is not None
        and continuous_ready_end_ns is not None
        and app_start_ns is not None
        and app_exit_ns is not None
        and continuous_ready_end_ns > continuous_ready_start_ns,
        "pressure trace has no complete continuous-ready application window",
    )
    return {
        "application_window": {
            "observed_start_monotonic_ns": app_start_ns,
            "observed_exit_monotonic_ns": app_exit_ns,
        },
        "continuous_ready_window": {
            "start_monotonic_ns": continuous_ready_start_ns,
            "end_monotonic_ns": continuous_ready_end_ns,
        },
    }


def _pressure_absolute_json_paths(value: object) -> set[str]:
    path_keys = {
        "path", "source_root", "output_root", "binary_path", "executable_path",
        "cwd", "tmpdir", "trace_directory", "directory", "pressure_scratch_path",
        "application_tmpdir_path", "mount_point",
    }
    result: set[str] = set()

    def visit(item: object, argv_context: bool = False) -> None:
        if type(item) is dict:
            for key, child in item.items():
                if key in path_keys and type(child) is str and child.startswith("/"):
                    result.add(child)
                if key in {"argv", "requested_argv", "executed_argv", "probe_argv"}:
                    visit(child, True)
                elif key == "environment" and type(child) is dict:
                    temp = child.get("TMPDIR")
                    if type(temp) is str and temp.startswith("/"):
                        result.add(temp)
                    visit(child)
                else:
                    visit(child, argv_context)
        elif type(item) is list:
            for child in item:
                visit(child, argv_context)
        elif argv_context and type(item) is str and item.startswith("/"):
            result.add(item)

    visit(value)
    return result



def _preflight_pressure_json_path_closure(
    documents: list[dict[str, Any]], mapped_paths: frozenset[str],
    mapped_directories: set[str],
) -> None:
    """Walk every mapped JSON dependency before any validator module is executed."""
    pending: list[dict[str, Any]] = list(documents)
    queued: set[str] = set()
    json_suffixes = (".json",)
    while pending:
        document = pending.pop()
        referenced = _pressure_absolute_json_paths(document)
        for raw_path in referenced:
            require(raw_path in mapped_paths,
                    f"offline pressure evidence map omits exact nested dependency: {raw_path}")
        for raw_path in referenced:
            if not raw_path.endswith(json_suffixes) or raw_path in queued:
                continue
            queued.add(raw_path)
            require(raw_path in mapped_paths and raw_path not in mapped_directories,
                    f"offline pressure JSON dependency is not an explicitly mapped file: {raw_path}")
            child, _raw, _raw_sha = read_canonical(
                Path(raw_path), "offline pressure nested JSON dependency", MAX_OFFLINE_JSON_BYTES,
            )
            pending.append(child)
            require(len(queued) <= 4096,
                    "offline pressure nested JSON dependency set exceeds its finite limit")


def _validate_pressure_pair_host_receipt(
    pin_value: object,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    pin = exact(pin_value, {"path", "raw_sha256", "receipt_sha256"},
                "pressure-pair host-verification receipt pin")
    path = absolute_path(pin["path"], "pressure-pair host-verification receipt path")
    raw_sha = sha256(pin["raw_sha256"], "pressure-pair host receipt raw SHA-256")
    receipt_sha = sha256(pin["receipt_sha256"], "pressure-pair host receipt semantic SHA-256")
    receipt, raw, actual_raw = read_canonical(path, "pressure-pair host-verification receipt", 16 * 1024 * 1024)
    info = path.lstat()
    require(actual_raw == raw_sha and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o600,
            "pressure-pair host receipt is not the exact owned mode-0600 pinned file")
    exact(receipt, {
        "schema", "campaign_id", "host_id", "job", "recipe", "readback",
        "source_manifest", "spec", "plan", "execution_manifest", "authorization_id",
        "journal_head", "registration_head", "observed_host", "origin_facts",
        "dependency_pins", "member_facts", "strict_result_sha256",
        "qualification_eligible", "execution_ready", "receipt_sha256",
    }, "pressure-pair host-verification receipt")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    require(receipt["schema"] == PRESSURE_PAIR_HOST_VERIFICATION_SCHEMA and
            raw == canonical_bytes(receipt),
            "pressure-pair host receipt schema or canonical bytes differ")
    require(receipt_sha == receipt["receipt_sha256"] == digest_object(body),
            "pressure-pair host receipt raw/semantic digest roles differ")
    require(receipt["qualification_eligible"] is False and receipt["execution_ready"] is False,
            "pressure-pair host receipt false eligibility fields differ")
    token(receipt["campaign_id"], "pressure-pair receipt campaign ID")
    token(receipt["host_id"], "pressure-pair receipt host ID")
    job = exact(receipt["job"], {"run_id", "ordinal", "job_index", "semantic_sha256"},
                "pressure-pair host receipt original job")
    token(job["run_id"], "pressure-pair receipt original run ID")
    uint(job["ordinal"], "pressure-pair receipt ordinal", positive=True)
    uint(job["job_index"], "pressure-pair receipt original job index")
    sha256(job["semantic_sha256"], "pressure-pair receipt job semantic digest")
    for label, expected_keys in (
        ("recipe", {"path", "raw_sha256", "semantic_sha256"}),
        ("readback", {"path", "raw_sha256", "semantic_sha256"}),
        ("spec", {"path", "raw_sha256", "semantic_sha256"}),
        ("plan", {"path", "raw_sha256", "semantic_sha256"}),
    ):
        item = exact(receipt[label], expected_keys, f"pressure-pair receipt {label} pin")
        absolute_path(item["path"], f"pressure-pair receipt {label} path")
        sha256(item["raw_sha256"], f"pressure-pair receipt {label} raw SHA-256")
        sha256(item["semantic_sha256"], f"pressure-pair receipt {label} semantic SHA-256")
    source = exact(receipt["source_manifest"], {
        "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
    }, "pressure-pair receipt SourceV5 manifest")
    absolute_path(source["path"], "pressure-pair receipt SourceV5 path")
    for name in ("raw_sha256", "semantic_sha256", "source_tree_sha256"):
        sha256(source[name], f"pressure-pair receipt SourceV5 {name}")
    execution = exact(receipt["execution_manifest"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "pressure-pair receipt execution manifest")
    absolute_path(execution["path"], "pressure-pair receipt execution manifest path")
    for name in ("raw_sha256", "semantic_sha256"):
        sha256(execution[name], f"pressure-pair receipt execution manifest {name}")
    token(receipt["authorization_id"], "pressure-pair receipt authorization ID")
    sha256(receipt["journal_head"], "pressure-pair receipt journal head")
    sha256(receipt["registration_head"], "pressure-pair receipt registration head")
    observed = exact(receipt["observed_host"], {"path", "raw_sha256"},
                     "pressure-pair receipt observed-host pin")
    absolute_path(observed["path"], "pressure-pair receipt observed-host path")
    sha256(observed["raw_sha256"], "pressure-pair receipt observed-host raw SHA-256")
    origin = exact(receipt["origin_facts"], {
        "schema", "host_id", "observed_host_raw_sha256", "before", "after",
        "storage_sha256", "origin_facts_sha256",
    }, "pressure-pair receipt origin facts")
    origin_body = {key: value for key, value in origin.items() if key != "origin_facts_sha256"}
    require(origin["schema"] == PRESSURE_PAIR_ORIGIN_FACTS_SCHEMA and
            origin["host_id"] == receipt["host_id"] and
            origin["observed_host_raw_sha256"] == observed["raw_sha256"] and
            origin["origin_facts_sha256"] == digest_object(origin_body),
            "pressure-pair origin facts schema, host, or self digest differs")
    sha256(origin["storage_sha256"], "pressure-pair origin storage digest")
    host_fact_keys = {"boot_id_sha256", "kernel_release", "cpu_affinity", "network_namespace_inode"}
    for phase in ("before", "after"):
        facts = exact(origin[phase], host_fact_keys, f"pressure-pair {phase} host facts")
        sha256(facts["boot_id_sha256"], f"pressure-pair {phase} boot ID digest")
        text(facts["kernel_release"], f"pressure-pair {phase} kernel release", 256)
        affinity = facts["cpu_affinity"]
        require(type(affinity) is list and affinity and
                affinity == sorted(set(uint(cpu, f"pressure-pair {phase} CPU", maximum=65535) for cpu in affinity)),
                f"pressure-pair {phase} CPU affinity is malformed")
        uint(facts["network_namespace_inode"], f"pressure-pair {phase} network namespace", positive=True)
    require(origin["before"] == origin["after"],
            "pressure-pair host identity changed during strict verification")
    deps = receipt["dependency_pins"]
    require(type(deps) is dict and set(deps) == {
        "campaign_controller", "campaign_chronology", "feedback_composition",
        "feedback_validator", "pressure_validator", "soak_supervisor",
        "capacity_producer", "pressure_pair", "pressure_driver",
        "source_inventory", "fixed_pair", "source5_helper_input", "source5_helper_module",
    }, "pressure-pair host receipt dependency pin set differs")
    for name, value in deps.items():
        dep = exact(value, {"path", "raw_sha256"}, f"pressure-pair dependency {name}")
        text(dep["path"], f"pressure-pair dependency {name} path", 4096)
        sha256(dep["raw_sha256"], f"pressure-pair dependency {name} raw SHA-256")
    sha256(receipt["strict_result_sha256"], "pressure-pair strict result digest")
    require(type(receipt["member_facts"]) is list and len(receipt["member_facts"]) == 2,
            "pressure-pair host receipt must retain exactly two original members")
    seen_identities: set[tuple[int, int]] = set()
    for index, value in enumerate(receipt["member_facts"]):
        row = exact(value, {
            "ordinal", "descriptor", "identity", "pressure_recipe", "pressure_artifacts",
            "application_identity", "worker_identities", "pid_absence", "probe_capture",
            "application_launch_attestation", "application_cleanup", "supervision_receipt",
            "storage_proof",
        }, f"pressure-pair host member[{index}]")
        require(row["ordinal"] == index, "pressure-pair host receipt member order differs from the original pair")
        exact(row["descriptor"], {"pair", "executor", "allocator"}, "pressure-pair host member descriptor")
        identity = row["identity"]
        require(type(identity) is dict and identity.get("host_id") == receipt["host_id"],
                "pressure-pair host member identity differs from its host")
        pressure_recipe = exact(row["pressure_recipe"], {
            "path", "raw_sha256", "semantic_sha256", "condition_sha256",
        }, "pressure-pair host member pressure recipe")
        absolute_path(pressure_recipe["path"], "pressure-pair host member recipe path")
        for key in ("raw_sha256", "semantic_sha256", "condition_sha256"):
            sha256(pressure_recipe[key], f"pressure-pair host member recipe {key}")
        pressure = exact(row["pressure_artifacts"], {
            "directory", "pins", "proof", "ready_sha256", "driver", "worker_sessions", "driver_logs",
        }, "pressure-pair host member pressure artifacts")
        absolute_path(pressure["directory"], "pressure-pair host member pressure directory")
        exact(pressure["pins"], {"events", "launch", "process_binding", "ready", "run"},
              "pressure-pair host member pressure artifact pins")
        for key, value in pressure["pins"].items():
            sha256(value, f"pressure-pair host member pressure {key} raw SHA-256")
        proof = exact(pressure["proof"], {"path", "raw_sha256"}, "pressure-pair host member proof pin")
        absolute_path(proof["path"], "pressure-pair host member proof path")
        sha256(proof["raw_sha256"], "pressure-pair host member proof raw SHA-256")
        app_identity = exact(row["application_identity"], {"pid", "start_ticks"},
                             "pressure-pair member APP identity")
        app_key = (uint(app_identity["pid"], "pressure-pair member APP PID", positive=True,
                         maximum=(1 << 31) - 1),
                   uint(app_identity["start_ticks"], "pressure-pair member APP start ticks", positive=True))
        require(app_key not in seen_identities, "pressure-pair host receipt repeats a process identity")
        seen_identities.add(app_key)
        workers = row["worker_identities"]
        require(type(workers) is list and 1 <= len(workers) <= MAX_SAMPLE_COUNT,
                "pressure-pair host member worker identity list is malformed")
        for worker_value in workers:
            worker = exact(worker_value, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id"},
                           "pressure-pair host member worker identity")
            key = (uint(worker["pid"], "pressure-pair worker PID", positive=True,
                        maximum=(1 << 31) - 1),
                   uint(worker["start_ticks"], "pressure-pair worker start ticks", positive=True))
            uint(worker["pgid"], "pressure-pair worker process group", positive=True,
                 maximum=(1 << 31) - 1)
            uint(worker["session_id"], "pressure-pair worker session", positive=True,
                 maximum=(1 << 31) - 1)
            require(key not in seen_identities, "pressure-pair host receipt repeats a worker identity")
            seen_identities.add(key)
        absence = row["pid_absence"]
        require(type(absence) is list and len(absence) == 1 + len(workers),
                "pressure-pair member origin-host absence receipt is sparse")
        absent_seen: set[tuple[int, int]] = set()
        for absence_value in absence:
            item = exact(absence_value, {"pid", "start_ticks", "absent", "observed_monotonic_ns"},
                         "pressure-pair origin PID absence observation")
            key = (uint(item["pid"], "pressure-pair absent PID", positive=True,
                        maximum=(1 << 31) - 1),
                   uint(item["start_ticks"], "pressure-pair absent start ticks", positive=True))
            require(item["absent"] is True and key not in absent_seen,
                    "pressure-pair host receipt lacks a unique positive PID absence observation")
            uint(item["observed_monotonic_ns"], "pressure-pair PID absence observation time", positive=True)
            absent_seen.add(key)
        require(absent_seen == {app_key} | {
            (item["pid"], item["start_ticks"]) for item in workers
        }, "pressure-pair absence identities differ from its original APP/worker set")
        capture = exact(row["probe_capture"], {
            "construction_probe", "capture_receipt", "capacity_bundle",
        }, "pressure-pair member ProbeV2 capture binding")
        probe_pin = exact(capture["construction_probe"], {
            "path", "raw_sha256", "allocator", "binary_sha256",
        }, "pressure-pair member original construction probe")
        absolute_path(probe_pin["path"], "pressure-pair member construction probe path")
        sha256(probe_pin["raw_sha256"], "pressure-pair member construction probe raw SHA-256")
        sha256(probe_pin["binary_sha256"], "pressure-pair member construction probe binary SHA-256")
        text(probe_pin["allocator"], "pressure-pair member construction probe allocator", 64)
        capture_pin = exact(capture["capture_receipt"], {
            "path", "raw_sha256", "receipt_sha256",
        }, "pressure-pair member ProbeV2 capture receipt pin")
        absolute_path(capture_pin["path"], "pressure-pair member ProbeV2 capture receipt path")
        sha256(capture_pin["raw_sha256"], "pressure-pair member ProbeV2 receipt raw SHA-256")
        sha256(capture_pin["receipt_sha256"], "pressure-pair member ProbeV2 receipt semantic SHA-256")
        capacity_bundle = exact(capture["capacity_bundle"], {"request", "artifact", "receipt"},
                                "pressure-pair member ProbeV2 capacity bundle")
        for name, capacity_pin_value in capacity_bundle.items():
            capacity_pin = exact(capacity_pin_value, {"path", "raw_sha256"},
                                 f"pressure-pair member ProbeV2 capacity {name}")
            absolute_path(capacity_pin["path"], f"pressure-pair member ProbeV2 capacity {name} path")
            sha256(capacity_pin["raw_sha256"], f"pressure-pair member ProbeV2 capacity {name} raw SHA-256")
        for name in ("application_launch_attestation", "application_cleanup", "supervision_receipt"):
            artifact = exact(row[name], {"path", "raw_sha256"}, f"pressure-pair member {name} pin")
            absolute_path(artifact["path"], f"pressure-pair member {name} path")
            sha256(artifact["raw_sha256"], f"pressure-pair member {name} raw SHA-256")
        storage = exact(row["storage_proof"], {
            "application_tmpdir_path", "pressure_scratch_path", "application_mount_id",
            "storage_sha256",
        }, "pressure-pair member storage proof")
        absolute_path(storage["application_tmpdir_path"], "pressure-pair member TMPDIR")
        absolute_path(storage["pressure_scratch_path"], "pressure-pair member scratch path")
        uint(storage["application_mount_id"], "pressure-pair member application mount", positive=True)
        sha256(storage["storage_sha256"], "pressure-pair member storage digest")
    require(len(seen_identities) == sum(1 + len(row["worker_identities"]) for row in receipt["member_facts"]),
            "pressure-pair host receipt repeats a process identity across members")
    require(origin["storage_sha256"] == digest_object([
        row["storage_proof"]["storage_sha256"] for row in receipt["member_facts"]
    ]), "pressure-pair origin storage digest differs from the two member proofs")
    return receipt, actual_raw, pin


def verify_pressure_offline(
    pressure_recipe_pin: object,
    pressure_artifacts: object,
    host_verification_pin: object,
    *, evidence_path_map: object,
    source_root: object,
) -> dict[str, Any]:
    """Replay one pressure run off-host using its exact member of a strict pair receipt.

    The reader recomputes recipe, calibration, launch, event, sample, readiness,
    and cleanup structure from original bytes. PID absence is accepted only for
    exact identities in the strict origin-host receipt; this API never probes
    the coordinator's process table or launches the peer APP/worker.
    """
    recipe_pin = exact(pressure_recipe_pin, {
        "path", "raw_sha256", "semantic_sha256", "condition_sha256",
    }, "offline pressure recipe pin")
    recipe_path = absolute_path(recipe_pin["path"], "offline pressure recipe path")
    for name in ("raw_sha256", "semantic_sha256", "condition_sha256"):
        sha256(recipe_pin[name], f"offline pressure recipe {name}")
    artifact_value = exact(pressure_artifacts, {
        "directory", "pins", "proof", "ready_sha256", "driver", "worker_sessions", "driver_logs",
    }, "offline pressure artifacts")
    artifact_root = absolute_path(artifact_value["directory"], "offline pressure artifact directory")
    pins = exact(artifact_value["pins"], {"events", "launch", "process_binding", "ready", "run"},
                 "offline pressure raw artifact pins")
    pins = {name: sha256(value, f"offline pressure {name} raw SHA-256") for name, value in pins.items()}
    require(artifact_value["ready_sha256"] == pins["ready"],
            "offline pressure ready digest differs from the frozen ready artifact pin")
    driver_logs = exact(artifact_value["driver_logs"], {"stdout", "stderr"},
                        "offline pressure driver log pins")
    for label, log_value in driver_logs.items():
        log_pin = exact(log_value, {"path", "raw_sha256"},
                        f"offline pressure driver {label} log pin")
        absolute_path(log_pin["path"], f"offline pressure driver {label} log path")
        sha256(log_pin["raw_sha256"], f"offline pressure driver {label} log raw SHA-256")
    proof_pin = exact(artifact_value["proof"], {"path", "raw_sha256"}, "offline pressure proof pin")
    proof_path = absolute_path(proof_pin["path"], "offline pressure proof path")
    sha256(proof_pin["raw_sha256"], "offline pressure proof raw SHA-256")
    source_root_path = absolute_path(source_root, "offline pressure SourceV5 root")
    mapping, directories = _normalize_evidence_path_map(evidence_path_map, source_root_path)
    mapped_paths = frozenset(mapping)
    mapped_files = frozenset(path for path in mapping if path not in directories)
    raw_host_pin = exact(host_verification_pin, {
        "path", "raw_sha256", "receipt_sha256",
    }, "offline pressure-pair host receipt pin")
    absolute_path(raw_host_pin["path"], "offline pressure-pair host receipt path")
    sha256(raw_host_pin["raw_sha256"], "offline pressure-pair host receipt raw SHA-256")
    sha256(raw_host_pin["receipt_sha256"], "offline pressure-pair host receipt semantic SHA-256")
    require(raw_host_pin["path"] in mapped_files,
            "offline pressure evidence map omits the strict origin-host receipt")
    require(str(recipe_path) in mapped_files and str(artifact_root) in directories and
            str(proof_path) in mapped_files,
            "offline pressure evidence map omits a top-level pinned input")
    for log_value in driver_logs.values():
        log_pin = exact(log_value, {"path", "raw_sha256"}, "offline pressure driver log pin")
        require(log_pin["path"] in mapped_files,
                "offline pressure evidence map omits an exact driver log")
    for path in (artifact_root / "events.jsonl", artifact_root / "process-binding.json",
                 artifact_root / "launch-record.json", artifact_root / "run.json",
                 artifact_root / "pressure-ready.json"):
        require(str(path) in mapped_files,
                f"offline pressure evidence map omits exact artifact member: {path}")
    for log_value in driver_logs.values():
        log_pin = exact(log_value, {"path", "raw_sha256"}, "offline pressure driver log pin")
        require(log_pin["path"] in mapped_files,
                "offline pressure evidence map omits an exact driver log")
    raw_recipe, recipe_raw_sha = read_stable(recipe_path, "offline frozen pressure recipe", MAX_RECIPE_BYTES)
    require(recipe_raw_sha == recipe_pin["raw_sha256"],
            "offline pressure recipe raw SHA-256 differs from its strict member pin")
    recipe_value = parse_object(raw_recipe, "offline frozen pressure recipe", MAX_RECIPE_BYTES)
    require(raw_recipe == canonical_bytes(recipe_value), "offline pressure recipe is not canonical JSON")
    require(recipe_pin["semantic_sha256"] == digest_object({
        key: value for key, value in recipe_value.items() if key != "recipe_sha256"
    }), "offline pressure recipe semantic digest differs from original bytes")
    required_paths = _pressure_absolute_json_paths(recipe_value)
    for path in required_paths:
        require(path in mapped_paths,
                f"offline pressure path map omits an exact nested recipe dependency: {path}")
    source_pin = exact(recipe_value.get("files", {}).get("source_manifest"),
                       {"path", "raw_sha256"}, "offline pressure SourceV5 manifest pin")
    require(source_pin["path"] in mapped_files,
            "offline pressure path map omits the typed SourceV5 manifest")
    source_manifest, _source_raw, source_raw_sha = read_canonical(
        Path(source_pin["path"]), "offline pressure SourceV5 manifest", MAX_SOURCE_BYTES,
    )
    require(source_raw_sha == source_pin["raw_sha256"],
            "offline pressure SourceV5 manifest raw digest differs")
    source = exact(source_manifest.get("source"), {
        "git_commit", "source_tree_sha256", "cargo_lock_sha256", "files",
    }, "offline pressure typed SourceV5 inventory")
    require(type(source["files"]) is list and len(source["files"]) <= 1_000_000,
            "offline pressure SourceV5 source inventory is malformed")
    inventory_paths: set[str] = set()
    for index, entry_value in enumerate(source["files"]):
        entry = exact(entry_value, {"path", "kind", "mode", "sha256", "size"},
                      f"offline pressure SourceV5 inventory[{index}]")
        relative = PurePosixPath(text(entry["path"], "offline pressure inventory path", 4096))
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == entry["path"] and entry["kind"] == "file" and
                entry["mode"] in ("100644", "100755"),
                "offline pressure SourceV5 inventory entry is not a typed regular file")
        inventory_path = str(source_root_path.joinpath(*relative.parts))
        inventory_paths.add(inventory_path)
    artifact_paths: set[str] = set()
    artifacts = source_manifest.get("artifacts")
    require(type(artifacts) is dict, "offline pressure SourceV5 artifact inventory is malformed")
    for artifact_value in artifacts.values():
        artifact = exact(artifact_value, {"path", "sha256"}, "offline pressure SourceV5 artifact")
        relative = PurePosixPath(text(artifact["path"], "offline pressure artifact path", 4096))
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == artifact["path"],
                "offline pressure SourceV5 artifact path is not portable")
        artifact_paths.add(str(source_root_path.joinpath(*relative.parts)))
    require(inventory_paths | artifact_paths <= mapped_files,
            "offline pressure evidence map omits a typed SourceV5 source or artifact member")
    host_receipt, host_receipt_raw_sha, host_pin = _validate_pressure_pair_host_receipt(
        raw_host_pin,
    )
    _preflight_pressure_json_path_closure(
        [recipe_value, host_receipt], mapped_paths, directories,
    )
    pressure_semantic = recipe_pin["semantic_sha256"]
    candidates = [row for row in host_receipt["member_facts"]
                  if row["pressure_recipe"]["path"] == str(recipe_path)]
    require(len(candidates) == 1, "strict host receipt does not contain exactly one matching pressure member")
    member = candidates[0]
    require(member["pressure_recipe"] == recipe_pin and
            member["pressure_artifacts"] == artifact_value,
            "strict host receipt member differs from the exact recipe/artifact input pins")
    for label, log_value in driver_logs.items():
        log_pin = exact(log_value, {"path", "raw_sha256"},
                        f"strict host pressure driver {label} log pin")
        log_raw, log_sha = read_stable(
            Path(log_pin["path"]), f"offline pressure driver {label} log", MAX_EVENTS_BYTES,
        )
        require(log_sha == log_pin["raw_sha256"] and len(log_raw) <= MAX_EVENTS_BYTES,
                f"offline pressure driver {label} log bytes differ from the strict member receipt")
    recipe = _validate_recipe(recipe_value, pressure_semantic)
    require(recipe["schema"] == RECIPE_SCHEMA_V2 and "calibration_scope_v2" in recipe,
            "offline pressure replay requires the original Source5 context-scoped calibration v2")
    require(recipe["identity"]["host_id"] == host_receipt["host_id"] and
            recipe_pin["condition_sha256"] == recipe["condition_sha256"],
            "offline pressure recipe host/condition differs from its strict pair receipt")
    member_identity = member["identity"]
    require(member_identity["host_id"] == recipe["identity"]["host_id"] and
            member_identity["run_id"] == recipe["identity"]["run_id"] and
            member_identity["allocator"] == recipe["identity"]["allocator"] and
            member_identity["executor"] == recipe["identity"]["executor"] and
            member_identity["pressure_nonce"] == recipe["identity"]["nonce"] and
            member["descriptor"]["allocator"] == recipe["identity"]["allocator"],
            "offline pressure recipe differs from its original normal-APP pair descriptor")
    storage_proof = member["storage_proof"]
    require(storage_proof == {
        "application_tmpdir_path": recipe["process"]["application_tmpdir_path"],
        "pressure_scratch_path": recipe["storage"]["pressure_scratch_path"],
        "application_mount_id": recipe["storage"]["application_mount_id"],
        "storage_sha256": digest_object({
            "application_storage": recipe["host"]["application_storage"],
            "pressure_scratch": recipe["host"]["pressure_scratch"],
            "storage": recipe["storage"],
        }),
    }, "strict pair storage/TMPDIR proof differs from the pressure recipe")
    expected = {"recipe": pressure_semantic, **pins}
    launch, _launch_raw, _launch_sha = read_canonical(
        artifact_root / "launch-record.json", "offline pressure launch record", MAX_LAUNCH_BYTES,
        pins["launch"],
    )
    process = _validate_launch(launch, recipe, pins["launch"])
    run_value, _run_raw, _run_sha = read_canonical(
        artifact_root / "run.json", "offline pressure run receipt", MAX_MANIFEST_BYTES,
        pins["run"],
    )
    run = _validate_run(run_value, expected)
    require(member["application_identity"] == {
        "pid": process["pid"], "start_ticks": process["start_ticks"],
    }, "strict pair receipt APP identity differs from the pressure launch record")
    run_workers = {
        (item["role"], item["cpu"], item["pid"], item["start_ticks"], item["pgid"], item["session_id"])
        for item in run["worker_cleanup"]
    }
    host_workers = {
        (item["role"], item["cpu"], item["pid"], item["start_ticks"], item["pgid"], item["session_id"])
        for item in member["worker_identities"]
    }
    require(host_workers == run_workers,
            "strict pair receipt pressure worker identities differ from the raw run cleanup rows")
    identity_keys = {(process["pid"], process["start_ticks"])}
    for record in run["worker_cleanup"]:
        identity_keys.add((record["pid"], record["start_ticks"]))
    absences = member["pid_absence"]
    absence_by_identity = {(item["pid"], item["start_ticks"]): item for item in absences}
    require(set(absence_by_identity) == identity_keys and len(absence_by_identity) == len(absences),
            "strict host receipt does not bind every exact pressure APP/worker PID-start identity")
    for pid, start_ticks in identity_keys:
        require(absence_by_identity[(pid, start_ticks)]["observed_monotonic_ns"] >= run["finish_monotonic_ns"],
                "strict host PID absence observation predates pressure cleanup completion")
    receipt_origin = host_receipt["origin_facts"]
    require(receipt_origin["host_id"] == recipe["identity"]["host_id"] and
            receipt_origin["observed_host_raw_sha256"] == recipe["calibration_scope_v2"]["observed_host"]["raw_sha256"],
            "strict host identity receipt differs from the exact pressure calibration observation")
    offline_context = types.MappingProxyType({
        "source_root": str(source_root_path),
        "evidence_path_map": evidence_path_map,
        "origin_absent_identities": frozenset(identity_keys),
        "host_receipt_pin": types.MappingProxyType(dict(host_pin)),
        "host_receipt_raw_sha256": host_receipt_raw_sha,
    })
    token_value = _EVIDENCE_PATH_MAP_CONTEXT.set((mapping, directories))
    replay_token = _PRESSURE_OFFLINE_REPLAY_CONTEXT.set(dict(offline_context))
    try:
        result = verify_pressure(recipe_path, pressure_semantic, artifact_root, expected)
        proof_value, proof_raw, proof_raw_sha = read_canonical(
            proof_path, "offline pressure proof output", MAX_PRESSURE_PROOF_BYTES,
            proof_pin["raw_sha256"],
        )
        require(proof_raw_sha == proof_pin["raw_sha256"] and proof_raw == canonical_bytes(result) and
                proof_value == result,
                "offline pressure replay differs from its exact original proof bytes")
        require(result["identity"]["host_id"] == host_receipt["host_id"] and
                result["recipe_raw_sha256"] == recipe_pin["raw_sha256"],
                "offline pressure readback differs from the host receipt's original generation")
        calibration = exact(result.get("calibration_scope_v2"), {
            "schema", "replay_success", "validated", "execution_ready", "qualification_eligible",
            "controller_chronology_proven", "calibration_raw_sha256", "calibration_sha256",
            "scope_sha256", "condition_id", "pressure_calibration_id", "capacity_key",
            "condition_sha256", "source_manifest_sha256", "source_manifest_semantic_sha256",
            "source_tree_sha256", "context_policy_bundle_raw_sha256",
            "context_policy_artifact_raw_sha256", "context_policy_sha256",
            "capacity_bundle_pins_sha256", "capacity_tsv_raw_sha256", "observed_host_raw_sha256",
            "host_verification", "driver_sha256", "reader_sha256", "capacity_producer_sha256",
            "feedback_composer_sha256", "feedback_reader_sha256", "sample_count",
            "samples_sha256", "summary", "pressure_thresholds", "readiness_thresholds",
            "suggested_readiness_thresholds", "worker_cleanup_sha256", "worker_session_count",
            "scratch_file_removed", "receipt_sha256",
        }, "offline pressure calibration scope receipt")
        origin = host_receipt["origin_facts"]
        host_verification = calibration["host_verification"]
        require(host_verification["host_id"] == origin["host_id"] and
                host_verification["boot_id_sha256"] == origin["before"]["boot_id_sha256"] ==
                origin["after"]["boot_id_sha256"] and
                host_verification["kernel_release"] == origin["before"]["kernel_release"] ==
                origin["after"]["kernel_release"] and
                host_verification["allowed_cpu_affinity"] == origin["before"]["cpu_affinity"] ==
                origin["after"]["cpu_affinity"] and
                host_verification["network_namespace_inode"] ==
                origin["before"]["network_namespace_inode"] == origin["after"]["network_namespace_inode"] and
                host_verification["observed_host_raw_sha256"] == origin["observed_host_raw_sha256"],
                "strict pair host facts differ from the independent calibration host receipt")
        return result
    finally:
        _PRESSURE_OFFLINE_REPLAY_CONTEXT.reset(replay_token)
        _EVIDENCE_PATH_MAP_CONTEXT.reset(token_value)


def _validate_source5_soak_host_receipt_v2(
    pin_value: object, *, allow_v3: bool = False,
) -> tuple[dict[str, Any], str, dict[str, str]]:
    """Validate the separate single-APP Soak host receipt without pair coercion."""
    pin = exact(pin_value, {"path", "raw_sha256", "receipt_sha256"},
                "Source5 Soak host-verification receipt pin")
    path = absolute_path(pin["path"], "Source5 Soak host receipt path")
    raw_sha = sha256(pin["raw_sha256"], "Source5 Soak host receipt raw SHA-256")
    receipt_sha = sha256(pin["receipt_sha256"], "Source5 Soak host receipt semantic SHA-256")
    receipt, raw, actual_raw = read_canonical(
        path, "Source5 Soak host-verification receipt",
        MAX_SOURCE5_SOAK_HOST_RECEIPT_BYTES,
    )
    info = path.lstat()
    require(actual_raw == raw_sha and stat.S_ISREG(info.st_mode) and
            info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
            "Source5 Soak host receipt is not the exact owned mode-0600 pinned file")
    bounded_v3 = receipt.get("schema") == SOURCE5_SOAK_HOST_VERIFICATION_SCHEMA_V3
    require(not bounded_v3 or allow_v3,
            "Source5 host-v3 receipt requires the bounded single-APP pressure API")
    fields = {
        "schema", "campaign_id", "host_id", "run_id", "component_sha256",
        "component_pins", "generation", "prepared_host_context_pin",
        "fixed_spec_host_pin", "observed_host_pin",
        "prepared_host_binding_sha256", "helper_input_pin",
        "construction_probe", "pressure_origin", "origin_host",
        "process_absence", "tree_roots", "evidence_inventory",
        "evidence_bases", "readback_sha256", "bounded_execution_ready",
        "bounded_blockers", "qualification_eligible", "execution_ready",
        "receipt_sha256",
    }
    if bounded_v3:
        fields |= {"resource_budget", "resource_monitor", "final_usage"}
    exact(receipt, fields, "Source5 Soak host-verification receipt")
    body = {key: value for key, value in receipt.items()
            if key != "receipt_sha256"}
    require(receipt["schema"] == (SOURCE5_SOAK_HOST_VERIFICATION_SCHEMA_V3
                                  if bounded_v3 else
                                  SOURCE5_SOAK_HOST_VERIFICATION_SCHEMA_V2) and
            receipt["receipt_sha256"] == receipt_sha == digest_object(body) and
            receipt["bounded_execution_ready"] is bounded_v3 and
            receipt["bounded_blockers"] == ([] if bounded_v3 else [
                "prospective_bounded_soak_resource_budget_not_pinned",
            ]) and receipt["qualification_eligible"] is False and
            receipt["execution_ready"] is False,
            "Source5 Soak host receipt schema/digest/status differs")
    token(receipt["campaign_id"], "Source5 Soak host receipt campaign")
    token(receipt["host_id"], "Source5 Soak host receipt host")
    token(receipt["run_id"], "Source5 Soak host receipt run")
    for name in ("component_sha256", "prepared_host_binding_sha256",
                 "readback_sha256"):
        sha256(receipt[name], f"Source5 Soak host receipt {name}")
    component_pin_fields = {
        "materials_index", "parent_recipe", "build_receipt", "preflight",
        "launch_authorization", "supervisor", "launch", "postflight",
        "readback",
    }
    if bounded_v3:
        component_pin_fields |= {
            "resource_budget", "probe_capture", "resource_monitor",
            "application_owner", "pressure_owner",
        }
    component_pins = exact(receipt["component_pins"], component_pin_fields,
                           "Source5 Soak component raw pins")
    for name, value in component_pins.items():
        if name == "resource_budget" and bounded_v3:
            exact(value, {"path", "raw_sha256", "semantic_sha256"},
                  "Source5 Soak component resource-budget pin")
        else:
            _raw_pin(value, f"Source5 Soak component {name}")
    if bounded_v3:
        budget_pin = exact(receipt["resource_budget"], {
            "path", "raw_sha256", "semantic_sha256",
        }, "Source5 Soak prospective resource-budget pin")
        budget_path = absolute_path(budget_pin["path"],
                                    "Source5 Soak resource-budget path")
        _require_evidence_path_mapped(budget_path)
        budget_raw_sha = sha256(budget_pin["raw_sha256"],
                                "Source5 Soak resource-budget raw SHA-256")
        budget_semantic_sha = sha256(
            budget_pin["semantic_sha256"],
            "Source5 Soak resource-budget semantic SHA-256",
        )
        budget, budget_raw, actual_budget_sha = read_canonical(
            budget_path, "Source5 Soak prospective resource budget", 64 * 1024,
        )
        require(actual_budget_sha == budget_raw_sha and
                budget_raw == canonical_bytes(budget) and
                budget.get("schema") ==
                    "allocatbelt.application-source5-soak-resource-budget.v2" and
                budget.get("resource_budget_sha256") == budget_semantic_sha ==
                    digest_object({key: value for key, value in budget.items()
                                   if key != "resource_budget_sha256"}),
                "Source5 Soak prospective budget raw/semantic/schema binding differs")
        budget_binding = exact(budget.get("binding"), {
            "campaign_id", "host_id", "job_sha256", "source_manifest",
            "source_tree_sha256", "parent_recipe", "build_receipt",
            "prepared_host_binding_sha256", "observed_host", "monitor_owner",
            "soak_adapter", "soak_reader",
        }, "Source5 Soak budget generation binding")
        source_generation = exact(receipt["generation"]["source_manifest"], {
            "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
        }, "Source5 Soak receipt source generation")
        budget_layout = exact(budget.get("layout"), {
            "output_root", "application_tmpdir", "pressure_scratch",
            "probe_capture_root", "probe_tmpdir", "host_receipt_path",
        }, "Source5 Soak budget output layout")
        budget_recipe = _raw_pin(
            budget_binding["parent_recipe"],
            "Source5 Soak budget parent recipe",
        )
        component_recipe = _raw_pin(
            component_pins["parent_recipe"],
            "Source5 Soak component parent recipe",
        )
        budget_build = _raw_pin(
            budget_binding["build_receipt"],
            "Source5 Soak budget build receipt",
        )
        component_build = _raw_pin(
            component_pins["build_receipt"],
            "Source5 Soak component build receipt",
        )
        prepared_host_pin = _raw_pin(
            receipt["prepared_host_context_pin"],
            "Source5 Soak prepared host context",
        )
        budget_observed_pin = _raw_pin(
            budget_binding["observed_host"],
            "Source5 Soak budget observed-host context",
        )
        receipt_observed_pin = _raw_pin(
            receipt["observed_host_pin"],
            "Source5 Soak receipt observed-host context",
        )
        probe_receipt_path = absolute_path(
            receipt["construction_probe"]["receipt_pin"]["path"],
            "Source5 Soak ProbeV2 capture receipt path",
        )
        require(budget_binding["campaign_id"] == receipt["campaign_id"] and
                budget_binding["host_id"] == receipt["host_id"] and
                budget_binding["job_sha256"] == digest_object(
                    receipt["generation"]["job"],
                ) and
                budget_binding["source_manifest"] == {
                    "path": source_generation["path"],
                    "raw_sha256": source_generation["raw_sha256"],
                    "semantic_sha256": source_generation["semantic_sha256"],
                } and
                budget_binding["source_tree_sha256"] ==
                    source_generation["source_tree_sha256"] and
                budget_binding["prepared_host_binding_sha256"] ==
                    receipt["prepared_host_binding_sha256"] and
                budget_recipe == component_recipe and
                budget_build == component_build and
                budget_observed_pin == receipt_observed_pin == prepared_host_pin and
                budget_layout["output_root"] == str(Path(
                    component_pins["supervisor"]["path"],
                ).parent) and
                budget_layout["application_tmpdir"] ==
                    receipt["pressure_origin"]["application_tmpdir_path"] and
                budget_layout["probe_capture_root"] ==
                    str(probe_receipt_path.parent) and
                budget_layout["probe_tmpdir"] == str(
                    probe_receipt_path.parent / "tmp",
                ) and
                budget_layout["host_receipt_path"] == pin["path"],
                "Source5 Soak v3 host receipt changed its original budget/job/source/layout binding")
        monitor = exact(receipt["resource_monitor"], {
            "schema", "budget", "stream", "row_count", "high_water",
            "final_usage", "failure", "prefix_sha256",
        }, "Source5 Soak resource-monitor summary")
        monitor_stream = exact(monitor["stream"], {"path", "raw_sha256"},
                               "Source5 Soak resource-monitor stream pin")
        _raw_pin(component_pins["resource_monitor"],
                 "Source5 Soak resource-monitor component pin")
        _require_evidence_path_mapped(monitor_stream["path"])
        require(monitor["schema"] ==
                    "allocatbelt.application-source5-soak-resource-monitor-summary.v1" and
                monitor["budget"] == budget_pin and
                component_pins["resource_budget"] == budget_pin and
                component_pins["resource_monitor"] == monitor_stream and
                monitor_stream["path"] ==
                    str(Path(budget["layout"]["output_root"]) /
                        "source5-soak-resource-monitor.jsonl") and
                type(monitor["row_count"]) is int and monitor["row_count"] > 0 and
                monitor["failure"] is None and
                monitor["final_usage"] == receipt["final_usage"]["domains"] and
                monitor["high_water"] == receipt["final_usage"]["high_water"],
                "Source5 Soak v3 host receipt budget/monitor/final usage differs")
        sha256(monitor_stream["raw_sha256"],
               "Source5 Soak resource-monitor stream raw SHA-256")
        final_usage = exact(receipt["final_usage"], {"domains", "high_water"},
                            "Source5 Soak final usage")
        expected_domains = {
            "output", "application_tmpdir", "pressure_scratch",
            "probe_capture", "probe_tmpdir",
        }
        exact(final_usage["domains"], expected_domains,
              "Source5 Soak final usage domains")
        exact(final_usage["high_water"], expected_domains,
              "Source5 Soak final high-water domains")
        for role in expected_domains:
            domain = exact(final_usage["domains"][role], {
                "bytes_used", "inode_count",
            }, f"Source5 Soak final {role} usage")
            high = exact(final_usage["high_water"][role], {
                "bytes", "inodes",
            }, f"Source5 Soak {role} high-water")
            for name, value in domain.items():
                uint(value, f"Source5 Soak final {role} {name}")
            for name, value in high.items():
                uint(value, f"Source5 Soak {role} {name}")
    generation = receipt["generation"]
    require(type(generation) is dict and
            generation.get("campaign_id") == receipt["campaign_id"] and
            generation.get("host_id") == receipt["host_id"] and
            type(generation.get("job")) is dict and
            generation["job"].get("run_id") == receipt["run_id"] and
            generation["job"].get("phase") == "soak",
            "Source5 Soak host receipt changed its original generation/job")
    source_generation = exact(generation.get("source_manifest"), {
        "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
    }, "Source5 Soak selected SourceV5 generation")
    absolute_path(source_generation["path"], "Source5 Soak selected source manifest path")
    for name in ("raw_sha256", "semantic_sha256", "source_tree_sha256"):
        sha256(source_generation[name], f"Source5 Soak source generation {name}")
    origin = exact(receipt["origin_host"], {
        "schema", "host_id", "observed_host_raw_sha256", "boot_id_sha256",
        "kernel_release", "allowed_cpu_affinity", "network_namespace_inode",
        "controls_sha256", "host_identity_sha256",
    }, "Source5 Soak origin host facts")
    origin_body = {key: value for key, value in origin.items()
                   if key != "host_identity_sha256"}
    require(origin["schema"] ==
            "allocatbelt.application-source5-soak-origin-host.v1" and
            origin["host_id"] == receipt["host_id"] and
            origin["host_identity_sha256"] == digest_object(origin_body),
            "Source5 Soak origin host fact digest or identity differs")
    for name in ("observed_host_raw_sha256", "boot_id_sha256", "controls_sha256"):
        sha256(origin[name], f"Source5 Soak origin host {name}")
    affinity = origin["allowed_cpu_affinity"]
    normalized_affinity = [
        uint(cpu, "Source5 Soak origin CPU", maximum=65535)
        for cpu in affinity
    ] if type(affinity) is list else []
    require(type(affinity) is list and 1 <= len(affinity) <= 4096 and
            affinity == sorted(set(normalized_affinity)),
            "Source5 Soak origin CPU affinity is malformed")
    uint(origin["network_namespace_inode"],
         "Source5 Soak origin network namespace", positive=True)
    text(origin["kernel_release"], "Source5 Soak origin kernel release", 256)
    observed_pin = _raw_pin(receipt["observed_host_pin"],
                            "Source5 Soak observed-host pin")
    require(observed_pin == _raw_pin(receipt["prepared_host_context_pin"],
                                     "Source5 Soak prepared host-context pin") and
            observed_pin["raw_sha256"] == origin["observed_host_raw_sha256"],
            "Source5 Soak origin host facts changed their observed-host pin")
    pressure_origin = exact(receipt["pressure_origin"], {
        "schema", "recipe_pin", "recipe_dependency_paths",
        "application_tmpdir_path", "storage_before", "storage_after",
    }, "Source5 Soak pressure origin facts")
    require(pressure_origin["schema"] ==
            "allocatbelt.application-source5-soak-pressure-origin.v2",
            "Source5 Soak pressure origin schema differs")
    dependency_paths = pressure_origin["recipe_dependency_paths"]
    require(type(dependency_paths) is list and dependency_paths and
            all(type(path_value) is str and
                absolute_path(path_value, "Source5 pressure dependency path")
                    == Path(path_value)
                for path_value in dependency_paths) and
            dependency_paths == sorted(set(dependency_paths)),
            "Source5 Soak pressure dependency path closure is malformed")
    return receipt, actual_raw, {"path": str(path), "raw_sha256": raw_sha,
                                 "receipt_sha256": receipt_sha}


def _verify_source5_soak_pressure_offline_impl(
    pressure_recipe_pin: object, pressure_artifacts: object,
    soak_host_verification_pin: object, *, evidence_path_map: object,
    source_root: object, bounded_v3: bool,
) -> dict[str, Any]:
    """Replay the one original Soak APP pressure run from its own strict facts.

    This API is separate from `verify_pressure_offline`, which requires exactly
    two original pressure-pair members. The Soak host receipt remains in its
    own closed schema; no pair-member rows are synthesized or inferred.
    """
    recipe_pin = exact(pressure_recipe_pin, {
        "path", "raw_sha256", "semantic_sha256", "condition_sha256",
    }, "Source5 Soak pressure recipe pin")
    recipe_path = absolute_path(recipe_pin["path"], "Source5 Soak pressure recipe path")
    for name in ("raw_sha256", "semantic_sha256", "condition_sha256"):
        sha256(recipe_pin[name], f"Source5 Soak pressure recipe {name}")
    artifacts = exact(pressure_artifacts, {
        "directory", "pins", "proof", "ready_sha256", "driver",
        "worker_sessions", "driver_logs",
    }, "Source5 Soak pressure artifacts")
    artifact_root = absolute_path(artifacts["directory"],
                                  "Source5 Soak pressure artifact directory")
    pins = exact(artifacts["pins"], {
        "events", "launch", "process_binding", "ready", "run",
    }, "Source5 Soak pressure artifact pins")
    pins = {name: sha256(value, f"Source5 Soak pressure {name} raw SHA-256")
            for name, value in pins.items()}
    require(artifacts["ready_sha256"] == pins["ready"],
            "Source5 Soak pressure ready pin differs")
    proof_pin = exact(artifacts["proof"], {"path", "raw_sha256"},
                      "Source5 Soak pressure proof pin")
    proof_path = absolute_path(proof_pin["path"], "Source5 Soak pressure proof path")
    sha256(proof_pin["raw_sha256"], "Source5 Soak pressure proof raw SHA-256")
    driver_logs = exact(artifacts["driver_logs"], {"stdout", "stderr"},
                        "Source5 Soak pressure driver log pins")
    for label, pin_value in driver_logs.items():
        log_pin = exact(pin_value, {"path", "raw_sha256"},
                        f"Source5 Soak pressure {label} log pin")
        absolute_path(log_pin["path"],
                      f"Source5 Soak pressure {label} log path")
        sha256(log_pin["raw_sha256"],
               f"Source5 Soak pressure {label} log raw SHA-256")
    source_root_path = absolute_path(source_root, "Source5 Soak pressure SourceV5 root")
    mapping, directories = _normalize_evidence_path_map(
        evidence_path_map, source_root_path,
    )
    mapped_paths = frozenset(mapping)
    mapped_files = frozenset(path for path in mapping if path not in directories)
    host_pin = exact(soak_host_verification_pin, {
        "path", "raw_sha256", "receipt_sha256",
    }, "Source5 Soak host receipt pin")
    absolute_path(host_pin["path"], "Source5 Soak host receipt path")
    sha256(host_pin["raw_sha256"], "Source5 Soak host receipt raw SHA-256")
    sha256(host_pin["receipt_sha256"], "Source5 Soak host receipt semantic SHA-256")
    direct_files = {
        str(recipe_path), str(proof_path), host_pin["path"],
        str(artifact_root / "events.jsonl"),
        str(artifact_root / "launch-record.json"),
        str(artifact_root / "process-binding.json"),
        str(artifact_root / "pressure-ready.json"),
        str(artifact_root / "run.json"),
    }
    direct_files.update(pin["path"] for pin in driver_logs.values())
    require(direct_files <= mapped_files and str(artifact_root) in directories and
            str(source_root_path) in directories,
            "Source5 Soak pressure path map omits a direct pinned input")

    token_value = _EVIDENCE_PATH_MAP_CONTEXT.set((mapping, directories))
    replay_token: contextvars.Token[dict[str, Any] | None] | None = None
    try:
        raw_host_receipt, host_receipt_raw_sha, _host_pin = \
            _validate_source5_soak_host_receipt_v2(
                host_pin, allow_v3=bounded_v3,
            )
        origin = raw_host_receipt["pressure_origin"]
        recorded_recipe_pin = origin["recipe_pin"]
        require(recorded_recipe_pin == recipe_pin and
                type(origin["application_tmpdir_path"]) is str,
                "Source5 Soak pressure receipt changed its original recipe/output scope")
        recorded_artifacts = origin["storage_after"].get("pressure_artifacts")
        require(recorded_artifacts == artifacts,
                "Source5 Soak pressure artifacts differ from its strict host receipt")
        recipe_value, recipe_raw, recipe_raw_sha = read_canonical(
            recipe_path, "Source5 Soak frozen pressure recipe", MAX_RECIPE_BYTES,
        )
        require(recipe_raw_sha == recipe_pin["raw_sha256"] and
                recipe_raw == canonical_bytes(recipe_value) and
                recipe_pin["semantic_sha256"] == digest_object({
                    key: value for key, value in recipe_value.items()
                    if key != "recipe_sha256"
                }) and
                recipe_value.get("condition_sha256") ==
                    recipe_pin["condition_sha256"],
                "Source5 Soak pressure recipe raw/semantic/condition roles differ")
        expected_dependencies = set(_pressure_absolute_json_paths(recipe_value))
        expected_dependencies.add(str(recipe_path))
        expected_dependencies = {
            str(absolute_path(value, "Source5 Soak nested recipe dependency"))
            for value in expected_dependencies
        }
        require(origin["recipe_dependency_paths"] ==
                sorted(expected_dependencies) and
                expected_dependencies <= mapped_paths,
                "Source5 Soak evidence map omits or changes the complete pressure recipe path closure")
        inventory = raw_host_receipt["evidence_inventory"]
        require(type(inventory) is list and
                len(inventory) <= MAX_SOURCE5_SOAK_INVENTORY_ENTRIES and
                expected_dependencies <= {
                    entry.get("path") for entry in inventory
                    if type(entry) is dict
                },
                "Source5 Soak host receipt does not bind every pressure recipe dependency")

        supervisor_pin = _raw_pin(
            raw_host_receipt["component_pins"]["supervisor"],
            "Source5 Soak pressure supervisor pin",
        )
        require(supervisor_pin["path"] in mapped_files,
                "Source5 Soak pressure map omits its pinned supervisor")
        supervisor, _supervisor_raw, supervisor_sha = read_canonical(
            Path(supervisor_pin["path"]), "Source5 Soak pressure supervisor",
            MAX_MANIFEST_BYTES,
        )
        require(supervisor_sha == supervisor_pin["raw_sha256"],
                "Source5 Soak pressure supervisor bytes differ from their raw pin")
        exact(supervisor, {
            "schema", "execution_kind", "status", "interrupted", "received_signal",
            "application_cleanup", "application_binding", "application_binding_sha256",
            "application_attestation", "pressure_ready_sha256", "pressure_proof",
            "pressure_cleanup", "pressure_driver", "pressure_worker_sessions", "details",
        }, "Source5 Soak pressure supervisor")
        require(supervisor["schema"] == "allocatbelt.application-pressure-supervision.v1" and
                supervisor["execution_kind"] == "timed_soak" and
                supervisor["status"] == 0 and supervisor["interrupted"] is False and
                supervisor["received_signal"] is None and
                supervisor["pressure_cleanup"] == "verified",
                "Source5 Soak pressure supervisor did not complete its original lifecycle")
        parent_recipe_pin = _raw_pin(
            raw_host_receipt["component_pins"]["parent_recipe"],
            "Source5 Soak parent recipe pin",
        )
        require(parent_recipe_pin["path"] in mapped_files,
                "Source5 Soak pressure map omits its parent recipe")
        parent_recipe, _parent_raw, parent_raw_sha = read_canonical(
            Path(parent_recipe_pin["path"]), "Source5 Soak parent recipe",
            MAX_RECIPE_BYTES,
        )
        require(parent_raw_sha == parent_recipe_pin["raw_sha256"] and
                parent_recipe.get("schema") ==
                    "allocatbelt.application-soak-parent-recipe.v2",
                "Source5 Soak parent recipe raw bytes/schema differ")
        parent_identity = exact(parent_recipe.get("identity"), {
            "campaign_id", "host_id", "run_id", "nonce", "allocator",
            "executor", "workload", "profile", "comparison_family",
            "source_sha256", "build_sha256", "binary_sha256",
            "resource_ceiling_sha256",
        }, "Source5 Soak parent recipe identity")
        parent_source = exact(parent_recipe.get("source"), {
            "root", "manifest_path", "manifest_sha256",
        }, "Source5 Soak parent SourceV5 binding")
        parent_qualification = parent_recipe.get("qualification")
        require(type(parent_qualification) is dict,
                "Source5 Soak parent recipe omits its frozen qualification inputs")
        parent_condition = exact(parent_qualification.get("pressure_condition"), {
            "condition_id", "condition_sha256", "condition",
            "pressure_calibration", "readiness_thresholds", "schedule",
        }, "Source5 Soak parent pressure condition")
        parent_condition_pin = exact(parent_condition["condition"], {
            "relative_path", "raw_sha256",
        }, "Source5 Soak parent raw pressure-condition pin")
        sha256(parent_condition_pin["raw_sha256"],
               "Source5 Soak parent pressure-condition raw SHA-256")
        require(parent_condition["condition_sha256"] ==
                parent_condition_pin["raw_sha256"],
                "Source5 Soak parent condition raw-digest roles differ")
        parent_pressure = exact(parent_recipe.get("pressure"), {
            "request_template", "recipe", "condition_sha256", "driver",
            "validator",
        }, "Source5 Soak parent pressure binding")
        parent_pressure_pin = exact(parent_pressure["recipe"], {
            "path", "raw_sha256", "semantic_sha256",
        }, "Source5 Soak parent pressure recipe pin")
        require(parent_identity["campaign_id"] == raw_host_receipt["campaign_id"] and
                parent_identity["host_id"] == raw_host_receipt["host_id"] and
                parent_identity["run_id"] == raw_host_receipt["run_id"] and
                parent_identity["allocator"] == "allocatbelt" and
                parent_identity["executor"] == "bounded" and
                parent_identity["workload"] == "mixed" and
                parent_identity["comparison_family"] == "external_pressure" and
                parent_source["root"] == str(source_root_path) and
                parent_source["manifest_path"] ==
                    raw_host_receipt["generation"]["source_manifest"]["path"] and
                parent_source["manifest_sha256"] ==
                    raw_host_receipt["generation"]["source_manifest"]["raw_sha256"] and
                parent_pressure["condition_sha256"] ==
                    recipe_pin["condition_sha256"] and
                parent_pressure_pin == {
                    key: recipe_pin[key] for key in (
                        "path", "raw_sha256", "semantic_sha256",
                    )
                } and
                parent_pressure["condition_sha256"] == recipe_pin["condition_sha256"],
                "Source5 Soak parent pressure/job identity differs from this single-APP run")
        app_cleanup = exact(supervisor["application_cleanup"], {
            "schema", "status", "pid", "return_code", "received_signal",
            "cleanup_error",
        }, "Source5 Soak direct APP cleanup")
        require(app_cleanup["schema"] ==
                "allocatbelt.application-soak-process-cleanup.v1" and
                app_cleanup["status"] == "verified" and
                app_cleanup["return_code"] == 0 and
                app_cleanup["received_signal"] is None and
                app_cleanup["cleanup_error"] is None,
                "Source5 Soak APP cleanup receipt is incomplete")
        details = exact(supervisor["details"], {
            "status", "child_return_code", "timed_out", "artifact_budget_exceeded",
            "received_signal", "started_monotonic_ns", "ended_monotonic_ns",
            "binary_path", "binary_sha256", "binary_device", "binary_inode",
            "binary_size", "requested_argv", "requested_argv_sha256",
            "executed_argv", "executed_file_descriptor", "environment",
            "environment_sha256", "cwd", "cpu_set",
        }, "Source5 Soak supervisor final APP facts")
        require(details["status"] == 0 and details["child_return_code"] == 0 and
                details["timed_out"] is False and
                details["artifact_budget_exceeded"] is False and
                details["received_signal"] is None and
                type(details["started_monotonic_ns"]) is int and
                type(details["ended_monotonic_ns"]) is int and
                details["ended_monotonic_ns"] >= details["started_monotonic_ns"],
                "Source5 Soak supervisor final APP status differs")
        app_attestation = exact(supervisor["application_attestation"], {
            "schema", "execution_kind", "process", "attestation_sha256",
        }, "Source5 Soak direct APP attestation")
        app_attestation_body = {
            key: value for key, value in app_attestation.items()
            if key != "attestation_sha256"
        }
        require(app_attestation["schema"] ==
                "allocatbelt.application-pressure-app-launch-attestation.v1" and
                app_attestation["execution_kind"] == "timed_soak" and
                app_attestation["attestation_sha256"] ==
                    digest_object(app_attestation_body),
                "Source5 Soak direct APP attestation digest or role differs")
        app_process = exact(app_attestation["process"], {
            "pid", "start_ticks", "executable_path", "executable_sha256",
            "executable_device", "executable_inode", "executable_size",
            "executable_fd_reference", "cwd", "argv", "argv_sha256",
            "cmdline_raw_sha256", "environment_sha256", "environment_raw_sha256",
        }, "Source5 Soak pressure APP attestation")
        app_binding = exact(supervisor["application_binding"]["process"], {
            "pid", "start_ticks", "executable_path", "executable_sha256", "cwd",
            "tmpdir_path", "cpu_affinity", "network_namespace_inode",
        }, "Source5 Soak pressure APP binding")
        driver = artifacts["driver"]
        require(driver == supervisor["pressure_driver"] and
                type(driver) is dict and type(driver.get("pid")) is int and
                driver["pid"] > 0 and type(driver.get("start_ticks")) is int and
                driver["start_ticks"] > 0 and driver.get("return_code") == 0 and
                artifacts["worker_sessions"] == supervisor["pressure_worker_sessions"] and
                app_binding["pid"] == app_process["pid"] and
                app_binding["start_ticks"] == app_process["start_ticks"],
                "Source5 Soak pressure identities differ from the supervisor capture")
        require(app_cleanup["pid"] == app_process["pid"] and
                details["binary_sha256"] == app_process["executable_sha256"] and
                details["requested_argv"] == app_process["argv"] and
                details["executed_argv"] == app_process["argv"] and
                details["environment_sha256"] == app_process["environment_sha256"] and
                supervisor["pressure_ready_sha256"] == artifacts["ready_sha256"],
                "Source5 Soak APP environment/cleanup or pressure readiness differs from its raw identities")
        supervisor_pressure_proof = exact(supervisor["pressure_proof"], {
            "proof", "raw_sha256",
        }, "Source5 Soak supervisor pressure proof")
        require(type(supervisor_pressure_proof["proof"]) is dict and
                supervisor_pressure_proof["raw_sha256"] ==
                    artifacts["proof"]["raw_sha256"],
                "Source5 Soak supervisor proof pin differs from the pressure artifact descriptor")
        worker_sessions = artifacts["worker_sessions"]
        require(type(worker_sessions) is list and worker_sessions,
                "Source5 Soak pressure worker set is empty")
        identities = [(app_process["pid"], app_process["start_ticks"]),
                      (driver["pid"], driver["start_ticks"])]
        expected_absence = [{
            "role": "application", "pid": app_process["pid"],
            "start_ticks": app_process["start_ticks"],
        }, {
            "role": "pressure_driver", "pid": driver["pid"],
            "start_ticks": driver["start_ticks"],
        }]
        for index, worker_value in enumerate(worker_sessions):
            require(type(worker_value) is dict and {
                "role", "cpu", "pid", "start_ticks", "pgid", "session_id",
                "reaped",
            } <= set(worker_value),
                f"Source5 Soak pressure worker[{index}] is malformed")
            worker = worker_value
            require(worker["reaped"] is True and type(worker["role"]) is str and
                    (worker["cpu"] is None or type(worker["cpu"]) is int),
                    "Source5 Soak pressure worker is not marked reaped")
            key = (uint(worker["pid"], "Source5 Soak pressure worker PID", positive=True,
                        maximum=(1 << 31) - 1),
                   uint(worker["start_ticks"], "Source5 Soak pressure worker start", positive=True))
            uint(worker["pgid"], "Source5 Soak pressure worker process group", positive=True,
                 maximum=(1 << 31) - 1)
            uint(worker["session_id"], "Source5 Soak pressure worker session", positive=True,
                 maximum=(1 << 31) - 1)
            identities.append(key)
            expected_absence.append({
                "role": f"pressure_worker:{worker['role']}:{'-' if worker['cpu'] is None else worker['cpu']}",
                "pid": key[0], "start_ticks": key[1],
            })
        require(len(identities) == len(set(identities)),
                "Source5 Soak pressure supervisor repeats a process identity")
        expected_absence.sort(key=lambda item: item["role"])
        absences = raw_host_receipt["process_absence"]
        require(type(absences) is list and len(absences) == len(expected_absence),
                "Source5 Soak pressure origin absence set is sparse")
        absence_observations: dict[tuple[int, int], int] = {}
        for index, (absence_value, identity) in enumerate(zip(
                absences, expected_absence, strict=True)):
            absence = exact(absence_value, {
                "role", "pid", "start_ticks", "original_identity_absent",
                "observed_start_ticks", "observed_monotonic_ns",
            }, f"Source5 Soak pressure absence[{index}]")
            require({key: absence[key] for key in identity} == identity and
                    absence["original_identity_absent"] is True and
                    type(absence["observed_monotonic_ns"]) is int and
                    absence["observed_monotonic_ns"] > 0 and
                    (absence["observed_start_ticks"] is None or
                     type(absence["observed_start_ticks"]) is int and
                     absence["observed_start_ticks"] != identity["start_ticks"]),
                    "Source5 Soak pressure origin absence does not bind the original PID/start")
            absence_observations[(identity["pid"], identity["start_ticks"])] = \
                absence["observed_monotonic_ns"]

        origin_host = raw_host_receipt["origin_host"]
        observed_pin = _raw_pin(raw_host_receipt["observed_host_pin"],
                                "Source5 Soak pressure observed-host pin")
        observed, _observed_raw, observed_sha = read_canonical(
            Path(observed_pin["path"]), "Source5 Soak pressure observed host",
            MAX_SOURCE_BYTES,
        )
        exact(observed, {
            "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
            "kernel_release", "cpu_model", "cpu_affinity",
            "network_namespace_inode",
        }, "Source5 Soak pressure observed host")
        require(observed_sha == observed_pin["raw_sha256"] and
                observed_sha == origin_host["observed_host_raw_sha256"] and
                observed["schema"] == "allocatbelt.application-capacity-host-context.v1" and
                observed["host_id"] == raw_host_receipt["host_id"] and
                observed["boot_id_sha256"] == origin_host["boot_id_sha256"] and
                observed["kernel_release"] == origin_host["kernel_release"] and
                observed["cpu_affinity"] == origin_host["allowed_cpu_affinity"] and
                observed["network_namespace_inode"] ==
                    origin_host["network_namespace_inode"] and
                observed["controls_sha256"] == origin_host["controls_sha256"],
                "Source5 Soak pressure origin host facts differ from observed bytes")

        storage_before = exact(origin["storage_before"], {
            "application_storage", "pressure_scratch", "recipe_storage",
        }, "Source5 Soak pressure storage-before facts")
        storage_after = exact(origin["storage_after"], {
            "application_process", "pressure_artifacts", "pressure_readback_sha256",
            "pressure_cleanup", "pressure_driver_source_sha256",
            "application_storage", "pressure_scratch",
        }, "Source5 Soak pressure storage-after facts")
        pressure_readback_sha = sha256(
            storage_after["pressure_readback_sha256"],
            "Source5 Soak strict pressure readback semantic SHA-256",
        )
        recipe_summary = _validate_recipe(
            recipe_value, recipe_pin["semantic_sha256"],
        )
        require(recipe_summary["condition_sha256"] ==
                recipe_pin["condition_sha256"],
                "Source5 Soak pressure recipe summary changed its condition digest")
        recipe = recipe_value
        condition_path = PurePosixPath(text(
            parent_condition_pin["relative_path"],
            "Source5 Soak parent pressure-condition relative path", 4096,
        ))
        spec_pin = exact(parent_qualification["spec"], {
            "path", "raw_sha256", "semantic_sha256",
        }, "Source5 Soak parent SpecV3 pin")
        expected_condition_path = Path(spec_pin["path"]).parent.joinpath(
            *condition_path.parts,
        )
        pressure_condition_pin = exact(
            recipe["calibration_scope_v2"]["condition"],
            {"path", "raw_sha256"},
            "Source5 pressure recipe condition raw pin",
        )
        require(not condition_path.is_absolute() and
                ".." not in condition_path.parts and
                pressure_condition_pin == {
                    "path": str(expected_condition_path),
                    "raw_sha256": parent_condition_pin["raw_sha256"],
                },
                "Source5 Soak pressure recipe changed the raw original condition path/bytes")
        binding_receipt = exact(supervisor["application_binding"], {
            "schema", "recipe_sha256", "nonce", "process",
            "launch_binding_sha256",
        }, "Source5 Soak direct APP pressure binding")
        binding_body = {key: value for key, value in binding_receipt.items()
                        if key != "launch_binding_sha256"}
        require(recipe["schema"] == RECIPE_SCHEMA_V2 and
                recipe["identity"]["host_id"] == raw_host_receipt["host_id"] and
                recipe["identity"]["run_id"] == raw_host_receipt["run_id"] and
                recipe["identity"]["condition_id"] ==
                    parent_condition["condition_id"] and
                recipe["identity"]["allocator"] == parent_identity["allocator"] ==
                    "allocatbelt" and
                recipe["identity"]["executor"] == "allocatbelt" and
                recipe["identity"]["phase"] == "external_pressure" and
                recipe["identity"]["nonce"] == parent_identity["nonce"] and
                recipe["condition_sha256"] == recipe_pin["condition_sha256"] and
                recipe["files"]["source_manifest"]["raw_sha256"] ==
                    raw_host_receipt["generation"]["source_manifest"]["raw_sha256"] and
                recipe["files"]["source_manifest"]["path"] ==
                    raw_host_receipt["generation"]["source_manifest"]["path"] and
                binding_receipt["recipe_sha256"] == recipe_pin["semantic_sha256"] and
                binding_receipt["nonce"] == recipe["identity"]["nonce"] and
                binding_receipt["launch_binding_sha256"] ==
                    digest_object(binding_body) and
                supervisor["application_binding_sha256"] ==
                    binding_receipt["launch_binding_sha256"],
                "Source5 Soak pressure recipe differs from its original host/generation")
        require(storage_before["application_storage"] == recipe["host"]["application_storage"] and
                storage_before["pressure_scratch"] == recipe["host"]["pressure_scratch"] and
                storage_before["recipe_storage"] == recipe["storage"] and
                origin["application_tmpdir_path"] ==
                    recipe["process"]["application_tmpdir_path"] and
                storage_after["pressure_cleanup"] == "verified" and
                storage_after["pressure_driver_source_sha256"] ==
                    recipe["script_hashes"]["driver_sha256"],
                "Source5 Soak pressure storage facts differ from the raw recipe")
        app_after = exact(storage_after["application_process"], {
            "pid", "start_ticks", "tmpdir_path", "cpu_affinity",
            "network_namespace_inode",
        }, "Source5 Soak pressure APP/storage identity")
        require(app_after["pid"] == app_process["pid"] and
                app_after["start_ticks"] == app_process["start_ticks"] and
                app_after["tmpdir_path"] == recipe["process"]["application_tmpdir_path"] ==
                    recipe["storage"]["application_io_paths"][
                        recipe["storage"]["application_io_paths"].index(
                            recipe["process"]["application_tmpdir_path"])
                    ] and
                app_after["cpu_affinity"] == recipe["schedule"]["application_cpu_affinity"] and
                app_after["network_namespace_inode"] ==
                    recipe["network"]["network_namespace_inode"] and
                app_binding["tmpdir_path"] == app_after["tmpdir_path"] and
                app_binding["cpu_affinity"] == app_after["cpu_affinity"] and
                app_binding["network_namespace_inode"] ==
                    app_after["network_namespace_inode"],
                "Source5 Soak pressure APP identity differs from its raw recipe")
        minimum_free = recipe["storage"]["output_minimum_free_bytes"]
        before_rows = {row["path"]: row
                       for row in storage_before["application_storage"]}
        after_rows = storage_after["application_storage"]
        require(type(after_rows) is list and set(before_rows) == {
            row.get("path") for row in after_rows if type(row) is dict
        }, "Source5 Soak post-pressure storage path set differs")
        for index, row_value in enumerate(after_rows):
            row = exact(row_value, {
                "path", "record", "available_bytes", "available_inodes",
            }, f"Source5 Soak post-pressure application storage[{index}]")
            require(row["record"] == before_rows[row["path"]] and
                    type(row["available_bytes"]) is int and
                    row["available_bytes"] >= minimum_free and
                    type(row["available_inodes"]) is int and
                    row["available_inodes"] >= 0,
                    "Source5 Soak post-pressure application storage facts differ")
        scratch_before = storage_before["pressure_scratch"]
        scratch_after = exact(storage_after["pressure_scratch"], {
            "path", "record", "available_bytes", "available_inodes",
        }, "Source5 Soak post-pressure scratch storage")
        require(scratch_after["path"] == scratch_before["path"] and
                scratch_after["record"] == scratch_before and
                type(scratch_after["available_bytes"]) is int and
                scratch_after["available_bytes"] >= minimum_free and
                type(scratch_after["available_inodes"]) is int and
                scratch_after["available_inodes"] >= 0,
                "Source5 Soak post-pressure scratch storage facts differ")

        require(set(artifacts["pins"]) == set(pins) and
                str(artifact_root) == str(Path(origin["storage_after"]["pressure_artifacts"]["directory"])) and
                storage_after["pressure_artifacts"] == artifacts and
                proof_path == Path(artifacts["proof"]["path"]) and
                proof_path == Path(raw_host_receipt["component_pins"]["supervisor"]["path"]).parent / "pressure-readback.json" and
                supervisor_pressure_proof["raw_sha256"] == proof_pin["raw_sha256"],
                "Source5 Soak pressure output descriptor differs from its host receipt")
        expected_paths = {str(recipe_path), str(proof_path),
                          str(artifact_root / "events.jsonl"),
                          str(artifact_root / "launch-record.json"),
                          str(artifact_root / "process-binding.json"),
                          str(artifact_root / "pressure-ready.json"),
                          str(artifact_root / "run.json"),
                          *(value["path"] for value in driver_logs.values())}
        require(expected_paths <= mapped_files,
                "Source5 Soak pressure map omits exact artifacts/logs")
        _preflight_pressure_json_path_closure(
            [recipe_value], mapped_paths, directories,
        )
        source_pin = exact(recipe["files"]["source_manifest"], {
            "path", "raw_sha256",
        }, "Source5 Soak pressure source-manifest pin")
        source_manifest, _source_raw, source_raw_sha = read_canonical(
            Path(source_pin["path"]), "Source5 Soak pressure SourceV5 manifest",
            MAX_SOURCE_BYTES,
        )
        source = exact(source_manifest.get("source"), {
            "git_commit", "source_tree_sha256", "cargo_lock_sha256", "files",
        }, "Source5 Soak pressure SourceV5 identity")
        source_body = {key: value for key, value in source_manifest.items()
                       if key != "manifest_sha256"}
        source_generation = raw_host_receipt["generation"]["source_manifest"]
        require(source_raw_sha == source_pin["raw_sha256"] and
                source_manifest.get("schema") == SOURCE5_MANIFEST_SCHEMA and
                source_manifest.get("manifest_sha256") ==
                    source_generation["semantic_sha256"] ==
                    digest_object(source_body) and
                source["source_tree_sha256"] ==
                    source_generation["source_tree_sha256"],
                "Source5 Soak pressure SourceV5 manifest raw bytes differ")
        source_files = source["files"]
        require(type(source_files) is list and len(source_files) <= 1_000_000,
                "Source5 Soak pressure typed SourceV5 inventory is malformed")
        typed_paths: set[str] = {source_pin["path"]}
        for index, entry_value in enumerate(source_files):
            entry = exact(entry_value, {
                "path", "kind", "mode", "sha256", "size",
            }, f"Source5 Soak pressure SourceV5 inventory[{index}]")
            relative = PurePosixPath(text(
                entry["path"], "Source5 Soak pressure SourceV5 relative path", 4096,
            ))
            require(not relative.is_absolute() and ".." not in relative.parts and
                    relative.as_posix() == entry["path"] and
                    entry["kind"] == "file" and entry["mode"] in ("100644", "100755"),
                    "Source5 Soak pressure source inventory entry is not a regular typed file")
            typed_paths.add(str(source_root_path.joinpath(*relative.parts)))
        artifacts_block = source_manifest.get("artifacts")
        require(type(artifacts_block) is dict,
                "Source5 Soak pressure SourceV5 artifact inventory is malformed")
        for artifact_value in artifacts_block.values():
            artifact = exact(artifact_value, {"path", "sha256"},
                             "Source5 Soak pressure SourceV5 artifact")
            relative = PurePosixPath(text(
                artifact["path"], "Source5 Soak pressure artifact path", 4096,
            ))
            require(not relative.is_absolute() and ".." not in relative.parts and
                    relative.as_posix() == artifact["path"],
                    "Source5 Soak pressure artifact path is not portable")
            typed_paths.add(str(source_root_path.joinpath(*relative.parts)))
        require(typed_paths <= mapped_files,
                "Source5 Soak pressure map omits typed SourceV5 source/artifact members")
        # The receipt was parsed above; compare its origin facts with the
        # original pressure recipe and its one direct APP identity before
        # enabling the existing full raw event/calibration verifier.
        pressure_value = recipe_value
        for label, pin_value in driver_logs.items():
            log_pin = exact(pin_value, {"path", "raw_sha256"},
                            f"Source5 Soak pressure {label} log pin")
            _log_raw, log_sha = read_stable(
                Path(log_pin["path"]), f"Source5 Soak pressure {label} log",
                MAX_EVENTS_BYTES,
            )
            require(log_sha == log_pin["raw_sha256"],
                    f"Source5 Soak pressure {label} log bytes differ")

        proof_pin_raw = proof_pin["raw_sha256"]
        expected = {"recipe": recipe_pin["semantic_sha256"], **pins}
        absent_ids = frozenset(identities)
        replay_context = {
            "source_root": str(source_root_path),
            "evidence_path_map": evidence_path_map,
            "origin_absent_identities": absent_ids,
            "host_receipt_pin": dict(host_pin),
            "host_receipt_raw_sha256": host_receipt_raw_sha,
        }
        replay_token = _PRESSURE_OFFLINE_REPLAY_CONTEXT.set(replay_context)
        recipe_validated = _validate_recipe(
            pressure_value, recipe_pin["semantic_sha256"],
        )
        require(pressure_value.get("schema") == RECIPE_SCHEMA_V2 and
                recipe_validated["condition_sha256"] == recipe_pin["condition_sha256"],
                "Source5 Soak pressure recipe no longer satisfies the original V2 gate")
        run_value, _run_raw, run_sha = read_canonical(
            artifact_root / "run.json", "Source5 Soak pressure run receipt",
            MAX_MANIFEST_BYTES,
        )
        require(run_sha == pins["run"],
                "Source5 Soak pressure run receipt bytes differ from their raw pin")
        run = _validate_run(run_value, expected)
        host_worker_identities = {
            (worker["role"], worker["cpu"], worker["pid"],
             worker["start_ticks"], worker["pgid"], worker["session_id"])
            for worker in worker_sessions
        }
        run_worker_identities = {
            (worker["role"], worker["cpu"], worker["pid"],
             worker["start_ticks"], worker["pgid"], worker["session_id"])
            for worker in run["worker_cleanup"]
        }
        require(host_worker_identities == run_worker_identities,
                "Source5 Soak supervisor workers differ from raw pressure cleanup rows")
        require(all(observed_ns >= run["finish_monotonic_ns"]
                    for observed_ns in absence_observations.values()),
                "Source5 Soak PID absence observation predates pressure cleanup completion")
        result = verify_pressure(
            recipe_path, recipe_pin["semantic_sha256"], artifact_root, expected,
        )
        proof_value, proof_raw, proof_raw_sha = read_canonical(
            proof_path, "Source5 Soak pressure proof", MAX_PRESSURE_PROOF_BYTES,
        )
        require(result["readback_sha256"] == pressure_readback_sha ==
                proof_value.get("readback_sha256") and
                result == proof_value and proof_raw == canonical_bytes(result) and
                proof_raw_sha == proof_pin_raw and
                supervisor_pressure_proof["proof"] == proof_value and
                result["identity"]["host_id"] == raw_host_receipt["host_id"] and
                result["identity"]["run_id"] == raw_host_receipt["run_id"] and
                result["recipe_raw_sha256"] == recipe_pin["raw_sha256"] and
                result["application_process"]["pid"] == app_process["pid"] and
                result["application_process"]["start_ticks"] == app_process["start_ticks"] and
                result["application_process"]["executable_sha256"] ==
                    app_process["executable_sha256"],
                "Source5 Soak pressure proof differs from full single-APP raw replay")
        calibration = exact(result.get("calibration_scope_v2"), {
            "schema", "replay_success", "validated", "execution_ready",
            "qualification_eligible", "controller_chronology_proven",
            "calibration_raw_sha256", "calibration_sha256", "scope_sha256",
            "condition_id", "pressure_calibration_id", "capacity_key",
            "condition_sha256", "source_manifest_sha256",
            "source_manifest_semantic_sha256", "source_tree_sha256",
            "context_policy_bundle_raw_sha256", "context_policy_artifact_raw_sha256",
            "context_policy_sha256", "capacity_bundle_pins_sha256",
            "capacity_tsv_raw_sha256", "observed_host_raw_sha256",
            "host_verification", "driver_sha256", "reader_sha256",
            "capacity_producer_sha256", "feedback_composer_sha256",
            "feedback_reader_sha256", "sample_count", "samples_sha256",
            "summary", "pressure_thresholds", "readiness_thresholds",
            "suggested_readiness_thresholds", "worker_cleanup_sha256",
            "worker_session_count", "scratch_file_removed", "receipt_sha256",
        }, "Source5 Soak offline pressure calibration replay")
        calibration_host = calibration["host_verification"]
        require(calibration_host["host_id"] == raw_host_receipt["host_id"] and
                calibration_host["boot_id_sha256"] == origin_host["boot_id_sha256"] and
                calibration_host["kernel_release"] == origin_host["kernel_release"] and
                calibration_host["allowed_cpu_affinity"] == origin_host["allowed_cpu_affinity"] and
                calibration_host["network_namespace_inode"] ==
                    origin_host["network_namespace_inode"] and
                calibration_host["observed_host_raw_sha256"] == observed_sha,
                "Source5 Soak pressure calibration host facts differ from the strict Soak host receipt")
        require(calibration["source_manifest_sha256"] == source_raw_sha and
                calibration["source_manifest_semantic_sha256"] ==
                    source_generation["semantic_sha256"] and
                calibration["source_tree_sha256"] ==
                    source_generation["source_tree_sha256"] and
                calibration["condition_id"] == parent_condition["condition_id"],
                "Source5 Soak pressure calibration changed its selected SourceV5 generation")
        capacity_key = _capacity_key_v2(
            calibration["capacity_key"],
            "Source5 Soak pressure calibration capacity key",
        )
        require(capacity_key["host_id"] == raw_host_receipt["host_id"] and
                capacity_key["workload"] == parent_identity["workload"] and
                capacity_key["profile"] == parent_identity["profile"],
                "Source5 Soak pressure capacity key differs from its original APP job")
        return result
    finally:
        if replay_token is not None:
            _PRESSURE_OFFLINE_REPLAY_CONTEXT.reset(replay_token)
        _EVIDENCE_PATH_MAP_CONTEXT.reset(token_value)


def verify_source5_soak_pressure_offline(
    pressure_recipe_pin: object, pressure_artifacts: object,
    soak_host_verification_pin: object, *, evidence_path_map: object,
    source_root: object,
) -> dict[str, Any]:
    """Replay the historical budgetless single-APP Soak host receipt."""
    return _verify_source5_soak_pressure_offline_impl(
        pressure_recipe_pin, pressure_artifacts, soak_host_verification_pin,
        evidence_path_map=evidence_path_map, source_root=source_root,
        bounded_v3=False,
    )


def verify_source5_soak_pressure_offline_v3(
    pressure_recipe_pin: object, pressure_artifacts: object,
    soak_host_verification_pin: object, *, evidence_path_map: object,
    source_root: object,
) -> dict[str, Any]:
    """Replay one bounded Soak APP against its strict host-v3 receipt."""
    return _verify_source5_soak_pressure_offline_impl(
        pressure_recipe_pin, pressure_artifacts, soak_host_verification_pin,
        evidence_path_map=evidence_path_map, source_root=source_root,
        bounded_v3=True,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    verify = command.add_parser("verify", help="independently recompute a bounded pressure run")
    verify.add_argument("--recipe", type=Path, required=True)
    verify.add_argument("--expected-recipe-sha256", required=True)
    verify.add_argument("--artifacts", type=Path, required=True)
    verify.add_argument("--expected-run-sha256", required=True)
    verify.add_argument("--expected-events-sha256", required=True)
    verify.add_argument("--expected-launch-sha256", required=True)
    verify.add_argument("--expected-process-binding-sha256", required=True)
    verify.add_argument("--expected-ready-sha256", required=True)
    scope = command.add_parser("verify-calibration-scope-v2", help="independently replay a SourceV5 context-scoped calibration")
    scope.add_argument("--request", type=Path, required=True)
    scope.add_argument("--calibration", type=Path, required=True)
    scope.add_argument("--expected-calibration-sha256", required=True)
    scope.add_argument("--output", type=Path, required=True)
    return parser


def _write_new_receipt(path: Path, raw: bytes) -> str:
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), "calibration receipt output path must be normalized and absolute")
    try:
        require(path.parent.resolve(strict=True) == path.parent, "calibration receipt output parent is a symlink or alias")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as error:
        raise ReadbackError(f"cannot create new calibration receipt: {error}") from error
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            count = os.write(descriptor, view)
            require(count > 0, "calibration receipt write made no progress")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return sha256_bytes(raw)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify-calibration-scope-v2":
            request, _, _ = read_canonical(args.request, "context calibration request", 4 * 1024 * 1024)
            exact(request, {"schema", "identity", "files", "storage", "schedule", "scope"}, "context calibration request")
            require(request["schema"] == CALIBRATION_REQUEST_SCHEMA_V2, "unsupported context calibration request schema")
            scope = exact(request["scope"], {
                "schema", "condition", "source_root", "source_manifest", "context_policy",
                "capacity_bundle_pins", "observed_host", "capacity_key",
            }, "context calibration request scope")
            require(scope["schema"] == CALIBRATION_SCOPE_SCHEMA_V2, "unsupported context calibration request scope schema")
            request_identity = exact(request["identity"], {"host_id", "run_id", "condition_id", "nonce"}, "context calibration request identity")
            request_files = exact(request["files"], {"source_manifest", "policy", "application_capacity_calibration"}, "context calibration request files")
            request_source = exact(request_files["source_manifest"], {"path", "sha256"}, "context calibration request source manifest")
            request_policy = exact(request_files["policy"], {"path", "sha256"}, "context calibration request policy")
            request_capacity = exact(request_files["application_capacity_calibration"], {"path", "sha256"}, "context calibration request capacity TSV")
            calibration_raw_sha = sha256(args.expected_calibration_sha256, "expected calibration raw SHA-256")
            calibration_value, _, actual_calibration_raw_sha = read_canonical(args.calibration, "context calibration artifact", 64 * 1024 * 1024)
            require(actual_calibration_raw_sha == calibration_raw_sha, "context calibration artifact raw digest differs")
            calibration = _validate_calibration_v2_body(calibration_value)
            calibration_scope = calibration["scope"]
            request_source_pin = {"path": str(absolute_path(request_source["path"], "request source manifest path")), "raw_sha256": sha256(request_source["sha256"], "request source manifest SHA-256")}
            request_policy_pin = {"path": str(absolute_path(request_policy["path"], "request policy path")), "raw_sha256": sha256(request_policy["sha256"], "request policy SHA-256")}
            request_capacity_pin = {"path": str(absolute_path(request_capacity["path"], "request capacity TSV path")), "raw_sha256": sha256(request_capacity["sha256"], "request capacity TSV SHA-256")}
            condition_pin = _raw_pin(scope["condition"], "request Source5 pressure condition")
            source_pin = _raw_pin(scope["source_manifest"], "request Source5 source manifest")
            context_policy_pin = _raw_pin(scope["context_policy"], "request context-policy bundle")
            observed_pin = _raw_pin(scope["observed_host"], "request observed Source5 host")
            require(
                calibration["identity"]["host_id"] == request_identity["host_id"]
                and calibration["identity"]["run_id"] == request_identity["run_id"]
                and calibration["identity"]["condition_id"] == request_identity["condition_id"]
                and calibration["identity"]["nonce"] == request_identity["nonce"]
                and calibration_scope["condition"] == condition_pin
                and calibration_scope["source_manifest"] == source_pin == request_source_pin
                and calibration_scope["context_policy_bundle"] == context_policy_pin
                and calibration_scope["observed_host"] == observed_pin
                and calibration_scope["capacity_key"] == _capacity_key_v2(scope["capacity_key"])
                and calibration_scope["source_root"] == str(absolute_path(scope["source_root"], "request SourceV5 root"))
                and calibration["schedule"] == _validate_calibration_schedule_v2(request["schedule"]),
                "context calibration request identity/scope differs from the measured artifact",
            )
            _, context_bundle, _, _ = _read_raw_pin(context_policy_pin, "request context-policy bundle", MAX_CONTEXT_POLICY_BUNDLE_BYTES)
            exact(context_bundle, {"schema", "artifact", "members"}, "request context-policy bundle")
            require(context_bundle["schema"] == CONTEXT_POLICY_BUNDLE_SCHEMA_V2, "request context-policy bundle schema differs")
            policy_artifact_pin = _raw_pin(context_bundle["artifact"], "request shared numeric policy artifact")
            require(policy_artifact_pin == request_policy_pin, "context calibration request policy differs from its pinned context-policy bundle")
            capacity_bundle = exact(scope["capacity_bundle_pins"], {
                "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
            }, "context calibration request capacity bundle")
            capacity_artifact_pin = _raw_pin(capacity_bundle["artifact"], "request prepared capacity TSV")
            require(capacity_artifact_pin == request_capacity_pin, "context calibration request capacity TSV differs from its producer bundle")
            result = verify_calibration_scope_v2(
                {"path": str(args.calibration), "raw_sha256": calibration_raw_sha},
                scope["context_policy"], scope["capacity_bundle_pins"], scope["observed_host"],
            )
            require(result["condition_sha256"] == condition_pin["raw_sha256"] and result["source_manifest_sha256"] == source_pin["raw_sha256"], "context calibration request condition/source pins differ from the replay receipt")
            raw = canonical_bytes(result)
            receipt_sha = _write_new_receipt(args.output, raw)
            sys.stdout.buffer.write(canonical_bytes({
                "path": str(args.output), "raw_sha256": receipt_sha,
                "scope_sha256": result["scope_sha256"],
                "context_policy_sha256": result["context_policy_sha256"],
                "receipt_sha256": result["receipt_sha256"],
            }))
            return 0
        expected_recipe = sha256(args.expected_recipe_sha256, "expected recipe SHA-256")
        expected = {
            "recipe": expected_recipe,
            "run": sha256(args.expected_run_sha256, "expected run SHA-256"),
            "events": sha256(args.expected_events_sha256, "expected event SHA-256"),
            "launch": sha256(args.expected_launch_sha256, "expected launch SHA-256"),
            "process_binding": sha256(args.expected_process_binding_sha256, "expected process binding SHA-256"),
            "ready": sha256(args.expected_ready_sha256, "expected readiness marker SHA-256"),
        }
        result = verify_pressure(args.recipe, expected_recipe, args.artifacts, expected)
    except (ReadbackError, OSError, ValueError) as error:
        print(f"application-pressure-readback: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
