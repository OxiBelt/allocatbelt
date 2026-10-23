#!/usr/bin/env python3
"""Compose prelaunch calibrated feedback policy and post-Popen expectations.

This module consumes source-pinned SourceV5, application-byte capacity, and
construction-probe inputs. It resolves policy numerics without launching a
workload and always emits ineligible preparation receipts. A separate
finalization step requires the caller's actual positive application PID.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import stat
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any, Callable


REQUEST_SCHEMA = "allocatbelt.application-feedback-composition-request.v1"
REQUEST_SCHEMA_V2 = "allocatbelt.application-feedback-composition-request.v2"
INITIAL_PROBE_REQUEST_SCHEMA = "allocatbelt.application-feedback-initial-probe-request.v1"
INITIAL_PROBE_EMISSION_SCHEMA = "allocatbelt.application-feedback-initial-probe-emission.v1"
INITIAL_PROBE_EMISSION_ROLE = "initial_calibrated_constructor_only"
POLICY_SCHEMA = "allocatbelt.application-feedback-resolved-policy.v1"
POLICY_SCHEMA_V2 = "allocatbelt.application-feedback-resolved-policy.v2"
RECEIPT_SCHEMA = "allocatbelt.application-feedback-composition-receipt.v1"
RECEIPT_SCHEMA_V2 = "allocatbelt.application-feedback-composition-receipt.v2"
CAPACITY_FLOOR_POLICY_ID = "application_capacity_relative_tenth_v1"
FINALIZE_SCHEMA = "allocatbelt.application-feedback-expectation-finalization.v1"
FINALIZE_RECEIPT_SCHEMA = "allocatbelt.application-feedback-expectation-finalization-receipt.v1"
EXPECTATION_SCHEMA_V5 = "allocatbelt.application-feedback-expectation.v5"
EXPECTATION_SCHEMA_V6 = "allocatbelt.application-feedback-expectation.v6"
SOURCE_SCHEMA_V5 = "allocatbelt.application-source-manifest.v5"
FEEDBACK_OFFLINE_CONTEXT_SCHEMA = "allocatbelt.application-feedback-offline-replay-context.v1"
EVIDENCE_PATH_MAP_SCHEMA = "allocatbelt.application-pressure-evidence-path-map.v1"
MAX_OFFLINE_PATH_MAP_ENTRIES = 16_384
CAPACITY_REQUEST_SCHEMA = "allocatbelt.application-byte-capacity-request.v1"
CAPACITY_RECEIPT_SCHEMA = "allocatbelt.application-byte-capacity-receipt.v1"
CAPACITY_TRACE_FILES = (
    "feedback-trace-manifest.tsv", "feedback-events.jsonl", "resource-samples.tsv",
)
FEEDBACK_CAPTURED_OFFLINE_CONTEXT_SCHEMA = "allocatbelt.application-feedback-captured-offline-replay-context.v1"
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_PROBE_BYTES = 512 * 1024
MAX_SMALL_ARTIFACT_BYTES = 4096
SOURCE_ROOT = Path(__file__).resolve().parent.parent
FEEDBACK_READER = "scripts/application-feedback-readback.py"
CAPACITY_PRODUCER = "scripts/application-byte-capacity.py"
FIXED_PAIR_OWNER = "scripts/application-fixed-pair.py"
PROBE_OWNER_HELPER = "scripts/application-soak-readback.py"
PROBE_CAPTURE_RECEIPT_SCHEMA = "allocatbelt.application-feedback-probe-capture.v2"
PROBE_CAPTURE_START_ROLE_SCHEMA = "allocatbelt.application-feedback-probe-start-role.v1"
PROBE_CAPTURE_START_ROLE = "calibrated_construction_probe"
PROBE_OWNER_RESULT_SCHEMA = "allocatbelt.application-feedback-probe-owner-result.v1"
PROBE_TMPDIR_INVENTORY_SCHEMA = "allocatbelt.application-feedback-probe-tmpdir-inventory.v1"
PROBE_CAPTURE_FAILURE_SCHEMA = "allocatbelt.application-feedback-probe-capture-failure.v1"
INITIAL_PROBE_EMISSION_RECEIPT_FIELDS = {
    "schema", "role", "verification_scope", "request_pin", "source_manifest", "context", "allocator",
    "capacity_bundle", "capacity_floor_policy_id", "binary", "observed_host",
    "origin_facts_before", "origin_facts_after", "requested_launch", "start_callback_count",
    "start_callback_proof", "owner_result_pin", "owner_supervision_sha256",
    "stdout", "stderr", "construction_probe", "resolved_policy_sha256",
    "timeout_ns", "storage_budget", "output_mount_initial", "output_mount_final",
    "tmpdir_initial", "tmpdir_final", "tmpdir_inventory_pin", "owner_modules",
    "exit_status", "qualification_eligible", "execution_ready",
    "controller_chronology_proven", "receipt_sha256",
}
MAX_PROBE_OWNER_RESULT_BYTES = 16 * 1024 * 1024
MAX_PROBE_TMPDIR_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_PROBE_CAPTURE_FAILURE_BYTES = 64 * 1024
MAX_PROBE_CAPTURE_RECEIPT_BYTES = MAX_METADATA_BYTES
PROBE_CAPTURE_RECEIPT_FIELDS = {
    "schema", "source_manifest", "capacity_bundle", "capacity_tsv", "probe_pin", "binary",
    "observed_host", "origin_facts", "probe_argv", "environment", "cwd", "affinity", "netns",
    "capture_timeout_ns", "start_callback_count", "start_callback_proof",
    "start", "owner_result_pin", "tmpdir_inventory_pin", "stdout", "stderr", "exit_status",
    "output_matches_probe", "stderr_empty", "storage_budget", "output_mount",
    "tmpdir_initial", "tmpdir_final",
    "owner_modules", "qualification_eligible", "execution_ready", "controller_chronology_proven",
    "receipt_sha256",
}
MAX_PROBE_CAPTURE_TIMEOUT_NS = 30_000_000_000
MAX_PROBE_STDERR_BYTES = 64 * 1024


class CompositionError(ValueError):
    """A pinned SourceV5 composition input fails its exact contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CompositionError(message)


def canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise CompositionError(f"value is not canonical JSON: {error}") from error


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value: object, label: str = "SHA-256") -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, f"{label} is malformed")
    return value


def _bounded_text(value: object, label: str, maximum: int) -> str:
    require(type(value) is str and 0 < len(value) <= maximum and
            not any(ord(character) < 32 or ord(character) == 127
                    for character in value),
            f"{label} must be bounded text without control characters")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected key set")
    return value


def uint(value: object, label: str, *, positive: bool = False, maximum: int = (1 << 64) - 1) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} must be an unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def absolute_path(value: object, label: str) -> Path:
    require(type(value) is str and 0 < len(value) <= 4096, f"{label} must be a bounded absolute path")
    path = Path(value)
    require(path.is_absolute() and str(path) == value and ".." not in PurePosixPath(value).parts, f"{label} must be normalized and absolute")
    return path


def _path_is_within(root: Path, candidate: Path, label: str) -> bool:
    root_path = absolute_path(str(root), f"{label} root")
    candidate_path = absolute_path(str(candidate), f"{label} candidate")
    try:
        resolved_root = root_path.resolve(strict=True)
        resolved_candidate = candidate_path.resolve(strict=True)
    except OSError as error:
        raise CompositionError(f"cannot resolve closed {label} paths: {error}") from error
    require(resolved_root == root_path and resolved_candidate == candidate_path,
            f"{label} root/candidate traverses an alias")
    try:
        resolved_candidate.relative_to(resolved_root)
        return True
    except ValueError:
        return False


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_stable(
    path: Path, label: str, maximum: int, *, artifact_view: Any = None,
) -> tuple[bytes, str]:
    if artifact_view is not None:
        require(artifact_view.has_file(path),
                f"{label} is absent from the exact captured refs")
        raw, actual = artifact_view.read(path, label, maximum)
        require(type(raw) is bytes and len(raw) <= maximum and
                sha256(raw) == actual,
                f"{label} captured bytes differ from their bounded raw pin")
        return raw, actual
    try:
        require(path.resolve(strict=True) == path, f"{label} traverses a symlink or alias")
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise CompositionError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(fd)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and key(before) == key(before_path), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its byte bound")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - len(raw)))
            require(block, f"{label} was truncated while reading")
            raw.extend(block)
        after_fd, after_path = os.fstat(fd), path.lstat()
        require(key(before) == key(after_fd) == key(after_path), f"{label} changed during read")
        return bytes(raw), sha256(raw)
    finally:
        os.close(fd)


def _capture_tmpdir_inventory(path: Path, byte_limit: int, inode_limit: int) -> list[dict[str, Any]]:
    """Bind every private TMPDIR descendant without retaining file contents in memory."""
    root = absolute_path(str(path), "captured probe TMPDIR inventory root")
    require(root.resolve(strict=True) == root, "captured probe TMPDIR inventory root traverses an alias")
    root_info = root.lstat()
    require(stat.S_ISDIR(root_info.st_mode) and not stat.S_ISLNK(root_info.st_mode) and
            root_info.st_uid == os.getuid() and stat.S_IMODE(root_info.st_mode) == 0o700,
            "captured probe TMPDIR inventory root is not a private owned directory")
    pending = [root]
    inventory: list[dict[str, Any]] = []
    total_bytes = 0
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                children: list[Path] = []
                for entry in entries:
                    require(len(inventory) + len(children) < inode_limit,
                            "captured probe TMPDIR exceeds its finite inode bound")
                    children.append(Path(entry.path))
                children.sort(key=str)
        except OSError as error:
            raise CompositionError(f"cannot enumerate captured probe TMPDIR {current}: {error}") from error
        for child in children:
            require(child.resolve(strict=True) == child,
                    "captured probe TMPDIR descendant traverses a symlink or alias")
            info = child.lstat()
            require(info.st_uid == os.getuid() and
                    (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) and
                    not stat.S_ISLNK(info.st_mode),
                    "captured probe TMPDIR contains an unowned, linked, or special file")
            if stat.S_ISDIR(info.st_mode):
                item = {
                    "path": str(child), "kind": "directory", "uid": info.st_uid,
                    "mode": stat.S_IMODE(info.st_mode), "size": None, "raw_sha256": None,
                }
                pending.append(child)
            else:
                before_key = (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                              info.st_mtime_ns, info.st_ctime_ns)
                try:
                    descriptor = os.open(
                        child, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                        getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                    )
                except OSError as error:
                    raise CompositionError(f"cannot open captured probe TMPDIR file {child}: {error}") from error
                try:
                    opened = os.fstat(descriptor)
                    key = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                         value.st_mtime_ns, value.st_ctime_ns)
                    require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.getuid() and
                            key(opened) == before_key and 0 <= opened.st_size <= byte_limit,
                            "captured probe TMPDIR file changed or exceeds its bound")
                    file_hash = hashlib.sha256()
                    remaining = opened.st_size
                    while remaining:
                        block = os.read(descriptor, min(1024 * 1024, remaining))
                        require(block, "captured probe TMPDIR file was truncated while hashing")
                        file_hash.update(block)
                        remaining -= len(block)
                    after_fd, after_path = os.fstat(descriptor), child.lstat()
                    require(key(opened) == key(after_fd) == key(after_path),
                            "captured probe TMPDIR file changed while hashing")
                finally:
                    os.close(descriptor)
                total_bytes += info.st_size
                item = {
                    "path": str(child), "kind": "file", "uid": info.st_uid,
                    "mode": stat.S_IMODE(info.st_mode), "size": info.st_size,
                    "raw_sha256": file_hash.hexdigest(),
                }
            inventory.append(item)
            require(len(inventory) <= inode_limit and total_bytes <= byte_limit,
                    "captured probe TMPDIR inventory exceeds its prospective byte or inode bound")
    inventory.sort(key=lambda value: value["path"])
    require(len(canonical(inventory)) <= MAX_PROBE_TMPDIR_INVENTORY_BYTES,
            "captured probe TMPDIR inventory exceeds its finite receipt bound")
    return inventory


def _probe_owner_result(direct: object, started: list[dict[str, Any]]) -> tuple[dict[str, Any], bytes]:
    body = {
        "schema": PROBE_OWNER_RESULT_SCHEMA,
        "direct": direct,
        "start_callback_count": len(started),
        "start_callback_proofs": started,
    }
    result = {**body, "owner_result_sha256": sha256(canonical(body))}
    return result, canonical(result)


def _seal_probe_capture_receipt(body: object) -> tuple[dict[str, Any], bytes]:
    """Seal the exact receipt body, excluding its self-digest field."""
    receipt_body = exact(
        body, PROBE_CAPTURE_RECEIPT_FIELDS - {"receipt_sha256"},
        "ProbeV2 capture receipt body",
    )
    receipt_sha = sha256(canonical(receipt_body))
    receipt = {**receipt_body, "receipt_sha256": receipt_sha}
    return receipt, canonical(receipt)


def _capture_failure_record(
    capture_dir: Path, capture_id: str, stage: str, error: BaseException,
    owner_result_pin: dict[str, str] | None, stdout_path: Path, stderr_path: Path,
    budget: dict[str, int], *, inventory_pin: dict[str, str] | None = None,
    owner_result_overflow: dict[str, Any] | None = None,
) -> Path:
    def output_pin(path: Path, maximum: int) -> dict[str, str | None] | None:
        try:
            _raw, raw_sha = _read_stable(path, "failed probe capture output", maximum)
        except Exception:
            return None
        return {"path": str(path), "raw_sha256": raw_sha}

    body = {
        "schema": PROBE_CAPTURE_FAILURE_SCHEMA,
        "capture_id": capture_id,
        "stage": stage,
        "error_type": type(error).__name__[:128],
        "error_message": str(error)[:4096],
        "owner_result_pin": owner_result_pin,
        "owner_result_overflow": owner_result_overflow,
        "tmpdir_inventory_pin": inventory_pin,
        "stdout": output_pin(stdout_path, budget["stdout_bytes"]),
        "stderr": output_pin(stderr_path, budget["stderr_bytes"]),
        "qualification_eligible": False,
        "execution_ready": False,
        "controller_chronology_proven": False,
    }
    value = {**body, "failure_sha256": sha256(canonical(body))}
    raw = canonical(value)
    require(len(raw) <= budget["failure_bytes"],
            "bounded failed ProbeV2 capture record exceeds its reserved byte budget")
    path = capture_dir / "capture-failure.json"
    _write_exclusive(path, raw)
    return path


def _read_canonical(
    path: Path, label: str, expected_sha: object,
    maximum: int = MAX_METADATA_BYTES, *, artifact_view: Any = None,
) -> tuple[dict[str, Any], bytes, str]:
    expected = digest(expected_sha, f"{label} raw SHA-256")
    raw, actual = _read_stable(
        path, label, maximum, artifact_view=artifact_view,
    )
    require(actual == expected, f"{label} raw SHA-256 differs from its pin")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=lambda item: (_ for _ in ()).throw(CompositionError(f"non-finite JSON number: {item}")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CompositionError(f"{label} is not bounded JSON: {error}") from error
    require(type(value) is dict and canonical(value) == raw, f"{label} is not canonical JSON")
    return value, raw, actual


def _record(source: dict[str, Any], relative: str, label: str) -> dict[str, Any]:
    records = source.get("source", {}).get("files")
    require(type(records) is list, "SourceV5 typed inventory is missing")
    matches = [item for item in records if type(item) is dict and item.get("path") == relative]
    require(len(matches) == 1, f"SourceV5 inventory must contain one {label} record")
    record = exact(matches[0], {"path", "kind", "mode", "sha256", "size"}, f"SourceV5 {label} inventory entry")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755"), f"SourceV5 {label} is not a canonical regular-file entry")
    digest(record["sha256"], f"SourceV5 {label} SHA-256")
    uint(record["size"], f"SourceV5 {label} size")
    return record


def _exec_registered_module(module: types.ModuleType, raw: bytes, path: Path) -> None:
    """Execute exact pinned bytes with normal import-time module semantics."""
    module_name = module.__name__
    previous_module = sys.modules.get(module_name)
    had_previous_module = module_name in sys.modules
    sys.modules[module_name] = module
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        if had_previous_module:
            sys.modules[module_name] = previous_module
        else:
            sys.modules.pop(module_name, None)
        raise


def _pinned_source_module(source: dict[str, Any], key: str, relative: str, label: str, maximum: int) -> types.ModuleType:
    harness = source.get("qualification_harness")
    require(type(harness) is dict and key in harness, f"SourceV5 harness omits {label}")
    pin = exact(harness[key], {"path", "sha256"}, f"SourceV5 {label} pin")
    record = _record(source, relative, label)
    require(pin == {"path": relative, "sha256": record["sha256"]}, f"SourceV5 {label} harness pin differs from its regular inventory entry")
    path = SOURCE_ROOT.joinpath(*PurePosixPath(relative).parts)
    raw, actual = _read_stable(path, f"pinned {label}", maximum)
    info = path.stat(follow_symlinks=False)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual == record["sha256"] and len(raw) == record["size"] and mode == record["mode"], f"installed {label} differs from SourceV5 inventory bytes")
    module = types.ModuleType(f"source5_{key}_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        _exec_registered_module(module, raw, path)
    except (SyntaxError, ValueError, TypeError) as error:
        raise CompositionError(f"pinned {label} cannot be compiled: {error}") from error
    return module


def _load_source_context_inputs(
    request: dict[str, Any], allocator: object,
) -> tuple[Any, Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_pin = exact(request["source_manifest"], {"path", "raw_sha256"}, "SourceV5 manifest pin")
    source_path = absolute_path(source_pin["path"], "SourceV5 manifest path")
    source, _source_raw, _source_raw_sha = _read_canonical(
        source_path, "SourceV5 manifest", source_pin["raw_sha256"],
    )
    require(source.get("schema") == SOURCE_SCHEMA_V5, "composition requires a SourceV5 manifest")
    source_root = absolute_path(request["source_root"], "SourceV5 source root")
    require(source_root == SOURCE_ROOT, "composition source root must be the root containing its pinned harness siblings")
    context = exact(request["context"], {"host_id", "workload", "profile", "calibration_id"}, "composition context")
    require(all(type(context[key]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", context[key]) for key in context), "composition context has an invalid token")
    reader = _pinned_source_module(source, "feedback_validator", FEEDBACK_READER, "feedback validator", MAX_METADATA_BYTES)
    require(type(allocator) is str and allocator in reader.APPLICATION_ALLOCATOR_LABELS,
            "SourceV5 selected allocator is outside the original application artifact set")
    artifact = exact(source.get("artifacts", {}).get(allocator), {"path", "sha256"},
                     "SourceV5 selected application artifact")
    binary_sha = digest(artifact["sha256"], "SourceV5 selected application artifact SHA-256")
    identity = {
        "host_id": context["host_id"], "workload": context["workload"], "profile": context["profile"],
        "allocator": allocator, "source_sha256": source["source"]["source_tree_sha256"],
        "binary_sha256": binary_sha,
    }
    require(source["build"]["host_id"] == context["host_id"], "composition host differs from SourceV5 build host")
    minimal = {"schema": EXPECTATION_SCHEMA_V5, "mode": "pressure_validation", "identity": identity}
    try:
        reader._verify_source_manifest_v5(source, minimal)
    except Exception as error:
        raise CompositionError(f"pinned SourceV5 full verifier rejected the source: {error}") from error
    producer = _pinned_source_module(source, "byte_capacity_producer", CAPACITY_PRODUCER, "byte-capacity producer", MAX_METADATA_BYTES)
    return reader, producer, source, context, identity


def _load_verified_inputs(request: dict[str, Any]) -> tuple[Any, Any, dict[str, Any], dict[str, Any], dict[str, Any]]:
    probe_pin = exact(request["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, "construction probe pin")
    reader, producer, source, context, identity = _load_source_context_inputs(
        request, probe_pin["allocator"],
    )
    require(digest(probe_pin["binary_sha256"], "construction probe binary SHA-256") ==
            identity["binary_sha256"],
            "construction probe binary differs from its SourceV5 application artifact")
    return reader, producer, source, context, identity


def _verify_capacity_request_binding(
    reader: Any, producer: Any, source: dict[str, Any], context: dict[str, Any], identity: dict[str, Any],
    source_pin: dict[str, Any], bundle: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    request_pin = exact(bundle["request"], {"path", "raw_sha256"}, "capacity request pin")
    artifact_pin = exact(bundle["artifact"], {"path", "raw_sha256"}, "capacity artifact pin")
    receipt_pin = exact(bundle["receipt"], {"path", "raw_sha256"}, "capacity receipt pin")
    request_path = absolute_path(request_pin["path"], "capacity request path")
    request, request_raw, request_sha = _read_canonical(request_path, "capacity request", request_pin["raw_sha256"])
    require(request.get("schema") == "allocatbelt.application-byte-capacity-request.v1", "unsupported capacity request schema")
    request_identity = exact(request.get("identity"), {
        "host_id", "run_id", "report_nonce", "process_id", "allocator", "executor", "workload", "profile",
        "mode", "source_sha256", "binary_sha256", "pressure_qualification",
    }, "capacity request identity")
    require(request_identity["host_id"] == context["host_id"] and request_identity["workload"] == context["workload"] and request_identity["profile"] == context["profile"], "capacity request context differs from the selected SourceV5 cell")
    require(request_identity["source_sha256"] == identity["source_sha256"] and request_identity["allocator"] in reader.APPLICATION_ALLOCATOR_LABELS, "capacity request source or allocator differs from SourceV5")
    calibrator_artifact = exact(source["artifacts"].get(request_identity["allocator"]), {"path", "sha256"}, "SourceV5 capacity calibrator artifact")
    require(request_identity["binary_sha256"] == calibrator_artifact["sha256"], "capacity request binary differs from its SourceV5 calibrator artifact")
    require(request_identity["executor"] in reader.V5_EXECUTOR_LABELS, "capacity request executor is outside the original native/Tokio role set")
    require(request_identity["mode"] == "capacity" and request_identity["pressure_qualification"] is False, "capacity request is not an ineligible calibration run")
    uint(request_identity["process_id"], "capacity request process ID", positive=True, maximum=(1 << 31) - 1)
    require(request.get("calibration_id") == context["calibration_id"], "capacity request calibration ID differs from the composition context")
    embedded_source_pin = exact(request.get("source_manifest"), {"path", "sha256"}, "capacity request SourceV5 manifest pin")
    require(embedded_source_pin == {"path": source_pin["path"], "sha256": source_pin["raw_sha256"]}, "capacity request does not pin the exact SourceV5 manifest bytes")
    expectation_pin = exact(request.get("expectation"), {"path", "sha256"}, "capacity expectation pin")
    expectation_path = absolute_path(expectation_pin["path"], "capacity expectation path")
    capacity_expectation, _expectation_raw, _ = _read_canonical(expectation_path, "capacity expectation", expectation_pin["sha256"])
    require(capacity_expectation.get("schema") == "allocatbelt.application-feedback-expectation.v4" and capacity_expectation.get("mode") == "capacity_calibration", "capacity request does not carry the SourceV5 V4 calibration expectation")
    require(capacity_expectation.get("identity") == request_identity, "capacity expectation identity differs from its producer request")
    capacity_host_pin = exact(capacity_expectation.get("host_binding"), {"path", "raw_sha256"}, "capacity expectation SourceV5 host binding")
    require(capacity_host_pin["path"] == embedded_source_pin["path"], "capacity expectation path differs from its SourceV5 request pin")
    require(digest(capacity_host_pin["raw_sha256"], "capacity expectation SourceV5 raw SHA-256") == digest(embedded_source_pin["sha256"], "capacity request SourceV5 SHA-256"), "capacity expectation does not pin the exact SourceV5 manifest bytes")
    artifact_sha = digest(artifact_pin["raw_sha256"], "capacity artifact raw SHA-256")
    producer_pin = {"path": request_pin["path"], "sha256": request_sha}
    producer_artifact_pin = {"path": artifact_pin["path"], "sha256": artifact_sha}
    producer_receipt_pin = {"path": receipt_pin["path"], "sha256": digest(receipt_pin["raw_sha256"], "capacity receipt raw SHA-256")}
    try:
        require(producer.verify_capacity_bundle(producer_pin, producer_artifact_pin, producer_receipt_pin) is True,
                "pinned byte-capacity producer did not accept its complete evidence bundle")
    except Exception as error:
        raise CompositionError(f"pinned byte-capacity producer bundle replay failed: {error}") from error
    receipt_path = absolute_path(receipt_pin["path"], "capacity receipt path")
    capacity_receipt, _receipt_raw, receipt_sha = _read_canonical(receipt_path, "capacity receipt", producer_receipt_pin["sha256"])
    require(capacity_receipt.get("schema") == CAPACITY_RECEIPT_SCHEMA and capacity_receipt.get("qualification_eligible") is False, "capacity receipt schema or eligibility is invalid")
    require(capacity_receipt.get("identity") == request_identity and capacity_receipt.get("calibration_id") == context["calibration_id"], "capacity receipt identity/calibration differs from the producer request")
    require(capacity_receipt.get("source_manifest_raw_sha256") == source_pin["raw_sha256"], "capacity receipt SourceV5 manifest digest differs")
    require(capacity_receipt.get("capacity_artifact_raw_sha256") == artifact_sha, "capacity receipt artifact digest differs")
    return request, capacity_receipt, {
        "request": request_sha, "artifact": artifact_sha, "receipt": receipt_sha,
    }


def _source_policy_context(source: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    feedback = exact(source.get("feedback_policy"), {"schema", "policy", "policy_sha256"}, "SourceV5 feedback policy artifact")
    body_keys = {"schema", "version", "reader_contract", "algorithm", "contexts", "source_pins"}
    if feedback["schema"] == "allocatbelt.application-feedback-policy-artifact.v2":
        body_keys.add("capacity_floor_policy")
    require(feedback["schema"] in (
        "allocatbelt.application-feedback-policy-artifact.v1",
        "allocatbelt.application-feedback-policy-artifact.v2",
    ), "unsupported SourceV5 feedback policy artifact schema")
    feedback_body = exact(feedback["policy"], body_keys, "SourceV5 feedback policy body")
    context_key = f"{context['workload']}/{context['profile']}"
    contexts = feedback_body["contexts"]
    require(type(contexts) is dict and context_key in contexts, "SourceV5 feedback policy omits the selected context")
    value = exact(contexts[context_key], {"workers", "minimum_dense_observations", "controls"}, "SourceV5 feedback policy context")
    return copy.deepcopy(value)


def _make_policy_document(
    request: dict[str, Any], request_raw_sha: str, reader: Any, source: dict[str, Any], context: dict[str, Any],
    identity: dict[str, Any], probe_pin: dict[str, Any], bundle: dict[str, Any],
    replay_context: dict[str, Any] | None = None, *, closed_recorded: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    probe_path = absolute_path(probe_pin["path"], "construction probe path")
    view = None
    if replay_context is not None:
        view = _offline_view_for_path(_offline_context(replay_context), probe_path)
    probe, _probe_raw, probe_sha = _read_canonical(
        probe_path, "calibrated construction probe", probe_pin["raw_sha256"],
        MAX_PROBE_BYTES, artifact_view=view,
    )
    artifact_pin = {"path": bundle["artifact"]["path"], "raw_sha256": bundle["artifact"]["raw_sha256"]}
    capacity_floor_policy_id = request.get("capacity_floor_policy_id")
    if capacity_floor_policy_id is not None:
        require(capacity_floor_policy_id == CAPACITY_FLOOR_POLICY_ID,
                "composition floor policy ID is unknown")
        source_floor_policy = reader._validate_capacity_floor_policy_descriptor(
            source["feedback_policy"]["policy"].get("capacity_floor_policy"),
        )
        require(source_floor_policy["policy_id"] == capacity_floor_policy_id,
                "composition floor policy ID differs from the pinned SourceV5 rule")
    try:
        if replay_context is None:
            observed_probe_sha = reader.validate_calibrated_construction_probe_v2(
                probe_pin, source, artifact_pin, identity,
                capacity_floor_policy_id=capacity_floor_policy_id,
            )
        elif closed_recorded:
            observed_probe_sha = reader.validate_calibrated_construction_probe_v2_closed_recorded_v1(
                probe_pin, request["source_manifest"], artifact_pin, identity,
                replay_context=replay_context,
                capacity_floor_policy_id=capacity_floor_policy_id,
            )
        else:
            observed_probe_sha = reader.validate_calibrated_construction_probe_v2_offline(
                probe_pin, request["source_manifest"], artifact_pin, identity,
                replay_context=replay_context,
                capacity_floor_policy_id=capacity_floor_policy_id,
            )
        require(observed_probe_sha == probe_sha, "captured feedback reader returned a different construction probe digest")
        policy = reader.resolve_calibrated_feedback_policy_v5(
            source, probe, artifact_pin, identity,
            capacity_floor_policy_id=capacity_floor_policy_id,
        )
    except Exception as error:
        raise CompositionError(f"captured calibrated feedback validator rejected the probe: {error}") from error
    feedback_artifact = source["feedback_policy"]
    static_context = _source_policy_context(source, context)
    if capacity_floor_policy_id is not None:
        static_context["capacity_floor_policy"] = source_floor_policy
        static_context["capacity_floor_policy_id"] = capacity_floor_policy_id
    static_policy, _algorithm, _workers = reader._static_policy_from_source_v5(
        source, identity, probe["collector"], probe["rust_control_context"]["algorithm"],
    )
    for direction in ("disk", "upload", "download"):
        static_policy["rate_buckets"][direction] = {
            "initial_bytes_per_second": static_policy["rate_buckets"][direction]["ceiling_bytes_per_second"],
            **static_policy["rate_buckets"][direction],
        }
    source_raw_sha = digest(request["source_manifest"]["raw_sha256"], "SourceV5 manifest raw SHA-256")
    semantic_sha = digest(source["manifest_sha256"], "SourceV5 semantic manifest SHA-256")
    source_tree_sha = digest(source["source"]["source_tree_sha256"], "SourceV5 source tree SHA-256")
    build_sha = reader.digest_object(source["build"])
    app_sha = digest(probe_pin["binary_sha256"], "SourceV5 APP artifact SHA-256")
    capacity_sha = digest(bundle["artifact"]["raw_sha256"], "capacity artifact SHA-256")
    base_policy_sha = reader.digest_object(static_policy)
    base_context_sha = reader.digest_object(static_context)
    policy_schema = POLICY_SCHEMA_V2 if capacity_floor_policy_id is not None else POLICY_SCHEMA
    receipt_schema = RECEIPT_SCHEMA_V2 if capacity_floor_policy_id is not None else RECEIPT_SCHEMA
    policy_context = {**context, "allocator": identity["allocator"]}
    if capacity_floor_policy_id is not None:
        policy_context["capacity_floor_policy_id"] = capacity_floor_policy_id
    policy_body = {
        "schema": policy_schema,
        "context": policy_context,
        "policy": policy,
        "source_manifest_raw_sha256": source_raw_sha,
        "source_manifest_sha256": semantic_sha,
        "source_tree_sha256": source_tree_sha,
        "build_sha256": build_sha,
        "app_binary_sha256": app_sha,
        "probe_raw_sha256": probe_sha,
        "capacity_request_raw_sha256": digest(request.get("capacity_bundle", {}).get("request", {}).get("raw_sha256"), "capacity request raw SHA-256"),
        "capacity_artifact_raw_sha256": capacity_sha,
        "capacity_receipt_raw_sha256": digest(request.get("capacity_bundle", {}).get("receipt", {}).get("raw_sha256"), "capacity receipt raw SHA-256"),
        "base_policy_artifact_sha256": digest(feedback_artifact["policy_sha256"], "SourceV5 feedback policy artifact SHA-256"),
        "base_policy_sha256": base_policy_sha,
        "base_context_sha256": base_context_sha,
        "resolution_rule_version": (
            reader.CAPACITY_RESOLUTION_VERSION
            if capacity_floor_policy_id is not None
            else reader.CAPACITY_RESOLUTION_STATIC_VERSION
        ),
    }
    if capacity_floor_policy_id is not None:
        policy_body["capacity_floor_policy_id"] = capacity_floor_policy_id
    policy_body["policy_sha256"] = reader.digest_object(policy_body)
    policy_raw = canonical(policy_body)
    receipt_body = {
        "schema": receipt_schema,
        "validated": True,
        "execution_ready": False,
        "qualification_eligible": False,
        "controller_chronology_proven": False,
        "request_raw_sha256": request_raw_sha,
        "source_manifest_raw_sha256": source_raw_sha,
        "source_manifest_sha256": semantic_sha,
        "source_tree_sha256": source_tree_sha,
        "build_sha256": build_sha,
        "app_binary_sha256": app_sha,
        "probe_raw_sha256": probe_sha,
        "capacity_request_raw_sha256": policy_body["capacity_request_raw_sha256"],
        "capacity_artifact_raw_sha256": capacity_sha,
        "capacity_receipt_raw_sha256": policy_body["capacity_receipt_raw_sha256"],
        "base_policy_artifact_sha256": policy_body["base_policy_artifact_sha256"],
        "base_policy_sha256": base_policy_sha,
        "base_context_sha256": base_context_sha,
        "resolved_policy_raw_sha256": sha256(policy_raw),
        "resolved_policy_sha256": policy_body["policy_sha256"],
        "resolution_rule_version": (
            reader.CAPACITY_RESOLUTION_VERSION
            if capacity_floor_policy_id is not None
            else reader.CAPACITY_RESOLUTION_STATIC_VERSION
        ),
        "validator_sha256": _self_sha256(),
        "context": policy_body["context"],
    }
    if capacity_floor_policy_id is not None:
        receipt_body["capacity_floor_policy_id"] = capacity_floor_policy_id
    receipt_body["receipt_sha256"] = sha256(canonical(receipt_body))
    return policy_body, receipt_body


def _validate_resolve_request(value: object) -> dict[str, Any]:
    require(type(value) is dict, "feedback composition request must be an object")
    schema = value.get("schema")
    base_keys = {"schema", "source_root", "source_manifest", "context", "construction_probe", "capacity_bundle"}
    if schema == REQUEST_SCHEMA:
        request = exact(value, base_keys, "feedback composition request")
        require(request.get("capacity_floor_policy_id") is None,
                "legacy composition requests cannot opt into a capacity floor policy")
    elif schema == REQUEST_SCHEMA_V2:
        request = exact(value, base_keys | {"capacity_floor_policy_id"}, "feedback composition request v2")
        require(request["capacity_floor_policy_id"] == CAPACITY_FLOOR_POLICY_ID,
                "composition request capacity floor policy ID is unknown")
    else:
        raise CompositionError("unsupported feedback composition request schema")
    absolute_path(request["source_root"], "SourceV5 source root")
    source = exact(request["source_manifest"], {"path", "raw_sha256"}, "SourceV5 manifest pin")
    absolute_path(source["path"], "SourceV5 manifest path")
    digest(source["raw_sha256"], "SourceV5 manifest raw SHA-256")
    context = exact(request["context"], {"host_id", "workload", "profile", "calibration_id"}, "composition context")
    for key in context:
        require(type(context[key]) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", context[key]) is not None, f"composition context {key} is malformed")
    probe = exact(request["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, "construction probe pin")
    absolute_path(probe["path"], "construction probe path")
    digest(probe["raw_sha256"], "construction probe raw SHA-256")
    digest(probe["binary_sha256"], "construction probe binary SHA-256")
    require(probe["allocator"] in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"), "composition allocator is outside the original application artifact set")
    bundle = exact(request["capacity_bundle"], {"request", "artifact", "receipt"}, "complete capacity producer bundle")
    for name in bundle:
        pin = exact(bundle[name], {"path", "raw_sha256"}, f"capacity bundle {name} pin")
        absolute_path(pin["path"], f"capacity bundle {name} path")
        digest(pin["raw_sha256"], f"capacity bundle {name} raw SHA-256")
    require(len({bundle[name]["path"] for name in bundle}) == 3, "capacity request, artifact, and receipt paths must be distinct")
    return request


def _self_sha256() -> str:
    raw, actual = _read_stable(Path(__file__).resolve(), "feedback composition validator", MAX_METADATA_BYTES)
    require(len(raw) <= MAX_METADATA_BYTES, "feedback composition validator exceeds its bound")
    return actual


def _offline_context(value: object) -> dict[str, Any]:
    if type(value) is dict and value.get("schema") == \
            FEEDBACK_CAPTURED_OFFLINE_CONTEXT_SCHEMA:
        context = exact(value, {
            "schema", "artifact_view", "captured_origin_paths",
            "evidence_file_paths", "evidence_directory_paths",
            "source_symlink_paths", "tree_inventories",
            "probe_capture_pin", "capacity_bundle",
        }, "captured feedback offline replay context")
        view = context["artifact_view"]
        require(callable(getattr(view, "has_file", None)) and
                callable(getattr(view, "read", None)) and
                callable(getattr(view, "open_snapshot", None)),
                "captured feedback context has no exact artifact reader")

        def normalized_set(raw: object, label: str) -> frozenset[str]:
            require(type(raw) is list and len(raw) <= MAX_OFFLINE_PATH_MAP_ENTRIES,
                    f"{label} is malformed or oversized")
            paths = [str(absolute_path(item, f"{label}[{index}]"))
                     for index, item in enumerate(raw)]
            require(paths == sorted(set(paths)),
                    f"{label} is not sorted and unique")
            return frozenset(paths)

        captured = normalized_set(context["captured_origin_paths"],
                                  "captured feedback object origins")
        files = normalized_set(context["evidence_file_paths"],
                               "captured owner inventory files")
        directories = normalized_set(context["evidence_directory_paths"],
                                     "captured owner inventory directories")
        symlinks = normalized_set(context["source_symlink_paths"],
                                  "resident SourceV5 symlinks")
        require(captured and captured <= files and not captured.intersection(directories) and
                symlinks <= files and all(view.has_file(path) for path in captured) and
                type(context["tree_inventories"]) is list,
                "captured feedback paths do not close the authenticated owner inventory")
        capture = exact(context["probe_capture_pin"], {
            "path", "raw_sha256", "receipt_sha256",
        }, "captured ProbeV2 receipt pin")
        absolute_path(capture["path"], "captured ProbeV2 receipt path")
        digest(capture["raw_sha256"], "captured ProbeV2 receipt raw SHA-256")
        digest(capture["receipt_sha256"], "captured ProbeV2 receipt digest")
        bundle = exact(context["capacity_bundle"], {"request", "artifact", "receipt"},
                       "captured feedback capacity bundle")
        for name, pin_value in bundle.items():
            pin = exact(pin_value, {"path", "raw_sha256"},
                        f"captured capacity {name} pin")
            absolute_path(pin["path"], f"captured capacity {name} path")
            digest(pin["raw_sha256"], f"captured capacity {name} raw SHA-256")
        require(len({bundle[name]["path"] for name in bundle}) == 3,
                "captured capacity producer paths must be distinct")
        return types.MappingProxyType({
            "schema": context["schema"], "captured": True,
            "artifact_view": view, "captured_files": captured,
            "mapped_paths": captured | files | directories,
            "mapped_directories": directories, "mapped_files": files,
            "mapped_symlinks": symlinks,
            "tree_inventories": tuple(context["tree_inventories"]),
            "probe_capture_pin": types.MappingProxyType(dict(capture)),
            "capacity_bundle": types.MappingProxyType({
                name: types.MappingProxyType(dict(bundle[name]))
                for name in bundle
            }),
        })
    try:
        snapshot = json.loads(canonical(value).decode("ascii"))
    except (TypeError, ValueError, UnicodeError) as error:
        raise CompositionError(f"feedback offline replay context is not closed JSON: {error}") from error
    context = exact(snapshot, {
        "schema", "evidence_path_map", "probe_capture_pin", "capacity_bundle",
    }, "feedback offline replay context")
    require(context["schema"] == FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
            "unsupported feedback offline replay context schema")
    mapping = exact(context["evidence_path_map"], {"schema", "entries"}, "feedback evidence path map")
    require(mapping["schema"] == EVIDENCE_PATH_MAP_SCHEMA and
            type(mapping["entries"]) is list and
            1 <= len(mapping["entries"]) <= MAX_OFFLINE_PATH_MAP_ENTRIES,
            "feedback evidence path map schema or entry count is invalid")
    previous = ""
    mapped: set[str] = set()
    directories: set[str] = set()
    files: set[str] = set()
    symlinks: set[str] = set()
    for index, entry_value in enumerate(mapping["entries"]):
        entry = exact(entry_value, {"origin", "local"}, f"feedback path map entry[{index}]")
        origin = absolute_path(entry["origin"], f"feedback evidence origin[{index}]")
        local = absolute_path(entry["local"], f"feedback evidence local[{index}]")
        origin_text = str(origin)
        require(origin_text > previous and origin == local and origin_text not in mapped,
                "feedback evidence map must contain sorted unique identity paths")
        previous = origin_text
        try:
            require(local.parent.resolve(strict=True) == local.parent,
                    "feedback evidence map path parent traverses a symlink or alias")
            info = local.lstat()
            if not stat.S_ISLNK(info.st_mode):
                require(local.resolve(strict=True) == local,
                        "feedback evidence map path traverses a symlink or alias")
        except OSError as error:
            raise CompositionError(f"feedback evidence map path is unavailable: {error}") from error
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or
                stat.S_ISLNK(info.st_mode),
                f"feedback evidence map entry[{index}] is not a regular file, directory, or typed symlink")
        mapped.add(origin_text)
        if stat.S_ISDIR(info.st_mode):
            directories.add(origin_text)
        elif stat.S_ISREG(info.st_mode):
            files.add(origin_text)
        else:
            symlinks.add(origin_text)
    capture = exact(context["probe_capture_pin"], {"path", "raw_sha256", "receipt_sha256"},
                    "offline ProbeV2 capture receipt pin")
    absolute_path(capture["path"], "offline ProbeV2 capture receipt path")
    digest(capture["raw_sha256"], "offline ProbeV2 capture raw SHA-256")
    digest(capture["receipt_sha256"], "offline ProbeV2 capture digest")
    bundle = exact(context["capacity_bundle"], {"request", "artifact", "receipt"},
                   "offline capacity bundle pins")
    for name, pin_value in bundle.items():
        pin = exact(pin_value, {"path", "raw_sha256"}, f"offline capacity {name} pin")
        absolute_path(pin["path"], f"offline capacity {name} path")
        digest(pin["raw_sha256"], f"offline capacity {name} raw SHA-256")
    require(len({bundle[name]["path"] for name in bundle}) == 3,
            "offline capacity request/artifact/receipt paths must be distinct")
    frozen_mapping = types.MappingProxyType({
        "schema": mapping["schema"],
        "entries": tuple(types.MappingProxyType(dict(entry)) for entry in mapping["entries"]),
    })
    frozen_capture = types.MappingProxyType(dict(capture))
    frozen_bundle = types.MappingProxyType({
        name: types.MappingProxyType(dict(bundle[name])) for name in bundle
    })
    return types.MappingProxyType({
        "schema": context["schema"], "evidence_path_map": frozen_mapping,
        "captured": False, "captured_files": frozenset(),
        "mapped_paths": frozenset(mapped), "mapped_directories": frozenset(directories),
        "mapped_files": frozenset(files), "mapped_symlinks": frozenset(symlinks),
        "probe_capture_pin": frozen_capture, "capacity_bundle": frozen_bundle,
    })


def _require_mapped(context: dict[str, Any], paths: set[str], label: str) -> None:
    mapped = context["mapped_paths"]
    for raw_path in paths:
        path = absolute_path(raw_path, f"{label} path")
        rendered = str(path)
        require(rendered in mapped,
                f"feedback evidence path map omits exact {label}: {rendered}")


def _require_mapped_files(context: dict[str, Any], paths: set[str], label: str) -> None:
    _require_mapped(context, paths, label)
    for path in paths:
        require(path in context["mapped_files"],
                f"feedback evidence path map does not mark {label} as a file: {path}")


def _require_mapped_directories(context: dict[str, Any], paths: set[str], label: str) -> None:
    _require_mapped(context, paths, label)
    for path in paths:
        require(path in context["mapped_directories"],
                f"feedback evidence path map does not mark {label} as a directory: {path}")


def _offline_view_for_path(context: dict[str, Any], path: str | Path) -> Any:
    if context.get("captured") is True and str(path) in context["captured_files"]:
        return context["artifact_view"]
    return None


def _hash_captured_object(
    artifact_view: Any, path: Path, label: str, maximum: int,
) -> tuple[int, str]:
    require(artifact_view.has_file(path),
            f"{label} is absent from the exact captured refs")
    total = 0
    hasher = hashlib.sha256()
    with artifact_view.open_snapshot(path, label, maximum) as (
            stream, expected_sha, byte_count):
        require(type(byte_count) is int and 0 <= byte_count <= maximum,
                f"{label} exceeds its finite captured byte bound")
        while total < byte_count:
            block = stream.read(min(1024 * 1024, byte_count - total))
            require(bool(block), f"{label} captured object was truncated")
            total += len(block)
            hasher.update(block)
        require(stream.read(1) == b"" and total == byte_count and
                hasher.hexdigest() == expected_sha,
                f"{label} captured bytes differ from their exact raw pin")
    return total, hasher.hexdigest()


def _preflight_probe_capture_tree(
    capture: dict[str, Any], replay_context: dict[str, Any], capture_path: Path,
) -> None:
    stdout = exact(capture["stdout"], {"path", "raw_sha256"}, "offline ProbeV2 stdout pin")
    stderr = exact(capture["stderr"], {"path", "raw_sha256"}, "offline ProbeV2 stderr pin")
    owner_pin = exact(capture["owner_result_pin"], {
        "path", "raw_sha256", "owner_result_sha256",
    }, "offline ProbeV2 owner-result pin")
    inventory_pin = exact(capture["tmpdir_inventory_pin"], {
        "path", "raw_sha256", "inventory_sha256",
    }, "offline ProbeV2 TMPDIR inventory pin")
    tmp_initial = exact(capture["tmpdir_initial"], {
        "path", "device", "inode", "mode", "mount", "available_bytes", "available_inodes",
        "bytes_limit", "inode_limit",
    }, "offline ProbeV2 initial TMPDIR proof")
    tmp_final = exact(capture["tmpdir_final"], {
        "path", "device", "inode", "mode", "mount", "bytes_used", "file_count", "directory_count",
        "bytes_limit", "inode_limit", "available_bytes", "available_inodes",
    }, "offline ProbeV2 final TMPDIR proof")
    tmp_root = absolute_path(tmp_initial["path"], "offline ProbeV2 TMPDIR")
    stdout_path = absolute_path(stdout["path"], "offline ProbeV2 stdout")
    output_root = stdout_path.parent
    expected_files = {
        str(stdout_path), str(absolute_path(stderr["path"], "offline ProbeV2 stderr")),
        str(absolute_path(owner_pin["path"], "offline ProbeV2 owner result")),
        str(absolute_path(inventory_pin["path"], "offline ProbeV2 TMPDIR inventory")),
        str(capture_path),
    }
    require(Path(stderr["path"]).parent == output_root and
            Path(owner_pin["path"]).parent == output_root and
            Path(inventory_pin["path"]).parent == output_root and
            capture_path.parent == output_root and tmp_root.parent == output_root,
            "offline ProbeV2 output/TMPDIR paths do not share their captured root")
    _require_mapped_directories(replay_context, {str(output_root), str(tmp_root)},
                                "ProbeV2 output/TMPDIR root")
    _require_mapped_files(replay_context, expected_files, "ProbeV2 output/receipt member")
    if replay_context.get("captured") is True:
        direct_files = {
            path for path in replay_context["mapped_files"]
            if Path(path).parent == output_root
        }
        direct_directories = {
            path for path in replay_context["mapped_directories"]
            if Path(path).parent == output_root
        }
        require(str(output_root) in replay_context["mapped_directories"] and
                str(tmp_root) in replay_context["mapped_directories"] and
                direct_files == expected_files and
                direct_directories == {str(tmp_root)},
                "captured ProbeV2 output root differs from its exact owner inventory")
    else:
        try:
            require(output_root.resolve(strict=True) == output_root and
                    tmp_root.resolve(strict=True) == tmp_root,
                    "offline ProbeV2 output/TMPDIR traverses an alias")
            output_info = output_root.lstat()
            tmp_info = tmp_root.lstat()
            with os.scandir(output_root) as entries:
                output_names = {entry.name for entry in entries}
        except OSError as error:
            raise CompositionError(f"cannot inspect offline ProbeV2 output/TMPDIR root: {error}") from error
        require(stat.S_ISDIR(output_info.st_mode) and not stat.S_ISLNK(output_info.st_mode) and
                output_info.st_uid == os.getuid() and stat.S_IMODE(output_info.st_mode) == 0o700 and
                stat.S_ISDIR(tmp_info.st_mode) and not stat.S_ISLNK(tmp_info.st_mode) and
                tmp_info.st_uid == os.getuid() and stat.S_IMODE(tmp_info.st_mode) == 0o700,
                "copied ProbeV2 output/TMPDIR roots are not owned private directories")
        require(output_names == {
            "tmp", "stdout.bin", "stderr.bin", "owner-result.json", "tmpdir-inventory.json",
            "capture-receipt.json",
        }, "copied ProbeV2 output root has an unpinned or missing member")
    inventory_value, _inventory_raw, inventory_raw_sha = _read_canonical(
        Path(inventory_pin["path"]), "offline ProbeV2 TMPDIR inventory sidecar",
        inventory_pin["raw_sha256"], MAX_PROBE_TMPDIR_INVENTORY_BYTES,
        artifact_view=_offline_view_for_path(replay_context, inventory_pin["path"]),
    )
    exact(inventory_value, {"schema", "entries", "inventory_sha256"},
          "offline ProbeV2 TMPDIR inventory sidecar")
    inventory_body = {key: item for key, item in inventory_value.items()
                      if key != "inventory_sha256"}
    require(inventory_value["schema"] == PROBE_TMPDIR_INVENTORY_SCHEMA and
            inventory_raw_sha == inventory_pin["raw_sha256"] and
            inventory_value["inventory_sha256"] == inventory_pin["inventory_sha256"] ==
            sha256(canonical(inventory_body)),
            "offline ProbeV2 TMPDIR inventory sidecar digest differs from its receipt pin")
    budget = exact(capture["storage_budget"], {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes", "receipt_bytes", "output_inodes",
    }, "offline ProbeV2 storage budget")
    inode_limit = uint(budget["tmpdir_inodes"], "offline ProbeV2 TMPDIR inode limit", positive=True)
    byte_limit = uint(budget["tmpdir_bytes"], "offline ProbeV2 TMPDIR byte limit", positive=True)
    require(inode_limit <= 4096 and byte_limit <= 1024 * 1024 * 1024,
            "offline ProbeV2 TMPDIR bounds exceed the fixed finite limits")
    inventory = inventory_value["entries"]
    require(type(inventory) is list and len(inventory) <= inode_limit,
            "offline ProbeV2 TMPDIR inventory exceeds its finite inode bound")
    expected: dict[str, str] = {}
    order: list[str] = []
    total_bytes = 0
    for index, item_value in enumerate(inventory):
        item = exact(item_value, {"path", "kind", "uid", "mode", "size", "raw_sha256"},
                     f"offline ProbeV2 TMPDIR inventory[{index}]")
        item_path = absolute_path(item["path"], f"offline ProbeV2 TMPDIR entry[{index}]")
        try:
            relative = item_path.relative_to(tmp_root)
        except ValueError as error:
            raise CompositionError("offline ProbeV2 TMPDIR inventory escapes its root") from error
        item_text = str(item_path)
        require(relative.parts and item_text not in expected and item["kind"] in ("file", "directory") and
                type(item["uid"]) is int and item["uid"] >= 0 and
                item["uid"] == os.getuid() and
                type(item["mode"]) is int and 0 <= item["mode"] <= 0o7777,
                "offline ProbeV2 TMPDIR inventory has duplicate or invalid entries")
        if item["kind"] == "file":
            size = uint(item["size"], f"offline ProbeV2 TMPDIR file size[{index}]")
            total_bytes += size
            digest(item["raw_sha256"], f"offline ProbeV2 TMPDIR file digest[{index}]")
            _require_mapped_files(replay_context, {item_text}, "ProbeV2 TMPDIR file descendant")
        else:
            require(item["size"] is None and item["raw_sha256"] is None,
                    "offline ProbeV2 TMPDIR directory carries file fields")
            _require_mapped_directories(replay_context, {item_text}, "ProbeV2 TMPDIR directory descendant")
        expected[item_text] = item["kind"]
        order.append(item_text)
    require(order == sorted(order), "offline ProbeV2 TMPDIR inventory is not in canonical path order")
    require(total_bytes <= byte_limit and tmp_initial["path"] == tmp_final["path"] == str(tmp_root) and
            tmp_initial["mode"] == tmp_final["mode"] == 0o700 and
            tmp_initial["bytes_limit"] == tmp_final["bytes_limit"] == byte_limit and
            tmp_initial["inode_limit"] == tmp_final["inode_limit"] == inode_limit and
            tmp_final["bytes_used"] == total_bytes and
            tmp_final["file_count"] == sum(1 for item in inventory if item["kind"] == "file") and
            tmp_final["directory_count"] == sum(1 for item in inventory if item["kind"] == "directory"),
            "offline ProbeV2 TMPDIR inventory totals differ from its strict storage proof")
    if replay_context.get("captured") is True:
        tree_rows = [exact(row, {
            "owner_job_sha256", "root_path", "role", "owner_receipt_pin",
            "inventory_pin", "inventory_sha256", "entry_count", "byte_count",
            "entries",
        }, f"captured ProbeV2 typed tree[{index}]")
            for index, row in enumerate(replay_context["tree_inventories"])
            if type(row) is dict and row.get("root_path") == str(tmp_root)]
        require(len(tree_rows) == 1,
                "captured ProbeV2 request has no unique typed TMPDIR tree row")
        tree = tree_rows[0]
        receipt_pin = replay_context["probe_capture_pin"]
        require(tree["role"] == "opaque_trace" and
                tree["owner_receipt_pin"] == {
                    "path": receipt_pin["path"],
                    "raw_sha256": receipt_pin["raw_sha256"],
                    "semantic_sha256": receipt_pin["receipt_sha256"],
                } and tree["inventory_pin"] == {
                    "path": inventory_pin["path"],
                    "raw_sha256": inventory_pin["raw_sha256"],
                    "semantic_sha256": inventory_pin["inventory_sha256"],
                } and tree["inventory_sha256"] == inventory_pin["inventory_sha256"] and
                tree["entries"] == inventory and
                tree["entry_count"] == len(inventory) and
                tree["byte_count"] == total_bytes,
                "captured ProbeV2 typed tree differs from its exact receipt/inventory")
        for item in inventory:
            if item["kind"] == "file":
                size, actual = _hash_captured_object(
                    replay_context["artifact_view"], Path(item["path"]),
                    "captured ProbeV2 TMPDIR descendant", byte_limit,
                )
                require(size == item["size"] and actual == item["raw_sha256"],
                        "captured ProbeV2 TMPDIR descendant differs from its typed inventory")
    owner_value, _owner_raw, owner_raw_sha = _read_canonical(
        Path(owner_pin["path"]), "offline FixedR8 owner-result sidecar",
        owner_pin["raw_sha256"], MAX_PROBE_OWNER_RESULT_BYTES,
        artifact_view=_offline_view_for_path(replay_context, owner_pin["path"]),
    )
    exact(owner_value, {
        "schema", "direct", "start_callback_count", "start_callback_proofs",
        "owner_result_sha256",
    }, "offline FixedR8 owner-result sidecar")
    owner_body = {key: item for key, item in owner_value.items() if key != "owner_result_sha256"}
    require(owner_value["schema"] == PROBE_OWNER_RESULT_SCHEMA and
            owner_raw_sha == owner_pin["raw_sha256"] and
            owner_value["owner_result_sha256"] == owner_pin["owner_result_sha256"] ==
            sha256(canonical(owner_body)),
            "offline FixedR8 owner-result sidecar digest differs from its receipt pin")
    if replay_context.get("captured") is True:
        return

    pending = [tmp_root]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                names: list[str] = []
                for entry in entries:
                    require(len(seen) + len(names) < inode_limit,
                            "copied ProbeV2 TMPDIR directory exceeds its finite inode bound")
                    names.append(entry.name)
        except OSError as error:
            raise CompositionError(f"cannot enumerate copied ProbeV2 TMPDIR {current}: {error}") from error
        for name in names:
            child = current / name
            child_text = str(child)
            kind = expected.get(child_text)
            require(kind is not None,
                    f"evidence path map omits exact ProbeV2 TMPDIR descendant: {child_text}")
            try:
                info = child.lstat()
            except OSError as error:
                raise CompositionError(f"cannot inspect mapped ProbeV2 TMPDIR descendant: {error}") from error
            actual_kind = "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "special"
            require(not stat.S_ISLNK(info.st_mode) and actual_kind == kind and info.st_uid == os.getuid(),
                    "copied ProbeV2 TMPDIR descendant differs from its mapped inventory type/owner")
            seen.add(child_text)
            if kind == "directory":
                pending.append(child)
            require(len(seen) <= inode_limit,
                    "copied ProbeV2 TMPDIR traversal exceeds its finite inode bound")
    require(seen == set(expected),
            "copied ProbeV2 TMPDIR is missing a declared inventory descendant")


def _absolute_paths(value: object) -> set[str]:
    paths: set[str] = set()
    path_keys = {
        "path", "source_root", "output_root", "binary_path", "executable_path", "cwd",
        "tmpdir", "trace_directory", "directory", "root", "tmpdir_path",
        "application_tmpdir_path", "pressure_scratch_path", "mount_point",
    }

    def visit(current: object, argv_context: bool = False) -> None:
        if type(current) is dict:
            for key, item in current.items():
                if key in path_keys and type(item) is str and item.startswith("/"):
                    paths.add(item)
                elif key == "environment" and type(item) is dict:
                    temp = item.get("TMPDIR")
                    if type(temp) is str and temp.startswith("/"):
                        paths.add(temp)
                    visit(item)
                else:
                    visit(item, key in {"argv", "requested_argv", "executed_argv", "probe_argv"})
        elif type(current) is list:
            for item in current:
                visit(item, argv_context)
        elif argv_context and type(current) is str and current.startswith("/"):
            paths.add(current)

    visit(value)
    return paths


def _preflight_capacity_request_trace(
    request: object, replay_context: dict[str, Any],
) -> None:
    value = exact(request, {
        "schema", "calibration_id", "identity", "source_manifest", "validation",
        "expectation", "expectation_sha256", "validator_sha256", "trace_directory",
        "context", "minimum_interval_seconds",
    }, "offline capacity producer request")
    require(value["schema"] == CAPACITY_REQUEST_SCHEMA,
            "unsupported offline capacity producer request schema")
    for name in ("source_manifest", "validation", "expectation", "context"):
        pin = exact(value[name], {"path", "sha256"}, f"offline capacity {name} pin")
        absolute_path(pin["path"], f"offline capacity {name} path")
        digest(pin["sha256"], f"offline capacity {name} raw SHA-256")
        _require_mapped_files(replay_context, {pin["path"]}, f"offline capacity {name} input")
    digest(value["expectation_sha256"], "offline capacity expectation SHA-256")
    digest(value["validator_sha256"], "offline capacity validator SHA-256")
    exact(value["identity"], {
        "host_id", "run_id", "report_nonce", "process_id", "allocator", "executor",
        "workload", "profile", "mode", "source_sha256", "binary_sha256",
        "pressure_qualification",
    }, "offline capacity identity")
    trace_root = absolute_path(value["trace_directory"], "offline capacity trace directory")
    _require_mapped_directories(replay_context, {str(trace_root)}, "capacity V4 trace directory")
    trace_paths = {str(trace_root / name) for name in CAPACITY_TRACE_FILES}
    _require_mapped_files(replay_context, trace_paths, "capacity V4 trace member")
    validation_pin = exact(value["validation"], {"path", "sha256"},
                           "offline capacity validation receipt pin")
    validation_path = absolute_path(validation_pin["path"], "offline capacity validation receipt path")
    _require_mapped_files(replay_context, {str(validation_path)}, "capacity validation receipt")
    validation, _validation_raw, _validation_sha = _read_canonical(
        validation_path, "offline capacity validation receipt", validation_pin["sha256"],
    )
    exact(validation, {
        "schema", "mode", "validated", "qualification_eligible", "expectation_raw_sha256",
        "validator_sha256", "identity", "raw_artifact_sha256", "production_window",
        "final_runtime_binding",
    }, "offline capacity validation receipt")
    require(validation["schema"] == "allocatbelt.application-feedback-validation.v1" and
            validation["mode"] == "capacity_calibration" and
            validation["validated"] is True and
            validation["qualification_eligible"] is False,
            "offline capacity validation receipt is not a validated ineligible calibration result")
    raw_pins = exact(validation["raw_artifact_sha256"], {"manifest", "events", "samples"},
                     "offline capacity trace raw pins")
    for name, raw_sha in raw_pins.items():
        digest(raw_sha, f"offline capacity {name} trace raw SHA-256")


def _verify_source5_symlink_literal(
    source_root: Path, relative: PurePosixPath, record: object, label: str,
) -> None:
    """Compare one mapped symlink's bounded literal bytes without following it."""
    value = exact(record, {"path", "kind", "mode", "target", "sha256", "size"},
                  f"{label} symlink inventory record")
    require(value["path"] == relative.as_posix() and value["kind"] == "symlink" and
            value["mode"] == "120000",
            f"{label} symlink record path/kind/mode is invalid")
    target = value["target"]
    require(type(target) is str, f"{label} symlink target is malformed")
    try:
        expected_target = target.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise CompositionError(f"{label} symlink target is not UTF-8") from error
    expected_size = uint(value["size"], f"{label} symlink target size")
    expected_sha = digest(value["sha256"], f"{label} symlink target SHA-256")
    require(0 < len(expected_target) <= 4096 and expected_size == len(expected_target) and
            sha256(expected_target) == expected_sha,
            f"{label} symlink target hash/size differs from its typed record")
    try:
        components = [part.encode("utf-8", "strict") for part in relative.parts]
    except UnicodeEncodeError as error:
        raise CompositionError(f"{label} symlink path is not UTF-8") from error
    require(bool(components), f"{label} symlink path has no leaf")

    directory_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
        getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = -1
    parent_fd = -1
    verify_parent_fd = -1

    def stat_key(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
        )

    def open_parent() -> tuple[int, tuple[tuple[int, int, int, int, int, int], ...]]:
        current = os.dup(root_fd)
        identities: list[tuple[int, int, int, int, int, int]] = []
        try:
            for component in components[:-1]:
                try:
                    child = os.open(component, directory_flags, dir_fd=current)
                except OSError as error:
                    raise CompositionError(
                        f"{label} symlink parent is missing or not a real directory: {error}"
                    ) from error
                try:
                    info = os.fstat(child)
                    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                            f"{label} symlink parent is not a real directory")
                    identities.append(stat_key(info))
                except BaseException:
                    os.close(child)
                    raise
                os.close(current)
                current = child
            return current, tuple(identities)
        except BaseException:
            os.close(current)
            raise

    try:
        require(source_root.resolve(strict=True) == source_root,
                f"{label} source root traverses a symlink or alias")
        root_path_before = source_root.lstat()
        require(stat.S_ISDIR(root_path_before.st_mode) and not stat.S_ISLNK(root_path_before.st_mode),
                f"{label} source root is not a real directory")
        root_fd = os.open(os.fsencode(str(source_root)), directory_flags)
        root_before = os.fstat(root_fd)
        require(stat_key(root_before) == stat_key(root_path_before),
                f"{label} source root changed while opening")

        parent_fd, parent_ids = open_parent()
        parent_before = os.fstat(parent_fd)
        leaf = components[-1]
        link_before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISLNK(link_before.st_mode),
                f"{label} typed symlink path is not a symlink")
        actual_target = os.readlink(leaf, dir_fd=parent_fd)
        require(type(actual_target) is bytes and len(actual_target) <= 4096 and
                link_before.st_size == len(actual_target) == expected_size,
                f"{label} literal symlink target exceeds its finite byte bound or size pin")
        link_after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        parent_after = os.fstat(parent_fd)

        verify_parent_fd, verify_parent_ids = open_parent()
        verify_parent_before = os.fstat(verify_parent_fd)
        verify_link_before = os.stat(leaf, dir_fd=verify_parent_fd, follow_symlinks=False)
        verify_target = os.readlink(leaf, dir_fd=verify_parent_fd)
        verify_link_after = os.stat(leaf, dir_fd=verify_parent_fd, follow_symlinks=False)
        require(verify_link_before.st_size == len(verify_target) == expected_size,
                f"{label} rechecked symlink target size differs from its typed record")
        verify_parent_after = os.fstat(verify_parent_fd)
        root_after = os.fstat(root_fd)
        root_path_after = source_root.lstat()
        require(source_root.resolve(strict=True) == source_root,
                f"{label} source root moved through an alias")
        require(parent_ids == verify_parent_ids and
                stat_key(parent_before) == stat_key(parent_after) ==
                stat_key(verify_parent_before) == stat_key(verify_parent_after),
                f"{label} symlink parent changed during literal capture")
        require(stat_key(link_before) == stat_key(link_after) ==
                stat_key(verify_link_before) == stat_key(verify_link_after) and
                actual_target == verify_target,
                f"{label} symlink changed during literal capture")
        require(stat_key(root_before) == stat_key(root_after) == stat_key(root_path_after),
                f"{label} source root changed during literal capture")
    except OSError as error:
        raise CompositionError(f"cannot safely capture {label} symlink literal: {error}") from error
    finally:
        for descriptor in (verify_parent_fd, parent_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)

    require(actual_target == expected_target and len(actual_target) == expected_size and
            sha256(actual_target) == expected_sha,
            f"{label} literal target/hash/size differs from its SourceV5 typed record")


def _source5_offline_inventory_closure(
    source_root: Path, inventory: object, artifact_paths: set[str],
    context: dict[str, Any], label: str, *, recorded_artifacts: bool = False,
) -> None:
    """Close typed SourceV5 regular/link paths before the captured verifier runs."""
    require(type(inventory) is list and len(inventory) <= 16_384,
            f"{label} typed inventory is malformed or exceeds the path-map bound")
    records: dict[str, str] = {}
    source_files: set[str] = set()
    source_symlinks: set[str] = set()
    symlink_records: list[tuple[PurePosixPath, dict[str, Any]]] = []
    for index, value in enumerate(inventory):
        require(type(value) is dict and type(value.get("kind")) is str,
                f"{label} inventory entry[{index}] is malformed")
        relative_text = value.get("path")
        require(type(relative_text) is str and 0 < len(relative_text) <= 4096,
                f"{label} inventory path[{index}] must be bounded text")
        relative = PurePosixPath(relative_text)
        require(not relative.is_absolute() and relative.parts and
                ".." not in relative.parts and relative.as_posix() == relative_text and
                "\\" not in relative_text,
                f"{label} inventory path[{index}] is not portable")
        kind = value["kind"]
        require(kind in ("file", "symlink"),
                f"{label} inventory kind[{index}] is unsupported")
        require(relative_text not in records,
                f"{label} inventory repeats {relative_text}")
        records[relative_text] = kind
        absolute = str(source_root.joinpath(*relative.parts))
        if kind == "file":
            source_files.add(absolute)
            continue
        source_symlinks.add(absolute)
        symlink_records.append((relative, value))

    checked_artifacts = {str(absolute_path(path, f"{label} artifact path"))
                         for path in artifact_paths}
    require(not checked_artifacts.intersection(source_files | source_symlinks),
            f"{label} artifact aliases a typed source path")
    require(set(context["mapped_symlinks"]) == source_symlinks,
            f"{label} path map symlinks differ from the typed inventory")
    _require_mapped(context, source_symlinks, f"{label} symlink member")
    required_files = source_files if recorded_artifacts else source_files | checked_artifacts
    _require_mapped_files(context, required_files,
                          f"{label} regular inventory/artifact member")
    for relative, record in symlink_records:
        _verify_source5_symlink_literal(source_root, relative, record, label)


def _closed_recorded_source_executable_paths_v1(
    source_root: Path, source: dict[str, Any],
) -> set[str]:
    """Derive every SourceV5 executable artifact path from checked metadata."""
    artifacts = source.get("artifacts")
    expected_labels = {"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"}
    require(type(artifacts) is dict and set(artifacts) == expected_labels,
            "closed-recorded SourceV5 application artifact table is incomplete")
    result: set[str] = set()

    def add(value: object, label: str) -> None:
        artifact = exact(value, {"path", "sha256"},
                         f"closed-recorded SourceV5 executable artifact {label}")
        relative_text = _bounded_text(artifact["path"],
                                      f"{label} artifact path", 4096)
        relative = PurePosixPath(relative_text)
        require(not relative.is_absolute() and relative.parts and
                ".." not in relative.parts and relative.as_posix() == relative_text and
                "\\" not in relative_text,
                f"closed-recorded SourceV5 artifact {label} path is not portable")
        digest(artifact["sha256"], f"closed-recorded SourceV5 artifact {label} SHA-256")
        result.add(str(source_root.joinpath(*relative.parts)))

    for label in sorted(expected_labels):
        add(artifacts[label], label)
    soak_artifacts = source.get("soak_artifacts")
    require(type(soak_artifacts) is dict and set(soak_artifacts) == {"allocatbelt"},
            "closed-recorded SourceV5 soak artifact table is malformed")
    add(soak_artifacts["allocatbelt"], "soak-allocatbelt")
    add(source.get("analysis_artifact"), "analysis")
    calibration = exact(source.get("resource_domain_calibration"), {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, "closed-recorded SourceV5 resource-domain calibration")
    add(calibration["binary"], "resource-domain calibration")
    require(len(result) == len(expected_labels) + 3,
            "closed-recorded SourceV5 executable artifacts alias one another")
    return result


def _reject_closed_recorded_artifact_map_v1(
    replay_context: object, request: dict[str, Any], source_root: Path,
    source: dict[str, Any],
) -> None:
    forbidden = _closed_recorded_source_executable_paths_v1(source_root, source)
    source_pin = exact(request["source_manifest"], {"path", "raw_sha256"},
                       "closed-recorded SourceV5 manifest pin")
    require(not (source_pin["path"] == str(source_root) or
                 source_pin["path"].startswith(str(source_root).rstrip("/") + "/")),
            "closed-recorded SourceV5 manifest pin must be outside SourceRoot")
    role_paths = [source_pin["path"], request["construction_probe"]["path"]]
    capacity = exact(request["capacity_bundle"], {"request", "artifact", "receipt"},
                     "closed-recorded composition capacity bundle")
    for name in ("request", "artifact", "receipt"):
        role_paths.append(exact(capacity[name], {"path", "raw_sha256"},
                                f"closed-recorded capacity {name} pin")["path"])

    context = exact(replay_context, {
        "schema", "evidence_path_map", "probe_capture_pin", "capacity_bundle",
    }, "closed-recorded feedback replay context")
    require(context["schema"] == FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
            "closed-recorded feedback context schema differs")
    capture = exact(context["probe_capture_pin"], {
        "path", "raw_sha256", "receipt_sha256",
    }, "closed-recorded ProbeV2 capture pin")
    role_paths.append(capture["path"])
    context_capacity = exact(context["capacity_bundle"],
                             {"request", "artifact", "receipt"},
                             "closed-recorded feedback capacity bundle")
    require(context_capacity == request["capacity_bundle"],
            "closed-recorded context capacity pins differ from the composer request")
    for name in context_capacity:
        role_paths.append(exact(context_capacity[name], {"path", "raw_sha256"},
                                 f"closed-recorded feedback capacity {name} pin")["path"])
    for index, raw_path in enumerate(role_paths):
        path = str(absolute_path(raw_path,
                                 f"closed-recorded SourceV5 role path[{index}]"))
        require(path not in forbidden,
                "closed-recorded SourceV5 role pin aliases an executable artifact")

    evidence_map = exact(context["evidence_path_map"], {"schema", "entries"},
                         "closed-recorded feedback evidence path map")
    require(evidence_map["schema"] == EVIDENCE_PATH_MAP_SCHEMA and
            type(evidence_map["entries"]) is list and
            1 <= len(evidence_map["entries"]) <= MAX_OFFLINE_PATH_MAP_ENTRIES,
            "closed-recorded feedback evidence map schema or entry count differs")
    previous = ""
    local_paths: set[str] = set()
    for index, entry_value in enumerate(evidence_map["entries"]):
        entry = exact(entry_value, {"origin", "local"},
                      f"closed-recorded feedback evidence map[{index}]")
        origin = str(absolute_path(entry["origin"],
                                   f"closed-recorded evidence origin[{index}]"))
        local = str(absolute_path(entry["local"],
                                  f"closed-recorded evidence local[{index}]"))
        require(origin == local and origin > previous and local not in local_paths,
                "closed-recorded feedback map must be sorted unique identity paths")
        previous = origin
        local_paths.add(local)
        require(origin not in forbidden and local not in forbidden,
                "closed-recorded feedback map names a SourceV5 executable artifact")


def _preflight_probe_replay(
    request: dict[str, Any], replay_context: dict[str, Any],
    *, recorded_artifacts: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_root = absolute_path(request["source_root"], "offline SourceV5 source root")
    source_pin = request["source_manifest"]
    probe_pin = request["construction_probe"]
    bundle = request["capacity_bundle"]
    capacity_floor_policy_id = request.get("capacity_floor_policy_id")
    top_paths = {
        str(source_root), source_pin["path"], probe_pin["path"],
        *(bundle[name]["path"] for name in bundle),
        replay_context["probe_capture_pin"]["path"],
    }
    _require_mapped(replay_context, top_paths, "top-level pinned probe input")
    _require_mapped_directories(replay_context, {str(source_root)}, "SourceV5 source root")
    _require_mapped_files(replay_context, {
        source_pin["path"], probe_pin["path"],
        *(bundle[name]["path"] for name in bundle),
        replay_context["probe_capture_pin"]["path"],
    }, "top-level pinned probe input")
    source, _source_raw, _source_sha = _read_canonical(
        absolute_path(source_pin["path"], "offline SourceV5 manifest path"),
        "offline SourceV5 manifest", source_pin["raw_sha256"],
    )
    require(source.get("schema") == SOURCE_SCHEMA_V5, "offline feedback composition requires SourceV5")
    _require_mapped(replay_context, _absolute_paths(source), "nested SourceV5 manifest evidence")
    inventory = source.get("source", {}).get("files")
    require(type(inventory) is list, "offline SourceV5 typed inventory is missing")
    artifact_paths: set[str] = set()
    artifacts = source.get("artifacts")
    require(type(artifacts) is dict, "offline SourceV5 artifact table is malformed")
    for artifact_value in artifacts.values():
        require(type(artifact_value) is dict and type(artifact_value.get("path")) is str,
                "offline SourceV5 artifact record is malformed")
        relative = PurePosixPath(artifact_value["path"])
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == artifact_value["path"] and
                "\\" not in artifact_value["path"],
                "offline SourceV5 artifact path is not portable")
        digest(artifact_value.get("sha256"), "offline SourceV5 artifact SHA-256")
        artifact_paths.add(str(source_root.joinpath(*relative.parts)))
    _source5_offline_inventory_closure(
        source_root, inventory, artifact_paths, replay_context, "offline SourceV5",
        recorded_artifacts=recorded_artifacts,
    )

    capture_pin = replay_context["probe_capture_pin"]
    _require_mapped_files(replay_context, {capture_pin["path"]}, "ProbeV2 capture receipt")
    capture_path = absolute_path(capture_pin["path"], "offline ProbeV2 capture receipt path")
    capture_output_root = capture_path.parent
    _require_mapped_directories(replay_context, {str(capture_output_root)},
                                "ProbeV2 captured output root")
    if replay_context.get("captured") is True:
        require(str(capture_output_root) in replay_context["mapped_directories"],
                "captured ProbeV2 output root has no authenticated directory fact")
    else:
        try:
            require(capture_output_root.resolve(strict=True) == capture_output_root,
                    "offline ProbeV2 output root traverses an alias")
            capture_output_info = capture_output_root.lstat()
        except OSError as error:
            raise CompositionError(f"cannot inspect copied ProbeV2 output root: {error}") from error
        require(stat.S_ISDIR(capture_output_info.st_mode) and
                not stat.S_ISLNK(capture_output_info.st_mode) and
                capture_output_info.st_uid == os.getuid() and
                stat.S_IMODE(capture_output_info.st_mode) == 0o700,
                "copied ProbeV2 output root is not an owned private directory")
    capture, _capture_raw, _capture_sha = _read_canonical(
        capture_path, "offline ProbeV2 capture receipt", capture_pin["raw_sha256"],
        MAX_PROBE_CAPTURE_RECEIPT_BYTES,
        artifact_view=_offline_view_for_path(replay_context, capture_path),
    )
    exact(capture, PROBE_CAPTURE_RECEIPT_FIELDS, "offline ProbeV2 capture receipt")
    capture_body = {key: item for key, item in capture.items() if key != "receipt_sha256"}
    capture_paths = _absolute_paths(capture)
    if recorded_artifacts:
        capture_paths.difference_update(artifact_paths)
    _require_mapped(replay_context, capture_paths,
                    "nested ProbeV2 capture evidence")
    require(capture["schema"] == PROBE_CAPTURE_RECEIPT_SCHEMA and
            capture["receipt_sha256"] == capture_pin["receipt_sha256"] ==
            sha256(canonical(capture_body)) and
            capture["qualification_eligible"] is False and
            capture["execution_ready"] is False and
            capture["controller_chronology_proven"] is False,
            "offline ProbeV2 capture receipt schema/digest/flags differ from its pin")
    _preflight_probe_capture_tree(capture, replay_context, capture_path)

    probe, _probe_raw, _probe_sha = _read_canonical(
        absolute_path(request["construction_probe"]["path"], "offline ProbeV2 path"),
        "offline calibrated ProbeV2", request["construction_probe"]["raw_sha256"],
        MAX_PROBE_BYTES,
        artifact_view=_offline_view_for_path(
            replay_context, request["construction_probe"]["path"],
        ),
    )
    _require_mapped(replay_context, _absolute_paths(probe), "nested ProbeV2 evidence")

    capacity_request_pin = bundle["request"]
    _require_mapped_files(replay_context, {capacity_request_pin["path"]},
                          "capacity producer request")
    capacity_request, _capacity_request_raw, _capacity_request_sha = _read_canonical(
        absolute_path(capacity_request_pin["path"], "offline byte-capacity request path"),
        "offline byte-capacity request", capacity_request_pin["raw_sha256"],
    )
    _require_mapped(replay_context, _absolute_paths(capacity_request),
                    "nested byte-capacity request evidence")
    _preflight_capacity_request_trace(capacity_request, replay_context)
    expectation_pin = capacity_request.get("expectation")
    if type(expectation_pin) is dict and type(expectation_pin.get("path")) is str:
        _require_mapped_files(replay_context, {expectation_pin["path"]},
                              "nested byte-capacity expectation")
        expectation, _expectation_raw, _expectation_sha = _read_canonical(
            absolute_path(expectation_pin["path"], "offline capacity expectation path"),
            "offline capacity expectation", expectation_pin.get("sha256"),
        )
        _require_mapped(replay_context, _absolute_paths(expectation),
                        "nested capacity expectation evidence")
    _require_mapped_files(replay_context, {bundle["receipt"]["path"]},
                          "capacity producer receipt")
    capacity_receipt, _capacity_receipt_raw, _capacity_receipt_sha = _read_canonical(
        absolute_path(bundle["receipt"]["path"], "offline capacity receipt path"),
        "offline byte-capacity receipt", bundle["receipt"]["raw_sha256"],
    )
    _require_mapped(replay_context, _absolute_paths(capacity_receipt),
                    "nested capacity receipt evidence")

    stdout_pin = exact(capture["stdout"], {"path", "raw_sha256"},
                       "offline ProbeV2 stdout pin")
    stderr_pin = exact(capture["stderr"], {"path", "raw_sha256"},
                       "offline ProbeV2 stderr pin")
    _require_mapped_files(replay_context, {stdout_pin["path"], stderr_pin["path"]},
                          "offline ProbeV2 raw output")
    stdout, stdout_sha = _read_stable(
        absolute_path(stdout_pin["path"], "offline ProbeV2 stdout path"),
        "offline ProbeV2 stdout", MAX_PROBE_BYTES,
        artifact_view=_offline_view_for_path(replay_context, stdout_pin["path"]),
    )
    stderr, stderr_sha = _read_stable(
        absolute_path(stderr_pin["path"], "offline ProbeV2 stderr path"),
        "offline ProbeV2 stderr", MAX_PROBE_BYTES,
        artifact_view=_offline_view_for_path(replay_context, stderr_pin["path"]),
    )
    require(stdout_sha == stdout_pin["raw_sha256"] == request["construction_probe"]["raw_sha256"] and
            stdout == canonical(probe) and stderr_sha == stderr_pin["raw_sha256"] and not stderr,
            "offline ProbeV2 receipt does not retain the original exact stdout and empty stderr")
    return source, capture


def _captured_source_module(reader: Any, source: dict[str, Any], relative: str, label: str) -> tuple[Any, str]:
    record = reader._source_v5_regular_record(source["source"], relative, label)
    raw = reader._capture_source_v5_sibling(relative, record, label)
    path = SOURCE_ROOT.joinpath(*PurePosixPath(relative).parts)
    module = types.ModuleType(f"source5_capture_{relative.rsplit('/', 1)[-1]}_{record['sha256']}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        _exec_registered_module(module, raw, path)
    except (SyntaxError, ValueError, TypeError) as error:
        raise CompositionError(f"pinned {label} cannot be compiled from captured bytes: {error}") from error
    return module, record["sha256"]


def _live_probe_origin_facts(host: dict[str, Any]) -> dict[str, Any]:
    try:
        boot_raw = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()
        netns = os.stat("/proc/self/ns/net").st_ino
        affinity = sorted(os.sched_getaffinity(0))
    except OSError as error:
        raise CompositionError(f"cannot capture strict probe host identity: {error}") from error
    require(bool(boot_raw) and b"\n" not in boot_raw, "strict probe boot identity is malformed")
    actual = {
        "boot_id_sha256": sha256(boot_raw), "kernel_release": platform.release(),
        "cpu_affinity": affinity, "network_namespace_inode": netns,
    }
    require(actual == {key: host[key] for key in actual},
            "strict probe host facts differ from the pinned observed-host bytes")
    return actual


def capture_calibrated_probe_v2(
    request: object, request_raw_sha256: object, observed_host_pin: object, *,
    output_root: Path | str, capture_id: str, capture_timeout_ns: int,
    storage_budget: object, resource_monitor: Callable[[], bool] | None = None,
) -> dict[str, str]:
    """Capture ProbeV2 with the pinned FixedR8 owner and optional outer monitor."""
    require(resource_monitor is None or callable(resource_monitor),
            "probe capture resource monitor must be a callable or None")
    value = _validate_resolve_request(request)
    raw_sha = digest(request_raw_sha256, "probe capture composition request raw SHA-256")
    require(raw_sha == sha256(canonical(value)),
            "probe capture request bytes differ from its supplied raw digest")
    value = _validate_resolve_request(json.loads(canonical(value).decode("ascii")))
    try:
        host_pin_snapshot = json.loads(canonical(observed_host_pin).decode("ascii"))
        storage_snapshot = json.loads(canonical(storage_budget).decode("ascii"))
    except (TypeError, ValueError, UnicodeError) as error:
        raise CompositionError(f"probe capture host/storage inputs are not closed JSON: {error}") from error
    host_pin = exact(host_pin_snapshot, {"path", "raw_sha256"}, "probe observed-host pin")
    host_path = absolute_path(host_pin["path"], "probe observed-host path")
    digest(host_pin["raw_sha256"], "probe observed-host raw SHA-256")
    host, _host_raw, host_sha = _read_canonical(host_path, "probe observed-host context", host_pin["raw_sha256"])
    host = exact(host, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity", "network_namespace_inode",
    }, "probe observed-host context")
    require(host["schema"] == "allocatbelt.application-capacity-host-context.v1" and
            host["host_id"] == value["context"]["host_id"],
            "probe observed-host schema or host ID differs from the original SourceV5 context")
    require(host["boot_id_sha256"] == digest(host["boot_id_sha256"], "probe observed boot ID SHA-256") and
            host["controls_sha256"] == sha256(canonical(host["controls"])) and
            host["kernel_release"] == host["controls"].get("kernel_release") and
            host["cpu_model"] == host["controls"].get("cpu_model"),
            "probe observed-host control binding is malformed")
    affinity = host["cpu_affinity"]
    require(type(affinity) is list and affinity and
            all(type(cpu) is int and 0 <= cpu <= 65_535 for cpu in affinity) and
            affinity == sorted(set(affinity)), "probe observed-host affinity is malformed")
    require(type(host["network_namespace_inode"]) is int and host["network_namespace_inode"] > 0,
            "probe observed-host network namespace is malformed")
    origin_facts = _live_probe_origin_facts(host)
    budget = exact(storage_snapshot, {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes", "receipt_bytes", "output_inodes",
    }, "prospective probe capture storage budget")
    for key in budget:
        require(type(budget[key]) is int and budget[key] > 0, f"probe capture storage budget {key} must be positive")
    require(budget["tmpdir_bytes"] <= 1024 * 1024 * 1024 and
            budget["tmpdir_inodes"] <= 4096 and
            budget["stdout_bytes"] <= 512 * 1024 and
            budget["stderr_bytes"] <= MAX_PROBE_STDERR_BYTES and
            budget["owner_result_bytes"] == MAX_PROBE_OWNER_RESULT_BYTES and
            budget["inventory_bytes"] == MAX_PROBE_TMPDIR_INVENTORY_BYTES and
            budget["failure_bytes"] == MAX_PROBE_CAPTURE_FAILURE_BYTES and
            0 < budget["receipt_bytes"] <= MAX_PROBE_CAPTURE_RECEIPT_BYTES and
            7 <= budget["output_inodes"] <= 4096,
            "probe capture storage budget exceeds its finite owner limits")
    require(budget["stdout_bytes"] >= 1 and budget["stderr_bytes"] >= 1,
            "probe capture output bounds must be positive")
    output_base = absolute_path(str(output_root), "probe capture output root")
    try:
        require(output_base.resolve(strict=True) == output_base, "probe capture output root traverses a symlink or alias")
        output_info = output_base.lstat()
    except OSError as error:
        raise CompositionError(f"probe capture output root is unavailable: {error}") from error
    require(stat.S_ISDIR(output_info.st_mode) and output_info.st_uid == os.getuid() and
            stat.S_IMODE(output_info.st_mode) == 0o700,
            "probe capture output root must be an existing owned mode-0700 directory")
    try:
        output_base.relative_to(SOURCE_ROOT)
        inside_source_tree = True
    except ValueError:
        inside_source_tree = False
    require(not inside_source_tree, "probe capture outputs must remain outside the immutable SourceV5 tree")
    require(type(capture_id) is str and re.fullmatch(r"[a-f0-9]{32}", capture_id) is not None,
            "probe capture ID must be a fresh lowercase 128-bit token")
    require(type(capture_timeout_ns) is int and 0 < capture_timeout_ns <= MAX_PROBE_CAPTURE_TIMEOUT_NS,
            "probe capture deadline must be a prospectively supplied positive bound of at most 30 seconds")

    reader, producer, source, context, identity = _load_verified_inputs(value)
    source_pin = value["source_manifest"]
    bundle = value["capacity_bundle"]
    _verify_capacity_request_binding(reader, producer, source, context, identity, source_pin, bundle)
    capacity_floor_policy_id = value.get("capacity_floor_policy_id")
    probe_sha, probe, binary, source_root, capacity_sha, capacity_path = reader._check_calibrated_construction_probe_v2_inputs(
        value["construction_probe"], source, bundle["artifact"], identity,
        capacity_floor_policy_id=capacity_floor_policy_id,
    )
    reader.resolve_calibrated_feedback_policy_v5(
        source, probe, bundle["artifact"], identity,
        capacity_floor_policy_id=capacity_floor_policy_id,
    )
    require(len(reader.canonical_bytes(probe)) <= budget["stdout_bytes"],
            "prospective ProbeV2 stdout bound is smaller than the exact pinned output")
    fixed, fixed_sha = _captured_source_module(reader, source, FIXED_PAIR_OWNER, "FixedR8 direct process owner")
    helper, helper_sha = _captured_source_module(reader, source, PROBE_OWNER_HELPER, "FixedR8 launch identity helper")
    require(callable(getattr(fixed, "_run_direct_process", None)) and
            callable(getattr(helper, "_proc_start_ticks", None)),
            "captured FixedR8 process-owner APIs are unavailable")
    require(callable(getattr(reader, "validate_probe_capture_receipt_envelope", None)),
            "captured SourceV5 reader lacks the ProbeV2 receipt-envelope API")

    capture_dir = output_base / capture_id
    require(not capture_dir.exists() and not capture_dir.is_symlink(),
            "probe capture output directory must be fresh and unreused")
    capture_dir.mkdir(mode=0o700)
    info = capture_dir.stat(follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700,
            "created probe capture directory is not private")
    tmpdir = capture_dir / "tmp"
    stdout_path = capture_dir / "stdout.bin"
    stderr_path = capture_dir / "stderr.bin"
    receipt_path = capture_dir / "capture-receipt.json"
    owner_result_path = capture_dir / "owner-result.json"
    inventory_path = capture_dir / "tmpdir-inventory.json"
    output_reservation = (
        budget["tmpdir_bytes"] + budget["stdout_bytes"] + budget["stderr_bytes"] +
        budget["owner_result_bytes"] + budget["inventory_bytes"] +
        budget["failure_bytes"] + budget["receipt_bytes"]
    )
    output_inode_reservation = budget["tmpdir_inodes"] + budget["output_inodes"]
    budget_for_owner = {"tmpdir_bytes": budget["tmpdir_bytes"], "tmpdir_inodes": budget["tmpdir_inodes"]}
    initial_tmp = fixed._prepare_member_tmpdir(tmpdir, capture_dir, budget_for_owner)
    statvfs = os.statvfs(capture_dir)
    output_bytes_available = statvfs.f_bavail * statvfs.f_frsize
    output_inodes_available = statvfs.f_favail
    require(output_bytes_available >= output_reservation and
            output_inodes_available >= output_inode_reservation,
            "probe capture output filesystem cannot satisfy its bounded evidence files")
    output_mount = fixed._mount_identity(capture_dir)
    require(output_mount["available_bytes"] >= output_reservation and
            output_mount["available_inodes"] >= output_inode_reservation,
            "captured probe output mount fell below its frozen storage budget")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TMPDIR": str(tmpdir)}
    argv = [
        str(binary), "--emit-feedback-policy-only", "--workload", identity["workload"],
        "--profile", identity["profile"], "--capacity-calibration-file", str(capacity_path),
        "--capacity-calibration-sha256", capacity_sha, "--host-id", identity["host_id"],
        "--source-sha256", identity["source_sha256"],
    ]
    if capacity_floor_policy_id is not None:
        require(capacity_floor_policy_id == CAPACITY_FLOOR_POLICY_ID,
                "typed ProbeV2 collector capacity floor policy ID is unknown")
        argv.extend(["--capacity-floor-policy-id", capacity_floor_policy_id])
    source_semantic_sha = digest(source["manifest_sha256"], "SourceV5 semantic manifest SHA-256")
    source_tree_sha = digest(source["source"]["source_tree_sha256"], "SourceV5 source-tree SHA-256")
    origin_body = {
        "schema": "allocatbelt.application-feedback-probe-origin-facts.v1",
        "host_id": host["host_id"],
        "boot_id_sha256": origin_facts["boot_id_sha256"],
        "kernel_release": origin_facts["kernel_release"],
        "cpu_affinity": origin_facts["cpu_affinity"],
        "network_namespace_inode": origin_facts["network_namespace_inode"],
        "observed_host_raw_sha256": host_sha,
    }
    capture_origin_facts = {**origin_body, "origin_facts_sha256": sha256(canonical(origin_body))}
    max_u64 = (1 << 64) - 1
    owner_start_template = {
        "pid": (1 << 31) - 1, "start_ticks": max_u64,
        "requested_argv": argv, "requested_argv_sha256": "f" * 64,
        "environment_sha256": "f" * 64,
    }
    start_role_body_template = {
        "schema": PROBE_CAPTURE_START_ROLE_SCHEMA,
        "role": PROBE_CAPTURE_START_ROLE,
        "owner_proof": owner_start_template,
    }
    tmp_final_template = {
        "path": str(tmpdir), "device": max_u64, "inode": max_u64, "mode": 0o700,
        "mount": fixed._mount_static(output_mount),
        "bytes_used": budget["tmpdir_bytes"],
        "file_count": budget["tmpdir_inodes"], "directory_count": budget["tmpdir_inodes"],
        "bytes_limit": budget["tmpdir_bytes"], "inode_limit": budget["tmpdir_inodes"],
        "available_bytes": max_u64, "available_inodes": max_u64,
    }
    receipt_template = {
        "schema": PROBE_CAPTURE_RECEIPT_SCHEMA,
        "source_manifest": {
            "path": source_pin["path"], "raw_sha256": source_pin["raw_sha256"],
            "semantic_sha256": source_semantic_sha, "source_tree_sha256": source_tree_sha,
            "build_sha256": reader.digest_object(source["build"]),
        },
        "capacity_bundle": bundle, "capacity_tsv": bundle["artifact"],
        "probe_pin": value["construction_probe"],
        "binary": {"path": str(binary), "raw_sha256": value["construction_probe"]["binary_sha256"]},
        "observed_host": {"path": host_pin["path"], "raw_sha256": host_sha},
        "origin_facts": capture_origin_facts,
        "probe_argv": argv, "environment": environment, "cwd": str(source_root),
        "affinity": affinity, "netns": host["network_namespace_inode"],
        "capture_timeout_ns": capture_timeout_ns, "start_callback_count": 1,
        "start_callback_proof": owner_start_template,
        "start": {**start_role_body_template, "start_sha256": "f" * 64},
        "owner_result_pin": {
            "path": str(owner_result_path), "raw_sha256": "f" * 64,
            "owner_result_sha256": "f" * 64,
        },
        "tmpdir_inventory_pin": {
            "path": str(inventory_path), "raw_sha256": "f" * 64,
            "inventory_sha256": "f" * 64,
        },
        "stdout": {"path": str(stdout_path), "raw_sha256": "f" * 64},
        "stderr": {"path": str(stderr_path), "raw_sha256": "f" * 64},
        "exit_status": -((1 << 63) - 1), "output_matches_probe": False,
        "stderr_empty": False, "storage_budget": budget, "output_mount": output_mount,
        "tmpdir_initial": initial_tmp, "tmpdir_final": tmp_final_template,
        "owner_modules": {
            "fixed_pair": {"path": FIXED_PAIR_OWNER, "raw_sha256": fixed_sha},
            "launch_identity_helper": {"path": PROBE_OWNER_HELPER, "raw_sha256": helper_sha},
        },
        "qualification_eligible": False, "execution_ready": False,
        "controller_chronology_proven": False, "receipt_sha256": "f" * 64,
    }
    receipt_budget_required = len(canonical(receipt_template))
    require(budget["receipt_bytes"] >= receipt_budget_required,
            f"prospective ProbeV2 receipt budget {budget['receipt_bytes']} is below its computed bound "
            f"{receipt_budget_required}")
    if resource_monitor is not None:
        try:
            prelaunch_stop = bool(resource_monitor())
        except BaseException as error:
            failure = CompositionError(
                f"aggregate Source5 resource monitor failed before ProbeV2 Popen: "
                f"{type(error).__name__}: {error}",
            )
            _capture_failure_record(
                capture_dir, capture_id, "resource_monitor_prelaunch", failure,
                None, stdout_path, stderr_path, budget,
            )
            raise failure from error
        if prelaunch_stop:
            failure = CompositionError(
                "aggregate Source5 resource monitor refused before ProbeV2 Popen",
            )
            failure_path = _capture_failure_record(
                capture_dir, capture_id, "resource_monitor_prelaunch", failure,
                None, stdout_path, stderr_path, budget,
            )
            raise CompositionError(
                f"{failure}; bounded failure evidence retained at {failure_path}",
            )
    started: list[dict[str, Any]] = []
    tmpdir_monitor = fixed._bounded_tmpdir_monitor(
        tmpdir, budget["tmpdir_bytes"], budget["tmpdir_inodes"],
    )

    def combined_resource_monitor() -> bool:
        tmpdir_exceeded = bool(tmpdir_monitor())
        outer_exceeded = bool(resource_monitor()) if resource_monitor is not None else False
        return tmpdir_exceeded or outer_exceeded

    try:
        direct = fixed._run_direct_process(
            argv, binary, value["construction_probe"]["binary_sha256"], source_root, environment,
            affinity, stdout_path, stderr_path, budget["stdout_bytes"], budget["stderr_bytes"],
            capture_timeout_ns / 1_000_000_000, helper, expected_tmpdir=tmpdir,
            expected_network_inode=host["network_namespace_inode"],
            on_started=lambda proof: started.append(proof),
            capture_identity=False,
            resource_monitor=combined_resource_monitor,
        )
    except BaseException as error:
        try:
            _capture_failure_record(
                capture_dir, capture_id, "owner_process_supervision", error, None,
                stdout_path, stderr_path, budget,
            )
        except BaseException as record_error:
            raise CompositionError(
                f"FixedR8 owner raised {type(error).__name__}: {error}; bounded failure record also failed: {record_error}"
            ) from error
        raise CompositionError(
            f"FixedR8 owner raised {type(error).__name__}: {error}; bounded failure evidence retained at "
            f"{capture_dir / 'capture-failure.json'}"
        ) from error
    owner_result, owner_result_raw = _probe_owner_result(direct, started)
    owner_result_raw_sha = sha256(owner_result_raw)
    if len(owner_result_raw) > budget["owner_result_bytes"]:
        supervision = direct.get("supervision", {}) if type(direct) is dict else {}
        overflow = {
            "raw_sha256": owner_result_raw_sha,
            "byte_length": len(owner_result_raw),
            "status": direct.get("status") if type(direct) is dict else None,
            "child_return_code": direct.get("child_return_code") if type(direct) is dict else None,
            "cleanup_status": supervision.get("cleanup_status") if type(supervision) is dict else None,
            "signal_record_count": len(supervision.get("signals", []))
            if type(supervision) is dict and type(supervision.get("signals")) is list else None,
            "start_callback_count": len(started),
        }
        error = CompositionError("complete FixedR8 owner result exceeds its prospectively reserved 16 MiB bound")
        _capture_failure_record(
            capture_dir, capture_id, "owner_result_budget", error, None,
            stdout_path, stderr_path, budget, owner_result_overflow=overflow,
        )
        raise CompositionError(
            f"{error}; bounded overflow diagnostic and original owner output files remain under {capture_dir}"
        )
    try:
        _write_exclusive(owner_result_path, owner_result_raw)
    except BaseException as error:
        supervision = direct.get("supervision", {}) if type(direct) is dict else {}
        overflow = {
            "raw_sha256": owner_result_raw_sha,
            "byte_length": len(owner_result_raw),
            "status": direct.get("status") if type(direct) is dict else None,
            "child_return_code": direct.get("child_return_code") if type(direct) is dict else None,
            "cleanup_status": supervision.get("cleanup_status") if type(supervision) is dict else None,
            "signal_record_count": len(supervision.get("signals", []))
            if type(supervision) is dict and type(supervision.get("signals")) is list else None,
            "start_callback_count": len(started),
        }
        try:
            _capture_failure_record(
                capture_dir, capture_id, "owner_result_persist", error, None,
                stdout_path, stderr_path, budget, owner_result_overflow=overflow,
            )
        except BaseException as record_error:
            raise CompositionError(
                f"FixedR8 owner result could not be persisted ({error}); overflow diagnostic also failed: {record_error}"
            ) from error
        raise CompositionError(
            f"FixedR8 owner result could not be persisted; bounded failure evidence retained at "
            f"{capture_dir / 'capture-failure.json'}"
        ) from error
    owner_result_pin = {
        "path": str(owner_result_path), "raw_sha256": owner_result_raw_sha,
        "owner_result_sha256": owner_result["owner_result_sha256"],
    }
    inventory_pin_holder: list[dict[str, str] | None] = [None]
    receipt_committed = False

    def finish_capture() -> dict[str, str]:
        owner_start = exact(direct["start"], {
            "pid", "start_ticks", "requested_argv", "requested_argv_sha256", "environment_sha256",
        }, "FixedR8 minimal probe start proof")
        require(type(owner_start["pid"]) is int and 0 < owner_start["pid"] <= (1 << 31) - 1 and
                type(owner_start["start_ticks"]) is int and owner_start["start_ticks"] > 0 and
                owner_start["requested_argv"] == argv and
                owner_start["requested_argv_sha256"] == sha256(canonical(argv)) and
                owner_start["environment_sha256"] == sha256(canonical(environment)),
                "FixedR8 minimal probe proof differs from the requested launch identity")
        start_role_body = {
            "schema": PROBE_CAPTURE_START_ROLE_SCHEMA,
            "role": PROBE_CAPTURE_START_ROLE,
            "owner_proof": owner_start,
        }
        start_role = {**start_role_body, "start_sha256": sha256(canonical(start_role_body))}
        stdout_raw, stdout_sha = _read_stable(stdout_path, "owned ProbeV2 stdout", reader.MAX_PROBE_OUTPUT_BYTES)
        stderr_raw, stderr_sha = _read_stable(stderr_path, "owned ProbeV2 stderr", reader.MAX_PROBE_OUTPUT_BYTES)
        output_matches_probe = stdout_raw == reader.canonical_bytes(probe) and stdout_sha == probe_sha
        stderr_empty = not stderr_raw
        final_tmp = fixed._tmpdir_usage(tmpdir, {
            "bytes_limit": budget["tmpdir_bytes"], "inode_limit": budget["tmpdir_inodes"],
        })
        fixed._verify_tmpdir_storage(
            initial_tmp, final_tmp, str(tmpdir), budget["tmpdir_bytes"], budget["tmpdir_inodes"],
            "calibrated feedback probe",
        )
        tmpdir_inventory = _capture_tmpdir_inventory(
            tmpdir, budget["tmpdir_bytes"], budget["tmpdir_inodes"],
        )
        inventory_body = {
            "schema": PROBE_TMPDIR_INVENTORY_SCHEMA,
            "entries": tmpdir_inventory,
        }
        inventory_value = {
            **inventory_body, "inventory_sha256": sha256(canonical(inventory_body)),
        }
        inventory_raw = canonical(inventory_value)
        require(len(inventory_raw) <= budget["inventory_bytes"],
                "complete ProbeV2 TMPDIR inventory exceeds its reserved sidecar bound")
        _write_exclusive(inventory_path, inventory_raw)
        inventory_pin = {
            "path": str(inventory_path), "raw_sha256": sha256(inventory_raw),
            "inventory_sha256": inventory_value["inventory_sha256"],
        }
        inventory_pin_holder[0] = inventory_pin
        require(_live_probe_origin_facts(host) == origin_facts,
                "strict probe host identity changed during the owned capture")
        receipt_body = {
            "schema": PROBE_CAPTURE_RECEIPT_SCHEMA,
            "source_manifest": {
                "path": source_pin["path"], "raw_sha256": source_pin["raw_sha256"],
                "semantic_sha256": source_semantic_sha, "source_tree_sha256": source_tree_sha,
                "build_sha256": reader.digest_object(source["build"]),
            },
            "capacity_bundle": bundle,
            "capacity_tsv": bundle["artifact"],
            "probe_pin": value["construction_probe"],
            "binary": {"path": str(binary), "raw_sha256": value["construction_probe"]["binary_sha256"]},
            "observed_host": {"path": host_pin["path"], "raw_sha256": host_sha},
            "origin_facts": capture_origin_facts,
            "probe_argv": argv, "environment": environment, "cwd": str(source_root),
            "affinity": affinity, "netns": host["network_namespace_inode"],
            "capture_timeout_ns": capture_timeout_ns,
            "start_callback_count": len(started),
            "start_callback_proof": started[0] if len(started) == 1 else None,
            "start": start_role,
            "owner_result_pin": owner_result_pin,
            "tmpdir_inventory_pin": inventory_pin,
            "stdout": {"path": str(stdout_path), "raw_sha256": stdout_sha},
            "stderr": {"path": str(stderr_path), "raw_sha256": stderr_sha},
            "exit_status": direct["status"], "output_matches_probe": output_matches_probe,
            "stderr_empty": stderr_empty, "storage_budget": budget,
            "output_mount": output_mount,
            "tmpdir_initial": initial_tmp, "tmpdir_final": final_tmp,
            "owner_modules": {
                "fixed_pair": {"path": FIXED_PAIR_OWNER, "raw_sha256": fixed_sha},
                "launch_identity_helper": {"path": PROBE_OWNER_HELPER, "raw_sha256": helper_sha},
            },
            "qualification_eligible": False, "execution_ready": False,
            "controller_chronology_proven": False,
        }
        receipt_body, receipt_raw = _seal_probe_capture_receipt(receipt_body)
        reader.validate_probe_capture_receipt_envelope(
            receipt_raw, sha256(receipt_raw), receipt_body["receipt_sha256"],
        )
        require(len(receipt_raw) <= budget["receipt_bytes"],
                "captured ProbeV2 owner receipt exceeds its prospectively supplied byte budget")
        _write_exclusive(receipt_path, receipt_raw)
        nonlocal receipt_committed
        receipt_committed = True
        receipt_pin = {
            "path": str(receipt_path), "raw_sha256": sha256(receipt_raw),
            "receipt_sha256": receipt_body["receipt_sha256"],
        }
        require(direct["status"] == 0 and direct["supervision"]["cleanup_status"] == "verified" and
                direct["child_return_code"] == 0 and direct["received_signal"] is None and
                len(started) == 1 and started[0] == owner_start and
                direct["timing"]["elapsed_ns"] <= capture_timeout_ns and
                output_matches_probe and stderr_empty,
                f"FixedR8-owned ProbeV2 capture failed; its raw receipt and outputs remain at {receipt_pin['path']}")
        return receipt_pin

    try:
        return finish_capture()
    except BaseException as error:
        if not receipt_committed:
            try:
                _capture_failure_record(
                    capture_dir, capture_id, "post_capture_validation", error, owner_result_pin,
                    stdout_path, stderr_path, budget, inventory_pin=inventory_pin_holder[0],
                )
            except BaseException as record_error:
                raise CompositionError(
                    f"ProbeV2 post-capture validation raised {type(error).__name__}: {error}; "
                    f"owner result remains at {owner_result_path}; failure record also failed: {record_error}"
                ) from error
        raise


def _read_initial_probe_request(request_pin_value: object) -> tuple[dict[str, Any], dict[str, str], bytes]:
    request_pin = exact(request_pin_value, {"path", "raw_sha256"},
                         "initial ProbeV2 request pin")
    request_path = absolute_path(request_pin["path"], "initial ProbeV2 request path")
    request_sha = digest(request_pin["raw_sha256"], "initial ProbeV2 request raw SHA-256")
    request, raw, actual = _read_canonical(
        request_path, "initial ProbeV2 request", request_sha,
    )
    try:
        info = request_path.stat(follow_symlinks=False)
    except OSError as error:
        raise CompositionError(f"cannot inspect initial ProbeV2 request: {error}") from error
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            "initial ProbeV2 request must be an owned immutable mode-0600 regular file")
    return request, {"path": str(request_path), "raw_sha256": actual}, raw


def _validate_initial_probe_request(value: object) -> dict[str, Any]:
    base_keys = {
        "schema", "source_root", "source_manifest", "context", "allocator",
        "capacity_bundle", "observed_host", "output_root", "emission_id",
        "timeout_ns", "storage_budget",
    }
    request = exact(value, base_keys | ({"capacity_floor_policy_id"}
                  if type(value) is dict and "capacity_floor_policy_id" in value else set()),
                   "initial ProbeV2 request")
    require(request["schema"] == INITIAL_PROBE_REQUEST_SCHEMA,
            "unsupported initial ProbeV2 request schema")
    source_root = absolute_path(request["source_root"], "initial ProbeV2 SourceV5 root")
    require(source_root == SOURCE_ROOT,
            "initial ProbeV2 SourceV5 root must contain this executing helper")
    source_pin = exact(request["source_manifest"], {"path", "raw_sha256"},
                       "initial ProbeV2 SourceV5 manifest pin")
    absolute_path(source_pin["path"], "initial ProbeV2 SourceV5 manifest path")
    digest(source_pin["raw_sha256"], "initial ProbeV2 SourceV5 manifest raw SHA-256")
    context = exact(request["context"], {
        "host_id", "workload", "profile", "calibration_id",
    }, "initial ProbeV2 context")
    for key, item in context.items():
        require(type(item) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", item)
                is not None, f"initial ProbeV2 context {key} is malformed")
    allocator = request["allocator"]
    require(type(allocator) is str and allocator in (
        "allocatbelt", "mimalloc-secure", "mimalloc-standard", "system",
    ), "initial ProbeV2 allocator is outside the original application artifact set")
    bundle = exact(request["capacity_bundle"], {"request", "artifact", "receipt"},
                   "initial ProbeV2 capacity bundle")
    bundle_paths: list[str] = []
    for name, item in bundle.items():
        pin = exact(item, {"path", "raw_sha256"}, f"initial ProbeV2 capacity {name} pin")
        absolute_path(pin["path"], f"initial ProbeV2 capacity {name} path")
        digest(pin["raw_sha256"], f"initial ProbeV2 capacity {name} raw SHA-256")
        bundle_paths.append(pin["path"])
    require(len(set(bundle_paths)) == 3,
            "initial ProbeV2 capacity request, artifact, and receipt paths must be distinct")
    host_pin = exact(request["observed_host"], {"path", "raw_sha256"},
                     "initial ProbeV2 observed-host pin")
    absolute_path(host_pin["path"], "initial ProbeV2 observed-host path")
    digest(host_pin["raw_sha256"], "initial ProbeV2 observed-host raw SHA-256")
    require(host_pin["path"] not in bundle_paths and source_pin["path"] not in bundle_paths and
            host_pin["path"] != source_pin["path"],
            "initial ProbeV2 source, host, and capacity inputs must have distinct paths")
    absolute_path(request["output_root"], "initial ProbeV2 output root")
    require(type(request["emission_id"]) is str and
            re.fullmatch(r"[a-f0-9]{32}", request["emission_id"]) is not None,
            "initial ProbeV2 emission ID must be a fresh lowercase 128-bit token")
    require(type(request["timeout_ns"]) is int and
            0 < request["timeout_ns"] <= MAX_PROBE_CAPTURE_TIMEOUT_NS,
            "initial ProbeV2 timeout must be a positive bound of at most 30 seconds")
    _validate_probe_storage_budget(request["storage_budget"])
    if "capacity_floor_policy_id" in request:
        require(request["capacity_floor_policy_id"] == CAPACITY_FLOOR_POLICY_ID,
                "initial ProbeV2 capacity floor policy ID is unknown")
    return request


def _validate_probe_storage_budget(value: object) -> dict[str, int]:
    budget = exact(value, {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes", "receipt_bytes",
        "output_inodes",
    }, "initial ProbeV2 storage budget")
    for key, number in budget.items():
        require(type(number) is int and number > 0,
                f"initial ProbeV2 storage budget {key} must be a positive integer")
    require(budget["tmpdir_bytes"] <= 1024 * 1024 * 1024 and
            budget["tmpdir_inodes"] <= 4096 and
            budget["stdout_bytes"] <= 512 * 1024 and
            budget["stderr_bytes"] <= MAX_PROBE_STDERR_BYTES and
            budget["owner_result_bytes"] == MAX_PROBE_OWNER_RESULT_BYTES and
            budget["inventory_bytes"] == MAX_PROBE_TMPDIR_INVENTORY_BYTES and
            budget["failure_bytes"] == MAX_PROBE_CAPTURE_FAILURE_BYTES and
            budget["receipt_bytes"] <= MAX_PROBE_CAPTURE_RECEIPT_BYTES and
            7 <= budget["output_inodes"] <= 4096,
            "initial ProbeV2 storage budget exceeds its fixed finite owner limits")
    return budget


def _validate_initial_probe_floor_policy(
    request: dict[str, Any], source: dict[str, Any], reader: Any,
) -> str | None:
    artifact = exact(source.get("feedback_policy"), {"schema", "policy", "policy_sha256"},
                     "SourceV5 feedback policy artifact")
    body = artifact["policy"]
    if artifact["schema"] == "allocatbelt.application-feedback-policy-artifact.v1":
        require("capacity_floor_policy_id" not in request,
                "initial ProbeV2 request selects a floor absent from its SourceV5 policy")
        return None
    require(artifact["schema"] == "allocatbelt.application-feedback-policy-artifact.v2",
            "initial ProbeV2 SourceV5 feedback policy schema is unsupported")
    descriptor = reader._validate_capacity_floor_policy_descriptor(
        body.get("capacity_floor_policy"),
    )
    selected = request.get("capacity_floor_policy_id")
    require(selected == descriptor["policy_id"] == CAPACITY_FLOOR_POLICY_ID,
            "initial ProbeV2 floor selection differs from the Source-published policy")
    return selected


def _initial_probe_host_context(
    host_pin: dict[str, str], context: dict[str, Any], source: dict[str, Any],
    capacity_stage: Any,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    host_path = absolute_path(host_pin["path"], "initial ProbeV2 observed-host path")
    host, _host_raw, host_sha = _read_canonical(
        host_path, "initial ProbeV2 observed-host context", host_pin["raw_sha256"],
    )
    host = exact(host, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity", "network_namespace_inode",
    }, "initial ProbeV2 observed-host context")
    require(host["schema"] == "allocatbelt.application-capacity-host-context.v1" and
            host["host_id"] == context["host_id"],
            "initial ProbeV2 observed-host identity differs from the Source-selected context")
    controls = exact(host["controls"], {
        "cpu_model", "microcode_sha256", "kernel_release", "governor",
        "frequency_policy", "boost_policy", "cpu_set", "numa_policy",
        "cgroup_policy_sha256", "background_load_policy_sha256",
        "x86_64_v3_capability_sha256", "target_triple", "target_cpu",
    }, "initial ProbeV2 observed host controls")
    require(host["controls_sha256"] == sha256(canonical(controls)) and
            host["kernel_release"] == controls["kernel_release"] and
            host["cpu_model"] == controls["cpu_model"] and
            controls["target_triple"] == source["build"]["target_triple"] and
            controls["target_cpu"] == source["build"]["target_cpu"],
            "initial ProbeV2 observed-host controls differ from their digest or Source build target")
    digest(host["boot_id_sha256"], "initial ProbeV2 boot ID SHA-256")
    affinity = host["cpu_affinity"]
    require(type(affinity) is list and bool(affinity) and
            all(type(cpu) is int and 0 <= cpu <= 65_535 for cpu in affinity) and
            affinity == sorted(set(affinity)) and
            capacity_stage._parse_cpu_set(controls["cpu_set"]) == affinity,
            "initial ProbeV2 observed affinity differs from its canonical frozen CPU set")
    uint(host["network_namespace_inode"], "initial ProbeV2 network namespace inode", positive=True)
    origin = _live_probe_origin_facts(host)
    try:
        require(capacity_stage._live_cpu_model() == host["cpu_model"] and
                capacity_stage._boot_id_sha256() == host["boot_id_sha256"],
                "initial ProbeV2 live CPU model or boot identity differs from the observed host")
    except Exception as error:
        raise CompositionError(f"initial ProbeV2 live host check failed: {error}") from error
    return host, host_sha, origin


def _validate_initial_probe_start_proof(
    value: object, argv: list[str], environment: dict[str, str],
) -> dict[str, Any]:
    start = exact(value, {
        "pid", "start_ticks", "requested_argv", "requested_argv_sha256",
        "environment_sha256",
    }, "FixedR8 initial ProbeV2 minimal start proof")
    uint(start["pid"], "initial ProbeV2 owner PID", positive=True,
         maximum=(1 << 31) - 1)
    uint(start["start_ticks"], "initial ProbeV2 owner start ticks", positive=True,
         maximum=(1 << 64) - 1)
    require(start["requested_argv"] == argv and
            start["requested_argv_sha256"] == sha256(canonical(argv)) and
            start["environment_sha256"] == sha256(canonical(environment)),
            "initial ProbeV2 minimal start proof differs from the actual requested launch")
    return start


def _validate_initial_probe_binary_identity(
    value: object, *, expected_path: Path, source_relative_path: str,
    expected_sha256: str, expected_descriptor: dict[str, int], maximum_size: int,
) -> dict[str, int]:
    binary = exact(value, {
        "path", "source_relative_path", "raw_sha256", "device", "inode", "size",
    }, "initial ProbeV2 opened binary identity")
    require(binary["path"] == str(expected_path) and
            binary["source_relative_path"] == source_relative_path and
            binary["raw_sha256"] == expected_sha256,
            "initial ProbeV2 binary path/hash differs from its SourceV5 artifact")
    descriptor = {
        "device": uint(binary["device"], "initial ProbeV2 opened binary device", positive=True),
        "inode": uint(binary["inode"], "initial ProbeV2 opened binary inode", positive=True),
        "size": uint(binary["size"], "initial ProbeV2 opened binary size", positive=True,
                     maximum=maximum_size),
    }
    require(descriptor == expected_descriptor,
            "initial ProbeV2 opened ELF device/inode/size differs from the stable Source artifact")
    return descriptor


def _validate_initial_probe_direct_binary(
    direct: object, *, expected_path: Path, expected_sha256: str,
    expected_descriptor: dict[str, int], maximum_size: int,
) -> dict[str, int]:
    require(type(direct) is dict and direct.get("binary_path") == str(expected_path) and
            direct.get("binary_sha256") == expected_sha256,
            "FixedR8 opened executable differs from the SourceV5 application artifact")
    descriptor = {
        "device": uint(direct.get("binary_device"), "FixedR8 binary device", positive=True),
        "inode": uint(direct.get("binary_inode"), "FixedR8 binary inode", positive=True),
        "size": uint(direct.get("binary_size"), "FixedR8 binary size", positive=True,
                     maximum=maximum_size),
    }
    require(descriptor == expected_descriptor,
            "FixedR8 opened ELF device/inode/size differs from the stable Source artifact")
    return descriptor


def _validate_initial_probe_owner_return(
    direct: object, started: list[dict[str, Any]], *, argv: list[str],
    environment: dict[str, str], cwd: Path, affinity: list[int],
    network_namespace_inode: int, binary: Path, binary_sha256: str,
    binary_descriptor: dict[str, int], maximum_binary_size: int,
    fixed: Any, capacity_stage: Any,
) -> tuple[dict[str, Any], dict[str, int]]:
    require(type(direct) is dict and type(started) is list,
            "initial ProbeV2 owner return/callbacks are malformed")
    start = _validate_initial_probe_start_proof(
        direct.get("start"), argv, environment,
    )
    require(len(started) == 1 and started[0] == start,
            "initial ProbeV2 owner callback does not match its actual minimal start")
    actual_binary = _validate_initial_probe_direct_binary(
        direct, expected_path=binary, expected_sha256=binary_sha256,
        expected_descriptor=binary_descriptor, maximum_size=maximum_binary_size,
    )
    capacity_stage._verify_owned_process_supervision(
        direct.get("supervision"), start, fixed,
    )
    require(direct.get("status") == 0 and direct.get("child_return_code") == 0 and
            direct.get("received_signal") is None and
            direct["supervision"].get("cleanup_status") == "verified" and
            direct.get("requested_argv") == argv and
            direct.get("requested_argv_sha256") == sha256(canonical(argv)) and
            direct.get("environment") == environment and
            direct.get("environment_sha256") == sha256(canonical(environment)) and
            direct.get("cwd") == str(cwd) and
            direct.get("cpu_affinity") == affinity and
            direct.get("network_namespace_inode") == network_namespace_inode,
            "initial ProbeV2 owner did not prove successful cleanup and its exact requested launch")
    return start, actual_binary


def _load_initial_probe_source_stack(
    request: dict[str, Any],
) -> tuple[Any, Any, Any, Any, Any, Any, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str], Path, str, dict[str, int]]:
    reader, producer, source, context, identity = _load_source_context_inputs(
        request, request["allocator"],
    )
    source_pin = exact(request["source_manifest"], {"path", "raw_sha256"},
                       "initial ProbeV2 SourceV5 manifest pin")
    source_path = absolute_path(source_pin["path"], "initial ProbeV2 SourceV5 manifest path")
    source, _source_raw, source_raw_sha = _read_canonical(
        source_path, "initial ProbeV2 SourceV5 manifest", source_pin["raw_sha256"],
    )
    require(source.get("schema") == SOURCE_SCHEMA_V5 and
            source["build"]["host_id"] == context["host_id"],
            "initial ProbeV2 selected host differs from its full SourceV5 build identity")
    controller = _pinned_source_module(
        source, "campaign_controller", "scripts/application-campaign.py",
        "campaign controller", MAX_METADATA_BYTES,
    )
    try:
        controller.verify_source_manifest(
            source, source_root=SOURCE_ROOT, verify_artifacts=True,
        )
    except Exception as error:
        raise CompositionError(
            f"pinned full SourceV5/artifact verifier rejected initial ProbeV2 inputs: {error}",
        ) from error
    composition_record = reader._source_v5_regular_record(
        source["source"], "scripts/application-feedback-composition.py",
        "feedback composition emitter",
    )
    active_raw, active_sha = _read_stable(
        Path(__file__).resolve(), "active feedback composition emitter", MAX_METADATA_BYTES,
    )
    require(active_sha == composition_record["sha256"] and
            len(active_raw) == composition_record["size"],
            "active initial ProbeV2 emitter differs from the exact SourceV5 typed inventory entry")
    fixed, fixed_sha = _captured_source_module(
        reader, source, FIXED_PAIR_OWNER, "FixedR8 direct process owner",
    )
    helper, helper_sha = _captured_source_module(
        reader, source, PROBE_OWNER_HELPER, "FixedR8 launch identity helper",
    )
    capacity_stage, capacity_stage_sha = _captured_source_module(
        reader, source, "scripts/application-capacity-stage.py",
        "Source5 capacity host/process verifier",
    )
    require(callable(getattr(reader, "_stable_file_sha256", None)) and
            callable(getattr(reader, "_validate_calibrated_construction_evidence", None)) and
            callable(getattr(reader, "resolve_calibrated_feedback_policy_v5", None)) and
            callable(getattr(fixed, "_run_direct_process", None)) and
            callable(getattr(fixed, "_prepare_member_tmpdir", None)) and
            callable(getattr(fixed, "_bounded_tmpdir_monitor", None)) and
            callable(getattr(helper, "_proc_start_ticks", None)) and
            callable(getattr(helper, "_hash_open_executable", None)) and
            callable(getattr(capacity_stage, "_verify_owned_process_supervision", None)) and
            callable(getattr(capacity_stage, "_parse_cpu_set", None)) and
            callable(getattr(capacity_stage, "_live_cpu_model", None)),
            "Source-pinned initial ProbeV2 reader, Fixed owner, or capacity verifier APIs are unavailable")
    binary_record = exact(source["artifacts"].get(identity["allocator"]), {"path", "sha256"},
                          "SourceV5 selected application artifact")
    try:
        _relative, binary = controller.safe_relative_artifact(
            SOURCE_ROOT, binary_record["path"], "SourceV5 selected application binary",
        )
    except Exception as error:
        raise CompositionError(f"SourceV5 selected application binary path is invalid: {error}") from error
    binary_sha, binary_size, binary_mode = reader._stable_file_sha256(
        binary, "SourceV5 selected application binary", reader.MAX_APP_BINARY_BYTES,
    )
    require(binary_sha == binary_record["sha256"] == identity["binary_sha256"] and
            binary_mode & 0o111 != 0,
            "selected SourceV5 application binary hash/mode differs from its published artifact")
    binary_identity = _validate_initial_probe_elf(binary, reader.MAX_APP_BINARY_BYTES)
    require(binary_identity["size"] == binary_size,
            "SourceV5 ELF size differs from its stable artifact hash descriptor")
    return (
        reader, producer, controller, fixed, helper, capacity_stage, source, context,
        identity, {"path": source_pin["path"], "raw_sha256": source_raw_sha},
        binary, binary_sha, binary_identity,
    )


def _validate_initial_probe_elf(path: Path, maximum_size: int) -> dict[str, int]:
    require(type(maximum_size) is int and maximum_size >= 20,
            "SourceV5 application binary is shorter than an ELF header")
    try:
        before_path = path.lstat()
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise CompositionError(f"cannot safely inspect SourceV5 ELF header: {error}") from error
    try:
        before = os.fstat(descriptor)
        key = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and key(before) == key(before_path) and
                before.st_mode & 0o111 != 0 and 20 <= before.st_size <= maximum_size and
                before.st_dev > 0 and before.st_ino > 0,
                "SourceV5 selected binary changed or exceeds its bounded ELF size")
        header = os.read(descriptor, 20)
        after_fd, after_path = os.fstat(descriptor), path.lstat()
        require(len(header) == 20 and key(before) == key(after_fd) == key(after_path),
                "SourceV5 selected binary changed while reading its ELF header")
    finally:
        os.close(descriptor)
    require(header[:4] == b"\x7fELF" and header[4] == 2 and header[5] == 1 and
            header[6] == 1 and int.from_bytes(header[16:18], "little") in (2, 3) and
            int.from_bytes(header[18:20], "little") == 62,
            "SourceV5 selected binary is not a little-endian x86_64 ELF executable")
    return {"device": before.st_dev, "inode": before.st_ino, "size": before.st_size}


def _require_initial_probe_private_output(path: Path, label: str) -> os.stat_result:
    require(path.resolve(strict=True) == path,
            f"{label} traverses a symlink or output alias")
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise CompositionError(f"cannot inspect {label}: {error}") from error
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
            f"{label} is not one owned private mode-0600 regular file")
    return info


def _probe_output_mount_bounds(
    fixed: Any, output_root: Path, budget: dict[str, int],
) -> tuple[dict[str, Any], int, int]:
    output_reservation = sum(budget[key] for key in (
        "tmpdir_bytes", "stdout_bytes", "stderr_bytes", "owner_result_bytes",
        "inventory_bytes", "failure_bytes", "receipt_bytes",
    ))
    inode_reservation = budget["tmpdir_inodes"] + budget["output_inodes"]
    mount = fixed._mount_identity(output_root)
    require(mount["available_bytes"] >= output_reservation and
            mount["available_inodes"] >= inode_reservation,
            "initial ProbeV2 output mount cannot reserve all bounded output and TMP evidence")
    return mount, output_reservation, inode_reservation


def _verify_initial_probe_success_layout(
    emission_dir: Path, budget_value: object, *, include_receipt: bool,
) -> dict[str, int]:
    budget = _validate_probe_storage_budget(budget_value)
    expected = {
        "tmp": "directory", "stdout.bin": "file", "stderr.bin": "file",
        "owner-result.json": "file", "tmpdir-inventory.json": "file",
    }
    if include_receipt:
        expected["emission-receipt.json"] = "file"
    byte_limits = {
        "stdout.bin": budget["stdout_bytes"],
        "stderr.bin": budget["stderr_bytes"],
        "owner-result.json": budget["owner_result_bytes"],
        "tmpdir-inventory.json": budget["inventory_bytes"],
        "emission-receipt.json": budget["receipt_bytes"],
        "capture-failure.json": budget["failure_bytes"],
    }
    aggregate_limit = sum(byte_limits.values())
    seen: set[str] = set()
    file_bytes = 0
    inode_count = 0
    try:
        entries = os.scandir(emission_dir)
    except OSError as error:
        raise CompositionError(f"cannot scan initial ProbeV2 success directory: {error}") from error
    try:
        for entry in entries:
            inode_count += 1
            require(inode_count <= budget["output_inodes"],
                    "initial ProbeV2 output directory exceeded its inode allowance during scan")
            require(entry.name not in seen,
                    "initial ProbeV2 output directory contains a duplicate name")
            seen.add(entry.name)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise CompositionError(
                    f"cannot inspect initial ProbeV2 output entry {entry.name}: {error}",
                ) from error
            require(not stat.S_ISLNK(info.st_mode) and
                    (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) and
                    info.st_uid == os.getuid(),
                    "initial ProbeV2 output contains a linked, special, or unowned entry")
            kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
            if kind == "file":
                file_bytes += info.st_size
                require(file_bytes <= aggregate_limit,
                        "initial ProbeV2 output files exceed the aggregate reserved byte budget")
                if entry.name in byte_limits:
                    require(info.st_size <= byte_limits[entry.name],
                            f"initial ProbeV2 output {entry.name} exceeds its exact byte slot")
                require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                        "initial ProbeV2 output file is not a private single-link inode")
            else:
                require(entry.name == "tmp" and stat.S_IMODE(info.st_mode) == 0o700,
                        "initial ProbeV2 success directory contains an unexpected directory")
            require(expected.get(entry.name) == kind,
                    f"initial ProbeV2 success directory contains an unexpected charged entry: {entry.name}")
    finally:
        entries.close()
    require(seen == set(expected),
            "initial ProbeV2 success directory lacks an exact required output entry")
    return {"inode_count": inode_count, "file_bytes": file_bytes}


def _initial_probe_failure_record(
    emission_dir: Path, emission_id: str, stage: str, error: BaseException,
    stdout_path: Path, stderr_path: Path, budget: dict[str, int],
    owner_result_pin: dict[str, str] | None = None, *,
    owner_result_overflow: dict[str, Any] | None = None,
    inventory_pin: dict[str, str] | None = None,
) -> Path:
    def output_pin(path: Path, maximum: int) -> dict[str, str | None] | None:
        try:
            _raw, raw_sha = _read_stable(path, "failed initial ProbeV2 output", maximum)
        except Exception:
            return None
        return {"path": str(path), "raw_sha256": raw_sha}

    body = {
        "schema": "allocatbelt.application-feedback-initial-probe-failure.v1",
        "emission_id": emission_id, "stage": stage,
        "error_type": type(error).__name__[:128],
        "error_message": str(error)[:4096],
        "owner_result_pin": owner_result_pin,
        "owner_result_overflow": owner_result_overflow,
        "tmpdir_inventory_pin": inventory_pin,
        "stdout": output_pin(stdout_path, budget["stdout_bytes"]),
        "stderr": output_pin(stderr_path, budget["stderr_bytes"]),
        "qualification_eligible": False, "execution_ready": False,
        "controller_chronology_proven": False,
    }
    value = {**body, "failure_sha256": sha256(canonical(body))}
    raw = canonical(value)
    require(len(raw) <= budget["failure_bytes"],
            "initial ProbeV2 failure record exceeds its reserved finite bound")
    path = emission_dir / "capture-failure.json"
    _write_exclusive(path, raw)
    return path


def _seal_initial_probe_emission_receipt(value: object) -> tuple[dict[str, Any], bytes]:
    body = exact(value, INITIAL_PROBE_EMISSION_RECEIPT_FIELDS - {"receipt_sha256"},
                 "initial ProbeV2 emission receipt body")
    receipt = {**body, "receipt_sha256": sha256(canonical(body))}
    return receipt, canonical(receipt)


def _initial_probe_receipt_template_size(value: object) -> int:
    receipt = exact(value, INITIAL_PROBE_EMISSION_RECEIPT_FIELDS,
                     "initial ProbeV2 receipt size projection")
    budget = _validate_probe_storage_budget(receipt["storage_budget"])
    template = copy.deepcopy(receipt)
    max_u64 = (1 << 64) - 1
    template["receipt_sha256"] = "f" * 64
    template["start_callback_count"] = 1
    start = exact(template["start_callback_proof"], {
        "pid", "start_ticks", "requested_argv", "requested_argv_sha256",
        "environment_sha256",
    }, "initial ProbeV2 receipt start size projection")
    start.update({
        "pid": (1 << 31) - 1, "start_ticks": max_u64,
        "requested_argv_sha256": "f" * 64,
        "environment_sha256": "f" * 64,
    })
    owner_pin = exact(template["owner_result_pin"], {
        "path", "raw_sha256", "owner_result_sha256",
    }, "initial ProbeV2 receipt owner-result size projection")
    owner_pin.update({"raw_sha256": "f" * 64, "owner_result_sha256": "f" * 64})
    template["owner_supervision_sha256"] = "f" * 64
    for name, maximum in (("stdout", budget["stdout_bytes"]),
                          ("stderr", budget["stderr_bytes"])):
        pin = exact(template[name], {"path", "raw_sha256", "byte_count"},
                    f"initial ProbeV2 receipt {name} size projection")
        pin.update({"raw_sha256": "f" * 64, "byte_count": maximum})
    probe = exact(template["construction_probe"], {
        "path", "raw_sha256", "allocator", "binary_sha256",
    }, "initial ProbeV2 receipt result-probe size projection")
    probe["raw_sha256"] = "f" * 64
    template["resolved_policy_sha256"] = "f" * 64
    template["exit_status"] = (1 << 31) - 1
    binary = exact(template["binary"], {
        "path", "source_relative_path", "raw_sha256", "device", "inode", "size",
    }, "initial ProbeV2 receipt binary size projection")
    binary.update({
        "raw_sha256": "f" * 64, "device": max_u64, "inode": max_u64,
        "size": max_u64,
    })
    for name in ("output_mount_initial", "output_mount_final"):
        mount = template[name]
        require(type(mount) is dict and "available_bytes" in mount and
                "available_inodes" in mount,
                f"initial ProbeV2 receipt {name} size projection is malformed")
        mount["available_bytes"] = max_u64
        mount["available_inodes"] = max_u64
    tmp_final = template["tmpdir_final"]
    require(type(tmp_final) is dict, "initial ProbeV2 TMPDIR final size projection is malformed")
    tmp_final.update({
        "device": max_u64, "inode": max_u64,
        "bytes_used": budget["tmpdir_bytes"],
        "file_count": budget["tmpdir_inodes"],
        "directory_count": budget["tmpdir_inodes"],
        "available_bytes": max_u64, "available_inodes": max_u64,
    })
    tmp_initial = template["tmpdir_initial"]
    require(type(tmp_initial) is dict and "available_bytes" in tmp_initial and
            "available_inodes" in tmp_initial,
            "initial ProbeV2 TMPDIR initial size projection is malformed")
    tmp_initial["available_bytes"] = max_u64
    tmp_initial["available_inodes"] = max_u64
    inventory_pin = exact(template["tmpdir_inventory_pin"], {
        "path", "raw_sha256", "inventory_sha256",
    }, "initial ProbeV2 receipt inventory size projection")
    inventory_pin.update({"raw_sha256": "f" * 64, "inventory_sha256": "f" * 64})
    return len(canonical(template))


def _validate_initial_probe_receipt_budget(
    receipt_value: object, receipt_raw: bytes, request_budget_value: object,
) -> dict[str, int]:
    receipt = exact(receipt_value, INITIAL_PROBE_EMISSION_RECEIPT_FIELDS,
                    "initial ProbeV2 receipt byte-budget value")
    budget = _validate_probe_storage_budget(request_budget_value)
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    require(receipt["receipt_sha256"] == sha256(canonical(body)) and
            receipt["storage_budget"] == budget and
            type(receipt_raw) is bytes and receipt_raw == canonical(receipt) and
            len(receipt_raw) <= MAX_PROBE_CAPTURE_RECEIPT_BYTES and
            len(receipt_raw) <= budget["receipt_bytes"] and
            _initial_probe_receipt_template_size(receipt) <= budget["receipt_bytes"],
            "initial ProbeV2 receipt exceeds or understates its original request byte reservation")
    return budget


def emit_initial_calibrated_probe_v2(
    request_pin: object, *, resource_monitor: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Emit the first calibrated ProbeV2 stdout under the Source-pinned owner."""
    require(resource_monitor is None or callable(resource_monitor),
            "initial ProbeV2 resource monitor must be callable or None")
    request, request_ref, request_raw = _read_initial_probe_request(request_pin)
    request = _validate_initial_probe_request(request)
    require(canonical(request) == request_raw,
            "initial ProbeV2 request changed during canonical validation")
    request = json.loads(canonical(request).decode("ascii"))
    source_and_evidence_pins = [
        request["source_manifest"], request["observed_host"],
        *request["capacity_bundle"].values(),
    ]
    require(not _path_is_within(SOURCE_ROOT, Path(request_ref["path"]),
                                "initial ProbeV2 request Source containment") and
            all(not _path_is_within(SOURCE_ROOT, Path(pin["path"]),
                                    "initial ProbeV2 evidence Source containment")
                for pin in source_and_evidence_pins),
            "initial ProbeV2 request and immutable evidence must remain outside SourceV5")
    budget = dict(request["storage_budget"])
    stack = _load_initial_probe_source_stack(request)
    (reader, producer, _controller, fixed, helper, capacity_stage, source, context,
     identity, source_pin, binary, source_binary_sha, binary_descriptor) = stack
    require(source_pin["raw_sha256"] == request["source_manifest"]["raw_sha256"],
            "initial ProbeV2 SourceV5 raw pin changed during full-source preflight")
    try:
        reader._validate_v2_workload_profile(context["workload"], context["profile"])
    except Exception as error:
        raise CompositionError(f"SourceV5 rejected initial ProbeV2 workload/profile: {error}") from error
    capacity_floor_policy_id = _validate_initial_probe_floor_policy(
        request, source, reader,
    )
    host, host_sha, origin_before = _initial_probe_host_context(
        request["observed_host"], context, source, capacity_stage,
    )
    bundle = request["capacity_bundle"]
    _capacity_request, _capacity_receipt, capacity_hashes = _verify_capacity_request_binding(
        reader, producer, source, context, identity, source_pin, bundle,
    )
    capacity_path = absolute_path(bundle["artifact"]["path"],
                                  "initial ProbeV2 capacity TSV path")
    output_base = fixed._private_output_root(
        request["output_root"], SOURCE_ROOT, create=False,
    )
    require(not _path_is_within(SOURCE_ROOT, output_base,
                                "initial ProbeV2 output Source containment"),
            "initial ProbeV2 output root must remain outside SourceV5")
    output_mount_base = fixed._mount_identity(output_base)
    emission_id = request["emission_id"]
    emission_dir = output_base / emission_id
    require(not emission_dir.exists() and not emission_dir.is_symlink(),
            "initial ProbeV2 emission directory must be fresh and unreused")
    try:
        emission_dir.mkdir(mode=0o700)
    except OSError as error:
        raise CompositionError(f"cannot create fresh initial ProbeV2 output directory: {error}") from error
    directory_info = emission_dir.stat(follow_symlinks=False)
    require(stat.S_ISDIR(directory_info.st_mode) and directory_info.st_uid == os.getuid() and
            stat.S_IMODE(directory_info.st_mode) == 0o700,
            "initial ProbeV2 emission directory is not an owned private directory")
    tmpdir = emission_dir / "tmp"
    stdout_path = emission_dir / "stdout.bin"
    stderr_path = emission_dir / "stderr.bin"
    owner_result_path = emission_dir / "owner-result.json"
    inventory_path = emission_dir / "tmpdir-inventory.json"
    receipt_path = emission_dir / "emission-receipt.json"
    failure_path = emission_dir / "capture-failure.json"

    budget_for_owner = {
        "tmpdir_bytes": budget["tmpdir_bytes"],
        "tmpdir_inodes": budget["tmpdir_inodes"],
    }
    try:
        initial_tmp = fixed._prepare_member_tmpdir(
            tmpdir, emission_dir, budget_for_owner,
        )
        output_mount_initial, output_reservation, inode_reservation = \
            _probe_output_mount_bounds(fixed, emission_dir, budget)
        require(fixed._mount_static(output_mount_initial) == initial_tmp["mount"] and
                output_mount_base["filesystem_type"] not in ("tmpfs", "ramfs", "devtmpfs"),
                "initial ProbeV2 output and TMP roots do not share a disk-backed mount")
        environment = {
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "TMPDIR": str(tmpdir),
        }
        argv = [
            str(binary), "--emit-feedback-policy-only", "--workload", context["workload"],
            "--profile", context["profile"], "--capacity-calibration-file", str(capacity_path),
            "--capacity-calibration-sha256", capacity_hashes["artifact"],
            "--host-id", context["host_id"], "--source-sha256", identity["source_sha256"],
        ]
        if capacity_floor_policy_id is not None:
            argv.extend(["--capacity-floor-policy-id", capacity_floor_policy_id])
        requested_launch = {
            "argv": argv, "environment": environment, "cwd": str(SOURCE_ROOT),
            "affinity": host["cpu_affinity"],
            "network_namespace_inode": host["network_namespace_inode"],
        }
        source_semantic_sha = digest(source["manifest_sha256"],
                                     "initial ProbeV2 SourceV5 semantic SHA-256")
        source_tree_sha = digest(source["source"]["source_tree_sha256"],
                                 "initial ProbeV2 SourceV5 tree SHA-256")
        source_build_sha = reader.digest_object(source["build"])
        origin_body = {
            "schema": "allocatbelt.application-feedback-probe-origin-facts.v1",
            "host_id": host["host_id"],
            "boot_id_sha256": origin_before["boot_id_sha256"],
            "kernel_release": origin_before["kernel_release"],
            "cpu_affinity": origin_before["cpu_affinity"],
            "network_namespace_inode": origin_before["network_namespace_inode"],
            "observed_host_raw_sha256": host_sha,
        }
        origin_record = {
            **origin_body, "origin_facts_sha256": sha256(canonical(origin_body)),
        }
        max_u64 = (1 << 64) - 1
        start_template = {
            "pid": (1 << 31) - 1, "start_ticks": max_u64,
            "requested_argv": argv,
            "requested_argv_sha256": "f" * 64,
            "environment_sha256": "f" * 64,
        }
        tmp_final_template = {
            "path": str(tmpdir), "device": max_u64, "inode": max_u64,
            "mode": 0o700, "mount": fixed._mount_static(output_mount_initial),
            "bytes_used": budget["tmpdir_bytes"],
            "file_count": budget["tmpdir_inodes"],
            "directory_count": budget["tmpdir_inodes"],
            "bytes_limit": budget["tmpdir_bytes"],
            "inode_limit": budget["tmpdir_inodes"],
            "available_bytes": max_u64, "available_inodes": max_u64,
        }
        output_mount_final_template = {
            **fixed._mount_static(output_mount_initial),
            "available_bytes": max_u64, "available_inodes": max_u64,
        }
        reader_record = reader._source_v5_regular_record(
            source["source"], FEEDBACK_READER, "feedback validator",
        )
        producer_record = reader._source_v5_regular_record(
            source["source"], CAPACITY_PRODUCER, "byte-capacity producer",
        )
        controller_record = reader._source_v5_regular_record(
            source["source"], "scripts/application-campaign.py", "campaign controller",
        )
        capacity_stage_record = reader._source_v5_regular_record(
            source["source"], "scripts/application-capacity-stage.py",
            "capacity host/process verifier",
        )
        fixed_record = reader._source_v5_regular_record(
            source["source"], FIXED_PAIR_OWNER, "FixedR8 direct process owner",
        )
        helper_record = reader._source_v5_regular_record(
            source["source"], PROBE_OWNER_HELPER, "launch identity helper",
        )
        composition_record = reader._source_v5_regular_record(
            source["source"], "scripts/application-feedback-composition.py",
            "feedback composition emitter",
        )
        owner_modules = {
            "feedback_reader": {"path": FEEDBACK_READER, "raw_sha256": reader_record["sha256"]},
            "capacity_producer": {"path": CAPACITY_PRODUCER, "raw_sha256": producer_record["sha256"]},
            "campaign_controller": {"path": "scripts/application-campaign.py",
                                    "raw_sha256": controller_record["sha256"]},
            "capacity_stage": {"path": "scripts/application-capacity-stage.py",
                               "raw_sha256": capacity_stage_record["sha256"]},
            "fixed_pair": {"path": FIXED_PAIR_OWNER, "raw_sha256": fixed_record["sha256"]},
            "launch_identity_helper": {"path": PROBE_OWNER_HELPER,
                                       "raw_sha256": helper_record["sha256"]},
            "feedback_composition": {
                "path": "scripts/application-feedback-composition.py",
                "raw_sha256": composition_record["sha256"],
            },
        }
        binary_template = {
            "path": str(binary), "source_relative_path": source["artifacts"][identity["allocator"]]["path"],
            "raw_sha256": source_binary_sha, "device": max_u64,
            "inode": max_u64, "size": max_u64,
        }
        receipt_template = {
        "schema": INITIAL_PROBE_EMISSION_SCHEMA,
        "role": INITIAL_PROBE_EMISSION_ROLE,
        "verification_scope": "origin_host_resident_paths",
            "request_pin": request_ref,
            "source_manifest": {
                "path": source_pin["path"], "raw_sha256": source_pin["raw_sha256"],
                "semantic_sha256": source_semantic_sha,
                "source_tree_sha256": source_tree_sha,
                "build_sha256": source_build_sha,
            },
            "context": context, "allocator": identity["allocator"],
            "capacity_bundle": bundle,
            "capacity_floor_policy_id": capacity_floor_policy_id,
            "binary": binary_template,
            "observed_host": {"path": request["observed_host"]["path"],
                              "raw_sha256": host_sha},
            "origin_facts_before": origin_record,
            "origin_facts_after": origin_record,
            "requested_launch": requested_launch,
            "start_callback_count": 1,
            "start_callback_proof": start_template,
            "owner_result_pin": {
                "path": str(owner_result_path), "raw_sha256": "f" * 64,
                "owner_result_sha256": "f" * 64,
            },
            "owner_supervision_sha256": "f" * 64,
            "stdout": {"path": str(stdout_path), "raw_sha256": "f" * 64,
                       "byte_count": budget["stdout_bytes"]},
            "stderr": {"path": str(stderr_path), "raw_sha256": "f" * 64,
                       "byte_count": budget["stderr_bytes"]},
            "construction_probe": {
                "path": str(stdout_path), "raw_sha256": "f" * 64,
                "allocator": identity["allocator"],
                "binary_sha256": source_binary_sha,
            },
            "resolved_policy_sha256": "f" * 64,
            "timeout_ns": request["timeout_ns"], "storage_budget": budget,
            "output_mount_initial": output_mount_initial,
            "output_mount_final": output_mount_final_template,
            "tmpdir_initial": initial_tmp, "tmpdir_final": tmp_final_template,
            "tmpdir_inventory_pin": {
                "path": str(inventory_path), "raw_sha256": "f" * 64,
                "inventory_sha256": "f" * 64,
            },
            "owner_modules": owner_modules,
            "exit_status": (1 << 31) - 1,
            "qualification_eligible": False, "execution_ready": False,
            "controller_chronology_proven": False, "receipt_sha256": "f" * 64,
        }
        require(_initial_probe_receipt_template_size(receipt_template) <=
                budget["receipt_bytes"],
                "initial ProbeV2 receipt budget is below its complete bounded template")
        fixed._require_waitable_sigchld()
        if resource_monitor is not None:
            try:
                monitor_stop = bool(resource_monitor())
            except BaseException as error:
                path = _initial_probe_failure_record(
                    emission_dir, emission_id, "resource_monitor_prelaunch", error,
                    stdout_path, stderr_path, budget,
                )
                raise CompositionError(
                    f"initial ProbeV2 outer resource monitor failed; failure retained at {path}: {error}",
                ) from error
            if monitor_stop:
                failure = CompositionError(
                    "initial ProbeV2 outer resource monitor refused before Popen",
                )
                path = _initial_probe_failure_record(
                    emission_dir, emission_id, "resource_monitor_prelaunch", failure,
                    stdout_path, stderr_path, budget,
                )
                raise CompositionError(f"{failure}; failure retained at {path}")
        started: list[dict[str, Any]] = []
        tmpdir_monitor = fixed._bounded_tmpdir_monitor(
            tmpdir, budget["tmpdir_bytes"], budget["tmpdir_inodes"],
            expected_root=initial_tmp,
        )

        def combined_resource_monitor() -> bool:
            tmpdir_stop = bool(tmpdir_monitor())
            outer_stop = bool(resource_monitor()) if resource_monitor is not None else False
            return tmpdir_stop or outer_stop

        try:
            direct = fixed._run_direct_process(
                argv, binary, source_binary_sha, SOURCE_ROOT, environment,
                host["cpu_affinity"], stdout_path, stderr_path,
                budget["stdout_bytes"], budget["stderr_bytes"],
                request["timeout_ns"] / 1_000_000_000, helper,
                expected_tmpdir=tmpdir,
                expected_network_inode=host["network_namespace_inode"],
                on_started=lambda proof: started.append(proof),
                capture_identity=False, resource_monitor=combined_resource_monitor,
            )
        except BaseException as error:
            try:
                retained = _initial_probe_failure_record(
                    emission_dir, emission_id, "owner_process_supervision", error,
                    stdout_path, stderr_path, budget,
                )
            except BaseException as record_error:
                raise CompositionError(
                    f"FixedR8 initial ProbeV2 owner raised {type(error).__name__}: {error}; "
                    f"failure record also failed: {record_error}",
                ) from error
            raise CompositionError(
                f"FixedR8 initial ProbeV2 owner raised {type(error).__name__}: {error}; "
                f"failure retained at {retained}",
            ) from error

        # Preserve the direct owner return before interpreting its result or outputs.
        try:
            owner_result, owner_result_raw = _probe_owner_result(direct, started)
        except BaseException as error:
            retained = _initial_probe_failure_record(
                emission_dir, emission_id, "owner_result_serialize", error,
                stdout_path, stderr_path, budget,
            )
            raise CompositionError(
                f"initial ProbeV2 owner returned nonserializable evidence; failure retained at {retained}",
            ) from error
        owner_result_sha = sha256(owner_result_raw)
        if len(owner_result_raw) > budget["owner_result_bytes"]:
            supervision = direct.get("supervision", {}) if type(direct) is dict else {}
            overflow = {
                "raw_sha256": owner_result_sha, "byte_length": len(owner_result_raw),
                "status": direct.get("status") if type(direct) is dict else None,
                "child_return_code": direct.get("child_return_code") if type(direct) is dict else None,
                "cleanup_status": supervision.get("cleanup_status") if type(supervision) is dict else None,
                "signal_record_count": len(supervision.get("signals", []))
                if type(supervision.get("signals")) is list else None,
                "start_callback_count": len(started),
            }
            failure = CompositionError(
                "complete initial ProbeV2 FixedR8 owner result exceeds its reserved bound",
            )
            retained = _initial_probe_failure_record(
                emission_dir, emission_id, "owner_result_budget", failure,
                stdout_path, stderr_path, budget,
                owner_result_overflow=overflow,
            )
            raise CompositionError(f"{failure}; bounded diagnostic retained at {retained}")
        try:
            _write_exclusive(owner_result_path, owner_result_raw)
            owner_readback, owner_readback_sha = _read_stable(
                owner_result_path, "persisted initial ProbeV2 owner result",
                budget["owner_result_bytes"],
            )
            _require_initial_probe_private_output(
                owner_result_path, "persisted initial ProbeV2 owner result",
            )
            require(owner_readback == owner_result_raw and owner_readback_sha == owner_result_sha,
                    "persisted initial ProbeV2 owner result differs from the complete direct return")
        except BaseException as error:
            supervision = direct.get("supervision", {}) if type(direct) is dict else {}
            overflow = {
                "raw_sha256": owner_result_sha, "byte_length": len(owner_result_raw),
                "status": direct.get("status") if type(direct) is dict else None,
                "child_return_code": direct.get("child_return_code") if type(direct) is dict else None,
                "cleanup_status": supervision.get("cleanup_status") if type(supervision) is dict else None,
                "signal_record_count": len(supervision.get("signals", []))
                if type(supervision.get("signals")) is list else None,
                "start_callback_count": len(started),
            }
            try:
                retained = _initial_probe_failure_record(
                    emission_dir, emission_id, "owner_result_persist", error,
                    stdout_path, stderr_path, budget,
                    owner_result_overflow=overflow,
                )
            except BaseException as record_error:
                raise CompositionError(
                    f"initial ProbeV2 owner result could not be persisted ({error}); "
                    f"overflow diagnostic also failed: {record_error}",
                ) from error
            raise CompositionError(
                f"initial ProbeV2 owner result could not be persisted; bounded failure retained at {retained}",
            ) from error
        owner_result_pin = {
            "path": str(owner_result_path), "raw_sha256": owner_result_sha,
            "owner_result_sha256": owner_result["owner_result_sha256"],
        }
        inventory_pin: dict[str, str] | None = None
        try:
            start, opened_binary_descriptor = _validate_initial_probe_owner_return(
                direct, started, argv=argv, environment=environment,
                cwd=SOURCE_ROOT, affinity=host["cpu_affinity"],
                network_namespace_inode=host["network_namespace_inode"],
                binary=binary, binary_sha256=source_binary_sha,
                binary_descriptor=binary_descriptor,
                maximum_binary_size=reader.MAX_APP_BINARY_BYTES,
                fixed=fixed, capacity_stage=capacity_stage,
            )
            stdout_raw, stdout_sha = _read_stable(
                stdout_path, "initial calibrated ProbeV2 stdout", reader.MAX_PROBE_OUTPUT_BYTES,
            )
            stderr_raw, stderr_sha = _read_stable(
                stderr_path, "initial calibrated ProbeV2 stderr", reader.MAX_PROBE_OUTPUT_BYTES,
            )
            _require_initial_probe_private_output(stdout_path, "initial ProbeV2 stdout")
            _require_initial_probe_private_output(stderr_path, "initial ProbeV2 stderr")
            require(len(stdout_raw) <= budget["stdout_bytes"] and
                    len(stderr_raw) <= budget["stderr_bytes"] and not stderr_raw,
                    "initial ProbeV2 stdout/stderr does not fit the reserved outputs or stderr is nonempty")
            probe, probe_raw, probe_sha = _read_canonical(
                stdout_path, "first calibrated ProbeV2 stdout", stdout_sha,
                reader.MAX_PROBE_OUTPUT_BYTES,
            )
            require(probe_raw == stdout_raw and probe_sha == stdout_sha and
                    probe["schema"] == reader.CALIBRATED_PROBE_SCHEMA_V2,
                    "first owner stdout is not one canonical calibrated ProbeV2 JSON value")
            policy = reader.resolve_calibrated_feedback_policy_v5(
                source, probe, bundle["artifact"], identity,
                capacity_floor_policy_id=capacity_floor_policy_id,
            )
            reader._validate_calibrated_construction_evidence(source, probe, identity)
            policy_sha = reader.digest_object(policy)
            host_after, host_after_sha, origin_after = _initial_probe_host_context(
                request["observed_host"], context, source, capacity_stage,
            )
            require(host_after_sha == host_sha and origin_after == origin_before and
                    host_after == host,
                    "initial ProbeV2 host identity changed during the owned constructor")

            # Reopen all original immutable pins after the process returns.
            post_request, post_request_ref, post_request_raw = _read_initial_probe_request(
                request_ref,
            )
            require(post_request_ref == request_ref and post_request_raw == request_raw and
                    _validate_initial_probe_request(post_request) == request,
                    "initial ProbeV2 request changed during constructor execution")
            post_stack = _load_initial_probe_source_stack(request)
            (post_reader, post_producer, _post_controller, _post_fixed,
             _post_helper, _post_stage, post_source, post_context, post_identity,
             post_source_pin, post_binary, post_binary_sha,
             post_binary_descriptor) = post_stack
            require(post_source_pin == source_pin and post_context == context and
                    post_identity == identity and post_binary == binary and
                    post_binary_sha == source_binary_sha and
                    post_binary_descriptor == binary_descriptor and
                    post_source == source,
                    "SourceV5 identity changed during initial ProbeV2 emission")
            _post_request, _post_capacity_receipt, post_capacity_hashes = \
                _verify_capacity_request_binding(
                    post_reader, post_producer, post_source, post_context, post_identity,
                    post_source_pin, bundle,
                )
            require(post_capacity_hashes == capacity_hashes and
                    _validate_initial_probe_floor_policy(request, post_source, post_reader) ==
                    capacity_floor_policy_id,
                    "capacity/floor inputs changed during initial ProbeV2 emission")

            tmpdir_final = fixed._tmpdir_usage(tmpdir, {
                "bytes_limit": budget["tmpdir_bytes"],
                "inode_limit": budget["tmpdir_inodes"],
            })
            fixed._verify_tmpdir_storage(
                initial_tmp, tmpdir_final, str(tmpdir), budget["tmpdir_bytes"],
                budget["tmpdir_inodes"], "initial calibrated ProbeV2 constructor",
            )
            entries = _capture_tmpdir_inventory(
                tmpdir, budget["tmpdir_bytes"], budget["tmpdir_inodes"],
            )
            inventory_body = {"schema": PROBE_TMPDIR_INVENTORY_SCHEMA, "entries": entries}
            inventory_value = {
                **inventory_body, "inventory_sha256": sha256(canonical(inventory_body)),
            }
            inventory_raw = canonical(inventory_value)
            require(len(inventory_raw) <= budget["inventory_bytes"],
                    "initial ProbeV2 TMPDIR inventory exceeds its reserved sidecar bound")
            _write_exclusive(inventory_path, inventory_raw)
            _require_initial_probe_private_output(
                inventory_path, "initial ProbeV2 TMPDIR inventory",
            )
            inventory_pin = {
                "path": str(inventory_path), "raw_sha256": sha256(inventory_raw),
                "inventory_sha256": inventory_value["inventory_sha256"],
            }
            _verify_initial_probe_success_layout(
                emission_dir, budget, include_receipt=False,
            )
            output_mount_final = fixed._mount_identity(emission_dir)
            require(fixed._mount_static(output_mount_final) ==
                    fixed._mount_static(output_mount_initial) and
                    output_mount_final["available_bytes"] >= output_reservation and
                    output_mount_final["available_inodes"] >= inode_reservation,
                    "initial ProbeV2 output mount fell below its complete reserved budget")
            require(_live_probe_origin_facts(host) == origin_before,
                    "initial ProbeV2 live boot/kernel/affinity/netns changed before receipt sealing")
            binary_info = {
                "path": str(binary),
                "source_relative_path": source["artifacts"][identity["allocator"]]["path"],
                "raw_sha256": source_binary_sha,
                "device": opened_binary_descriptor["device"],
                "inode": opened_binary_descriptor["inode"],
                "size": opened_binary_descriptor["size"],
            }
            receipt_body = {
                "schema": INITIAL_PROBE_EMISSION_SCHEMA,
                "role": INITIAL_PROBE_EMISSION_ROLE,
                "verification_scope": "origin_host_resident_paths",
                "request_pin": request_ref,
                "source_manifest": {
                    "path": source_pin["path"], "raw_sha256": source_pin["raw_sha256"],
                    "semantic_sha256": source_semantic_sha,
                    "source_tree_sha256": source_tree_sha,
                    "build_sha256": source_build_sha,
                },
                "context": context, "allocator": identity["allocator"],
                "capacity_bundle": bundle,
                "capacity_floor_policy_id": capacity_floor_policy_id,
                "binary": binary_info,
                "observed_host": {
                    "path": request["observed_host"]["path"], "raw_sha256": host_sha,
                },
                "origin_facts_before": origin_record,
                "origin_facts_after": origin_record,
                "requested_launch": requested_launch,
                "start_callback_count": len(started),
                "start_callback_proof": start,
                "owner_result_pin": owner_result_pin,
                "owner_supervision_sha256": sha256(canonical(direct["supervision"])),
                "stdout": {
                    "path": str(stdout_path), "raw_sha256": stdout_sha,
                    "byte_count": len(stdout_raw),
                },
                "stderr": {
                    "path": str(stderr_path), "raw_sha256": stderr_sha,
                    "byte_count": len(stderr_raw),
                },
                "construction_probe": {
                    "path": str(stdout_path), "raw_sha256": stdout_sha,
                    "allocator": identity["allocator"],
                    "binary_sha256": source_binary_sha,
                },
                "resolved_policy_sha256": policy_sha,
                "timeout_ns": request["timeout_ns"], "storage_budget": budget,
                "output_mount_initial": output_mount_initial,
                "output_mount_final": output_mount_final,
                "tmpdir_initial": initial_tmp, "tmpdir_final": tmpdir_final,
                "tmpdir_inventory_pin": inventory_pin,
                "owner_modules": owner_modules,
                "exit_status": direct["status"],
                "qualification_eligible": False, "execution_ready": False,
                "controller_chronology_proven": False,
            }
            receipt_value, receipt_raw = _seal_initial_probe_emission_receipt(receipt_body)
            _validate_initial_probe_receipt_budget(
                receipt_value, receipt_raw, budget,
            )
            receipt_identity = _write_initial_probe_receipt_exclusive(
                receipt_path, receipt_raw,
            )
            try:
                receipt_raw_check, receipt_raw_sha = _read_stable(
                    receipt_path, "initial ProbeV2 emission receipt", budget["receipt_bytes"],
                )
                require(receipt_raw_check == receipt_raw and
                        receipt_raw_sha == sha256(receipt_raw),
                        "initial ProbeV2 emission receipt differs after exclusive persistence")
                final_mount_after_receipt = fixed._mount_identity(emission_dir)
                require(fixed._mount_static(final_mount_after_receipt) ==
                        fixed._mount_static(output_mount_initial) and
                        final_mount_after_receipt["available_bytes"] >= output_reservation and
                        final_mount_after_receipt["available_inodes"] >= inode_reservation,
                        "initial ProbeV2 output mount fell below its complete budget after receipt persistence")
                _verify_initial_probe_success_layout(
                    emission_dir, budget, include_receipt=True,
                )
            except BaseException:
                try:
                    _unlink_exact_output(receipt_path, receipt_identity)
                except Exception:
                    pass
                raise
            receipt_pin = {
                "path": str(receipt_path), "raw_sha256": receipt_raw_sha,
                "receipt_sha256": receipt_value["receipt_sha256"],
            }
            return {
                "construction_probe": receipt_value["construction_probe"],
                "emission_receipt": receipt_pin,
            }
        except BaseException as error:
            if not failure_path.exists():
                try:
                    retained = _initial_probe_failure_record(
                        emission_dir, emission_id, "post_owner_validation", error,
                        stdout_path, stderr_path, budget, owner_result_pin,
                        inventory_pin=inventory_pin,
                    )
                except BaseException as record_error:
                    raise CompositionError(
                        f"initial ProbeV2 validation failed after owner return ({error}); "
                        f"owner result remains at {owner_result_path}; failure record failed: {record_error}",
                    ) from error
                raise CompositionError(
                    f"initial ProbeV2 validation failed after owner return ({error}); "
                    f"owner result and failure evidence remain at {retained}",
                ) from error
            raise
    except BaseException as error:
        if failure_path.exists():
            raise
        try:
            retained = _initial_probe_failure_record(
                emission_dir, emission_id, "initial_probe_preflight_or_storage", error,
                stdout_path, stderr_path, budget,
            )
        except BaseException as record_error:
            raise CompositionError(
                f"initial ProbeV2 preflight/storage failed ({error}); failure record also failed: {record_error}",
            ) from error
        raise CompositionError(
            f"initial ProbeV2 preflight/storage failed ({error}); failure evidence retained at {retained}",
        ) from error


def verify_initial_calibrated_probe_emission(receipt_pin: object) -> dict[str, Any]:
    """Replay an origin-host receipt without launching its APP constructor again."""
    receipt_ref = exact(receipt_pin, {"path", "raw_sha256", "receipt_sha256"},
                        "initial ProbeV2 emission receipt pin")
    receipt_path = absolute_path(receipt_ref["path"], "initial ProbeV2 emission receipt path")
    digest(receipt_ref["raw_sha256"], "initial ProbeV2 receipt raw SHA-256")
    digest(receipt_ref["receipt_sha256"], "initial ProbeV2 receipt semantic SHA-256")
    receipt, receipt_raw, receipt_raw_sha = _read_canonical(
        receipt_path, "initial ProbeV2 emission receipt", receipt_ref["raw_sha256"],
        MAX_PROBE_CAPTURE_RECEIPT_BYTES,
    )
    receipt = exact(receipt, INITIAL_PROBE_EMISSION_RECEIPT_FIELDS,
                    "initial ProbeV2 emission receipt")
    receipt_body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    require(receipt["schema"] == INITIAL_PROBE_EMISSION_SCHEMA and
            receipt["role"] == INITIAL_PROBE_EMISSION_ROLE and
            receipt["verification_scope"] == "origin_host_resident_paths" and
            receipt["receipt_sha256"] == sha256(canonical(receipt_body)) ==
            receipt_ref["receipt_sha256"] and receipt_raw_sha == receipt_ref["raw_sha256"] and
            receipt_raw == canonical(receipt),
            "initial ProbeV2 emission receipt schema, raw pin, or semantic digest differs")
    require(receipt["qualification_eligible"] is False and
            receipt["execution_ready"] is False and
            receipt["controller_chronology_proven"] is False and
            receipt["exit_status"] == 0,
            "initial ProbeV2 receipt claims readiness or lacks a successful constructor return")
    receipt_info = receipt_path.stat(follow_symlinks=False)
    require(stat.S_ISREG(receipt_info.st_mode) and receipt_info.st_uid == os.getuid() and
            receipt_info.st_nlink == 1 and stat.S_IMODE(receipt_info.st_mode) == 0o600,
            "initial ProbeV2 receipt is not a private immutable regular file")

    request_ref = exact(receipt["request_pin"], {"path", "raw_sha256"},
                        "initial ProbeV2 receipt request pin")
    request, request_ref_read, _request_raw = _read_initial_probe_request(request_ref)
    request = _validate_initial_probe_request(request)
    require(request_ref_read == request_ref and request["emission_id"] == receipt_path.parent.name,
            "initial ProbeV2 receipt is detached from its exact original request/emission ID")
    verify_inputs = [request["source_manifest"], request["observed_host"],
                     *request["capacity_bundle"].values()]
    require(not _path_is_within(SOURCE_ROOT, Path(request_ref["path"]),
                                "initial ProbeV2 receipt request Source containment") and
            all(not _path_is_within(SOURCE_ROOT, Path(pin["path"]),
                                    "initial ProbeV2 receipt input Source containment")
                for pin in verify_inputs),
            "initial ProbeV2 receipt inputs are inside the immutable Source")
    request_budget = _validate_probe_storage_budget(request["storage_budget"])
    _validate_initial_probe_receipt_budget(
        receipt, receipt_raw, request_budget,
    )
    (reader, producer, controller, fixed, helper, capacity_stage, source, context,
     identity, source_pin, binary, binary_sha,
     binary_descriptor) = _load_initial_probe_source_stack(request)
    source_value = {
        "path": source_pin["path"], "raw_sha256": source_pin["raw_sha256"],
        "semantic_sha256": source["manifest_sha256"],
        "source_tree_sha256": source["source"]["source_tree_sha256"],
        "build_sha256": reader.digest_object(source["build"]),
    }
    require(receipt["source_manifest"] == source_value and
            receipt["context"] == context and receipt["allocator"] == identity["allocator"] and
            receipt["capacity_bundle"] == request["capacity_bundle"] and
            receipt["capacity_floor_policy_id"] ==
                _validate_initial_probe_floor_policy(request, source, reader),
            "initial ProbeV2 receipt Source/context/capacity/floor binding differs")
    require(receipt["timeout_ns"] == request["timeout_ns"] and
            receipt["storage_budget"] == request["storage_budget"],
            "initial ProbeV2 receipt timeout or storage reservation differs from its request")
    expected_owner_modules = {
        "feedback_reader": {
            "path": FEEDBACK_READER,
            "raw_sha256": reader._source_v5_regular_record(
                source["source"], FEEDBACK_READER, "feedback validator",
            )["sha256"],
        },
        "capacity_producer": {
            "path": CAPACITY_PRODUCER,
            "raw_sha256": reader._source_v5_regular_record(
                source["source"], CAPACITY_PRODUCER, "byte-capacity producer",
            )["sha256"],
        },
        "campaign_controller": {
            "path": "scripts/application-campaign.py",
            "raw_sha256": reader._source_v5_regular_record(
                source["source"], "scripts/application-campaign.py", "campaign controller",
            )["sha256"],
        },
        "capacity_stage": {
            "path": "scripts/application-capacity-stage.py",
            "raw_sha256": reader._source_v5_regular_record(
                source["source"], "scripts/application-capacity-stage.py",
                "capacity host/process verifier",
            )["sha256"],
        },
        "fixed_pair": {
            "path": FIXED_PAIR_OWNER,
            "raw_sha256": reader._source_v5_regular_record(
                source["source"], FIXED_PAIR_OWNER, "FixedR8 direct process owner",
            )["sha256"],
        },
        "launch_identity_helper": {
            "path": PROBE_OWNER_HELPER,
            "raw_sha256": reader._source_v5_regular_record(
                source["source"], PROBE_OWNER_HELPER, "launch identity helper",
            )["sha256"],
        },
        "feedback_composition": {
            "path": "scripts/application-feedback-composition.py",
            "raw_sha256": reader._source_v5_regular_record(
                source["source"], "scripts/application-feedback-composition.py",
                "feedback composition emitter",
            )["sha256"],
        },
    }
    require(receipt["owner_modules"] == expected_owner_modules,
            "initial ProbeV2 receipt owner/module hashes differ from SourceV5 inventory")

    host, host_sha, origin = _initial_probe_host_context(
        request["observed_host"], context, source, capacity_stage,
    )
    require(receipt["observed_host"] == {
        "path": request["observed_host"]["path"], "raw_sha256": host_sha,
    }, "initial ProbeV2 receipt observed-host pin differs")
    for label in ("origin_facts_before", "origin_facts_after"):
        item = exact(receipt[label], {
            "schema", "host_id", "boot_id_sha256", "kernel_release", "cpu_affinity",
            "network_namespace_inode", "observed_host_raw_sha256", "origin_facts_sha256",
        }, f"initial ProbeV2 {label}")
        body = {key: value for key, value in item.items() if key != "origin_facts_sha256"}
        require(item["schema"] == "allocatbelt.application-feedback-probe-origin-facts.v1" and
                item["host_id"] == host["host_id"] and
                item["boot_id_sha256"] == origin["boot_id_sha256"] and
                item["kernel_release"] == origin["kernel_release"] and
                item["cpu_affinity"] == origin["cpu_affinity"] and
                item["network_namespace_inode"] == origin["network_namespace_inode"] and
                item["observed_host_raw_sha256"] == host_sha and
                item["origin_facts_sha256"] == sha256(canonical(body)),
                f"initial ProbeV2 {label} differs from current live origin facts")
    require(receipt["origin_facts_before"] == receipt["origin_facts_after"],
            "initial ProbeV2 origin identity changed during constructor execution")

    bundle = request["capacity_bundle"]
    _capacity_request, _capacity_receipt, capacity_hashes = _verify_capacity_request_binding(
        reader, producer, source, context, identity, source_pin, bundle,
    )
    capacity_path = absolute_path(bundle["artifact"]["path"],
                                  "initial ProbeV2 capacity TSV path")
    output_base = fixed._private_output_root(request["output_root"], SOURCE_ROOT, create=False)
    require(not _path_is_within(SOURCE_ROOT, output_base,
                                "initial ProbeV2 receipt output Source containment"),
            "initial ProbeV2 receipt output root is inside SourceV5")
    emission_dir = output_base / request["emission_id"]
    require(receipt_path == emission_dir / "emission-receipt.json" and
            receipt_path.parent == emission_dir and
            stat.S_IMODE(emission_dir.stat(follow_symlinks=False).st_mode) == 0o700,
            "initial ProbeV2 receipt path is outside its exact private emission directory")
    paths = {
        "stdout": emission_dir / "stdout.bin",
        "stderr": emission_dir / "stderr.bin",
        "owner_result": emission_dir / "owner-result.json",
        "inventory": emission_dir / "tmpdir-inventory.json",
        "tmpdir": emission_dir / "tmp",
    }
    budget = request_budget
    _verify_initial_probe_success_layout(
        emission_dir, budget, include_receipt=True,
    )

    expected_argv = [
        str(binary), "--emit-feedback-policy-only", "--workload", context["workload"],
        "--profile", context["profile"], "--capacity-calibration-file", str(capacity_path),
        "--capacity-calibration-sha256", capacity_hashes["artifact"],
        "--host-id", context["host_id"], "--source-sha256", identity["source_sha256"],
    ]
    floor_id = receipt["capacity_floor_policy_id"]
    if floor_id is not None:
        expected_argv.extend(["--capacity-floor-policy-id", floor_id])
    expected_environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "TMPDIR": str(paths["tmpdir"]),
    }
    launch = exact(receipt["requested_launch"], {
        "argv", "environment", "cwd", "affinity", "network_namespace_inode",
    }, "initial ProbeV2 requested launch")
    require(launch == {
        "argv": expected_argv, "environment": expected_environment,
        "cwd": str(SOURCE_ROOT), "affinity": host["cpu_affinity"],
        "network_namespace_inode": host["network_namespace_inode"],
    }, "initial ProbeV2 receipt requested argv/environment differs from Source/capacity/host")

    owner_pin = exact(receipt["owner_result_pin"], {
        "path", "raw_sha256", "owner_result_sha256",
    }, "initial ProbeV2 owner result pin")
    require(owner_pin["path"] == str(paths["owner_result"]),
            "initial ProbeV2 owner result path differs from its private directory")
    owner_result, owner_raw, owner_raw_sha = _read_canonical(
        paths["owner_result"], "initial ProbeV2 owner result", owner_pin["raw_sha256"],
        MAX_PROBE_OWNER_RESULT_BYTES,
    )
    _require_initial_probe_private_output(paths["owner_result"],
                                          "initial ProbeV2 owner result")
    owner_result = exact(owner_result, {
        "schema", "direct", "start_callback_count", "start_callback_proofs",
        "owner_result_sha256",
    }, "initial ProbeV2 owner result")
    owner_body = {key: item for key, item in owner_result.items()
                  if key != "owner_result_sha256"}
    require(owner_result["schema"] == PROBE_OWNER_RESULT_SCHEMA and
            owner_result["owner_result_sha256"] == sha256(canonical(owner_body)) ==
            owner_pin["owner_result_sha256"] and owner_raw_sha == owner_pin["raw_sha256"] and
            owner_raw == canonical(owner_result) and
            owner_result["start_callback_count"] == receipt["start_callback_count"] == 1,
            "initial ProbeV2 complete owner result raw/self digest or callback count differs")
    direct = owner_result["direct"]
    require(type(direct) is dict and type(owner_result["start_callback_proofs"]) is list and
            owner_result["start_callback_proofs"] == [receipt["start_callback_proof"]],
            "initial ProbeV2 owner result lacks its exact actual start callback")
    start, opened_descriptor = _validate_initial_probe_owner_return(
        direct, owner_result["start_callback_proofs"], argv=expected_argv,
        environment=expected_environment, cwd=SOURCE_ROOT,
        affinity=host["cpu_affinity"],
        network_namespace_inode=host["network_namespace_inode"],
        binary=binary, binary_sha256=binary_sha,
        binary_descriptor=binary_descriptor,
        maximum_binary_size=reader.MAX_APP_BINARY_BYTES,
        fixed=fixed, capacity_stage=capacity_stage,
    )
    require(start == receipt["start_callback_proof"],
            "initial ProbeV2 minimal start proof differs from the actual request")
    binary_receipt = exact(receipt["binary"], {
        "path", "source_relative_path", "raw_sha256", "device", "inode", "size",
    }, "initial ProbeV2 opened binary identity")
    _validate_initial_probe_binary_identity(
        binary_receipt, expected_path=binary,
        source_relative_path=source["artifacts"][identity["allocator"]]["path"],
        expected_sha256=binary_sha, expected_descriptor=binary_descriptor,
        maximum_size=reader.MAX_APP_BINARY_BYTES,
    )
    require(opened_descriptor == binary_descriptor and
            receipt["owner_supervision_sha256"] == sha256(canonical(direct["supervision"])),
            "initial ProbeV2 direct owner return differs from its bound ELF/supervision proof")

    stdout_pin = exact(receipt["stdout"], {"path", "raw_sha256", "byte_count"},
                       "initial ProbeV2 stdout pin")
    stderr_pin = exact(receipt["stderr"], {"path", "raw_sha256", "byte_count"},
                       "initial ProbeV2 stderr pin")
    require(stdout_pin["path"] == str(paths["stdout"]) and
            stderr_pin["path"] == str(paths["stderr"]),
            "initial ProbeV2 stdout/stderr paths differ from the exact output directory")
    stdout_raw, stdout_sha = _read_stable(
        paths["stdout"], "initial ProbeV2 stdout", reader.MAX_PROBE_OUTPUT_BYTES,
    )
    stderr_raw, stderr_sha = _read_stable(
        paths["stderr"], "initial ProbeV2 stderr", reader.MAX_PROBE_OUTPUT_BYTES,
    )
    _require_initial_probe_private_output(paths["stdout"], "initial ProbeV2 stdout")
    _require_initial_probe_private_output(paths["stderr"], "initial ProbeV2 stderr")
    require(receipt["storage_budget"] == budget,
            "initial ProbeV2 receipt storage budget changed after request replay")
    require(len(stdout_raw) == stdout_pin["byte_count"] <= budget["stdout_bytes"] and
            stdout_sha == stdout_pin["raw_sha256"] and
            len(stderr_raw) == stderr_pin["byte_count"] <= budget["stderr_bytes"] and
            stderr_sha == stderr_pin["raw_sha256"] and not stderr_raw,
            "initial ProbeV2 output raw pins, sizes, or empty-stderr condition differ")
    probe_pin = exact(receipt["construction_probe"], {
        "path", "raw_sha256", "allocator", "binary_sha256",
    }, "initial ProbeV2 construction-probe result pin")
    require(probe_pin == {
        "path": str(paths["stdout"]), "raw_sha256": stdout_sha,
        "allocator": identity["allocator"], "binary_sha256": binary_sha,
    }, "initial ProbeV2 result pin does not point to the actual first stdout")
    probe, probe_raw, probe_sha = _read_canonical(
        paths["stdout"], "initial calibrated ProbeV2", stdout_sha,
        reader.MAX_PROBE_OUTPUT_BYTES,
    )
    require(probe_raw == stdout_raw and probe_sha == stdout_sha and
            probe.get("schema") == reader.CALIBRATED_PROBE_SCHEMA_V2,
            "initial ProbeV2 stdout is not canonical calibrated ProbeV2 JSON")
    checked_sha, checked_probe, _binary, _root, _capacity_sha, _capacity_path = \
        reader._check_calibrated_construction_probe_v2_inputs(
            probe_pin, source, bundle["artifact"], identity,
            capacity_floor_policy_id=floor_id,
        )
    require(checked_sha == probe_sha and checked_probe == probe,
            "SourceV5 static ProbeV2 checker returned different first stdout bytes")
    policy = reader.resolve_calibrated_feedback_policy_v5(
        source, probe, bundle["artifact"], identity,
        capacity_floor_policy_id=floor_id,
    )
    reader._validate_calibrated_construction_evidence(source, probe, identity)
    require(receipt["resolved_policy_sha256"] == reader.digest_object(policy),
            "initial ProbeV2 resolved numeric policy digest differs")

    inventory_pin = exact(receipt["tmpdir_inventory_pin"], {
        "path", "raw_sha256", "inventory_sha256",
    }, "initial ProbeV2 TMPDIR inventory pin")
    require(inventory_pin["path"] == str(emission_dir / "tmpdir-inventory.json"),
            "initial ProbeV2 TMPDIR inventory path differs")
    inventory, inventory_raw, inventory_raw_sha = _read_canonical(
        Path(inventory_pin["path"]), "initial ProbeV2 TMPDIR inventory",
        inventory_pin["raw_sha256"], budget["inventory_bytes"],
    )
    _require_initial_probe_private_output(Path(inventory_pin["path"]),
                                          "initial ProbeV2 TMPDIR inventory")
    inventory = exact(inventory, {"schema", "entries", "inventory_sha256"},
                      "initial ProbeV2 TMPDIR inventory")
    inventory_body = {key: item for key, item in inventory.items()
                      if key != "inventory_sha256"}
    require(inventory["schema"] == PROBE_TMPDIR_INVENTORY_SCHEMA and
            inventory["inventory_sha256"] == sha256(canonical(inventory_body)) ==
            inventory_pin["inventory_sha256"] and inventory_raw_sha == inventory_pin["raw_sha256"] and
            inventory_raw == canonical(inventory),
            "initial ProbeV2 TMPDIR inventory raw/self digest differs")
    initial_tmp = receipt["tmpdir_initial"]
    final_tmp = receipt["tmpdir_final"]
    fixed._verify_tmpdir_storage(
        initial_tmp, final_tmp, str(paths["tmpdir"]), budget["tmpdir_bytes"],
        budget["tmpdir_inodes"], "initial ProbeV2 emission receipt",
    )
    actual_entries = _capture_tmpdir_inventory(
        paths["tmpdir"], budget["tmpdir_bytes"], budget["tmpdir_inodes"],
    )
    require(inventory["entries"] == actual_entries,
            "initial ProbeV2 TMPDIR inventory differs from current owned descendants")
    output_reservation = sum(budget[key] for key in (
        "tmpdir_bytes", "stdout_bytes", "stderr_bytes", "owner_result_bytes",
        "inventory_bytes", "failure_bytes", "receipt_bytes",
    ))
    inode_reservation = budget["tmpdir_inodes"] + budget["output_inodes"]
    initial_mount = receipt["output_mount_initial"]
    final_mount = receipt["output_mount_final"]
    static_initial = fixed._mount_static(initial_mount)
    static_final = fixed._mount_static(final_mount)
    require(static_initial == static_final and
            initial_mount["available_bytes"] >= output_reservation and
            initial_mount["available_inodes"] >= inode_reservation and
            final_mount["available_bytes"] >= output_reservation and
            final_mount["available_inodes"] >= inode_reservation,
            "initial ProbeV2 output mount proof is below its complete reservation")
    current_mount = fixed._mount_identity(emission_dir)
    require(fixed._mount_static(current_mount) == static_initial and
            current_mount["available_bytes"] >= output_reservation and
            current_mount["available_inodes"] >= inode_reservation,
            "initial ProbeV2 output mount no longer satisfies its frozen reservation")
    _verify_initial_probe_success_layout(
        emission_dir, budget, include_receipt=True,
    )
    return receipt


def compose_calibrated_policy_v5(request: object, request_raw_sha256: object) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replay the pinned producer bundle and resolve a prelaunch V5 policy."""
    value = _validate_resolve_request(request)
    raw_sha = digest(request_raw_sha256, "composition request raw SHA-256")
    reader, producer, source, context, identity = _load_verified_inputs(value)
    source_pin = value["source_manifest"]
    bundle = value["capacity_bundle"]
    _verify_capacity_request_binding(reader, producer, source, context, identity, source_pin, bundle)
    return _make_policy_document(value, raw_sha, reader, source, context, identity, value["construction_probe"], bundle)


def compose_calibrated_policy_v5_offline(
    request: object, request_raw_sha256: object, *, replay_context: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve SourceV5 policy from fully replayed peer files and ProbeV2 capture bytes."""
    value = _validate_resolve_request(request)
    raw_sha = digest(request_raw_sha256, "offline composition request raw SHA-256")
    require(raw_sha == sha256(canonical(value)),
            "offline composition request canonical bytes differ from its supplied raw digest")
    value = _validate_resolve_request(json.loads(canonical(value).decode("ascii")))
    require(type(replay_context) is dict and replay_context.get("schema") in {
                FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
                FEEDBACK_CAPTURED_OFFLINE_CONTEXT_SCHEMA,
            }, "feedback offline replay context schema differs")
    context_value = replay_context
    checked_context = _offline_context(context_value)
    context_capacity = {name: dict(checked_context["capacity_bundle"][name])
                        for name in checked_context["capacity_bundle"]}
    require(context_capacity == value["capacity_bundle"],
            "offline replay context capacity pins differ from the original composition request")
    source_preflight, _capture_preflight = _preflight_probe_replay(value, checked_context)
    # Load the captured SourceV5 verifier only after the complete mapped closure passes.
    reader, producer, source, context, identity = _load_verified_inputs(value)
    require(source_preflight.get("manifest_sha256") == source.get("manifest_sha256") and
            source_preflight.get("source", {}).get("source_tree_sha256") ==
            source.get("source", {}).get("source_tree_sha256"),
            "offline SourceV5 preflight differs from the freshly loaded source manifest")
    _verify_capacity_request_binding(reader, producer, source, context, identity,
                                     value["source_manifest"], value["capacity_bundle"])
    return _make_policy_document(
        value, raw_sha, reader, source, context, identity, value["construction_probe"],
        value["capacity_bundle"], context_value,
    )


def compose_calibrated_policy_v5_closed_recorded_v1(
    request: object, request_raw_sha256: object, *, replay_context: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve policy from strict capture.v2 evidence without opening its ELF."""
    value = _validate_resolve_request(request)
    raw_sha = digest(request_raw_sha256, "closed-recorded composition request raw SHA-256")
    require(raw_sha == sha256(canonical(value)),
            "closed-recorded composition request canonical bytes differ from its supplied raw digest")
    value = _validate_resolve_request(json.loads(canonical(value).decode("ascii")))
    source_root = absolute_path(value["source_root"], "closed-recorded SourceV5 root")
    source_pin = exact(value["source_manifest"], {"path", "raw_sha256"},
                       "closed-recorded SourceV5 manifest pin")
    require(not (source_pin["path"] == str(source_root) or
                 source_pin["path"].startswith(str(source_root).rstrip("/") + "/")),
            "closed-recorded SourceV5 manifest pin must be outside SourceRoot")
    # This loads and checks raw-pinned SourceV5 metadata/code only. No caller
    # evidence-map entry is classified until every Source executable path has
    # been derived and rejected lexically below.
    reader, producer, source, context, identity = _load_verified_inputs(value)
    _reject_closed_recorded_artifact_map_v1(
        replay_context, value, source_root, source,
    )
    context_value = replay_context
    checked_context = _offline_context(context_value)
    source_preflight, _capture_preflight = _preflight_probe_replay(
        value, checked_context, recorded_artifacts=True,
    )
    require(source_preflight.get("manifest_sha256") == source.get("manifest_sha256") and
            source_preflight.get("source", {}).get("source_tree_sha256") ==
            source.get("source", {}).get("source_tree_sha256"),
            "closed-recorded SourceV5 preflight differs from the freshly loaded source manifest")
    _verify_capacity_request_binding(reader, producer, source, context, identity,
                                     value["source_manifest"], value["capacity_bundle"])
    return _make_policy_document(
        value, raw_sha, reader, source, context, identity, value["construction_probe"],
        value["capacity_bundle"], context_value, closed_recorded=True,
    )


def build_calibrated_feedback_expectation_v5(request: object) -> dict[str, Any]:
    """Finalize a V5 expectation only after the caller supplies its actual PID."""
    return _build_calibrated_feedback_expectation_v5(request)


def _build_calibrated_feedback_expectation_v5(
    request: object, replay_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = exact(request, {
        "schema", "source_root", "source_manifest", "resolved_policy", "composition_receipt",
        "construction_probe", "capacity_bundle", "expectation_header",
    }, "V5 expectation finalization request")
    require(value["schema"] == FINALIZE_SCHEMA, "unsupported V5 expectation finalization schema")
    source_root = absolute_path(value["source_root"], "SourceV5 source root")
    require(source_root == SOURCE_ROOT, "finalization source root differs from pinned harness root")
    source_pin = exact(value["source_manifest"], {"path", "raw_sha256"}, "SourceV5 manifest pin")
    source_path = absolute_path(source_pin["path"], "SourceV5 manifest path")
    source, _source_raw, source_raw_sha = _read_canonical(source_path, "SourceV5 manifest", source_pin["raw_sha256"])
    policy_pin = exact(value["resolved_policy"], {"path", "raw_sha256"}, "resolved policy pin")
    policy_path = absolute_path(policy_pin["path"], "resolved policy path")
    policy, _policy_raw, policy_raw_sha = _read_canonical(policy_path, "resolved calibrated policy", policy_pin["raw_sha256"])
    receipt_pin = exact(value["composition_receipt"], {"path", "raw_sha256"}, "composition receipt pin")
    receipt_path = absolute_path(receipt_pin["path"], "composition receipt path")
    receipt, _receipt_raw, receipt_raw_sha = _read_canonical(receipt_path, "calibrated policy composition receipt", receipt_pin["raw_sha256"])
    _verify_policy_and_receipt(source, source_raw_sha, policy, policy_raw_sha, receipt, receipt_raw_sha)
    probe_pin = exact(value["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, "construction probe pin")
    capacity_bundle = exact(value["capacity_bundle"], {"request", "artifact", "receipt"}, "capacity bundle pins")
    bundle_context = {key: policy["context"][key] for key in ("host_id", "workload", "profile", "calibration_id")}
    reader, producer, verified_source, context, probe_identity = _load_verified_inputs({
        "source_root": str(source_root),
        "source_manifest": source_pin,
        "context": bundle_context,
        "construction_probe": probe_pin,
        "capacity_bundle": capacity_bundle,
    })
    require(verified_source["manifest_sha256"] == source["manifest_sha256"], "finalization SourceV5 semantic digest changed after policy composition")
    _verify_capacity_request_binding(reader, producer, verified_source, context, probe_identity, source_pin, capacity_bundle)
    identity = exact(value["expectation_header"].get("identity"), {
        "host_id", "run_id", "report_nonce", "process_id", "allocator", "executor", "workload", "profile",
        "mode", "source_sha256", "binary_sha256", "pressure_qualification",
    }, "post-Popen V5 identity")
    require(identity["allocator"] in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system") and identity["executor"] in ("allocatbelt", "tokio-1.53.1"), "V5 expectation role is outside the original APP artifact/executor set")
    require(identity["allocator"] == policy["context"]["allocator"], "actual APP allocator differs from the prelaunch selected artifact")
    require(identity["host_id"] == policy["context"]["host_id"] and identity["workload"] == policy["context"]["workload"] and identity["profile"] == policy["context"]["profile"], "actual APP identity differs from the prelaunch calibrated context")
    require(identity["source_sha256"] == policy["source_tree_sha256"] and identity["binary_sha256"] == policy["app_binary_sha256"], "actual APP source or binary differs from the prelaunch composition")
    require(identity["pressure_qualification"] is True, "V5 expectation identity does not request pressure validation")
    uint(identity["process_id"], "actual APP process ID", positive=True, maximum=(1 << 31) - 1)
    require(re.fullmatch(r"[0-9a-f]{32}", identity["report_nonce"]) is not None, "actual APP report nonce is malformed")
    header = exact(value["expectation_header"], {
        "identity", "external_pressure_proof", "final_runtime_binding", "minimum_production_seconds",
        "minimum_pressure_overlap_seconds",
    }, "caller-frozen V5 expectation header")
    artifact_pin = exact(capacity_bundle["artifact"], {"path", "raw_sha256"}, "capacity artifact pin")
    require(probe_pin["allocator"] == identity["allocator"] and probe_pin["binary_sha256"] == policy["app_binary_sha256"] and probe_pin["raw_sha256"] == policy["probe_raw_sha256"], "construction probe differs from the prelaunch policy composition")
    require(artifact_pin["raw_sha256"] == policy["capacity_artifact_raw_sha256"], "capacity artifact differs from the prelaunch policy composition")
    for name in ("request", "artifact", "receipt"):
        exact(capacity_bundle[name], {"path", "raw_sha256"}, f"capacity bundle {name} pin")
        absolute_path(capacity_bundle[name]["path"], f"capacity bundle {name} path")
        digest(capacity_bundle[name]["raw_sha256"], f"capacity bundle {name} raw SHA-256")
    require(capacity_bundle["request"]["raw_sha256"] == policy["capacity_request_raw_sha256"] and capacity_bundle["receipt"]["raw_sha256"] == policy["capacity_receipt_raw_sha256"], "capacity producer bundle differs from the prelaunch policy composition")
    body = {
        "schema": (EXPECTATION_SCHEMA_V6
                   if policy.get("capacity_floor_policy_id") is not None
                   else EXPECTATION_SCHEMA_V5),
        "mode": "pressure_validation",
        "identity": identity,
        "policy": policy["policy"],
        "app_capacity_artifact_sha256": artifact_pin["raw_sha256"],
        "app_capacity_artifact": artifact_pin,
        "host_binding": {"path": source_pin["path"], "raw_sha256": source_pin["raw_sha256"]},
        "construction_probe": probe_pin,
        "external_pressure_proof": header["external_pressure_proof"],
        "final_runtime_binding": header["final_runtime_binding"],
        "minimum_production_seconds": header["minimum_production_seconds"],
        "minimum_pressure_overlap_seconds": header["minimum_pressure_overlap_seconds"],
    }
    try:
        reader._validate_expectation_body(body)
        if replay_context is None:
            reader.validate_calibrated_construction_probe_v2(
                probe_pin, verified_source, artifact_pin, identity, policy["policy"],
                policy.get("capacity_floor_policy_id"),
            )
        else:
            reader.validate_calibrated_construction_probe_v2_offline(
                probe_pin, source_pin, artifact_pin, probe_identity,
                replay_context=replay_context, expected_policy=policy["policy"],
                capacity_floor_policy_id=policy.get("capacity_floor_policy_id"),
            )
    except reader.ValidationError as error:
        raise CompositionError(f"captured feedback reader rejected finalization: {error}") from error
    return body


def finalize_calibrated_feedback_expectation_v5_offline(
    request: object, request_raw_sha256: object, *, replay_context: object,
) -> dict[str, Any]:
    """Rebuild expectation V5 after replaying the exact origin-host ProbeV2 bytes."""
    value = exact(request, {
        "schema", "source_root", "source_manifest", "resolved_policy", "composition_receipt",
        "construction_probe", "capacity_bundle", "expectation_header",
    }, "offline V5 expectation finalization request")
    require(value["schema"] == FINALIZE_SCHEMA,
            "unsupported offline V5 expectation finalization schema")
    raw_sha = digest(request_raw_sha256, "offline finalization request raw SHA-256")
    require(raw_sha == sha256(canonical(value)),
            "offline finalization request canonical bytes differ from its supplied raw digest")
    value = json.loads(canonical(value).decode("ascii"))
    value = exact(value, {
        "schema", "source_root", "source_manifest", "resolved_policy", "composition_receipt",
        "construction_probe", "capacity_bundle", "expectation_header",
    }, "offline V5 expectation finalization request")
    context_value = exact(replay_context, {
        "schema", "evidence_path_map", "probe_capture_pin", "capacity_bundle",
    }, "feedback offline replay context")
    checked_context = _offline_context(context_value)
    context_capacity = {name: dict(checked_context["capacity_bundle"][name])
                        for name in checked_context["capacity_bundle"]}
    require(context_capacity == value["capacity_bundle"],
            "offline finalization capacity pins differ from the original request")
    offline_header = exact(value["expectation_header"], {
        "identity", "external_pressure_proof", "final_runtime_binding",
        "minimum_production_seconds", "minimum_pressure_overlap_seconds",
    }, "offline finalization expectation header")
    pressure_pin = exact(offline_header["external_pressure_proof"], {
        "path", "raw_sha256", "validator_sha256", "recipe_raw_sha256",
    }, "offline external pressure receipt pin")
    runtime_pin = exact(offline_header["final_runtime_binding"], {"path", "raw_sha256"},
                        "offline final runtime binding pin")
    _require_mapped_files(checked_context, {
        value["source_manifest"]["path"], value["resolved_policy"]["path"],
        value["composition_receipt"]["path"], value["construction_probe"]["path"],
        checked_context["probe_capture_pin"]["path"],
    }, "offline finalization input")
    _require_mapped_directories(checked_context, {value["source_root"]},
                                "offline finalization SourceV5 root")
    policy, _policy_raw, _policy_sha = _read_canonical(
        absolute_path(value["resolved_policy"]["path"], "offline resolved policy path"),
        "offline resolved calibrated policy", value["resolved_policy"]["raw_sha256"],
    )
    bundle_context = {key: policy["context"][key]
                      for key in ("host_id", "workload", "profile", "calibration_id")}
    preflight_request = {
        "schema": (REQUEST_SCHEMA_V2 if policy.get("capacity_floor_policy_id") is not None else REQUEST_SCHEMA),
        "source_root": value["source_root"],
        "source_manifest": value["source_manifest"], "context": bundle_context,
        "construction_probe": value["construction_probe"], "capacity_bundle": value["capacity_bundle"],
    }
    if policy.get("capacity_floor_policy_id") is not None:
        preflight_request["capacity_floor_policy_id"] = policy["capacity_floor_policy_id"]
    _preflight_probe_replay(preflight_request, checked_context)
    return _build_calibrated_feedback_expectation_v5(value, context_value)


def _verify_policy_and_receipt(
    source: dict[str, Any], source_raw_sha: str, policy: dict[str, Any], policy_raw_sha: str,
    receipt: dict[str, Any], receipt_raw_sha: str,
) -> None:
    policy_keys = {
        "schema", "context", "policy", "source_manifest_raw_sha256", "source_manifest_sha256",
        "source_tree_sha256", "build_sha256", "app_binary_sha256", "probe_raw_sha256",
        "capacity_request_raw_sha256", "capacity_artifact_raw_sha256", "capacity_receipt_raw_sha256",
        "base_policy_artifact_sha256", "base_policy_sha256", "base_context_sha256",
        "resolution_rule_version", "policy_sha256",
    }
    if type(policy) is dict and policy.get("schema") == POLICY_SCHEMA_V2:
        policy_keys.add("capacity_floor_policy_id")
    exact(policy, policy_keys, "resolved calibrated policy")
    policy_floor_id = policy.get("capacity_floor_policy_id")
    require(policy["schema"] in (POLICY_SCHEMA, POLICY_SCHEMA_V2) and
            (policy_floor_id is None or policy_floor_id == CAPACITY_FLOOR_POLICY_ID) and
            ((policy["schema"] == POLICY_SCHEMA_V2) == (policy_floor_id is not None)) and
            digest(policy["policy_sha256"], "resolved policy digest") ==
            sha256(canonical({key: item for key, item in policy.items() if key != "policy_sha256"})),
            "resolved policy schema, selector, or self digest is invalid")
    receipt_keys = {
        "schema", "validated", "execution_ready", "qualification_eligible", "controller_chronology_proven",
        "request_raw_sha256", "source_manifest_raw_sha256", "source_manifest_sha256", "source_tree_sha256",
        "build_sha256", "app_binary_sha256", "probe_raw_sha256", "capacity_request_raw_sha256",
        "capacity_artifact_raw_sha256", "capacity_receipt_raw_sha256", "base_policy_artifact_sha256",
        "base_policy_sha256", "base_context_sha256", "resolved_policy_raw_sha256",
        "resolved_policy_sha256", "resolution_rule_version", "validator_sha256", "context", "receipt_sha256",
    }
    if policy_floor_id is not None:
        receipt_keys.add("capacity_floor_policy_id")
    exact(receipt, receipt_keys, "calibrated policy composition receipt")
    receipt_body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    expected_receipt_schema = RECEIPT_SCHEMA_V2 if policy_floor_id is not None else RECEIPT_SCHEMA
    require(receipt["schema"] == expected_receipt_schema and
            (policy_floor_id is None or receipt.get("capacity_floor_policy_id") == policy_floor_id) and
            digest(receipt["receipt_sha256"], "composition receipt digest") ==
            sha256(canonical(receipt_body)),
            "composition receipt schema, selector, or self digest is invalid")
    for flag in ("validated", "execution_ready", "qualification_eligible", "controller_chronology_proven"):
        require(type(receipt[flag]) is bool, f"composition receipt {flag} flag is not boolean")
    require(receipt["validated"] is True and receipt["execution_ready"] is False and receipt["qualification_eligible"] is False and receipt["controller_chronology_proven"] is False, "composition receipt has an invalid readiness or qualification claim")
    require(digest(receipt["validator_sha256"], "composition validator SHA-256") == _self_sha256(), "composition receipt was produced by different validator bytes")
    digest(receipt["request_raw_sha256"], "composition request raw SHA-256")
    links = (
        ("source_manifest_raw_sha256", source_raw_sha),
        ("source_manifest_sha256", source["manifest_sha256"]),
        ("source_tree_sha256", source["source"]["source_tree_sha256"]),
        ("build_sha256", policy["build_sha256"]),
        ("app_binary_sha256", policy["app_binary_sha256"]),
        ("probe_raw_sha256", policy["probe_raw_sha256"]),
        ("capacity_request_raw_sha256", policy["capacity_request_raw_sha256"]),
        ("capacity_artifact_raw_sha256", policy["capacity_artifact_raw_sha256"]),
        ("capacity_receipt_raw_sha256", policy["capacity_receipt_raw_sha256"]),
        ("base_policy_artifact_sha256", policy["base_policy_artifact_sha256"]),
        ("base_policy_sha256", policy["base_policy_sha256"]),
        ("base_context_sha256", policy["base_context_sha256"]),
        ("resolution_rule_version", policy["resolution_rule_version"]),
        ("resolved_policy_sha256", policy["policy_sha256"]),
        ("resolved_policy_raw_sha256", policy_raw_sha),
    )
    for field, expected in links:
        require(receipt[field] == expected, f"composition receipt differs from resolved policy at {field}")
    require(receipt["context"] == policy["context"], "composition receipt context differs from the resolved policy")
    require(policy["context"].get("capacity_floor_policy_id") == policy_floor_id,
            "composition context differs from the explicit capacity-floor selector")
    require(policy["source_manifest_raw_sha256"] == source_raw_sha and policy["source_manifest_sha256"] == source["manifest_sha256"] and policy["source_tree_sha256"] == source["source"]["source_tree_sha256"], "resolved policy is bound to a different SourceV5 manifest")
    require(receipt_raw_sha == sha256(canonical(receipt)), "composition receipt canonical digest differs")


def _finish_expectation(request: dict[str, Any], raw_sha: str) -> tuple[bytes, dict[str, Any]]:
    body = build_calibrated_feedback_expectation_v5(request)
    source_root = absolute_path(request["source_root"], "SourceV5 source root")
    reader_path = source_root / FEEDBACK_READER
    reader_raw, reader_sha = _read_stable(reader_path, "pinned feedback reader", MAX_METADATA_BYTES)
    source_value, _source_raw, _source_sha = _read_canonical(
        absolute_path(request["source_manifest"]["path"], "SourceV5 manifest path"),
        "SourceV5 manifest", request["source_manifest"]["raw_sha256"],
    )
    reader_record = _record(source_value, FEEDBACK_READER, "feedback validator")
    reader_pin = exact(source_value["qualification_harness"].get("feedback_validator"), {"path", "sha256"}, "SourceV5 feedback validator pin")
    require(reader_pin == {"path": FEEDBACK_READER, "sha256": reader_sha} and reader_record["sha256"] == reader_sha, "finalization feedback reader differs from the SourceV5 pin")
    reader = types.ModuleType(f"finalize_feedback_reader_{reader_sha}")
    reader.__file__ = str(reader_path)
    reader.__package__ = ""
    _exec_registered_module(reader, reader_raw, reader_path)
    final_bytes, final_sha = reader.build_pressure_expectation_recipe(body)
    receipt = {
        "schema": FINALIZE_RECEIPT_SCHEMA,
        "validated": True,
        "execution_ready": False,
        "qualification_eligible": False,
        "controller_chronology_proven": False,
        "finalization_request_raw_sha256": raw_sha,
        "composition_receipt_raw_sha256": request["composition_receipt"]["raw_sha256"],
        "expectation_header_sha256": reader.digest_object(request["expectation_header"]),
        "expectation_raw_sha256": final_sha,
        "validator_sha256": _self_sha256(),
    }
    receipt["receipt_sha256"] = sha256(canonical(receipt))
    return final_bytes, receipt


def _write_exclusive(path: Path, raw: bytes) -> None:
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), "output path must be normalized and absolute")
    try:
        require(path.parent.resolve(strict=True) == path.parent, "output parent traverses a symlink or alias")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    except OSError as error:
        raise CompositionError(f"cannot create fresh composition output: {error}") from error
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            require(written > 0, "composition output write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_initial_probe_receipt_exclusive(
    path: Path, raw: bytes,
) -> tuple[int, int]:
    """Durably create one receipt and remove only its inode after a failed write."""
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)) and
            type(raw) is bytes and len(raw) <= MAX_PROBE_CAPTURE_RECEIPT_BYTES,
            "initial ProbeV2 receipt write path or bytes are outside their fixed bound")
    parent = path.parent
    try:
        parent_info = parent.lstat()
        require(parent.resolve(strict=True) == parent and
                stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.getuid() and
                stat.S_IMODE(parent_info.st_mode) == 0o700,
                "initial ProbeV2 receipt parent is not an owned private directory")
        directory_fd = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise CompositionError(f"cannot safely open initial ProbeV2 receipt parent: {error}") from error
    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        anchored = os.fstat(directory_fd)
        require((anchored.st_dev, anchored.st_ino) ==
                (parent_info.st_dev, parent_info.st_ino),
                "initial ProbeV2 receipt parent changed while opening")
        descriptor = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600, dir_fd=directory_fd,
        )
        created = os.fstat(descriptor)
        identity = (created.st_dev, created.st_ino)
        require(stat.S_ISREG(created.st_mode) and created.st_uid == os.getuid() and
                created.st_nlink == 1,
                "initial ProbeV2 receipt descriptor is not its exact private regular inode")
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            require(written > 0, "initial ProbeV2 receipt write made no progress")
            offset += written
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        require(identity == (final.st_dev, final.st_ino) and
                stat.S_ISREG(final.st_mode) and final.st_uid == os.getuid() and
                stat.S_IMODE(final.st_mode) == 0o600 and final.st_nlink == 1 and
                final.st_size == len(raw),
                "initial ProbeV2 receipt inode differs after durable write")
        os.fsync(directory_fd)
        return identity
    except BaseException:
        if identity is not None:
            try:
                current = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == identity:
                    os.unlink(path.name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _unlink_exact_output(path: Path, expected_identity: tuple[int, int]) -> None:
    """Remove only one owned regular inode after its enclosing write fails validation."""
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)),
            "owned output removal path must be normalized and absolute")
    directory_fd = os.open(
        path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                (info.st_dev, info.st_ino) == expected_identity,
                "refusing to remove an output that is not its exact private inode")
        os.unlink(path.name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("resolve", help="verify capacity evidence and resolve the prelaunch numeric policy")
    resolve.add_argument("--request", type=Path, required=True)
    resolve.add_argument("--policy-output", type=Path, required=True)
    resolve.add_argument("--receipt-output", type=Path, required=True)
    finalize = commands.add_parser("finalize", help="freeze a V5 expectation after the actual APP PID is known")
    finalize.add_argument("--request", type=Path, required=True)
    finalize.add_argument("--expectation-output", type=Path, required=True)
    finalize.add_argument("--receipt-output", type=Path, required=True)
    initial_probe = commands.add_parser(
        "emit-initial-probe",
        help="emit first calibrated ProbeV2 stdout with the Source-pinned direct owner",
    )
    initial_probe.add_argument("--request", type=Path, required=True)
    initial_probe.add_argument("--request-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        request_path = absolute_path(str(args.request), "composition request path")
        request_raw, request_sha = _read_stable(request_path, "composition request", MAX_METADATA_BYTES)
        try:
            request = json.loads(request_raw.decode("utf-8"), object_pairs_hook=_unique)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise CompositionError(f"composition request is invalid JSON: {error}") from error
        require(type(request) is dict and canonical(request) == request_raw, "composition request is not canonical JSON")
        if args.command == "emit-initial-probe":
            supplied_sha = digest(args.request_sha256,
                                  "initial ProbeV2 CLI request raw SHA-256")
            require(supplied_sha == request_sha,
                    "initial ProbeV2 CLI request bytes differ from the supplied raw SHA-256")
            result = emit_initial_calibrated_probe_v2({
                "path": str(request_path), "raw_sha256": supplied_sha,
            })
            sys.stdout.buffer.write(canonical(result))
            return 0
        if args.command == "resolve":
            policy, receipt = compose_calibrated_policy_v5(request, request_sha)
            _write_exclusive(absolute_path(str(args.policy_output), "resolved policy output"), canonical(policy))
            _write_exclusive(absolute_path(str(args.receipt_output), "composition receipt output"), canonical(receipt))
            sys.stdout.buffer.write(canonical({"validated": True, "execution_ready": False, "qualification_eligible": False, "controller_chronology_proven": False, "policy_sha256": policy["policy_sha256"], "receipt_sha256": receipt["receipt_sha256"]}))
            return 0
        require(request.get("schema") == FINALIZE_SCHEMA, "unsupported V5 finalization request schema")
        final, receipt = _finish_expectation(request, request_sha)
        _write_exclusive(absolute_path(str(args.expectation_output), "V5 expectation output"), final)
        _write_exclusive(absolute_path(str(args.receipt_output), "V5 finalization receipt output"), canonical(receipt))
        sys.stdout.buffer.write(canonical({"validated": True, "execution_ready": False, "qualification_eligible": False, "controller_chronology_proven": False, "expectation_raw_sha256": sha256(final), "receipt_sha256": receipt["receipt_sha256"]}))
        return 0
    except (CompositionError, OSError, ValueError, TypeError) as error:
        print(f"application-feedback-composition: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
