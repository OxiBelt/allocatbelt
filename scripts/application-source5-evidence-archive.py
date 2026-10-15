#!/usr/bin/env python3
"""Private coordinator for bounded Source5 per-job evidence offload.

This module runs on the private archive coordinator, never in a timed APP lane.
It copies already staged, raw-pinned objects into the accepted Source5 v3 object
layout, seals a per-job checkpoint and manifest, and signs an ACK only after
fsync plus independent reopen and rehash. It does not create the later full-host
v3 index or origin receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


CONTEXT_SCHEMA_V1 = "allocatbelt.application-source5-evidence-archive-context.v1"
REQUEST_SCHEMA_V1 = "allocatbelt.application-source5-evidence-checkpoint-request.v1"
CHECKPOINT_SCHEMA_V1 = "allocatbelt.application-source5-evidence-job-checkpoint.v1"
OBJECT_MANIFEST_SCHEMA_V1 = "allocatbelt.application-source5-evidence-object-manifest.v1"
ACK_SCHEMA_V1 = "allocatbelt.application-source5-evidence-durable-ack.v1"
STAGE_MAP_SCHEMA_V1 = "allocatbelt.application-source5-evidence-stage-map.v1"
VERIFIED_ACK_SCHEMA_V1 = "allocatbelt.application-source5-evidence-verified-ack.v1"
CATALOGUE_LOCAL_MAP_SCHEMA_V1 = "allocatbelt.application-source5-host-catalogue-local-map.v1"
DEPENDENCY_LOCAL_MAP_SCHEMA_V1 = "allocatbelt.application-source5-dependency-local-map.v1"
SIGNER_CONTEXT_SCHEMA_V1 = "allocatbelt.application-source5-archive-signer-context.v1"
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_SOURCE_MANIFEST_BYTES = 256 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_ROWS = 1_000_000
MAX_OBJECT_BYTES = 1 << 40
MAX_TOTAL_BYTES = 1 << 48
MAX_GPG_OUTPUT_BYTES = 1 << 20
COPY_BLOCK_BYTES = 1024 * 1024
MAX_U64 = (1 << 64) - 1
HOST_BUDGET_FIELDS = {
    "schema", "campaign_id", "host_id", "original_pins", "schedule",
    "owner_contract", "path_catalogue", "storage_reservation",
    "role_byte_reservations", "transport", "execution_blockers",
    "readiness", "budget_sha256",
}
NON_EXPORTABLE_JOB_ROLES = frozenset({
    "source5_job_record", "source5_job_disposition",
})
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class EvidenceArchiveError(ValueError):
    """A Source5 archive input, durable object, or signed ACK is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceArchiveError(message)


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _canonical(value: Any, *, maximum_bytes: int = MAX_JSON_BYTES) -> bytes:
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise EvidenceArchiveError(f"{label_type(value)} is not canonical JSON: {error}") from error
    _require(len(raw) <= maximum_bytes,
             "canonical archive metadata exceeds its fixed byte ceiling")
    return raw


def label_type(value: object) -> str:
    return type(value).__name__


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             f"{label} is not a lowercase SHA-256")
    return value


def _fingerprint(value: object, label: str) -> str:
    _require(type(value) is str and
             re.fullmatch(r"[A-F0-9]{40,64}", value) is not None,
             f"{label} is not an uppercase GPG fingerprint")
    return value


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    _require(type(value) is int and 0 <= value <= MAX_U64 and
             (not positive or value > 0), f"{label} is outside its finite integer bound")
    return value


def _absolute_path(value: object, label: str) -> str:
    _require(type(value) is str and value.startswith("/") and "\x00" not in value and
             len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             not any(ord(char) < 32 or ord(char) == 127 for char in value),
             f"{label} is not a bounded absolute path")
    pure = PurePosixPath(value)
    _require(".." not in pure.parts and pure.as_posix() == value,
             f"{label} is not normalized")
    return value


def _token(value: object, label: str) -> str:
    _require(type(value) is str and
             re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None,
             f"{label} is malformed")
    return value


def _run_id(value: object, label: str) -> str:
    _require(type(value) is str and
             0 < len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             not any(ord(char) < 32 or ord(char) == 127 for char in value),
             f"{label} is not bounded original run-ID text")
    return value


def _pin(value: object, label: str) -> dict[str, str]:
    row = _exact(value, {"path", "raw_sha256", "semantic_sha256"}, label)
    return {
        "path": _absolute_path(row["path"], f"{label} path"),
        "raw_sha256": _digest(row["raw_sha256"], f"{label} raw SHA-256"),
        "semantic_sha256": _digest(row["semantic_sha256"],
                                   f"{label} semantic SHA-256"),
    }


def _pin_raw(value: object, label: str) -> dict[str, str]:
    row = _exact(value, {"path", "raw_sha256"}, label)
    return {
        "path": _absolute_path(row["path"], f"{label} path"),
        "raw_sha256": _digest(row["raw_sha256"], f"{label} raw SHA-256"),
    }


def _parse_canonical(
    raw: bytes, label: str, *, maximum_bytes: int = MAX_JSON_BYTES,
) -> dict[str, Any]:
    _require(type(raw) is bytes and len(raw) <= maximum_bytes and raw.endswith(b"\n") and
             b"\r" not in raw, f"{label} exceeds its canonical JSON framing bound")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise EvidenceArchiveError(f"{label} is not valid bounded JSON: {error}") from error
    _require(type(value) is dict and
             _canonical(value, maximum_bytes=maximum_bytes) == raw,
             f"{label} is not canonical JSON")
    return value


def _read_self_digest(raw: bytes, label: str,
                      fields: tuple[str, ...]) -> tuple[dict[str, Any], str]:
    value = _parse_canonical(raw, label)
    matches = []
    for field in fields:
        candidate = value.get(field)
        body = {key: item for key, item in value.items() if key != field}
        if type(candidate) is str and candidate == _sha(_canonical(body)):
            matches.append((field, candidate))
    _require(len(matches) == 1, f"{label} lacks one exact canonical self digest")
    return value, matches[0][1]


def _info_key(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink, info.st_uid)


def _open_dir_path(path_value: object, label: str, *, private_final: bool) -> int:
    path = Path(_absolute_path(str(path_value), label))
    parts = path.parts
    _require(path.is_absolute() and parts and parts[0] == "/",
             f"{label} must be absolute")
    fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        for component in parts[1:]:
            _require(component not in ("", ".", ".."),
                     f"{label} has an unsafe path component")
            child = os.open(component, os.O_RDONLY | _O_DIRECTORY |
                            _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode), f"{label} is not a directory")
        if private_final:
            _require(info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o700,
                     f"{label} is not an owned mode-0700 private directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _ensure_private_child(parent_fd: int, name: str, label: str) -> int:
    _require(name not in ("", ".", "..") and "/" not in name and "\x00" not in name,
             f"{label} has an unsafe child name")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                 dir_fd=parent_fd)
    info = os.fstat(fd)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o700,
             f"{label} is not an owned mode-0700 directory")
    return fd


def _open_relative_dir(root_fd: int, relative: str, *, create: bool,
                       label: str) -> int:
    parts = PurePosixPath(relative).parts
    _require(parts and all(part not in ("", ".", "..", "/") for part in parts),
             f"{label} has an unsafe relative path")
    fd = os.dup(root_fd)
    try:
        for component in parts:
            if create:
                child = _ensure_private_child(fd, component, label)
            else:
                child = os.open(component, os.O_RDONLY | _O_DIRECTORY |
                                _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
                info = os.fstat(child)
                _require(stat.S_ISDIR(info.st_mode) and
                         info.st_uid == os.getuid() and
                         stat.S_IMODE(info.st_mode) == 0o700,
                         f"{label} traverses a non-private directory")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_parent(root_fd: int, relative_file: str, *, create: bool,
                 label: str) -> tuple[int, str]:
    pure = PurePosixPath(relative_file)
    _require(not pure.is_absolute() and pure.name not in ("", ".", "..") and
             all(part not in ("", ".", "..", "/") for part in pure.parts),
             f"{label} has an unsafe relative file path")
    parent = "." if len(pure.parts) == 1 else "/".join(pure.parts[:-1])
    fd = os.dup(root_fd) if parent == "." else _open_relative_dir(
        root_fd, parent, create=create, label=f"{label} parent",
    )
    return fd, pure.name


def _read_at(fd: int, name: str, maximum: int, label: str,
             *, expected_bytes: int | None = None,
             collect: bool = True) -> tuple[bytes | None, str, os.stat_result]:
    try:
        before_path = os.stat(name, dir_fd=fd, follow_symlinks=False)
        _require(stat.S_ISREG(before_path.st_mode) and before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and before_path.st_size <= maximum and
                 (expected_bytes is None or before_path.st_size == expected_bytes),
                 f"{label} is not the exact bounded owned mode-0600 single-link file")
        descriptor = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
                             dir_fd=fd)
    except OSError as error:
        raise EvidenceArchiveError(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        _require(_info_key(before) == _info_key(before_path) and
                 stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                 stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
                 f"{label} changed identity before read")
        hasher = hashlib.sha256()
        blocks: list[bytes] | None = [] if collect else None
        total = 0
        while total < before.st_size:
            block = os.read(descriptor, min(COPY_BLOCK_BYTES, before.st_size - total))
            _require(bool(block), f"{label} ended before its pinned size")
            total += len(block)
            _require(total <= maximum and total <= before.st_size,
                     f"{label} exceeded its read ceiling")
            hasher.update(block)
            if blocks is not None:
                blocks.append(block)
        _require(os.read(descriptor, 1) == b"" and total == before.st_size,
                 f"{label} has trailing bytes or changed size")
        after = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=fd, follow_symlinks=False)
        _require(_info_key(before) == _info_key(after) == _info_key(after_path),
                 f"{label} changed during its stable read")
        return (None if blocks is None else b"".join(blocks),
                hasher.hexdigest(), after)
    finally:
        os.close(descriptor)


def _write_at(fd: int, name: str, raw: bytes, label: str) -> tuple[str, int]:
    _require(type(raw) is bytes and len(raw) <= MAX_JSON_BYTES,
             f"{label} exceeds the bounded metadata writer")
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, f"{label} writer made no progress")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                 info.st_size == len(raw),
                 f"{label} writer did not create the exact private file")
    finally:
        os.close(descriptor)
    os.fsync(fd)
    return _sha(raw), len(raw)


def _semantic_for_document(value: dict[str, Any]) -> str:
    candidates = []
    for field in ("receipt_sha256", "record_sha256", "checkpoint_sha256",
                  "manifest_sha256", "ack_sha256", "stage_map_sha256"):
        candidate = value.get(field)
        body = {key: item for key, item in value.items() if key != field}
        if type(candidate) is str and candidate == _sha(_canonical(body)):
            candidates.append(candidate)
    if candidates:
        _require(len(set(candidates)) == 1,
                 "owner receipt contains conflicting self-digest fields")
        return candidates[0]
    return _sha(_canonical(value))


def _validate_context(value: object) -> dict[str, Any]:
    fields = {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "source_manifest_pin", "execution_manifest_pin", "plan_pin",
        "resource_budget_pin", "predecessor_ack_pin",
        "authorized_signer_fingerprint",
    }
    context = _exact(value, fields, "Source5 archive context")
    _require(context["schema"] == CONTEXT_SCHEMA_V1,
             "Source5 archive context schema differs")
    _token(context["campaign_id"], "campaign ID")
    _token(context["host_id"], "host ID")
    phase = _token(context["phase"], "original phase")
    job_index = _uint(context["job_index"], "original filtered job index")
    for name in ("source_manifest_pin", "execution_manifest_pin",
                 "plan_pin", "resource_budget_pin"):
        _pin(context[name], f"archive {name}")
    predecessor = context["predecessor_ack_pin"]
    _require(predecessor is None or type(predecessor) is dict,
             "archive predecessor ACK pin is malformed")
    if predecessor is not None:
        _pin(predecessor, "archive predecessor ACK")
    signer = _fingerprint(context["authorized_signer_fingerprint"],
                          "authorized signer fingerprint")
    return {**context, "phase": phase, "job_index": job_index}


def _campaign_signature_limit(
    raw: bytes, budget_pin: object, context: dict[str, Any],
) -> int:
    pin = _pin(budget_pin, "campaign host evidence budget pin")
    _require(_sha(raw) == pin["raw_sha256"],
             "campaign host budget bytes differ from their raw pin")
    budget = _exact(_parse_canonical(raw, "campaign host evidence budget"),
                    HOST_BUDGET_FIELDS, "campaign host evidence budget v2")
    body = {key: item for key, item in budget.items()
            if key != "budget_sha256"}
    _require(budget.get("schema") ==
             "allocatbelt.application-source5-host-evidence-budget.v2" and
             budget.get("campaign_id") == context["campaign_id"] and
             budget.get("host_id") == context["host_id"] and
             budget.get("budget_sha256") == _sha(_canonical(body)) ==
                 pin["semantic_sha256"],
             "campaign host budget schema/identity/semantic pin differs")
    original_pins = _exact(budget.get("original_pins"), {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256",
    }, "host budget original input pins")
    _digest(original_pins["source_tree_sha256"], "budget source tree SHA-256")
    source_pins = original_pins["source_manifests"]
    _require(type(source_pins) is dict and context["host_id"] in source_pins and
             _pin(original_pins["plan"], "budget PlanV3 pin") ==
                 context["plan_pin"] and
             _pin(original_pins["execution_manifest"],
                  "budget execution-manifest pin") ==
                 context["execution_manifest_pin"] and
             _pin(source_pins[context["host_id"]],
                  "budget SourceV5 pin") == context["source_manifest_pin"],
             "archive context Source/Plan/execution pins differ from host budget")
    blockers = budget["execution_blockers"]
    readiness = _exact(budget["readiness"], {
        "budget_complete", "execution_ready", "component_gate_ready",
        "qualification_eligible",
    }, "campaign host budget readiness")
    _require(type(blockers) is list and
             all(type(item) is str and bool(item) for item in blockers) and
             len(blockers) == len(set(blockers)) and
             all(type(readiness[field]) is bool for field in readiness) and
             readiness["qualification_eligible"] is False and
             (not readiness["execution_ready"] or
              (readiness["budget_complete"] and not blockers)),
             "campaign budget blockers/readiness are inconsistent")
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict and
             catalogue.get("schema") ==
                 "allocatbelt.application-source5-host-path-catalogue.v2" and
             catalogue.get("semantic_sha256") == _sha(_canonical({
                 key: item for key, item in catalogue.items()
                 if key != "semantic_sha256"
             })),
             "campaign host path catalogue semantic digest differs")
    retention = catalogue.get("retention_policy")
    _require(type(retention) is dict,
             "campaign path catalogue lacks signature quota")
    limit = _uint(retention.get("maximum_signature_bytes"),
                  "campaign maximum signature bytes", positive=True)
    _require(limit <= MAX_GPG_OUTPUT_BYTES,
             "campaign signature quota exceeds the generic parser ceiling")
    return limit


def _validate_execution_manifest_signer_context(
    raw: bytes, execution_manifest_pin: object,
    signer_context_pin: dict[str, str], context: dict[str, Any],
) -> dict[str, Any]:
    """Tie the host verifier context to the prepared execution-manifest pin."""
    pin = _pin(execution_manifest_pin, "execution-manifest pin")
    _require(pin == context["execution_manifest_pin"] and
             type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             "execution-manifest bytes differ from the checkpoint pin")
    manifest = _exact(_parse_canonical(raw, "Source5 execution manifest"), {
        "schema", "campaign_id", "hosts", "original_inputs",
        "execution_sources", "modules", "observed_hosts", "artifact_root",
        "output_root", "phase_order", "protocol_sha256",
        "qualification_eligible", "scope", "prepared_input_generation",
        "prepared_capacity_registration", "archive_signer_contexts",
        "manifest_sha256",
    }, "bounded Source5 execution manifest v4")
    body = {key: item for key, item in manifest.items()
            if key != "manifest_sha256"}
    hosts = manifest["hosts"]
    _require(manifest["schema"] ==
             "allocatbelt.application-source5-campaign-execution.v4" and
             manifest["campaign_id"] == context["campaign_id"] and
             type(hosts) is list and bool(hosts) and
             all(type(host) is str and host for host in hosts) and
             len(hosts) == len(set(hosts)) and context["host_id"] in hosts and
             manifest["scope"] == "final_prepared_bounded" and
             manifest["qualification_eligible"] is False and
             manifest["manifest_sha256"] == _sha(_canonical(body)) ==
                 pin["semantic_sha256"],
             "execution-manifest schema, identity, scope or self digest differs")
    host_contexts = _exact(
        manifest["archive_signer_contexts"], set(hosts),
        "execution-manifest archive signer-context map",
    )
    wrapper = _exact(host_contexts[context["host_id"]], {
        "artifact", "semantic_sha256",
    }, "execution-manifest host signer-context wrapper")
    artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                       "execution-manifest signer-context artifact")
    expected = {
        "path": signer_context_pin["path"],
        "raw_sha256": signer_context_pin["raw_sha256"],
        "semantic_sha256": signer_context_pin["semantic_sha256"],
    }
    _require(artifact == {"path": expected["path"],
                          "raw_sha256": expected["raw_sha256"]} and
             wrapper["semantic_sha256"] == expected["semantic_sha256"],
             "signer-context pin is not the exact execution-manifest host entry")
    return pin


def _validate_archive_signer_context(
    raw: bytes, signer_context_pin: object, context: dict[str, Any],
    host_budget_raw: bytes, execution_manifest_pin: object,
    execution_manifest_raw: bytes,
) -> dict[str, Any]:
    context_pin = _pin(signer_context_pin, "archive signer-context pin")
    _require(type(raw) is bytes and _sha(raw) == context_pin["raw_sha256"],
             "archive signer-context bytes differ from their origin raw pin")
    value = _exact(_parse_canonical(raw, "archive signer context"), {
        "schema", "campaign_id", "host_id", "authorized_primary_fingerprint",
        "maximum_signature_bytes", "keyring_pin", "gpgv_pin",
        "signature_format", "signer_context_sha256",
    }, "archive signer context")
    body = {key: item for key, item in value.items()
            if key != "signer_context_sha256"}
    self_sha = _digest(value["signer_context_sha256"],
                       "archive signer-context semantic digest")
    maximum_signature_bytes = _campaign_signature_limit(
        host_budget_raw, context["resource_budget_pin"], context,
    )
    fingerprint = _fingerprint(
        value["authorized_primary_fingerprint"],
        "archive signer-context primary fingerprint",
    )
    keyring_pin = _pin_raw(value["keyring_pin"],
                           "archive signer-context keyring pin")
    gpgv_pin = _pin_raw(value["gpgv_pin"],
                        "archive signer-context GPGV pin")
    _require(value["schema"] == SIGNER_CONTEXT_SCHEMA_V1 and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             fingerprint == context["authorized_signer_fingerprint"] and
             self_sha == _sha(_canonical(body)) ==
                 context_pin["semantic_sha256"] and
             value["maximum_signature_bytes"] == maximum_signature_bytes and
             value["signature_format"] ==
                 "binary_detached_primary_sha256_v1",
             "archive signer context differs from its host, budget or format pin")
    execution_pin = _validate_execution_manifest_signer_context(
        execution_manifest_raw, execution_manifest_pin,
        context_pin, context,
    )
    return {
        "signer_context_pin": context_pin,
        "execution_manifest_pin": execution_pin,
        "fingerprint": fingerprint,
        "maximum_signature_bytes": maximum_signature_bytes,
        "keyring_pin": keyring_pin, "gpgv_pin": gpgv_pin,
    }


def _parse_catalogue_local_map(
    raw: bytes, context: dict[str, Any],
) -> dict[str, str]:
    value = _exact(_parse_canonical(raw, "private catalogue local-path map"), {
        "schema", "campaign_id", "host_id", "resource_budget_pin",
        "chunks", "map_sha256",
    }, "private catalogue local-path map")
    body = {key: item for key, item in value.items() if key != "map_sha256"}
    _require(value["schema"] == CATALOGUE_LOCAL_MAP_SCHEMA_V1 and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             _pin(value["resource_budget_pin"], "catalogue-map budget pin") ==
                 context["resource_budget_pin"] and
             value["map_sha256"] == _sha(_canonical(body)) and
             type(value["chunks"]) is list,
             "private catalogue local map identity or digest differs")
    paths: dict[str, str] = {}
    previous = ""
    local_paths = set()
    for index, chunk_value in enumerate(value["chunks"]):
        row = _exact(chunk_value, {"origin_path", "local_path"},
                     f"catalogue local map row[{index}]")
        origin = _absolute_path(row["origin_path"],
                                "catalogue chunk origin path")
        local = _absolute_path(row["local_path"],
                               "Root-local catalogue chunk path")
        _require(origin > previous and local != origin and local not in local_paths,
                 "catalogue local map is unsorted, aliased, or uses an origin path")
        previous = origin
        local_paths.add(local)
        paths[origin] = local
    return paths


def _parse_dependency_local_map(
    raw: bytes, context: dict[str, Any],
) -> dict[str, str]:
    value = _exact(_parse_canonical(raw, "private dependency local-path map"), {
        "schema", "campaign_id", "host_id", "entries", "map_sha256",
    }, "private dependency local-path map")
    body = {key: item for key, item in value.items() if key != "map_sha256"}
    _require(value["schema"] == DEPENDENCY_LOCAL_MAP_SCHEMA_V1 and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             value["map_sha256"] == _sha(_canonical(body)) and
             type(value["entries"]) is list,
             "private dependency local map identity or digest differs")
    paths: dict[str, str] = {}
    local_paths = set()
    previous = ""
    for index, entry_value in enumerate(value["entries"]):
        entry = _exact(entry_value, {
            "origin_pin", "local_path",
        }, f"dependency local map entry[{index}]")
        pin = _pin(entry["origin_pin"], "mapped dependency origin pin")
        local = _absolute_path(entry["local_path"],
                               "Root-local dependency path")
        _require(pin["path"] > previous and local != pin["path"] and
                 local not in local_paths,
                 "dependency map is unsorted, aliased, or uses a host origin path")
        previous = pin["path"]
        local_paths.add(local)
        paths[pin["path"]] = local
    expected_pins = {
        context["source_manifest_pin"]["path"]:
            context["source_manifest_pin"],
        context["plan_pin"]["path"]: context["plan_pin"],
        context["resource_budget_pin"]["path"]:
            context["resource_budget_pin"],
    }
    _require(len(expected_pins) == 3 and set(paths) == set(expected_pins),
             "dependency map does not close over exact Source/Plan/budget pins")
    for origin_path, pin in expected_pins.items():
        entry_pin = next(item["origin_pin"] for item in value["entries"]
                         if item["origin_pin"]["path"] == origin_path)
        _require(_pin(entry_pin, "mapped dependency origin pin") == pin,
                 "dependency map origin pin differs from archive context")
    return paths


def _validate_host_budget_object_rows(
    budget_raw: bytes, context: dict[str, Any], job_identity: dict[str, Any],
    entries: list[dict[str, Any]], job_record_pin: dict[str, str],
    job_record_bytes: int, job_record_semantic_sha256: str,
    catalogue_chunk_paths: dict[str, str], catalogue_cache_root: str,
) -> None:
    """Bind every reclaimable row and the local job record to exact budget rows."""
    budget_pin = _pin(context["resource_budget_pin"],
                      "host budget object-row pin")
    _require(_sha(budget_raw) == budget_pin["raw_sha256"],
             "host budget raw bytes differ before object-row validation")
    budget = _exact(
        _parse_canonical(budget_raw, "host evidence budget"),
        HOST_BUDGET_FIELDS, "host evidence budget v2",
    )
    budget_body = {key: item for key, item in budget.items()
                   if key != "budget_sha256"}
    _require(budget.get("schema") ==
             "allocatbelt.application-source5-host-evidence-budget.v2" and
             budget.get("campaign_id") == context["campaign_id"] and
             budget.get("host_id") == context["host_id"] and
             budget.get("budget_sha256") == _sha(_canonical(budget_body)) ==
                 budget_pin["semantic_sha256"],
             "host budget identity/semantic pin differs for object rows")
    original_pins = _exact(budget.get("original_pins"), {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256",
    }, "host budget original input pins")
    _digest(original_pins["source_tree_sha256"], "budget source tree SHA-256")
    source_pins = original_pins["source_manifests"]
    _require(type(source_pins) is dict and context["host_id"] in source_pins and
             _pin(original_pins["plan"], "budget PlanV3 pin") ==
                 context["plan_pin"] and
             _pin(original_pins["execution_manifest"],
                  "budget execution-manifest pin") ==
                 context["execution_manifest_pin"] and
             _pin(source_pins[context["host_id"]],
                  "budget SourceV5 pin") == context["source_manifest_pin"],
             "archive context Source/Plan/execution pins differ from host budget")
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict and
             catalogue.get("schema") ==
                 "allocatbelt.application-source5-host-path-catalogue.v2" and
             type(catalogue.get("chunks")) is list and
             bool(catalogue["chunks"]),
             "host budget lacks its exact path catalogue chunks")
    catalogue_body = {key: item for key, item in catalogue.items()
                      if key != "semantic_sha256"}
    _require(catalogue.get("semantic_sha256") ==
             _sha(_canonical(catalogue_body)),
             "host path catalogue semantic digest differs")
    retention = catalogue.get("retention_policy")
    _require(type(retention) is dict,
             "host path catalogue lacks the prospective live-window ceiling")
    window_bytes = _uint(retention.get("maximum_window_total_bytes"),
                         "host maximum live-window bytes")
    window_inodes = _uint(retention.get("maximum_window_total_inodes"),
                          "host maximum live-window inodes")
    _require(sum(row["byte_count"] for row in entries) <= window_bytes and
             len(entries) <= window_inodes,
             "job object closure exceeds its pinned live-window bytes/inodes")
    chunk_bytes = _uint(catalogue.get("chunk_bytes"),
                        "host path catalogue chunk byte cap", positive=True)
    entry_count = _uint(catalogue.get("entry_count"),
                        "host path catalogue entry count", positive=True)
    _require(chunk_bytes <= MAX_JSON_BYTES and entry_count <= MAX_ROWS,
             "host path catalogue exceeds its finite metadata row/byte bound")
    targets = {
        row["origin_path"]: (row["role"], row["byte_count"],
                             row["raw_sha256"], row["semantic_sha256"])
        for row in entries
    }
    _require(job_record_pin["path"] not in targets,
             "always-local job record appeared in reclaimable budget targets")
    targets[job_record_pin["path"]] = (
        "source5_job_record", job_record_bytes,
        job_record_pin["raw_sha256"], job_record_semantic_sha256,
    )
    descriptors = []
    previous_descriptor_path = ""
    previous_last_path = ""
    described_rows = 0
    for index, descriptor_value in enumerate(catalogue["chunks"]):
        descriptor = _exact(descriptor_value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "row_count", "first_path", "last_path",
        }, f"host path catalogue chunk[{index}]")
        chunk_path = _absolute_path(descriptor["path"],
                                    "host path catalogue chunk path")
        raw_sha = _digest(descriptor["raw_sha256"],
                          "host path catalogue chunk raw digest")
        semantic_sha = _digest(descriptor["semantic_sha256"],
                               "host path catalogue chunk semantic digest")
        byte_count = _uint(descriptor["byte_count"],
                           "host path catalogue chunk byte count", positive=True)
        row_count = _uint(descriptor["row_count"],
                          "host path catalogue chunk row count", positive=True)
        first_path = _absolute_path(descriptor["first_path"],
                                    "host catalogue first path")
        last_path = _absolute_path(descriptor["last_path"],
                                   "host catalogue last path")
        _require(chunk_path > previous_descriptor_path and
                 first_path <= last_path and first_path > previous_last_path and
                 semantic_sha == raw_sha and byte_count <= chunk_bytes and
                 row_count <= MAX_ROWS,
                 "host path catalogue chunk pins or order differ")
        previous_descriptor_path = chunk_path
        previous_last_path = last_path
        described_rows += row_count
        descriptors.append((first_path, last_path, chunk_path, raw_sha,
                            byte_count, row_count))
    _require(described_rows == entry_count,
             "host path catalogue chunk row counts do not close")
    cache_root = Path(_absolute_path(catalogue_cache_root,
                                     "private catalogue cache root"))
    cache_fd = _open_dir_path(str(cache_root), "private catalogue cache root",
                              private_final=True)
    os.close(cache_fd)
    _require(type(catalogue_chunk_paths) is dict and
             set(catalogue_chunk_paths) ==
                 {item[2] for item in descriptors},
             "Root-local catalogue chunk map does not close over its pinned budget")
    checked_local_paths = {}
    local_names = set()
    for descriptor in descriptors:
        origin = descriptor[2]
        local = Path(_absolute_path(catalogue_chunk_paths[origin],
                                    "Root-local catalogue chunk"))
        _require(local != cache_root and cache_root in local.parents and
                 str(local) != origin and str(local) not in local_names and
                 local.resolve(strict=True) == local,
                 "catalogue chunk is not a distinct file under the private cache root")
        local_names.add(str(local))
        checked_local_paths[origin] = str(local)
    selected = {}
    for target in targets:
        matches = [item for item in descriptors
                   if item[0] <= target <= item[1]]
        _require(len(matches) == 1,
                 "budgeted origin path is absent from one exact catalogue chunk")
        selected[matches[0][2]] = matches[0]
    found: dict[str, dict[str, Any]] = {}
    previous_path = ""
    for first_path, last_path, chunk_path, raw_sha, byte_count, row_count in sorted(
        selected.values(), key=lambda item: item[2],
    ):
        local_path = checked_local_paths[chunk_path]
        raw, actual_sha, _info = _read_absolute_private_file(
            Path(local_path), byte_count, "Root-local pinned host catalogue chunk",
        )
        _require(len(raw) == byte_count and actual_sha == raw_sha,
                 "host path catalogue chunk differs from its raw pin")
        lines = raw.splitlines(keepends=True)
        _require(len(lines) == row_count and bool(lines),
                 "host path catalogue chunk line count differs")
        chunk_first = ""
        chunk_last = ""
        for line_index, line in enumerate(lines):
            _require(line.endswith(b"\n") and b"\r" not in line and
                     len(line) <= 64 * 1024,
                     "host path catalogue row framing/size differs")
            row = _parse_canonical(
                line, f"host path catalogue row {chunk_path}:{line_index}",
            )
            row = _exact(row, {
                "path", "kind", "role", "host_id", "max_bytes",
                "max_file_bytes", "max_inodes", "storage_root", "owner",
                "phase", "run_id", "member_index", "aggregate_id",
                "aggregate_max_bytes", "origin_pin",
            }, "host path catalogue row")
            _require(_canonical(row) == line,
                     "host path catalogue row is not canonical")
            path = _absolute_path(row["path"], "host path catalogue origin")
            _require(path > previous_path and
                     row["kind"] in {"file", "tree"} and
                     row["role"] == _token(row["role"],
                                           "host catalogue role"),
                     "host path catalogue row order or kind differs")
            previous_path = path
            chunk_first = path if not chunk_first else chunk_first
            chunk_last = path
            for field in ("max_bytes", "max_file_bytes", "max_inodes"):
                _uint(row[field], f"host path catalogue {field}")
            if row["storage_root"] is not None:
                _absolute_path(row["storage_root"],
                               "host path catalogue storage root")
            _token(row["owner"], "host path catalogue owner")
            if row["host_id"] is not None:
                _token(row["host_id"], "host path catalogue host ID")
            if row["phase"] is not None:
                _token(row["phase"], "host path catalogue phase")
            if row["run_id"] is not None:
                _run_id(row["run_id"], "host path catalogue run ID")
            _require(
                     row["max_file_bytes"] <= row["max_bytes"] and
                     ((row["kind"] == "file" and row["max_inodes"] == 1) or
                      (row["kind"] == "tree" and row["max_inodes"] > 0)),
                     "host path catalogue row bounds/owner/group are malformed")
            if path in targets:
                _require(path not in found and row["kind"] == "file" and
                         row["host_id"] == context["host_id"] and
                         row["phase"] == context["phase"] and
                         row["run_id"] == job_identity["run_id"] and
                         row["role"] == targets[path][0] and
                         row["max_inodes"] == 1 and
                         row["max_file_bytes"] == row["max_bytes"] and
                         targets[path][1] <= row["max_file_bytes"],
                         "budgeted job object differs from its exact catalogue row/cap")
                if row["origin_pin"] is not None:
                    origin_pin = _exact(row["origin_pin"], {
                        "raw_sha256", "semantic_sha256",
                    }, "catalogued original object pin")
                    origin_raw = _digest(
                        origin_pin["raw_sha256"], "catalogued origin raw digest",
                    )
                    origin_semantic = origin_pin["semantic_sha256"]
                    if origin_semantic is not None:
                        origin_semantic = _digest(
                            origin_semantic,
                            "catalogued origin semantic digest",
                        )
                    _require(origin_raw == targets[path][2] and
                             origin_semantic == targets[path][3],
                             "request object differs from its catalogued origin pin")
                found[path] = row
        _require(chunk_first == first_path and chunk_last == last_path,
                 "host path catalogue chunk range differs from its raw rows")
    _require(set(found) == set(targets),
             "host path catalogue does not close over the exact job object set")


def _validate_job_record(
    context: dict[str, Any], job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    pin = _pin_raw(job_record_pin, "Source5 job record pin")
    _require(_sha(job_record_bytes) == pin["raw_sha256"],
             "Source5 job record bytes differ from their raw pin")
    record = _parse_canonical(job_record_bytes, "Source5 job record")
    _exact(record, {
        "schema", "state", "job", "pair_directory", "process_metrics",
        "evidence", "chronology", "qualification_eligible", "record_sha256",
    }, "Source5 job record")
    body = {key: item for key, item in record.items() if key != "record_sha256"}
    _require(record["schema"] == "allocatbelt.application-source5-job-record.v1" and
             record["record_sha256"] == _sha(_canonical(body)) and
             record["qualification_eligible"] is False,
             "Source5 job record schema, self digest, or eligibility differs")
    plan_pin = context["plan_pin"]
    _require(type(plan_bytes) is bytes and _sha(plan_bytes) ==
             plan_pin["raw_sha256"],
             "raw PlanV3 bytes differ from their archive context pin")
    plan = _parse_canonical(
        plan_bytes, "original PlanV3", maximum_bytes=MAX_PLAN_BYTES,
    )
    _require(plan.get("schema") == "allocatbelt.application-campaign-plan.v3" and
             plan.get("campaign_id") == context["campaign_id"] and
             plan.get("plan_sha256") == plan_pin["semantic_sha256"] and
             plan.get("plan_sha256") == _sha(_canonical({
                 key: item for key, item in plan.items()
                 if key != "plan_sha256"
             }, maximum_bytes=MAX_PLAN_BYTES)),
             "PlanV3 identity or semantic digest differs from the archive context")
    job = record["job"]
    _require(type(job) is dict and job.get("host_id") == context["host_id"] and
             job.get("phase") == context["phase"] and
             type(job.get("ordinal")) is int and job["ordinal"] > 0 and
             type(job.get("run_id")) is str and
             type(record["process_metrics"]) is list,
             "Source5 job record identity is malformed")
    phase_jobs = plan.get("jobs", {}).get(context["phase"])
    _require(type(phase_jobs) is list and
             all(type(item) is dict for item in phase_jobs),
             "PlanV3 lacks the exact original phase job list")
    host_jobs = [item for item in phase_jobs
                 if item.get("host_id") == context["host_id"]]
    _require(context["job_index"] < len(host_jobs) and
             host_jobs[context["job_index"]] == job,
             "Source5 job record differs from its original filtered PlanV3 ordinal")
    job_sha = _sha(_canonical(job))
    job_identity = {
        "job": job, "job_index": context["job_index"],
        "job_ordinal": job["ordinal"], "job_sha256": job_sha,
        "run_id": _run_id(job["run_id"], "Source5 run ID"),
    }
    predecessors = job.get("predecessor_run_ids", [])
    _require(type(predecessors) is list and
             all(type(item) is str and item for item in predecessors),
             "PlanV3 predecessor run list is malformed")
    _require((context["predecessor_ack_pin"] is None) == (not predecessors) and
             len(predecessors) <= 1,
             "predecessor ACK presence differs from the original PlanV3 job")
    chronology = _exact(record["chronology"], {
        "authorization_id", "authorization_head", "app_started_heads",
        "app_terminal_heads", "job_terminal_head", "component_sha256",
        "process_metrics_sha256", "app_start_events", "app_terminal_events",
        "member_processes",
    }, "Source5 job record chronology")
    authorization = {
        "authorization_id": _token(chronology["authorization_id"],
                                   "Source5 authorization ID"),
        "authorization_head": _digest(chronology["authorization_head"],
                                      "Source5 authorization head"),
        "terminal_head": _digest(chronology["job_terminal_head"],
                                 "Source5 terminal head"),
        "component_sha256": _digest(chronology["component_sha256"],
                                    "Source5 component digest"),
        "process_metrics_sha256": _digest(
            chronology["process_metrics_sha256"],
            "Source5 process metrics digest",
        ),
    }
    _require(authorization["process_metrics_sha256"] ==
             _sha(_canonical(record["process_metrics"])),
             "Source5 job record metrics differ from the terminal chain")
    _require(pin["path"].endswith("/" + job["run_id"] + ".json"),
             "Source5 job record path does not name its exact run ID")
    return record, authorization, job_identity


def _validate_rows(value: object) -> list[dict[str, Any]]:
    _require(type(value) in (list, tuple) and 0 < len(value) <= MAX_ROWS,
             "archive object rows are outside their finite count bound")
    rows: list[dict[str, Any]] = []
    prior = ""
    total = 0
    for index, row_value in enumerate(value):
        row = _exact(row_value, {
            "origin_path", "role", "byte_count", "raw_sha256", "semantic_sha256",
        }, f"archive row[{index}]")
        origin = _absolute_path(row["origin_path"], f"archive row[{index}] origin")
        role = _token(row["role"], f"archive row[{index}] role")
        _require(role not in NON_EXPORTABLE_JOB_ROLES,
                 "always-local job-record/disposition role is not reclaimable")
        count = _uint(row["byte_count"], f"archive row[{index}] byte count")
        _require(count <= MAX_OBJECT_BYTES and origin > prior,
                 "archive rows are unsorted, duplicated, or exceed the per-object ceiling")
        prior = origin
        total += count
        _require(total <= MAX_TOTAL_BYTES,
                 "archive rows exceed the fixed total-payload ceiling")
        semantic = row["semantic_sha256"]
        _require(semantic is None or
                 (type(semantic) is str and
                  re.fullmatch(r"[0-9a-f]{64}", semantic) is not None),
                 f"archive row[{index}] semantic SHA-256 is malformed")
        rows.append({
            "origin_path": origin, "role": role, "byte_count": count,
            "raw_sha256": _digest(row["raw_sha256"],
                                  f"archive row[{index}] raw SHA-256"),
            "semantic_sha256": semantic,
        })
    return rows


def _tmp_final_proof(
    final_value: object, receipt_pin: dict[str, str], role: str,
    ordinal: int, label: str,
) -> dict[str, Any]:
    final = _exact(final_value, {
        "path", "device", "inode", "mode", "mount", "bytes_used",
        "file_count", "directory_count", "bytes_limit", "inode_limit",
        "available_bytes", "available_inodes",
    }, f"{label} final TMPDIR facts")
    path = _absolute_path(final["path"], f"{label} TMPDIR path")
    for field in ("device", "inode", "mode", "bytes_used", "file_count",
                  "directory_count", "bytes_limit", "inode_limit",
                  "available_bytes", "available_inodes"):
        _uint(final[field], f"{label} TMPDIR {field}")
    mount = _exact(final["mount"], {
        "mount_id", "major_minor", "mount_root", "mount_point",
        "filesystem_type", "mount_source", "device",
    }, f"{label} TMPDIR mount identity")
    _require(type(mount["mount_id"]) is int and mount["mount_id"] > 0 and
             type(mount["major_minor"]) is str and
             re.fullmatch(r"[0-9]+:[0-9]+", mount["major_minor"]) is not None and
             type(mount["mount_root"]) is str and mount["mount_root"].startswith("/") and
             type(mount["mount_point"]) is str and mount["mount_point"].startswith("/") and
             type(mount["filesystem_type"]) is str and
             mount["filesystem_type"] not in {"tmpfs", "ramfs", "devtmpfs"} and
             type(mount["mount_source"]) is str and
             type(mount["device"]) is int and mount["device"] >= 0 and
             mount["device"] == final["device"] and
             final["inode"] > 0 and final["mode"] == 0o700 and
             final["bytes_used"] == 0 and final["file_count"] == 0 and
             final["directory_count"] == 0 and final["bytes_limit"] > 0 and
             final["inode_limit"] > 0,
             f"{label} TMPDIR is not an exact empty private directory")
    return {
        "role": role, "path": path, "owner_receipt_pin": dict(receipt_pin),
        "member_ordinal": ordinal, "device": final["device"],
        "inode": final["inode"], "mode": final["mode"],
        "mount": mount, "bytes_used": 0, "file_count": 0,
        "directory_count": 0, "bytes_limit": final["bytes_limit"],
        "inode_limit": final["inode_limit"],
    }


def _zero_fixed_tmp_proofs(
    receipt: dict[str, Any], receipt_pin: dict[str, str], role: str,
) -> list[dict[str, Any]]:
    if receipt.get("schema") != "allocatbelt.application-fixed-pair-execution-receipt.v1":
        return []
    if receipt.get("status") != "valid_pair":
        return []
    attempts = receipt.get("member_attempts")
    _require(type(attempts) is list and len(attempts) == 2,
             "successful fixed receipt lacks its two original member TMPDIR facts")
    proofs = []
    for ordinal, attempt in enumerate(attempts):
        _require(type(attempt) is dict and attempt.get("ordinal") == ordinal,
                 "fixed receipt TMPDIR members are not in original order")
        proofs.append(_tmp_final_proof(
            attempt.get("tmpdir_final"), receipt_pin, role, ordinal,
            f"fixed member {ordinal}",
        ))
    return proofs


def _zero_pressure_tmp_proofs(
    receipt: dict[str, Any], receipt_pin: dict[str, str], role: str,
) -> list[dict[str, Any]]:
    if receipt.get("schema") != "allocatbelt.application-pressure-pair-host-verification.v2":
        return []
    members = receipt.get("member_facts")
    _require(type(members) is list and len(members) == 2,
             "successful pressure receipt lacks two original member facts")
    proofs = []
    for ordinal, member in enumerate(members):
        _require(type(member) is dict and member.get("ordinal") == ordinal,
                 "pressure receipt member order differs from the original pair")
        storage = member.get("storage_proof")
        _require(type(storage) is dict and
                 "application_tmpdir_final" in storage,
                 "pressure owner receipt lacks its immediate final TMPDIR fact")
        proofs.append(_tmp_final_proof(
            storage["application_tmpdir_final"], receipt_pin, role,
            ordinal, f"pressure member {ordinal}",
        ))
    return proofs

def _zero_soak_tmp_proofs(
    receipt: dict[str, Any], receipt_pin: dict[str, str], role: str,
) -> list[dict[str, Any]]:
    if receipt.get("schema") != "allocatbelt.application-source5-soak-host-verification.v3":
        return []
    final = receipt.get("final_usage")
    domains = final.get("domains") if type(final) is dict else None
    domain = domains.get("application_tmpdir") if type(domains) is dict else None
    _require(type(domain) is dict and set(domain) == {"bytes_used", "inode_count"} and
             domain["bytes_used"] == 0 and domain["inode_count"] == 0,
             "successful Soak receipt does not prove zero application TMPDIR usage")
    origin = receipt.get("pressure_origin")
    _require(type(origin) is dict and
             type(origin.get("application_tmpdir_path")) is str,
             "Soak receipt lacks the original application TMPDIR path")
    inventory = receipt.get("evidence_inventory")
    _require(type(inventory) is list,
             "Soak receipt lacks its complete evidence inventory")
    return [{
        "role": role,
        "path": _absolute_path(origin["application_tmpdir_path"],
                                "Soak application TMPDIR path"),
        "owner_receipt_pin": dict(receipt_pin),
        "member_ordinal": 0, "domain": "application_tmpdir",
        "bytes_used": 0, "inode_count": 0,
        "inventory_sha256": _sha(_canonical(inventory)),
    }]


def _zero_usage_proofs(
    receipt: dict[str, Any], receipt_pin: dict[str, str], role: str,
) -> list[dict[str, Any]]:
    proofs = _zero_fixed_tmp_proofs(receipt, receipt_pin, role)
    if proofs:
        return proofs
    proofs = _zero_pressure_tmp_proofs(receipt, receipt_pin, role)
    if proofs:
        return proofs
    return _zero_soak_tmp_proofs(receipt, receipt_pin, role)


def _bind_owner_receipt_identity(
    receipt: dict[str, Any], context: dict[str, Any], job: dict[str, Any],
    label: str,
) -> None:
    for field, expected in (
        ("campaign_id", context["campaign_id"]),
        ("host_id", context["host_id"]),
        ("run_id", job["run_id"]),
    ):
        if field in receipt:
            _require(receipt[field] == expected,
                     f"{label} {field} differs from its original job")
    nested_job = receipt.get("job")
    if type(nested_job) is dict and "run_id" in nested_job:
        _require(nested_job["run_id"] == job["run_id"] and
                 nested_job.get("ordinal") == job["ordinal"],
                 f"{label} nested job differs from its original ordinal")
        if "job_index" in nested_job:
            _require(nested_job["job_index"] == context["job_index"],
                     f"{label} nested job index differs from raw PlanV3")


def _require_success_tmp_proofs(
    record: dict[str, Any], empty_tmp_proofs: list[dict[str, Any]],
) -> None:
    phase = record["job"]["phase"]
    state = record["state"]
    if state == "valid_pair":
        members = sorted(
            item["member_ordinal"] for item in empty_tmp_proofs
            if "domain" not in item
        )
        _require(members == [0, 1],
                 f"successful {phase} job lacks both owner-return zero TMPDIR facts")
    elif state == "valid_soak":
        domains = [item for item in empty_tmp_proofs
                   if item.get("domain") == "application_tmpdir"]
        _require(len(domains) == 1 and domains[0]["member_ordinal"] == 0 and
                 domains[0]["bytes_used"] == 0 and
                 domains[0]["inode_count"] == 0,
                 "successful Soak job lacks its exact zero-usage TMPDIR receipt")


def _checkpoint_request_projection(
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    checked_context = _validate_context(context)
    record, authorization, identity = _validate_job_record(
        checked_context, job_record_pin, job_record_bytes, plan_bytes,
    )
    checked_rows = _validate_rows(list(rows))
    job_pin = _pin_raw(job_record_pin, "Source5 job record pin")
    _require(all(row["origin_path"] != job_pin["path"]
                 for row in checked_rows),
             "always-local job record must not enter reclaimable object rows")
    _require(type(owner_receipt_bytes) is dict,
             "owner receipt bytes must be keyed by exact origin path")
    receipt_origins = {
        row["origin_path"] for row in checked_rows
        if "receipt" in row["role"].lower()
    }
    _require(set(owner_receipt_bytes) == receipt_origins,
             "owner receipt byte set differs from the exact receipt-role closure")
    by_origin = {row["origin_path"]: row for row in checked_rows}
    owner_pins: dict[str, dict[str, str]] = {}
    empty_proofs: list[dict[str, Any]] = []
    for origin, raw in owner_receipt_bytes.items():
        _absolute_path(origin, "owner receipt origin path")
        row = by_origin.get(origin)
        _require(row is not None and type(raw) is bytes and
                 len(raw) == row["byte_count"] and _sha(raw) == row["raw_sha256"],
                 "owner receipt bytes differ from their exact object row")
        receipt, semantic = _read_self_digest(
            raw, f"owner receipt {origin}",
            ("receipt_sha256", "record_sha256"),
        )
        _bind_owner_receipt_identity(
            receipt, checked_context, record["job"], f"owner receipt {row['role']}",
        )
        _require(row["semantic_sha256"] == semantic,
                 "owner receipt semantic digest differs from its pinned row")
        role = row["role"]
        _require(role not in owner_pins,
                 "owner receipt roles must be unique within one job")
        receipt_pin = {
            "path": origin, "raw_sha256": row["raw_sha256"],
            "semantic_sha256": semantic,
        }
        owner_pins[role] = receipt_pin
        empty_proofs.extend(_zero_usage_proofs(receipt, receipt_pin, role))
    owner_pins = {role: owner_pins[role] for role in sorted(owner_pins)}
    _require_success_tmp_proofs(record, empty_proofs)
    request_body = {
        "schema": REQUEST_SCHEMA_V1,
        "context": checked_context,
        "job_record_pin": job_pin,
        "authorization": authorization,
        "predecessor_ack_pin": checked_context["predecessor_ack_pin"],
        "owner_receipt_pins": owner_pins,
        "empty_tmp_proofs": sorted(
            empty_proofs, key=lambda item: (item["role"], item["member_ordinal"]),
        ),
        "entries": checked_rows,
        "request_sha256": "",
    }
    request_sha = _sha(_canonical({
        key: item for key, item in request_body.items()
        if key != "request_sha256"
    }))
    return ({**request_body, "request_sha256": request_sha},
            record, identity)


def _validate_checkpoint_request(value: object) -> dict[str, Any]:
    request = _exact(value, {
        "schema", "context", "job_record_pin", "authorization",
        "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
        "entries", "request_sha256",
    }, "Source5 job checkpoint request")
    _require(request["schema"] == REQUEST_SCHEMA_V1,
             "Source5 job checkpoint request schema differs")
    context = _validate_context(request["context"])
    _pin_raw(request["job_record_pin"], "checkpoint-request job record pin")
    _require(request["predecessor_ack_pin"] == context["predecessor_ack_pin"] and
             type(request["owner_receipt_pins"]) is dict and
             list(request["owner_receipt_pins"]) ==
                 sorted(request["owner_receipt_pins"]) and
             type(request["empty_tmp_proofs"]) is list,
             "checkpoint-request receipt/predecessor facts are malformed")
    entries = _validate_rows(request["entries"])
    job_pin = _pin_raw(request["job_record_pin"],
                       "checkpoint-request job record pin")
    _require(all(row["origin_path"] != job_pin["path"] for row in entries),
             "always-local job record must not enter reclaimable request entries")
    body = {key: item for key, item in request.items()
            if key != "request_sha256"}
    _require(request["request_sha256"] == _sha(_canonical(body)),
             "Source5 checkpoint-request self digest differs")
    # Validate proof/pin structure through the exact final-checkpoint validator
    # without inventing a manifest pin or publishing a final checkpoint.
    provisional = {
        "schema": CHECKPOINT_SCHEMA_V1,
        "request_pin": {
            "path": "/request.json", "raw_sha256": "0" * 64,
            "semantic_sha256": "0" * 64,
        },
        "context": context,
        "job_record_pin": request["job_record_pin"],
        "authorization": request["authorization"],
        "predecessor_ack_pin": request["predecessor_ack_pin"],
        "owner_receipt_pins": request["owner_receipt_pins"],
        "empty_tmp_proofs": request["empty_tmp_proofs"],
        "object_manifest_pin": {
            "path": "/manifest.json", "raw_sha256": "0" * 64,
            "semantic_sha256": "0" * 64,
        },
        "entries": entries, "checkpoint_sha256": "0" * 64,
    }
    _validate_checkpoint(provisional, validate_digest=False)
    return request


def build_checkpoint_request(
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes],
    output_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Write the immutable host intent sent with its one bounded transfer packet."""
    request, _record, _identity = _checkpoint_request_projection(
        context, job_record_pin, job_record_bytes, plan_bytes, rows,
        owner_receipt_bytes,
    )
    output = Path(_absolute_path(os.fspath(output_path),
                                 "checkpoint-request output path"))
    _require(output.parent.is_dir() and
             output.parent.resolve(strict=True) == output.parent,
             "checkpoint-request output parent is absent or aliased")
    parent_fd = _open_dir_path(str(output.parent),
                               "checkpoint-request output parent",
                               private_final=True)
    try:
        raw = _canonical(request)
        raw_sha, size = _write_at(
            parent_fd, output.name, raw, "Source5 checkpoint request",
        )
        reopened, reopened_sha, _ = _read_at(
            parent_fd, output.name, MAX_JSON_BYTES,
            "Source5 checkpoint request", expected_bytes=size,
        )
        _require(reopened == raw and reopened_sha == raw_sha,
                 "checkpoint request failed independent reopen verification")
        return request, {
            "path": str(output), "raw_sha256": raw_sha,
            "semantic_sha256": request["request_sha256"],
        }
    finally:
        os.close(parent_fd)


def build_job_checkpoint(
    request_pin: object, request_bytes: bytes,
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes],
    object_manifest_pin: object,
    output_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Write the final checkpoint after its durable object manifest exists."""
    request, _record, _identity = _checkpoint_request_projection(
        context, job_record_pin, job_record_bytes, plan_bytes, rows,
        owner_receipt_bytes,
    )
    checked_request_pin = _pin(request_pin, "checkpoint request pin")
    _require(type(request_bytes) is bytes and
             _sha(request_bytes) == checked_request_pin["raw_sha256"] and
             _parse_canonical(request_bytes, "checkpoint request") == request and
             checked_request_pin["semantic_sha256"] == request["request_sha256"],
             "checkpoint request differs from its exact raw/semantic pin")
    manifest_pin = _pin(object_manifest_pin, "Source5 object manifest pin")
    checked_context = _validate_context(context)
    job_pin = _pin_raw(job_record_pin, "Source5 job record pin")
    checkpoint_body = {
        "schema": CHECKPOINT_SCHEMA_V1,
        "request_pin": checked_request_pin,
        "context": checked_context,
        "job_record_pin": job_pin,
        "authorization": request["authorization"],
        "predecessor_ack_pin": request["predecessor_ack_pin"],
        "owner_receipt_pins": request["owner_receipt_pins"],
        "empty_tmp_proofs": request["empty_tmp_proofs"],
        "object_manifest_pin": manifest_pin,
        "entries": request["entries"],
        "checkpoint_sha256": "",
    }
    checkpoint_digest = _sha(_canonical({
        key: item for key, item in checkpoint_body.items()
        if key != "checkpoint_sha256"
    }))
    checkpoint = {**checkpoint_body, "checkpoint_sha256": checkpoint_digest}
    output = Path(_absolute_path(os.fspath(output_path),
                                 "checkpoint output path"))
    _require(output.parent.is_dir() and
             output.parent.resolve(strict=True) == output.parent,
             "checkpoint output parent is absent or aliased")
    parent_fd = _open_dir_path(str(output.parent), "checkpoint output parent",
                               private_final=True)
    try:
        raw = _canonical(checkpoint)
        raw_sha, size = _write_at(
            parent_fd, output.name, raw, "final Source5 job checkpoint",
        )
        reopened, reopened_sha, _ = _read_at(
            parent_fd, output.name, MAX_JSON_BYTES,
            "final Source5 job checkpoint", expected_bytes=size,
        )
        _require(reopened == raw and reopened_sha == raw_sha,
                 "final checkpoint failed independent reopen verification")
        return checkpoint, {
            "path": str(output), "raw_sha256": raw_sha,
            "semantic_sha256": checkpoint_digest,
        }
    finally:
        os.close(parent_fd)

def _validate_checkpoint(
    value: object, *, validate_digest: bool = True,
) -> dict[str, Any]:
    checkpoint = _exact(value, {
        "schema", "request_pin", "context", "job_record_pin", "authorization",
        "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
        "object_manifest_pin", "entries", "checkpoint_sha256",
    }, "Source5 job checkpoint")
    _require(checkpoint["schema"] == CHECKPOINT_SCHEMA_V1,
             "Source5 job checkpoint schema differs")
    _pin(checkpoint["request_pin"], "checkpoint request pin")
    context = _validate_context(checkpoint["context"])
    _pin_raw(checkpoint["job_record_pin"], "checkpoint job record pin")
    _require(checkpoint["predecessor_ack_pin"] == context["predecessor_ack_pin"],
             "checkpoint predecessor differs from its context")
    _require(type(checkpoint["owner_receipt_pins"]) is dict and
             list(checkpoint["owner_receipt_pins"]) ==
                 sorted(checkpoint["owner_receipt_pins"]) and
             type(checkpoint["empty_tmp_proofs"]) is list,
             "checkpoint receipt or TMP proof maps are malformed")
    entries = _validate_rows(checkpoint["entries"])
    job_origin = checkpoint["job_record_pin"]["path"]
    _require(all(row["origin_path"] != job_origin for row in entries),
             "always-local job record must not enter reclaimable checkpoint entries")
    by_origin = {row["origin_path"]: row for row in entries}
    for role, value_pin in checkpoint["owner_receipt_pins"].items():
        _token(role, "checkpoint owner receipt role")
        owner_pin = _pin(value_pin, f"checkpoint owner receipt {role}")
        row = by_origin.get(owner_pin["path"])
        _require(row is not None and row["role"] == role and
                 row["raw_sha256"] == owner_pin["raw_sha256"] and
                 row["semantic_sha256"] == owner_pin["semantic_sha256"],
                 "checkpoint owner receipt pin has no exact closure row")
    proof_order = []
    for index, proof_value in enumerate(checkpoint["empty_tmp_proofs"]):
        _require(type(proof_value) is dict,
                 f"checkpoint empty TMP proof[{index}] is malformed")
        proof = proof_value
        role = _token(proof.get("role"), "empty TMP proof role")
        owner_pin = _pin(proof.get("owner_receipt_pin"),
                         "empty TMP proof owner receipt")
        _require(checkpoint["owner_receipt_pins"].get(role) == owner_pin and
                 proof.get("bytes_used") == 0,
                 "empty TMP proof is not tied to its exact zero-usage owner receipt")
        if proof.get("domain") == "application_tmpdir":
            _exact(proof, {
                "role", "path", "owner_receipt_pin", "member_ordinal",
                "domain", "bytes_used", "inode_count", "inventory_sha256",
            }, f"Soak empty TMP proof[{index}]")
            _absolute_path(proof["path"], "Soak empty TMP path")
            _uint(proof["member_ordinal"], "Soak TMP member ordinal")
            _require(proof["inode_count"] == 0,
                     "Soak application TMPDIR inode count is not zero")
            _digest(proof["inventory_sha256"], "Soak TMP inventory digest")
        else:
            _exact(proof, {
                "role", "path", "owner_receipt_pin", "member_ordinal",
                "device", "inode", "mode", "mount", "bytes_used",
                "file_count", "directory_count", "bytes_limit", "inode_limit",
            }, f"empty TMP proof[{index}]")
            _absolute_path(proof["path"], "empty TMP path")
            for field in ("member_ordinal", "device", "inode", "mode",
                          "file_count", "directory_count", "bytes_limit",
                          "inode_limit"):
                _uint(proof[field], f"empty TMP proof {field}")
            _require(proof["inode"] > 0 and proof["mode"] == 0o700 and
                     proof["file_count"] == 0 and
                     proof["directory_count"] == 0 and
                     proof["bytes_limit"] > 0 and proof["inode_limit"] > 0,
                     "empty TMP proof counters or private identity differ")
            mount = _exact(proof["mount"], {
                "mount_id", "major_minor", "mount_root", "mount_point",
                "filesystem_type", "mount_source", "device",
            }, "empty TMP proof mount")
            _require(mount["device"] == proof["device"],
                     "empty TMP mount device differs from the owner proof")
        proof_order.append((role, proof["member_ordinal"]))
    _require(proof_order == sorted(proof_order) and
             len(proof_order) == len(set(proof_order)),
             "checkpoint empty TMP proofs are not sorted unique")
    manifest_pin = checkpoint["object_manifest_pin"]
    _pin(manifest_pin, "checkpoint object-manifest pin")
    body = {key: item for key, item in checkpoint.items()
            if key != "checkpoint_sha256"}
    if validate_digest:
        _require(checkpoint["checkpoint_sha256"] == _sha(_canonical(body)),
                 "Source5 checkpoint self digest differs")
    return checkpoint


def _object_identity(origin_path: str, raw_sha256: str) -> str:
    origin_name = _sha(origin_path.encode("utf-8"))
    return f"{origin_name[:2]}/{origin_name}-{raw_sha256}.bin"


def _staged_descriptor(
    path_value: object, staging_root: str, expected: dict[str, Any],
) -> tuple[dict[str, Any], bytes | None]:
    path_text = _absolute_path(path_value, "local staged file path")
    root = Path(_absolute_path(staging_root, "private staging root"))
    path = Path(path_text)
    _require(path != root and root in path.parents,
             "staged file escapes its caller-reserved private staging root")
    rel = path.relative_to(root).as_posix()
    root_fd = _open_dir_path(str(root), "private staging root", private_final=True)
    parent_fd, name = _open_parent(root_fd, rel, create=False,
                                   label="staged file")
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISREG(before.st_mode):
            _require(before.st_uid == os.getuid() and
                     stat.S_IMODE(before.st_mode) == 0o600 and
                     before.st_nlink == 1 and before.st_size <= MAX_OBJECT_BYTES,
                     "staged regular file is not owned, private, single-link, and bounded")
            descriptor = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                                 _O_NONBLOCK, dir_fd=parent_fd)
            try:
                opened = os.fstat(descriptor)
                _require(_info_key(opened) == _info_key(before),
                         "staged file changed identity before open")
                hasher = hashlib.sha256()
                total = 0
                while total < opened.st_size:
                    block = os.read(descriptor, min(COPY_BLOCK_BYTES,
                                                    opened.st_size - total))
                    _require(bool(block), "staged file ended before its pinned size")
                    total += len(block)
                    _require(total <= expected["byte_count"] and
                             total <= MAX_OBJECT_BYTES,
                             "staged file grew beyond the exact object size")
                    hasher.update(block)
                _require(os.read(descriptor, 1) == b"" and
                         total == opened.st_size == expected["byte_count"],
                         "staged file size differs from its checkpoint row")
                after = os.fstat(descriptor)
                after_path = os.stat(name, dir_fd=parent_fd,
                                     follow_symlinks=False)
                _require(_info_key(opened) == _info_key(after) ==
                         _info_key(after_path),
                         "staged file changed while being hashed")
                digest = hasher.hexdigest()
                _require(digest == expected["raw_sha256"],
                         "staged file bytes differ from the checkpoint raw pin")
                return ({
                    "path": path_text, "kind": "regular",
                    "device": after.st_dev, "inode": after.st_ino,
                    "mode": stat.S_IMODE(after.st_mode),
                    "byte_count": total, "raw_sha256": digest,
                }, None)
            finally:
                os.close(descriptor)
        _require(stat.S_ISLNK(before.st_mode) and before.st_uid == os.getuid() and
                 before.st_nlink == 1,
                 "staged object is neither an owned regular file nor a literal symlink")
        target_before = os.readlink(name, dir_fd=parent_fd)
        raw_target = os.fsencode(target_before)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        target_after = os.readlink(name, dir_fd=parent_fd)
        _require(_info_key(before) == _info_key(after) and
                 target_before == target_after and
                 len(raw_target) == expected["byte_count"] and
                 _sha(raw_target) == expected["raw_sha256"],
                 "staged literal symlink bytes differ from the checkpoint raw pin")
        return ({
            "path": path_text, "kind": "symlink",
            "device": after.st_dev, "inode": after.st_ino,
            "mode": stat.S_IMODE(after.st_mode),
            "byte_count": len(raw_target), "raw_sha256": _sha(raw_target),
        }, raw_target)
    finally:
        os.close(parent_fd)
        os.close(root_fd)


def _copy_object(
    archive_root_fd: int, object_id: str, staged_path: str,
    staging_root: str, expected: dict[str, Any],
) -> tuple[dict[str, str], dict[str, Any]]:
    source_descriptor, literal = _staged_descriptor(staged_path, staging_root, expected)
    parent_fd, name = _open_parent(
        archive_root_fd, f"objects/{object_id}", create=True,
        label="archive object",
    )
    try:
        try:
            existing_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing_info = None
        if existing_info is not None:
            _require(stat.S_ISREG(existing_info.st_mode) and
                     existing_info.st_uid == os.getuid() and
                     stat.S_IMODE(existing_info.st_mode) == 0o600 and
                     existing_info.st_nlink == 1,
                     "existing content-addressed object is not private and single-link")
            raw, digest, info = _read_at(
                parent_fd, name, expected["byte_count"], "existing archive object",
                expected_bytes=expected["byte_count"], collect=False,
            )
            _require(raw is None and digest == expected["raw_sha256"],
                     "existing content-addressed object has different bytes")
            os.fsync(parent_fd)
        else:
            output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                _O_CLOEXEC | _O_NOFOLLOW, 0o600,
                                dir_fd=parent_fd)
            try:
                os.fchmod(output_fd, 0o600)
                if literal is not None:
                    view = memoryview(literal)
                    while view:
                        count = os.write(output_fd, view)
                        _require(count > 0, "literal-link object writer made no progress")
                        view = view[count:]
                else:
                    staging_root_path = Path(staging_root)
                    source = Path(staged_path)
                    source_rel = source.relative_to(staging_root_path).as_posix()
                    stage_root_fd = _open_dir_path(
                        staging_root, "private staging root", private_final=True,
                    )
                    stage_parent_fd, stage_name = _open_parent(
                        stage_root_fd, source_rel, create=False,
                        label="staged source",
                    )
                    source_fd = os.open(
                        stage_name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                        _O_NONBLOCK, dir_fd=stage_parent_fd,
                    )
                    try:
                        source_before = os.fstat(source_fd)
                        _require(stat.S_ISREG(source_before.st_mode) and
                                 source_before.st_uid == os.getuid() and
                                 stat.S_IMODE(source_before.st_mode) == 0o600 and
                                 source_before.st_nlink == 1 and
                                 source_before.st_size == expected["byte_count"] and
                                 source_before.st_dev == source_descriptor["device"] and
                                 source_before.st_ino == source_descriptor["inode"] and
                                 stat.S_IMODE(source_before.st_mode) ==
                                     source_descriptor["mode"],
                                 "staged regular file changed before object copy")
                        hasher = hashlib.sha256()
                        total = 0
                        while total < source_before.st_size:
                            block = os.read(source_fd, min(COPY_BLOCK_BYTES,
                                                           source_before.st_size - total))
                            _require(bool(block), "staged regular file ended during copy")
                            total += len(block)
                            _require(total <= expected["byte_count"],
                                     "staged regular file exceeded its exact copy bound")
                            hasher.update(block)
                            view = memoryview(block)
                            while view:
                                count = os.write(output_fd, view)
                                _require(count > 0,
                                         "archive object writer made no progress")
                                view = view[count:]
                        _require(os.read(source_fd, 1) == b"" and
                                 total == expected["byte_count"] and
                                 hasher.hexdigest() == expected["raw_sha256"] and
                                 _info_key(source_before) ==
                                 _info_key(os.fstat(source_fd)),
                                 "staged source changed or failed its exact copy hash")
                    finally:
                        os.close(source_fd)
                        os.close(stage_parent_fd)
                        os.close(stage_root_fd)
                os.fsync(output_fd)
            finally:
                os.close(output_fd)
            os.fsync(parent_fd)
            raw, digest, info = _read_at(
                parent_fd, name, expected["byte_count"], "new archive object",
                expected_bytes=expected["byte_count"], collect=False,
            )
            _require(raw is None and digest == expected["raw_sha256"],
                     "archive object failed independent reopen hashing")
        staged_after, _literal_after = _staged_descriptor(
            staged_path, staging_root, expected,
        )
        _require(staged_after == source_descriptor,
                 "staged local identity changed during archive object copy")
        pin = {
            "path": object_id, "raw_sha256": digest,
            "semantic_sha256": digest, "byte_count": info.st_size,
        }
        return pin, source_descriptor
    finally:
        os.close(parent_fd)


def _gpg_sign(raw: bytes, signer: object) -> bytes:
    config = _exact(signer, {
        "gpg_executable", "gpg_homedir", "primary_fingerprint",
        "maximum_signature_bytes",
    }, "archive signer configuration")
    executable = _absolute_path(config["gpg_executable"], "GPG executable")
    homedir = _absolute_path(config["gpg_homedir"], "private signing home")
    fingerprint = _fingerprint(config["primary_fingerprint"],
                               "archive signer fingerprint")
    signature_limit = _uint(config["maximum_signature_bytes"],
                            "campaign signature byte ceiling", positive=True)
    _require(signature_limit <= MAX_GPG_OUTPUT_BYTES,
             "campaign signature byte ceiling exceeds its generic parser limit")
    homedir_fd = _open_dir_path(homedir, "private signing home",
                                private_final=True)
    os.close(homedir_fd)
    _gpg_raw_before, gpg_sha_before, _gpg_info = _read_absolute_executable(
        Path(executable), MAX_OBJECT_BYTES, "GPG signing executable",
    )
    command = [
        executable, "--no-options", "--batch", "--no-tty", "--no-armor",
        "--digest-algo", "SHA256", "--homedir", homedir,
        "--local-user", fingerprint + "!", "--detach-sign", "--output", "-",
    ]
    try:
        result = subprocess.run(
            command, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False, close_fds=True,
            env={"LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceArchiveError(f"GPG detached signing failed: {error}") from error
    _require(result.returncode == 0 and
             0 < len(result.stdout) <= signature_limit,
             "GPG detached signature exceeds its pinned campaign quota")
    _gpg_raw_after, gpg_sha_after, _gpg_info_after = _read_absolute_executable(
        Path(executable), MAX_OBJECT_BYTES, "GPG signing executable after sign",
    )
    _require(gpg_sha_after == gpg_sha_before,
             "GPG signing executable changed during detached signing")
    return result.stdout


def _verify_detached_signature(
    ack_raw: bytes, signature_raw: bytes, signer_pin: object,
) -> str:
    signer = _exact(signer_pin, {
        "fingerprint", "keyring_pin", "gpgv_pin",
    }, "archive verification signer pin")
    fingerprint = _fingerprint(signer["fingerprint"],
                               "archive verification fingerprint")
    keyring_pin = _pin_raw(signer["keyring_pin"], "archive public keyring pin")
    gpgv_pin = _pin_raw(signer["gpgv_pin"], "pinned gpgv executable")
    keyring = Path(keyring_pin["path"])
    keyring_raw, keyring_sha, _ = _read_absolute_external_file(
        keyring, MAX_GPG_OUTPUT_BYTES * 16, "archive public keyring",
    )
    _require(keyring_sha == keyring_pin["raw_sha256"],
             "archive public keyring changed from its raw pin")
    gpgv_path = Path(gpgv_pin["path"])
    _gpgv_raw, gpgv_sha, _ = _read_absolute_executable(
        gpgv_path, MAX_OBJECT_BYTES, "pinned gpgv executable",
    )
    _require(gpgv_sha == gpgv_pin["raw_sha256"],
             "gpgv executable changed from its raw pin")
    with _private_temp_pair(ack_raw, signature_raw, keyring_raw) as (
        ack_path, sig_path, keyring_path,
    ):
        try:
            result = subprocess.run(
                [str(gpgv_path), "--status-fd", "1", "--keyring",
                 str(keyring_path), str(sig_path), str(ack_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30, check=False,
                close_fds=True, env={"LC_ALL": "C", "LANG": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EvidenceArchiveError(f"gpgv ACK verification failed: {error}") from error
    _require(result.returncode == 0,
             "gpgv rejected the durable ACK detached signature")
    try:
        lines = result.stdout.decode("ascii", "strict").splitlines()
    except UnicodeError as error:
        raise EvidenceArchiveError("gpgv status output is not ASCII") from error
    valid = [line.split() for line in lines if line.startswith("[GNUPG:] VALIDSIG ")]
    rejected = [line for line in lines if line.startswith((
        "[GNUPG:] BADSIG ", "[GNUPG:] ERRSIG ", "[GNUPG:] NO_PUBKEY ",
        "[GNUPG:] REVKEYSIG ", "[GNUPG:] EXPKEYSIG ", "[GNUPG:] EXPSIG ",
    ))]
    _require(len(valid) == 1 and not rejected and len(valid[0]) >= 4,
             "gpgv status lacks one unambiguous valid signature")
    status = valid[0]
    signing_fingerprint = _fingerprint(status[2].upper(),
                                        "gpgv signing fingerprint")
    primary_raw = status[-1] if len(status) >= 12 else status[2]
    primary_fingerprint = _fingerprint(primary_raw.upper(),
                                       "gpgv primary fingerprint")
    _require(primary_fingerprint == fingerprint and
             signing_fingerprint == fingerprint,
             "detached ACK signer or primary fingerprint differs from its pin")
    return primary_fingerprint


def _read_absolute_private_file(
    path: Path, maximum: int, label: str,
) -> tuple[bytes, str, os.stat_result]:
    path_text = _absolute_path(str(path), f"{label} path")
    require_path = Path(path_text)
    _require(require_path.resolve(strict=True) == require_path,
             f"{label} path traverses a symlink or alias")
    parent_fd = _open_dir_path(str(require_path.parent), f"{label} parent",
                               private_final=False)
    try:
        raw, digest, info = _read_at(parent_fd, require_path.name, maximum, label)
        return raw, digest, info
    finally:
        os.close(parent_fd)


def _hash_absolute_private_file(
    path: Path, maximum: int, label: str,
) -> tuple[str, os.stat_result]:
    path_text = _absolute_path(str(path), f"{label} path")
    checked = Path(path_text)
    _require(checked.resolve(strict=True) == checked,
             f"{label} path traverses a symlink or alias")
    parent_fd = _open_dir_path(str(checked.parent), f"{label} parent",
                               private_final=False)
    try:
        raw, digest, info = _read_at(
            parent_fd, checked.name, maximum, label, collect=False,
        )
        _require(raw is None, f"{label} unexpectedly allocated its full contents")
        return digest, info
    finally:
        os.close(parent_fd)


def _validate_local_dependencies(
    dependency_paths: dict[str, str], dependency_cache_root: str,
    context: dict[str, Any], plan_bytes: bytes, host_budget_raw: bytes,
) -> None:
    root = Path(_absolute_path(dependency_cache_root,
                               "private dependency cache root"))
    root_fd = _open_dir_path(str(root), "private dependency cache root",
                             private_final=True)
    os.close(root_fd)
    pins = {
        "source": context["source_manifest_pin"],
        "plan": context["plan_pin"],
        "budget": context["resource_budget_pin"],
    }
    _require(type(dependency_paths) is dict and
             set(dependency_paths) == {pin["path"] for pin in pins.values()},
             "Root-local dependency map does not close over Source/Plan/budget pins")
    local_paths = set()
    checked = {}
    for kind, pin in pins.items():
        local = Path(_absolute_path(dependency_paths[pin["path"]],
                                    f"Root-local {kind} path"))
        _require(local != root and root in local.parents and
                 str(local) != pin["path"] and str(local) not in local_paths and
                 local.resolve(strict=True) == local,
                 f"Root-local {kind} copy is aliased or outside its private cache")
        local_paths.add(str(local))
        checked[kind] = (local, pin)
    plan_local, plan_pin = checked["plan"]
    local_plan, plan_sha, _plan_info = _read_absolute_private_file(
        plan_local, MAX_PLAN_BYTES, "Root-local original PlanV3",
    )
    _require(plan_sha == plan_pin["raw_sha256"] and local_plan == plan_bytes,
             "PlanV3 bytes used by the coordinator differ from their Root-local captured pin")
    budget_local, budget_pin = checked["budget"]
    local_budget, budget_sha, _budget_info = _read_absolute_private_file(
        budget_local, MAX_JSON_BYTES, "Root-local host evidence budget",
    )
    _require(budget_sha == budget_pin["raw_sha256"] and
             local_budget == host_budget_raw,
             "host budget bytes used by the coordinator differ from their Root-local captured pin")
    source_local, source_pin = checked["source"]
    source_sha, _source_info = _hash_absolute_private_file(
        source_local, MAX_SOURCE_MANIFEST_BYTES,
        "Root-local Source manifest",
    )
    _require(source_sha == source_pin["raw_sha256"],
             "Root-local Source manifest differs from its origin raw pin")


def _read_absolute_external_file(
    path: Path, maximum: int, label: str,
) -> tuple[bytes, str, os.stat_result]:
    """Read a pinned public key/tool without trusting its path ancestors."""
    path_text = _absolute_path(str(path), f"{label} path")
    checked = Path(path_text)
    _require(checked.resolve(strict=True) == checked,
             f"{label} path traverses a symlink or alias")
    parent_fd = _open_dir_path(str(checked.parent), f"{label} parent",
                               private_final=False)
    try:
        try:
            before_path = os.stat(checked.name, dir_fd=parent_fd,
                                  follow_symlinks=False)
            _require(stat.S_ISREG(before_path.st_mode) and
                     before_path.st_uid in {0, os.getuid()} and
                     before_path.st_nlink == 1 and
                     before_path.st_size <= maximum,
                     f"{label} is not a bounded root/user-owned regular file")
            descriptor = os.open(checked.name, os.O_RDONLY | _O_CLOEXEC |
                                 _O_NOFOLLOW | _O_NONBLOCK, dir_fd=parent_fd)
        except OSError as error:
            raise EvidenceArchiveError(f"cannot open {label}: {error}") from error
        try:
            before = os.fstat(descriptor)
            _require(_info_key(before) == _info_key(before_path),
                     f"{label} changed identity before read")
            hasher = hashlib.sha256()
            chunks = []
            total = 0
            while total < before.st_size:
                block = os.read(descriptor, min(COPY_BLOCK_BYTES,
                                                before.st_size - total))
                _require(bool(block), f"{label} ended before its pinned size")
                total += len(block)
                _require(total <= maximum and total <= before.st_size,
                         f"{label} exceeded its bounded read")
                hasher.update(block)
                chunks.append(block)
            _require(os.read(descriptor, 1) == b"" and total == before.st_size,
                     f"{label} has trailing bytes or changed size")
            after = os.fstat(descriptor)
            after_path = os.stat(checked.name, dir_fd=parent_fd,
                                 follow_symlinks=False)
            _require(_info_key(before) == _info_key(after) ==
                     _info_key(after_path), f"{label} changed during stable read")
            return b"".join(chunks), hasher.hexdigest(), after
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _read_absolute_executable(
    path: Path, maximum: int, label: str,
) -> tuple[bytes, str, os.stat_result]:
    raw, digest, info = _read_absolute_external_file(path, maximum, label)
    _require(stat.S_IMODE(info.st_mode) & 0o111,
             f"{label} is not executable")
    return raw, digest, info


class _private_temp_pair:
    """Create bounded private GPG inputs and remove only these exact temp names."""

    def __init__(self, ack_raw: bytes, signature_raw: bytes,
                 keyring_raw: bytes) -> None:
        self.ack_raw = ack_raw
        self.signature_raw = signature_raw
        self.keyring_raw = keyring_raw
        self.directory = None
        self.paths: tuple[Path, Path] | None = None

    def __enter__(self) -> tuple[Path, Path, Path]:
        import tempfile
        directory = tempfile.mkdtemp(prefix="source5-ack-verify-", dir="/tmp")
        os.chmod(directory, 0o700)
        self.directory = Path(directory)
        _require(self.directory.parent == Path("/tmp") and
                 self.directory.lstat().st_uid == os.getuid() and
                 stat.S_IMODE(self.directory.lstat().st_mode) == 0o700,
                 "GPG verification inputs are outside an owned private temp directory")
        ack_path = self.directory / "ack.json"
        signature_path = self.directory / "ack.sig"
        keyring_path = self.directory / "trusted-keyring.gpg"
        for path, raw in ((ack_path, self.ack_raw),
                          (signature_path, self.signature_raw),
                          (keyring_path, self.keyring_raw)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         _O_CLOEXEC | _O_NOFOLLOW, 0o600)
            try:
                view = memoryview(raw)
                while view:
                    count = os.write(fd, view)
                    _require(count > 0, "GPG verification input writer made no progress")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
        self.paths = (ack_path, signature_path, keyring_path)
        return self.paths

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.paths is not None:
            for path in self.paths:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            try:
                self.directory.rmdir()
            except FileNotFoundError:
                pass


def archive_job_checkpoint(
    request_pin: object, request_bytes: bytes,
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, host_budget_raw: bytes,
    dependency_paths: dict[str, str],
    dependency_cache_root: str | os.PathLike[str],
    catalogue_chunk_paths: dict[str, str],
    catalogue_cache_root: str | os.PathLike[str], rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes], staged_files: dict[str, str],
    staging_root: str | os.PathLike[str], archive_root: str | os.PathLike[str],
    stage_map_path: str | os.PathLike[str], signer: object,
) -> dict[str, Any]:
    """Copy, seal, and sign one completed job outside every timed lane."""
    rows = list(rows)
    checked_context = _validate_context(context)
    _validate_local_dependencies(
        dependency_paths,
        _absolute_path(os.fspath(dependency_cache_root),
                       "private dependency cache root"),
        checked_context, plan_bytes, host_budget_raw,
    )
    signature_limit = _campaign_signature_limit(
        host_budget_raw, checked_context["resource_budget_pin"],
        checked_context,
    )
    signer_value = _exact(signer, {
        "gpg_executable", "gpg_homedir", "primary_fingerprint",
        "maximum_signature_bytes",
    }, "private archive signing configuration")
    _require(_fingerprint(signer_value["primary_fingerprint"],
                          "private archive signer fingerprint") ==
             checked_context["authorized_signer_fingerprint"] and
             _uint(signer_value["maximum_signature_bytes"],
                   "private signer signature quota", positive=True) ==
                 signature_limit,
             "private signer fingerprint/quota differs from the pinned campaign budget")
    request, _request_record, job_identity = _checkpoint_request_projection(
        checked_context, job_record_pin, job_record_bytes, plan_bytes, rows,
        owner_receipt_bytes,
    )
    checked_request_pin = _pin(request_pin, "host checkpoint request pin")
    _require(type(request_bytes) is bytes and
             _sha(request_bytes) == checked_request_pin["raw_sha256"] and
             _parse_canonical(request_bytes, "transferred checkpoint request") ==
                 request and
             checked_request_pin["semantic_sha256"] == request["request_sha256"],
             "transferred checkpoint request differs from its raw/semantic pin")
    record, _authorization, job_identity = _validate_job_record(
        checked_context, job_record_pin, job_record_bytes, plan_bytes,
    )
    checked_rows = _validate_rows(list(rows))
    job_pin = _pin_raw(job_record_pin, "Source5 job record pin")
    _require(all(row["origin_path"] != job_pin["path"]
                 for row in checked_rows),
             "always-local job record must not enter the reclaimable object closure")
    _validate_host_budget_object_rows(
        host_budget_raw, checked_context, job_identity, checked_rows,
        job_pin, len(job_record_bytes), record["record_sha256"],
        catalogue_chunk_paths,
        _absolute_path(os.fspath(catalogue_cache_root),
                       "private catalogue cache root"),
    )
    _require(type(staged_files) is dict and
             set(staged_files) == {row["origin_path"] for row in checked_rows},
             "staged-file map is not a complete exact-origin mapping")
    stage_root = _absolute_path(os.fspath(staging_root), "private staging root")
    archive = _absolute_path(os.fspath(archive_root), "private archive root")
    context_value = checked_context
    phase = _token(context_value["phase"], "original phase")
    leaf = (f"{job_identity['job_ordinal']:06d}-"
            f"{job_identity['job_sha256']}.json")
    checkpoint_relative = f"checkpoints/{phase}/{leaf}"
    manifest_relative = f"objects/manifests/{phase}/{leaf}"
    ack_relative = f"acks/{phase}/{leaf}"
    signature_relative = f"acks/signatures/{phase}/{leaf[:-5]}.sig"

    archive_root_fd = _open_dir_path(archive, "private archive root",
                                     private_final=True)
    try:
        campaign_fd = _ensure_private_child(
            archive_root_fd, context_value["campaign_id"],
            "archive campaign directory",
        )
        try:
            host_fd = _ensure_private_child(
                campaign_fd, context_value["host_id"], "archive host directory",
            )
            try:
                source5_fd = _ensure_private_child(
                    host_fd, "source5", "archive Source5 directory",
                )
                try:
                    validation_relative = (
                        f"validation/job-records/{phase}/{leaf}"
                    )
                    validation_parent, validation_name = _open_parent(
                        source5_fd, validation_relative, create=True,
                        label="always-local Source5 job-record validation",
                    )
                    try:
                        try:
                            validation_raw_sha, validation_size = _write_at(
                                validation_parent, validation_name,
                                job_record_bytes,
                                "always-local Source5 job record",
                            )
                        except FileExistsError:
                            validation_raw_sha = _sha(job_record_bytes)
                            validation_size = len(job_record_bytes)
                        validation_reopened, validation_reopened_sha, _ = _read_at(
                            validation_parent, validation_name, MAX_JSON_BYTES,
                            "always-local Source5 job record",
                            expected_bytes=validation_size,
                        )
                        _require(validation_reopened == job_record_bytes and
                                 validation_reopened_sha == validation_raw_sha ==
                                     job_pin["raw_sha256"],
                                 "always-local job record failed independent reopen")
                    finally:
                        os.close(validation_parent)
                    job_record_validation = {
                        "path": str(
                            Path(archive) / context_value["campaign_id"] /
                            context_value["host_id"] / "source5" /
                            validation_relative
                        ),
                        "origin_path": job_pin["path"],
                        "raw_sha256": validation_raw_sha,
                        "semantic_sha256": record["record_sha256"],
                        "byte_count": validation_size,
                    }
                    object_rows = []
                    stage_rows = []
                    payload_bytes = 0
                    for row in checked_rows:
                        origin = row["origin_path"]
                        object_id = _object_identity(origin, row["raw_sha256"])
                        object_pin, staged_descriptor = _copy_object(
                            source5_fd, object_id, staged_files[origin],
                            stage_root, row,
                        )
                        relative_object = f"objects/{object_id}"
                        object_pin = {
                            "path": str(Path(archive) /
                                        context_value["campaign_id"] /
                                        context_value["host_id"] / "source5" /
                                        relative_object),
                            "raw_sha256": object_pin["raw_sha256"],
                            "semantic_sha256": object_pin["semantic_sha256"],
                            "byte_count": object_pin["byte_count"],
                        }
                        object_rows.append({
                            "origin_path": origin, "role": row["role"],
                            "object_id": object_id,
                            "byte_count": row["byte_count"],
                            "raw_sha256": row["raw_sha256"],
                            "semantic_sha256": row["semantic_sha256"],
                            "object_pin": object_pin,
                        })
                        stage_rows.append({
                            "origin_path": origin, "object_id": object_id,
                            "remote_object_pin": dict(object_pin),
                            "local_staged_file": staged_descriptor,
                        })
                        payload_bytes += row["byte_count"]
                        _require(payload_bytes <= MAX_TOTAL_BYTES,
                                 "job archive exceeds the fixed total payload ceiling")

                    manifest_body = {
                        "schema": OBJECT_MANIFEST_SCHEMA_V1,
                        "campaign_id": context_value["campaign_id"],
                        "host_id": context_value["host_id"],
                        "phase": phase,
                        "job_index": context_value["job_index"],
                        "job_ordinal": job_identity["job_ordinal"],
                        "job_sha256": job_identity["job_sha256"],
                        "run_id": job_identity["run_id"],
                        "job_record_raw_sha256": job_pin["raw_sha256"],
                        "predecessor_ack_pin":
                            context_value["predecessor_ack_pin"],
                        "objects": object_rows,
                        "object_count": len(object_rows),
                        "payload_bytes": payload_bytes,
                        "manifest_sha256": "",
                    }
                    manifest_sha = _sha(_canonical({
                        key: item for key, item in manifest_body.items()
                        if key != "manifest_sha256"
                    }))
                    manifest = {**manifest_body, "manifest_sha256": manifest_sha}
                    manifest_raw = _canonical(manifest)
                    manifest_parent, manifest_name = _open_parent(
                        source5_fd, manifest_relative, create=True,
                        label="Source5 object manifest",
                    )
                    try:
                        manifest_raw_sha, manifest_size = _write_at(
                            manifest_parent, manifest_name, manifest_raw,
                            "Source5 object manifest",
                        )
                        reopened, reopened_sha, _ = _read_at(
                            manifest_parent, manifest_name, MAX_JSON_BYTES,
                            "Source5 object manifest",
                            expected_bytes=manifest_size,
                        )
                        _require(reopened == manifest_raw and
                                 reopened_sha == manifest_raw_sha,
                                 "object manifest failed independent reopen")
                    finally:
                        os.close(manifest_parent)
                    manifest_pin = {
                        "path": str(Path(archive) /
                                    context_value["campaign_id"] /
                                    context_value["host_id"] / "source5" /
                                    manifest_relative),
                        "raw_sha256": manifest_raw_sha,
                        "semantic_sha256": manifest_sha,
                    }

                    checkpoint_path = str(
                        Path(archive) / context_value["campaign_id"] /
                        context_value["host_id"] / "source5" /
                        checkpoint_relative
                    )
                    checkpoint_parent, _checkpoint_name = _open_parent(
                        source5_fd, checkpoint_relative, create=True,
                        label="final Source5 checkpoint",
                    )
                    os.close(checkpoint_parent)
                    checkpoint, checkpoint_pin = build_job_checkpoint(
                        checked_request_pin, request_bytes, checked_context,
                        job_pin, job_record_bytes, plan_bytes, checked_rows,
                        owner_receipt_bytes, manifest_pin, checkpoint_path,
                    )
                    checked_manifest = _validate_manifest(
                        manifest, checkpoint, job_identity,
                    )
                    object_reopen_sha = _verify_archive_objects(
                        checked_manifest,
                    )

                    root_info = os.fstat(source5_fd)
                    archive_directory = {
                        "path": str(Path(archive) /
                                    context_value["campaign_id"] /
                                    context_value["host_id"] / "source5"),
                        "device": root_info.st_dev, "inode": root_info.st_ino,
                        "mode": stat.S_IMODE(root_info.st_mode),
                    }
                    durable_commit = {
                        "commit_id": _sha(_canonical({
                            "checkpoint_pin": checkpoint_pin,
                            "object_manifest_pin": manifest_pin,
                            "object_reopen_sha256": object_reopen_sha,
                            "job_record_validation": job_record_validation,
                        })),
                        "archive_source5_directory": archive_directory,
                        "job_record_validation": job_record_validation,
                        "checkpoint_pin": checkpoint_pin,
                        "object_manifest_pin": manifest_pin,
                        "object_reopen_sha256": object_reopen_sha,
                        "object_count": len(object_rows),
                        "payload_bytes": payload_bytes,
                    }
                    fingerprint = _fingerprint(
                        context_value["authorized_signer_fingerprint"],
                        "authorized signer fingerprint",
                    )
                    ack_body = {
                        "schema": ACK_SCHEMA_V1,
                        "checkpoint_pin": checkpoint_pin,
                        "object_manifest_pin": manifest_pin,
                        "predecessor_ack_pin":
                            context_value["predecessor_ack_pin"],
                        "signer_fingerprint": fingerprint,
                        "durable_commit": durable_commit,
                        "ack_sha256": "",
                    }
                    ack_sha = _sha(_canonical({
                        key: item for key, item in ack_body.items()
                        if key != "ack_sha256"
                    }))
                    ack = {**ack_body, "ack_sha256": ack_sha}
                    ack_raw = _canonical(ack)
                    signature_raw = _gpg_sign(ack_raw, signer_value)
                    ack_parent, ack_name = _open_parent(
                        source5_fd, ack_relative, create=True,
                        label="Source5 durable ACK",
                    )
                    try:
                        ack_raw_sha, ack_size = _write_at(
                            ack_parent, ack_name, ack_raw,
                            "Source5 durable ACK",
                        )
                        reopened, reopened_sha, _ = _read_at(
                            ack_parent, ack_name, MAX_JSON_BYTES,
                            "Source5 durable ACK", expected_bytes=ack_size,
                        )
                        _require(reopened == ack_raw and
                                 reopened_sha == ack_raw_sha,
                                 "durable ACK failed independent reopen")
                    finally:
                        os.close(ack_parent)
                    signature_parent, signature_name = _open_parent(
                        source5_fd, signature_relative, create=True,
                        label="Source5 ACK signature",
                    )
                    try:
                        signature_sha, signature_size = _write_at(
                            signature_parent, signature_name, signature_raw,
                            "Source5 detached signature",
                        )
                        signature_read, signature_read_sha, _ = _read_at(
                            signature_parent, signature_name,
                            signature_limit, "Source5 detached signature",
                            expected_bytes=signature_size,
                        )
                        _require(signature_read == signature_raw and
                                 signature_read_sha == signature_sha,
                                 "detached signature failed independent reopen")
                    finally:
                        os.close(signature_parent)

                    stage_map_body = {
                        "schema": STAGE_MAP_SCHEMA_V1,
                        "checkpoint_pin": checkpoint_pin,
                        "object_manifest_pin": manifest_pin,
                        "rows": stage_rows,
                        "stage_map_sha256": "",
                    }
                    stage_map_sha = _sha(_canonical({
                        key: item for key, item in stage_map_body.items()
                        if key != "stage_map_sha256"
                    }))
                    stage_map = {
                        **stage_map_body, "stage_map_sha256": stage_map_sha,
                    }
                    stage_raw = _canonical(stage_map)
                    stage_path = Path(_absolute_path(
                        os.fspath(stage_map_path), "stage-map output path",
                    ))
                    stage_parent_fd = _open_dir_path(
                        str(stage_path.parent), "stage-map output parent",
                        private_final=True,
                    )
                    try:
                        stage_raw_sha, stage_size = _write_at(
                            stage_parent_fd, stage_path.name, stage_raw,
                            "Source5 stage map",
                        )
                        stage_reopened, stage_reopened_sha, _ = _read_at(
                            stage_parent_fd, stage_path.name, MAX_JSON_BYTES,
                            "Source5 stage map", expected_bytes=stage_size,
                        )
                        _require(stage_reopened == stage_raw and
                                 stage_reopened_sha == stage_raw_sha,
                                 "stage map failed independent reopen")
                    finally:
                        os.close(stage_parent_fd)
                    stage_map_pin = {
                        "path": str(stage_path), "raw_sha256": stage_raw_sha,
                        "semantic_sha256": stage_map_sha,
                    }
                    checked_stage_map = _validate_stage_map(
                        stage_map, checkpoint, checked_manifest,
                    )
                    _require(checked_stage_map == stage_map,
                             "stage map changed during archive sealing")
                    return {
                        "request": request,
                        "request_pin": checked_request_pin,
                        "checkpoint": checkpoint,
                        "checkpoint_pin": checkpoint_pin,
                        "object_manifest": manifest,
                        "object_manifest_pin": manifest_pin,
                        "ack": ack,
                        "ack_pin": {
                            "path": str(Path(archive) /
                                        context_value["campaign_id"] /
                                        context_value["host_id"] / "source5" /
                                        ack_relative),
                            "raw_sha256": ack_raw_sha,
                            "semantic_sha256": ack_sha,
                        },
                        "signature_pin": {
                            "path": str(Path(archive) /
                                        context_value["campaign_id"] /
                                        context_value["host_id"] / "source5" /
                                        signature_relative),
                            "raw_sha256": signature_sha,
                            "signer_fingerprint": fingerprint,
                        },
                        "job_record_validation": job_record_validation,
                        "coordinator_stage_map": stage_map,
                        "coordinator_stage_map_pin": stage_map_pin,
                        "object_pin_map": {
                            row["origin_path"]: row["object_pin"]
                            for row in object_rows
                        },
                    }
                finally:
                    os.close(source5_fd)
            finally:
                os.close(host_fd)
        finally:
            os.close(campaign_fd)
    finally:
        os.close(archive_root_fd)

def _read_object_pin(pin: object, byte_count: int) -> tuple[None, dict[str, Any]]:
    object_pin = _exact(pin, {
        "path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "captured object pin")
    path = Path(_absolute_path(object_pin["path"], "captured object path"))
    parent_fd = _open_dir_path(str(path.parent), "captured object parent",
                               private_final=True)
    try:
        raw, digest, info = _read_at(
            parent_fd, path.name, byte_count, "captured object",
            expected_bytes=byte_count, collect=False,
        )
    finally:
        os.close(parent_fd)
    _require(raw is None and byte_count == object_pin["byte_count"] and
             digest == object_pin["raw_sha256"] ==
                 object_pin["semantic_sha256"],
             "captured object differs from its exact raw/semantic pin")
    return None, object_pin


def _validate_stage_map(value: object, checkpoint: dict[str, Any],
                        manifest: dict[str, Any]) -> dict[str, Any]:
    stage_map = _exact(value, {
        "schema", "checkpoint_pin", "object_manifest_pin", "rows",
        "stage_map_sha256",
    }, "Source5 local stage map")
    _require(stage_map["schema"] == STAGE_MAP_SCHEMA_V1 and
             type(stage_map["rows"]) is list,
             "Source5 local stage map schema/rows differ")
    body = {key: item for key, item in stage_map.items()
            if key != "stage_map_sha256"}
    _require(stage_map["stage_map_sha256"] == _sha(_canonical(body)),
             "Source5 local stage map self digest differs")
    manifest_rows = manifest["objects"]
    rows = stage_map["rows"]
    _require(len(rows) == len(checkpoint["entries"]) == len(manifest_rows),
             "stage map is not one-to-one with checkpoint and object manifest")
    expected_by_origin = {row["origin_path"]: row for row in manifest_rows}
    prior = ""
    for index, value_row in enumerate(rows):
        row = _exact(value_row, {
            "origin_path", "object_id", "remote_object_pin",
            "local_staged_file",
        }, f"stage map row[{index}]")
        origin = _absolute_path(row["origin_path"],
                                f"stage map row[{index}] origin")
        _require(origin > prior and origin in expected_by_origin,
                 "stage map origins are unsorted or unexpected")
        prior = origin
        expected = expected_by_origin[origin]
        _require(row["object_id"] == expected["object_id"] and
                 row["remote_object_pin"] == expected["object_pin"],
                 "stage map object identity differs from the exact manifest row")
        local = _exact(row["local_staged_file"], {
            "path", "kind", "device", "inode", "mode", "byte_count",
            "raw_sha256",
        }, f"stage map row[{index}] local staged file")
        _absolute_path(local["path"], "stage map local staged file path")
        _require(local["kind"] in {"regular", "symlink"} and
                 type(local["device"]) is int and local["device"] >= 0 and
                 type(local["inode"]) is int and local["inode"] > 0 and
                 type(local["mode"]) is int and local["mode"] >= 0,
                 "stage map local file identity is malformed")
        _uint(local["byte_count"], "stage map local byte count")
        _digest(local["raw_sha256"], "stage map local raw digest")
    return stage_map


def _validate_manifest(
    value: object, checkpoint: dict[str, Any], job_identity: dict[str, Any],
) -> dict[str, Any]:
    manifest = _exact(value, {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "job_ordinal", "job_sha256", "run_id", "job_record_raw_sha256",
        "predecessor_ack_pin",
        "objects", "object_count", "payload_bytes", "manifest_sha256",
    }, "Source5 object manifest")
    context = checkpoint["context"]
    _require(manifest["schema"] == OBJECT_MANIFEST_SCHEMA_V1 and
             manifest["campaign_id"] == context["campaign_id"] and
             manifest["host_id"] == context["host_id"] and
             manifest["phase"] == context["phase"] and
             manifest["job_index"] == context["job_index"] and
             manifest["job_ordinal"] == job_identity["job_ordinal"] and
             manifest["job_sha256"] == job_identity["job_sha256"] and
             manifest["run_id"] == job_identity["run_id"] and
             manifest["job_record_raw_sha256"] ==
                 checkpoint["job_record_pin"]["raw_sha256"] and
             manifest["predecessor_ack_pin"] ==
                 checkpoint["predecessor_ack_pin"] and
             type(manifest["objects"]) is list,
             "object manifest identity differs from its checkpoint")
    entries = checkpoint["entries"]
    _require(len(manifest["objects"]) == len(entries) ==
             manifest["object_count"] and len(entries) <= MAX_ROWS,
             "object manifest row count differs from checkpoint")
    total = 0
    for row, obj in zip(entries, manifest["objects"], strict=True):
        exact_obj = _exact(obj, {
            "origin_path", "role", "object_id", "byte_count", "raw_sha256",
            "semantic_sha256", "object_pin",
        }, "object manifest entry")
        expected_object_id = _object_identity(row["origin_path"],
                                              row["raw_sha256"])
        _require(exact_obj["origin_path"] == row["origin_path"] and
                 exact_obj["role"] == row["role"] and
                 exact_obj["object_id"] == expected_object_id and
                 exact_obj["byte_count"] == row["byte_count"] and
                 exact_obj["raw_sha256"] == row["raw_sha256"] and
                 exact_obj["semantic_sha256"] == row["semantic_sha256"],
                 "object manifest entry differs from its exact checkpoint row")
        object_pin = _exact(exact_obj["object_pin"], {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
        }, "object pin")
        _absolute_path(object_pin["path"], "object pin path")
        _require(object_pin["path"].endswith("/objects/" + expected_object_id) and
                 object_pin["raw_sha256"] == row["raw_sha256"] and
                 object_pin["semantic_sha256"] == row["raw_sha256"] and
                 object_pin["byte_count"] == row["byte_count"],
                 "object pin does not use accepted Source5 v3 content-address naming")
        total += row["byte_count"]
        _require(total <= MAX_TOTAL_BYTES,
                 "manifest payload exceeds the fixed aggregate ceiling")
    _require(manifest["payload_bytes"] == total,
             "object manifest payload byte total differs")
    body = {key: item for key, item in manifest.items()
            if key != "manifest_sha256"}
    _require(manifest["manifest_sha256"] == _sha(_canonical(body)),
             "object manifest self digest differs")
    return manifest


def _validate_archive_path_bindings(
    source5_path: str, checkpoint_pin: dict[str, str],
    manifest_pin: dict[str, str], ack_pin: dict[str, str],
    signature_pin: dict[str, Any], manifest: dict[str, Any],
    context: dict[str, Any], identity: dict[str, Any],
) -> None:
    root = Path(_absolute_path(source5_path, "signed archive Source5 root"))
    _require(root.name == "source5" and root.parent.name == context["host_id"] and
             root.parent.parent.name == context["campaign_id"],
             "signed archive root is outside the exact campaign/host layout")
    phase = context["phase"]
    leaf = f"{identity['job_ordinal']:06d}-{identity['job_sha256']}.json"
    expected = {
        "checkpoint": root / "checkpoints" / phase / leaf,
        "manifest": root / "objects" / "manifests" / phase / leaf,
        "ack": root / "acks" / phase / leaf,
        "signature": root / "acks" / "signatures" / phase /
                    f"{leaf[:-5]}.sig",
    }
    for label, actual in (
        ("checkpoint", checkpoint_pin["path"]),
        ("manifest", manifest_pin["path"]),
        ("ack", ack_pin["path"]),
        ("signature", signature_pin["path"]),
    ):
        _require(Path(_absolute_path(actual, f"signed {label} path")) ==
                 expected[label],
                 f"signed {label} path differs from deterministic Source5 layout")
    for item in manifest["objects"]:
        _require(Path(item["object_pin"]["path"]) ==
                 root / "objects" / item["object_id"],
                 "signed object path differs from the accepted v3 object root")


def _verify_archive_objects(manifest: dict[str, Any]) -> str:
    projection = []
    for item in manifest["objects"]:
        pin = item["object_pin"]
        _read_object_pin(pin, item["byte_count"])
        checked_pin = pin
        projection.append({
            "object_id": item["object_id"], "path": checked_pin["path"],
            "raw_sha256": checked_pin["raw_sha256"],
            "byte_count": item["byte_count"],
        })
    return _sha(_canonical(projection))


def _read_staged_raw(
    path_text: str, staging_root: str, expected: dict[str, Any],
) -> bytes:
    descriptor, literal = _staged_descriptor(path_text, staging_root, expected)
    if literal is not None:
        return literal
    path = Path(path_text)
    root = Path(staging_root)
    root_fd = _open_dir_path(str(root), "private staging root",
                             private_final=True)
    parent_fd, name = _open_parent(
        root_fd, path.relative_to(root).as_posix(), create=False,
        label="staged evidence object",
    )
    try:
        fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                     _O_NONBLOCK, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and
                     before.st_size == expected["byte_count"] and
                     before.st_size <= MAX_OBJECT_BYTES,
                     "staged evidence object changed type or size")
            pieces = []
            total = 0
            while total < before.st_size:
                block = os.read(fd, min(COPY_BLOCK_BYTES,
                                        before.st_size - total))
                _require(bool(block), "staged evidence object shortened while reading")
                total += len(block)
                pieces.append(block)
            _require(os.read(fd, 1) == b"" and
                     _info_key(before) == _info_key(os.fstat(fd)),
                     "staged evidence object changed during bounded read")
            raw = b"".join(pieces)
            _require(_sha(raw) == expected["raw_sha256"],
                     "staged evidence object changed after its exact path check")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(root_fd)


def _validate_host_stage_closure(
    checkpoint: dict[str, Any], manifest: dict[str, Any],
    stage_map: dict[str, Any], staging_root: str,
) -> str:
    rows_by_origin = {row["origin_path"]: row for row in stage_map["rows"]}
    _require(set(rows_by_origin) == {
        row["origin_path"] for row in checkpoint["entries"]
    }, "host stage map is not the exact per-job origin closure")
    projection = []
    for entry, obj in zip(checkpoint["entries"], manifest["objects"], strict=True):
        staged = rows_by_origin[entry["origin_path"]]
        local = staged["local_staged_file"]
        measured, _literal = _staged_descriptor(
            local["path"], staging_root, entry,
        )
        _require(measured == local,
                 "local staged object identity changed from the pinned stage map")
        _require(staged["object_id"] == obj["object_id"] and
                 staged["remote_object_pin"] == obj["object_pin"],
                 "host stage map differs from the signed object manifest")
        projection.append({
            "object_id": obj["object_id"],
            "path": obj["object_pin"]["path"],
            "raw_sha256": obj["object_pin"]["raw_sha256"],
            "byte_count": obj["byte_count"],
        })
    return _sha(_canonical(projection))


def _verify_owner_receipt_bytes(
    checkpoint: dict[str, Any], stage_map: dict[str, Any],
    staging_root: str, job: dict[str, Any],
) -> dict[str, bytes]:
    entries = {row["origin_path"]: row for row in checkpoint["entries"]}
    staged = {row["origin_path"]: row for row in stage_map["rows"]}
    owner_bytes: dict[str, bytes] = {}
    _require(type(checkpoint["owner_receipt_pins"]) is dict,
             "checkpoint owner receipt pin map is malformed")
    for role, raw_pin in checkpoint["owner_receipt_pins"].items():
        pin = _pin(raw_pin, f"owner receipt pin {role}")
        row = entries.get(pin["path"])
        map_row = staged.get(pin["path"])
        _require(row is not None and map_row is not None and
                 row["role"] == role and row["raw_sha256"] == pin["raw_sha256"] and
                 row["semantic_sha256"] == pin["semantic_sha256"],
                 f"owner receipt {role} is not bound to one exact closure row")
        raw = _read_staged_raw(map_row["local_staged_file"]["path"],
                               staging_root, row)
        owner_bytes[pin["path"]] = raw
        receipt, semantic = _read_self_digest(
            raw, f"owner receipt {role}",
            ("receipt_sha256", "record_sha256"),
        )
        _bind_owner_receipt_identity(
            receipt, checkpoint["context"], job, f"owner receipt {role}",
        )
        _require(semantic == pin["semantic_sha256"],
                 f"owner receipt {role} semantic digest differs")
        expected_proofs = _zero_usage_proofs(receipt, pin, role)
        if expected_proofs:
            matching = [item for item in checkpoint["empty_tmp_proofs"]
                        if item.get("role") == role]
            _require(matching == expected_proofs,
                     f"owner {role} TMPDIR proof differs from its raw receipt")
    return owner_bytes


def verify_durable_ack(
    checkpoint_pin: object, checkpoint: object, checkpoint_raw: bytes,
    request_raw: bytes, host_budget_raw: bytes,
    job_record_pin: object, job_record_bytes: bytes, plan_bytes: bytes,
    object_manifest_pin: object, object_manifest: object, manifest_raw: bytes,
    ack_pin: object, ack: object, ack_raw: bytes,
    signature_pin: object, signature_raw: bytes,
    signer_context_pin: object, signer_context_raw: bytes,
    execution_manifest_pin: object, execution_manifest_raw: bytes,
    stage_map_pin: object, stage_map: object, staging_root: str | os.PathLike[str],
    expected_predecessor: object,
) -> dict[str, Any]:
    """Verify transferred bytes and signature without opening private-store paths.

    Absolute object paths in the manifest are authenticated origin identities.
    On the host this verifier rehashes the already-owned originals in the local
    stage map and never claims to reopen a Root-private archive path.
    """
    checked_checkpoint = _validate_checkpoint(checkpoint)
    checked_context = checked_checkpoint["context"]
    check_pin = _pin(checkpoint_pin, "checkpoint pin")
    _require(type(checkpoint_raw) is bytes and
             _sha(checkpoint_raw) == check_pin["raw_sha256"] and
             _parse_canonical(checkpoint_raw, "transferred checkpoint") ==
                 checked_checkpoint and
             check_pin["semantic_sha256"] ==
                 checked_checkpoint["checkpoint_sha256"],
             "transferred checkpoint bytes differ from their exact pin")
    _require(_pin_raw(job_record_pin, "Source5 job record pin") ==
             checked_checkpoint["job_record_pin"],
             "job record pin differs from its checkpoint")
    record, authorization, identity = _validate_job_record(
        checked_context, job_record_pin, job_record_bytes, plan_bytes,
    )
    _require(authorization == checked_checkpoint["authorization"] and
             checked_checkpoint["predecessor_ack_pin"] ==
                 checked_context["predecessor_ack_pin"],
             "checkpoint authorization or predecessor differs from raw Plan/record")
    _require_success_tmp_proofs(
        record, checked_checkpoint["empty_tmp_proofs"],
    )
    if expected_predecessor is None:
        _require(checked_checkpoint["predecessor_ack_pin"] is None,
                 "first original job has a predecessor ACK")
    else:
        _require(_pin(expected_predecessor, "expected predecessor ACK") ==
                 checked_checkpoint["predecessor_ack_pin"],
                 "checkpoint is not bound to the exact expected predecessor ACK")
    checked_manifest_pin = _pin(
        object_manifest_pin, "transferred object manifest pin",
    )
    _require(checked_checkpoint["object_manifest_pin"] == checked_manifest_pin and
             type(manifest_raw) is bytes and
             _sha(manifest_raw) == checked_manifest_pin["raw_sha256"] and
             _parse_canonical(manifest_raw, "transferred object manifest") ==
                 object_manifest,
             "transferred object manifest bytes differ from checkpoint pin")
    manifest = _validate_manifest(object_manifest, checked_checkpoint, identity)
    _require(_semantic_for_document(manifest) ==
             checked_manifest_pin["semantic_sha256"],
             "transferred object manifest semantic digest differs")
    checked_ack_pin = _pin(ack_pin, "transferred durable ACK pin")
    _require(type(ack_raw) is bytes and
             _sha(ack_raw) == checked_ack_pin["raw_sha256"] and
             _parse_canonical(ack_raw, "transferred durable ACK") == ack,
             "transferred ACK bytes differ from their raw pin")
    checked_ack = _exact(ack, {
        "schema", "checkpoint_pin", "object_manifest_pin",
        "predecessor_ack_pin", "signer_fingerprint", "durable_commit",
        "ack_sha256",
    }, "Source5 durable ACK")
    ack_body = {key: item for key, item in checked_ack.items()
                if key != "ack_sha256"}
    _require(checked_ack["schema"] == ACK_SCHEMA_V1 and
             checked_ack["ack_sha256"] == _sha(_canonical(ack_body)) and
             checked_ack_pin["semantic_sha256"] == checked_ack["ack_sha256"] and
             checked_ack["checkpoint_pin"] == check_pin and
             checked_ack["object_manifest_pin"] == checked_manifest_pin and
             checked_ack["predecessor_ack_pin"] ==
                 checked_checkpoint["predecessor_ack_pin"],
             "durable ACK does not bind the exact checkpoint/manifest/predecessor")
    signer = _validate_archive_signer_context(
        signer_context_raw, signer_context_pin, checked_context,
        host_budget_raw, execution_manifest_pin, execution_manifest_raw,
    )
    fingerprint = signer["fingerprint"]
    signature_limit = signer["maximum_signature_bytes"]
    _require(fingerprint == checked_context["authorized_signer_fingerprint"] and
             checked_ack["signer_fingerprint"] == fingerprint and
             signature_limit > 0,
             "durable ACK signer differs from externally pinned authority")
    durable = _exact(checked_ack["durable_commit"], {
        "commit_id", "archive_source5_directory", "checkpoint_pin",
        "object_manifest_pin", "object_reopen_sha256", "object_count",
        "payload_bytes", "job_record_validation",
    }, "durable commit facts")
    archive_dir = _exact(durable["archive_source5_directory"], {
        "path", "device", "inode", "mode",
    }, "durable archive directory identity")
    archive_dir_path = _absolute_path(
        archive_dir["path"], "durable archive directory path",
    )
    _uint(archive_dir["device"], "durable archive directory device")
    _uint(archive_dir["inode"], "durable archive directory inode", positive=True)
    _require(archive_dir["mode"] == 0o700 and
             durable["checkpoint_pin"] == check_pin and
             durable["object_manifest_pin"] == checked_manifest_pin and
             durable["object_count"] == manifest["object_count"] and
             durable["payload_bytes"] == manifest["payload_bytes"],
             "signed durable commit facts differ from the exact transferred manifest")
    validation_pin = _exact(durable["job_record_validation"], {
        "path", "origin_path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "durable always-local job-record validation")
    expected_validation_path = (
        Path(archive_dir_path) / "validation" / "job-records" /
        checked_context["phase"] /
        f"{identity['job_ordinal']:06d}-{identity['job_sha256']}.json"
    )
    _require(Path(_absolute_path(validation_pin["path"],
                                 "durable job-record validation path")) ==
                 expected_validation_path and
             validation_pin["origin_path"] ==
                 checked_checkpoint["job_record_pin"]["path"] and
             _digest(validation_pin["raw_sha256"],
                     "durable job-record raw digest") ==
                 checked_checkpoint["job_record_pin"]["raw_sha256"] ==
                 _sha(job_record_bytes) and
             _digest(validation_pin["semantic_sha256"],
                     "durable job-record semantic digest") ==
                 record["record_sha256"] and
             _uint(validation_pin["byte_count"],
                   "durable job-record byte count", positive=True) ==
                 len(job_record_bytes),
             "signed durable job-record validation facts differ from the original local pin")
    checked_signature = _exact(signature_pin, {
        "path", "raw_sha256", "signer_fingerprint",
    }, "detached signature pin")
    _validate_archive_path_bindings(
        archive_dir_path, check_pin, checked_manifest_pin, checked_ack_pin,
        checked_signature, manifest, checked_context, identity,
    )
    stage = _validate_stage_map(stage_map, checked_checkpoint, manifest)
    stage_pin = _pin(stage_map_pin, "transferred local stage-map pin")
    _require(type(stage_pin["path"]) is str and
             _absolute_path(stage_pin["path"], "stage-map path") and
             stage_pin["semantic_sha256"] == stage["stage_map_sha256"],
             "stage-map pin differs from its semantic body")
    stage_raw_file, stage_raw_sha, _ = _read_absolute_private_file(
        Path(stage_pin["path"]), MAX_JSON_BYTES, "local stage map",
    )
    _require(stage_raw_sha == stage_pin["raw_sha256"] and
             stage_raw_file == _canonical(stage),
             "local stage map file differs from its exact pin")
    staging = _absolute_path(os.fspath(staging_root), "private staging root")
    object_projection_sha = _validate_host_stage_closure(
        checked_checkpoint, manifest, stage, staging,
    )
    owner_receipt_bytes = _verify_owner_receipt_bytes(
        checked_checkpoint, stage, staging, record["job"],
    )
    request_pin = _pin(checked_checkpoint["request_pin"],
                       "checkpoint request pin")
    request = _validate_checkpoint_request(
        _parse_canonical(request_raw, "transferred checkpoint request"),
    )
    expected_request, _request_record, _request_identity = \
        _checkpoint_request_projection(
            checked_context, job_record_pin, job_record_bytes, plan_bytes,
            checked_checkpoint["entries"], owner_receipt_bytes,
        )
    _require(_sha(request_raw) == request_pin["raw_sha256"] and
             request_pin["semantic_sha256"] == request["request_sha256"] and
             request == expected_request and
             request["context"] == checked_context and
             request["job_record_pin"] == checked_checkpoint["job_record_pin"] and
             request["authorization"] == checked_checkpoint["authorization"] and
             request["predecessor_ack_pin"] ==
                 checked_checkpoint["predecessor_ack_pin"] and
             request["owner_receipt_pins"] ==
                 checked_checkpoint["owner_receipt_pins"] and
             request["empty_tmp_proofs"] ==
                 checked_checkpoint["empty_tmp_proofs"] and
             request["entries"] == checked_checkpoint["entries"],
             "final checkpoint does not bind its exact host checkpoint request")
    _require(durable["object_reopen_sha256"] == object_projection_sha and
             durable["commit_id"] == _sha(_canonical({
                 "checkpoint_pin": check_pin,
                 "object_manifest_pin": checked_manifest_pin,
                 "object_reopen_sha256": object_projection_sha,
                 "job_record_validation": validation_pin,
             })),
             "signed coordinator reopen projection differs from transferred bytes")
    signature = checked_signature
    _absolute_path(signature["path"], "detached signature origin path")
    signature_sha = _digest(signature["raw_sha256"],
                             "detached signature raw SHA-256")
    _require(type(signature_raw) is bytes and _sha(signature_raw) == signature_sha and
             len(signature_raw) <= signature_limit and
             signature["signer_fingerprint"] == fingerprint,
             "detached signature transfer differs from its exact pin")
    primary = _verify_detached_signature(ack_raw, signature_raw, {
        "fingerprint": fingerprint, "keyring_pin": signer["keyring_pin"],
        "gpgv_pin": signer["gpgv_pin"],
    })
    return {
        "schema": VERIFIED_ACK_SCHEMA_V1,
        "checkpoint_pin": check_pin,
        "object_manifest_pin": checked_manifest_pin,
        "ack_pin": checked_ack_pin,
        "signature_pin": {
            "path": signature["path"], "raw_sha256": signature_sha,
            "signer_fingerprint": primary,
        },
        "stage_map_pin": stage_pin,
        "signer_pin": {
            "fingerprint": fingerprint,
            "keyring_pin": signer["keyring_pin"],
            "gpgv_pin": signer["gpgv_pin"],
            "maximum_signature_bytes": signature_limit,
        },
        "signer_context_pin": signer["signer_context_pin"],
        "object_reopen_sha256": object_projection_sha,
        "stage_map_sha256": stage["stage_map_sha256"],
        "archive_source5_directory": archive_dir_path,
    }


def _unlink_stage_file(path_text: str, staging_root: str,
                       expected: dict[str, Any]) -> None:
    path = Path(_absolute_path(path_text, "stage file to reclaim"))
    root = Path(_absolute_path(staging_root, "private staging root"))
    _require(path != root and root in path.parents,
             "stage file to reclaim escaped the caller-reserved root")
    root_fd = _open_dir_path(str(root), "private staging root",
                             private_final=True)
    parent_fd, name = _open_parent(
        root_fd, path.relative_to(root).as_posix(), create=False,
        label="stage file to reclaim",
    )
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require((info.st_dev, info.st_ino, info.st_uid,
                  stat.S_IMODE(info.st_mode)) ==
                 (expected["device"], expected["inode"], os.getuid(),
                  expected["mode"]),
                 "staged file identity changed before reclamation")
        if expected["kind"] == "regular":
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     info.st_size == expected["byte_count"],
                     "staged regular file changed type, link count, or size")
            descriptor = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                                 _O_NONBLOCK, dir_fd=parent_fd)
            try:
                before = os.fstat(descriptor)
                hasher = hashlib.sha256()
                total = 0
                while total < before.st_size:
                    block = os.read(descriptor, min(COPY_BLOCK_BYTES,
                                                    before.st_size - total))
                    _require(bool(block), "staged regular file shortened before reclaim")
                    hasher.update(block)
                    total += len(block)
                _require(os.read(descriptor, 1) == b"" and
                         total == expected["byte_count"] and
                         hasher.hexdigest() == expected["raw_sha256"] and
                         _info_key(before) == _info_key(os.fstat(descriptor)),
                         "staged regular file bytes changed before reclaim")
            finally:
                os.close(descriptor)
        else:
            _require(stat.S_ISLNK(info.st_mode) and info.st_nlink == 1,
                     "staged literal symlink changed before reclaim")
            target = os.fsencode(os.readlink(name, dir_fd=parent_fd))
            _require(len(target) == expected["byte_count"] and
                     _sha(target) == expected["raw_sha256"],
                     "staged literal symlink bytes changed before reclaim")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
        os.close(root_fd)


def reclaim_acknowledged_local_paths(
    checkpoint: object, verified_ack: object, stage_map: object,
    staging_root: str | os.PathLike[str], *,
    checkpoint_raw: bytes, request_raw: bytes, host_budget_raw: bytes,
    job_record_bytes: bytes, plan_bytes: bytes,
    object_manifest: object, manifest_raw: bytes,
    ack: object, ack_raw: bytes, signature_raw: bytes,
    signer_context_pin: object, signer_context_raw: bytes,
    execution_manifest_pin: object, execution_manifest_raw: bytes,
) -> list[str]:
    """Reverify the signed transferred closure, then unlink only its exact files."""
    checked = _validate_checkpoint(checkpoint)
    capability = _exact(verified_ack, {
        "schema", "checkpoint_pin", "object_manifest_pin", "ack_pin",
        "signature_pin", "stage_map_pin", "signer_pin",
        "signer_context_pin", "object_reopen_sha256", "stage_map_sha256",
        "archive_source5_directory",
    }, "verified durable ACK capability")
    _require(capability["schema"] == VERIFIED_ACK_SCHEMA_V1,
             "reclamation lacks a coordinator-verified ACK result")
    signer = _validate_archive_signer_context(
        signer_context_raw, signer_context_pin, checked["context"],
        host_budget_raw, execution_manifest_pin, execution_manifest_raw,
    )
    expected_signer_pin = {
        "fingerprint": signer["fingerprint"],
        "keyring_pin": signer["keyring_pin"],
        "gpgv_pin": signer["gpgv_pin"],
        "maximum_signature_bytes": signer["maximum_signature_bytes"],
    }
    _require(capability["signer_context_pin"] == signer["signer_context_pin"] and
             capability["signer_pin"] == expected_signer_pin,
             "reclamation signer context/pins differ from the verified capability")
    checked_capability = verify_durable_ack(
        capability["checkpoint_pin"], checked, checkpoint_raw,
        request_raw, host_budget_raw,
        checked["job_record_pin"], job_record_bytes, plan_bytes,
        capability["object_manifest_pin"], object_manifest, manifest_raw,
        capability["ack_pin"], ack, ack_raw,
        capability["signature_pin"], signature_raw,
        signer_context_pin, signer_context_raw,
        execution_manifest_pin, execution_manifest_raw,
        capability["stage_map_pin"], stage_map, staging_root,
        checked["predecessor_ack_pin"],
    )
    _require(checked_capability == capability and
             capability["stage_map_sha256"] ==
                 _validate_stage_map(
                     stage_map, checked, object_manifest,
                 )["stage_map_sha256"],
             "durable ACK capability changed before local cleanup")
    rows = _validate_stage_map(stage_map, checked, object_manifest)["rows"]
    # Verify every mapped byte before beginning exact-name unlink operations.
    for row in rows:
        local = row["local_staged_file"]
        checked_descriptor, _literal = _staged_descriptor(
            local["path"], os.fspath(staging_root), {
                "byte_count": local["byte_count"],
                "raw_sha256": local["raw_sha256"],
            },
        )
        _require(checked_descriptor == local,
                 "local stage file identity changed before cleanup")
    removed = []
    for row in rows:
        local = row["local_staged_file"]
        _unlink_stage_file(local["path"], os.fspath(staging_root), local)
        removed.append(local["path"])
    return removed

def _read_staged_path(
    path_text: str, staging_root: str, maximum: int, label: str,
) -> bytes:
    path = Path(_absolute_path(path_text, f"{label} path"))
    root = Path(_absolute_path(staging_root, "private staging root"))
    _require(path != root and root in path.parents,
             f"{label} escapes the caller-reserved staging root")
    root_fd = _open_dir_path(str(root), "private staging root",
                             private_final=True)
    parent_fd, name = _open_parent(
        root_fd, path.relative_to(root).as_posix(), create=False, label=label,
    )
    try:
        raw, _digest_value, _info = _read_at(
            parent_fd, name, maximum, label,
        )
        _require(raw is not None, f"{label} was not collected within its byte ceiling")
        return raw
    finally:
        os.close(parent_fd)
        os.close(root_fd)


def _cli_request(path: str) -> tuple[dict[str, Any], bytes]:
    raw, digest, _ = _read_absolute_private_file(
        Path(path), MAX_JSON_BYTES, "private checkpoint request",
    )
    request = _validate_checkpoint_request(
        _parse_canonical(raw, "private checkpoint request"),
    )
    _require(digest == _sha(raw),
             "private checkpoint request raw digest changed")
    return request, raw


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Archive one completed Source5 job outside its timed lane.",
    )
    parser.add_argument("--request", required=True,
                        help="mode-0600 canonical host checkpoint request")
    parser.add_argument("--request-pin", required=True,
                        help="mode-0600 pin file for the host request bytes")
    parser.add_argument("--job-record", required=True,
                        help="separate packet-staged validation/job-record.json member")
    parser.add_argument("--catalogue-chunk-map", required=True,
                        help="canonical origin-to-local map for captured path-catalogue chunks")
    parser.add_argument("--catalogue-cache-root", required=True,
                        help="owned mode-0700 Root-local catalogue chunk cache")
    parser.add_argument("--dependency-local-map", required=True,
                        help="canonical Root-local Source/Plan/budget path map")
    parser.add_argument("--dependency-cache-root", required=True,
                        help="owned mode-0700 Root-local dependency cache")
    parser.add_argument("--staging-root", required=True,
                        help="existing owned mode-0700 staging root")
    parser.add_argument("--archive-root", required=True,
                        help="existing owned mode-0700 private archive root")
    parser.add_argument("--stage-map-path", required=True,
                        help="new mode-0600 local stage-map output path")
    parser.add_argument("--gpg-executable", required=True,
                        help="absolute GPG executable path on this private coordinator")
    parser.add_argument("--gpg-homedir", required=True,
                        help="owned mode-0700 private signing key home on this coordinator")
    parser.add_argument("--signer-fingerprint", required=True,
                        help="externally pinned signer primary fingerprint")
    arguments = parser.parse_args(argv)
    try:
        request_path = _absolute_path(arguments.request, "request path")
        staging_root = _absolute_path(arguments.staging_root, "staging root")
        request, request_raw = _cli_request(request_path)
        request_pin_raw, _request_pin_raw_sha, _ = _read_absolute_private_file(
            Path(_absolute_path(arguments.request_pin, "request pin path")),
            MAX_JSON_BYTES, "host checkpoint request pin file",
        )
        request_pin = _pin(
            _parse_canonical(request_pin_raw, "host request pin file"),
            "host checkpoint request pin",
        )
        _require(request_pin["raw_sha256"] == _sha(request_raw) and
                 request_pin["semantic_sha256"] == request["request_sha256"],
                 "host checkpoint request differs from its external pin file")
        rows = _validate_rows(request["entries"])
        staged_files = {
            row["origin_path"]: str(
                Path(staging_root) / "objects" /
                _object_identity(row["origin_path"], row["raw_sha256"])
            ) for row in rows
        }
        job_pin = _pin_raw(request["job_record_pin"], "request job record pin")
        job_record_bytes = _read_staged_path(
            _absolute_path(arguments.job_record, "staged validation job-record path"),
            staging_root, MAX_JSON_BYTES, "staged always-local job record",
        )
        _require(_sha(job_record_bytes) == job_pin["raw_sha256"],
                 "separate packet validation record differs from its request raw pin")
        dependency_map_raw, _dependency_map_sha, _dependency_map_info = \
            _read_absolute_private_file(
                Path(_absolute_path(arguments.dependency_local_map,
                                    "dependency local map path")),
                MAX_JSON_BYTES, "Root-local dependency map",
            )
        dependency_paths = _parse_dependency_local_map(
            dependency_map_raw, request["context"],
        )
        plan_bytes, _plan_sha, _plan_info = _read_absolute_private_file(
            Path(dependency_paths[
                request["context"]["plan_pin"]["path"]
            ]), MAX_PLAN_BYTES, "Root-local captured PlanV3",
        )
        host_budget_raw, _budget_sha, _budget_info = _read_absolute_private_file(
            Path(dependency_paths[
                request["context"]["resource_budget_pin"]["path"]
            ]), MAX_JSON_BYTES, "Root-local captured host evidence budget",
        )
        catalogue_map_raw, _catalogue_map_sha, _catalogue_map_info = \
            _read_absolute_private_file(
                Path(_absolute_path(arguments.catalogue_chunk_map,
                                    "catalogue chunk map path")),
                MAX_JSON_BYTES, "Root-local catalogue chunk map",
            )
        catalogue_chunk_paths = _parse_catalogue_local_map(
            catalogue_map_raw, request["context"],
        )
        signature_limit = _campaign_signature_limit(
            host_budget_raw, request["context"]["resource_budget_pin"],
            request["context"],
        )
        owner_receipt_bytes = {
            row["origin_path"]: _read_staged_raw(
                staged_files[row["origin_path"]], staging_root, row,
            )
            for row in rows if "receipt" in row["role"].lower()
        }
        result = archive_job_checkpoint(
            request_pin, request_raw, request["context"], job_pin,
            job_record_bytes, plan_bytes, host_budget_raw,
            dependency_paths,
            _absolute_path(arguments.dependency_cache_root,
                           "dependency cache root"),
            catalogue_chunk_paths,
            _absolute_path(arguments.catalogue_cache_root,
                           "catalogue cache root"),
            rows,
            owner_receipt_bytes,
            staged_files, staging_root,
            _absolute_path(arguments.archive_root, "archive root"),
            _absolute_path(arguments.stage_map_path, "stage-map output path"),
            {
                "gpg_executable": _absolute_path(
                    arguments.gpg_executable, "GPG executable",
                ),
                "gpg_homedir": _absolute_path(
                    arguments.gpg_homedir, "private GPG home",
                ),
                "primary_fingerprint": _fingerprint(
                    arguments.signer_fingerprint,
                    "external signer fingerprint",
                ),
                "maximum_signature_bytes": signature_limit,
            },
        )
        summary = {
            "schema": "allocatbelt.application-source5-evidence-archive-result.v1",
            "request_pin": result["request_pin"],
            "checkpoint_pin": result["checkpoint_pin"],
            "object_manifest_pin": result["object_manifest_pin"],
            "ack_pin": result["ack_pin"],
            "signature_pin": result["signature_pin"],
            "coordinator_stage_map_pin":
                result["coordinator_stage_map_pin"],
            "object_count": result["object_manifest"]["object_count"],
            "payload_bytes": result["object_manifest"]["payload_bytes"],
        }
        sys.stdout.buffer.write(_canonical(summary))
        return 0
    except (EvidenceArchiveError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Source5 evidence archive failed: {type(error).__name__}: {error}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
