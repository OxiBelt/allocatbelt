#!/usr/bin/env python3
"""One bounded, no-link tar packet per completed Source5 job.

The host sends an immutable checkpoint request plus its exact raw-pinned row
bytes. The private coordinator verifies the whole archive before extracting any
member, then copies objects into its private content-addressed staging tree.
Final checkpoints and signed ACKs are produced only after coordinator-side
object fsync and independent reopen.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterable


REQUEST_SCHEMA = "allocatbelt.application-source5-evidence-checkpoint-request.v1"
PACKET_PIN_SCHEMA = "allocatbelt.application-source5-evidence-transfer-packet-pin.v1"
HOST_BUDGET_SCHEMA = "allocatbelt.application-source5-host-evidence-budget.v2"
HOST_BUDGET_FIELDS = {
    "schema", "campaign_id", "host_id", "original_pins", "schedule",
    "owner_contract", "path_catalogue", "storage_reservation",
    "role_byte_reservations", "transport", "execution_blockers",
    "readiness", "budget_sha256",
}
CATALOGUE_LOCAL_MAP_SCHEMA = "allocatbelt.application-source5-host-catalogue-local-map.v1"
ARCHIVE_SIGNER_CONTEXT_SCHEMA = "allocatbelt.application-source5-archive-signer-context.v1"
NON_EXPORTABLE_JOB_ROLES = frozenset({
    "source5_job_record", "source5_job_disposition",
})
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_GPG_OUTPUT_BYTES = 1 << 20
MAX_PATH_BYTES = 4096
MAX_ROWS = 1_000_000
MAX_OBJECT_BYTES = (1 << 64) - 1
BLOCK_BYTES = 1024 * 1024
TAR_BLOCK_BYTES = 512
TAR_RECORD_BYTES = 10240
USTAR_MAX_SIZE = (1 << 33) - 1
MAX_PAX_HEADER_BYTES = 4096
MAX_CATALOGUE_CHUNK_BYTES = 8 * 1024 * 1024
RENAME_NOREPLACE = 1
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class TransferPacketError(ValueError):
    """A packet, budget pin, source file, or extracted object is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TransferPacketError(message)


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _canonical(value: Any) -> bytes:
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise TransferPacketError(
            f"{type(value).__name__} is not canonical JSON: {error}"
        ) from error
    _require(len(raw) <= MAX_JSON_BYTES,
             "packet metadata exceeds its finite byte ceiling")
    return raw


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             f"{label} is not a lowercase SHA-256")
    return value


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    _require(type(value) is int and 0 <= value <= (1 << 64) - 1 and
             (not positive or value > 0),
             f"{label} is outside its finite integer bound")
    return value


def _path(value: object, label: str) -> str:
    _require(type(value) is str and value.startswith("/") and
             len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             "\x00" not in value and
             not any(ord(ch) < 32 or ord(ch) == 127 for ch in value),
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
        "path": _path(row["path"], f"{label} path"),
        "raw_sha256": _digest(row["raw_sha256"], f"{label} raw digest"),
        "semantic_sha256": _digest(row["semantic_sha256"],
                                   f"{label} semantic digest"),
    }


def _pin_raw(value: object, label: str) -> dict[str, str]:
    row = _exact(value, {"path", "raw_sha256"}, label)
    return {
        "path": _path(row["path"], f"{label} path"),
        "raw_sha256": _digest(row["raw_sha256"], f"{label} raw digest"),
    }


def _validate_archive_signer_context(
    raw: bytes, signer_context_pin: object, context: dict[str, Any],
    maximum_signature_bytes: int, execution_manifest_pin: object,
    execution_manifest_raw: bytes,
) -> dict[str, Any]:
    pin = _pin(signer_context_pin, "host archive signer-context pin")
    _require(type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             "host archive signer-context bytes differ from their raw pin")
    value = _exact(_parse_canonical(raw, "host archive signer context"), {
        "schema", "campaign_id", "host_id", "authorized_primary_fingerprint",
        "maximum_signature_bytes", "keyring_pin", "gpgv_pin",
        "signature_format", "signer_context_sha256",
    }, "host archive signer context")
    body = {key: item for key, item in value.items()
            if key != "signer_context_sha256"}
    fingerprint = value["authorized_primary_fingerprint"]
    _require(type(fingerprint) is str and
             re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", fingerprint) is not None,
             "host signer-context fingerprint is malformed")
    keyring_pin = _pin_raw(value["keyring_pin"],
                           "host signer-context keyring pin")
    gpgv_pin = _pin_raw(value["gpgv_pin"],
                        "host signer-context GPGV pin")
    _require(value["schema"] == ARCHIVE_SIGNER_CONTEXT_SCHEMA and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             fingerprint == context["authorized_signer_fingerprint"] and
             value["signer_context_sha256"] == _sha(_canonical(body)) ==
                 pin["semantic_sha256"] and
             _uint(value["maximum_signature_bytes"],
                   "host signer-context signature quota", positive=True) ==
                 maximum_signature_bytes and
             value["signature_format"] ==
                 "binary_detached_primary_sha256_v1",
             "host signer context differs from its raw pin, identity, quota or format")
    checked_execution_pin = _pin(
        execution_manifest_pin, "host execution-manifest pin",
    )
    _require(checked_execution_pin == context["execution_manifest_pin"] and
             type(execution_manifest_raw) is bytes and
             _sha(execution_manifest_raw) == checked_execution_pin["raw_sha256"],
             "host execution-manifest bytes differ from the checkpoint pin")
    execution = _exact(_parse_canonical(
        execution_manifest_raw, "host Source5 execution manifest",
    ), {
        "schema", "campaign_id", "hosts", "original_inputs",
        "execution_sources", "modules", "observed_hosts", "artifact_root",
        "output_root", "phase_order", "protocol_sha256",
        "qualification_eligible", "scope", "prepared_input_generation",
        "prepared_capacity_registration", "archive_signer_contexts",
        "manifest_sha256",
    }, "bounded Source5 execution manifest v4")
    execution_body = {key: item for key, item in execution.items()
                      if key != "manifest_sha256"}
    hosts = execution["hosts"]
    _require(execution["schema"] ==
             "allocatbelt.application-source5-campaign-execution.v4" and
             execution["campaign_id"] == context["campaign_id"] and
             type(hosts) is list and bool(hosts) and
             all(type(host) is str and bool(host) for host in hosts) and
             len(hosts) == len(set(hosts)) and context["host_id"] in hosts and
             execution["scope"] == "final_prepared_bounded" and
             execution["qualification_eligible"] is False and
             execution["manifest_sha256"] == _sha(_canonical(execution_body)) ==
                 checked_execution_pin["semantic_sha256"],
             "host execution manifest schema, identity, scope or digest differs")
    contexts = _exact(
        execution["archive_signer_contexts"], set(hosts),
        "host execution-manifest signer-context map",
    )
    wrapper = _exact(contexts[context["host_id"]], {
        "artifact", "semantic_sha256",
    }, "host execution-manifest signer-context wrapper")
    artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                       "host execution-manifest signer-context artifact")
    _require(artifact == {"path": pin["path"], "raw_sha256": pin["raw_sha256"]} and
             wrapper["semantic_sha256"] == pin["semantic_sha256"],
             "host signer-context pin differs from its execution-manifest entry")
    return {
        "schema": value["schema"], "campaign_id": context["campaign_id"],
        "host_id": context["host_id"],
        "authorized_primary_fingerprint": fingerprint,
        "maximum_signature_bytes": maximum_signature_bytes,
        "keyring_pin": keyring_pin, "gpgv_pin": gpgv_pin,
        "signature_format": value["signature_format"],
        "signer_context_sha256": value["signer_context_sha256"],
        "execution_manifest_pin": checked_execution_pin,
    }


def _validate_budget_context(
    budget: dict[str, Any], context: dict[str, Any],
) -> None:
    original = _exact(budget.get("original_pins"), {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256",
    }, "host budget original input pins")
    _digest(original["source_tree_sha256"], "budget source tree SHA-256")
    sources = original["source_manifests"]
    _require(type(sources) is dict and context["host_id"] in sources and
             _pin(original["plan"], "budget PlanV3 pin") == context["plan_pin"] and
             _pin(original["execution_manifest"],
                  "budget execution-manifest pin") ==
                 context["execution_manifest_pin"] and
             _pin(sources[context["host_id"]], "budget SourceV5 pin") ==
                 context["source_manifest_pin"],
             "checkpoint source/Plan/execution pins differ from host budget")


def _parse_catalogue_local_map(
    raw: bytes, campaign_id: str, host_id: str, budget_pin: object,
) -> dict[str, str]:
    value = _exact(_parse_canonical(raw, "Root-local catalogue path map"), {
        "schema", "campaign_id", "host_id", "resource_budget_pin",
        "chunks", "map_sha256",
    }, "Root-local catalogue path map")
    body = {key: item for key, item in value.items() if key != "map_sha256"}
    _require(value["schema"] == CATALOGUE_LOCAL_MAP_SCHEMA and
             value["campaign_id"] == campaign_id and
             value["host_id"] == host_id and
             _pin(value["resource_budget_pin"], "catalogue map budget pin") ==
                 _pin(budget_pin, "host evidence budget pin") and
             value["map_sha256"] == _sha(_canonical(body)) and
             type(value["chunks"]) is list,
             "Root-local catalogue path map identity/digest differs")
    paths = {}
    local_paths = set()
    previous = ""
    for index, item_value in enumerate(value["chunks"]):
        item = _exact(item_value, {"origin_path", "local_path"},
                      f"Root-local catalogue chunk map[{index}]")
        origin = _path(item["origin_path"], "catalogue chunk origin")
        local = _path(item["local_path"], "Root-local catalogue chunk")
        _require(origin > previous and local != origin and local not in local_paths,
                 "Root-local catalogue map is unsorted or aliases an origin path")
        previous = origin
        local_paths.add(local)
        paths[origin] = local
    return paths


def _parse_canonical(raw: bytes, label: str) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_JSON_BYTES and
             raw.endswith(b"\n") and b"\r" not in raw,
             f"{label} framing differs from canonical JSON")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise TransferPacketError(f"{label} is malformed JSON: {error}") from error
    _require(type(value) is dict and _canonical(value) == raw,
             f"{label} is not canonical JSON")
    return value


def _info_key(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink, info.st_uid)


def _rename_identity(info: os.stat_result) -> tuple[int, ...]:
    # A same-directory rename may update ctime while preserving the file bytes.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_nlink, info.st_uid)


def _open_abs_dir(path_value: object, label: str, *, private_final: bool) -> int:
    path = Path(_path(str(path_value), label))
    fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            _require(component not in ("", ".", ".."),
                     f"{label} has an unsafe component")
            child = os.open(component, os.O_RDONLY | _O_DIRECTORY |
                            _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode), f"{label} is not a directory")
        if private_final:
            _require(info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o700,
                     f"{label} is not an owned mode-0700 directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_relative_dir(root_fd: int, relative: str, *, create: bool,
                       label: str) -> int:
    parts = PurePosixPath(relative).parts
    _require(parts and all(part not in ("", ".", "..", "/") for part in parts),
             f"{label} has an unsafe relative path")
    fd = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | _O_DIRECTORY |
                                _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
            else:
                child = os.open(part, os.O_RDONLY | _O_DIRECTORY |
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


def _parent_at(root_fd: int, relative: str, *, create: bool,
               label: str) -> tuple[int, str]:
    pure = PurePosixPath(relative)
    _require(not pure.is_absolute() and pure.name not in ("", ".", "..") and
             all(part not in ("", ".", "..", "/") for part in pure.parts),
             f"{label} path is unsafe")
    parent = "." if len(pure.parts) == 1 else "/".join(pure.parts[:-1])
    fd = os.dup(root_fd) if parent == "." else _open_relative_dir(
        root_fd, parent, create=create, label=label,
    )
    return fd, pure.name


def _read_fd(fd: int, size: int, maximum: int, label: str,
             *, collect: bool) -> tuple[bytes | None, str, os.stat_result]:
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
             before.st_size == size and size <= maximum,
             f"{label} is not the exact bounded mode-0600 single-link file")
    hasher = hashlib.sha256()
    parts: list[bytes] | None = [] if collect else None
    count = 0
    while count < size:
        block = os.read(fd, min(BLOCK_BYTES, size - count))
        _require(bool(block), f"{label} ended before its pinned size")
        count += len(block)
        hasher.update(block)
        if parts is not None:
            parts.append(block)
    _require(os.read(fd, 1) == b"" and count == size and
             _info_key(before) == _info_key(os.fstat(fd)),
             f"{label} changed while being read")
    return (None if parts is None else b"".join(parts),
            hasher.hexdigest(), before)


def _read_regular_absolute(path_value: object, maximum: int,
                           label: str) -> tuple[bytes, str, os.stat_result]:
    path = Path(_path(str(path_value), f"{label} path"))
    _require(path.resolve(strict=True) == path,
             f"{label} traverses a symlink or alias")
    parent_fd = _open_abs_dir(str(path.parent), f"{label} parent",
                              private_final=True)
    try:
        before_path = os.stat(path.name, dir_fd=parent_fd,
                              follow_symlinks=False)
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and before_path.st_size <= maximum,
                 f"{label} is not an owned mode-0600 bounded regular file")
        fd = os.open(path.name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                     _O_NONBLOCK, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            _require(_info_key(before) == _info_key(before_path),
                     f"{label} changed identity before read")
            raw, digest, _ = _read_fd(fd, before.st_size, maximum, label,
                                      collect=True)
            after_path = os.stat(path.name, dir_fd=parent_fd,
                                 follow_symlinks=False)
            _require(raw is not None and _info_key(before) == _info_key(after_path),
                     f"{label} changed at its path during read")
            return raw, digest, before
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _budget_limits(
    budget_raw: bytes, budget_pin: object, campaign_id: str, host_id: str,
) -> tuple[int, int, int, int, list[str], str, int, int]:
    pin = _pin(budget_pin, "host evidence budget pin")
    _require(_sha(budget_raw) == pin["raw_sha256"],
             "host evidence budget bytes differ from their raw pin")
    budget = _exact(_parse_canonical(budget_raw, "host evidence budget"),
                    HOST_BUDGET_FIELDS, "host evidence budget v2")
    _require(budget.get("schema") == HOST_BUDGET_SCHEMA and
             budget.get("campaign_id") == campaign_id and
             budget.get("host_id") == host_id,
             "host evidence budget identity differs from request")
    blockers = budget["execution_blockers"]
    readiness = _exact(budget["readiness"], {
        "budget_complete", "execution_ready", "component_gate_ready",
        "qualification_eligible",
    }, "host evidence budget readiness")
    _require(type(blockers) is list and
             all(type(item) is str and bool(item) for item in blockers) and
             len(blockers) == len(set(blockers)) and
             all(type(readiness[field]) is bool for field in readiness) and
             readiness["qualification_eligible"] is False and
             (not readiness["execution_ready"] or
              (readiness["budget_complete"] and not blockers)),
             "host evidence budget blockers/readiness are inconsistent")
    body = {key: item for key, item in budget.items()
            if key != "budget_sha256"}
    budget_sha = _digest(budget.get("budget_sha256"),
                         "host evidence budget semantic digest")
    _require(budget_sha == _sha(_canonical(body)) and
             budget_sha == pin["semantic_sha256"],
             "host evidence budget semantic pin differs")
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict, "budget lacks its pinned path catalogue")
    retention = catalogue.get("retention_policy")
    _require(type(retention) is dict,
             "budget path catalogue lacks retention policy")
    max_packet = _uint(retention.get("maximum_transfer_packet_bytes"),
                       "budget transfer packet byte cap", positive=True)
    max_packet_inodes = _uint(
        retention.get("maximum_transfer_packet_inodes"),
        "budget transfer packet inode cap", positive=True,
    )
    max_window_bytes = _uint(retention.get("maximum_window_total_bytes"),
                             "budget live-window byte cap")
    max_window_inodes = _uint(retention.get("maximum_window_total_inodes"),
                              "budget live-window inode cap")
    max_ack_bundle = _uint(retention.get("maximum_ack_bundle_bytes"),
                           "budget ACK-bundle byte cap", positive=True)
    max_signature = _uint(retention.get("maximum_signature_bytes"),
                          "budget detached-signature byte cap", positive=True)
    _require(max_signature <= MAX_GPG_OUTPUT_BYTES,
             "budget signature cap exceeds the generic bounded parser ceiling")
    transport = budget.get("transport")
    _require(type(transport) is dict and
             transport.get("maximum_job_packet_bytes") == max_packet and
             transport.get("maximum_job_packet_inodes") == max_packet_inodes,
             "budget transport packet limits differ from its path catalogue")
    reservation = budget.get("storage_reservation")
    _require(type(reservation) is dict and
             type(reservation.get("roots")) is dict,
             "budget lacks its pinned storage roots")
    scratch_roots = [
        root for root, row in reservation["roots"].items()
        if type(row) is dict and row.get("role") == "scratch"
    ]
    _require(len(scratch_roots) == 1,
             "budget does not declare one packet scratch root")
    source_roots = catalogue.get("root_byte_bounds")
    _require(type(source_roots) is dict and source_roots,
             "budget path catalogue has no source roots")
    return (max_packet, max_packet_inodes, max_window_bytes,
            max_window_inodes, list(source_roots), scratch_roots[0],
            max_ack_bundle, max_signature)


def _validate_request(value: object) -> dict[str, Any]:
    request = _exact(value, {
        "schema", "context", "job_record_pin", "authorization",
        "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
        "entries", "request_sha256",
    }, "checkpoint request")
    _require(request["schema"] == REQUEST_SCHEMA,
             "checkpoint request schema differs")
    context = _exact(request["context"], {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "source_manifest_pin", "execution_manifest_pin", "plan_pin",
        "resource_budget_pin", "predecessor_ack_pin",
        "authorized_signer_fingerprint",
    }, "checkpoint request context")
    _require(context["schema"] ==
             "allocatbelt.application-source5-evidence-archive-context.v1",
             "checkpoint request context schema differs")
    campaign = _token(context["campaign_id"], "request campaign ID")
    host = _token(context["host_id"], "request host ID")
    _token(context["phase"], "request phase")
    _require(type(context["authorized_signer_fingerprint"]) is str and
             re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}",
                          context["authorized_signer_fingerprint"]) is not None,
             "request authorized signer fingerprint is malformed")
    _uint(context["job_index"], "request original job index")
    for name in ("source_manifest_pin", "execution_manifest_pin",
                 "plan_pin", "resource_budget_pin"):
        _pin(context[name], f"request {name}")
    predecessor = context["predecessor_ack_pin"]
    _require(predecessor is None or type(predecessor) is dict,
             "request predecessor pin is malformed")
    if predecessor is not None:
        _pin(predecessor, "request predecessor pin")
    job_pin = _pin_raw(request["job_record_pin"], "request job record pin")
    _require(request["predecessor_ack_pin"] == predecessor and
             type(request["owner_receipt_pins"]) is dict and
             list(request["owner_receipt_pins"]) ==
                 sorted(request["owner_receipt_pins"]) and
             type(request["empty_tmp_proofs"]) is list,
             "checkpoint request receipt/predecessor map is malformed")
    rows = request["entries"]
    _require(type(rows) is list and 0 < len(rows) <= MAX_ROWS,
             "checkpoint request entry count is outside its finite bound")
    previous = ""
    total = 0
    expected_receipt_origins = set()
    for index, value in enumerate(rows):
        row = _exact(value, {
            "origin_path", "role", "byte_count", "raw_sha256",
            "semantic_sha256",
        }, f"request entry[{index}]")
        origin = _path(row["origin_path"], f"request entry[{index}] origin")
        role = _token(row["role"], f"request entry[{index}] role")
        _require(role not in NON_EXPORTABLE_JOB_ROLES,
                 "always-local job-record/disposition role is not exportable")
        size = _uint(row["byte_count"], f"request entry[{index}] byte count")
        _require(size <= MAX_OBJECT_BYTES and origin > previous,
                 "request entries are unsorted, duplicated, or too large")
        previous = origin
        total += size
        _digest(row["raw_sha256"], f"request entry[{index}] raw digest")
        semantic = row["semantic_sha256"]
        _require(semantic is None or
                 (type(semantic) is str and
                  re.fullmatch(r"[0-9a-f]{64}", semantic) is not None),
                 "request entry semantic digest is malformed")
        if "receipt" in row["role"].lower():
            expected_receipt_origins.add(origin)
    _require(total <= MAX_OBJECT_BYTES * MAX_ROWS,
             "request aggregate payload exceeds finite arithmetic bounds")
    _require(all(row["origin_path"] != job_pin["path"] for row in rows),
             "always-local job record cannot appear in reclaimable packet entries")
    for role, pin_value in request["owner_receipt_pins"].items():
        _token(role, "request owner receipt role")
        pin = _pin(pin_value, f"request owner receipt {role}")
        row = next((item for item in rows if item["origin_path"] == pin["path"]), None)
        _require(row is not None and row["role"] == role and
                 row["raw_sha256"] == pin["raw_sha256"] and
                 row["semantic_sha256"] == pin["semantic_sha256"],
                 "request owner pin does not match one exact row")
    _require(set(request["owner_receipt_pins"]) ==
             {row["role"] for row in rows
              if "receipt" in row["role"].lower()} and
             len(expected_receipt_origins) == len(request["owner_receipt_pins"]),
             "request owner receipt map does not close over receipt rows")
    authorization = _exact(request["authorization"], {
        "authorization_id", "authorization_head", "terminal_head",
        "component_sha256", "process_metrics_sha256",
    }, "checkpoint request terminal authorization")
    _token(authorization["authorization_id"],
           "checkpoint request authorization ID")
    for field in ("authorization_head", "terminal_head", "component_sha256",
                  "process_metrics_sha256"):
        _digest(authorization[field],
                f"checkpoint request authorization {field}")
    body = {key: item for key, item in request.items()
            if key != "request_sha256"}
    _require(_digest(request["request_sha256"], "request self digest") ==
             _sha(_canonical(body)),
             "checkpoint request self digest differs")
    return request


def _object_identity(origin: str, raw_sha: str) -> str:
    name = _sha(origin.encode("utf-8"))
    return f"{name[:2]}/{name}-{raw_sha}.bin"


def _packet_member_name(origin: str, raw_sha: str) -> str:
    object_id = _object_identity(origin, raw_sha)
    transfer_id = _sha(object_id.encode("ascii"))
    return f"objects/{transfer_id}.bin"


def _tar_size(members: Iterable[tuple[str, int]]) -> int:
    content = 0
    for name, size in members:
        _require(type(name) is str and len(name.encode("ascii")) <= 100,
                 "packet member name exceeds its deterministic short encoding")
        _require(type(size) is int and 0 <= size <= MAX_OBJECT_BYTES,
                 "packet member size is outside bounded PAX")
        content += TAR_BLOCK_BYTES + (
            (size + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES
        ) * TAR_BLOCK_BYTES
        if size > USTAR_MAX_SIZE:
            record = _pax_size_record(size)
            _require(len(record) <= MAX_PAX_HEADER_BYTES,
                     "PAX size extension exceeds its finite header bound")
            content += TAR_BLOCK_BYTES + (
                (len(record) + TAR_BLOCK_BYTES - 1) // TAR_BLOCK_BYTES
            ) * TAR_BLOCK_BYTES
    with_end_markers = content + 1024
    return ((with_end_markers + TAR_RECORD_BYTES - 1) //
            TAR_RECORD_BYTES) * TAR_RECORD_BYTES


def _pax_size_record(size: int) -> bytes:
    body = f"size={size}\n".encode("ascii")
    record_length = len(body) + 2
    while True:
        candidate = len(body) + len(str(record_length)) + 1
        if candidate == record_length:
            break
        record_length = candidate
    return f"{record_length} ".encode("ascii") + body


def _open_source(
    origin: str, roots: list[str],
) -> tuple[int, str, os.stat_result]:
    path = Path(_path(origin, "origin object path"))
    candidates = [Path(_path(root, "budget source root")) for root in roots
                  if path != Path(root) and Path(root) in path.parents]
    _require(bool(candidates),
             "origin path escapes every byte-bounded host budget root")
    root = max(candidates, key=lambda item: len(item.parts))
    relative = path.relative_to(root).as_posix()
    root_fd = _open_abs_dir(str(root), "budget source root",
                            private_final=True)
    parent_fd, name = _parent_at(root_fd, relative, create=False,
                                 label="origin source")
    os.close(root_fd)
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISREG(info.st_mode):
            _require(info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                     "origin source is not an owned mode-0600 single-link file")
            fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                         _O_NONBLOCK, dir_fd=parent_fd)
            opened = os.fstat(fd)
            _require(_info_key(opened) == _info_key(info),
                     "origin source changed identity before open")
            return fd, "regular", opened
        _require(stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid() and
                 info.st_nlink == 1,
                 "origin source is not a regular file or literal owned symlink")
        return parent_fd, "symlink:" + name, info
    except BaseException:
        os.close(parent_fd)
        raise


def _read_symlink(
    parent_fd: int, name: str, expected: dict[str, Any],
) -> tuple[bytes, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    target = os.readlink(name, dir_fd=parent_fd)
    raw = os.fsencode(target)
    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _require(_info_key(before) == _info_key(after) and
             len(raw) == expected["byte_count"] and
             _sha(raw) == expected["raw_sha256"],
             "literal symlink bytes differ from the exact request row")
    return raw, after


def _hash_source(origin: str, roots: list[str],
                 row: dict[str, Any]) -> tuple[str, int, tuple[int, ...]]:
    fd, kind, info = _open_source(origin, roots)
    try:
        if kind.startswith("symlink:"):
            parent_fd, name = fd, kind.split(":", 1)[1]
            raw, after = _read_symlink(parent_fd, name, row)
            return "symlink", len(raw), _info_key(after)
        _require(info.st_size == row["byte_count"] and
                 info.st_size <= MAX_OBJECT_BYTES,
                 "origin regular-file size differs from the request row")
        hasher = hashlib.sha256()
        total = 0
        while total < info.st_size:
            block = os.read(fd, min(BLOCK_BYTES, info.st_size - total))
            _require(bool(block), "origin regular file shortened while hashing")
            total += len(block)
            hasher.update(block)
        _require(os.read(fd, 1) == b"" and total == row["byte_count"] and
                 hasher.hexdigest() == row["raw_sha256"] and
                 _info_key(info) == _info_key(os.fstat(fd)),
                 "origin regular file changed or differs from its raw pin")
        return "regular", total, _info_key(os.fstat(fd))
    finally:
        if kind.startswith("symlink:"):
            os.close(fd)
        else:
            os.close(fd)


class _HashingReader:
    def __init__(self, fd: int, size: int) -> None:
        self.fd = fd
        self.size = size
        self.count = 0
        self.hasher = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        remaining = self.size - self.count
        if remaining <= 0:
            return b""
        amount = remaining if size is None or size < 0 else min(size, remaining)
        block = os.read(self.fd, min(BLOCK_BYTES, amount))
        _require(bool(block), "origin file shortened during tar streaming")
        self.count += len(block)
        self.hasher.update(block)
        return block


def _octal_field(value: int, width: int) -> bytes:
    _require(type(value) is int and 0 <= value <= MAX_OBJECT_BYTES,
             "tar header number is outside its finite bound")
    digits = f"{value:o}".encode("ascii")
    _require(len(digits) < width,
             "tar header number exceeds its octal field")
    return b"0" * (width - len(digits) - 1) + digits + b"\x00"


def _tar_header(name: str, size: int, *, typeflag: bytes = b"0") -> bytes:
    encoded = name.encode("ascii", "strict")
    _require(0 < len(encoded) <= 100 and typeflag in (b"0", b"x"),
             "tar member header name/type is outside the packet grammar")
    header = bytearray(TAR_BLOCK_BYTES)
    header[0:len(encoded)] = encoded
    header[100:108] = _octal_field(0o600, 8)
    header[108:116] = _octal_field(0, 8)
    header[116:124] = _octal_field(0, 8)
    header[124:136] = _octal_field(
        0 if size > USTAR_MAX_SIZE else size, 12,
    )
    header[136:148] = _octal_field(0, 12)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[257:263] = b"ustar\x00"
    header[263:265] = b"00"
    checksum = sum(header)
    checksum_field = f"{checksum:06o}".encode("ascii") + b"\x00 "
    _require(len(checksum_field) == 8,
             "tar header checksum exceeds its fixed field")
    header[148:156] = checksum_field
    return bytes(header)


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        _require(written > 0, "packet writer made no progress")
        view = view[written:]


def _write_at_fd(parent_fd: int, name: str, raw: bytes,
                 label: str) -> tuple[str, int]:
    _require(type(raw) is bytes and len(raw) <= MAX_JSON_BYTES,
             f"{label} exceeds its bounded metadata size")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd)
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, raw)
        os.fsync(fd)
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and
                 info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o600 and
                 info.st_nlink == 1 and info.st_size == len(raw),
                 f"{label} writer did not produce its exact private file")
    finally:
        os.close(fd)
    os.fsync(parent_fd)
    return _sha(raw), len(raw)


def _read_fd_at(parent_fd: int, name: str, maximum: int, label: str,
                *, expected_bytes: int) -> tuple[bytes, str, os.stat_result]:
    path_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    _require(stat.S_ISREG(path_info.st_mode) and
             path_info.st_uid == os.getuid() and
             stat.S_IMODE(path_info.st_mode) == 0o600 and
             path_info.st_nlink == 1 and path_info.st_size == expected_bytes,
             f"{label} is not its exact private mode-0600 file")
    fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
                 dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        _require(_info_key(before) == _info_key(path_info),
                 f"{label} changed identity before reopen")
        raw, digest, _ = _read_fd(fd, expected_bytes, maximum, label,
                                  collect=True)
        after_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require(raw is not None and
                 _info_key(before) == _info_key(after_path),
                 f"{label} changed during reopen")
        return raw, digest, before
    finally:
        os.close(fd)


def _write_padding(fd: int, size: int) -> None:
    padding = (-size) % TAR_BLOCK_BYTES
    if padding:
        _write_all(fd, b"\x00" * padding)


def _budget_and_pin_for_request(
    request: dict[str, Any], budget_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], bytes,
           tuple[int, int, int, int, list[str], str, int, int]]:
    pin = request["context"]["resource_budget_pin"]
    raw, actual, _ = _read_regular_absolute(
        os.fspath(budget_path), MAX_JSON_BYTES, "pinned host budget",
    )
    _require(actual == pin["raw_sha256"],
             "host budget local bytes differ from checkpoint request raw pin")
    limits = _budget_limits(
        raw, pin, request["context"]["campaign_id"],
        request["context"]["host_id"],
    )
    return _parse_canonical(raw, "pinned host budget"), raw, limits


def _request_job_group(request: dict[str, Any]) -> tuple[str, str, str, str]:
    context = request["context"]
    record_name = PurePosixPath(request["job_record_pin"]["path"]).name
    _require(record_name.endswith(".json") and len(record_name) > 5,
             "checkpoint request job-record path lacks its original run ID")
    run_id = _run_id(record_name[:-5], "original Source5 run ID")
    return (context["host_id"], context["phase"], run_id,
            context["campaign_id"])


def _job_record_catalogue_row(
    request: dict[str, Any], budget: dict[str, Any], *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> dict[str, Any]:
    host_id, phase, run_id, _campaign_id = _request_job_group(request)
    path = request["job_record_pin"]["path"]
    row = _catalogue_rows_for_paths(
        budget, {path}, host_id, phase, run_id,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )[path]
    _require(row["role"] == "source5_job_record" and
             row["kind"] == "file" and row["max_file_bytes"] > 0,
             "raw-pinned job record lacks its exact always-local catalogue row")
    return row


def _job_record_source(
    request: dict[str, Any], budget: dict[str, Any], roots: list[str],
) -> tuple[dict[str, Any], tuple[str, int, tuple[int, ...]]]:
    catalogue_row = _job_record_catalogue_row(request, budget)
    pin = request["job_record_pin"]
    fd, kind, before = _open_source(pin["path"], roots)
    try:
        _require(kind == "regular" and stat.S_ISREG(before.st_mode) and
                 0 < before.st_size <= catalogue_row["max_file_bytes"] and
                 before.st_size <= MAX_JSON_BYTES,
                 "always-local job record is not a bounded regular file")
        row = {
            "origin_path": pin["path"], "byte_count": before.st_size,
            "raw_sha256": pin["raw_sha256"], "semantic_sha256": None,
        }
        identity = _hash_source(pin["path"], roots, row)
        return row, identity
    finally:
        os.close(fd)


def _offer_body(
    request_pin: dict[str, str], packet_path: str, packet_sha: str,
    packet_size: int, receiver_path: str, receiver_cap: int,
) -> dict[str, Any]:
    body = {
        "schema": "allocatbelt.application-source5-archive-transfer-offer.v1",
        "checkpoint_request_pin": request_pin,
        "transfer_packet_pin": {
            "path": packet_path, "raw_sha256": packet_sha,
            "byte_count": packet_size,
        },
        "acknowledgement_receiver": {
            "path": receiver_path, "maximum_bytes": receiver_cap,
        },
        "offer_sha256": "",
    }
    digest = _sha(_canonical({key: item for key, item in body.items()
                              if key != "offer_sha256"}))
    return {**body, "offer_sha256": digest}


def publish_transfer_offer(
    request_raw: bytes, request_pin: object, packet_pin: object,
    budget_raw: bytes, budget_pin: object, offer_path: str | os.PathLike[str],
    acknowledgement_receiver_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Publish the exact v1 offer only at its prospectively budgeted job paths."""
    request = _validate_request(_parse_canonical(
        request_raw, "host checkpoint request",
    ))
    checked_request_pin = _pin(request_pin, "checkpoint request pin")
    _require(_sha(request_raw) == checked_request_pin["raw_sha256"] and
             request["request_sha256"] ==
                 checked_request_pin["semantic_sha256"],
             "offer request differs from its exact pin")
    packet = _exact(packet_pin, {
        "path", "raw_sha256", "byte_count",
    }, "transfer packet pin")
    packet_path = _path(packet["path"], "transfer packet origin path")
    packet_sha = _digest(packet["raw_sha256"], "transfer packet raw digest")
    packet_size = _uint(packet["byte_count"], "transfer packet byte count",
                        positive=True)
    offer_path_text = _path(os.fspath(offer_path), "offer output path")
    receiver_path = _path(os.fspath(acknowledgement_receiver_path),
                          "ACK bundle receiver path")
    budget_pin_checked = _pin(budget_pin, "host evidence budget pin")
    _require(_sha(budget_raw) == budget_pin_checked["raw_sha256"],
             "offer budget bytes differ from raw pin")
    budget = _parse_canonical(budget_raw, "host evidence budget")
    context = request["context"]
    _validate_budget_context(budget, context)
    limits = _budget_limits(
        budget_raw, budget_pin_checked, context["campaign_id"],
        context["host_id"],
    )
    (max_packet, packet_inodes, _window_bytes, _window_inodes, _roots,
     _scratch, max_ack, _max_signature) = limits
    _require(packet_inodes == 1 and packet_size <= max_packet,
             "offer packet pin exceeds the exact one-inode budget")
    (req_row, packet_row, offer_row, receiver_row,
     incoming_row) = _offer_catalogue_rows(
        request, budget, checked_request_pin["path"], packet_path,
        offer_path_text, receiver_path,
    )
    _require(len(request_raw) <= req_row["max_file_bytes"] and
             packet_size <= packet_row["max_file_bytes"] and
             receiver_row["max_file_bytes"] <= max_ack and
             receiver_row["max_file_bytes"] > 0 and
             incoming_row["max_file_bytes"] == receiver_row["max_file_bytes"],
             "offer request/packet/ACK caps differ from exact catalogue ceilings")
    request_disk_raw, request_disk_sha, _ = _read_regular_absolute(
        checked_request_pin["path"], req_row["max_file_bytes"],
        "host checkpoint request before offer",
    )
    _require(request_disk_raw == request_raw and
             request_disk_sha == checked_request_pin["raw_sha256"],
             "catalogued checkpoint request file differs from its exact pin")
    packet_disk_sha, packet_info = _hash_absolute_regular(
        Path(packet_path), packet_row["max_file_bytes"],
        "transfer packet before offer",
    )
    _require(packet_disk_sha == packet_sha and
             packet_info.st_size == packet_size,
             "catalogued transfer packet file differs from its exact pin")
    receiver = Path(receiver_path)
    receiver_parent_fd = _open_abs_dir(
        str(receiver.parent), "ACK receiver parent", private_final=True,
    )
    try:
        for receiver_name in (receiver.name, receiver.name + ".incoming"):
            try:
                os.stat(receiver_name, dir_fd=receiver_parent_fd,
                        follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise TransferPacketError(
                "exclusive ACK final/incoming path already exists",
            )
    finally:
        os.close(receiver_parent_fd)
    offer = _offer_body(
        checked_request_pin, packet_path, packet_sha, packet_size,
        receiver_path, receiver_row["max_file_bytes"],
    )
    raw = _canonical(offer)
    _require(len(raw) <= offer_row["max_file_bytes"],
             "transfer offer exceeds its exact catalogue path ceiling")
    path = Path(offer_path_text)
    parent_fd = _open_abs_dir(str(path.parent), "transfer offer parent",
                              private_final=True)
    try:
        try:
            os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise TransferPacketError(
                "catalogued transfer offer path already exists",
            )
        raw_sha, size = _write_at_fd(parent_fd, path.name, raw,
                                     "Source5 transfer offer")
        reopened, reopened_sha, _ = _read_fd_at(
            parent_fd, path.name, MAX_JSON_BYTES,
            "Source5 transfer offer", expected_bytes=size,
        )
        _require(reopened == raw and reopened_sha == raw_sha,
                 "transfer offer failed independent reopen")
        return offer, {
            "path": str(path), "raw_sha256": raw_sha,
            "semantic_sha256": offer["offer_sha256"],
        }
    finally:
        os.close(parent_fd)


def validate_transfer_offer(
    offer_raw: bytes, offer_pin: object, budget_raw: bytes,
    budget_pin: object, *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> tuple[dict[str, Any], dict[str, str],
           tuple[int, int, int, int, list[str], str, int, int]]:
    offer = _exact(_parse_canonical(offer_raw, "archive transfer offer"), {
        "schema", "checkpoint_request_pin", "transfer_packet_pin",
        "acknowledgement_receiver", "offer_sha256",
    }, "archive transfer offer")
    checked_offer_pin = _pin(offer_pin, "archive transfer offer pin")
    body = {key: item for key, item in offer.items()
            if key != "offer_sha256"}
    _require(offer["schema"] ==
             "allocatbelt.application-source5-archive-transfer-offer.v1" and
             offer["offer_sha256"] == _sha(_canonical(body)) and
             checked_offer_pin["raw_sha256"] == _sha(offer_raw) and
             checked_offer_pin["semantic_sha256"] == offer["offer_sha256"],
             "transfer offer bytes or semantic pin differs")
    request_pin = _pin(offer["checkpoint_request_pin"],
                       "offer checkpoint request pin")
    packet_pin = _exact(offer["transfer_packet_pin"], {
        "path", "raw_sha256", "byte_count",
    }, "offer transfer packet pin")
    packet_pin = {
        "path": _path(packet_pin["path"], "offer packet path"),
        "raw_sha256": _digest(packet_pin["raw_sha256"],
                              "offer packet raw digest"),
        "byte_count": _uint(packet_pin["byte_count"],
                            "offer packet size", positive=True),
    }
    receiver = _exact(offer["acknowledgement_receiver"], {
        "path", "maximum_bytes",
    }, "offer ACK bundle receiver")
    receiver_path = _path(receiver["path"], "offer ACK receiver path")
    receiver_cap = _uint(receiver["maximum_bytes"],
                         "offer ACK bundle byte cap", positive=True)
    budget = _parse_canonical(budget_raw, "host evidence budget")
    budget_pin_checked = _pin(budget_pin, "host evidence budget pin")
    _require(_sha(budget_raw) == budget_pin_checked["raw_sha256"],
             "offer budget bytes differ from their raw pin")
    budget_body = {key: item for key, item in budget.items()
                   if key != "budget_sha256"}
    _require(budget.get("budget_sha256") == _sha(_canonical(budget_body)) ==
             budget_pin_checked["semantic_sha256"],
             "offer budget semantic pin differs")
    limits = _budget_limits(
        budget_raw, budget_pin_checked, budget["campaign_id"],
        budget["host_id"],
    )
    (max_packet, packet_inodes, _window_bytes, _window_inodes, _roots,
     _scratch, max_ack, _max_signature) = limits
    offer_path = checked_offer_pin["path"]
    request_path = request_pin["path"]
    packet_path = packet_pin["path"]
    incoming_path = _path(receiver_path + ".incoming",
                          "offer ACK incoming path")
    rows = _catalogue_rows_for_paths(
        budget, {offer_path, request_path, packet_path, receiver_path,
                 incoming_path},
        budget["host_id"], None, None,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )
    phase = rows[request_path]["phase"]
    run_id = rows[request_path]["run_id"]
    _require(type(phase) is str and type(run_id) is str and
             all(row["phase"] == phase and row["run_id"] == run_id
                 for row in rows.values()),
             "offer paths do not share one original phase/run group")
    expected_roles = {
        offer_path: "source5_transfer_offer",
        request_path: "source5_checkpoint_request",
        packet_path: "source5_transfer_packet",
        receiver_path: "source5_ack_bundle",
        incoming_path: "source5_ack_bundle_incoming",
    }
    for path, role in expected_roles.items():
        _require(rows[path]["role"] == role,
                 f"offer path {path} is not catalogued as {role}")
    _require(rows[incoming_path]["max_file_bytes"] ==
             rows[receiver_path]["max_file_bytes"] and
             rows[incoming_path]["max_bytes"] ==
                 rows[receiver_path]["max_bytes"] and
             rows[incoming_path]["storage_root"] ==
                 rows[receiver_path]["storage_root"] and
             rows[incoming_path]["owner"] == rows[receiver_path]["owner"] and
             rows[incoming_path]["max_inodes"] == 1 and
             rows[receiver_path]["max_inodes"] == 1,
             "incoming/final ACK alternatives differ from their exact cap")
    _require(packet_inodes == 1 and packet_pin["byte_count"] <= max_packet and
             packet_pin["byte_count"] <= rows[packet_path]["max_file_bytes"] and
             receiver_cap == rows[receiver_path]["max_file_bytes"] and
             receiver_cap <= max_ack,
             "offer paths or caps differ from the pinned catalogue")
    return offer, checked_offer_pin, limits


def _catalogue_rows_for_paths(
    budget: dict[str, Any], paths: set[str], host_id: str,
    phase: str | None, run_id: str | None,
    *, catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> dict[str, dict[str, Any]]:
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict and
             catalogue.get("schema") ==
                 "allocatbelt.application-source5-host-path-catalogue.v2" and
             type(catalogue.get("chunks")) is list and
             type(catalogue.get("entry_count")) is int,
             "pinned host budget lacks its exact path catalogue")
    chunk_bytes = _uint(catalogue.get("chunk_bytes"),
                        "catalogue chunk byte ceiling", positive=True)
    entry_count = _uint(catalogue.get("entry_count"),
                        "catalogue entry count", positive=True)
    _require(chunk_bytes <= MAX_CATALOGUE_CHUNK_BYTES,
             "catalogue chunk byte ceiling exceeds the producer metadata bound")
    catalogue_body = {key: item for key, item in catalogue.items()
                      if key != "semantic_sha256"}
    _require(catalogue.get("semantic_sha256") ==
             _sha(_canonical(catalogue_body)),
             "host path catalogue semantic digest differs")
    _require((catalogue_chunk_paths is None) ==
             (catalogue_cache_root is None),
             "Root-local catalogue mapping and cache root must be supplied together")
    local_cache = None
    if catalogue_chunk_paths is not None:
        _require(type(catalogue_chunk_paths) is dict,
                 "Root-local catalogue map is not a path dictionary")
        local_cache = Path(_path(catalogue_cache_root,
                                 "Root-local catalogue cache root"))
        cache_fd = _open_abs_dir(str(local_cache),
                                 "Root-local catalogue cache root",
                                 private_final=True)
        os.close(cache_fd)
    expected_chunk_rows = 0
    found: dict[str, dict[str, Any]] = {}
    previous_chunk = ""
    previous_path = ""
    seen_chunk_paths = set()
    for index, descriptor_value in enumerate(catalogue["chunks"]):
        descriptor = _exact(descriptor_value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "row_count", "first_path", "last_path",
        }, f"host path catalogue chunk[{index}]")
        chunk_path = _path(descriptor["path"], "host path catalogue chunk path")
        raw_sha = _digest(descriptor["raw_sha256"], "catalogue chunk raw digest")
        semantic_sha = _digest(descriptor["semantic_sha256"],
                               "catalogue chunk semantic digest")
        byte_count = _uint(descriptor["byte_count"], "catalogue chunk byte count",
                           positive=True)
        row_count = _uint(descriptor["row_count"], "catalogue chunk row count",
                          positive=True)
        _require(chunk_path > previous_chunk and
                 semantic_sha == raw_sha and
                 byte_count <= chunk_bytes and
                 row_count <= entry_count and row_count <= byte_count and
                 expected_chunk_rows + row_count <= entry_count,
                 "host path catalogue chunk pin/order differs")
        previous_chunk = chunk_path
        seen_chunk_paths.add(chunk_path)
        if catalogue_chunk_paths is None:
            read_path = chunk_path
        else:
            _require(chunk_path in catalogue_chunk_paths,
                     "Root-local map omits a pinned host catalogue origin")
            read_path = _path(catalogue_chunk_paths[chunk_path],
                              "Root-local catalogue chunk path")
            local = Path(read_path)
            _require(read_path != chunk_path and local != local_cache and
                     local_cache in local.parents,
                     "Root-local catalogue chunk aliases or escapes its cache")
        raw, digest, _ = _read_regular_absolute(
            read_path, byte_count, "host path catalogue chunk",
        )
        _require(len(raw) == byte_count and digest == raw_sha,
                 "host path catalogue chunk differs from its raw pin")
        lines = raw.splitlines(keepends=True)
        _require(len(lines) == row_count and bool(lines),
                 "host path catalogue chunk row count differs")
        chunk_first = None
        chunk_last = None
        for line_index, line in enumerate(lines):
            _require(line.endswith(b"\n") and b"\r" not in line and
                     len(line) <= 64 * 1024,
                     "path catalogue line framing/size differs")
            try:
                row_value = json.loads(line.decode("ascii", "strict"))
            except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                raise TransferPacketError(
                    f"path catalogue row is malformed: {error}",
                ) from error
            row = _exact(row_value, {
                "path", "kind", "role", "host_id", "max_bytes",
                "max_file_bytes", "max_inodes", "storage_root", "owner",
                "phase", "run_id", "member_index", "aggregate_id",
                "aggregate_max_bytes", "origin_pin",
            }, "path catalogue row")
            _require(line == _canonical(row),
                     "path catalogue row is not canonical")
            row_path = _path(row["path"], "catalogue row path")
            role = _token(row["role"], "catalogue row role")
            _require(row_path > previous_path and row["kind"] in {"file", "tree"} and
                     (row["host_id"] is None or
                      type(row["host_id"]) is str) and
                     (row["phase"] is None or type(row["phase"]) is str) and
                     (row["run_id"] is None or type(row["run_id"]) is str),
                     "path catalogue order/identity is malformed")
            previous_path = row_path
            chunk_first = row_path if chunk_first is None else chunk_first
            chunk_last = row_path
            for field in ("max_bytes", "max_file_bytes", "max_inodes"):
                _uint(row[field], f"catalogue row {field}")
            _require(row["max_file_bytes"] <= row["max_bytes"] and
                     ((row["kind"] == "file" and row["max_inodes"] == 1) or
                      (row["kind"] == "tree" and row["max_inodes"] > 0)),
                     "catalogue row per-file/inode bounds are malformed")
            if row_path in paths:
                _require(row_path not in found and row["kind"] == "file" and
                         row["host_id"] == host_id and
                         (phase is None or row["phase"] == phase) and
                         (run_id is None or row["run_id"] == run_id),
                         "offer path is missing, duplicated, or outside its original job")
                found[row_path] = row
        _require(chunk_first == descriptor["first_path"] and
                 chunk_last == descriptor["last_path"],
                 "path catalogue chunk path range differs from its actual rows")
        expected_chunk_rows += row_count
    _require(expected_chunk_rows == catalogue["entry_count"] and
             set(found) == paths,
             "exact offer paths do not close over the pinned catalogue")
    if catalogue_chunk_paths is not None:
        _require(set(catalogue_chunk_paths) == seen_chunk_paths,
                 "Root-local catalogue map is not the complete exact chunk set")
    return found


def _offer_catalogue_rows(
    request: dict[str, Any], budget: dict[str, Any],
    request_path: str, packet_path: str, offer_path: str,
    receiver_path: str, *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    host_id, phase, run_id, _campaign_id = _request_job_group(request)
    incoming_path = _path(receiver_path + ".incoming",
                          "ACK bundle incoming path")
    paths = {request_path, packet_path, offer_path, receiver_path,
             incoming_path}
    rows = _catalogue_rows_for_paths(
        budget, paths, host_id, phase, run_id,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )
    expected_roles = {
        request_path: "source5_checkpoint_request",
        packet_path: "source5_transfer_packet",
        offer_path: "source5_transfer_offer",
        receiver_path: "source5_ack_bundle",
        incoming_path: "source5_ack_bundle_incoming",
    }
    for path, role in expected_roles.items():
        _require(rows[path]["role"] == role and rows[path]["kind"] == "file",
                 f"catalogued path {path} has role other than {role}")
    _require(rows[incoming_path]["max_file_bytes"] ==
             rows[receiver_path]["max_file_bytes"] and
             rows[incoming_path]["max_bytes"] ==
                 rows[receiver_path]["max_bytes"] and
             rows[incoming_path]["storage_root"] ==
                 rows[receiver_path]["storage_root"] and
             rows[incoming_path]["owner"] == rows[receiver_path]["owner"] and
             rows[incoming_path]["max_inodes"] == 1 and
             rows[receiver_path]["max_inodes"] == 1,
             "incoming and final ACK alternatives have different exact caps")
    return (rows[request_path], rows[packet_path], rows[offer_path],
            rows[receiver_path], rows[incoming_path])


def _entry_catalogue_rows(
    request: dict[str, Any], budget: dict[str, Any], *,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
) -> dict[str, dict[str, Any]]:
    host_id, phase, run_id, _campaign_id = _request_job_group(request)
    entries = request["entries"]
    paths = {row["origin_path"] for row in entries}
    rows = _catalogue_rows_for_paths(
        budget, paths, host_id, phase, run_id,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )
    for entry in entries:
        catalogue_row = rows[entry["origin_path"]]
        _require(catalogue_row["role"] == entry["role"] and
                 catalogue_row["kind"] == "file" and
                 catalogue_row["max_inodes"] == 1 and
                 catalogue_row["max_file_bytes"] ==
                     catalogue_row["max_bytes"] and
                 entry["byte_count"] <= catalogue_row["max_file_bytes"],
                 "request object row exceeds its exact source-pinned catalogue role/cap")
        if catalogue_row["origin_pin"] is not None:
            origin_pin = _exact(catalogue_row["origin_pin"], {
                "raw_sha256", "semantic_sha256",
            }, "catalogued source origin pin")
            origin_raw = _digest(origin_pin["raw_sha256"],
                                 "catalogued source origin raw digest")
            origin_semantic = origin_pin["semantic_sha256"]
            _require(origin_semantic is None or
                     type(origin_semantic) is str,
                     "catalogued source origin semantic digest is malformed")
            if origin_semantic is not None:
                origin_semantic = _digest(
                    origin_semantic,
                    "catalogued source origin semantic digest",
                )
            _require(origin_raw == entry["raw_sha256"] and
                     origin_semantic == entry["semantic_sha256"],
                     "request object differs from its source-pinned catalogue origin")
    return rows


def _packet_parent(
    packet_path: str, scratch_root: str,
) -> tuple[int, str]:
    path = Path(_path(packet_path, "packet output path"))
    root = Path(_path(scratch_root, "budget packet scratch root"))
    _require(path != root and root in path.parents,
             "packet output escapes the budget-reserved scratch root")
    root_fd = _open_abs_dir(str(root), "budget packet scratch root",
                            private_final=True)
    parent_fd, name = _parent_at(root_fd, path.relative_to(root).as_posix(),
                                 create=False, label="packet output")
    os.close(root_fd)
    return parent_fd, name


def export_transfer_packet(
    request_raw: bytes, request_pin: object,
    budget_path: str | os.PathLike[str],
    packet_path: str | os.PathLike[str],
    offer_path: str | os.PathLike[str],
    acknowledgement_receiver_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Stream one canonical request and its exact source bytes into one tar file."""
    request = _validate_request(_parse_canonical(
        request_raw, "host checkpoint request",
    ))
    pin = _pin(request_pin, "host checkpoint request pin")
    _require(_sha(request_raw) == pin["raw_sha256"] and
             request["request_sha256"] == pin["semantic_sha256"],
             "host checkpoint request differs from its transfer pin")
    _budget, budget_raw, limits = _budget_and_pin_for_request(
        request, budget_path,
    )
    _validate_budget_context(_budget, request["context"])
    (max_packet, max_packet_inodes, max_window_bytes, max_window_inodes,
     roots, scratch_root, max_ack_bundle_bytes, max_signature_bytes) = limits
    rows = request["entries"]
    _entry_catalogue_rows(request, _budget)
    payload = sum(row["byte_count"] for row in rows)
    _require(payload <= max_window_bytes and len(rows) <= max_window_inodes,
             "job payload exceeds the pinned live-window bytes/inodes")
    job_row, job_identity = _job_record_source(
        request, _budget, roots,
    )
    members = [("checkpoint-request.json", len(request_raw)),
               ("validation/job-record.json", job_row["byte_count"])]
    identities = {}
    for row in rows:
        name = _packet_member_name(row["origin_path"], row["raw_sha256"])
        members.append((name, row["byte_count"]))
        identities[row["origin_path"]] = _hash_source(
            row["origin_path"], roots, row,
        )
    packet_size = _tar_size(members)
    _require(max_packet_inodes == 1 and packet_size <= max_packet,
             "complete tar packet cannot fit the pinned byte/inode reservation")
    destination = _path(os.fspath(packet_path), "packet output path")
    offer_path_text = _path(os.fspath(offer_path), "offer output path")
    receiver_path_text = _path(
        os.fspath(acknowledgement_receiver_path), "ACK receiver output path",
    )
    (req_row, packet_row, offer_row, receiver_row,
     incoming_row) = _offer_catalogue_rows(
        request, _budget, pin["path"], destination, offer_path_text,
        receiver_path_text,
    )
    _require(len(request_raw) <= req_row["max_file_bytes"] and
             packet_size <= packet_row["max_file_bytes"] and
             receiver_row["max_file_bytes"] <= max_ack_bundle_bytes and
             receiver_row["max_file_bytes"] > 0 and
             incoming_row["max_file_bytes"] == receiver_row["max_file_bytes"],
             "request/packet/ACK paths exceed their exact prewrite caps")
    request_disk_raw, request_disk_sha, _request_info = _read_regular_absolute(
        pin["path"], req_row["max_file_bytes"],
        "catalogued checkpoint request before packet write",
    )
    _require(request_disk_raw == request_raw and
             request_disk_sha == pin["raw_sha256"],
             "request path differs from its exact transfer pin")
    provisional_offer = _offer_body(
        pin, destination, "f" * 64, packet_size,
        receiver_path_text, receiver_row["max_file_bytes"],
    )
    _require(len(_canonical(provisional_offer)) <= offer_row["max_file_bytes"],
             "provisional offer exceeds its exact catalogue file ceiling")
    receiver_parent_fd = _open_abs_dir(
        str(Path(receiver_path_text).parent), "ACK receiver parent",
        private_final=True,
    )
    try:
        receiver_name = Path(receiver_path_text).name
        for candidate_name in (receiver_name, receiver_name + ".incoming"):
            try:
                os.stat(candidate_name, dir_fd=receiver_parent_fd,
                        follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise TransferPacketError(
                "exclusive ACK final/incoming path already exists before export",
            )
    finally:
        os.close(receiver_parent_fd)
    parent_fd, name = _packet_parent(destination, scratch_root)
    try:
        out_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(out_fd, 0o600)
            position = 0

            def emit(raw: bytes) -> None:
                nonlocal position
                _write_all(out_fd, raw)
                position += len(raw)

            def emit_member_header(member: str, size: int) -> None:
                nonlocal position
                if size > USTAR_MAX_SIZE:
                    pax_record = _pax_size_record(size)
                    emit(_tar_header("PaxHeaders/size", len(pax_record),
                                     typeflag=b"x"))
                    emit(pax_record)
                    pax_padding = (-len(pax_record)) % TAR_BLOCK_BYTES
                    if pax_padding:
                        emit(b"\x00" * pax_padding)
                emit(_tar_header(member, size, typeflag=b"0"))

            emit_member_header("checkpoint-request.json", len(request_raw))
            emit(request_raw)
            request_padding = (-len(request_raw)) % TAR_BLOCK_BYTES
            if request_padding:
                emit(b"\x00" * request_padding)
            job_fd, job_kind, job_before = _open_source(
                request["job_record_pin"]["path"], roots,
            )
            try:
                _require(job_kind == "regular" and
                         _info_key(job_before) == job_identity[2] and
                         job_before.st_size == job_row["byte_count"],
                         "always-local job record identity changed before transfer")
                emit_member_header("validation/job-record.json",
                                   job_row["byte_count"])
                job_stream = _HashingReader(job_fd, job_row["byte_count"])
                while job_stream.count < job_row["byte_count"]:
                    emit(job_stream.read(BLOCK_BYTES))
                _require(job_stream.count == job_row["byte_count"] and
                         job_stream.hasher.hexdigest() == job_row["raw_sha256"] and
                         _info_key(job_before) == _info_key(os.fstat(job_fd)),
                         "always-local job record changed during transfer")
                job_padding = (-job_row["byte_count"]) % TAR_BLOCK_BYTES
                if job_padding:
                    emit(b"\x00" * job_padding)
            finally:
                os.close(job_fd)
            for row in rows:
                member = _packet_member_name(
                    row["origin_path"], row["raw_sha256"],
                )
                fd, kind, before = _open_source(row["origin_path"], roots)
                try:
                    emit_member_header(member, row["byte_count"])
                    if kind.startswith("symlink:"):
                        parent_source, leaf = fd, kind.split(":", 1)[1]
                        raw_link, after = _read_symlink(
                            parent_source, leaf, row,
                        )
                        _require(_info_key(after) ==
                                 identities[row["origin_path"]][2],
                                 "source link identity changed before export")
                        emit(raw_link)
                        link_padding = (-len(raw_link)) % TAR_BLOCK_BYTES
                        if link_padding:
                            emit(b"\x00" * link_padding)
                    else:
                        _require(identities[row["origin_path"]][0] ==
                                 "regular" and
                                 _info_key(before) ==
                                 identities[row["origin_path"]][2] and
                                 before.st_size == row["byte_count"],
                                 "source file identity changed before export")
                        stream = _HashingReader(fd, row["byte_count"])
                        while stream.count < row["byte_count"]:
                            block = stream.read(BLOCK_BYTES)
                            emit(block)
                        after = os.fstat(fd)
                        _require(stream.count == row["byte_count"] and
                                 stream.hasher.hexdigest() ==
                                     row["raw_sha256"] and
                                 _info_key(before) == _info_key(after),
                                 "source file changed during packet streaming")
                        file_padding = (-row["byte_count"]) % TAR_BLOCK_BYTES
                        if file_padding:
                            emit(b"\x00" * file_padding)
                finally:
                    os.close(fd)
            emit(b"\x00" * 1024)
            trailer_padding = packet_size - position
            _require(0 <= trailer_padding < TAR_RECORD_BYTES,
                     "packet record padding differs from its preflight size")
            if trailer_padding:
                emit(b"\x00" * trailer_padding)
            _require(position == packet_size,
                     "packet writer size differs from its preflight bound")
            os.fsync(out_fd)
        finally:
            os.close(out_fd)
        os.fsync(parent_fd)
        # Independent reopen and full packet hash; packet creation remains
        # outside the APP/pressure timed lanes and uses the reserved one inode.
        packet_sha, packet_info = _hash_absolute_regular(
            Path(destination), max_packet, "completed transfer packet",
        )
        _require(packet_info.st_size == packet_size,
                 "completed transfer packet differs from its sealed size/hash")
        return {
            "schema": PACKET_PIN_SCHEMA,
            "path": destination, "raw_sha256": packet_sha,
            "byte_count": packet_info.st_size,
            "request_pin": pin,
            "maximum_packet_bytes": max_packet,
        }
    finally:
        os.close(parent_fd)


def _hash_absolute_regular(path: Path, maximum: int,
                           label: str) -> tuple[str, os.stat_result]:
    path_text = _path(str(path), f"{label} path")
    checked = Path(path_text)
    _require(checked.resolve(strict=True) == checked,
             f"{label} traverses a symlink or alias")
    parent_fd = _open_abs_dir(str(checked.parent), f"{label} parent",
                              private_final=True)
    try:
        path_info = os.stat(checked.name, dir_fd=parent_fd,
                            follow_symlinks=False)
        _require(stat.S_ISREG(path_info.st_mode) and
                 path_info.st_uid == os.getuid() and
                 stat.S_IMODE(path_info.st_mode) == 0o600 and
                 path_info.st_nlink == 1 and path_info.st_size <= maximum,
                 f"{label} is not an owned private bounded regular file")
        fd = os.open(checked.name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                     _O_NONBLOCK, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            _require(_info_key(before) == _info_key(path_info),
                     f"{label} changed identity before hashing")
            hasher = hashlib.sha256()
            total = 0
            while total < before.st_size:
                block = os.read(fd, min(BLOCK_BYTES, before.st_size - total))
                _require(bool(block), f"{label} shortened while hashing")
                total += len(block)
                hasher.update(block)
            _require(os.read(fd, 1) == b"" and total == before.st_size and
                     _info_key(before) == _info_key(os.fstat(fd)) and
                     _info_key(before) == _info_key(os.stat(
                         checked.name, dir_fd=parent_fd,
                         follow_symlinks=False,
                     )), f"{label} changed during stable hash")
            return hasher.hexdigest(), before
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _packet_file(
    path_value: str | os.PathLike[str], maximum: int,
) -> tuple[int, os.stat_result]:
    path = Path(_path(os.fspath(path_value), "transfer packet path"))
    _require(path.resolve(strict=True) == path,
             "transfer packet path traverses a symlink or alias")
    parent_fd = _open_abs_dir(str(path.parent), "packet parent",
                              private_final=True)
    try:
        before_path = os.stat(path.name, dir_fd=parent_fd,
                              follow_symlinks=False)
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and before_path.st_size <= maximum,
                 "transfer packet is not an owned bounded mode-0600 single-link file")
        fd = os.open(path.name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                     _O_NONBLOCK, dir_fd=parent_fd)
        opened = os.fstat(fd)
        _require(_info_key(opened) == _info_key(before_path),
                 "transfer packet changed identity before open")
        os.close(parent_fd)
        return fd, opened
    except BaseException:
        os.close(parent_fd)
        raise


def _hash_packet_fd(fd: int, expected: os.stat_result) -> str:
    hasher = hashlib.sha256()
    offset = 0
    while offset < expected.st_size:
        block = os.pread(fd, min(BLOCK_BYTES, expected.st_size - offset), offset)
        _require(bool(block), "packet shortened during independent raw hash")
        hasher.update(block)
        offset += len(block)
    _require(offset == expected.st_size and
             _info_key(expected) == _info_key(os.fstat(fd)),
             "packet changed during independent raw hash")
    return hasher.hexdigest()


def _parse_octal(value: bytes, label: str) -> int:
    _require(value and not (value[0] & 0x80),
             f"{label} uses unsupported base-256 encoding")
    trimmed = value.strip(b"\x00 ")
    _require(bool(trimmed) and all(48 <= byte <= 55 for byte in trimmed),
             f"{label} is not bounded octal")
    return int(trimmed, 8)


def _read_tar_header(fd: int, offset: int, file_size: int) -> dict[str, Any] | None:
    _require(0 <= offset <= file_size - TAR_BLOCK_BYTES,
             "tar packet ended before a complete header")
    header = os.pread(fd, TAR_BLOCK_BYTES, offset)
    _require(len(header) == TAR_BLOCK_BYTES,
             "tar packet ended during a header")
    if header == b"\x00" * TAR_BLOCK_BYTES:
        return None
    _require(header[257:263] == b"ustar\x00" and header[263:265] == b"00",
             "packet member is not the accepted USTAR header version")
    _require(header[265:345] == b"\x00" * 80 and
             header[345:500] == b"\x00" * 155 and
             header[500:512] == b"\x00" * 12,
             "packet header uses unsupported owner, prefix, or device fields")
    expected_checksum = _parse_octal(header[148:156], "tar header checksum")
    check = bytearray(header)
    check[148:156] = b" " * 8
    _require(sum(check) == expected_checksum,
             "tar header checksum differs")
    name_raw = header[0:100].split(b"\x00", 1)[0]
    prefix_raw = header[345:500].split(b"\x00", 1)[0]
    try:
        name = name_raw.decode("ascii", "strict")
        prefix = prefix_raw.decode("ascii", "strict")
    except UnicodeError as error:
        raise TransferPacketError("tar member name is not ASCII") from error
    full_name = name if not prefix else prefix + "/" + name
    _require(full_name and not full_name.startswith("/") and
             all(part not in ("", ".", "..") for part in
                 PurePosixPath(full_name).parts),
             "tar member name is absolute or traverses a path")
    return {
        "name": full_name,
        "mode": _parse_octal(header[100:108], "tar mode"),
        "uid": _parse_octal(header[108:116], "tar uid"),
        "gid": _parse_octal(header[116:124], "tar gid"),
        "size": _parse_octal(header[124:136], "tar size"),
        "mtime": _parse_octal(header[136:148], "tar mtime"),
        "typeflag": header[156:157],
        "linkname": header[157:257].split(b"\x00", 1)[0],
        "offset": offset,
    }


def _read_tar_bytes(fd: int, offset: int, size: int, maximum: int,
                    label: str) -> bytes:
    _require(0 <= size <= maximum,
             f"{label} exceeds its pre-parse byte ceiling")
    chunks = []
    total = 0
    while total < size:
        block = os.pread(fd, min(BLOCK_BYTES, size - total), offset + total)
        _require(bool(block), f"{label} shortened while reading")
        total += len(block)
        chunks.append(block)
    _require(total == size, f"{label} size differs")
    return b"".join(chunks)


def _require_zero_padding(fd: int, offset: int, size: int, label: str) -> int:
    padding = (-size) % TAR_BLOCK_BYTES
    if padding:
        raw = _read_tar_bytes(fd, offset + size, padding,
                              TAR_BLOCK_BYTES, f"{label} padding")
        _require(raw == b"\x00" * padding,
                 f"{label} has nonzero tar padding")
    return offset + size + padding


def _parse_pax_size(fd: int, header: dict[str, Any], file_size: int) -> tuple[int, int]:
    _require(header["name"] == "PaxHeaders/size" and
             header["typeflag"] == b"x" and header["mode"] == 0o600 and
             header["uid"] == 0 and header["gid"] == 0 and
             header["mtime"] == 0 and header["linkname"] == b"" and
             0 < header["size"] <= MAX_PAX_HEADER_BYTES,
             "extended tar header is not one bounded size-only PAX header")
    end = header["offset"] + TAR_BLOCK_BYTES + header["size"]
    _require(end <= file_size,
             "PAX header exceeds the packet file size")
    raw = _read_tar_bytes(
        fd, header["offset"] + TAR_BLOCK_BYTES, header["size"],
        MAX_PAX_HEADER_BYTES, "PAX size header",
    )
    space = raw.find(b" ")
    _require(space > 0 and raw.endswith(b"\n") and
             raw[:space].isdigit() and int(raw[:space]) == len(raw),
             "PAX record length/framing differs")
    body = raw[space + 1:-1]
    _require(body.startswith(b"size=") and body.count(b"=") == 1 and
             body[5:].isdigit(),
             "PAX header contains anything except one numeric size")
    size = int(body[5:])
    _require(0 <= size <= MAX_OBJECT_BYTES and _pax_size_record(size) == raw,
             "PAX size record is noncanonical or outside its finite bound")
    return size, _require_zero_padding(
        fd, header["offset"] + TAR_BLOCK_BYTES, header["size"], "PAX header",
    )


def _hash_packet_member(
    fd: int, offset: int, size: int, expected_sha: str,
) -> None:
    hasher = hashlib.sha256()
    total = 0
    while total < size:
        block = os.pread(fd, min(BLOCK_BYTES, size - total), offset + total)
        _require(bool(block), "tar object shortened during closure hashing")
        total += len(block)
        hasher.update(block)
    _require(total == size and hasher.hexdigest() == expected_sha,
             "tar object bytes differ from their exact row pin")


def _scan_packet(
    fd: int, packet_info: os.stat_result,
    expected_request_pin: dict[str, str],
    budget: dict[str, Any],
    catalogue_chunk_paths: dict[str, str], catalogue_cache_root: str,
) -> tuple[dict[str, Any], bytes, dict[str, Any], list[dict[str, Any]]]:
    file_size = packet_info.st_size
    offset = 0
    first = _read_tar_header(fd, offset, file_size)
    _require(first is not None and first["name"] == "checkpoint-request.json" and
             first["typeflag"] == b"0" and first["mode"] == 0o600 and
             first["uid"] == 0 and first["gid"] == 0 and first["mtime"] == 0 and
             first["linkname"] == b"" and first["size"] <= MAX_JSON_BYTES,
             "packet does not begin with one bounded canonical request file")
    request_size = first["size"]
    request_raw = _read_tar_bytes(
        fd, offset + TAR_BLOCK_BYTES, request_size, MAX_JSON_BYTES,
        "packet checkpoint request",
    )
    request = _validate_request(_parse_canonical(
        request_raw, "packet checkpoint request",
    ))
    _require(_sha(request_raw) == expected_request_pin["raw_sha256"] and
             request["request_sha256"] ==
                 expected_request_pin["semantic_sha256"],
             "packet checkpoint request differs from its external pin")
    _entry_catalogue_rows(
        request, budget, catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )
    maximum_job_record_bytes = _job_record_catalogue_row(
        request, budget, catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )["max_file_bytes"]
    offset = _require_zero_padding(
        fd, offset + TAR_BLOCK_BYTES, request_size,
        "packet checkpoint request",
    )
    job_header = _read_tar_header(fd, offset, file_size)
    _require(job_header is not None and
             job_header["name"] == "validation/job-record.json" and
             job_header["typeflag"] == b"0" and
             job_header["mode"] == 0o600 and job_header["uid"] == 0 and
             job_header["gid"] == 0 and job_header["mtime"] == 0 and
             job_header["linkname"] == b"" and
             0 < job_header["size"] <= maximum_job_record_bytes and
             job_header["size"] <= MAX_JSON_BYTES,
             "packet lacks its exact bounded always-local job-record member")
    job_record_size = job_header["size"]
    job_record_offset = offset + TAR_BLOCK_BYTES
    job_record_raw = _read_tar_bytes(
        fd, job_record_offset, job_record_size, maximum_job_record_bytes,
        "packet always-local job record",
    )
    _require(_sha(job_record_raw) == request["job_record_pin"]["raw_sha256"],
             "packet job-record bytes differ from the original raw pin")
    job_record = _parse_canonical(job_record_raw,
                                  "packet always-local job record")
    _require(job_record.get("schema") ==
             "allocatbelt.application-source5-job-record.v1" and
             job_record.get("record_sha256") == _sha(_canonical({
                 key: item for key, item in job_record.items()
                 if key != "record_sha256"
             })),
             "packet job-record self digest or schema differs")
    job_location = {
        "offset": job_record_offset, "byte_count": job_record_size,
        "raw_sha256": request["job_record_pin"]["raw_sha256"],
    }
    offset = _require_zero_padding(fd, job_record_offset, job_record_size,
                                   "packet always-local job record")
    locations = []
    for row in request["entries"]:
        header = _read_tar_header(fd, offset, file_size)
        _require(header is not None,
                 "packet ended before every raw object member")
        expected_size = row["byte_count"]
        if expected_size > USTAR_MAX_SIZE:
            pax_size, offset = _parse_pax_size(fd, header, file_size)
            _require(pax_size == expected_size,
                     "PAX object size differs from the exact request row")
            header = _read_tar_header(fd, offset, file_size)
            _require(header is not None,
                     "packet ended after its PAX size header")
            _require(header["size"] == 0,
                     "large member USTAR header has an unexpected fallback size")
            offset += TAR_BLOCK_BYTES
        else:
            _require(header["size"] == expected_size,
                     "tar object size differs from its exact request row")
            offset += TAR_BLOCK_BYTES
        member_name = _packet_member_name(
            row["origin_path"], row["raw_sha256"],
        )
        _require(header["name"] == member_name and
                 header["typeflag"] == b"0" and header["mode"] == 0o600 and
                 header["uid"] == 0 and header["gid"] == 0 and
                 header["mtime"] == 0 and header["linkname"] == b"",
                 "packet object member is not its exact regular content-addressed file")
        data_offset = offset
        _hash_packet_member(fd, data_offset, expected_size, row["raw_sha256"])
        offset = _require_zero_padding(fd, data_offset, expected_size,
                                       "packet object")
        locations.append({
            "origin_path": row["origin_path"],
            "object_id": _object_identity(row["origin_path"],
                                           row["raw_sha256"]),
            "offset": data_offset, "byte_count": expected_size,
            "raw_sha256": row["raw_sha256"],
        })
    end = _read_tar_header(fd, offset, file_size)
    _require(end is None, "packet has an extra or unrecognized tar member")
    offset += TAR_BLOCK_BYTES
    second_end = os.pread(fd, TAR_BLOCK_BYTES, offset)
    _require(second_end == b"\x00" * TAR_BLOCK_BYTES,
             "packet lacks the complete tar end marker")
    offset += TAR_BLOCK_BYTES
    expected_packet_size = _tar_size(
        [("checkpoint-request.json", request_size),
         ("validation/job-record.json", job_record_size)] +
        [(_packet_member_name(row["origin_path"], row["raw_sha256"]),
          row["byte_count"]) for row in request["entries"]],
    )
    _require(expected_packet_size == file_size and offset <= file_size and
             file_size - offset < TAR_RECORD_BYTES,
             "packet size differs from exact header/padding closure")
    trailer = _read_tar_bytes(fd, offset, file_size - offset,
                              TAR_RECORD_BYTES, "tar record padding")
    _require(trailer == b"\x00" * len(trailer),
             "packet has nonzero trailing tar padding")
    return request, request_raw, job_location, locations


def _document_self_digest(raw: bytes, field: str,
                          label: str) -> tuple[dict[str, Any], str]:
    value = _parse_canonical(raw, label)
    claimed = _digest(value.get(field), f"{label} self digest")
    body = {key: item for key, item in value.items() if key != field}
    _require(claimed == _sha(_canonical(body)),
             f"{label} self digest differs")
    return value, claimed


def _validate_ack_bundle_documents(
    checkpoint_raw: bytes, manifest_raw: bytes, ack_raw: bytes,
    signature_raw: bytes, maximum_signature_bytes: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    checkpoint, checkpoint_sha = _document_self_digest(
        checkpoint_raw, "checkpoint_sha256", "final checkpoint",
    )
    _exact(checkpoint, {
        "schema", "request_pin", "context", "job_record_pin", "authorization",
        "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
        "object_manifest_pin", "entries", "checkpoint_sha256",
    }, "final checkpoint")
    _require(checkpoint["schema"] ==
             "allocatbelt.application-source5-evidence-job-checkpoint.v1",
             "final checkpoint schema differs")
    request_pin = _pin(checkpoint["request_pin"], "checkpoint request pin")
    context = checkpoint["context"]
    request_projection = _validate_request({
        "schema": REQUEST_SCHEMA, "context": context,
        "job_record_pin": checkpoint["job_record_pin"],
        "authorization": checkpoint["authorization"],
        "predecessor_ack_pin": checkpoint["predecessor_ack_pin"],
        "owner_receipt_pins": checkpoint["owner_receipt_pins"],
        "empty_tmp_proofs": checkpoint["empty_tmp_proofs"],
        "entries": checkpoint["entries"],
        "request_sha256": request_pin["semantic_sha256"],
    })
    _require(checkpoint["predecessor_ack_pin"] ==
             request_projection["context"]["predecessor_ack_pin"],
             "final checkpoint predecessor differs from its original request")
    manifest_pin = _pin(checkpoint["object_manifest_pin"],
                         "checkpoint object-manifest pin")
    manifest, manifest_sha = _document_self_digest(
        manifest_raw, "manifest_sha256", "object manifest",
    )
    manifest = _exact(manifest, {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "job_ordinal", "job_sha256", "run_id", "job_record_raw_sha256",
        "predecessor_ack_pin", "objects", "object_count", "payload_bytes",
        "manifest_sha256",
    }, "object manifest")
    _require(manifest["schema"] ==
             "allocatbelt.application-source5-evidence-object-manifest.v1" and
             manifest["campaign_id"] == context["campaign_id"] and
             manifest["host_id"] == context["host_id"] and
             manifest["phase"] == context["phase"] and
             manifest["job_index"] == context["job_index"] and
             manifest["job_record_raw_sha256"] ==
                 checkpoint["job_record_pin"]["raw_sha256"] and
             manifest["predecessor_ack_pin"] ==
                 checkpoint["predecessor_ack_pin"] and
             type(manifest["job_ordinal"]) is int and
             manifest["job_ordinal"] > 0 and
             type(manifest["job_sha256"]) is str and
             re.fullmatch(r"[0-9a-f]{64}", manifest["job_sha256"]) and
             type(manifest["run_id"]) is str and
             type(manifest["objects"]) is list and
             len(manifest["objects"]) == len(checkpoint["entries"]) ==
                 manifest["object_count"],
             "object manifest identity or row count differs from checkpoint")
    total_object_bytes = 0
    for entry_value, object_value in zip(
        checkpoint["entries"], manifest["objects"], strict=True,
    ):
        entry = _exact(entry_value, {
            "origin_path", "role", "byte_count", "raw_sha256",
            "semantic_sha256",
        }, "checkpoint object entry")
        entry_role = _token(entry["role"], "checkpoint object role")
        _require(entry_role not in NON_EXPORTABLE_JOB_ROLES,
                 "always-local job-record/disposition role is not in an ACK closure")
        obj = _exact(object_value, {
            "origin_path", "role", "object_id", "byte_count", "raw_sha256",
            "semantic_sha256", "object_pin",
        }, "object manifest entry")
        origin = _path(entry["origin_path"], "checkpoint object origin")
        raw_sha = _digest(entry["raw_sha256"], "checkpoint object raw digest")
        object_name = _sha(origin.encode("utf-8"))
        object_id = f"{object_name[:2]}/{object_name}-{raw_sha}.bin"
        expected_object_pin = _exact(obj["object_pin"], {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
        }, "manifest content-addressed object pin")
        _require(obj["origin_path"] == origin and obj["role"] == entry["role"] and
                 obj["object_id"] == object_id and
                 obj["byte_count"] == entry["byte_count"] and
                 obj["raw_sha256"] == raw_sha and
                 obj["semantic_sha256"] == entry["semantic_sha256"] and
                 _path(expected_object_pin["path"],
                       "manifest private object path").endswith("/objects/" + object_id) and
                 expected_object_pin["raw_sha256"] == raw_sha and
                 expected_object_pin["semantic_sha256"] == raw_sha and
                 expected_object_pin["byte_count"] == entry["byte_count"],
                 "object manifest row differs from exact checkpoint object closure")
        total_object_bytes += entry["byte_count"]
        _require(total_object_bytes <= MAX_OBJECT_BYTES * MAX_ROWS,
                 "object manifest aggregate byte count exceeds finite bounds")
    _require(manifest["payload_bytes"] == total_object_bytes,
             "object manifest total differs from its exact checkpoint rows")
    ack, ack_sha = _document_self_digest(ack_raw, "ack_sha256", "durable ACK")
    _exact(ack, {
        "schema", "checkpoint_pin", "object_manifest_pin",
        "predecessor_ack_pin", "signer_fingerprint", "durable_commit",
        "ack_sha256",
    }, "durable ACK")
    _require(ack["schema"] ==
             "allocatbelt.application-source5-evidence-durable-ack.v1" and
             ack["checkpoint_pin"]["raw_sha256"] == _sha(checkpoint_raw) and
             ack["checkpoint_pin"]["semantic_sha256"] == checkpoint_sha and
             ack["object_manifest_pin"] == manifest_pin and
             ack["object_manifest_pin"]["raw_sha256"] == _sha(manifest_raw) and
             ack["object_manifest_pin"]["semantic_sha256"] == manifest_sha and
             checkpoint["object_manifest_pin"] == manifest_pin and
             ack["predecessor_ack_pin"] ==
                 checkpoint["predecessor_ack_pin"] and
             ack["signer_fingerprint"] ==
                 checkpoint["context"]["authorized_signer_fingerprint"] and
             type(signature_raw) is bytes and
             0 < len(signature_raw) <= maximum_signature_bytes <=
                 MAX_GPG_OUTPUT_BYTES,
             "ACK bundle documents do not form one exact signed closure")
    durable = _exact(ack["durable_commit"], {
        "commit_id", "archive_source5_directory", "checkpoint_pin",
        "object_manifest_pin", "object_reopen_sha256", "object_count",
        "payload_bytes", "job_record_validation",
    }, "ACK bundle durable commit")
    job_validation = _exact(durable["job_record_validation"], {
        "path", "origin_path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "ACK bundle always-local job-record validation")
    _require(_path(job_validation["path"], "job-record validation path") and
             _path(job_validation["origin_path"], "job-record origin path") ==
                 checkpoint["job_record_pin"]["path"] and
             _digest(job_validation["raw_sha256"],
                     "job-record validation raw digest") ==
                 checkpoint["job_record_pin"]["raw_sha256"] and
             _digest(job_validation["semantic_sha256"],
                     "job-record validation semantic digest") and
             _uint(job_validation["byte_count"],
                   "job-record validation byte count", positive=True),
             "ACK bundle job-record validation facts differ from its checkpoint")
    _require(durable["checkpoint_pin"] == ack["checkpoint_pin"] and
             durable["object_manifest_pin"] == ack["object_manifest_pin"] and
             durable["object_count"] == manifest.get("object_count") and
             durable["payload_bytes"] == manifest.get("payload_bytes"),
             "ACK bundle durable counts differ from its object manifest")
    return checkpoint, manifest, ack


def build_ack_bundle(
    checkpoint_raw: bytes, manifest_raw: bytes, ack_raw: bytes,
    signature_raw: bytes, budget_raw: bytes, budget_pin: object,
    output_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Write one bounded four-file USTAR ACK response bundle."""
    checkpoint_document = _parse_canonical(checkpoint_raw, "final checkpoint")
    limits = _budget_limits(
        budget_raw, budget_pin,
        checkpoint_document["context"]["campaign_id"],
        checkpoint_document["context"]["host_id"],
    )
    maximum_signature_bytes = limits[-1]
    checkpoint, _manifest, _ack = _validate_ack_bundle_documents(
        checkpoint_raw, manifest_raw, ack_raw, signature_raw,
        maximum_signature_bytes,
    )
    _require(checkpoint["context"]["resource_budget_pin"] ==
             _pin(budget_pin, "host evidence budget pin"),
             "checkpoint signer quota is not bound to the exact host budget")
    max_ack_bundle = limits[-2]
    members = [
        ("checkpoint.json", checkpoint_raw),
        ("object-manifest.json", manifest_raw),
        ("ack.json", ack_raw), ("ack.sig", signature_raw),
    ]
    _require(all(len(name) <= 100 for name, _raw in members) and
             max(len(raw) for _name, raw in members[:3]) <= MAX_JSON_BYTES and
             len(signature_raw) <= maximum_signature_bytes,
             "ACK bundle member exceeds its fixed metadata/signature ceiling")
    bundle_size = _tar_size([(name, len(raw)) for name, raw in members])
    _require(bundle_size <= max_ack_bundle,
             "complete ACK bundle exceeds the pinned catalogue byte ceiling")
    output = Path(_path(os.fspath(output_path), "ACK bundle output path"))
    parent_fd = _open_abs_dir(str(output.parent), "ACK bundle output parent",
                              private_final=True)
    try:
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            position = 0
            for name, raw in members:
                header = _tar_header(name, len(raw), typeflag=b"0")
                _write_all(fd, header)
                _write_all(fd, raw)
                padding = (-len(raw)) % TAR_BLOCK_BYTES
                if padding:
                    _write_all(fd, b"\x00" * padding)
                position += TAR_BLOCK_BYTES + len(raw) + padding
            _write_all(fd, b"\x00" * 1024)
            position += 1024
            trailer_padding = bundle_size - position
            _require(0 <= trailer_padding < TAR_RECORD_BYTES,
                     "ACK bundle trailer differs from its bounded record size")
            if trailer_padding:
                _write_all(fd, b"\x00" * trailer_padding)
                position += trailer_padding
            _require(position == bundle_size,
                     "ACK bundle writer size differs from its preflight bound")
            os.fsync(fd)
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                     info.st_size == bundle_size,
                     "ACK bundle writer did not produce its exact private file")
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        raw_sha, reopened_info = _hash_absolute_regular(
            output, max_ack_bundle, "completed ACK bundle",
        )
        _require(reopened_info.st_size == bundle_size,
                 "ACK bundle failed independent reopen size check")
        return {
            "path": str(output), "raw_sha256": raw_sha,
            "byte_count": bundle_size,
        }
    finally:
        os.close(parent_fd)


def read_ack_bundle(
    bundle_path: str | os.PathLike[str], budget_raw: bytes,
    budget_pin: object, offer_raw: bytes, offer_pin: object,
    bundle_pin: object, signer_context_raw: bytes,
    signer_context_pin: object, execution_manifest_raw: bytes,
    execution_manifest_pin: object,
) -> dict[str, Any]:
    """Read the exact four regular ACK members without extracting tar paths."""
    offer, _offer_pin, limits = validate_transfer_offer(
        offer_raw, offer_pin, budget_raw, budget_pin,
    )
    maximum_signature_bytes = limits[-1]
    budget = _exact(_parse_canonical(budget_raw, "host evidence budget"),
                    HOST_BUDGET_FIELDS, "host evidence budget v2")
    receiver = offer["acknowledgement_receiver"]
    path = Path(_path(os.fspath(bundle_path), "ACK bundle receiver path"))
    _require(str(path) == receiver["path"],
             "ACK bundle is not at its exact offered receiver path")
    expected_bundle = _exact(bundle_pin, {
        "path", "raw_sha256", "byte_count",
    }, "ACK bundle pin")
    _require(expected_bundle["path"] == receiver["path"],
             "ACK bundle pin path differs from offer")
    raw_sha = _digest(expected_bundle["raw_sha256"], "ACK bundle raw digest")
    bundle_size = _uint(expected_bundle["byte_count"],
                        "ACK bundle byte count", positive=True)
    _require(bundle_size <= receiver["maximum_bytes"] and
             bundle_size <= limits[-2],
             "ACK bundle exceeds the exact offered/catalogued byte cap")
    fd, info = _packet_file(path, receiver["maximum_bytes"])
    try:
        actual_sha = _hash_packet_fd(fd, info)
        _require(actual_sha == raw_sha and info.st_size == bundle_size,
                 "ACK bundle raw bytes differ from their transfer pin")
        names = ["checkpoint.json", "object-manifest.json", "ack.json", "ack.sig"]
        docs = []
        offset = 0
        for index, name in enumerate(names):
            header = _read_tar_header(fd, offset, info.st_size)
            maximum = (maximum_signature_bytes if name == "ack.sig"
                       else MAX_JSON_BYTES)
            _require(header is not None and header["name"] == name and
                     header["typeflag"] == b"0" and header["mode"] == 0o600 and
                     header["uid"] == 0 and header["gid"] == 0 and
                     header["mtime"] == 0 and header["linkname"] == b"" and
                     header["size"] <= maximum,
                     "ACK bundle member names/types/sizes are not the exact four-file set")
            data_offset = offset + TAR_BLOCK_BYTES
            raw = _read_tar_bytes(fd, data_offset, header["size"], maximum,
                                  f"ACK bundle {name}")
            digest = _sha(raw)
            docs.append(raw)
            offset = _require_zero_padding(fd, data_offset, header["size"],
                                           f"ACK bundle {name}")
        _require(_read_tar_header(fd, offset, info.st_size) is None,
                 "ACK bundle contains an extra member")
        offset += TAR_BLOCK_BYTES
        _require(os.pread(fd, TAR_BLOCK_BYTES, offset) ==
                 b"\x00" * TAR_BLOCK_BYTES,
                 "ACK bundle lacks its full tar end marker")
        offset += TAR_BLOCK_BYTES
        _require(offset <= info.st_size and
                 info.st_size - offset < TAR_RECORD_BYTES and
                 _read_tar_bytes(fd, offset, info.st_size - offset,
                                 TAR_RECORD_BYTES,
                                 "ACK bundle trailer") ==
                     b"\x00" * (info.st_size - offset) and
                 _tar_size(zip(names, [len(raw) for raw in docs], strict=True)) ==
                     info.st_size,
                 "ACK bundle size/trailer differs from its exact four-file closure")
        checkpoint, manifest, ack = _validate_ack_bundle_documents(
            docs[0], docs[1], docs[2], docs[3], maximum_signature_bytes,
        )
        context = checkpoint["context"]
        _validate_budget_context(budget, context)
        signer_context = _validate_archive_signer_context(
            signer_context_raw, signer_context_pin, context,
            maximum_signature_bytes, execution_manifest_pin,
            execution_manifest_raw,
        )
        _require(ack["signer_fingerprint"] ==
                 signer_context["authorized_primary_fingerprint"] and
                 len(docs[3]) <= signer_context["maximum_signature_bytes"],
                 "ACK signer differs from the host-pinned signer context")
        _require(checkpoint["request_pin"] ==
                 offer["checkpoint_request_pin"],
                 "returned final checkpoint differs from the offered request pin")
        _require(checkpoint["context"]["resource_budget_pin"] ==
                 _pin(budget_pin, "host evidence budget pin"),
                 "returned checkpoint differs from the pinned host budget")
        _require(_info_key(info) == _info_key(os.fstat(fd)) and
                 _hash_packet_fd(fd, info) == actual_sha,
                 "ACK bundle changed while its exact members were read")
        source5_root = Path(_path(
            ack["durable_commit"]["archive_source5_directory"]["path"],
            "signed private Source5 root",
        ))
        context = checkpoint["context"]
        _require(source5_root.name == "source5" and
                 source5_root.parent.name == context["host_id"] and
                 source5_root.parent.parent.name == context["campaign_id"],
                 "signed ACK archive root is outside its original campaign/host")
        phase = _token(manifest["phase"], "ACK bundle original phase")
        leaf = (f"{manifest['job_ordinal']:06d}-"
                f"{manifest['job_sha256']}.json")
        ack_path = source5_root / "acks" / phase / leaf
        signature_path = source5_root / "acks" / "signatures" / phase / f"{leaf[:-5]}.sig"
        checkpoint_pin = ack["checkpoint_pin"]
        manifest_pin = ack["object_manifest_pin"]
        ack_pin = {
            "path": str(ack_path), "raw_sha256": _sha(docs[2]),
            "semantic_sha256": ack["ack_sha256"],
        }
        signature_pin = {
            "path": str(signature_path), "raw_sha256": _sha(docs[3]),
            "signer_fingerprint": ack["signer_fingerprint"],
        }
        return {
            "checkpoint": checkpoint, "checkpoint_raw": docs[0],
            "checkpoint_pin": checkpoint_pin,
            "manifest": manifest, "manifest_raw": docs[1],
            "manifest_pin": manifest_pin,
            "ack": ack, "ack_raw": docs[2], "signature_raw": docs[3],
            "ack_pin": ack_pin, "signature_pin": signature_pin,
            "signer_context": signer_context,
            "signer_context_pin": _pin(
                signer_context_pin, "host signer-context pin",
            ),
            "bundle_pin": expected_bundle,
        }
    finally:
        os.close(fd)


def _rename_noreplace(parent_fd: int, source_name: str,
                      destination_name: str) -> None:
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    _require(function is not None,
             "atomic no-replace ACK publication is unavailable on this host")
    function.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    result = function(
        parent_fd, os.fsencode(source_name), parent_fd,
        os.fsencode(destination_name), RENAME_NOREPLACE,
    )
    if result != 0:
        code = ctypes.get_errno()
        raise TransferPacketError(
            f"atomic ACK no-replace publication failed: {os.strerror(code)}",
        )


def publish_ack_bundle(
    incoming_path: str | os.PathLike[str], budget_raw: bytes,
    budget_pin: object, offer_raw: bytes, offer_pin: object,
    bundle_pin: object,
) -> dict[str, Any]:
    """Publish completed SFTP bytes from the offered .incoming name atomically.

    This operation takes no phase lock: its waiting controller already owns
    that lock and observes only the immutable final receiver path.
    """
    offer, checked_offer_pin, limits = validate_transfer_offer(
        offer_raw, offer_pin, budget_raw, budget_pin,
    )
    receiver = offer["acknowledgement_receiver"]
    final_path = _path(receiver["path"], "offered final ACK receiver")
    incoming = _path(os.fspath(incoming_path), "uploaded incoming ACK path")
    _require(incoming == final_path + ".incoming",
             "SFTP upload is not at the exact offered same-directory .incoming path")
    expected = _exact(bundle_pin, {
        "path", "raw_sha256", "byte_count",
    }, "uploaded ACK bundle pin")
    _require(_path(expected["path"], "ACK bundle final pin path") == final_path,
             "uploaded ACK bundle pin does not name the offered final path")
    raw_sha = _digest(expected["raw_sha256"], "uploaded ACK bundle raw digest")
    byte_count = _uint(expected["byte_count"],
                       "uploaded ACK bundle byte count", positive=True)
    maximum = min(receiver["maximum_bytes"], limits[-2])
    _require(byte_count <= maximum,
             "uploaded ACK bundle exceeds the pinned campaign byte cap")
    final = Path(final_path)
    source = Path(incoming)
    _require(source.parent == final.parent,
             "ACK .incoming file and final receiver are not same-directory")
    parent_fd = _open_abs_dir(str(final.parent), "ACK receiver parent",
                              private_final=True)
    try:
        source_info = os.stat(source.name, dir_fd=parent_fd,
                              follow_symlinks=False)
        _require(stat.S_ISREG(source_info.st_mode) and
                 source_info.st_uid == os.getuid() and
                 stat.S_IMODE(source_info.st_mode) == 0o600 and
                 source_info.st_nlink == 1 and
                 source_info.st_size == byte_count,
                 "uploaded ACK .incoming path is not its exact private regular file")
        source_fd = os.open(
            source.name, os.O_RDWR | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            dir_fd=parent_fd,
        )
        try:
            before = os.fstat(source_fd)
            _require(_info_key(before) == _info_key(source_info),
                     "uploaded ACK .incoming changed identity before hashing")
            actual_sha = _hash_packet_fd(source_fd, before)
            _require(actual_sha == raw_sha and before.st_size == byte_count,
                     "uploaded ACK .incoming bytes differ from the coordinator pin")
            os.fsync(source_fd)
            _require(_info_key(before) == _info_key(os.fstat(source_fd)) and
                     _info_key(before) == _info_key(os.stat(
                         source.name, dir_fd=parent_fd,
                         follow_symlinks=False,
                     )),
                     "uploaded ACK .incoming changed during its durable hash")
            try:
                os.stat(final.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise TransferPacketError(
                    "offered final ACK receiver already exists; refusing replacement",
                )
            _rename_noreplace(parent_fd, source.name, final.name)
            os.fsync(parent_fd)
            published = os.stat(final.name, dir_fd=parent_fd,
                                follow_symlinks=False)
            _require(_rename_identity(published) == _rename_identity(before),
                     "published ACK changed identity during atomic rename")
        finally:
            os.close(source_fd)
        final_fd, final_info = _packet_file(final, maximum)
        try:
            _require(_info_key(final_info) == _info_key(published) and
                     _hash_packet_fd(final_fd, final_info) == raw_sha and
                     final_info.st_size == byte_count,
                     "published final ACK failed independent reopen verification")
        finally:
            os.close(final_fd)
        return {
            "path": final_path, "raw_sha256": raw_sha,
            "byte_count": byte_count,
        }
    finally:
        os.close(parent_fd)


def _write_stage_file(
    root_fd: int, relative: str, packet_fd: int, source_offset: int,
    expected_size: int, expected_sha: str,
) -> str:
    parent_fd, name = _parent_at(root_fd, relative, create=True,
                                 label="packet stage object")
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            hasher = hashlib.sha256()
            total = 0
            while total < expected_size:
                block = os.pread(
                    packet_fd, min(BLOCK_BYTES, expected_size - total),
                    source_offset + total,
                )
                _require(bool(block), "packet object shortened during extraction")
                total += len(block)
                hasher.update(block)
                _write_all(fd, block)
            _require(total == expected_size and
                     hasher.hexdigest() == expected_sha,
                     "extracted object changed after the full packet pass")
            os.fsync(fd)
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode) and
                     info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o600 and
                     info.st_nlink == 1 and info.st_size == expected_size,
                     "extracted object is not an owned private regular file")
        finally:
            os.close(fd)
        os.fsync(parent_fd)
        check_fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                           _O_NONBLOCK, dir_fd=parent_fd)
        try:
            _raw, digest, _info = _read_fd(
                check_fd, expected_size, expected_size,
                "reopened extracted object", collect=False,
            )
            _require(_raw is None and digest == expected_sha,
                     "extracted object failed independent reopen hashing")
        finally:
            os.close(check_fd)
        return relative
    finally:
        os.close(parent_fd)


def import_transfer_packet(
    packet_path: str | os.PathLike[str], budget_raw: bytes,
    budget_pin: object, offer_raw: bytes, offer_pin: object,
    staging_root: str | os.PathLike[str],
    catalogue_chunk_paths: dict[str, str], catalogue_cache_root: str,
) -> dict[str, Any]:
    """Verify the complete no-link packet before writing its first stage file."""
    offer, checked_offer_pin, offer_limits = validate_transfer_offer(
        offer_raw, offer_pin, budget_raw, budget_pin,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
    )
    expected = _pin(offer["checkpoint_request_pin"],
                    "offered request pin")
    packet_pin = offer["transfer_packet_pin"]
    budget = _parse_canonical(budget_raw, "host evidence budget")
    budget_pin_checked = _pin(budget_pin, "host budget pin")
    _require(_sha(budget_raw) == budget_pin_checked["raw_sha256"],
             "host budget differs from its raw pin")
    budget_context = _exact(budget, HOST_BUDGET_FIELDS,
                             "host evidence budget")
    _require(budget_context["schema"] == HOST_BUDGET_SCHEMA,
             "host budget schema differs")
    limits = offer_limits
    (max_packet, max_inodes, max_window_bytes, max_window_inodes,
     _roots, _scratch, max_ack_bundle_bytes, max_signature_bytes) = limits
    packet_probe = Path(_path(os.fspath(packet_path), "packet path"))
    packet_fd, packet_info = _packet_file(packet_probe, max_packet)
    try:
        packet_sha = _hash_packet_fd(packet_fd, packet_info)
        _require(packet_sha == packet_pin["raw_sha256"] and
                 packet_info.st_size == packet_pin["byte_count"],
                 "transferred packet differs from its exact offer pin")
        request, request_raw, job_record_location, locations = _scan_packet(
            packet_fd, packet_info, expected, budget,
            catalogue_chunk_paths, catalogue_cache_root,
        )
        context = request["context"]
        _validate_budget_context(budget_context, context)
        _require(context["campaign_id"] == budget_context["campaign_id"] and
                 context["host_id"] == budget_context["host_id"] and
                 _pin(context["resource_budget_pin"], "request host budget") ==
                     budget_pin_checked,
                 "packet request is not bound to the exact host budget")
        (request_row, packet_row, _offer_row, receiver_row,
         incoming_row) = _offer_catalogue_rows(
            request, budget, expected["path"], packet_pin["path"],
            checked_offer_pin["path"],
            offer["acknowledgement_receiver"]["path"],
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
        )
        job_record_row = _job_record_catalogue_row(
            request, budget, catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
        )
        _require(len(request_raw) <= request_row["max_file_bytes"] and
                 job_record_location["byte_count"] <=
                     job_record_row["max_file_bytes"] and
                 packet_info.st_size <= packet_row["max_file_bytes"] and
                 offer["acknowledgement_receiver"]["maximum_bytes"] ==
                     receiver_row["max_file_bytes"] and
                 incoming_row["max_file_bytes"] == receiver_row["max_file_bytes"],
                 "packet request/response differs from exact catalogue file ceilings")
        rows = request["entries"]
        payload = sum(row["byte_count"] for row in rows)
        _require(payload <= max_window_bytes and
                 len(rows) <= max_window_inodes and max_inodes == 1 and
                 packet_info.st_size <= max_packet,
                 "transfer packet exceeds its pinned byte/inode budget")
        _require(_info_key(packet_info) == _info_key(os.fstat(packet_fd)) and
                 _hash_packet_fd(packet_fd, packet_info) == packet_sha,
                 "transfer packet changed while its complete closure was verified")

        stage = Path(_path(os.fspath(staging_root), "private staging root"))
        stage_fd = _open_abs_dir(str(stage), "private packet stage root",
                                 private_final=True)
        try:
            _require(not os.listdir(stage_fd),
                     "packet stage root must start empty")
            request_fd = os.open(
                "checkpoint-request.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=stage_fd,
            )
            try:
                _write_all(request_fd, request_raw)
                os.fsync(request_fd)
            finally:
                os.close(request_fd)
            os.fsync(stage_fd)
            reopened_fd = os.open(
                "checkpoint-request.json", os.O_RDONLY | _O_CLOEXEC |
                _O_NOFOLLOW | _O_NONBLOCK, dir_fd=stage_fd,
            )
            try:
                reopened, digest, _ = _read_fd(
                    reopened_fd, len(request_raw), MAX_JSON_BYTES,
                    "staged checkpoint request", collect=True,
                )
                _require(reopened == request_raw and digest == _sha(request_raw),
                         "staged checkpoint request failed independent reopen")
            finally:
                os.close(reopened_fd)
            _write_stage_file(
                stage_fd, "validation/job-record.json", packet_fd,
                job_record_location["offset"],
                job_record_location["byte_count"],
                job_record_location["raw_sha256"],
            )
            staged_files = {}
            for location in locations:
                relative = f"objects/{location['object_id']}"
                _write_stage_file(
                    stage_fd, relative, packet_fd, location["offset"],
                    location["byte_count"], location["raw_sha256"],
                )
                staged_files[location["origin_path"]] = str(stage / relative)
            _require(_info_key(packet_info) == _info_key(os.fstat(packet_fd)) and
                     _hash_packet_fd(packet_fd, packet_info) == packet_sha,
                     "packet changed during stage extraction")
            return {
                "request": request, "request_raw": request_raw,
                "request_pin": expected,
                "offer": offer, "offer_pin": checked_offer_pin,
                "acknowledgement_receiver":
                    offer["acknowledgement_receiver"],
                "request_path": str(stage / "checkpoint-request.json"),
                "job_record_path": str(stage / "validation" / "job-record.json"),
                "job_record_raw_sha256": job_record_location["raw_sha256"],
                "job_record_byte_count": job_record_location["byte_count"],
                "staging_root": str(stage), "staged_files": staged_files,
                "packet_byte_count": packet_info.st_size,
                "packet_raw_sha256": packet_sha,
                "object_count": len(rows), "payload_bytes": payload,
            }
        finally:
            os.close(stage_fd)
    finally:
        os.close(packet_fd)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export/import one bounded Source5 checkpoint-request packet.",
    )
    sub = parser.add_subparsers(dest="operation", required=True)
    export_parser = sub.add_parser("export-transfer")
    export_parser.add_argument("--request", required=True)
    export_parser.add_argument("--budget", required=True)
    export_parser.add_argument("--request-origin", required=True)
    export_parser.add_argument("--packet", required=True)
    export_parser.add_argument("--offer", required=True)
    export_parser.add_argument("--acknowledgement-receiver", required=True)
    import_parser = sub.add_parser("import-transfer")
    import_parser.add_argument("--packet", required=True)
    import_parser.add_argument("--budget", required=True)
    import_parser.add_argument("--budget-pin", required=True)
    import_parser.add_argument("--offer", required=True)
    import_parser.add_argument("--offer-pin", required=True)
    import_parser.add_argument("--staging-root", required=True)
    import_parser.add_argument("--catalogue-chunk-map", required=True)
    import_parser.add_argument("--catalogue-cache-root", required=True)
    ack_parser = sub.add_parser("build-ack-bundle")
    ack_parser.add_argument("--checkpoint", required=True)
    ack_parser.add_argument("--object-manifest", required=True)
    ack_parser.add_argument("--ack", required=True)
    ack_parser.add_argument("--signature", required=True)
    ack_parser.add_argument("--budget", required=True)
    ack_parser.add_argument("--output", required=True)
    publish_parser = sub.add_parser("publish-ack")
    publish_parser.add_argument("--incoming", required=True)
    publish_parser.add_argument("--budget", required=True)
    publish_parser.add_argument("--budget-pin", required=True)
    publish_parser.add_argument("--offer", required=True)
    publish_parser.add_argument("--offer-pin", required=True)
    publish_parser.add_argument("--bundle-pin", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "build-ack-bundle":
            checkpoint_raw, _checkpoint_sha, _ = _read_regular_absolute(
                args.checkpoint, MAX_JSON_BYTES, "final checkpoint",
            )
            checkpoint = _parse_canonical(checkpoint_raw, "final checkpoint")
            manifest_raw, _manifest_sha, _ = _read_regular_absolute(
                args.object_manifest, MAX_JSON_BYTES, "object manifest",
            )
            ack_raw, _ack_sha, _ = _read_regular_absolute(
                args.ack, MAX_JSON_BYTES, "durable ACK",
            )
            signature_raw, _signature_sha, _ = _read_regular_absolute(
                args.signature, MAX_GPG_OUTPUT_BYTES, "ACK signature",
            )
            budget_raw, _budget_sha, _ = _read_regular_absolute(
                args.budget, MAX_JSON_BYTES, "host evidence budget",
            )
            bundle_pin = build_ack_bundle(
                checkpoint_raw, manifest_raw, ack_raw, signature_raw,
                budget_raw, checkpoint["context"]["resource_budget_pin"],
                args.output,
            )
            sys.stdout.buffer.write(_canonical({
                "schema": "allocatbelt.application-source5-archive-ack-bundle-pin.v1",
                **bundle_pin,
            }))
            return 0
        if args.operation == "export-transfer":
            request_raw, request_sha, _ = _read_regular_absolute(
                args.request, MAX_JSON_BYTES, "host checkpoint request",
            )
            request = _validate_request(_parse_canonical(
                request_raw, "host checkpoint request",
            ))
            request_pin = {
                "path": _path(args.request_origin, "request origin path"),
                "raw_sha256": request_sha,
                "semantic_sha256": request["request_sha256"],
            }
            budget_raw, _budget_sha, _ = _read_regular_absolute(
                args.budget, MAX_JSON_BYTES, "host evidence budget",
            )
            result = export_transfer_packet(
                request_raw, request_pin, args.budget, args.packet,
                args.offer, args.acknowledgement_receiver,
            )
            budget_raw, _budget_sha, _ = _read_regular_absolute(
                args.budget, MAX_JSON_BYTES, "host evidence budget",
            )
            offer, offer_pin = publish_transfer_offer(
                request_raw, request_pin, result, budget_raw,
                request["context"]["resource_budget_pin"], args.offer,
                args.acknowledgement_receiver,
            )
            sys.stdout.buffer.write(_canonical({
                **result, "offer": offer, "offer_pin": offer_pin,
            }))
            return 0
        if args.operation == "publish-ack":
            offer_raw, _offer_sha, _ = _read_regular_absolute(
                args.offer, MAX_JSON_BYTES, "archive transfer offer",
            )
            offer_pin_raw, _offer_pin_sha, _ = _read_regular_absolute(
                args.offer_pin, MAX_JSON_BYTES, "archive transfer offer pin",
            )
            offer_pin = _pin(
                _parse_canonical(offer_pin_raw, "archive transfer offer pin"),
                "external archive transfer offer pin",
            )
            budget_raw, _budget_sha, _ = _read_regular_absolute(
                args.budget, MAX_JSON_BYTES, "host evidence budget",
            )
            budget_pin_raw, _budget_pin_sha, _ = _read_regular_absolute(
                args.budget_pin, MAX_JSON_BYTES, "host evidence budget pin",
            )
            budget_pin = _pin(
                _parse_canonical(budget_pin_raw, "host evidence budget pin"),
                "external host evidence budget pin",
            )
            bundle_pin_raw, _bundle_pin_sha, _ = _read_regular_absolute(
                args.bundle_pin, MAX_JSON_BYTES, "coordinator ACK bundle pin",
            )
            bundle_pin_value = _parse_canonical(
                bundle_pin_raw, "coordinator ACK bundle pin",
            )
            bundle_pin = _exact(bundle_pin_value, {
                "path", "raw_sha256", "byte_count",
            }, "coordinator ACK bundle pin")
            result = publish_ack_bundle(
                args.incoming, budget_raw, budget_pin,
                offer_raw, offer_pin, bundle_pin,
            )
            sys.stdout.buffer.write(_canonical({
                "schema": "allocatbelt.application-source5-archive-ack-bundle-pin.v1",
                **result,
            }))
            return 0
        offer_raw, _offer_sha, _ = _read_regular_absolute(
            args.offer, MAX_JSON_BYTES, "archive transfer offer",
        )
        offer_pin_raw, _offer_pin_sha, _ = _read_regular_absolute(
            args.offer_pin, MAX_JSON_BYTES, "archive transfer offer pin file",
        )
        offer_pin = _parse_canonical(
            offer_pin_raw, "archive transfer offer pin file",
        )
        _pin(offer_pin, "external archive transfer offer pin")
        budget_raw, _budget_sha, _ = _read_regular_absolute(
            args.budget, MAX_JSON_BYTES, "host evidence budget",
        )
        budget_pin_raw, _pin_raw_sha, _ = _read_regular_absolute(
            args.budget_pin, MAX_JSON_BYTES, "host evidence budget pin file",
        )
        budget_pin = _parse_canonical(
            budget_pin_raw, "host evidence budget pin file",
        )
        _pin(budget_pin, "external host evidence budget pin")
        budget_doc = _exact(_parse_canonical(budget_raw,
                                              "host evidence budget"),
                            HOST_BUDGET_FIELDS, "host evidence budget v2")
        catalogue_map_raw, _catalogue_map_sha, _ = _read_regular_absolute(
            args.catalogue_chunk_map, MAX_JSON_BYTES,
            "Root-local catalogue chunk map",
        )
        catalogue_chunk_paths = _parse_catalogue_local_map(
            catalogue_map_raw, budget_doc["campaign_id"],
            budget_doc["host_id"], budget_pin,
        )
        result = import_transfer_packet(
            args.packet, budget_raw, budget_pin, offer_raw, offer_pin,
            args.staging_root, catalogue_chunk_paths,
            _path(args.catalogue_cache_root, "Root-local catalogue cache root"),
        )
        summary = {
            "schema": PACKET_PIN_SCHEMA,
            "offer_pin": result["offer_pin"],
            "acknowledgement_receiver":
                result["acknowledgement_receiver"],
            "packet_path": _path(args.packet, "transfer packet path"),
            "packet_raw_sha256": result["packet_raw_sha256"],
            "request_pin": result["request_pin"],
            "staging_root": result["staging_root"],
            "request_path": result["request_path"],
            "job_record_path": result["job_record_path"],
            "job_record_raw_sha256": result["job_record_raw_sha256"],
            "job_record_byte_count": result["job_record_byte_count"],
            "staged_files": result["staged_files"],
            "packet_byte_count": result["packet_byte_count"],
            "object_count": result["object_count"],
            "payload_bytes": result["payload_bytes"],
        }
        sys.stdout.buffer.write(_canonical(summary))
        return 0
    except (TransferPacketError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Source5 transfer packet failed: {type(error).__name__}: {error}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
