#!/usr/bin/env python3
"""Replay Source5 component evidence from one closed, captured host journal.

This adapter deliberately separates the chronology module's byte-only replay
from the existing component readers.  The adapter binds every component path
to an exact role-indexed byte entry, checks local bytes before and after each
reader, and returns component-only results with campaign eligibility false.
It does not launch programs or infer success from a journal claim.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "allocatbelt.application-source5-offline-dispatch.v1"
REQUEST_SCHEMA = "allocatbelt.application-source5-offline-job-request.v1"
CONTEXT_SCHEMA = "allocatbelt.application-source5-pressure-journal-context.v1"
RESULT_SCHEMA = "allocatbelt.application-source5-offline-job-result.v1"
CAPTURED_SCHEMA = "allocatbelt.application-source5-captured-evidence.v1"
INDEX_SCHEMA = "allocatbelt.application-source5-journal-evidence-index.v1"
MAX_PATH_BYTES = 4096
MAX_INDEX_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 256 * 1024 * 1024
MAX_CAPTURE_BYTES = 1024 * 1024 * 1024
MAX_ENTRIES = 800_000
MAX_MAP_ENTRIES = 16_384
MAX_SOURCE_FILE_COUNT = 100_000
MAX_SOURCE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SOURCE_SYMLINK_BYTES = 4 * 1024
SOURCE5_JOB_SCHEMA = "allocatbelt.application-source5-job-record.v1"
FIXED_HOST_SCHEMA = "allocatbelt.application-fixed-pair-host-verification.v1"
PRESSURE_HOST_SCHEMA = "allocatbelt.application-pressure-pair-host-verification.v1"
SOAK_HOST_SCHEMA = "allocatbelt.application-source5-soak-host-verification.v2"

ROLE_LIMITS = {
    "evidence_index": MAX_INDEX_BYTES,
    "origin_receipt": 16 * 1024 * 1024,
    "journal": MAX_CAPTURE_BYTES,
    "execution_manifest": MAX_JSON_BYTES,
    "preparation": 16 * 1024 * 1024,
    "prepared_completion": 16 * 1024 * 1024,
    "spec_v3": 32 * 1024 * 1024,
    "plan_v3": MAX_JSON_BYTES,
    "source_manifest": 16 * 1024 * 1024,
    "observed_host": 16 * 1024 * 1024,
    "typed_source_file": MAX_SOURCE_BYTES,
    "typed_source_symlink": MAX_SOURCE_SYMLINK_BYTES,
    "capacity_completion": 16 * 1024 * 1024,
    "capacity_ledger": 256 * 1024 * 1024,
    "source5_helper_input": MAX_JSON_BYTES,
    "source5_job_record": 4 * 1024 * 1024,
    "capacity_host_receipt": 16 * 1024 * 1024,
    "component_receipt": MAX_JSON_BYTES,
    "fixed_pair_artifact": MAX_CAPTURE_BYTES,
    "pressure_pair_artifact": MAX_CAPTURE_BYTES,
    "source5_soak_artifact": MAX_CAPTURE_BYTES,
    "normal_app_output": MAX_CAPTURE_BYTES,
    "analysis_artifact": 4 * 1024 * 1024,
    "opaque_trace": MAX_CAPTURE_BYTES,
    # Added by the ProbeV2 evidence-index contract; these raw-only roles are
    # separate from capacity-stage completion/host-verification receipts.
    "capacity_request": MAX_JSON_BYTES,
    "capacity_artifact": MAX_JSON_BYTES,
    "capacity_receipt": MAX_JSON_BYTES,
}

COMPONENT_ROLES = frozenset({
    "fixed_pair_artifact", "pressure_pair_artifact", "source5_soak_artifact",
    "normal_app_output", "opaque_trace", "component_receipt",
    "source5_helper_input", "source5_job_record", "analysis_artifact",
    "capacity_completion", "capacity_ledger", "capacity_host_receipt",
    "capacity_request", "capacity_artifact", "capacity_receipt",
})


class Source5OfflineDispatchError(ValueError):
    """A captured role, original job, component replay, or ancestry is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Source5OfflineDispatchError(message)


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys,
             f"{label} has an unexpected field set")
    return value


def _sha(value: object, label: str) -> str:
    _require(type(value) is str and len(value) == 64 and
             all(char in "0123456789abcdef" for char in value),
             f"{label} is not a lowercase SHA-256")
    return value


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise Source5OfflineDispatchError(
            f"value cannot be represented as canonical JSON: {error}",
        ) from error
    return (encoded + "\n").encode("ascii")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _absolute(value: object, label: str) -> str:
    _require(type(value) is str and 0 < len(value) <= MAX_PATH_BYTES and
             Path(value).is_absolute() and "\x00" not in value and
             ".." not in Path(value).parts and
             str(Path(value)) == os.path.normpath(value),
             f"{label} is not a normalized absolute path")
    return value


def _entry_chunks(value: object, count: int, label: str) -> Iterable[bytes]:
    _require(type(count) is int and 0 <= count <= MAX_CAPTURE_BYTES,
             f"{label} byte count is outside its finite bound")
    if type(value) is bytes:
        _require(len(value) == count,
                 f"{label} byte length differs from its pinned count")
        for offset in range(0, count, 1024 * 1024):
            yield value[offset:offset + 1024 * 1024]
        return
    _require(type(value) is io.BufferedReader and type(value.raw) is io.FileIO and
             value.readable() and not value.writable() and value.seekable() and
             value.raw.mode == "rb",
             f"{label} is not immutable bytes or a read-only seekable stream")
    try:
        value.seek(0)
        _require(value.tell() == 0, f"{label} stream did not rewind to byte zero")
        remaining = count
        while remaining:
            block = value.read(min(1024 * 1024, remaining))
            _require(type(block) is bytes and bool(block),
                     f"{label} stream ended before its pinned byte count")
            remaining -= len(block)
            yield block
        _require(value.read(1) == b"", f"{label} stream has trailing bytes")
    except (OSError, ValueError) as error:
        raise Source5OfflineDispatchError(
            f"cannot read captured {label}: {error}",
        ) from error


def _hash_entry(row: dict[str, Any]) -> str:
    hasher = hashlib.sha256()
    total = 0
    for block in _entry_chunks(row["raw_bytes"], row["byte_count"],
                              f"captured {row['role']} {row['origin_path']}"):
        total += len(block)
        _require(total <= ROLE_LIMITS[row["role"]],
                 f"captured {row['role']} exceeds its byte ceiling")
        hasher.update(block)
    actual = hasher.hexdigest()
    _require(total == row["byte_count"] and actual == row["raw_sha256"],
             f"captured {row['role']} bytes differ from their raw pin")
    return actual


def _entry_bytes(row: dict[str, Any], maximum: int, label: str) -> bytes:
    _require(row["byte_count"] <= maximum and
             row["byte_count"] <= ROLE_LIMITS[row["role"]],
             f"{label} exceeds its declared role or parser ceiling")
    parts: list[bytes] = []
    hasher = hashlib.sha256()
    count = 0
    for block in _entry_chunks(row["raw_bytes"], row["byte_count"], label):
        count += len(block)
        _require(count <= maximum, f"{label} exceeds its finite parser ceiling")
        parts.append(block)
        hasher.update(block)
    raw = b"".join(parts)
    _require(count == row["byte_count"] and
             hasher.hexdigest() == row["raw_sha256"],
             f"{label} differs from its exact captured raw pin")
    return raw


def _store_rows(captured: object) -> dict[str, dict[str, Any]]:
    store = _exact(captured, {"schema", "entries"},
                   "Source5 captured evidence store")
    _require(store["schema"] == CAPTURED_SCHEMA and
             type(store["entries"]) is list and
             len(store["entries"]) <= MAX_ENTRIES,
             "Source5 captured evidence schema/count is invalid")
    rows: dict[str, dict[str, Any]] = {}
    prior = ""
    for index, value in enumerate(store["entries"]):
        row = _exact(value, {
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count", "raw_bytes",
        }, f"captured Source5 entry[{index}]")
        path = _absolute(row["origin_path"],
                         f"captured origin path[{index}]")
        local = _absolute(row["local_path"],
                           f"captured local path[{index}]")
        _require(path == local and path > prior and path not in rows,
                 "captured Source5 paths are not sorted unique identity mappings")
        prior = path
        _require(row["role"] in ROLE_LIMITS,
                 f"captured Source5 entry[{index}] has an unknown role")
        _require(row["host_id"] is None or
                 (type(row["host_id"]) is str and row["host_id"]),
                 f"captured Source5 entry[{index}] host ID is malformed")
        _sha(row["raw_sha256"], f"captured Source5 entry[{index}] raw SHA")
        semantic = row["semantic_sha256"]
        _require(semantic is None or
                 (type(semantic) is str and len(semantic) == 64 and
                  all(char in "0123456789abcdef" for char in semantic)),
                 f"captured Source5 entry[{index}] semantic SHA is malformed")
        _require(type(row["byte_count"]) is int and
                 0 <= row["byte_count"] <= ROLE_LIMITS[row["role"]],
                 f"captured Source5 entry[{index}] exceeds its typed byte ceiling")
        data = row["raw_bytes"]
        _require(type(data) is bytes or
                 (type(data) is io.BufferedReader and
                  type(data.raw) is io.FileIO and data.readable() and
                  not data.writable() and data.seekable() and
                  data.raw.mode == "rb"),
                 f"captured Source5 entry[{index}] is not immutable/read-only")
        rows[path] = row
    _require(bool(rows), "Source5 captured evidence store is empty")
    return rows


def _json_entry(rows: dict[str, dict[str, Any]], path: object,
                label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    path_text = _absolute(path, f"{label} path")
    row = rows.get(path_text)
    _require(row is not None, f"captured evidence omits {label}")
    raw = _entry_bytes(row, maximum, label)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Source5OfflineDispatchError(f"{label} is not bounded UTF-8 JSON") from error
    _require(type(value) is dict and raw == _canonical(value),
             f"{label} is not one canonical JSON object")
    return value, raw


def _source_inventory_records(
    manifest: dict[str, Any], label: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    source = _exact(manifest.get("source"), {
        "git_commit", "source_tree_sha256", "cargo_lock_sha256", "files",
    }, f"{label} source inventory")
    files = source["files"]
    _require(type(files) is list and 0 < len(files) <= MAX_SOURCE_FILE_COUNT,
             f"{label} source inventory is empty or exceeds its file-count bound")
    normalized: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    previous_path = b""
    total = 0
    for position, value in enumerate(files):
        _require(type(value) is dict,
                 f"{label} source inventory entry[{position}] is not an object")
        kind = value.get("kind")
        expected_keys = {"path", "kind", "mode", "sha256", "size"}
        if kind == "symlink":
            expected_keys.add("target")
        record = _exact(value, expected_keys,
                        f"{label} source inventory entry[{position}]")
        relative = PurePosixPath(record["path"])
        _require(type(record["path"]) is str and record["path"] and
                 not relative.is_absolute() and relative.as_posix() == record["path"] and
                 ".." not in relative.parts and "\\" not in record["path"] and
                 "\n" not in record["path"] and "\r" not in record["path"] and
                 "\x00" not in record["path"] and
                 record["path"] not in by_path,
                 f"{label} source inventory path[{position}] is aliased or repeated")
        try:
            encoded_path = record["path"].encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise Source5OfflineDispatchError(
                f"{label} source inventory path[{position}] is not UTF-8",
            ) from error
        _require(encoded_path > previous_path,
                 f"{label} source inventory paths are not UTF-8 byte sorted")
        previous_path = encoded_path
        _sha(record["sha256"], f"{label} source file digest[{position}]")
        _require(type(record["size"]) is int and record["size"] >= 0,
                 f"{label} source inventory size[{position}] is malformed")
        if kind == "file":
            _require(record["mode"] in {"100644", "100755"} and
                     record["size"] <= MAX_SOURCE_BYTES,
                     f"{label} regular source file[{position}] exceeds its mode/size contract")
            normalized_record = {
                "path": record["path"], "kind": "file", "mode": record["mode"],
                "sha256": record["sha256"], "size": record["size"],
            }
        else:
            _require(kind == "symlink" and record["mode"] == "120000" and
                     type(record["target"]) is str,
                     f"{label} source inventory symlink[{position}] is malformed")
            try:
                target_bytes = record["target"].encode("utf-8", "strict")
            except UnicodeEncodeError as error:
                raise Source5OfflineDispatchError(
                    f"{label} source symlink target[{position}] is not UTF-8",
                ) from error
            _require(0 < len(target_bytes) <= MAX_SOURCE_SYMLINK_BYTES and
                     record["size"] == len(target_bytes) and
                     _digest(target_bytes) == record["sha256"] and
                     not record["target"].startswith("/") and
                     "\\" not in record["target"] and "\x00" not in record["target"] and
                     "\n" not in record["target"] and "\r" not in record["target"],
                     f"{label} source symlink target[{position}] hash/size/text differs")
            normalized_record = {
                "path": record["path"], "kind": "symlink", "mode": "120000",
                "target": record["target"], "sha256": record["sha256"],
                "size": record["size"],
            }
        total += record["size"]
        _require(total <= MAX_SOURCE_TOTAL_BYTES,
                 f"{label} source inventory exceeds its total-byte bound")
        by_path[record["path"]] = normalized_record
        normalized.append(normalized_record)

    symlink_paths = {path for path, record in by_path.items()
                     if record["kind"] == "symlink"}
    for path, record in by_path.items():
        parts = path.split("/")
        for position in range(1, len(parts)):
            parent = "/".join(parts[:position])
            _require(parent not in by_path and parent not in symlink_paths,
                     f"{label} source inventory has a non-directory parent: {path}")
        if record["kind"] != "symlink":
            continue
        resolved = path.split("/")[:-1]
        target_parts = record["target"].split("/")
        _require(all(target_parts),
                 f"{label} source symlink target is not normalized: {path}")
        for position, part in enumerate(target_parts):
            if part == ".":
                continue
            if part == "..":
                _require(bool(resolved),
                         f"{label} source symlink escapes its source root: {path}")
                resolved.pop()
            else:
                resolved.append(part)
                if position < len(target_parts) - 1:
                    prefix = "/".join(resolved)
                    _require(prefix not in by_path,
                             f"{label} source symlink traverses a non-directory: {path}")
        target_record = by_path.get("/".join(resolved))
        _require(target_record is not None and target_record["kind"] == "file",
                 f"{label} source symlink does not target an indexed regular file: {path}")

    _sha(source["source_tree_sha256"], f"{label} source-tree digest")
    expected_tree = _digest(_canonical({
        "schema": "allocatbelt.application-source-inventory.v1",
        "entries": normalized,
    }))
    _require(source["source_tree_sha256"] == expected_tree,
             f"{label} source-tree digest differs from its normalized inventory")
    return normalized, by_path


def _source_manifest_artifacts(
    manifest: dict[str, Any], inventory: dict[str, dict[str, Any]], label: str,
) -> list[tuple[str, str, str]]:
    allocators = {"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"}
    declared: dict[str, tuple[str, str]] = {}

    def add(value: object, role: str, item_label: str) -> None:
        item = _exact(value, {"path", "sha256"}, item_label)
        relative = PurePosixPath(item["path"])
        _require(type(item["path"]) is str and not relative.is_absolute() and
                 relative.as_posix() == item["path"] and ".." not in relative.parts and
                 "\\" not in item["path"],
                 f"{item_label} path is not normalized and relative")
        _sha(item["sha256"], f"{item_label} raw SHA-256")
        path = relative.as_posix()
        prior = declared.get(path)
        expected = (role, item["sha256"])
        _require(prior is None or prior == expected,
                 f"{label} declares one path with incompatible artifact roles: {path}")
        declared[path] = expected

    applications = _exact(manifest.get("artifacts"), allocators,
                          f"{label} application artifact map")
    for allocator, value in applications.items():
        add(value, "normal_app_output", f"{label} {allocator} application artifact")
    soak = manifest.get("soak_artifacts")
    _require(type(soak) is dict and "allocatbelt" in soak and
             set(soak).issubset(allocators),
             f"{label} Soak artifact map omits the candidate or names an unknown allocator")
    for allocator, value in soak.items():
        add(value, "source5_soak_artifact", f"{label} {allocator} Soak artifact")
    add(manifest.get("analysis_artifact"), "analysis_artifact",
        f"{label} analyzer artifact")
    calibration = _exact(manifest.get("resource_domain_calibration"), {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, f"{label} resource-domain calibration")
    for name in ("binary", "output"):
        add(calibration[name], "capacity_artifact",
            f"{label} resource-domain calibration {name}")
    runtime = _exact(manifest.get("runtime_readback_validator"), {"path", "sha256"},
                     f"{label} runtime readback validator")
    runtime_path = PurePosixPath(runtime["path"])
    _require(not runtime_path.is_absolute() and runtime_path.as_posix() == runtime["path"] and
             ".." not in runtime_path.parts and "\\" not in runtime["path"],
             f"{label} runtime readback validator path is not normalized")
    _sha(runtime["sha256"], f"{label} runtime validator raw SHA-256")
    runtime_record = inventory.get(runtime_path.as_posix())
    _require(runtime_record is not None and runtime_record["kind"] == "file" and
             runtime_record["sha256"] == runtime["sha256"],
             f"{label} runtime readback validator is not the exact regular source file")
    return [(path, role, raw_sha) for path, (role, raw_sha) in sorted(declared.items())]


def _local_symlink_snapshot(
    row: dict[str, Any], expected_target: bytes | None = None,
) -> tuple[int, ...]:
    path = Path(row["local_path"])
    try:
        before = path.lstat()
        _require(stat.S_ISLNK(before.st_mode),
                 f"typed source symlink was replaced by another node: {path}")
        target = os.readlink(path)
        _require(type(target) is str,
                 f"typed source symlink target is not text: {path}")
        target_bytes = target.encode("utf-8", "strict")
        after = path.lstat()
    except (OSError, UnicodeError) as error:
        raise Source5OfflineDispatchError(
            f"cannot verify literal typed source symlink {path}: {error}",
        ) from error
    captured_target = _entry_bytes(
        row, MAX_SOURCE_SYMLINK_BYTES,
        f"literal typed source symlink {row['origin_path']}",
    )
    _require(target_bytes == captured_target and
             (expected_target is None or target_bytes == expected_target),
             f"typed source symlink target bytes differ: {path}")
    first = (before.st_dev, before.st_ino, before.st_uid, before.st_gid,
             before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    second = (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
              after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    _require(first == second,
             f"typed source symlink changed during literal-target verification: {path}")
    return (*first, int.from_bytes(hashlib.sha256(target_bytes).digest(), "big"))


def _verify_local_source_symlink_snapshots(
    rows: dict[str, dict[str, Any]], snapshots: dict[str, tuple[int, ...]],
) -> None:
    for path, prior in snapshots.items():
        row = rows.get(path)
        _require(row is not None and row["role"] == "typed_source_symlink",
                 f"typed source symlink row disappeared from its captured store: {path}")
        _require(_local_symlink_snapshot(row) == prior,
                 f"typed source symlink changed during component replay: {path}")


def _validate_full_source_index_closure(
    request: dict[str, Any], index_rows: dict[str, dict[str, Any]],
    rows: dict[str, dict[str, Any]], selected_modules: dict[str, Any],
) -> dict[str, tuple[int, ...]]:
    """Close every original Source.files/artifact row before compiling a module."""
    source_manifest_rows = [row for row in index_rows.values()
                            if row["role"] == "source_manifest"]
    _require(len(source_manifest_rows) == 3 and
             len({row["host_id"] for row in source_manifest_rows}) == 3,
             "complete SourceV5 replay requires three unique indexed host manifests")
    manifests: dict[str, dict[str, Any]] = {}
    inventories: dict[str, dict[str, dict[str, Any]]] = {}
    normalized_inventory: list[dict[str, Any]] | None = None
    expected: dict[str, tuple[
        str, str, int | None, bytes | None, str | None,
    ]] = {}

    def expect(
        path: str, role: str, raw_sha: str, byte_count: int | None,
        target_bytes: bytes | None = None, mode: str | None = None,
    ) -> None:
        absolute = _absolute(path, "SourceV5 closed inventory path")
        value = (role, raw_sha, byte_count, target_bytes, mode)
        prior = expected.get(absolute)
        _require(prior is None or prior == value,
                 f"SourceV5 source/artifact paths alias incompatible typed roles: {absolute}")
        expected[absolute] = value

    for source_row in source_manifest_rows:
        source_doc, source_raw = _json_entry(
            rows, source_row["origin_path"],
            "SourceV5 host source manifest before module execution",
            16 * 1024 * 1024,
        )
        semantic = source_doc.get("manifest_sha256")
        _require(type(semantic) is str and len(semantic) == 64 and
                 all(char in "0123456789abcdef" for char in semantic) and
                 source_row["semantic_sha256"] == semantic and
                 semantic == _digest(_canonical({
                     key: value for key, value in source_doc.items()
                     if key != "manifest_sha256"
                 })) and
                 source_doc.get("build", {}).get("host_id") == source_row["host_id"],
                 "SourceV5 host manifest raw/semantic/host identity differs")
        host_id = source_row["host_id"]
        _require(type(host_id) is str and host_id not in manifests,
                 "SourceV5 source manifests have duplicate or missing host IDs")
        manifests[host_id] = source_doc
        normalized, inventory = _source_inventory_records(
            source_doc, f"SourceV5 host {host_id}",
        )
        if normalized_inventory is None:
            normalized_inventory = normalized
        else:
            _require(normalized == normalized_inventory,
                     "SourceV5 host manifests disagree on their complete typed source inventory")
        inventories[host_id] = inventory
        for record in normalized:
            absolute = str(Path(request["source_root"]).joinpath(*PurePosixPath(
                record["path"],
            ).parts))
            role = ("typed_source_file" if record["kind"] == "file" else
                    "typed_source_symlink")
            target_bytes = (record["target"].encode("utf-8")
                            if record["kind"] == "symlink" else None)
            expect(absolute, role, record["sha256"], record["size"],
                   target_bytes, record["mode"])

        for relative, role, raw_sha in _source_manifest_artifacts(
                source_doc, inventory, f"SourceV5 host {host_id}"):
            absolute = str(Path(request["source_root"]).joinpath(*PurePosixPath(
                relative,
            ).parts))
            expect(absolute, role, raw_sha, None)

    selected = manifests.get(request["host_id"])
    _require(selected is not None,
             "selected request host has no exact original SourceV5 manifest")
    module_inventory = inventories[request["host_id"]]
    expected_modules = {
        relative: {"path": relative, "sha256": record["sha256"]}
        for relative, record in module_inventory.items()
        if record["kind"] == "file" and relative.startswith("scripts/") and
        relative.endswith((".py", ".sh"))
    }
    _require(selected_modules == expected_modules,
             "selected execution module map does not equal the complete regular script inventory")

    # Verify every typed role before reading any nested source, artifact, or
    # symlink stream. This keeps a missing late row from causing earlier
    # unindexed streams to be consumed.
    for path, (role, raw_sha, byte_count, target_bytes, mode) in expected.items():
        row = index_rows.get(path)
        _require(row is not None and row["role"] == role and
                 row["host_id"] == request["host_id"] and
                 row["raw_sha256"] == raw_sha and
                 row["semantic_sha256"] is None,
                 f"SourceV5 complete source/artifact index row is missing or mistyped: {path}")
        if byte_count is None:
            _require(row["byte_count"] > 0,
                     f"SourceV5 declared artifact has no captured bytes: {path}")
        else:
            _require(row["byte_count"] == byte_count,
                     f"SourceV5 source byte count differs from its exact inventory: {path}")
        captured = rows[path]
        _require(captured["role"] == role and
                 captured["host_id"] == request["host_id"] and
                 captured["raw_sha256"] == raw_sha and
                 captured["semantic_sha256"] is None and
                 captured["byte_count"] == row["byte_count"],
                 f"captured SourceV5 source/artifact bytes differ from their index row: {path}")

    symlink_snapshots: dict[str, tuple[int, ...]] = {}
    for path, (role, raw_sha, byte_count, target_bytes, mode) in expected.items():
        captured = rows[path]
        if role == "typed_source_symlink":
            _require(target_bytes is not None and
                     _entry_bytes(captured, MAX_SOURCE_SYMLINK_BYTES,
                                  f"SourceV5 literal symlink target {path}") == target_bytes,
                     f"SourceV5 symlink row does not contain its exact literal target: {path}")
            symlink_snapshots[path] = _local_symlink_snapshot(captured, target_bytes)
        else:
            _hash_entry(captured)
            local_snapshot, local_sha = _read_local_stable(captured)
            _require(local_sha == raw_sha and
                     local_snapshot[3] == captured["byte_count"] and
                     (mode is None or local_snapshot[2] == int(mode, 8)),
                     f"SourceV5 original local bytes/mode differ from the complete typed closure: {path}")

    for relative, item in expected_modules.items():
        path = str(Path(request["source_root"]) / relative)
        row = index_rows.get(path)
        _require(row is not None and row["role"] == "typed_source_file" and
                 row["raw_sha256"] == item["sha256"] and
                 row["byte_count"] == module_inventory[relative]["size"],
                 f"selected captured SourceV5 module is not in the full typed source closure: {relative}")
    return symlink_snapshots


def _index_and_manifest_preflight(
    request: object, rows: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]],
           dict[str, tuple[int, ...]]]:
    req = _exact(request, {
        "schema", "scope", "campaign_id", "host_id", "source_root",
        "input_root", "output_root", "execution_manifest", "provenance",
        "journal", "origin_receipt", "evidence_index",
    }, "Source5 host-journal request")
    _require(req["schema"] == "allocatbelt.application-source5-host-journal-request.v1" and
             req["scope"] in {"prospective_exploration", "final_prepared",
                              "final_prepared_bounded"},
             "Source5 host-journal request schema/scope is unsupported")
    for key in ("campaign_id", "host_id"):
        _require(type(req[key]) is str and req[key],
                 f"Source5 {key} is malformed")
    for key in ("source_root", "input_root", "output_root"):
        _absolute(req[key], f"Source5 {key}")
    index_pin = _exact(req["evidence_index"],
                       {"path", "raw_sha256", "semantic_sha256"},
                       "Source5 evidence-index pin")
    for field in ("raw_sha256", "semantic_sha256"):
        _sha(index_pin[field], f"Source5 evidence-index {field}")
    index_row = rows.get(index_pin["path"])
    _require(index_row is not None and index_row["role"] == "evidence_index" and
             index_row["raw_sha256"] == index_pin["raw_sha256"] and
             index_row["semantic_sha256"] == index_pin["semantic_sha256"],
             "captured Source5 external index row differs from its request pin")
    index, index_raw = _json_entry(rows, index_pin["path"],
                                   "Source5 evidence index", MAX_INDEX_BYTES)
    index = _exact(index, {
        "schema", "campaign_id", "host_id", "source_root", "input_root",
        "output_root", "entries", "index_sha256",
    }, "Source5 journal evidence index")
    index_body = {key: value for key, value in index.items()
                  if key != "index_sha256"}
    _require(index["schema"] == INDEX_SCHEMA and
             index["campaign_id"] == req["campaign_id"] and
             index["host_id"] == req["host_id"] and
             index["source_root"] == req["source_root"] and
             index["input_root"] == req["input_root"] and
             index["output_root"] == req["output_root"] and
             index["index_sha256"] == index_pin["semantic_sha256"] ==
             _digest(_canonical(index_body)),
             "Source5 evidence index self-digest or original roots differ")
    _require(type(index["entries"]) is list and
             len(index["entries"]) <= MAX_ENTRIES,
             "Source5 evidence index entries exceed their finite bound")
    index_rows: dict[str, dict[str, Any]] = {}
    prior = ""
    for pos, value in enumerate(index["entries"]):
        row = _exact(value, {
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count",
        }, f"Source5 evidence index row[{pos}]")
        path = _absolute(row["origin_path"],
                         f"Source5 evidence index origin[{pos}]")
        _require(row["local_path"] == path and path > prior and
                 path not in index_rows and row["role"] in ROLE_LIMITS,
                 "Source5 evidence index has a duplicate, alias, or unknown role")
        prior = path
        _sha(row["raw_sha256"], f"Source5 index raw digest[{pos}]")
        semantic = row["semantic_sha256"]
        _require(semantic is None or
                 (type(semantic) is str and len(semantic) == 64 and
                  all(char in "0123456789abcdef" for char in semantic)),
                 f"Source5 index semantic digest[{pos}] is malformed")
        _require(type(row["byte_count"]) is int and
                 0 <= row["byte_count"] <= ROLE_LIMITS[row["role"]],
                 f"Source5 index role byte count[{pos}] exceeds its bound")
        index_rows[path] = row
    receipt_pin = _exact(req["origin_receipt"],
                         {"path", "raw_sha256", "semantic_sha256"},
                         "Source5 origin receipt pin")
    _require(receipt_pin["path"] != index_pin["path"] and
             receipt_pin["path"] not in index_rows and
             index_pin["path"] not in index_rows,
             "Source5 external index/receipt has a recursive or shared path")
    _sha(receipt_pin["raw_sha256"], "Source5 origin receipt raw digest")
    _sha(receipt_pin["semantic_sha256"], "Source5 origin receipt semantic digest")
    expected_store = set(index_rows) | {index_pin["path"], receipt_pin["path"]}
    _require(set(rows) == expected_store,
             "captured Source5 store differs from the exact evidence index closure")
    for path, indexed in index_rows.items():
        captured = rows[path]
        _require(all(captured[name] == indexed[name] for name in (
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count",
        )), f"captured Source5 row differs from index metadata at {path}")
    receipt_row = rows[receipt_pin["path"]]
    _require(receipt_row["role"] == "origin_receipt" and
             receipt_row["raw_sha256"] == receipt_pin["raw_sha256"] and
             receipt_row["semantic_sha256"] == receipt_pin["semantic_sha256"],
             "captured Source5 receipt row differs from its external pin")

    manifest_pin = _exact(req["execution_manifest"],
                          {"path", "raw_sha256", "semantic_sha256"},
                          "Source5 execution-manifest pin")
    manifest_row = index_rows.get(manifest_pin["path"])
    _require(manifest_row is not None and
             manifest_row["role"] == "execution_manifest" and
             manifest_row["host_id"] == req["host_id"] and
             manifest_row["raw_sha256"] == manifest_pin["raw_sha256"] and
             manifest_row["semantic_sha256"] == manifest_pin["semantic_sha256"],
             "Source5 execution-manifest pin is absent from its typed index")
    manifest, _manifest_raw = _json_entry(
        rows, manifest_pin["path"], "Source5 execution manifest", MAX_JSON_BYTES,
    )
    manifest_semantic = manifest.get("manifest_sha256")
    _require(type(manifest_semantic) is str and len(manifest_semantic) == 64 and
             all(char in "0123456789abcdef" for char in manifest_semantic) and
             manifest_semantic == manifest_pin["semantic_sha256"] and
             manifest_semantic == _digest(_canonical({
                 key: value for key, value in manifest.items()
                 if key != "manifest_sha256"
             })),
             "Source5 execution manifest semantic digest differs from its exact pin")
    module_map = manifest.get("modules")
    _require(type(module_map) is dict and req["host_id"] in module_map and
             type(module_map[req["host_id"]]) is dict,
             "Source5 execution manifest has no selected-host module map")
    selected_modules = module_map[req["host_id"]]
    source_symlink_snapshots = _validate_full_source_index_closure(
        req, index_rows, rows, selected_modules,
    )
    return req, index, rows, source_symlink_snapshots


def _load_pinned_module(
    request: dict[str, Any], index: dict[str, Any],
    rows: dict[str, dict[str, Any]], relative: str,
) -> types.ModuleType:
    path = str(Path(request["source_root"]) / relative)
    row = rows.get(path)
    _require(row is not None and row["role"] == "typed_source_file" and
             row["host_id"] == request["host_id"],
             f"captured SourceV5 module {relative} has no selected-host typed role")
    manifest_rows = [candidate for candidate_path, candidate in rows.items()
                     if candidate["role"] == "source_manifest" and
                     candidate["host_id"] == request["host_id"]]
    _require(len(manifest_rows) == 1,
             "pinned module has no unique selected-host SourceV5 manifest")
    source_doc, _source_raw = _json_entry(
        rows, manifest_rows[0]["origin_path"],
        "selected SourceV5 module inventory", 16 * 1024 * 1024,
    )
    source_records = [item for item in source_doc["source"]["files"]
                      if item["path"] == relative]
    _require(len(source_records) == 1 and
             source_records[0]["kind"] == "file" and
             source_records[0]["sha256"] == row["raw_sha256"] and
             source_records[0]["size"] == row["byte_count"],
             f"captured SourceV5 module differs from its typed inventory: {relative}")
    execution_manifest, _manifest_raw = _json_entry(
        rows, request["execution_manifest"]["path"],
        "Source5 selected execution manifest", MAX_JSON_BYTES,
    )
    modules = execution_manifest.get("modules")
    _require(type(modules) is dict and request["host_id"] in modules and
             modules[request["host_id"]].get(relative) == {
                 "path": relative, "sha256": row["raw_sha256"],
             }, f"execution manifest module map does not pin {relative}")
    file_key, file_sha = _read_local_stable(row)
    _require(file_sha == row["raw_sha256"] and
             file_key[2] == int(source_records[0]["mode"], 8),
             f"local pinned module bytes/mode differ from captured inventory: {relative}")
    raw = _entry_bytes(row, MAX_SOURCE_BYTES,
                       f"captured SourceV5 module {relative}")
    name = f"source5_offline_{relative.rsplit('/', 1)[-1].replace('-', '_').replace('.', '_')}_{row['raw_sha256']}"
    module = types.ModuleType(name)
    module.__file__ = path
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(raw, path, "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        sys.modules.pop(name, None)
        raise Source5OfflineDispatchError(
            f"captured SourceV5 module {relative} cannot be compiled: {error}",
        ) from error
    return module


def _close_module(module: types.ModuleType) -> None:
    name = module.__name__
    if sys.modules.get(name) is module:
        sys.modules.pop(name, None)


def _read_local_stable(row: dict[str, Any]) -> tuple[tuple[int, ...], str]:
    path = Path(row["local_path"])
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | \
        getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before_path = path.lstat()
        _require(stat.S_ISREG(before_path.st_mode),
                 f"captured local member is not a regular file: {path}")
        fd = os.open(path, flags)
    except OSError as error:
        raise Source5OfflineDispatchError(
            f"cannot open captured local member {path}: {error}",
        ) from error
    try:
        before = os.fstat(fd)
        key = (before.st_dev, before.st_ino, before.st_mode, before.st_size,
               before.st_mtime_ns, before.st_ctime_ns)
        path_key = (before_path.st_dev, before_path.st_ino, before_path.st_mode,
                    before_path.st_size, before_path.st_mtime_ns,
                    before_path.st_ctime_ns)
        _require(stat.S_ISREG(before.st_mode) and key == path_key and
                 before.st_size == row["byte_count"] and
                 before.st_nlink == 1,
                 f"captured local member identity/size/link count differs: {path}")
        hasher = hashlib.sha256()
        total = 0
        while total < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - total))
            _require(bool(block), f"captured local member truncated: {path}")
            total += len(block)
            hasher.update(block)
        _require(os.read(fd, 1) == b"" and total == row["byte_count"] and
                 hasher.hexdigest() == row["raw_sha256"],
                 f"captured local member differs from immutable store: {path}")
        after = os.fstat(fd)
        after_path = path.lstat()
        after_key = (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns)
        after_path_key = (after_path.st_dev, after_path.st_ino, after_path.st_mode,
                          after_path.st_size, after_path.st_mtime_ns,
                          after_path.st_ctime_ns)
        _require(key == after_key == after_path_key,
                 f"captured local member changed during stable read: {path}")
        return key, hasher.hexdigest()
    finally:
        os.close(fd)


def _read_local_directory(path_text: str) -> tuple[int, ...]:
    path = Path(path_text)
    try:
        before = path.lstat()
        _require(stat.S_ISDIR(before.st_mode) and
                 not stat.S_ISLNK(before.st_mode) and
                 path.resolve(strict=True) == path,
                 f"captured evidence directory is aliased or not a directory: {path}")
        after = path.lstat()
    except OSError as error:
        raise Source5OfflineDispatchError(
            f"captured evidence directory is unavailable: {path}: {error}",
        ) from error
    key = (before.st_dev, before.st_ino, before.st_mode, before.st_mtime_ns,
           before.st_ctime_ns)
    after_key = (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns,
                 after.st_ctime_ns)
    _require(key == after_key, f"captured evidence directory changed: {path}")
    return key


def _row_map_from_paths(
    rows: dict[str, dict[str, Any]],
    explicit_paths: set[str],
    subtree_roots: set[str],
    request: dict[str, Any],
    *, maximum_entries: int = MAX_MAP_ENTRIES,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, tuple[int, ...]]]:
    """Create an identity map from exact indexed files and their parent dirs."""
    for path in explicit_paths:
        row = rows.get(path)
        _require(row is None or row["role"] != "typed_source_symlink",
                 f"typed source symlink is data-only and cannot enter a component file map: {path}")
    allowed_roles = COMPONENT_ROLES | {
        "typed_source_file", "source_manifest", "spec_v3", "plan_v3",
        "observed_host", "execution_manifest", "journal", "preparation",
        "prepared_completion", "evidence_index", "origin_receipt",
    }
    execution_manifest, _manifest_raw = _json_entry(
        rows, request["execution_manifest"]["path"],
        "Source5 execution manifest", MAX_JSON_BYTES,
    )
    artifact_root = _absolute(execution_manifest["artifact_root"],
                              "Source5 execution artifact root")
    root_paths = set(subtree_roots)
    explicit_directories: set[str] = set()
    base_roots = {
        request["source_root"], request["input_root"], request["output_root"],
        artifact_root,
    }
    for path in explicit_paths - set(rows) - root_paths:
        try:
            info = Path(path).lstat()
            _require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                     Path(path).resolve(strict=True) == Path(path),
                     f"declared component path is neither indexed file nor directory: {path}")
        except OSError as error:
            raise Source5OfflineDispatchError(
                f"declared component directory is unavailable: {path}: {error}",
            ) from error
        explicit_directories.add(path)
        is_ancestor_of_base = any(
            Path(base).is_relative_to(Path(path))
            for base in base_roots
        )
        has_indexed_descendant = any(
            Path(candidate).is_relative_to(Path(path))
            for candidate in rows
        )
        if not is_ancestor_of_base and has_indexed_descendant:
            root_paths.add(path)
    selected: dict[str, dict[str, Any]] = {}
    for path, row in rows.items():
        if row["role"] not in allowed_roles:
            continue
        in_subtree = any(Path(path).is_relative_to(Path(root))
                         for root in root_paths)
        if path in explicit_paths or in_subtree:
            selected[path] = row
    for path in explicit_paths:
        if path in rows:
            selected[path] = rows[path]
    missing = explicit_paths - set(rows)
    for path in missing:
        _require(path in root_paths or path in explicit_directories or
                 any(Path(candidate).is_relative_to(Path(path))
                     for candidate in selected),
                 f"component closure names an unindexed file or unowned directory: {path}")
    dir_paths: set[str] = {
        request["source_root"], request["input_root"], request["output_root"],
    }
    dir_paths.add(artifact_root)
    for root in root_paths:
        dir_paths.add(_absolute(root, "component subtree root"))
    for path in selected:
        parent = Path(path).parent
        dir_paths.add(str(parent))
        for root in (request["source_root"], request["input_root"],
                     request["output_root"], execution_manifest["artifact_root"],
                     *root_paths, *missing):
            root_path = Path(root)
            if parent.is_relative_to(root_path):
                cursor = parent
                while cursor != root_path:
                    dir_paths.add(str(cursor))
                    cursor = cursor.parent
                break
    dir_paths.update(explicit_directories)
    dir_paths.update(path for path in explicit_paths if path in rows and
                     rows[path]["role"] not in allowed_roles)
    _require(len(selected) + len(dir_paths) <= maximum_entries,
             "exact component identity map exceeds its finite entry bound")
    snapshots: dict[str, tuple[int, ...]] = {}
    for path, row in selected.items():
        if row["role"] == "typed_source_file" and \
                Path(path).is_relative_to(Path(request["source_root"])):
            relative = Path(path).relative_to(Path(request["source_root"])).as_posix()
            source_matches = [candidate for source_path, candidate in rows.items()
                              if candidate["role"] == "source_manifest" and
                              candidate["host_id"] == request["host_id"]]
            _require(len(source_matches) == 1,
                     "typed module map has no unique selected SourceV5 manifest")
            source_doc, _source_raw = _json_entry(
                rows, source_matches[0]["origin_path"],
                "selected SourceV5 manifest", 16 * 1024 * 1024,
            )
            inventory = [item for item in source_doc["source"]["files"]
                         if item["path"] == relative]
            _require(len(inventory) == 1 and
                     inventory[0]["kind"] == "file" and
                     row["raw_sha256"] == inventory[0]["sha256"] and
                     row["byte_count"] == inventory[0]["size"],
                     f"typed source bytes differ from the selected inventory: {relative}")
            snapshot = _read_local_stable(row)[0]
            _require(snapshot[2] == int(inventory[0]["mode"], 8),
                     f"typed source local mode differs from its selected inventory: {relative}")
            snapshots[path] = snapshot
        else:
            snapshots[path] = _read_local_stable(row)[0]
    for path in sorted(dir_paths):
        snapshots[path] = _read_local_directory(path)
    entries = [{"origin": path, "local": path}
               for path in sorted(set(selected) | dir_paths)]
    return ({
        "schema": "allocatbelt.application-pressure-evidence-path-map.v1",
        "entries": entries,
    }, list(selected.values()), snapshots)


def _verify_local_snapshot(
    file_rows: list[dict[str, Any]], snapshots: dict[str, tuple[int, ...]],
) -> None:
    for row in file_rows:
        prior = snapshots.get(row["local_path"])
        current, actual = _read_local_stable(row)
        _require(prior == current and actual == row["raw_sha256"],
                 f"component evidence changed during offline replay: {row['local_path']}")
    for path, prior in snapshots.items():
        if path in {row["local_path"] for row in file_rows}:
            continue
        _require(_read_local_directory(path) == prior,
                 f"component evidence directory changed during offline replay: {path}")


def _direct_paths(value: object, helper: Any) -> set[str]:
    paths = helper._pair_absolute_paths(value)
    return {_absolute(path, "component-declared path") for path in paths}


def _validate_active_dispatcher(
    request: dict[str, Any], rows: dict[str, dict[str, Any]],
) -> None:
    expected = Path(request["source_root"]) / \
        "scripts/application-source5-offline-dispatch.py"
    active_text = globals().get("__file__")
    _require(type(active_text) is str and Path(active_text).is_absolute() and
             Path(active_text).resolve(strict=True) == expected and
             verify_source5_job_artifacts_offline.__code__.co_filename == str(expected),
             "executing Source5 dispatcher is not the selected inventory-pinned module")
    row = rows.get(str(expected))
    _require(row is not None and row["role"] == "typed_source_file" and
             row["host_id"] == request["host_id"],
             "executing Source5 dispatcher is absent from its selected typed inventory")
    key, raw_sha = _read_local_stable(row)
    _require(raw_sha == row["raw_sha256"] and key[2] in {
                 stat.S_IFREG | 0o644, stat.S_IFREG | 0o755,
             }, "executing Source5 dispatcher bytes/mode differ from captured typed source")


def _indexed_record(host: dict[str, Any], pin_value: object) -> dict[str, Any]:
    pin = _exact(pin_value, {"path", "raw_sha256"}, "Source5 job-record pin")
    path = _absolute(pin["path"], "Source5 job-record path")
    _sha(pin["raw_sha256"], "Source5 job-record raw SHA")
    found = [row for row in host["indexed_job_records"]
             if row["path"] == path and row["raw_sha256"] == pin["raw_sha256"]]
    _require(len(found) == 1,
             "requested Source5 job record is not one exact indexed journal descendant")
    row = found[0]
    _require(row["semantic_sha256"] == row["record"]["record_sha256"],
             "Source5 job record semantic digest differs from its typed index role")
    return row


def _component_receipt(
    host: dict[str, Any], run_id: str, expected_schema: str,
) -> dict[str, Any]:
    found = [row for row in host["indexed_component_receipts"]
             if row["run_id"] == run_id and row["component_schema"] == expected_schema]
    _require(len(found) == 1,
             f"Source5 job has no unique strict {expected_schema} origin receipt")
    return found[0]


def _unique_job_rows(
    host: dict[str, Any], phase: str, run_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    auths = [row for row in host["source5_authorizations"]
             if row["phase"] == phase and row["job_run_id"] == run_id]
    finished = [row for row in host["source5_finished"]
                if row["phase"] == phase and row["job_run_id"] == run_id]
    _require(len(auths) == len(finished) == 1,
             "Source5 job lacks one unique original authorization and terminal")
    return auths[0], finished[0]


def _selected_files_for_component(
    request: dict[str, Any], host: dict[str, Any], rows: dict[str, dict[str, Any]],
    record: dict[str, Any], auth: dict[str, Any], receipt_row: dict[str, Any],
    component_paths: set[str], component_roots: set[str],
    *, maximum_entries: int = MAX_MAP_ENTRIES,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, tuple[int, ...]]]:
    explicit = set(component_paths)
    explicit.update(path for path, row in rows.items()
                    if row["role"] == "typed_source_file" and
                    Path(path).is_relative_to(Path(request["source_root"])))
    explicit.update({request["execution_manifest"]["path"],
                     request["origin_receipt"]["path"],
                     request["evidence_index"]["path"],
                     request["journal"]["path"]})
    original = host["original_pins"]
    original_inputs = original.get("original_inputs", original)
    if type(original_inputs) is dict:
        for name in ("spec", "plan"):
            value = original_inputs.get(name)
            if type(value) is dict:
                artifact = value.get("artifact", value)
                if type(artifact) is dict and type(artifact.get("path")) is str:
                    explicit.add(artifact["path"])
        source_map = original_inputs.get("source_manifests")
        if type(source_map) is dict:
            for value in source_map.values():
                if type(value) is dict:
                    artifact = value.get("artifact", value)
                    if type(artifact) is dict and type(artifact.get("path")) is str:
                        explicit.add(artifact["path"])
    for item in host["indexed_direct_refs"]:
        if item["role"] in {"journal", "execution_manifest", "spec_v3", "plan_v3",
                             "source_manifest", "observed_host", "preparation",
                             "prepared_completion", "capacity_completion",
                             "capacity_ledger", "capacity_host_receipt"}:
            if item["role"] in {"journal", "execution_manifest", "spec_v3",
                                 "plan_v3", "source_manifest", "observed_host"}:
                explicit.add(item["path"])
    explicit.add(record["path"])
    explicit.add(auth["helper_input"]["path"])
    explicit.add(receipt_row["path"])
    for path in component_roots:
        _absolute(path, "component exact root")
    return _row_map_from_paths(
        rows, explicit, component_roots, request,
        maximum_entries=maximum_entries,
    )


def _source_manifest_file_paths(
    request: dict[str, Any], rows: dict[str, dict[str, Any]],
    manifest_path: str,
) -> set[str]:
    manifest, _raw = _json_entry(
        rows, manifest_path, "SourceV5 manifest artifact closure", 16 * 1024 * 1024,
    )
    normalized, inventory = _source_inventory_records(
        manifest, "SourceV5 component artifact closure",
    )
    paths: set[str] = set()
    for item in normalized:
        relative = PurePosixPath(item["path"])
        path = str(Path(request["source_root"]).joinpath(*relative.parts))
        row = rows.get(path)
        if item["kind"] == "symlink":
            target_bytes = item["target"].encode("utf-8")
            _require(row is not None and row["role"] == "typed_source_symlink" and
                     row["host_id"] == request["host_id"] and
                 row["raw_sha256"] == item["sha256"] and
                     row["semantic_sha256"] is None and
                     row["byte_count"] == item["size"] and
                     _entry_bytes(row, MAX_SOURCE_SYMLINK_BYTES,
                                  f"literal SourceV5 symlink target {path}") == target_bytes,
                     f"SourceV5 symlink is absent from exact typed evidence: {path}")
            continue
        _require(row is not None and row["role"] == "typed_source_file" and
                 row["host_id"] == request["host_id"] and
                 row["raw_sha256"] == item["sha256"] and
                 row["semantic_sha256"] is None and
                 row["byte_count"] == item["size"],
                 f"SourceV5 source inventory file is absent from exact typed evidence: {path}")
        paths.add(path)
    for relative_text, role, raw_sha in _source_manifest_artifacts(
            manifest, inventory, "SourceV5 component artifact closure"):
        relative = PurePosixPath(relative_text)
        path = str(Path(request["source_root"]).joinpath(*relative.parts))
        row = rows.get(path)
        _require(row is not None and row["role"] == role and
                 row["host_id"] == request["host_id"] and
                 row["raw_sha256"] == raw_sha and
                 row["semantic_sha256"] is None and row["byte_count"] > 0,
                 f"SourceV5 declared artifact is absent from its exact typed role: {path}")
        paths.add(path)
    return paths


def _pressure_component_path_map(
    request: dict[str, Any], host: dict[str, Any],
    rows: dict[str, dict[str, Any]], record: dict[str, Any],
    auth: dict[str, Any], receipt_row: dict[str, Any], pressure: Any,
    recipe: dict[str, Any], sidecar: dict[str, Any],
    host_receipt: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, tuple[int, ...]]]:
    component_paths = set()
    for document in (recipe, sidecar, host_receipt):
        component_paths |= _direct_paths(document, pressure)
    source_manifests = [row for row in host["indexed_direct_refs"]
                        if row["role"] == "source_manifest"]
    _require(len(source_manifests) == 3,
             "pressure replay requires all three original indexed SourceV5 manifests")
    for row in source_manifests:
        component_paths.add(row["path"])
        component_paths |= _source_manifest_file_paths(
            request, rows, row["path"],
        )
    original_inputs = host["original_pins"].get("original_inputs",
                                                host["original_pins"])
    for name in ("spec", "plan"):
        pin = original_inputs[name]["artifact"]
        path = _absolute(pin["path"], f"original Source5 {name} path")
        component_paths.add(path)
        document, _raw = _json_entry(rows, path, f"original Source5 {name}",
                                     MAX_JSON_BYTES)
        component_paths |= _direct_paths(document, pressure)
    root = _absolute(record["pair_directory"],
                     "Source5 pressure job output root")
    execution_manifest, _manifest_raw = _json_entry(
        rows, request["execution_manifest"]["path"],
        "Source5 execution manifest", MAX_JSON_BYTES,
    )
    _require(Path(root).is_relative_to(Path(request["output_root"])) or
             Path(root).is_relative_to(Path(execution_manifest["artifact_root"])),
             "Source5 pressure job output root is outside its original host roots")
    component_paths.update({
        record["evidence"]["recipe"]["path"],
        record["evidence"]["readback"]["path"],
        record["evidence"]["processes"]["path"],
        auth["helper_input"]["path"], receipt_row["path"],
    })
    return _selected_files_for_component(
        request, host, rows, record, auth, receipt_row,
        component_paths, {root},
    )


def _validate_auth_record_binding(
    request: dict[str, Any], record_row: dict[str, Any],
    auth: dict[str, Any], finished: dict[str, Any],
) -> dict[str, Any]:
    record = record_row["record"]
    _require(record["schema"] == SOURCE5_JOB_SCHEMA and
             record["state"] == finished["job_terminal"]["state_claim"] and
             record["job"] == auth["job"] and
             record["chronology"]["authorization_id"] == auth["authorization_id"] and
             record["chronology"]["authorization_head"] == auth["authorization_head"] and
             record["chronology"]["job_terminal_head"] ==
                 finished["job_terminal"]["event_head"] and
             record["chronology"]["component_sha256"] ==
                 finished["job_terminal"]["details"]["component_sha256"] and
             record["chronology"]["process_metrics_sha256"] ==
                 finished["job_terminal"]["details"]["process_metrics_sha256"] and
             _digest(_canonical(record["process_metrics"])) ==
                 finished["job_terminal"]["details"]["process_metrics_sha256"],
             "Source5 job record differs from its exact journal authorization/terminal projection")
    _require(request["scope"] != "prospective_exploration" or
             auth["phase"] == "exploration",
             "prospective Source5 replay cannot authorize later campaign phases")
    return record


def _fixed_component_replay(
    request: dict[str, Any], host: dict[str, Any], rows: dict[str, dict[str, Any]],
    record_row: dict[str, Any], auth: dict[str, Any], receipt_row: dict[str, Any],
    chronology: Any, pressure: Any,
) -> dict[str, Any]:
    record = record_row["record"]
    evidence = _exact(record["evidence"], {
        "kind", "execution_manifest", "helper_input", "helper_module", "overlay",
        "receipt", "processes", "runtime_bindings", "source_snapshot",
    }, "Source5 fixed-pair job evidence")
    _require(evidence["kind"] == "source5_fixed_pair",
             "fixed Source5 phase contains a different component kind")
    receipt_pin = _exact(evidence["receipt"], {"path", "raw_sha256"},
                         "Source5 fixed component receipt pin")
    overlay_pin = _exact(evidence["overlay"], {"path", "raw_sha256"},
                         "Source5 fixed overlay pin")
    fixed_pin = {
        "path": receipt_row["path"],
        "raw_sha256": receipt_row["raw_sha256"],
        "host_verification_sha256": receipt_row["semantic_sha256"],
    }
    _require(receipt_row["component_schema"] == FIXED_HOST_SCHEMA and
             receipt_row["run_id"] == auth["job_run_id"],
             "fixed origin receipt belongs to another Source5 job")
    source_path = str(Path(request["source_root"]) /
                      "scripts/application-campaign.py")
    fixed_path = str(Path(request["source_root"]) /
                     "scripts/application-fixed-pair.py")
    _require(source_path in rows and fixed_path in rows,
             "captured Source5 fixed verifier/controller bytes are absent")
    overlay_row = rows.get(overlay_pin["path"])
    execution_row = rows.get(receipt_pin["path"])
    _require(overlay_row is not None and
             overlay_row["role"] == "fixed_pair_artifact" and
             overlay_row["raw_sha256"] == overlay_pin["raw_sha256"] and
             execution_row is not None and
             execution_row["raw_sha256"] == receipt_pin["raw_sha256"],
             "fixed pair overlay/receipt are not exact typed captured artifacts")
    overlay, _overlay_raw = _json_entry(
        rows, overlay_pin["path"], "Source5 fixed execution overlay", MAX_JSON_BYTES,
    )
    component_roots = {overlay["output_root"]}
    receipt_path = receipt_row["path"]
    component_paths = {overlay_pin["path"], receipt_pin["path"], receipt_path,
                       source_path, fixed_path}
    receipt_value, _receipt_raw = _json_entry(
        rows, receipt_pin["path"], "Source5 fixed component receipt", MAX_JSON_BYTES,
    )
    host_value, _host_raw = _json_entry(
        rows, receipt_path, "strict fixed-pair host receipt", MAX_JSON_BYTES,
    )
    component_paths |= _direct_paths(overlay, pressure)
    component_paths |= _direct_paths(receipt_value, pressure)
    component_paths |= _direct_paths(host_value, pressure)
    for manifest_ref in host["indexed_direct_refs"]:
        if manifest_ref["role"] == "source_manifest":
            component_paths.add(manifest_ref["path"])
            component_paths |= _source_manifest_file_paths(
                request, rows, manifest_ref["path"],
            )
    original_inputs = host["original_pins"].get(
        "original_inputs", host["original_pins"],
    )
    for label in ("spec", "plan"):
        original_pin = original_inputs[label]["artifact"]
        original_doc, _original_raw = _json_entry(
            rows, original_pin["path"], f"original Source5 {label}",
            MAX_JSON_BYTES,
        )
        component_paths.add(original_pin["path"])
        component_paths |= _direct_paths(original_doc, pressure)
    path_map, file_rows, snapshots = _selected_files_for_component(
        request, host, rows, record, auth, receipt_row,
        component_paths, component_roots, maximum_entries=4096,
    )
    overlay_arg = {"path": overlay_pin["path"],
                   "sha256": overlay_pin["raw_sha256"]}
    execution_pin = {"path": receipt_pin["path"],
                     "sha256": receipt_pin["raw_sha256"]}
    try:
        verified = pressure.fixed_pair_module.verify_fixed_pair_overlay_offline(
            overlay_arg, execution_pin, fixed_pin, path_map,
        )
        _verify_local_snapshot(file_rows, snapshots)
    except Exception as error:
        raise Source5OfflineDispatchError(
            f"Source5 fixed-pair component replay failed: {type(error).__name__}: {error}",
        ) from error
    expected_status = "valid_pair" if record["state"] == "valid_pair" else "failed_or_invalid"
    _require(verified.get("verified") is True and
             verified.get("status") == expected_status and
             verified.get("qualification_eligible") is False and
             verified.get("receipt_sha256") == receipt_pin["raw_sha256"] and
             verified.get("run_id") == auth["job_run_id"] and
             verified.get("host_verification_sha256") == receipt_row["semantic_sha256"],
             "fixed-pair offline result differs from its exact job/origin receipt")
    process_metrics = receipt_value.get("process_metrics")
    _require(type(process_metrics) is list and
             _digest(_canonical(process_metrics)) ==
             record["chronology"]["process_metrics_sha256"],
             "fixed-pair recomputed metrics differ from the Source5 terminal digest")
    component = {
        "schema": "allocatbelt.application-source5-fixed-component.v1",
        "overlay": overlay_pin,
        "receipt": receipt_pin,
        "verification": {
            key: verified[key] for key in (
                "schema", "verified", "status", "qualification_eligible",
                "receipt_sha256", "overlay_sha256", "run_id",
            )
        },
    }
    component_sha = _digest(_canonical(component))
    _require(component_sha == record["chronology"]["component_sha256"] and
             record["state"] in {"valid_pair", "invalid_pair"},
             "fixed-pair reconstructed component digest differs from its journal terminal")
    return {
        "state": record["state"], "component": component,
        "component_sha256": component_sha,
        "process_metrics": process_metrics,
        "process_metrics_sha256": _digest(_canonical(process_metrics)),
        "readback": verified,
    }


def _load_component_modules(
    request: dict[str, Any], index: dict[str, Any],
    rows: dict[str, dict[str, Any]],
) -> dict[str, types.ModuleType]:
    modules: dict[str, types.ModuleType] = {}
    for relative in (
        "scripts/application-fixed-pair.py",
        "scripts/application-pressure-pair.py",
        "scripts/application-pressure-readback.py",
        "scripts/application-feedback-readback.py",
        "scripts/application-feedback-composition.py",
        "scripts/application-campaign.py",
        "scripts/application-source-inventory.py",
        "scripts/application-source5-soak.py",
        "scripts/application-soak-readback.py",
    ):
        path = str(Path(request["source_root"]) / relative)
        row = rows.get(path)
        _require(row is not None and row["role"] == "typed_source_file" and
                 row["host_id"] == request["host_id"],
                 f"captured Source5 component module is absent from the exact typed source closure: {relative}")
        modules[relative] = _load_pinned_module(request, index, rows, relative)
    _require("scripts/application-fixed-pair.py" in modules and
             "scripts/application-pressure-pair.py" in modules and
             "scripts/application-campaign.py" in modules,
             "captured Source5 component modules are incomplete")
    return modules


def verify_source5_pressure_prerequisites_offline(
    request: object, captured_evidence: object, job_record_pin: object, *,
    recipe_pin: object, readback_pin: object, host_verification_pin: object,
) -> dict[str, Any]:
    """Prove the exact registered pressure authorization and replay its fixed predecessor."""
    rows = _store_rows(captured_evidence)
    req, index, rows, source_symlink_snapshots = _index_and_manifest_preflight(
        request, rows,
    )
    _validate_active_dispatcher(req, rows)
    chronology = _load_pinned_module(
        req, index, rows, "scripts/application-campaign-chronology.py",
    )
    _verify_local_source_symlink_snapshots(rows, source_symlink_snapshots)
    modules: dict[str, types.ModuleType] = {"chronology": chronology}
    try:
        host = chronology.verify_source5_host_journal_offline(req, captured_evidence)
        record_row = _indexed_record(host, job_record_pin)
        record = record_row["record"]
        _require(record["job"].get("phase") == "pressure",
                 "pressure prerequisites were requested for a non-pressure job")
        auth, finished = _unique_job_rows(
            host, "pressure", record["job"]["run_id"],
        )
        _validate_auth_record_binding(req, record_row, auth, finished)
        recipe_pin_exact = _exact(recipe_pin, {"path", "raw_sha256"},
                                  "Source5 pressure recipe pin")
        readback_pin_exact = _exact(readback_pin, {"path", "raw_sha256"},
                                    "Source5 pressure readback pin")
        host_pin = _exact(host_verification_pin,
                          {"path", "raw_sha256", "receipt_sha256"},
                          "Source5 pressure host receipt pin")
        evidence = _exact(record["evidence"], {
            "kind", "execution_manifest", "helper_input", "helper_module",
            "recipe", "overlay", "readback", "processes",
            "fixed_predecessor", "source_snapshot",
        }, "Source5 pressure job evidence")
        _require(evidence["kind"] == "source5_pressure_pair" and
                 evidence["recipe"] == recipe_pin_exact and
                 evidence["readback"] == readback_pin_exact,
                 "pressure recipe/readback pins differ from the original job record")
        receipt_rows = [row for row in host["indexed_component_receipts"]
                        if row["path"] == host_pin["path"] and
                        row["raw_sha256"] == host_pin["raw_sha256"] and
                        row["semantic_sha256"] == host_pin["receipt_sha256"] and
                        row["component_schema"] == PRESSURE_HOST_SCHEMA and
                        row["run_id"] == auth["job_run_id"]]
        _require(len(receipt_rows) == 1,
                 "pressure host receipt is not the exact indexed origin receipt for this job")
        recipe, _recipe_raw = _json_entry(
            rows, recipe_pin_exact["path"], "Source5 pressure recipe", MAX_JSON_BYTES,
        )
        overlay_pin = recipe.get("execution_overlay", {}).get("artifact")
        _require(type(overlay_pin) is dict,
                 "pressure recipe omits its original execution overlay pin")
        overlay_path = _absolute(overlay_pin.get("path"),
                                 "pressure overlay path")
        overlay_row = rows.get(overlay_path)
        _require(overlay_row is not None and
                 overlay_row["role"] == "fixed_pair_artifact" and
                 overlay_row["raw_sha256"] == overlay_pin.get("raw_sha256"),
                 "pressure overlay is not an exact indexed fixed-pair artifact")
        overlay, _overlay_raw = _json_entry(
            rows, overlay_path, "Source5 pressure execution overlay", MAX_JSON_BYTES,
        )
        chronology_binding = _exact(overlay.get("chronology"), {
            "observed_host", "output_root", "capacity_output_root",
            "journal_head", "journal_record_count", "registration_head",
            "dispatch_event_count",
        }, "pressure overlay original chronology snapshot")
        origin_row = receipt_rows[0]
        host_receipt, _host_receipt_raw = _json_entry(
            rows, origin_row["path"], "strict pressure host receipt", MAX_JSON_BYTES,
        )
        proof = chronology.verify_source5_journal_ancestry(
            req, captured_evidence,
            authorization_head=auth["authorization_head"],
            authorization_record_count=auth["authorization_record_count"],
            authorization_id=auth["authorization_id"],
            job_run_id=auth["job_run_id"], phase="pressure",
            historical_head=chronology_binding["journal_head"],
            historical_record_count=chronology_binding["journal_record_count"],
        )
        _require(proof["completed"] is True and
                 proof["authorization"]["job"] == record["job"] and
                 host_receipt.get("authorization_id") == auth["authorization_id"] and
                 host_receipt.get("journal_head") == chronology_binding["journal_head"] and
                 host_receipt.get("registration_head") ==
                    chronology_binding["registration_head"] and
                 host_receipt.get("strict_result_sha256") != "0" * 64,
                 "strict pressure origin receipt does not bind its exact authorized journal snapshot")
        predecessor = proof.get("fixed_predecessor")
        _require(type(predecessor) is dict and
                 predecessor.get("component_replay_required") is True and
                 predecessor.get("qualification_eligible") is False,
                 "original pressure job has no exact earlier fixed predecessor ancestry")
        predecessor_auth = predecessor["authorization"]
        predecessor_record_path = str(
            Path(req["output_root"]) / req["campaign_id"] / "source5" /
            req["host_id"] / "confirmation" / "job-records" /
            f"{predecessor['run_id']}.json"
        )
        predecessor_index_rows = [row for row in host["indexed_job_records"]
                                  if row["path"] == predecessor_record_path and
                                  row["phase"] == "confirmation" and
                                  row["job_run_id"] == predecessor["run_id"] and
                                  row["authorization_id"] ==
                                      predecessor_auth["authorization_id"]]
        _require(len(predecessor_index_rows) == 1,
                 "fixed predecessor record path is not the unique original confirmation member")
        predecessor_row = predecessor_index_rows[0]
        predecessor_job_pin = {"path": predecessor_record_path,
                               "raw_sha256": predecessor_row["raw_sha256"]}
        recipe_predecessor = _exact(recipe.get("fixed_predecessor"), {"record"},
                                    "Source5 pressure recipe fixed predecessor")
        _require(recipe_predecessor["record"] == predecessor_job_pin,
                 "pressure recipe does not pin the exact journal-confirmed fixed predecessor record")
        component_modules = _load_component_modules(req, index, rows)
        modules.update(component_modules)
        _verify_local_source_symlink_snapshots(rows, source_symlink_snapshots)
        predecessor_result = _fixed_component_replay(
            req, host, rows, predecessor_row, predecessor_auth,
            _component_receipt(host, predecessor["run_id"], FIXED_HOST_SCHEMA),
            chronology, types.SimpleNamespace(
                fixed_pair_module=component_modules["scripts/application-fixed-pair.py"],
                _pair_absolute_paths=component_modules[
                    "scripts/application-pressure-pair.py"]._pair_absolute_paths,
            ),
        )
        _require(predecessor_result["state"] == "valid_pair" and
                 predecessor_result["component_sha256"] ==
                    predecessor["finished"]["job_terminal"]["component_sha256"] and
                 predecessor_result["process_metrics_sha256"] ==
                    predecessor["finished"]["job_terminal"]["process_metrics_sha256"],
                 "fixed predecessor component does not replay to its original successful terminal")
        _verify_local_source_symlink_snapshots(rows, source_symlink_snapshots)
        source_ref = host["source_manifest_refs"][req["host_id"]]
        source_value, _source_raw = _json_entry(
            rows, source_ref["path"], "selected SourceV5 manifest", 16 * 1024 * 1024,
        )
        original_inputs = host["original_pins"].get(
            "original_inputs", host["original_pins"],
        )
        spec_pin = original_inputs["spec"]["artifact"]
        spec_value, _spec_raw = _json_entry(
            rows, spec_pin["path"], "original Source5 SpecV3", 32 * 1024 * 1024,
        )
        campaign_module = component_modules["scripts/application-campaign.py"]
        predecessor_receipt_value = campaign_module.fixed_pressure_predecessor_receipt(
            record["job"], predecessor_row["record"], spec_value, source_value,
        )
        fixed_receipt_pin = _exact(record["evidence"].get("fixed_predecessor"), {
            "path", "raw_sha256",
        }, "Source5 pressure reconstructed fixed-predecessor receipt pin")
        expected_receipt_path = str(Path(record["pair_directory"]) /
                                    "preflight/fixed-pressure-predecessor.json")
        _require(fixed_receipt_pin["path"] == expected_receipt_path,
                 "Source5 pressure record changed the original fixed-predecessor receipt path")
        fixed_receipt_row = rows.get(fixed_receipt_pin["path"])
        _require(fixed_receipt_row is not None and
                 fixed_receipt_row["raw_sha256"] == fixed_receipt_pin["raw_sha256"],
                 "Source5 fixed-predecessor reconstruction is absent from the typed evidence index")
        stored_predecessor_receipt, _stored_predecessor_raw = _json_entry(
            rows, fixed_receipt_pin["path"],
            "Source5 reconstructed fixed-predecessor receipt", 1024 * 1024,
        )
        _require(stored_predecessor_receipt == predecessor_receipt_value,
                 "stored fixed-predecessor receipt differs from fresh source/job/metrics reconstruction")
        return {
            "schema": "allocatbelt.application-source5-pressure-prerequisites.v1",
            "job": auth["job"], "job_index": auth["job_index"],
            "helper_input": auth["helper_input"],
            "authorization_id": auth["authorization_id"],
            "authorization_head": auth["authorization_head"],
            "authorization_record_count": auth["authorization_record_count"],
            "registration_head": auth["capacity_registration_head"],
            "historical_head": chronology_binding["journal_head"],
            "historical_record_count": chronology_binding["journal_record_count"],
            "fixed_predecessor": {
                "run_id": predecessor["run_id"],
                "job_record": {"path": predecessor_record_path,
                               "raw_sha256": predecessor_index_rows[0]["raw_sha256"]},
                "receipt": fixed_receipt_pin,
                "receipt_value": predecessor_receipt_value,
                "component_sha256": predecessor_result["component_sha256"],
                "process_metrics_sha256": predecessor_result["process_metrics_sha256"],
                "state": predecessor_result["state"],
            },
            "component_replayed": True,
            "qualification_eligible": False,
        }
    finally:
        for module in reversed(list(modules.values())):
            _close_module(module)


def _soak_component_replay(
    request: dict[str, Any], host: dict[str, Any],
    rows: dict[str, dict[str, Any]], record_row: dict[str, Any],
    auth: dict[str, Any], receipt_row: dict[str, Any],
    modules: dict[str, types.ModuleType],
) -> dict[str, Any]:
    record = record_row["record"]
    evidence = _exact(record["evidence"], {
        "kind", "execution_manifest", "helper_input", "helper_module",
        "soak_component",
    }, "Source5 Soak job evidence")
    _require(evidence["kind"] == "source5_timed_soak",
             "Source5 Soak phase contains a different component kind")
    component_pin = _exact(evidence["soak_component"],
                           {"path", "raw_sha256"},
                           "Source5 Soak component pin")
    component_row = rows.get(component_pin["path"])
    _require(component_row is not None and
             component_row["role"] == "source5_soak_artifact" and
             component_row["raw_sha256"] == component_pin["raw_sha256"],
             "Source5 Soak component is absent from its exact typed evidence role")
    component, _component_raw = _json_entry(
        rows, component_pin["path"], "Source5 Soak component", MAX_JSON_BYTES,
    )
    receipt_value, _receipt_raw = _json_entry(
        rows, receipt_row["path"], "strict Source5 Soak host receipt", MAX_JSON_BYTES,
    )
    _require(receipt_row["component_schema"] == SOAK_HOST_SCHEMA and
             receipt_row["run_id"] == auth["job_run_id"] and
             receipt_value.get("component_sha256") == _digest(_canonical(component)) and
             receipt_value.get("component_pins") == component["pins"],
             "Source5 Soak host receipt differs from its exact component artifact")
    execution_manifest, _manifest_raw = _json_entry(
        rows, request["execution_manifest"]["path"],
        "Source5 execution manifest", MAX_JSON_BYTES,
    )
    original = host["original_pins"].get("original_inputs", host["original_pins"])
    spec_pin = original["spec"]["artifact"]
    plan_pin = original["plan"]["artifact"]
    spec, _spec_raw = _json_entry(rows, spec_pin["path"],
                                  "original Source5 SpecV3", 32 * 1024 * 1024)
    plan, _plan_raw = _json_entry(rows, plan_pin["path"],
                                  "original Source5 PlanV3", MAX_JSON_BYTES)
    source_ref = host["source_manifest_refs"][request["host_id"]]
    source, _source_raw = _json_entry(rows, source_ref["path"],
                                      "selected SourceV5 manifest", 16 * 1024 * 1024)
    completion_pin = execution_manifest["prepared_input_generation"]["completion"]
    completion, _completion_raw = _json_entry(
        rows, completion_pin["path"], "Source5 prepared-input completion",
        16 * 1024 * 1024,
    )
    prepared = {
        "campaign_id": request["campaign_id"], "host_id": request["host_id"],
        "source_root": request["source_root"], "source": source,
        "source_manifest_raw_refs": host["source_manifest_refs"],
        "source5_execution_manifest": execution_manifest,
        "source5_execution_manifest_pin": {
            "path": request["execution_manifest"]["path"],
            "raw_sha256": request["execution_manifest"]["raw_sha256"],
        },
        "source5_prepared_input_completion": completion,
        "prepared": {
            "spec_path": spec_pin["path"], "spec_raw_sha256": spec_pin["raw_sha256"],
            "spec_semantic_sha256": original["spec"]["semantic_sha256"],
            "plan_path": plan_pin["path"], "plan_raw_sha256": plan_pin["raw_sha256"],
            "plan_semantic_sha256": original["plan"]["semantic_sha256"],
        },
    }
    component_root = str(Path(component["pins"]["supervisor"]["path"]).parent)
    evidence_inventory = receipt_value.get("evidence_inventory")
    evidence_bases = receipt_value.get("evidence_bases")
    _require(type(evidence_inventory) is list and type(evidence_bases) is list,
             "Source5 Soak host receipt has no complete typed evidence inventory")
    component_paths = _direct_paths(component, modules["scripts/application-pressure-pair.py"])
    component_paths |= _direct_paths(prepared, modules["scripts/application-pressure-pair.py"])
    component_paths |= _direct_paths(auth, modules["scripts/application-pressure-pair.py"])
    component_paths |= _direct_paths(receipt_value, modules["scripts/application-pressure-pair.py"])
    for index, value in enumerate(evidence_inventory):
        _require(type(value) is dict and value.get("kind") in {"file", "directory"},
                 f"Source5 Soak evidence inventory[{index}] has an unsupported node type")
        row = _exact(value, (
            {"path", "kind", "mode", "size", "raw_sha256"}
            if value["kind"] == "file" else
            {"path", "kind", "mode"}
        ), f"Source5 Soak evidence inventory[{index}]")
        path = _absolute(row["path"], f"Source5 Soak evidence path[{index}]")
        if row["kind"] == "directory":
            component_paths.add(path)
            continue
        store_row = rows.get(path)
        _require(store_row is not None and
                 store_row["raw_sha256"] == row["raw_sha256"] and
                 store_row["byte_count"] == row["size"],
                 f"Source5 Soak evidence inventory is not closed over its exact index role: {path}")
        component_paths.add(path)
    for index, value in enumerate(evidence_bases):
        component_paths.add(_absolute(value, f"Source5 Soak evidence base[{index}]"))
    component_paths.add(component_pin["path"])
    component_paths.add(receipt_row["path"])
    for source_manifest in host["indexed_direct_refs"]:
        if source_manifest["role"] == "source_manifest":
            component_paths.add(source_manifest["path"])
            component_paths |= _source_manifest_file_paths(
                request, rows, source_manifest["path"],
            )
    probe_receipt_pin = receipt_value["construction_probe"]["receipt_pin"]
    probe_root = str(Path(probe_receipt_pin["path"]).parent)
    path_map, file_rows, snapshots = _selected_files_for_component(
        request, host, rows, record, auth, receipt_row, component_paths,
        {component_root, probe_root},
    )
    soak = modules.get("scripts/application-source5-soak.py")
    _require(soak is not None and callable(getattr(
        soak, "verify_source5_soak_component_offline", None,
    )), "captured Source5 Soak adapter has no strict offline component API")
    try:
        soak.verify_source5_soak_component_offline(
            component, prepared, auth["job"], auth,
            {"path": receipt_row["path"],
             "raw_sha256": receipt_row["raw_sha256"],
             "receipt_sha256": receipt_row["semantic_sha256"]},
            replay_context={
                "schema": "allocatbelt.application-source5-soak-offline-replay-context.v1",
                "evidence_path_map": path_map,
            },
        )
    except Exception as error:
        _verify_local_snapshot(file_rows, snapshots)
        message = str(error)
        if "source5_soak_bounded_acceptance_blocked" in message:
            component_sha = _digest(_canonical(component))
            process_metrics = record["process_metrics"]
            _require(record["state"] == "valid_soak" and
                     process_metrics == [component["readback"]] and
                     component_sha == record["chronology"]["component_sha256"] and
                     _digest(_canonical(process_metrics)) ==
                        record["chronology"]["process_metrics_sha256"],
                     "Soak component/metrics do not match the exact source5 terminal")
            return {
                "state": record["state"], "component": component,
                "component_sha256": component_sha,
                "process_metrics": process_metrics,
                "process_metrics_sha256": _digest(_canonical(process_metrics)),
                "component_replayed": True,
                "acceptance_blocked": "prospective_bounded_soak_resource_budget_not_pinned",
            }
        raise Source5OfflineDispatchError(
            f"Source5 Soak offline replay failed: {type(error).__name__}: {error}",
        ) from error
    raise Source5OfflineDispatchError(
        "Source5 Soak offline verifier returned without its required bounded-budget blocker",
    )


def verify_source5_job_artifacts_offline(
    request: object, captured_evidence: object, job_record_pin: object,
) -> dict[str, Any]:
    """Reconstruct one original fixed, pressure, or Soak job from exact bytes."""
    rows = _store_rows(captured_evidence)
    req, index, rows, source_symlink_snapshots = _index_and_manifest_preflight(
        request, rows,
    )
    _validate_active_dispatcher(req, rows)
    chronology = _load_pinned_module(
        req, index, rows, "scripts/application-campaign-chronology.py",
    )
    _verify_local_source_symlink_snapshots(rows, source_symlink_snapshots)
    modules: dict[str, types.ModuleType] = {"chronology": chronology}
    try:
        host = chronology.verify_source5_host_journal_offline(req, captured_evidence)
        record_row = _indexed_record(host, job_record_pin)
        auth, finished = _unique_job_rows(
            host, record_row["phase"], record_row["job_run_id"],
        )
        record = _validate_auth_record_binding(req, record_row, auth, finished)
        _require(finished["job_terminal"]["component_replay_required"] is True and
                 host["component_dispatch_pending"] is True,
                 "structural journal result cannot replace a component replay")
        component_schema = {
            "exploration": FIXED_HOST_SCHEMA,
            "aa": FIXED_HOST_SCHEMA,
            "confirmation": FIXED_HOST_SCHEMA,
            "pressure": PRESSURE_HOST_SCHEMA,
            "soak": SOAK_HOST_SCHEMA,
        }.get(auth["phase"])
        _require(component_schema is not None,
                 "job phase has no closed offline component dispatcher")
        receipt_row = _component_receipt(host, auth["job_run_id"], component_schema)
        component_modules = _load_component_modules(req, index, rows)
        modules.update(component_modules)
        _verify_local_source_symlink_snapshots(rows, source_symlink_snapshots)
        local_file_rows: list[dict[str, Any]] = []
        local_snapshots: dict[str, tuple[int, ...]] = {}
        if auth["phase"] in {"exploration", "aa", "confirmation"}:
            result = _fixed_component_replay(
                req, host, rows, record_row, auth, receipt_row, chronology,
                types.SimpleNamespace(
                    fixed_pair_module=component_modules[
                        "scripts/application-fixed-pair.py"],
                    _pair_absolute_paths=component_modules[
                        "scripts/application-pressure-pair.py"]._pair_absolute_paths,
                ),
            )
        elif auth["phase"] == "pressure":
            evidence = _exact(record["evidence"], {
                "kind", "execution_manifest", "helper_input", "helper_module",
                "recipe", "overlay", "readback", "processes",
                "fixed_predecessor", "source_snapshot",
            }, "Source5 pressure job evidence")
            context = {
                "schema": CONTEXT_SCHEMA,
                "request": req,
                "captured_evidence": captured_evidence,
                "job_record_pin": {"path": record_row["path"],
                                   "raw_sha256": record_row["raw_sha256"]},
            }
            pressure_module = component_modules[
                "scripts/application-pressure-pair.py"]
            pressure_host_pin = {
                "path": receipt_row["path"],
                "raw_sha256": receipt_row["raw_sha256"],
                "receipt_sha256": receipt_row["semantic_sha256"],
            }
            recipe_value, _recipe_raw = _json_entry(
                rows, evidence["recipe"]["path"],
                "Source5 pressure recipe", MAX_JSON_BYTES,
            )
            sidecar_value, _sidecar_raw = _json_entry(
                rows, evidence["readback"]["path"],
                "Source5 pressure readback", MAX_JSON_BYTES,
            )
            host_receipt_value, _host_receipt_raw = _json_entry(
                rows, receipt_row["path"],
                "strict pressure host receipt", MAX_JSON_BYTES,
            )
            path_map, local_file_rows, local_snapshots = \
                _pressure_component_path_map(
                    req, host, rows, record, auth, receipt_row,
                    pressure_module, recipe_value, sidecar_value,
                    host_receipt_value,
                )
            replay = pressure_module.validate_pressure_pair_artifacts_offline(
                evidence["recipe"], record["pair_directory"], evidence["readback"],
                pressure_host_pin, path_map,
                source5_journal_context=context,
            )
            _verify_local_snapshot(local_file_rows, local_snapshots)
            pressure_receipt = _json_entry(
                rows, receipt_row["path"],
                "strict pressure host receipt", MAX_JSON_BYTES,
            )[0]
            starts = auth.get("starts")
            _require(type(starts) is list and len(starts) == 2 and
                     type(pressure_receipt.get("member_facts")) is list and
                     len(pressure_receipt["member_facts"]) == 2,
                     "pressure APP start callbacks/host facts are not a complete ordered pair")
            for member_index, (start_row, host_fact) in enumerate(zip(
                    starts, pressure_receipt["member_facts"], strict=True)):
                event = start_row.get("event_details")
                _require(type(event) is dict and
                         event.get("descriptor") ==
                            pressure_receipt["member_facts"][member_index]["descriptor"] and
                         event["proof"]["pid"] ==
                            host_fact["application_identity"]["pid"] and
                         event["proof"]["start_ticks"] ==
                            host_fact["application_identity"]["start_ticks"],
                         "pressure direct APP PID/start differs from its durable Source5 start callback")
            _require(type(replay) is dict and replay.get("schema") ==
                     "allocatbelt.application-pressure-pair-readback.v1",
                     "pressure-pair offline reader returned no complete Source5 readback")
            result = _pressure_result_from_readback(
                record_row, auth, receipt_row, evidence, replay,
            )
        else:
            result = _soak_component_replay(
                req, host, rows, record_row, auth, receipt_row, component_modules,
            )
        _require(result["component_sha256"] ==
                 finished["job_terminal"]["details"]["component_sha256"] and
                 result["process_metrics_sha256"] ==
                 finished["job_terminal"]["details"]["process_metrics_sha256"] and
                 result["process_metrics"] == record["process_metrics"],
                 "reconstructed component and metrics differ from the exact Source5 journal terminal")
        _verify_local_source_symlink_snapshots(rows, source_symlink_snapshots)
        post_host = chronology.verify_source5_host_journal_offline(
            req, captured_evidence,
        )
        _require(post_host["journal"] == host["journal"] and
                 post_host["source5_authorizations"] ==
                    host["source5_authorizations"] and
                 post_host["source5_finished"] == host["source5_finished"] and
                 post_host["evidence_index"] == host["evidence_index"],
                 "captured Source5 store changed during component dispatch")
        return {
            "schema": RESULT_SCHEMA,
            "campaign_id": req["campaign_id"], "host_id": req["host_id"],
            "phase": auth["phase"], "job_index": auth["job_index"],
            "job": auth["job"], "job_record": {
                "path": record_row["path"],
                "raw_sha256": record_row["raw_sha256"],
                "semantic_sha256": record_row["semantic_sha256"],
            },
            "state": result["state"], "component": result["component"],
            "component_sha256": result["component_sha256"],
            "process_metrics": result["process_metrics"],
            "process_metrics_sha256": result["process_metrics_sha256"],
            "component_replayed": True,
            "qualification_eligible": False,
            "execution_ready": False,
            **({"acceptance_blocked": result["acceptance_blocked"]}
               if result.get("acceptance_blocked") is not None else {}),
        }
    finally:
        for module in reversed(list(modules.values())):
            _close_module(module)


def _pressure_result_from_readback(
    record_row: dict[str, Any], auth: dict[str, Any], receipt_row: dict[str, Any],
    evidence: dict[str, Any], replay: dict[str, Any],
) -> dict[str, Any]:
    record = record_row["record"]
    process_metrics = replay.get("pressure_metrics")
    _require(type(process_metrics) is list and len(process_metrics) == 2 and
             replay.get("validated") is True and
             replay.get("qualification_eligible") is False and
             replay.get("execution_ready") is False,
             "pressure replay is not the complete component-only two-member result")
    component = {
        "schema": "allocatbelt.application-source5-pressure-component.v1",
        "validated": True,
        "qualification_eligible": False,
        "recipe": evidence["recipe"],
        "overlay": evidence["overlay"],
        "readback": evidence["readback"],
        "processes": evidence["processes"],
        "pressure_metrics": process_metrics,
    }
    component_sha = _digest(_canonical(component))
    metrics_sha = _digest(_canonical(process_metrics))
    _require(replay.get("readback_sha256") ==
             evidence["readback"]["raw_sha256"] and
             replay.get("processes_sha256") ==
             evidence["processes"]["raw_sha256"] and
             len(replay.get("application_identities", [])) == 2 and
             auth["phase"] == "pressure" and receipt_row["run_id"] ==
             auth["job_run_id"] and
             record["state"] == "valid_pair",
             "pressure readback differs from exact Source5 host/job member bindings")
    return {
        "state": "valid_pair", "component": component,
        "component_sha256": component_sha,
        "process_metrics": process_metrics,
        "process_metrics_sha256": metrics_sha,
        "readback": replay,
    }
