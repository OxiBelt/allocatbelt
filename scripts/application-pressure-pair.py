#!/usr/bin/env python3
"""Run and independently read back one original SourceV5 pressure pair.

The runner consumes an immutable pressure-pair recipe. It never edits the
campaign plan or manufactures execution readiness. Every APP is launched
directly under the SourceV5 pressure-first supervisor, and qualification stays
false until the surrounding campaign has validated every planned job.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import time
import types
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any


RECIPE_SCHEMA = "allocatbelt.application-pressure-pair-recipe.v1"
RECIPE_SCHEMA_V2 = "allocatbelt.application-pressure-pair-recipe.v2"
POLICY_SCHEMA = "allocatbelt.application-pressure-pair-policy.v1"
READBACK_SCHEMA = "allocatbelt.application-pressure-pair-readback.v1"
SOURCE5_HELPER_INPUT_SCHEMA = "allocatbelt.application-source5-helper-input.v1"
SOURCE5_PRESSURE_HELPER_PAYLOAD_SCHEMA_V2 = "allocatbelt.application-source5-pressure-helper-payload.v2"
SOURCE5_PROBE_CAPTURE_BUNDLE_SCHEMA_V1 = "allocatbelt.application-source5-probe-capture-bundle.v1"
OFFLINE_CALIBRATION_CONTEXT_SCHEMA = "allocatbelt.application-pressure-calibration-offline-context.v1"
EXECUTION_OVERLAY_SCHEMA = "allocatbelt.application-pressure-pair-execution-overlay.v1"
PAIR_PROCESS_FILE = "processes.tsv"
PAIR_READBACK_FILE = "pressure-pair-readback.json"
APP_DESCRIPTOR_SCHEMA = "allocatbelt.application-pressure-app-descriptor.v1"
PAIR_PROCESS_HEADER_FALLBACK = (
    "pair executor allocator exit_code row_validation p99_qualification argv stdout time_report ids_sha256 "
    "shutdown_sha256 capacity_family_sha256 stdout_sha256 runtime_readback runtime_readback_sha256 "
    "runtime_expectation runtime_expectation_sha256 runtime_validation runtime_validation_sha256 "
    "runtime_recipe_sha256 resource_ceiling_sha256 policy_sha256 fixed_global_control_baseline "
    "validator_sha256 source_manifest_sha256 calibration_binary_sha256 calibration_output_sha256"
).split()

ALLOCATORS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
EXECUTOR_LABELS = {"bounded": "allocatbelt", "tokio": "tokio-1.53.1"}
U64_MAX = (1 << 64) - 1
U128_MAX = (1 << 128) - 1
MAX_RECIPE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_SMALL_BYTES = 1024 * 1024
MAX_PROBE_CAPTURE_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_PROBE_CAPTURE_TIMEOUT_NS = 30_000_000_000
MAX_PROBE_CAPTURE_TMPDIR_BYTES = 1024 * 1024 * 1024
MAX_PROBE_CAPTURE_TMPDIR_INODES = 4096
MAX_PROBE_CAPTURE_STDOUT_BYTES = 512 * 1024
MAX_PROBE_CAPTURE_STDERR_BYTES = 64 * 1024
PROBE_CAPTURE_OWNER_RESULT_BYTES = 16 * 1024 * 1024
PROBE_CAPTURE_INVENTORY_BYTES = 16 * 1024 * 1024
PROBE_CAPTURE_FAILURE_BYTES = 64 * 1024
PROBE_CAPTURE_MIN_OUTPUT_INODES = 7
PROBE_CAPTURE_MAX_OUTPUT_INODES = 4096
MAX_TRACE_BYTES = 512 * 1024 * 1024
MAX_SAMPLE_BYTES = 96 * 1024 * 1024
MAX_TERMINAL_BYTES = 32 * 1024 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024
MAX_SOURCE5_CAPTURE_BYTES = 1024 * 1024 * 1024
MAX_SOURCE5_CAPTURE_ENTRIES = 800_000
MAX_SOURCE5_TYPED_SOURCE_FILES = 100_000
MAX_SOURCE5_TYPED_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_SOURCE5_TYPED_SYMLINK_BYTES = 4 * 1024
SOURCE5_CAPTURED_SCHEMA = "allocatbelt.application-source5-captured-evidence.v1"
SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA = "allocatbelt.application-source5-host-journal-request.v1"
SOURCE5_EVIDENCE_INDEX_SCHEMA = "allocatbelt.application-source5-journal-evidence-index.v1"
SOURCE5_OFFLINE_DISPATCH_RELATIVE = "scripts/application-source5-offline-dispatch.py"
SOURCE5_ROLE_LIMITS = {
    "evidence_index": MAX_PLAN_BYTES,
    "origin_receipt": 16 * 1024 * 1024,
    "journal": MAX_SOURCE5_CAPTURE_BYTES,
    "execution_manifest": MAX_PLAN_BYTES,
    "preparation": 16 * 1024 * 1024,
    "prepared_completion": 16 * 1024 * 1024,
    "spec_v3": MAX_SPEC_BYTES,
    "plan_v3": MAX_PLAN_BYTES,
    "source_manifest": MAX_MANIFEST_BYTES,
    "observed_host": MAX_MANIFEST_BYTES,
    "typed_source_file": MAX_SOURCE_BYTES,
    "typed_source_symlink": MAX_SOURCE5_TYPED_SYMLINK_BYTES,
    "capacity_completion": 16 * 1024 * 1024,
    "capacity_ledger": 256 * 1024 * 1024,
    "capacity_request": MAX_PLAN_BYTES,
    "capacity_artifact": MAX_PLAN_BYTES,
    "capacity_receipt": MAX_PLAN_BYTES,
    "source5_helper_input": MAX_PLAN_BYTES,
    "source5_job_record": 4 * 1024 * 1024,
    "capacity_host_receipt": 16 * 1024 * 1024,
    "component_receipt": MAX_PLAN_BYTES,
    "fixed_pair_artifact": MAX_BINARY_BYTES,
    "pressure_pair_artifact": MAX_BINARY_BYTES,
    "source5_soak_artifact": MAX_BINARY_BYTES,
    "normal_app_output": MAX_BINARY_BYTES,
    "analysis_artifact": 4 * 1024 * 1024,
    "opaque_trace": MAX_BINARY_BYTES,
}
V5_SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v5"
V5_SPEC_SCHEMA = "allocatbelt.application-campaign-spec.v3"
V5_PLAN_SCHEMA = "allocatbelt.application-campaign-plan.v3"


class PressurePairError(ValueError):
    """A SourceV5 input, live APP, pressure proof, or paired readback is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PressurePairError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise PressurePairError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value: object, label: str = "SHA-256") -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, f"{label} is malformed")
    return value


def digest_object(value: object) -> str:
    return sha256_bytes(canonical_bytes(value))


def _source5_capture_chunks(value: object, count: int, label: str):
    require(type(count) is int and 0 <= count <= MAX_SOURCE5_CAPTURE_BYTES,
            f"{label} byte count exceeds the captured-store bound")
    if type(value) is bytes:
        require(len(value) == count, f"{label} captured byte count differs")
        for offset in range(0, count, 1024 * 1024):
            yield value[offset:offset + 1024 * 1024]
        return
    require(type(value) is io.BufferedReader and type(value.raw) is io.FileIO and
            value.readable() and not value.writable() and value.seekable() and
            value.raw.mode == "rb",
            f"{label} is not immutable bytes or a read-only seekable stream")
    try:
        value.seek(0)
        remaining = count
        while remaining:
            block = value.read(min(1024 * 1024, remaining))
            require(type(block) is bytes and bool(block),
                    f"{label} stream ended before its declared byte count")
            remaining -= len(block)
            yield block
        require(value.read(1) == b"", f"{label} stream has trailing bytes")
    except (OSError, ValueError) as error:
        raise PressurePairError(f"cannot read {label} captured bytes: {error}") from error


def _source5_capture_digest(row: dict[str, Any]) -> str:
    limit = SOURCE5_ROLE_LIMITS.get(row.get("role"))
    require(limit is not None and type(row.get("byte_count")) is int and
            0 <= row["byte_count"] <= limit,
            "captured Source5 entry has an unknown role or exceeds its exact role cap")
    hasher = hashlib.sha256()
    total = 0
    for block in _source5_capture_chunks(
            row.get("raw_bytes"), row["byte_count"],
            f"Source5 {row['role']} {row['origin_path']}"):
        total += len(block)
        require(total <= limit,
                f"captured Source5 {row['role']} exceeds its role byte cap")
        hasher.update(block)
    actual = hasher.hexdigest()
    require(total == row["byte_count"] and actual == row["raw_sha256"],
            f"captured Source5 {row['role']} bytes differ from their raw pin")
    return actual


def _source5_capture_bytes(row: dict[str, Any], maximum: int, label: str) -> bytes:
    require(row["byte_count"] <= maximum and
            row["byte_count"] <= SOURCE5_ROLE_LIMITS[row["role"]],
            f"{label} exceeds its exact captured role/parser ceiling")
    pieces: list[bytes] = []
    hasher = hashlib.sha256()
    total = 0
    for block in _source5_capture_chunks(row["raw_bytes"], row["byte_count"], label):
        total += len(block)
        require(total <= maximum, f"{label} exceeds its bounded parser ceiling")
        pieces.append(block)
        hasher.update(block)
    raw = b"".join(pieces)
    require(total == row["byte_count"] and hasher.hexdigest() == row["raw_sha256"],
            f"{label} differs from its exact captured raw pin")
    return raw


def _source5_capture_json(
    rows: dict[str, dict[str, Any]], path: str, label: str, maximum: int,
) -> tuple[dict[str, Any], bytes]:
    row = rows.get(path)
    require(row is not None, f"captured Source5 store omits {label}: {path}")
    raw = _source5_capture_bytes(row, maximum, label)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PressurePairError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict and raw == canonical_bytes(value),
            f"{label} is not one canonical JSON object")
    return value, raw


def _source5_absolute_path(value: object, label: str) -> str:
    path_text = text(value, label, 4096)
    path = Path(path_text)
    require(path.is_absolute() and str(path) == os.path.normpath(path_text) and
            ".." not in path.parts,
            f"{label} is not a normalized original absolute path")
    return path_text


def _source5_source_inventory(
    manifest: dict[str, Any], label: str,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    source = exact(manifest.get("source"), {
        "git_commit", "source_tree_sha256", "cargo_lock_sha256", "files",
    }, f"{label} typed source inventory")
    files = source["files"]
    require(type(files) is list and 0 < len(files) <= MAX_SOURCE5_TYPED_SOURCE_FILES,
            f"{label} source inventory is empty or exceeds its file-count cap")
    normalized: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    previous = b""
    total = 0
    for position, value in enumerate(files):
        require(type(value) is dict,
                f"{label} source inventory row[{position}] is not an object")
        kind = value.get("kind")
        fields = {"path", "kind", "mode", "sha256", "size"}
        if kind == "symlink":
            fields.add("target")
        item = exact(value, fields, f"{label} source inventory row[{position}]")
        relative = PurePosixPath(item["path"])
        require(type(item["path"]) is str and item["path"] and
                not relative.is_absolute() and relative.as_posix() == item["path"] and
                ".." not in relative.parts and "\\" not in item["path"] and
                "\n" not in item["path"] and "\r" not in item["path"] and
                "\x00" not in item["path"] and
                item["path"] not in by_path,
                f"{label} source inventory row[{position}] has an aliased path")
        try:
            encoded_path = item["path"].encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise PressurePairError(f"{label} source path is not UTF-8") from error
        require(encoded_path > previous,
                f"{label} source paths are not UTF-8 byte sorted")
        previous = encoded_path
        digest(item["sha256"], f"{label} source digest[{position}]")
        require(type(item["size"]) is int and item["size"] >= 0,
                f"{label} source size[{position}] is malformed")
        if kind == "file":
            require(item["mode"] in {"100644", "100755"} and
                    item["size"] <= MAX_SOURCE_BYTES,
                    f"{label} regular source row[{position}] exceeds its mode/size cap")
            record = {"path": item["path"], "kind": "file", "mode": item["mode"],
                      "sha256": item["sha256"], "size": item["size"]}
        else:
            require(kind == "symlink" and item["mode"] == "120000" and
                    type(item["target"]) is str,
                    f"{label} symlink row[{position}] is malformed")
            try:
                target_bytes = item["target"].encode("utf-8", "strict")
            except UnicodeEncodeError as error:
                raise PressurePairError(f"{label} symlink target is not UTF-8") from error
            require(0 < len(target_bytes) <= MAX_SOURCE5_TYPED_SYMLINK_BYTES and
                    item["size"] == len(target_bytes) and
                    sha256_bytes(target_bytes) == item["sha256"] and
                    not item["target"].startswith("/") and
                    "\\" not in item["target"] and "\x00" not in item["target"] and
                    "\n" not in item["target"] and "\r" not in item["target"],
                    f"{label} symlink target hash/size/text differs")
            record = {"path": item["path"], "kind": "symlink", "mode": "120000",
                      "target": item["target"], "sha256": item["sha256"],
                      "size": item["size"]}
        total += item["size"]
        require(total <= MAX_SOURCE5_TYPED_SOURCE_BYTES,
                f"{label} source inventory exceeds its aggregate size cap")
        normalized.append(record)
        by_path[item["path"]] = record

    symlinks = {path for path, record in by_path.items()
                if record["kind"] == "symlink"}
    for path, record in by_path.items():
        parts = path.split("/")
        for position in range(1, len(parts)):
            parent = "/".join(parts[:position])
            require(parent not in by_path and parent not in symlinks,
                    f"{label} source path has a non-directory parent: {path}")
        if record["kind"] != "symlink":
            continue
        resolved = path.split("/")[:-1]
        target_parts = record["target"].split("/")
        require(all(target_parts), f"{label} symlink target is not normalized: {path}")
        for position, token_value in enumerate(target_parts):
            if token_value == ".":
                continue
            if token_value == "..":
                require(bool(resolved), f"{label} symlink escapes source root: {path}")
                resolved.pop()
            else:
                resolved.append(token_value)
                if position < len(target_parts) - 1:
                    require("/".join(resolved) not in by_path,
                            f"{label} symlink traverses a non-directory: {path}")
        target = by_path.get("/".join(resolved))
        require(target is not None and target["kind"] == "file",
                f"{label} symlink does not target a regular Source.files member: {path}")
    expected_tree = sha256_bytes(canonical_bytes({
        "schema": "allocatbelt.application-source-inventory.v1",
        "entries": normalized,
    }))
    require(source.get("source_tree_sha256") == expected_tree,
            f"{label} source-tree digest differs from its normalized typed inventory")
    return normalized, by_path


def _source5_manifest_artifacts(
    manifest: dict[str, Any], inventory: dict[str, dict[str, Any]], label: str,
) -> list[tuple[str, str, str]]:
    allocators = {"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"}
    result: dict[str, tuple[str, str]] = {}

    def add(value: object, role: str, item_label: str) -> None:
        item = exact(value, {"path", "sha256"}, item_label)
        relative = PurePosixPath(item["path"])
        require(type(item["path"]) is str and not relative.is_absolute() and
                relative.as_posix() == item["path"] and ".." not in relative.parts and
                "\\" not in item["path"],
                f"{item_label} path is not normalized and relative")
        raw_sha = digest(item["sha256"], f"{item_label} raw SHA-256")
        prior = result.get(relative.as_posix())
        expected = (role, raw_sha)
        require(prior is None or prior == expected,
                f"{label} aliases an artifact path under incompatible roles")
        result[relative.as_posix()] = expected

    applications = exact(manifest.get("artifacts"), allocators,
                         f"{label} four-allocator artifacts")
    for allocator, value in applications.items():
        add(value, "normal_app_output", f"{label} {allocator} application artifact")
    soak = manifest.get("soak_artifacts")
    require(type(soak) is dict and "allocatbelt" in soak and
            set(soak).issubset(allocators),
            f"{label} Soak artifact map omits the candidate or names an unknown allocator")
    for allocator, value in soak.items():
        add(value, "source5_soak_artifact", f"{label} {allocator} Soak artifact")
    add(manifest.get("analysis_artifact"), "analysis_artifact",
        f"{label} native analyzer artifact")
    calibration = exact(manifest.get("resource_domain_calibration"), {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, f"{label} resource-domain calibration")
    for name in ("binary", "output"):
        add(calibration[name], "capacity_artifact",
            f"{label} calibration {name}")
    runtime = exact(manifest.get("runtime_readback_validator"), {"path", "sha256"},
                    f"{label} runtime readback validator")
    runtime_path = PurePosixPath(runtime["path"])
    digest(runtime["sha256"], f"{label} runtime validator raw SHA-256")
    runtime_record = inventory.get(runtime_path.as_posix())
    require(not runtime_path.is_absolute() and runtime_path.as_posix() == runtime["path"] and
            ".." not in runtime_path.parts and runtime_record is not None and
            runtime_record["kind"] == "file" and
            runtime_record["sha256"] == runtime["sha256"],
            f"{label} runtime validator is not one exact typed regular source file")
    return [(path, role, raw_sha) for path, (role, raw_sha) in sorted(result.items())]


def _source5_read_local_digest(
    path_value: str, label: str, maximum: int,
) -> tuple[str, int, os.stat_result]:
    path = Path(path_value)
    try:
        path_before = path.lstat()
        require(stat.S_ISREG(path_before.st_mode),
                f"{label} is not a regular nonsymlink file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise PressurePairError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and
                _stat_key(before) == _stat_key(path_before) and
                0 <= before.st_size <= maximum,
                f"{label} changed while opening or exceeds its exact role cap")
        count = 0
        hasher = hashlib.sha256()
        while count < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated while hashing")
            count += len(block)
            hasher.update(block)
        after = os.fstat(fd)
        path_after = path.lstat()
        require(_stat_key(before) == _stat_key(after) == _stat_key(path_after) and
                count == before.st_size,
                f"{label} changed during bounded hash verification")
        return hasher.hexdigest(), count, before
    finally:
        os.close(fd)


def _verify_source5_local_symlinks(
    *, rows: dict[str, dict[str, Any]],
    snapshots: dict[str, tuple[int, ...]],
) -> None:
    for path, prior in snapshots.items():
        row = rows.get(path)
        require(row is not None and row["role"] == "typed_source_symlink",
                f"captured Source5 symlink row disappeared: {path}")
        expected_target = _source5_capture_bytes(
            row, MAX_SOURCE5_TYPED_SYMLINK_BYTES,
            f"captured Source5 literal symlink target {path}",
        )
        try:
            before = Path(path).lstat()
            target = os.readlink(path)
            target_bytes = target.encode("utf-8", "strict")
            after = Path(path).lstat()
        except (OSError, UnicodeError) as error:
            raise PressurePairError(f"cannot recheck Source5 literal symlink {path}: {error}") from error
        signature = (
            before.st_dev, before.st_ino, before.st_uid, before.st_gid,
            before.st_mode, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns,
            int.from_bytes(hashlib.sha256(target_bytes).digest(), "big"),
        )
        after_signature = (
            after.st_dev, after.st_ino, after.st_uid, after.st_gid,
            after.st_mode, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns,
            int.from_bytes(hashlib.sha256(target_bytes).digest(), "big"),
        )
        require(stat.S_ISLNK(before.st_mode) and signature == after_signature == prior and
                target_bytes == expected_target,
                f"Source5 literal symlink changed during pressure replay: {path}")


def _source5_preflight_capture_context(
    context_value: object, path_map_value: object,
) -> dict[str, Any]:
    """Verify Source.files/artifact row closure before compiling captured modules."""
    context = exact(context_value, {
        "schema", "request", "captured_evidence", "job_record_pin",
    }, "closed Source5 pressure journal context")
    require(context["schema"] == "allocatbelt.application-source5-pressure-journal-context.v1",
            "offline Source5 pressure context schema differs")
    request = exact(context["request"], {
        "schema", "scope", "campaign_id", "host_id", "source_root",
        "input_root", "output_root", "execution_manifest", "provenance",
        "journal", "origin_receipt", "evidence_index",
    }, "Source5 host-journal request")
    require(request["schema"] == SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA and
            request["scope"] in {"prospective_exploration", "final_prepared",
                                 "final_prepared_bounded"},
            "Source5 host-journal request schema/scope differs")
    for key in ("campaign_id", "host_id"):
        token(request[key], f"Source5 {key}")
    roots = {key: _source5_absolute_path(request[key], f"Source5 {key}")
             for key in ("source_root", "input_root", "output_root")}
    store = exact(context["captured_evidence"], {"schema", "entries"},
                  "captured Source5 identity store")
    require(store["schema"] == SOURCE5_CAPTURED_SCHEMA and
            type(store["entries"]) is list and
            0 < len(store["entries"]) <= MAX_SOURCE5_CAPTURE_ENTRIES,
            "captured Source5 store schema/count is invalid")
    capture_rows: dict[str, dict[str, Any]] = {}
    previous = ""
    for position, value in enumerate(store["entries"]):
        row = exact(value, {
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count", "raw_bytes",
        }, f"captured Source5 row[{position}]")
        origin = _source5_absolute_path(row["origin_path"],
                                        f"captured Source5 origin[{position}]")
        local = _source5_absolute_path(row["local_path"],
                                       f"captured Source5 local[{position}]")
        require(origin == local and origin > previous and origin not in capture_rows,
                "captured Source5 paths are not sorted identity mappings")
        previous = origin
        require(row["role"] in SOURCE5_ROLE_LIMITS and
                (row["host_id"] is None or
                 (type(row["host_id"]) is str and bool(row["host_id"]))),
                "captured Source5 row role/host is malformed")
        digest(row["raw_sha256"], f"captured Source5 raw digest[{position}]")
        semantic = row["semantic_sha256"]
        require(semantic is None or
                (type(semantic) is str and re.fullmatch(r"[0-9a-f]{64}", semantic)),
                f"captured Source5 semantic digest[{position}] is malformed")
        require(type(row["byte_count"]) is int and
                0 <= row["byte_count"] <= SOURCE5_ROLE_LIMITS[row["role"]],
                f"captured Source5 row[{position}] exceeds its role cap")
        capture_rows[origin] = row

    index_pin = exact(request["evidence_index"],
                      {"path", "raw_sha256", "semantic_sha256"},
                      "Source5 evidence-index pin")
    _source5_absolute_path(index_pin["path"], "Source5 evidence-index path")
    digest(index_pin["raw_sha256"], "Source5 evidence-index raw SHA-256")
    digest(index_pin["semantic_sha256"], "Source5 evidence-index semantic SHA-256")
    index_capture = capture_rows.get(index_pin["path"])
    require(index_capture is not None and index_capture["role"] == "evidence_index" and
            index_capture["raw_sha256"] == index_pin["raw_sha256"] and
            index_capture["semantic_sha256"] == index_pin["semantic_sha256"],
            "captured Source5 evidence index differs from its exact external pin")
    index, index_raw = _source5_capture_json(
        capture_rows, index_pin["path"], "Source5 evidence index", MAX_PLAN_BYTES,
    )
    index = exact(index, {
        "schema", "campaign_id", "host_id", "source_root", "input_root",
        "output_root", "entries", "index_sha256",
    }, "Source5 evidence index")
    body = {key: value for key, value in index.items() if key != "index_sha256"}
    require(index["schema"] == SOURCE5_EVIDENCE_INDEX_SCHEMA and
            index["campaign_id"] == request["campaign_id"] and
            index["host_id"] == request["host_id"] and
            index["source_root"] == roots["source_root"] and
            index["input_root"] == roots["input_root"] and
            index["output_root"] == roots["output_root"] and
            index["index_sha256"] == index_pin["semantic_sha256"] ==
            digest_object(body) and index_raw == canonical_bytes(index),
            "Source5 evidence-index roots/self-digest differ from its original request")
    require(type(index["entries"]) is list and
            len(index["entries"]) <= MAX_SOURCE5_CAPTURE_ENTRIES,
            "Source5 evidence-index entry count exceeds its finite bound")
    index_rows: dict[str, dict[str, Any]] = {}
    previous = ""
    for position, value in enumerate(index["entries"]):
        row = exact(value, {
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count",
        }, f"Source5 evidence-index row[{position}]")
        path = _source5_absolute_path(row["origin_path"],
                                      f"Source5 evidence-index path[{position}]")
        require(row["local_path"] == path and path > previous and
                path not in index_rows and row["role"] in SOURCE5_ROLE_LIMITS,
                "Source5 evidence index has an alias, duplicate, or unknown role")
        previous = path
        digest(row["raw_sha256"], f"Source5 evidence-index raw hash[{position}]")
        semantic = row["semantic_sha256"]
        require(semantic is None or
                (type(semantic) is str and re.fullmatch(r"[0-9a-f]{64}", semantic)),
                f"Source5 evidence-index semantic hash[{position}] is malformed")
        require(type(row["byte_count"]) is int and
                0 <= row["byte_count"] <= SOURCE5_ROLE_LIMITS[row["role"]],
                f"Source5 evidence-index row[{position}] exceeds its role cap")
        index_rows[path] = row

    origin_pin = exact(request["origin_receipt"],
                       {"path", "raw_sha256", "semantic_sha256"},
                       "Source5 origin-journal receipt pin")
    _source5_absolute_path(origin_pin["path"], "Source5 origin-journal receipt path")
    digest(origin_pin["raw_sha256"], "Source5 origin-receipt raw hash")
    digest(origin_pin["semantic_sha256"], "Source5 origin-receipt semantic hash")
    require(origin_pin["path"] not in index_rows and index_pin["path"] not in index_rows and
            set(capture_rows) == set(index_rows) | {index_pin["path"], origin_pin["path"]},
            "captured Source5 store is not the exact index/receipt closure")
    for path, indexed in index_rows.items():
        captured = capture_rows[path]
        require(all(captured[key] == indexed[key] for key in (
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count",
        )), f"captured Source5 row differs from its index metadata: {path}")
    origin = capture_rows[origin_pin["path"]]
    require(origin["role"] == "origin_receipt" and
            origin["raw_sha256"] == origin_pin["raw_sha256"] and
            origin["semantic_sha256"] == origin_pin["semantic_sha256"],
            "captured Source5 origin receipt differs from its exact pin")

    execution_pin = exact(request["execution_manifest"],
                          {"path", "raw_sha256", "semantic_sha256"},
                          "Source5 execution-manifest pin")
    execution_row = index_rows.get(execution_pin["path"])
    require(execution_row is not None and execution_row["role"] == "execution_manifest" and
            execution_row["host_id"] == request["host_id"] and
            execution_row["raw_sha256"] == execution_pin["raw_sha256"] and
            execution_row["semantic_sha256"] == execution_pin["semantic_sha256"],
            "Source5 execution manifest is not the exact selected-host index member")
    execution, _execution_raw = _source5_capture_json(
        capture_rows, execution_pin["path"], "Source5 execution manifest", MAX_PLAN_BYTES,
    )
    execution_semantic = execution.get("manifest_sha256")
    require(type(execution_semantic) is str and
            execution_semantic == execution_pin["semantic_sha256"] ==
            digest_object({key: value for key, value in execution.items()
                           if key != "manifest_sha256"}),
            "Source5 execution-manifest semantic digest differs")

    source_rows = [row for row in index_rows.values()
                   if row["role"] == "source_manifest"]
    require(len(source_rows) == 3 and
            len({row["host_id"] for row in source_rows}) == 3,
            "Source5 pressure replay requires three unique indexed host manifests")
    source_docs: dict[str, dict[str, Any]] = {}
    source_inventories: dict[str, dict[str, dict[str, Any]]] = {}
    common_records: list[dict[str, Any]] | None = None
    expected: dict[str, tuple[str, str, int | None, str | None, bytes | None]] = {}

    def expect(path: str, role: str, raw_sha: str, size: int | None,
               mode: str | None = None, target: bytes | None = None) -> None:
        absolute = _source5_absolute_path(path, "Source5 typed closure path")
        value = (role, raw_sha, size, mode, target)
        prior = expected.get(absolute)
        require(prior is None or prior == value,
                f"Source5 path is declared under incompatible source/artifact roles: {absolute}")
        expected[absolute] = value

    for source_row in source_rows:
        source_doc, source_raw = _source5_capture_json(
            capture_rows, source_row["origin_path"],
            "Source5 host manifest before any nested reads", MAX_MANIFEST_BYTES,
        )
        semantic = source_doc.get("manifest_sha256")
        require(type(semantic) is str and
                semantic == source_row["semantic_sha256"] ==
                digest_object({key: value for key, value in source_doc.items()
                               if key != "manifest_sha256"}) and
                source_doc.get("build", {}).get("host_id") == source_row["host_id"] and
                source_raw == canonical_bytes(source_doc),
                "Source5 host manifest raw/semantic/host identity differs")
        host_id = source_row["host_id"]
        require(type(host_id) is str and host_id not in source_docs,
                "Source5 host manifest IDs are missing or duplicated")
        source_docs[host_id] = source_doc
        normalized, inventory = _source5_source_inventory(
            source_doc, f"Source5 host {host_id}",
        )
        if common_records is None:
            common_records = normalized
        else:
            require(normalized == common_records,
                    "Source5 host manifests do not share one exact Source.files inventory")
        source_inventories[host_id] = inventory
        for record in normalized:
            relative = PurePosixPath(record["path"])
            path = str(Path(roots["source_root"]).joinpath(*relative.parts))
            if record["kind"] == "file":
                expect(path, "typed_source_file", record["sha256"], record["size"],
                       record["mode"])
            else:
                target = record["target"].encode("utf-8")
                expect(path, "typed_source_symlink", record["sha256"],
                       record["size"], "120000", target)
        for relative, role, raw_sha in _source5_manifest_artifacts(
                source_doc, inventory, f"Source5 host {host_id}"):
            path = str(Path(roots["source_root"]).joinpath(*PurePosixPath(relative).parts))
            expect(path, role, raw_sha, None)

    selected_source = source_docs.get(request["host_id"])
    require(selected_source is not None,
            "Source5 request host has no original host source manifest")
    selected_inventory = source_inventories[request["host_id"]]
    modules_map = execution.get("modules")
    require(type(modules_map) is dict and request["host_id"] in modules_map and
            type(modules_map[request["host_id"]]) is dict,
            "Source5 execution manifest has no selected-host module map")
    expected_modules = {
        relative: {"path": relative, "sha256": record["sha256"]}
        for relative, record in selected_inventory.items()
        if record["kind"] == "file" and relative.startswith("scripts/") and
        relative.endswith((".py", ".sh"))
    }
    require(modules_map[request["host_id"]] == expected_modules,
            "Source5 module map differs from the complete regular script inventory")

    path_map = exact(path_map_value, {"schema", "entries"},
                     "offline Source5 pressure evidence path map")
    require(path_map["schema"] == "allocatbelt.application-pressure-evidence-path-map.v1" and
            type(path_map["entries"]) is list and
            1 <= len(path_map["entries"]) <= 16_384,
            "offline Source5 pressure path-map schema/count is invalid")
    mapped: set[str] = set()
    directories: set[str] = set()
    local_stats: dict[str, os.stat_result] = {}
    previous = ""
    for position, value in enumerate(path_map["entries"]):
        item = exact(value, {"origin", "local"},
                     f"offline Source5 pressure path-map row[{position}]")
        origin_path = _source5_absolute_path(item["origin"],
                                              "offline Source5 path-map origin")
        local_path = _source5_absolute_path(item["local"],
                                             "offline Source5 path-map local")
        require(origin_path == local_path and origin_path > previous,
                "offline Source5 pressure path map is not sorted and identity-bound")
        previous = origin_path
        try:
            info = Path(local_path).lstat()
        except OSError as error:
            raise PressurePairError(
                f"offline Source5 mapped path is unavailable: {error}",
            ) from error
        require(not stat.S_ISLNK(info.st_mode),
                "offline Source5 path map cannot contain a symlink")
        if stat.S_ISDIR(info.st_mode):
            require(Path(local_path).resolve(strict=True) == Path(local_path),
                    "offline Source5 mapped directory is an alias")
            directories.add(origin_path)
        else:
            require(stat.S_ISREG(info.st_mode),
                    "offline Source5 path map contains an unsupported node")
            capture = capture_rows.get(origin_path)
            require(capture is not None and capture["role"] != "typed_source_symlink",
                    f"offline Source5 mapped file lacks an exact regular captured role: {origin_path}")
            local_stats[origin_path] = info
            source_relative = None
            try:
                source_relative = Path(origin_path).relative_to(Path(roots["source_root"])).as_posix()
            except ValueError:
                pass
            if source_relative in selected_inventory and \
                    selected_inventory[source_relative]["kind"] == "file":
                require((stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode)) ==
                        int(selected_inventory[source_relative]["mode"], 8),
                        f"offline Source5 local source mode differs from its typed inventory: {origin_path}")
        mapped.add(origin_path)
    require(roots["source_root"] in directories,
            "offline Source5 evidence path map omits its exact SourceRoot directory")

    # Finish all index/store/source-role metadata checks before reading any
    # nested captured source or artifact stream.
    for path, (role, raw_sha, size, _mode, target) in expected.items():
        row = index_rows.get(path)
        require(row is not None and row["role"] == role and
                row["host_id"] == request["host_id"] and
                row["raw_sha256"] == raw_sha and row["semantic_sha256"] is None,
                f"Source5 complete typed closure row is missing or misroled: {path}")
        capture = capture_rows[path]
        require(capture["role"] == role and capture["host_id"] == request["host_id"] and
                capture["raw_sha256"] == raw_sha and capture["semantic_sha256"] is None and
                capture["byte_count"] == row["byte_count"] and
                (size is None or row["byte_count"] == size) and
                (size is not None or row["byte_count"] > 0),
                f"Source5 captured typed closure metadata differs: {path}")
        if role == "typed_source_symlink":
            require(target is not None and path not in mapped,
                    f"Source5 symlink is not indexed as literal data-only evidence: {path}")
        else:
            require(path in mapped,
                    f"offline Source5 path map omits a typed regular source/artifact: {path}")

    # Bind every mapped regular local file, not just the typed Source.files and
    # declared build artifacts, to the already-closed captured/index metadata.
    # This runs before callers parse component recipes, receipts, or plans and
    # before they compile any captured source module.
    for path, prior_stat in local_stats.items():
        capture = capture_rows[path]
        indexed = index_rows.get(path)
        reference = indexed if indexed is not None else capture
        require(all(capture[key] == reference[key] for key in (
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count",
        )), f"offline Source5 mapped capture/index metadata differs: {path}")
        local_sha, local_size, local_stat = _source5_read_local_digest(
            path, "offline Source5 mapped original file",
            SOURCE5_ROLE_LIMITS[capture["role"]],
        )
        require(_stat_key(prior_stat) == _stat_key(local_stat) and
                local_sha == reference["raw_sha256"] and
                local_size == reference["byte_count"],
                f"offline Source5 mapped local/captured bytes differ: {path}")

    symlink_snapshots: dict[str, tuple[int, ...]] = {}
    for path, (role, raw_sha, _size, _mode, target) in expected.items():
        capture = capture_rows[path]
        if role == "typed_source_symlink":
            require(target is not None and
                    _source5_capture_bytes(capture, MAX_SOURCE5_TYPED_SYMLINK_BYTES,
                                           "Source5 literal symlink target") == target,
                    f"Source5 symlink literal bytes differ from their typed inventory: {path}")
            try:
                before = Path(path).lstat()
                link_target = os.readlink(path)
                target_bytes = link_target.encode("utf-8", "strict")
                after = Path(path).lstat()
            except (OSError, UnicodeError) as error:
                raise PressurePairError(
                    f"cannot verify Source5 literal symlink {path}: {error}",
                ) from error
            require(stat.S_ISLNK(before.st_mode) and
                    (before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                     before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                     after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                    target_bytes == target,
                    f"Source5 local LICENSE symlink differs from its captured target: {path}")
            symlink_snapshots[path] = (
                before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
                int.from_bytes(hashlib.sha256(target_bytes).digest(), "big"),
            )
        else:
            _source5_capture_digest(capture)

    return {
        "request": request, "captured_evidence": store,
        "capture_rows": capture_rows, "index_rows": index_rows,
        "source_root": roots["source_root"], "mapped": mapped,
        "directories": directories, "path_map": path_map,
        "source_symlink_snapshots": symlink_snapshots,
        "selected_source": selected_source, "source_docs": source_docs,
    }


def text(value: object, label: str, maximum: int = 4096) -> str:
    require(type(value) is str and 0 < len(value) <= maximum and
            not any(ord(char) < 32 or ord(char) == 127 for char in value),
            f"{label} is malformed")
    return value


def token(value: object, label: str, maximum: int = 128) -> str:
    require(type(value) is str and 0 < len(value) <= maximum and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is not None, f"{label} is malformed")
    return value


def uint(value: object, label: str, *, positive: bool = False, maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} is not a bounded unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected field set")
    return value


def _stat_key(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str, os.stat_result]:
    try:
        path_before = path.lstat()
        require(stat.S_ISREG(path_before.st_mode), f"{label} is not a regular nonsymlink file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise PressurePairError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(path_before), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its finite byte limit")
        chunks: list[bytes] = []
        count = 0
        hasher = hashlib.sha256()
        while count < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated during read")
            count += len(block)
            hasher.update(block)
            chunks.append(block)
        after = os.fstat(fd)
        path_after = path.lstat()
        require(_stat_key(before) == _stat_key(after) == _stat_key(path_after) and count == before.st_size, f"{label} changed during read")
        return b"".join(chunks), hasher.hexdigest(), before
    finally:
        os.close(fd)


def read_json(path: Path, label: str, maximum: int, expected_sha256: str | None = None) -> tuple[dict[str, Any], bytes, str]:
    raw, raw_sha, _info = read_stable(path, label, maximum)
    if expected_sha256 is not None:
        require(raw_sha == digest(expected_sha256, f"{label} raw SHA-256"), f"{label} raw bytes differ from their pin")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PressurePairError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict and raw == canonical_bytes(value), f"{label} is not canonical JSON")
    return value, raw, raw_sha


def write_new(path: Path, raw: bytes, label: str, mode: int = 0o600) -> str:
    require(not path.exists() and not path.is_symlink(), f"refusing to replace {label}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, mode)
    except OSError as error:
        raise PressurePairError(f"cannot create {label}: {error}") from error
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            require(written > 0, f"short write while creating {label}")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return sha256_bytes(raw)


def pin(path: Path, raw_sha256: str, label: str) -> dict[str, str]:
    return {"path": str(path), "raw_sha256": digest(raw_sha256, f"{label} raw SHA-256")}


def raw_pin(value: object, label: str) -> dict[str, str]:
    item = exact(value, {"path", "raw_sha256"}, f"{label} raw pin")
    require(type(item["path"]) is str and Path(item["path"]).is_absolute(),
            f"{label} path is not absolute")
    return {"path": item["path"],
            "raw_sha256": digest(item["raw_sha256"], f"{label} raw SHA-256")}


def read_pin(value: object, label: str, maximum: int) -> tuple[Path, bytes, str]:
    item = exact(value, {"path", "raw_sha256"}, f"{label} pin")
    raw_path = item["path"]
    require(type(raw_path) is str and Path(raw_path).is_absolute() and ".." not in Path(raw_path).parts, f"{label} path is not a normalized absolute path")
    path = Path(raw_path)
    require(path.resolve(strict=True) == path, f"{label} path traverses a symlink or alias")
    raw, actual, _info = read_stable(path, label, maximum)
    require(actual == digest(item["raw_sha256"], f"{label} raw SHA-256"), f"{label} differs from its raw pin")
    return path, raw, actual


def safe_root(value: object, label: str) -> Path:
    require(type(value) is str and Path(value).is_absolute(), f"{label} must be absolute")
    path = Path(value)
    require(path.resolve(strict=True) == path and path.is_dir() and not path.is_symlink(), f"{label} is missing, aliased, or not a directory")
    return path


def safe_child(root: Path, relative: object, label: str) -> Path:
    require(type(relative) is str and relative and "\\" not in relative and "\x00" not in relative, f"{label} path is malformed")
    rel = PurePosixPath(relative)
    require(not rel.is_absolute() and rel.as_posix() == relative and all(part not in ("", ".", "..") for part in rel.parts), f"{label} path is not normalized and relative")
    path = root.joinpath(*rel.parts)
    require(path.resolve(strict=True).is_relative_to(root.resolve(strict=True)) and path.resolve(strict=True) == path, f"{label} escapes its pinned root or traverses an alias")
    return path


def _load_module(raw: bytes, path: Path, name: str) -> types.ModuleType:
    module = types.ModuleType(f"pressure_pair_{name}_{sha256_bytes(raw)}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise PressurePairError(f"pinned {name} cannot be loaded: {error}") from error
    return module


def _inventory_record(source: dict[str, Any], relative: str, label: str) -> dict[str, Any]:
    files = source.get("source", {}).get("files")
    require(type(files) is list, "SourceV5 typed source inventory is missing")
    matches = [item for item in files if type(item) is dict and item.get("path") == relative]
    require(len(matches) == 1, f"SourceV5 inventory has no unique {label} entry")
    record = exact(matches[0], {"path", "kind", "mode", "sha256", "size"}, f"SourceV5 {label} inventory entry")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755"), f"SourceV5 {label} is not a regular file inventory entry")
    digest(record["sha256"], f"SourceV5 {label} inventory digest")
    uint(record["size"], f"SourceV5 {label} size")
    return record


def _pinned_source_module(source: dict[str, Any], source_root: Path, relative: str, label: str, maximum: int) -> tuple[types.ModuleType, dict[str, str]]:
    record = _inventory_record(source, relative, label)
    path = safe_child(source_root, relative, f"SourceV5 {label}")
    raw, raw_sha, info = read_stable(path, f"SourceV5 {label}", maximum)
    mode = stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode)
    require(raw_sha == record["sha256"] and len(raw) == record["size"] and mode == int(record["mode"], 8), f"SourceV5 {label} differs from its typed regular-file inventory pin")
    module = _load_module(raw, path, label.replace(" ", "_"))
    return module, {"path": relative, "sha256": raw_sha}


def _semantic_manifest(manifest: dict[str, Any], raw: bytes, semantic_sha: str, label: str) -> str:
    require(raw == canonical_bytes(manifest), f"{label} is not canonical")
    body = dict(manifest)
    claimed = body.pop("manifest_sha256", None)
    actual = sha256_bytes(canonical_bytes(body))
    require(claimed == semantic_sha == actual, f"{label} semantic digest differs from the original spec/plan reference")
    return sha256_bytes(raw)


def _validate_source_tree(source_root: Path, manifest: dict[str, Any], inventory: Any) -> None:
    source = manifest["source"]
    files = source["files"]
    validated = inventory.validate_records({"schema": inventory.SCHEMA, "entries": files})
    require(validated == files and inventory.digest_records(files) == source["source_tree_sha256"], "SourceV5 typed inventory does not reproduce its source-tree digest")
    inventory_record = _inventory_record(manifest, "scripts/application-source-inventory.py", "shared source inventory")
    inventory_path = safe_child(source_root, inventory_record["path"], "SourceV5 shared source inventory")
    inventory_raw, inventory_sha, inventory_info = read_stable(inventory_path, "SourceV5 shared source inventory", MAX_SOURCE_BYTES)
    inventory_mode = stat.S_IFMT(inventory_info.st_mode) | stat.S_IMODE(inventory_info.st_mode)
    require(inventory_sha == inventory_record["sha256"] and len(inventory_raw) == inventory_record["size"] and inventory_mode == int(inventory_record["mode"], 8), "SourceV5 shared source inventory bytes differ")


def pressure_process_descriptors(job: dict[str, Any]) -> list[dict[str, str]]:
    """Derive exactly the two supported process descriptors for an original pressure job."""
    require(job.get("phase") == "pressure" and job.get("comparison_family") == "external_pressure", "pressure descriptors require an original external-pressure job")
    if job.get("comparison_kind") == "allocator":
        candidate = token(job.get("allocator"), "pressure candidate allocator")
        baseline = token(job.get("baseline_allocator"), "pressure baseline allocator")
        require(candidate == "allocatbelt" and baseline in ALLOCATORS and baseline != candidate, "pressure allocator comparison differs from the original candidate/baseline set")
        return [
            {"pair": "candidate", "executor": "bounded", "allocator": candidate},
            {"pair": "baseline", "executor": "bounded", "allocator": baseline},
        ]
    require(job.get("comparison_kind") == "executor", "pressure job has an unsupported comparison kind")
    allocator = token(job.get("allocator"), "pressure executor-comparison allocator")
    require(allocator in ALLOCATORS, "pressure executor-comparison allocator is outside SourceV5")
    return [
        {"pair": "bounded", "executor": "bounded", "allocator": allocator},
        {"pair": "tokio", "executor": "tokio", "allocator": allocator},
    ]


def _source5_normalized_terminal_status(cleanup: dict[str, Any]) -> tuple[int, int | None]:
    """Keep the chronology's unsigned status valid while retaining raw wait status."""
    child_return_code = cleanup.get("return_code")
    if child_return_code is None:
        return 125, None
    require(type(child_return_code) is int and -127 <= child_return_code <= 255,
            "pressure supervisor returned an invalid child wait status")
    if child_return_code < 0:
        signal_number = -child_return_code
        return 128 + signal_number, signal_number
    return child_return_code, None


def _verify_source5_host_verification_v2(
    receipt: dict[str, Any], observed_host_pin: dict[str, str], host_id: str,
) -> dict[str, Any]:
    """Bind the calibration scope's reaped-worker host receipt to this host pin."""
    value = exact(receipt.get("host_verification"), {
        "schema", "host_id", "boot_id_sha256", "kernel_release",
        "allowed_cpu_affinity", "network_namespace_inode",
        "observed_host_raw_sha256", "owned_worker_pids_reaped",
        "host_verification_sha256",
    }, "Source5 calibration host-verification receipt")
    require(value["schema"] ==
            "allocatbelt.application-pressure-calibration-host-verification.v1" and
            value["host_id"] == host_id and
            value["observed_host_raw_sha256"] == observed_host_pin["raw_sha256"] and
            value["owned_worker_pids_reaped"] is True,
            "Source5 calibration host-verification identity or cleanup differs")
    expected_sha = sha256_bytes(canonical_bytes({
        key: item for key, item in value.items()
        if key != "host_verification_sha256"
    }))
    require(value["host_verification_sha256"] == expected_sha,
            "Source5 calibration host-verification self digest differs")
    observed_path = Path(observed_host_pin["path"])
    observed, _raw, observed_sha = read_json(
        observed_path, "Source5 observed-host context", MAX_SMALL_BYTES,
        observed_host_pin["raw_sha256"],
    )
    require(observed_sha == observed_host_pin["raw_sha256"] and
            observed.get("host_id") == host_id and
            value["boot_id_sha256"] == observed.get("boot_id_sha256") and
            value["kernel_release"] == observed.get("kernel_release") and
            value["allowed_cpu_affinity"] == observed.get("cpu_affinity") and
            value["network_namespace_inode"] ==
                observed.get("network_namespace_inode"),
            "Source5 calibration host-verification receipt differs from the exact observed-host artifact")
    return value


def instantiate_feedback_nonce(template_nonce: str, campaign_id: str, job_run_id: str, pair_member: str, ordinal: int) -> str:
    require(type(template_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", template_nonce) is not None, "feedback prospective nonce is malformed")
    material = {
        "template_nonce": template_nonce,
        "campaign_id": token(campaign_id, "campaign ID"),
        "job_run_id": token(job_run_id, "pressure job run ID"),
        "pair_member": token(pair_member, "pressure pair member"),
        "ordinal": uint(ordinal, "pressure pair ordinal", positive=True),
    }
    return hashlib.sha256(b"allocatbelt.application-process-nonce-instantiation.v1\0" + canonical_bytes(material)).hexdigest()[:32]


def _planned_job_index(controller: Any, spec: dict[str, Any], plan: dict[str, Any], job: dict[str, Any], host_id: str) -> tuple[int, list[dict[str, Any]]]:
    rebuilt = controller.build_jobs(spec, "pressure", host_id)
    planned = [item for item in plan["jobs"]["pressure"] if item.get("host_id") == host_id]
    require(planned == rebuilt, "SourceV5 pressure jobs do not equal the complete original matrix derivation")
    matches = [index for index, item in enumerate(planned) if item.get("run_id") == job.get("run_id")]
    require(len(matches) == 1 and planned[matches[0]] == job, "pressure job is not the exact unique original plan entry")
    return matches[0], planned


def _verify_source_manifest_files_offline(
    manifest: dict[str, Any], source_root: Path, mapped_paths: set[str],
    controller: Any,
) -> None:
    artifact_refs: list[tuple[str, dict[str, Any], int]] = []
    for label, value in manifest["artifacts"].items():
        artifact_refs.append((f"APP {label}", value, MAX_BINARY_BYTES))
    for label, value in manifest["soak_artifacts"].items():
        artifact_refs.append((f"Soak {label}", value, MAX_BINARY_BYTES))
    artifact_refs.append(("analysis engine", manifest["analysis_artifact"], MAX_BINARY_BYTES))
    calibration = manifest["resource_domain_calibration"]
    artifact_refs.extend((
        ("resource-domain calibration binary", calibration["binary"], MAX_BINARY_BYTES),
        ("resource-domain calibration output", calibration["output"], MAX_SMALL_BYTES),
        ("runtime readback validator", manifest["runtime_readback_validator"], MAX_SOURCE_BYTES),
    ))
    for label, value, maximum in artifact_refs:
        artifact = exact(value, {"path", "sha256"}, f"offline SourceV5 {label} artifact")
        relative = PurePosixPath(text(artifact["path"], f"offline SourceV5 {label} path", 4096))
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == artifact["path"],
                f"offline SourceV5 {label} path is not portable")
        path = safe_child(source_root, artifact["path"], f"offline SourceV5 {label}")
        require(str(path) in mapped_paths,
                f"offline evidence map omits exact SourceV5 {label} artifact")
        _raw, raw_sha, _info = read_stable(path, f"offline SourceV5 {label}", maximum)
        require(raw_sha == digest(artifact["sha256"], f"offline SourceV5 {label} raw SHA-256"),
                f"offline SourceV5 {label} bytes differ from the frozen manifest")
    output_ref = calibration["output"]
    output_path = safe_child(source_root, output_ref["path"], "offline SourceV5 calibration output")
    output, _output_raw, _output_sha = read_json(
        output_path, "offline SourceV5 resource-domain calibration output",
        MAX_SMALL_BYTES, output_ref["sha256"],
    )
    try:
        require(controller.validate_calibration_record(output) == calibration["record"],
                "offline SourceV5 calibration output differs from its embedded record")
    except Exception as error:
        if isinstance(error, PressurePairError):
            raise
        raise PressurePairError(
            f"offline SourceV5 calibration record replay failed: {type(error).__name__}"
        ) from error


def _load_campaign_inputs(
    recipe: dict[str, Any], output_root: Path, *,
    offline_mapped_paths: set[str] | None = None,
) -> dict[str, Any]:
    spec_pin = exact(recipe["spec"], {"artifact", "semantic_sha256"}, "pressure pair spec")
    plan_pin = exact(recipe["plan"], {"artifact", "semantic_sha256"}, "pressure pair plan")
    source_pin = exact(recipe["source_manifest"], {"artifact", "semantic_sha256", "source_root"}, "pressure pair source manifest")
    spec_path, spec_raw, spec_raw_sha = read_pin(spec_pin["artifact"], "original SourceV5 campaign spec", MAX_SPEC_BYTES)
    plan_path, plan_raw, plan_raw_sha = read_pin(plan_pin["artifact"], "original SourceV5 campaign plan", MAX_PLAN_BYTES)
    spec, plan = json.loads(spec_raw), json.loads(plan_raw)
    require(spec_raw == canonical_bytes(spec) and plan_raw == canonical_bytes(plan), "original SourceV5 spec/plan bytes are not canonical JSON")
    require(spec.get("schema") == V5_SPEC_SCHEMA and plan.get("schema") == V5_PLAN_SCHEMA, "pressure pair requires the original canonical SourceV5 specV3 and planV3")
    require(sha256_bytes(canonical_bytes(spec)) == spec_pin["semantic_sha256"], "original spec semantic digest differs")
    plan_body = dict(plan)
    plan_semantic = plan_body.pop("plan_sha256", None)
    require(plan_semantic == plan_pin["semantic_sha256"] and sha256_bytes(canonical_bytes(plan_body)) == plan_semantic, "original plan semantic digest differs")
    source_root = safe_root(source_pin["source_root"], "SourceV5 root")
    manifest_path, manifest_raw, manifest_raw_sha = read_pin(source_pin["artifact"], "selected SourceV5 source manifest", MAX_MANIFEST_BYTES)
    source, _raw, _sha = read_json(manifest_path, "selected SourceV5 source manifest", MAX_MANIFEST_BYTES, manifest_raw_sha)
    require(source.get("schema") == V5_SOURCE_SCHEMA, "pressure pair requires a SourceV5 source manifest")
    semantic = _semantic_manifest(source, manifest_raw, source_pin["semantic_sha256"], "selected SourceV5 source manifest")
    require(source["build"]["host_id"] == spec["hosts"][0]["host_id"] or source["build"]["host_id"] in {item["host_id"] for item in spec["hosts"]}, "selected SourceV5 host is absent from the original campaign spec")
    inventory, _inventory_pin = _pinned_source_module(source, source_root, "scripts/application-source-inventory.py", "shared source inventory", MAX_SOURCE_BYTES)
    _validate_source_tree(source_root, source, inventory)

    refs = spec.get("source_manifests")
    require(type(refs) is list and len(refs) == 3, "SourceV5 spec must retain its complete three-host source-manifest set")
    sources: dict[str, dict[str, Any]] = {}
    for index, ref_value in enumerate(refs):
        ref = exact(ref_value, {"host_id", "relative_path", "sha256"}, f"SourceV5 source reference[{index}]")
        host_id = token(ref["host_id"], f"SourceV5 source host[{index}]")
        require(host_id not in sources, "SourceV5 spec repeats a host manifest")
        path = safe_child(spec_path.parent, ref["relative_path"], f"SourceV5 host {host_id} manifest")
        raw, raw_sha, _info = read_stable(path, f"SourceV5 host {host_id} manifest", MAX_MANIFEST_BYTES)
        manifest = json.loads(raw)
        _semantic_manifest(manifest, raw, ref["sha256"], f"SourceV5 host {host_id} manifest")
        require(manifest.get("schema") == V5_SOURCE_SCHEMA, f"SourceV5 host {host_id} uses another manifest schema")
        sources[host_id] = manifest
    require(source["build"]["host_id"] in sources and sources[source["build"]["host_id"]] == source, "selected host manifest differs from the original spec reference")

    controller_pin = exact(source["qualification_harness"]["campaign_controller"], {"path", "sha256"}, "SourceV5 controller pin")
    controller, _controller_pin = _pinned_source_module(source, source_root, controller_pin["path"], "campaign controller", MAX_SOURCE_BYTES)
    require(controller_pin["path"] == "scripts/application-campaign.py" and controller_pin["sha256"] == _controller_pin["sha256"], "SourceV5 campaign controller pin is malformed")
    try:
        for host_id, manifest in sources.items():
            require(manifest["qualification_harness"]["campaign_controller"] == controller_pin, f"SourceV5 host {host_id} uses a different campaign controller")
            controller.verify_source_manifest(manifest, verify_artifacts=False)
        if offline_mapped_paths is None:
            controller.verify_source_manifest(source, source_root=source_root, verify_artifacts=True)
        else:
            controller.verify_source_manifest(source, verify_artifacts=False)
            require(all(manifest["source"]["source_tree_sha256"] == source["source"]["source_tree_sha256"] for manifest in sources.values()),
                    "offline SourceV5 host manifests do not share the original typed source tree")
            for manifest in sources.values():
                _verify_source_manifest_files_offline(manifest, source_root, offline_mapped_paths, controller)
        cell_validation = controller.validate_spec(spec, sources, input_root=spec_path.parent)
        controller.verify_plan(plan, source["runtime_readback_validator"]["sha256"], cell_validation["campaign_inputs_module_sha256"])
    except Exception as error:
        raise PressurePairError(f"pinned SourceV5 controller rejected the full source/spec/plan inputs: {error}") from error

    host_id = token(recipe["job"]["value"].get("host_id"), "pressure job host")
    require(host_id == source["build"]["host_id"], "selected host differs from the SourceV5 source manifest")
    job_record = exact(recipe["job"], {"value", "semantic_sha256"}, "original pressure job")
    job = job_record["value"]
    require(type(job) is dict and sha256_bytes(canonical_bytes(job)) == digest(job_record["semantic_sha256"], "original pressure job semantic digest"), "original pressure job semantic digest differs")
    job_index, pressure_jobs = _planned_job_index(controller, spec, plan, job, host_id)
    require(job["phase"] == "pressure" and job["comparison_family"] == "external_pressure", "selected planned job is not an original pressure job")
    require(job["family"] == job["workload"] or (job["family"] == "mixed" and job["workload"] == "mixed"), "pressure job family/workload mapping differs")
    return {
        "spec": spec, "plan": plan, "source": source, "sources": sources,
        "source_root": source_root, "input_root": spec_path.parent,
        "spec_path": spec_path, "spec_raw_sha256": spec_raw_sha,
        "plan_path": plan_path, "plan_raw_sha256": plan_raw_sha,
        "manifest_path": manifest_path, "manifest_raw_sha256": manifest_raw_sha,
        "manifest_semantic_sha256": semantic,
        "controller": controller, "inventory": inventory,
        "host_id": host_id, "job": job, "job_index": job_index,
        "pressure_jobs": pressure_jobs,
    }


def _verify_execution_overlay(
    recipe: dict[str, Any], inputs: dict[str, Any], chronology_module: Any,
    *, lock: Any | None = None, authorization_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    overlay_pin = exact(recipe["execution_overlay"], {"artifact"}, "SourceV5 execution overlay reference")
    overlay_path, overlay_raw, overlay_raw_sha = read_pin(overlay_pin["artifact"], "SourceV5 execution overlay", 4 * 1024 * 1024)
    overlay = json.loads(overlay_raw)
    require(overlay_raw == canonical_bytes(overlay), "SourceV5 execution overlay bytes are not canonical JSON")
    overlay_fields = {
        "schema", "campaign_id", "host_id", "source_manifest", "spec", "plan", "job_index",
        "job_sha256", "runner", "capacity_completion", "chronology", "overlay_sha256",
    }
    exact(overlay, overlay_fields, "SourceV5 execution overlay")
    require(overlay["schema"] == EXECUTION_OVERLAY_SCHEMA, "unsupported SourceV5 execution overlay schema")
    body = {key: value for key, value in overlay.items() if key != "overlay_sha256"}
    require(digest(overlay["overlay_sha256"], "execution overlay self digest") == sha256_bytes(canonical_bytes(body)), "execution overlay self digest is invalid")
    require(overlay["campaign_id"] == inputs["spec"]["campaign_id"] and overlay["host_id"] == inputs["host_id"], "execution overlay campaign/host differs from the original plan")
    expected_source = {"path": str(inputs["manifest_path"]), "raw_sha256": inputs["manifest_raw_sha256"], "semantic_sha256": inputs["manifest_semantic_sha256"]}
    expected_spec = {"path": str(inputs["spec_path"]), "raw_sha256": inputs["spec_raw_sha256"], "semantic_sha256": recipe["spec"]["semantic_sha256"]}
    expected_plan = {"path": str(inputs["plan_path"]), "raw_sha256": inputs["plan_raw_sha256"], "semantic_sha256": recipe["plan"]["semantic_sha256"]}
    require(overlay["source_manifest"] == expected_source and overlay["spec"] == expected_spec and overlay["plan"] == expected_plan, "execution overlay does not bind the exact original source/spec/plan bytes and semantic digests")
    require(overlay["job_index"] == inputs["job_index"] and overlay["job_sha256"] == sha256_bytes(canonical_bytes(inputs["job"])), "execution overlay does not bind the exact original pressure job and ordinal")
    runner = exact(overlay["runner"], {"path", "raw_sha256"}, "execution overlay runner self pin")
    current_path = Path(__file__).resolve(strict=True)
    require(current_path == inputs["source_root"] / "scripts/application-pressure-pair.py", "executing pressure-pair runner path differs from the new regular SourceV5 inventory module")
    current_raw, current_sha, current_info = read_stable(current_path, "executing pressure-pair runner", MAX_SOURCE_BYTES)
    require(runner["path"] == str(current_path) and digest(runner["raw_sha256"], "execution overlay runner SHA-256") == current_sha, "execution overlay does not pin the executing runner bytes")
    runner_record = _inventory_record(inputs["source"], "scripts/application-pressure-pair.py", "pressure-pair runner")
    runner_mode = stat.S_IFMT(current_info.st_mode) | stat.S_IMODE(current_info.st_mode)
    require(runner_record["sha256"] == current_sha and runner_record["mode"] == "100755" and runner_mode == int(runner_record["mode"], 8), "pressure-pair runner is not the new regular SourceV5 inventory pin")
    completion_ref = exact(overlay["capacity_completion"], {"path", "raw_sha256"}, "execution overlay capacity completion pin")
    require(completion_ref == recipe["capacity_completion"]["artifact"], "execution overlay capacity completion differs from the pair recipe")
    chronology = exact(overlay["chronology"], {
        "observed_host", "output_root", "capacity_output_root", "journal_head", "journal_record_count",
        "registration_head", "dispatch_event_count",
    }, "execution overlay chronology heads")
    host_pin = exact(chronology["observed_host"], {"path", "raw_sha256"}, "execution overlay observed-host pin")
    chronology_host_pin = _chronology_api_pin(host_pin, "execution overlay observed-host")
    output_root = safe_root(chronology["output_root"], "campaign chronology output root")
    capacity_output_root = None if chronology["capacity_output_root"] is None else safe_root(chronology["capacity_output_root"], "capacity evidence output root")
    digest(chronology["journal_head"], "execution overlay chronology journal head")
    digest(chronology["registration_head"], "execution overlay capacity registration head")
    uint(chronology["journal_record_count"], "execution overlay chronology record count")
    uint(chronology["dispatch_event_count"], "execution overlay chronology dispatch count")
    completion = read_pin(completion_ref, "SourceV5 capacity-stage completion", 16 * 1024 * 1024)
    del completion
    chronology_completion_pin = _chronology_api_pin(completion_ref, "execution overlay capacity completion")
    if lock is None:
        require(authorization_context is None,
                "Source5 authorization context requires an already-owned chronology lock")
        with chronology_module.campaign_host_lock(
            output_root, inputs["spec"]["campaign_id"], inputs["host_id"], timeout_seconds=30.0,
        ) as owned_lock:
            try:
                replay = chronology_module.verify_campaign_chronology_locked(
                    owned_lock,
                    {"path": str(inputs["plan_path"]), "sha256": inputs["plan_raw_sha256"]},
                    {"path": str(inputs["spec_path"]), "sha256": inputs["spec_raw_sha256"]},
                    inputs["source_root"], inputs["input_root"], inputs["host_id"], chronology_host_pin,
                    output_root, chronology_completion_pin, capacity_output_root=capacity_output_root,
                )
            except Exception as error:
                raise PressurePairError(f"SourceV5 chronology/capacity registration replay failed: {error}") from error
        for field in ("journal_head", "journal_record_count", "registration_head", "dispatch_event_count"):
            require(replay[field] == chronology[field], f"execution overlay {field} differs from the live full chronology replay")
    else:
        require(authorization_context is not None and
                getattr(lock, "campaign_id", None) == inputs["spec"]["campaign_id"] and
                getattr(lock, "host_id", None) == inputs["host_id"] and
                getattr(lock, "output_root", None) == output_root,
                "Source5 pressure replay did not receive the current campaign/host lock and authorization")
        authorized_job = authorization_context.get("job")
        authorized_members = authorization_context.get("members")
        expected_members = pressure_process_descriptors(inputs["job"])
        require(authorization_context.get("phase") == "pressure" and
                authorized_job == inputs["job"] and
                authorization_context.get("job_sha256") ==
                    sha256_bytes(canonical_bytes(inputs["job"])) and
                authorized_members == expected_members and
                [member["descriptor"] for member in recipe["members"]] == expected_members and
                authorization_context.get("output_root") == str(output_root),
                "Source5 pressure recipe job, member order, or output root differs from its durable authorization")
        execution_manifest = _artifact_reference(
            authorization_context.get("execution_manifest"),
            "Source5 execution manifest",
        )
        try:
            replay = chronology_module.verify_source5_capacity_ancestor_locked(
                lock,
                {"path": execution_manifest["path"],
                 "sha256": execution_manifest["raw_sha256"]},
                authorization_context,
                historical_journal_head=chronology["journal_head"],
                historical_registration_head=chronology["registration_head"],
            )
        except Exception as error:
            raise PressurePairError(f"Source5 historical chronology/capacity ancestry replay failed: {error}") from error
        require(replay["historical_journal_record_count"] == chronology["journal_record_count"] and
                replay["registration_head"] == chronology["registration_head"],
                "Source5 pressure overlay chronology snapshot is not the registered historical ancestor")
    require(
        replay["registration_head"] == recipe["capacity_completion"]["registration_head"]
        and replay["capacity_schedule_sha256"] == recipe["capacity_completion"]["schedule_sha256"]
        and replay["capacity_completion_raw_sha256"] == completion_ref["raw_sha256"],
        "pair capacity completion registration/schedule heads differ from the live chronology replay",
    )
    require(replay["entry_count"] == 15,
            "execution overlay chronology has no complete sealed capacity registration")
    if lock is None:
        require(replay["pending_authorization"] is False and
                replay["api_transaction_order_proven"] is True,
                "execution overlay chronology has a pending legacy dispatch or incomplete capacity registration")
    else:
        require(replay["authorization_state"] in {"pending", "valid_pair"} and
                replay["authorization_id"] == authorization_context["authorization_id"] and
                replay["dispatch_event_count"] == chronology["dispatch_event_count"] and
                replay["output_root"] == str(output_root),
                "Source5 pressure authorization is not a clean pending/completed chronology descendant")
        replay = {
            **replay,
            "journal_head": chronology["journal_head"],
            "journal_record_count": chronology["journal_record_count"],
            "dispatch_event_count": chronology["dispatch_event_count"],
        }
    return {
        "path": str(overlay_path), "raw_sha256": overlay_raw_sha,
        "value": overlay, "chronology": replay,
    }


def _artifact_reference(value: object, label: str) -> dict[str, str]:
    item = exact(value, {"path", "raw_sha256"}, f"{label} artifact pin")
    require(type(item["path"]) is str and Path(item["path"]).is_absolute() and ".." not in Path(item["path"]).parts, f"{label} artifact path is not normalized and absolute")
    digest(item["raw_sha256"], f"{label} artifact raw SHA-256")
    return item


def _validate_source5_calibration_id_roles_v2(
    binding: dict[str, Any], original_pressure_calibration_id: str,
    condition_id: str, capacity_key: dict[str, Any],
) -> None:
    """Keep the pressure-condition token separate from the capacity key ID."""
    capacity_calibration_id = token(
        binding["calibration_id"], "Source5 context capacity calibration ID",
    )
    pressure_calibration_id = token(
        binding["pressure_calibration_id"],
        "Source5 prospective pressure calibration ID",
    )
    require(pressure_calibration_id == original_pressure_calibration_id and
            capacity_calibration_id == capacity_key["calibration_id"] and
            len({condition_id, pressure_calibration_id,
                 capacity_calibration_id}) == 3,
            "Source5 V2 condition, pressure and capacity calibration identities are conflated or changed")


def _chronology_api_pin(value: object, label: str) -> dict[str, str]:
    """Translate private raw_sha256 pins to the chronology API's sha256 pins."""
    item = _artifact_reference(value, label)
    return {"path": item["path"], "sha256": item["raw_sha256"]}


def _validate_probe_capture_budget(value: object) -> dict[str, Any]:
    budget = exact(value, {"capture_timeout_ns", "storage_budget"},
                   "prospective ProbeV2 capture budget")
    timeout = uint(budget["capture_timeout_ns"], "prospective ProbeV2 timeout",
                   positive=True, maximum=MAX_PROBE_CAPTURE_TIMEOUT_NS)
    storage = exact(budget["storage_budget"], {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes", "receipt_bytes",
        "output_inodes",
    }, "prospective ProbeV2 storage budget")
    values = {
        name: uint(storage[name], f"prospective ProbeV2 {name}", positive=True)
        for name in storage
    }
    require(values["tmpdir_bytes"] <= MAX_PROBE_CAPTURE_TMPDIR_BYTES and
            values["tmpdir_inodes"] <= MAX_PROBE_CAPTURE_TMPDIR_INODES and
            values["stdout_bytes"] <= MAX_PROBE_CAPTURE_STDOUT_BYTES and
            values["stderr_bytes"] <= MAX_PROBE_CAPTURE_STDERR_BYTES and
            values["owner_result_bytes"] == PROBE_CAPTURE_OWNER_RESULT_BYTES and
            values["inventory_bytes"] == PROBE_CAPTURE_INVENTORY_BYTES and
            values["failure_bytes"] == PROBE_CAPTURE_FAILURE_BYTES and
            values["receipt_bytes"] <= MAX_PROBE_CAPTURE_RECEIPT_BYTES and
            PROBE_CAPTURE_MIN_OUTPUT_INODES <= values["output_inodes"] <=
            PROBE_CAPTURE_MAX_OUTPUT_INODES,
            "prospective ProbeV2 storage budget exceeds the FixedR8 finite owner contract")
    return {"capture_timeout_ns": timeout, "storage_budget": values}


def _verify_probe_capture_budget_receipt(
    feedback_module: Any, capture_pin_value: object,
    expected_budget: dict[str, Any], ordinal: int,
) -> dict[str, Any]:
    capture_pin = exact(capture_pin_value, {"path", "raw_sha256", "receipt_sha256"},
                        f"ProbeV2 capture receipt[{ordinal}] pin")
    path = Path(text(capture_pin["path"], f"ProbeV2 capture receipt[{ordinal}] path", 4096))
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)),
            f"ProbeV2 capture receipt[{ordinal}] path is not normalized and absolute")
    raw, raw_sha, _info = read_stable(
        path, f"ProbeV2 capture receipt[{ordinal}]", MAX_PROBE_CAPTURE_RECEIPT_BYTES,
    )
    require(raw_sha == digest(capture_pin["raw_sha256"],
                              f"ProbeV2 capture receipt[{ordinal}] raw SHA-256"),
            f"ProbeV2 capture receipt[{ordinal}] raw bytes differ from the locked pin")
    try:
        receipt = feedback_module.validate_probe_capture_receipt_envelope(
            raw, capture_pin["raw_sha256"], capture_pin["receipt_sha256"],
        )
    except Exception as error:
        raise PressurePairError(
            f"SourceV5 feedback reader rejected locked ProbeV2 capture receipt[{ordinal}]: "
            f"{type(error).__name__}: {error}"
        ) from error
    require(receipt["capture_timeout_ns"] == expected_budget["capture_timeout_ns"] and
            receipt["storage_budget"] == expected_budget["storage_budget"],
            f"ProbeV2 capture receipt[{ordinal}] differs from its prospective recipe budget")
    return receipt


def _validate_recipe_shape(value: object) -> dict[str, Any]:
    fields = {
        "schema", "spec", "plan", "source_manifest", "job", "execution_overlay",
        "capacity_completion", "capacity_bundle", "fixed_predecessor", "shared_policy",
        "pressure_condition", "members", "deadlines", "artifact_budgets", "validators",
    }
    require(type(value) is dict, "private pressure-pair recipe must be an object")
    if value.get("schema") == RECIPE_SCHEMA:
        recipe = exact(value, fields, "private pressure-pair recipe v1")
    elif value.get("schema") == RECIPE_SCHEMA_V2:
        recipe = exact(value, fields | {"probe_capture"}, "private pressure-pair recipe v2")
        recipe = {**recipe,
                  "probe_capture": _validate_probe_capture_budget(recipe["probe_capture"])}
    else:
        raise PressurePairError("unsupported private pressure-pair recipe schema")
    for name in ("spec", "plan"):
        reference = exact(recipe[name], {"artifact", "semantic_sha256"}, f"pressure pair {name}")
        _artifact_reference(reference["artifact"], f"pressure pair {name}")
        digest(reference["semantic_sha256"], f"pressure pair {name} semantic SHA-256")
    source = exact(recipe["source_manifest"], {"artifact", "semantic_sha256", "source_root"}, "pressure pair SourceV5 manifest")
    _artifact_reference(source["artifact"], "pressure pair SourceV5 manifest")
    digest(source["semantic_sha256"], "SourceV5 semantic manifest SHA-256")
    require(type(source["source_root"]) is str and Path(source["source_root"]).is_absolute(), "SourceV5 source root is malformed")
    job = exact(recipe["job"], {"value", "semantic_sha256"}, "pressure pair original job")
    require(type(job["value"]) is dict, "pressure pair original job must be an object")
    digest(job["semantic_sha256"], "pressure pair original job semantic SHA-256")
    overlay = exact(recipe["execution_overlay"], {"artifact"}, "pressure pair execution overlay")
    _artifact_reference(overlay["artifact"], "pressure pair execution overlay")
    completion = exact(recipe["capacity_completion"], {"artifact", "schedule_sha256", "registration_head"}, "pressure pair capacity completion")
    _artifact_reference(completion["artifact"], "pressure pair capacity completion")
    digest(completion["schedule_sha256"], "capacity schedule SHA-256")
    digest(completion["registration_head"], "capacity registration head")
    bundle = exact(recipe["capacity_bundle"], {"request", "artifact", "receipt"}, "complete SourceV5 capacity bundle")
    for name in bundle:
        _artifact_reference(bundle[name], f"SourceV5 capacity {name}")
    require(len({bundle[name]["path"] for name in bundle}) == 3, "capacity bundle paths must be distinct")
    predecessor = exact(recipe["fixed_predecessor"], {"record"}, "fixed-pressure predecessor record")
    _artifact_reference(predecessor["record"], "fixed-pressure predecessor")
    shared = exact(recipe["shared_policy"], {"artifact"}, "shared numeric policy")
    _artifact_reference(shared["artifact"], "shared numeric policy")
    condition_fields = {
        "condition", "condition_id", "condition_sha256", "pressure_calibration",
        "readiness_thresholds", "schedule",
    }
    condition_value = exact(
        recipe["pressure_condition"],
        condition_fields | ({"pressure_calibration_v2"}
                            if type(recipe["pressure_condition"]) is dict and
                            "pressure_calibration_v2" in recipe["pressure_condition"]
                            else set()),
        "original SourceV5 pressure condition",
    )
    condition = condition_value
    _artifact_reference(condition["condition"], "original pressure condition")
    token(condition["condition_id"], "original pressure condition ID")
    digest(condition["condition_sha256"], "original pressure condition SHA-256")
    require(condition["condition"]["raw_sha256"] == condition["condition_sha256"], "condition file pin differs from the typed semantic condition digest")
    calibration = exact(condition["pressure_calibration"], {"artifact", "receipt", "validator_sha256", "calibration_id"}, "pressure calibration")
    _artifact_reference(calibration["artifact"], "pressure calibration artifact")
    _artifact_reference(calibration["receipt"], "pressure calibration receipt")
    digest(calibration["validator_sha256"], "pressure calibration validator SHA-256")
    token(calibration["calibration_id"], "pressure calibration ID")
    if "pressure_calibration_v2" in condition:
        v2 = exact(condition["pressure_calibration_v2"], {
            "schema", "calibration_id", "pressure_calibration_id",
            "artifact", "scope_receipt",
            "validator_sha256", "context_policy", "capacity_bundle_pins",
            "observed_host",
        }, "Source5 context-scoped pressure calibration v2 binding")
        require(v2["schema"] == "allocatbelt.application-pressure-calibration-binding.v2",
                "unsupported Source5 context-scoped calibration binding")
        _artifact_reference(v2["artifact"], "Source5 context-scoped calibration")
        scope_receipt = exact(v2["scope_receipt"], {
            "path", "raw_sha256", "scope_sha256",
        }, "Source5 calibration scope receipt pin")
        _artifact_reference({key: scope_receipt[key] for key in ("path", "raw_sha256")},
                            "Source5 calibration scope receipt")
        digest(scope_receipt["scope_sha256"], "Source5 calibration scope digest")
        digest(v2["validator_sha256"], "Source5 calibration scope validator SHA-256")
        _artifact_reference(v2["context_policy"], "Source5 context-policy bundle")
        _artifact_reference(v2["observed_host"], "Source5 observed host")
        capacity_pin = exact(v2["capacity_bundle_pins"], {
            "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
        }, "Source5 prepared capacity bundle pin")
        require(capacity_pin["schema"] ==
                "allocatbelt.application-pressure-capacity-bundle-pin.v2",
                "unsupported Source5 prepared capacity bundle pin")
        capacity_key = exact(capacity_pin["capacity_key"], {
            "host_id", "workload", "profile", "calibration_id",
        }, "Source5 prepared capacity key")
        _validate_source5_calibration_id_roles_v2(
            v2, calibration["calibration_id"], condition["condition_id"],
            capacity_key,
        )
        require(capacity_key == {
            "host_id": recipe["job"]["value"]["host_id"],
            "workload": recipe["job"]["value"]["workload"],
            "profile": recipe["job"]["value"]["profile"],
            "calibration_id": v2["calibration_id"],
        }, "Source5 prepared capacity key differs from the original pressure job")
        for name in ("source_manifest", "request", "artifact", "receipt"):
            _artifact_reference(capacity_pin[name],
                                f"Source5 prepared capacity {name}")
    thresholds = exact(condition["readiness_thresholds"], {
        "minimum_overlap_seconds", "minimum_ready_samples", "maximum_sample_gap_ms",
    }, "pressure readiness thresholds")
    for name, item in thresholds.items():
        uint(item, f"pressure readiness {name}", positive=True)
    typed_schedule = exact(condition["schedule"], {"duration_seconds", "sample_interval_ms", "seed"}, "typed pressure condition schedule")
    uint(typed_schedule["duration_seconds"], "typed pressure condition duration", positive=True)
    uint(typed_schedule["sample_interval_ms"], "typed pressure sample interval", positive=True)
    uint(typed_schedule["seed"], "typed pressure seed", positive=True)

    deadlines = exact(recipe["deadlines"], {
        "trace_seconds", "drain_seconds", "shutdown_seconds", "process_seconds", "outer_seconds",
        "application_wall_timeout_seconds", "application_term_grace_seconds",
        "pressure_exit_observation_seconds", "pressure_duration_seconds", "pressure_total_seconds",
    }, "pressure-pair deadlines")
    for name in (
        "trace_seconds", "drain_seconds", "shutdown_seconds", "process_seconds", "outer_seconds",
        "application_wall_timeout_seconds", "pressure_exit_observation_seconds",
        "pressure_duration_seconds", "pressure_total_seconds",
    ):
        uint(deadlines[name], f"pressure-pair {name}", positive=True, maximum=14_400)
    require(type(deadlines["application_term_grace_seconds"]) in (int, float) and 0 < deadlines["application_term_grace_seconds"] <= 60, "pressure-pair TERM grace is outside its finite bound")

    budgets = exact(recipe["artifact_budgets"], {
        "stdout_bytes", "ids_bytes", "shutdown_bytes", "runtime_binding_bytes",
        "feedback_manifest_bytes", "feedback_events_bytes", "feedback_samples_bytes",
        "feedback_validation_bytes", "pressure_proof_bytes", "supervision_bytes",
        "member_sidecar_bytes", "pair_sidecar_bytes",
    }, "pressure-pair artifact budgets")
    for name, maximum in (
        ("stdout_bytes", 16 * 1024 * 1024), ("ids_bytes", MAX_TRACE_BYTES),
        ("shutdown_bytes", MAX_SMALL_BYTES), ("runtime_binding_bytes", MAX_SMALL_BYTES),
        ("feedback_manifest_bytes", 16 * 1024 * 1024), ("feedback_events_bytes", MAX_TRACE_BYTES),
        ("feedback_samples_bytes", MAX_SAMPLE_BYTES), ("feedback_validation_bytes", MAX_SMALL_BYTES),
        ("pressure_proof_bytes", MAX_SMALL_BYTES), ("supervision_bytes", MAX_SMALL_BYTES),
        ("member_sidecar_bytes", 4 * 1024 * 1024), ("pair_sidecar_bytes", 16 * 1024 * 1024),
    ):
        uint(budgets[name], f"pressure-pair {name}", positive=True, maximum=maximum)

    validators = exact(recipe["validators"], {
        "campaign_controller", "campaign_chronology", "feedback_composition", "feedback_validator",
        "pressure_validator", "soak_supervisor", "capacity_producer",
    }, "SourceV5 pressure-pair validators")
    for name, value in validators.items():
        item = exact(value, {"path", "sha256"}, f"SourceV5 {name} validator pin")
        require(type(item["path"]) is str and item["path"].startswith("scripts/"), f"SourceV5 {name} validator path is malformed")
        digest(item["sha256"], f"SourceV5 {name} validator SHA-256")
    require(type(recipe["members"]) is list and len(recipe["members"]) == 2, "pressure pair requires exactly two original member descriptors")
    for index, member_value in enumerate(recipe["members"]):
        member = exact(member_value, {
            "ordinal", "descriptor", "feedback_template", "identity", "application_binary",
            "construction_probe", "composition", "argv", "environment", "cwd", "tmpdir_path",
            "cpu_set", "cpu_affinity", "network_namespace_inode", "oracle", "outputs", "pressure_recipe",
        }, f"pressure pair member[{index}]")
        require(member["ordinal"] == index, "pressure pair member ordinal differs from original member order")
        desc = exact(member["descriptor"], {"pair", "executor", "allocator"}, f"pressure pair member[{index}] descriptor")
        token(desc["pair"], f"pressure pair member[{index}] pair")
        require(desc["executor"] in ("bounded", "tokio") and desc["allocator"] in ALLOCATORS, f"pressure pair member[{index}] executor/allocator is outside the original matrix")
        template = exact(member["feedback_template"], {"value", "template_sha256"}, f"pressure pair member[{index}] feedback template")
        require(type(template["value"]) is dict, "pressure member feedback template must be the original plan object")
        digest(template["template_sha256"], "feedback template semantic SHA-256")
        identity = exact(member["identity"], {
            "host_id", "run_id", "report_nonce", "allocator", "executor", "workload", "profile",
            "mode", "rate_per_second", "arrivals", "source_sha256", "binary_sha256",
            "resource_ceiling_sha256", "policy_sha256", "pressure_nonce",
        }, f"pressure pair member[{index}] APP identity")
        for name in ("host_id", "run_id", "allocator", "executor", "workload", "profile", "mode"):
            token(identity[name], f"pressure pair member[{index}] {name}")
        for name in ("report_nonce", "pressure_nonce"):
            require(type(identity[name]) is str and re.fullmatch(r"[0-9a-f]{32}", identity[name]) is not None, f"pressure pair member[{index}] {name} is malformed")
        digest(identity["source_sha256"], "pressure APP source SHA-256")
        digest(identity["binary_sha256"], "pressure APP binary SHA-256")
        digest(identity["resource_ceiling_sha256"], "pressure APP resource ceiling SHA-256")
        digest(identity["policy_sha256"], "pressure APP resolved policy SHA-256")
        require(identity["allocator"] == desc["allocator"] and identity["executor"] == EXECUTOR_LABELS[desc["executor"]], "pressure APP identity differs from its original process descriptor")
        require((identity["rate_per_second"] is None) == (identity["mode"] == "capacity"), "pressure APP rate field differs from its mode")
        require((identity["arrivals"] is None) == (identity["mode"] == "capacity"), "pressure APP arrivals field differs from its mode")
        if identity["mode"] == "open_loop":
            uint(identity["rate_per_second"], "pressure APP rate", positive=True)
            uint(identity["arrivals"], "pressure APP arrivals", positive=True)
        app_pin = _artifact_reference(member["application_binary"], f"pressure member[{index}] APP binary")
        probe = exact(member["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, f"pressure member[{index}] construction probe")
        require(type(probe["path"]) is str and Path(probe["path"]).is_absolute(), "pressure construction probe path is malformed")
        digest(probe["raw_sha256"], "pressure construction probe raw SHA-256")
        require(probe["allocator"] == desc["allocator"] and probe["binary_sha256"] == identity["binary_sha256"], "pressure construction probe identity differs from its target APP")
        composition = exact(member["composition"], {"request", "policy", "receipt"}, f"pressure member[{index}] composition")
        for name in composition:
            _artifact_reference(composition[name], f"pressure member[{index}] composition {name}")
        require(type(member["argv"]) is list and member["argv"] and all(type(arg) is str and "\x00" not in arg for arg in member["argv"]), "pressure member argv is malformed")
        require(type(member["environment"]) is dict and member["environment"], "pressure member environment is empty")
        require(type(member["cwd"]) is str and Path(member["cwd"]).is_absolute(), "pressure member cwd is malformed")
        require(type(member["tmpdir_path"]) is str and Path(member["tmpdir_path"]).is_absolute(), "pressure member TMPDIR is malformed")
        require(type(member["cpu_set"]) is str and member["cpu_set"], "pressure member CPU set is malformed")
        require(type(member["cpu_affinity"]) is list and member["cpu_affinity"] and all(type(cpu) is int and 0 <= cpu < 65536 for cpu in member["cpu_affinity"]), "pressure member CPU affinity is malformed")
        uint(member["network_namespace_inode"], "pressure member network namespace inode", positive=True)
        if member["oracle"] is not None:
            oracle = exact(member["oracle"], {"entry", "artifact"}, f"pressure member[{index}] oracle")
            require(type(oracle["entry"]) is dict, "pressure member oracle plan entry is malformed")
            _artifact_reference(oracle["artifact"], f"pressure member[{index}] oracle")
        outputs = exact(member["outputs"], {
            "root", "stdout", "stderr", "timing", "ids", "shutdown", "capacity_families", "runtime_binding",
            "trace_directory", "feedback_manifest", "feedback_events", "feedback_samples",
            "feedback_validation", "pressure_readback", "app_launch_attestation",
            "supervision_receipt", "cleanup_receipt", "runtime_expectation",
            "finalization_request", "finalization_receipt",
        }, f"pressure member[{index}] outputs")
        for name, path_value in outputs.items():
            require(type(path_value) is str and Path(path_value).is_absolute() and ".." not in Path(path_value).parts, f"pressure member[{index}] output {name} is not a normalized absolute path")
        file_output_names = set(outputs) - {"root", "trace_directory"}
        file_output_paths = [outputs[name] for name in file_output_names]
        require(len(set(file_output_paths)) == len(file_output_paths), f"pressure member[{index}] output paths alias each other")
        require(outputs["trace_directory"] not in file_output_paths and outputs["root"] not in file_output_paths, f"pressure member[{index}] output path aliases a directory")
        pressure = exact(member["pressure_recipe"], {"artifact", "semantic_sha256", "condition_sha256"}, f"pressure member[{index}] pressure recipe")
        _artifact_reference(pressure["artifact"], f"pressure member[{index}] pressure recipe")
        digest(pressure["semantic_sha256"], "pressure recipe semantic SHA-256")
        digest(pressure["condition_sha256"], "pressure recipe condition SHA-256")
    return recipe


def _load_validators(
    recipe: dict[str, Any], inputs: dict[str, Any],
    chronology_module: Any | None = None,
) -> dict[str, Any]:
    source, source_root = inputs["source"], inputs["source_root"]
    result: dict[str, Any] = {}
    paths = {
        "campaign_controller": "scripts/application-campaign.py",
        "campaign_chronology": "scripts/application-campaign-chronology.py",
        "feedback_composition": "scripts/application-feedback-composition.py",
        "feedback_validator": "scripts/application-feedback-readback.py",
        "pressure_validator": "scripts/application-pressure-readback.py",
        "soak_supervisor": "scripts/application-soak-readback.py",
        "capacity_producer": "scripts/application-byte-capacity.py",
    }
    harness_keys = {
        "campaign_controller": "campaign_controller",
        "feedback_validator": "feedback_validator",
        "pressure_validator": "pressure_validator",
        "soak_supervisor": "soak_validator",
        "capacity_producer": "byte_capacity_producer",
    }
    for name, relative in paths.items():
        pin = exact(recipe["validators"][name], {"path", "sha256"}, f"{name} SourceV5 validator")
        require(pin["path"] == relative, f"{name} validator path differs from the SourceV5 contract")
        module, inventory_pin = _pinned_source_module(source, source_root, relative, name, MAX_SOURCE_BYTES)
        require(pin["sha256"] == inventory_pin["sha256"], f"{name} validator differs from its regular SourceV5 inventory pin")
        if name in harness_keys:
            harness = exact(source["qualification_harness"], {
                "campaign_controller", "feedback_validator", "byte_capacity_producer", "pressure_driver",
                "pressure_validator", "soak_recipe_builder", "soak_validator", "soak_runner",
            }, "SourceV5 qualification harness")
            require(harness[harness_keys[name]] == pin, f"{name} validator differs from the original SourceV5 harness pin")
        result[name] = module
        result[f"{name}_pin"] = pin

    if chronology_module is not None:
        relative = paths["campaign_chronology"]
        expected = recipe["validators"]["campaign_chronology"]
        active_path = Path(getattr(chronology_module, "__file__", "")).resolve(strict=True)
        require(active_path == source_root / relative and
                expected["path"] == relative and
                expected["sha256"] == result["campaign_chronology_pin"]["sha256"],
                "Source5 pressure must receive the already-loaded pinned chronology module instance")
        result["campaign_chronology"] = chronology_module

    # The pressure reader validates sealed artifacts, while the separate
    # pressure driver owns the live host/storage/network recheck. Bind and load
    # that driver through its original SourceV5 harness pin as well.
    harness = exact(source["qualification_harness"], {
        "campaign_controller", "feedback_validator", "byte_capacity_producer", "pressure_driver",
        "pressure_validator", "soak_recipe_builder", "soak_validator", "soak_runner",
    }, "SourceV5 qualification harness")
    driver_pin = exact(harness["pressure_driver"], {"path", "sha256"}, "SourceV5 pressure driver pin")
    require(driver_pin["path"] == "scripts/application-pressure-driver.py", "SourceV5 pressure driver path differs from its captured contract")
    driver_module, driver_inventory_pin = _pinned_source_module(
        source, source_root, driver_pin["path"], "pressure driver", MAX_SOURCE_BYTES,
    )
    require(driver_pin["sha256"] == driver_inventory_pin["sha256"], "SourceV5 pressure driver differs from its regular source inventory pin")
    result["pressure_driver"] = driver_module
    result["pressure_driver_pin"] = driver_pin
    fixed_path = "scripts/application-fixed-pair.py"
    fixed_module, fixed_inventory_pin = _pinned_source_module(
        source, source_root, fixed_path, "Source5 fixed-pair verifier",
        MAX_SOURCE_BYTES,
    )
    result["fixed_pair"] = fixed_module
    result["fixed_pair_pin"] = fixed_inventory_pin
    return result


def _member_feedback_template(
    inputs: dict[str, Any], member: dict[str, Any], normalized_inputs: dict[str, Any],
) -> dict[str, Any]:
    descriptor = member["descriptor"]
    wanted_executor = EXECUTOR_LABELS[descriptor["executor"]]
    matches = [item for item in inputs["plan"]["feedback_process_templates"] if (
        item["identity"]["host_id"] == inputs["host_id"]
        and item["identity"]["workload"] == inputs["job"]["workload"]
        and item["identity"]["profile"] == inputs["job"]["profile"]
        and item["identity"]["comparison_family"] == "external_pressure"
        and item["identity"]["allocator"] == descriptor["allocator"]
        and item["identity"]["executor"] == wanted_executor
        and item["identity"]["pressure_condition_id"] == inputs["condition"]["condition_id"]
    )]
    require(len(matches) == 1, "pressure member has no unique original SourceV5 feedback template")
    template = matches[0]
    stored = member["feedback_template"]
    require(stored["value"] == template and stored["template_sha256"] == template["template_sha256"], "pressure member feedback template differs from its exact original plan object")
    return template


def _derive_member_argv(
    inputs: dict[str, Any], member: dict[str, Any], deadlines: dict[str, Any], binary_path: Path,
) -> list[str]:
    job = inputs["job"]
    descriptor = member["descriptor"]
    argv = [
        str(binary_path), "--executor", descriptor["executor"], "--workload", job["workload"],
        "--profile", job["profile"], "--mode", job["mode"],
        "--trace-deadline-seconds", str(deadlines["trace_seconds"]),
        "--drain-deadline-seconds", str(deadlines["drain_seconds"]),
        "--shutdown-deadline-seconds", str(deadlines["shutdown_seconds"]),
        "--process-deadline-seconds", str(deadlines["process_seconds"]),
    ]
    if job["mode"] == "open_loop":
        argv.extend(["--rate", str(job["rate_per_second"]), "--arrivals", str(job["arrivals"])])
    return argv


def _expected_member_environment(
    inputs: dict[str, Any], member: dict[str, Any], shared_policy: dict[str, Any],
    modules: dict[str, Any],
) -> dict[str, str]:
    source = inputs["source"]
    job = inputs["job"]
    descriptor = member["descriptor"]
    outputs = member["outputs"]
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": member["tmpdir_path"],
        "ALLOCATBELT_APP_SHUTDOWN_REPORT": outputs["shutdown"],
        "ALLOCATBELT_APP_ID_REPORT": outputs["ids"],
        "ALLOCATBELT_APP_FAMILY_REPORT": outputs["capacity_families"],
        "ALLOCATBELT_APP_RUNTIME_REPORT": outputs["runtime_binding"],
        "ALLOCATBELT_APP_COMPARISON_FAMILY": "external_pressure",
        "ALLOCATBELT_APP_RESOURCE_CEILING_SHA256": member["identity"]["resource_ceiling_sha256"],
        "ALLOCATBELT_APP_POLICY_SHA256": member["identity"]["policy_sha256"],
        "ALLOCATBELT_APP_REPORT_NONCE": member["identity"]["report_nonce"],
        "ALLOCATBELT_APP_RUN_ID": job["run_id"],
        "ALLOCATBELT_APP_EXECUTOR": EXECUTOR_LABELS[descriptor["executor"]],
        "ALLOCATBELT_APP_ALLOCATOR": descriptor["allocator"],
        "ALLOCATBELT_APP_WORKLOAD": job["workload"],
        "ALLOCATBELT_APP_PROFILE": job["profile"],
        "ALLOCATBELT_APP_SOURCE_SHA256": source["source"]["source_tree_sha256"],
        "ALLOCATBELT_APP_BINARY_SHA256": member["identity"]["binary_sha256"],
        "ALLOCATBELT_APP_ORACLE_FILE": "" if member["oracle"] is None else member["oracle"]["artifact"]["path"],
        "ALLOCATBELT_APP_ORACLE_SHA256": "" if member["oracle"] is None else member["oracle"]["artifact"]["raw_sha256"],
        "ALLOCATBELT_APP_PRESSURE_NONCE": member["identity"]["pressure_nonce"],
        "ALLOCATBELT_APP_PRESSURE_QUALIFICATION": "true",
        "ALLOCATBELT_APP_HOST_ID": inputs["host_id"],
        "ALLOCATBELT_APP_CAPACITY_CALIBRATION_FILE": inputs["recipe"]["capacity_bundle"]["artifact"]["path"],
        "ALLOCATBELT_APP_CAPACITY_CALIBRATION_SHA256": inputs["recipe"]["capacity_bundle"]["artifact"]["raw_sha256"],
        "ALLOCATBELT_APP_FEEDBACK_TRACE_DIR": outputs["trace_directory"],
    }
    require(shared_policy["policy_sha256"] == _shared_policy_semantic_sha(shared_policy), "shared numeric policy self digest is invalid")
    floor_policy_id = _validated_capacity_floor_policy_id(
        inputs, member, shared_policy, modules,
    )
    if floor_policy_id is not None:
        environment["ALLOCATBELT_APP_CAPACITY_FLOOR_POLICY_ID"] = floor_policy_id
    return environment


def _validated_capacity_floor_policy_id(
    inputs: dict[str, Any], member: dict[str, Any], shared_policy: dict[str, Any],
    modules: dict[str, Any],
) -> str | None:
    """Bind the optional launch selector to SourceV5, capacity, and this member."""
    selected = inputs["spec"].get("capacity_floor_policy_id")
    source_feedback = inputs["source"]["feedback_policy"]
    source_policy = source_feedback["policy"]
    policy_context = shared_policy.get("context")
    require(type(policy_context) is dict, "shared numeric policy context is malformed")
    capacity_bundle = inputs["recipe"]["capacity_bundle"]
    expected_capacity = {
        name: {"path": capacity_bundle[name]["path"],
               "raw_sha256": capacity_bundle[name]["raw_sha256"]}
        for name in ("request", "artifact", "receipt")
    }
    require(shared_policy.get("capacity_bundle") == expected_capacity,
            "shared numeric policy capacity pins differ from the validated SourceV5 bundle")

    if selected is None:
        require("capacity_floor_policy" not in source_policy and
                "capacity_floor_policy_id" not in policy_context,
                "uncalibrated pressure launch contains a capacity-floor selector")
        return None

    composer = modules["feedback_composition"]
    validator = modules["feedback_validator"]
    require(type(selected) is str and
            selected == getattr(composer, "CAPACITY_FLOOR_POLICY_ID", None),
            "SourceV5 campaign selected an unknown capacity-floor policy ID")
    try:
        descriptor = validator._validate_capacity_floor_policy_descriptor(
            source_policy.get("capacity_floor_policy"),
        )
    except Exception as error:
        raise PressurePairError(
            f"SourceV5 feedback reader rejected the capacity-floor policy: {error}"
        ) from error
    require(descriptor["policy_id"] == selected and
            policy_context.get("capacity_floor_policy_id") == selected,
            "launch selector differs from the pinned SourceV5 or resolved policy context")
    matches = [row for row in shared_policy["member_resolutions"] if (
        row.get("pair") == member["descriptor"]["pair"]
        and row.get("executor") == member["descriptor"]["executor"]
        and row.get("allocator") == member["descriptor"]["allocator"]
    )]
    require(len(matches) == 1 and
            matches[0]["resolved_policy_sha256"] == member["identity"]["policy_sha256"],
            "launch selector has no unique matching SourceV5 member resolution")
    return selected


def _shared_policy_semantic_sha(value: dict[str, Any]) -> str:
    body = {key: item for key, item in value.items() if key != "policy_sha256"}
    return sha256_bytes(canonical_bytes(body))


def _run_composer_cli(composer: Any, arguments: list[str]) -> dict[str, Any]:
    output = io.BytesIO()
    text_output = io.TextIOWrapper(output, encoding="ascii", write_through=True)
    with contextlib.redirect_stdout(text_output):
        status = composer.main(arguments)
        text_output.flush()
    require(status == 0, "captured SourceV5 composer CLI rejected its pinned request")
    raw = output.getvalue()
    try:
        result = json.loads(raw.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PressurePairError(f"captured SourceV5 composer CLI returned malformed status JSON: {error}") from error
    require(type(result) is dict and raw == canonical_bytes(result), "captured SourceV5 composer CLI status is not canonical JSON")
    require(result.get("validated") is True and result.get("execution_ready") is False and result.get("qualification_eligible") is False and result.get("controller_chronology_proven") is False, "composer CLI output attempts to claim readiness")
    return result


def _verify_policy_resolutions(
    recipe: dict[str, Any], inputs: dict[str, Any], modules: dict[str, Any], output_root: Path,
    capacity: dict[str, Any], *, offline_replay_context: object | None = None,
) -> dict[str, Any]:
    composer = modules["feedback_composition"]
    capacity_floor_policy_id = inputs["spec"].get("capacity_floor_policy_id")
    if capacity_floor_policy_id is not None:
        require(type(capacity_floor_policy_id) is str and
                capacity_floor_policy_id == getattr(composer, "CAPACITY_FLOOR_POLICY_ID", None) and
                type(getattr(composer, "REQUEST_SCHEMA_V2", None)) is str,
                "SourceV5 campaign selected an unsupported capacity-floor policy")
    else:
        require("capacity_floor_policy" not in inputs["source"]["feedback_policy"]["policy"],
                "static pressure composition received a selected SourceV5 floor policy")
    bundle = {
        key: {"path": recipe["capacity_bundle"][key]["path"], "raw_sha256": recipe["capacity_bundle"][key]["raw_sha256"]}
        for key in ("request", "artifact", "receipt")
    }
    source_pin = {"path": str(inputs["manifest_path"]), "raw_sha256": inputs["manifest_raw_sha256"]}
    resolutions: list[dict[str, Any]] = []
    for index, member in enumerate(recipe["members"]):
        request_path, request_raw, request_sha = read_pin(member["composition"]["request"], f"member[{index}] resolve request", MAX_SMALL_BYTES)
        request = json.loads(request_raw)
        require(request_raw == canonical_bytes(request), f"member[{index}] resolve request is not canonical JSON")
        probe = member["construction_probe"]
        context = {
            "host_id": inputs["host_id"], "workload": inputs["job"]["workload"],
            "profile": inputs["job"]["profile"], "calibration_id": capacity["request_value"]["calibration_id"],
        }
        expected_request = {
            "schema": (composer.REQUEST_SCHEMA_V2 if capacity_floor_policy_id is not None
                       else composer.REQUEST_SCHEMA),
            "source_root": str(inputs["source_root"]),
            "source_manifest": source_pin,
            "context": context,
            "construction_probe": {
                "path": probe["path"], "raw_sha256": probe["raw_sha256"],
                "allocator": probe["allocator"], "binary_sha256": probe["binary_sha256"],
            },
            "capacity_bundle": bundle,
        }
        if capacity_floor_policy_id is not None:
            expected_request["capacity_floor_policy_id"] = capacity_floor_policy_id
        require(request == expected_request, f"member[{index}] resolve request differs from the exact pinned SourceV5/probe/capacity inputs")
        if offline_replay_context is None:
            with tempfile.TemporaryDirectory(prefix=f"resolve-{index}-", dir=output_root / "preflight") as temporary:
                temporary_root = Path(temporary)
                policy_output = temporary_root / "resolved-policy.json"
                receipt_output = temporary_root / "composition-receipt.json"
                cli_result = _run_composer_cli(composer, [
                    "resolve", "--request", str(request_path),
                    "--policy-output", str(policy_output),
                    "--receipt-output", str(receipt_output),
                ])
                resolved, _resolved_bytes, _resolved_rawsha = read_json(policy_output, f"member[{index}] CLI resolved policy", MAX_SMALL_BYTES)
                receipt, _receipt_bytes, _receipt_rawsha = read_json(receipt_output, f"member[{index}] CLI resolve receipt", MAX_SMALL_BYTES)
                resolved_raw = canonical_bytes(resolved)
                receipt_raw = canonical_bytes(receipt)
                require(cli_result["policy_sha256"] == resolved["policy_sha256"] and cli_result["receipt_sha256"] == receipt["receipt_sha256"], f"member[{index}] resolver CLI status differs from its output artifacts")
        else:
            replay = exact(offline_replay_context, {
                "schema", "evidence_path_map", "capture_members",
            }, "offline pressure policy replay context")
            require(replay["schema"] == "allocatbelt.application-pressure-policy-replay.v1" and
                    type(replay["capture_members"]) is list and
                    len(replay["capture_members"]) == len(recipe["members"]),
                    "offline pressure policy replay context has the wrong capture-member set")
            capture = exact(replay["capture_members"][index], {
                "construction_probe", "capture_receipt", "capacity_bundle",
            }, f"offline pressure policy capture member[{index}]")
            expected_bundle = {
                name: {"path": recipe["capacity_bundle"][name]["path"],
                       "raw_sha256": recipe["capacity_bundle"][name]["raw_sha256"]}
                for name in ("request", "artifact", "receipt")
            }
            require(capture["construction_probe"] == probe and
                    capture["capacity_bundle"] == expected_bundle,
                    f"offline pressure policy capture member[{index}] differs from original probe/bundle pins")
            context = {
                "schema": composer.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
                "evidence_path_map": replay["evidence_path_map"],
                "probe_capture_pin": capture["capture_receipt"],
                "capacity_bundle": capture["capacity_bundle"],
            }
            resolved, receipt = composer.compose_calibrated_policy_v5_offline(
                request, request_sha, replay_context=context,
            )
            resolved_raw = canonical_bytes(resolved)
            receipt_raw = canonical_bytes(receipt)
        if capacity_floor_policy_id is None:
            require("capacity_floor_policy_id" not in resolved and
                    "capacity_floor_policy_id" not in resolved["context"] and
                    "capacity_floor_policy_id" not in receipt and
                    "capacity_floor_policy_id" not in receipt["context"],
                    f"member[{index}] static composition unexpectedly contains a capacity-floor selector")
        else:
            require(resolved.get("capacity_floor_policy_id") == capacity_floor_policy_id and
                    resolved["context"].get("capacity_floor_policy_id") == capacity_floor_policy_id and
                    receipt.get("capacity_floor_policy_id") == capacity_floor_policy_id and
                    receipt["context"].get("capacity_floor_policy_id") == capacity_floor_policy_id,
                    f"member[{index}] resolved policy/receipt lost the explicit capacity-floor selector")
        _policy_path, expected_policy_raw, expected_policy_sha = read_pin(member["composition"]["policy"], f"member[{index}] resolved policy", MAX_SMALL_BYTES)
        _receipt_path, expected_receipt_raw, expected_receipt_sha = read_pin(member["composition"]["receipt"], f"member[{index}] resolve receipt", MAX_SMALL_BYTES)
        require(resolved_raw == expected_policy_raw and sha256_bytes(resolved_raw) == expected_policy_sha, f"member[{index}] resolver output differs from its frozen policy pin")
        require(receipt_raw == expected_receipt_raw and sha256_bytes(receipt_raw) == expected_receipt_sha, f"member[{index}] resolver receipt differs from its frozen pin")
        resolutions.append({
            "pair": member["descriptor"]["pair"],
            "executor": member["descriptor"]["executor"],
            "allocator": member["descriptor"]["allocator"],
            "binary_sha256": member["identity"]["binary_sha256"],
            "probe_raw_sha256": member["construction_probe"]["raw_sha256"],
            "request_raw_sha256": request_sha,
            "resolved_policy_raw_sha256": expected_policy_sha,
            "resolved_policy_sha256": resolved["policy_sha256"],
            "composition_receipt_raw_sha256": expected_receipt_sha,
            "policy": resolved,
        })

    first_policy = resolutions[0]["policy"]
    first_context = first_policy["context"]
    for row in resolutions[1:]:
        policy = row["policy"]
        require(policy["policy"] == first_policy["policy"], "paired APPs resolve different numeric feedback policies")
        for key in (
            "source_manifest_raw_sha256", "source_manifest_sha256", "source_tree_sha256", "build_sha256",
            "base_policy_artifact_sha256", "base_policy_sha256", "base_context_sha256",
            "capacity_request_raw_sha256", "capacity_artifact_raw_sha256", "capacity_receipt_raw_sha256",
            "resolution_rule_version",
        ):
            require(policy[key] == first_policy[key], f"paired APPs resolve different shared policy context at {key}")
        require({name: value for name, value in policy["context"].items() if name != "allocator"} == {name: value for name, value in first_context.items() if name != "allocator"}, "paired APPs resolve different feedback context")

    first_numeric = first_policy["policy"]
    comparison_values = {
        "source_manifest": source_pin,
        "context": {key: first_context[key] for key in ("host_id", "workload", "profile", "calibration_id")},
        "capacity_bundle": bundle,
        "base_policy_artifact_sha256": first_policy["base_policy_artifact_sha256"],
        "base_policy_sha256": first_policy["base_policy_sha256"],
        "base_context_sha256": first_policy["base_context_sha256"],
        "resolution_rule_version": first_policy["resolution_rule_version"],
        "numeric_policy": first_numeric,
        "baseline": first_numeric["collector"]["expected_global_control_baseline"],
        "hard_ceilings": {
            "global": first_numeric["global_ceilings"],
            "tenant": first_numeric["tenant_ceilings"],
        },
        "normalization_denominators": {
            "capacity_sources": first_numeric["capacity_sources"],
            "scope_limits": first_numeric["scope_limits"],
            "rate_buckets": first_numeric["rate_buckets"],
        },
        "member_resolutions": [
            {key: row[key] for key in (
                "pair", "executor", "allocator", "binary_sha256", "probe_raw_sha256",
                "request_raw_sha256", "resolved_policy_raw_sha256", "resolved_policy_sha256",
                "composition_receipt_raw_sha256",
            )}
            for row in resolutions
        ],
    }
    if capacity_floor_policy_id is not None:
        comparison_values["context"]["capacity_floor_policy_id"] = capacity_floor_policy_id
    policy_doc = {"schema": POLICY_SCHEMA, **comparison_values}
    policy_doc["policy_sha256"] = _shared_policy_semantic_sha(policy_doc)
    shared_path, shared_raw, shared_sha = read_pin(recipe["shared_policy"]["artifact"], "common numeric feedback policy", MAX_SMALL_BYTES)
    expected_shared = json.loads(shared_raw)
    require(expected_shared == policy_doc and sha256_bytes(canonical_bytes(expected_shared)) == shared_sha, "shared numeric policy artifact differs from both independently resolved target policies")
    return {"path": str(shared_path), "raw_sha256": shared_sha, "value": expected_shared, "resolutions": resolutions}


def _verify_pressure_condition(
    recipe: dict[str, Any], inputs: dict[str, Any], modules: dict[str, Any],
    *, offline_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controller = modules["campaign_controller"]
    inputs_module = controller.campaign_inputs_module(inputs["plan"]["campaign_inputs_module_sha256"])
    normalized = inputs_module.validate_qualification_inputs(
        inputs["spec"]["qualification_inputs"],
        [item["host_id"] for item in inputs["spec"]["hosts"]],
        inputs["spec"]["cells"],
        inputs["sources"],
        inputs["input_root"],
    )
    job = inputs["job"]
    matches = [item for item in normalized["pressure_conditions"] if (
        item["host_id"] == inputs["host_id"]
        and item["capacity_key"]["workload"] == job["workload"]
        and item["capacity_key"]["profile"] == job["profile"]
    )]
    require(len(matches) == 1, "original SourceV5 plan has no unique typed pressure condition for this job")
    typed = matches[0]
    stored = recipe["pressure_condition"]
    condition_file = safe_child(inputs["input_root"], typed["condition"]["relative_path"], "original pressure condition file")
    _raw, raw_sha, _info = read_stable(condition_file, "original pressure condition file", MAX_SPEC_BYTES)
    require(raw_sha == stored["condition"]["raw_sha256"] == typed["condition"]["raw_sha256"] == stored["condition_sha256"] == typed["condition_sha256"], "pressure condition raw bytes or typed condition digest differ")
    require(stored["condition"]["path"] == str(condition_file.resolve(strict=True)), "pressure condition external path differs from the original input")
    condition_value, condition_raw, _condition_sha = read_json(condition_file, "original pressure request template", MAX_SPEC_BYTES, raw_sha)
    if "pressure_calibration_v2" in stored:
        condition_value = exact(condition_value, {
            "schema", "host_id", "condition_id", "capacity_key",
            "pressure_calibration_id", "readiness_threshold_rule",
            "readiness_thresholds", "pressure_thresholds", "schedule",
        }, "original Source5 prospective pressure condition")
        require(condition_value["schema"] ==
                "allocatbelt.application-source5-pressure-condition.v1" and
                condition_value["host_id"] == inputs["host_id"] and
                condition_value["condition_id"] == typed["condition_id"] and
                condition_value["capacity_key"] == typed["capacity_key"] and
                condition_value["pressure_calibration_id"] ==
                    stored["pressure_calibration_v2"]["pressure_calibration_id"] and
                condition_value["readiness_threshold_rule"] ==
                    "allocatbelt.application-source5-pressure-readiness-threshold-rule.v1" and
                condition_value["readiness_thresholds"] ==
                    typed["readiness_thresholds"],
                "Source5 prospective pressure-condition identity/readiness differs from its typed generation")
    else:
        require(condition_value.get("schema") == "allocatbelt.application-pressure-request.v1" and condition_value.get("identity", {}).get("condition_id") == typed["condition_id"], "pressure request template differs from its typed condition ID")
    driver = modules["pressure_driver"]
    driver_schedule = driver._schedule(condition_value.get("schedule"))
    require(
        {name: driver_schedule[name] for name in ("duration_seconds", "sample_interval_ms", "seed")} == typed["schedule"],
        "typed SourceV5 pressure schedule differs from the immutable driver request template",
    )
    threshold_keys = driver._threshold_keys()
    if "pressure_calibration_v2" in stored:
        require(condition_value.get("pressure_calibration_id") ==
                stored["pressure_calibration_v2"]["pressure_calibration_id"],
                "Source5 v2 condition calibration ID differs from its predeclared raw condition")
        require(condition_value.get("readiness_thresholds") ==
                typed["readiness_thresholds"],
                "Source5 v2 condition campaign-readiness thresholds differ from their typed inputs")
        driver_threshold_values = exact(
            condition_value.get("pressure_thresholds"), threshold_keys,
            "original Source5 numeric pressure thresholds",
        )
    else:
        driver_threshold_values = exact(condition_value.get("readiness_thresholds"),
                                        threshold_keys,
                                        "original driver readiness thresholds")
    driver_thresholds = {
        name: uint(driver_threshold_values[name], f"original driver readiness threshold {name}", positive=True)
        for name in sorted(threshold_keys)
    }
    require(stored["condition_id"] == typed["condition_id"] and stored["readiness_thresholds"] == typed["readiness_thresholds"] and stored["schedule"] == typed["schedule"], "pressure condition thresholds or schedule differ from the original plan inputs")
    stored_calibration = stored["pressure_calibration"]
    typed_calibration = typed["pressure_calibration"]
    for name in ("artifact", "receipt"):
        path = safe_child(inputs["input_root"], typed_calibration[name]["relative_path"], f"original pressure calibration {name}")
        _raw, actual, _info = read_stable(path, f"original pressure calibration {name}", MAX_SMALL_BYTES)
        require(stored_calibration[name]["path"] == str(path.resolve(strict=True)) and stored_calibration[name]["raw_sha256"] == typed_calibration[name]["raw_sha256"] == actual, f"pressure calibration {name} differs from its original typed pin")
    if "pressure_calibration_v2" not in stored:
        request_calibration = exact(condition_value.get("pressure_calibration"), {"path", "sha256"}, "original pressure request calibration pin")
        require(request_calibration == {
            "path": stored_calibration["artifact"]["path"],
            "sha256": stored_calibration["artifact"]["raw_sha256"],
        }, "original pressure request calibration differs from its typed SourceV5 calibration artifact")
    require(stored_calibration["validator_sha256"] == typed_calibration["validator_sha256"] == modules["pressure_validator_pin"]["sha256"], "pressure calibration validator differs from SourceV5")
    source_capacity = [item for item in normalized["capacity_templates"] if (
        item["host_id"] == inputs["host_id"] and item["workload"] == job["workload"] and item["profile"] == job["profile"]
    )]
    require(len(source_capacity) == 1,
            "pressure condition has no unique original capacity template")
    if "pressure_calibration_v2" in stored:
        require(stored_calibration["calibration_id"] ==
                stored["pressure_calibration_v2"]["pressure_calibration_id"] and
                source_capacity[0]["calibration_id"] ==
                stored["pressure_calibration_v2"]["calibration_id"],
                "Source5 pressure and capacity calibration identities differ from their separate frozen roles")
    else:
        require(source_capacity[0]["calibration_id"] ==
                stored_calibration["calibration_id"],
                "pressure calibration ID differs from its original capacity template")
    calibration_scope_v2 = None
    effective_calibration = stored_calibration["artifact"]
    if "pressure_calibration_v2" in stored:
        binding = stored["pressure_calibration_v2"]
        require(binding["validator_sha256"] == modules["pressure_validator_pin"]["sha256"],
                "Source5 calibration scope reader differs from the captured pressure validator")
        require(binding["calibration_id"] == source_capacity[0]["calibration_id"],
                "Source5 context calibration ID differs from the original capacity key")
        require(binding["pressure_calibration_id"] ==
                condition_value.get("pressure_calibration_id"),
                "Source5 prospective pressure calibration ID differs from the original condition bytes")
        expected_key = {
            "host_id": inputs["host_id"], "workload": job["workload"],
            "profile": job["profile"], "calibration_id": binding["calibration_id"],
        }
        require(binding["capacity_bundle_pins"]["capacity_key"] == expected_key and
                binding["capacity_bundle_pins"]["source_manifest"] == {
                    "path": str(inputs["manifest_path"]),
                    "raw_sha256": inputs["manifest_raw_sha256"],
                }, "Source5 context calibration producer bundle differs from its frozen host/cell/source")
        reader = modules["pressure_validator"]
        calibration_v2 = raw_pin(binding["artifact"], "Source5 context calibration artifact")
        context_policy_pin = raw_pin(binding["context_policy"], "Source5 context-policy bundle")
        capacity_bundle_pins = binding["capacity_bundle_pins"]
        observed_host_pin = raw_pin(binding["observed_host"], "Source5 observed host context")
        stored_scope_pin = exact(binding["scope_receipt"], {
            "path", "raw_sha256", "scope_sha256",
        }, "Source5 independent calibration scope receipt pin")
        scope_receipt, scope_raw, scope_sha = read_json(
            Path(stored_scope_pin["path"]),
            "Source5 independent calibration scope receipt", MAX_SMALL_BYTES,
            stored_scope_pin["raw_sha256"],
        )
        host_verification = _verify_source5_host_verification_v2(
            scope_receipt, observed_host_pin, inputs["host_id"],
        )
        require(scope_raw == canonical_bytes(scope_receipt) and
                scope_receipt.get("schema") == "allocatbelt.application-pressure-calibration-scope-readback.v2" and
                scope_receipt.get("replay_success") is True and
                scope_receipt.get("validated") is True and
                scope_receipt.get("execution_ready") is False and
                scope_receipt.get("qualification_eligible") is False and
                scope_receipt.get("controller_chronology_proven") is False and
                scope_receipt.get("scope_sha256") == stored_scope_pin["scope_sha256"] and
                scope_receipt.get("condition_id") == stored["condition_id"] and
                scope_receipt.get("pressure_calibration_id") == binding["pressure_calibration_id"] and
                scope_receipt.get("host_verification") == host_verification and
                scope_receipt.get("capacity_key") == expected_key and
                scope_receipt.get("condition_sha256") == raw_sha and
                scope_receipt.get("readiness_thresholds") == typed["readiness_thresholds"] and
                scope_receipt.get("pressure_thresholds") == driver_thresholds and
                scope_receipt.get("capacity_tsv_raw_sha256") ==
                    capacity_bundle_pins["artifact"]["raw_sha256"] and
                scope_receipt.get("capacity_bundle_pins_sha256") ==
                    sha256_bytes(canonical_bytes(capacity_bundle_pins)) and
                scope_receipt.get("source_manifest_sha256") == inputs["manifest_raw_sha256"] and
                scope_receipt.get("source_manifest_semantic_sha256") == inputs["source"]["manifest_sha256"] and
                scope_receipt.get("source_tree_sha256") == inputs["source"]["source"]["source_tree_sha256"] and
                scope_receipt.get("observed_host_raw_sha256") == observed_host_pin["raw_sha256"],
                "Source5 independent calibration scope receipt differs from the exact condition/source/capacity/host pins")
        try:
            if offline_context is None:
                replayed_scope = reader.verify_calibration_scope_v2(
                    calibration_v2, context_policy_pin, capacity_bundle_pins,
                    observed_host_pin,
                )
            else:
                offline = exact(offline_context, {
                    "schema", "source_root", "evidence_path_map",
                }, "closed offline pressure calibration context")
                require(offline["schema"] == OFFLINE_CALIBRATION_CONTEXT_SCHEMA and
                        offline["source_root"] == str(inputs["source_root"]),
                        "offline pressure calibration context changed its original SourceRoot")
                replayed_scope = reader.verify_calibration_scope_v2_offline(
                    calibration_v2, context_policy_pin, capacity_bundle_pins,
                    observed_host_pin, source_root=offline["source_root"],
                    evidence_path_map=offline["evidence_path_map"],
                    host_verification_pin=stored_scope_pin,
                )
        except Exception as error:
            raise PressurePairError(
                f"pinned pressure reader rejected context-scoped calibration v2: {error}"
            ) from error
        require(type(replayed_scope) is dict and
                reader._validate_scope_receipt_v2(
                    scope_receipt, calibration_v2["raw_sha256"],
                ) == scope_receipt and
                reader._scope_receipts_match_replay_v2(scope_receipt, replayed_scope) and
                scope_sha == stored_scope_pin["raw_sha256"] and
                replayed_scope.get("context_policy_sha256") ==
                    scope_receipt.get("context_policy_sha256") and
                replayed_scope.get("condition_sha256") == raw_sha and
                replayed_scope.get("pressure_calibration_id") ==
                    binding["pressure_calibration_id"] and
                replayed_scope.get("capacity_key") == expected_key and
                replayed_scope.get("pressure_thresholds") == driver_thresholds and
                replayed_scope.get("readiness_thresholds") == typed["readiness_thresholds"],
                "Source5 context calibration scope receipt differs from its independent replay")
        effective_calibration = calibration_v2
        calibration_scope_v2 = {
            "schema": "allocatbelt.application-pressure-calibration-binding.v2",
            "scope_receipt": stored_scope_pin,
            "validator_sha256": binding["validator_sha256"],
            "condition": stored["condition"],
            "context_policy": context_policy_pin,
            "capacity_bundle_pins": capacity_bundle_pins,
            "observed_host": observed_host_pin,
            "context_policy_sha256": scope_receipt["context_policy_sha256"],
        }
    return {
        "value": typed, "request": condition_value, "raw_sha256": raw_sha,
        "driver_readiness_thresholds": driver_thresholds, "normalized_inputs": normalized,
        "effective_calibration": effective_calibration,
        "calibration_scope_v2": calibration_scope_v2,
    }


def _verify_capacity_bundle(recipe: dict[str, Any], inputs: dict[str, Any], modules: dict[str, Any]) -> dict[str, Any]:
    producer = modules["capacity_producer"]
    capacity_bundle = recipe["capacity_bundle"]
    pins = {
        key: {"path": value["path"], "sha256": value["raw_sha256"]}
        for key, value in capacity_bundle.items()
    }
    try:
        require(producer.verify_capacity_bundle(pins["request"], pins["artifact"], pins["receipt"]) is True, "pinned SourceV5 capacity producer did not accept the complete bundle")
    except Exception as error:
        raise PressurePairError(f"SourceV5 producer bundle replay failed: {error}") from error
    request_path, request_raw, _request_sha = read_pin(capacity_bundle["request"], "SourceV5 capacity request", MAX_SMALL_BYTES)
    artifact_path, artifact_raw, artifact_sha = read_pin(capacity_bundle["artifact"], "SourceV5 capacity artifact", 4096)
    receipt_path, receipt_raw, receipt_sha = read_pin(capacity_bundle["receipt"], "SourceV5 capacity receipt", MAX_SMALL_BYTES)
    request = json.loads(request_raw)
    receipt = json.loads(receipt_raw)
    require(request_raw == canonical_bytes(request) and receipt_raw == canonical_bytes(receipt), "SourceV5 capacity request/receipt bytes are not canonical JSON")
    identity = request.get("identity")
    require(type(identity) is dict and identity.get("host_id") == inputs["host_id"] and identity.get("workload") == inputs["job"]["workload"] and identity.get("profile") == inputs["job"]["profile"], "capacity bundle context differs from the selected pressure cell")
    require(identity.get("source_sha256") == inputs["source"]["source"]["source_tree_sha256"] and identity.get("mode") == "capacity" and identity.get("pressure_qualification") is False, "capacity bundle is not an ineligible SourceV5 calibration run")
    source_pin = exact(request.get("source_manifest"), {"path", "sha256"}, "capacity request SourceV5 manifest")
    require(source_pin == {"path": str(inputs["manifest_path"]), "sha256": inputs["manifest_raw_sha256"]}, "capacity request does not pin the selected SourceV5 manifest bytes")
    require(receipt.get("qualification_eligible") is False and receipt.get("identity") == identity and receipt.get("capacity_artifact_raw_sha256") == artifact_sha, "capacity receipt is eligible or differs from its producer request/artifact")
    return {
        "request": {"path": str(request_path), "raw_sha256": capacity_bundle["request"]["raw_sha256"]},
        "artifact": {"path": str(artifact_path), "raw_sha256": artifact_sha},
        "receipt": {"path": str(receipt_path), "raw_sha256": receipt_sha},
        "request_value": request,
        "receipt_value": receipt,
    }


def _verify_pressure_recipe(
    member: dict[str, Any], recipe: dict[str, Any], inputs: dict[str, Any], shared_policy: dict[str, Any],
    modules: dict[str, Any], condition: dict[str, Any], capacity: dict[str, Any], deadlines: dict[str, Any],
    *, offline_origin: dict[str, Any] | None = None,
    offline_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reference = member["pressure_recipe"]
    path, raw, raw_sha = read_pin(reference["artifact"], "member SourceV5 pressure recipe", MAX_RECIPE_BYTES)
    try:
        pressure_recipe = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PressurePairError(f"member pressure recipe is invalid JSON: {error}") from error
    require(type(pressure_recipe) is dict and raw == canonical_bytes(pressure_recipe), "member pressure recipe is not canonical JSON")
    pressure_reader = modules["pressure_validator"]
    pressure_driver = modules["pressure_driver"]
    recipe_value = pressure_reader._validate_recipe(pressure_recipe, reference["semantic_sha256"])
    recipe_sha = digest(pressure_recipe.get("recipe_sha256"), "validated pressure recipe semantic SHA-256")
    require(recipe_sha == reference["semantic_sha256"], "validated pressure recipe semantic digest differs from its private pin")
    require(recipe_value["condition_sha256"] == reference["condition_sha256"], "member pressure recipe condition semantic digest differs from its private pin")
    require(pressure_recipe["identity"]["phase"] == "external_pressure", "member pressure recipe has the wrong pressure phase")
    identity = member["identity"]
    descriptor = member["descriptor"]
    expected_pressure_identity = {
        "host_id": inputs["host_id"], "run_id": inputs["job"]["run_id"],
        "pair_id": inputs["job"]["run_id"], "condition_id": recipe["pressure_condition"]["condition_id"],
        "member": descriptor["pair"], "nonce": identity["pressure_nonce"],
        "allocator": descriptor["allocator"], "executor": identity["executor"],
    }
    for name, expected in expected_pressure_identity.items():
        require(pressure_recipe["identity"].get(name) == expected, f"member pressure recipe identity differs at {name}")
    app_binary = exact(member["application_binary"], {"path", "raw_sha256"}, "member APP binary pin")
    source_artifact = exact(inputs["source"]["artifacts"].get(descriptor["allocator"]), {"path", "sha256"}, "SourceV5 member APP artifact")
    binary_path = safe_child(inputs["source_root"], source_artifact["path"], "SourceV5 member APP binary")
    _binary_raw, binary_sha, binary_info = read_stable(binary_path, "SourceV5 member APP binary", MAX_BINARY_BYTES)
    require(binary_path.stat().st_mode & 0o111 != 0 and app_binary == {"path": str(binary_path), "raw_sha256": source_artifact["sha256"]} and binary_sha == source_artifact["sha256"] == identity["binary_sha256"], "member APP binary differs from its exact SourceV5 artifact")
    require(pressure_recipe["files"]["application_binary"]["path"] == str(binary_path) and pressure_recipe["files"]["application_binary"]["raw_sha256"] == binary_sha, "pressure recipe APP binary differs from its original SourceV5 artifact")
    require(pressure_recipe["files"]["source_manifest"]["raw_sha256"] == inputs["manifest_raw_sha256"], "pressure recipe SourceV5 manifest pin differs")
    shared_pin = recipe["shared_policy"]["artifact"]
    require(pressure_recipe["files"]["policy"] == {"path": shared_pin["path"], "raw_sha256": shared_pin["raw_sha256"]}, "pressure recipe does not pin the one common numeric policy artifact")
    require(pressure_recipe["files"]["application_capacity_calibration"]["raw_sha256"] == capacity["artifact"]["raw_sha256"], "pressure recipe does not pin the shared capacity artifact")
    require(pressure_recipe["readiness_thresholds"] == condition["driver_readiness_thresholds"], "pressure recipe readiness thresholds differ from the original driver request template")
    effective_calibration = condition["effective_calibration"]
    require(pressure_recipe["pressure_calibration"]["raw_sha256"] ==
            effective_calibration["raw_sha256"],
            "pressure recipe calibration differs from the selected SourceV5 condition binding")
    expected_scope_v2 = condition["calibration_scope_v2"]
    if expected_scope_v2 is None:
        require("calibration_scope_v2" not in pressure_recipe,
                "legacy SourceV5 condition cannot accept an unbound context calibration")
    else:
        member_scope_v2 = exact(pressure_recipe.get("calibration_scope_v2"), {
            "schema", "scope_receipt", "validator_sha256", "condition",
            "context_policy", "capacity_bundle_pins", "observed_host",
            "context_policy_sha256",
        }, "member context calibration v2 binding")
        require(member_scope_v2 == expected_scope_v2,
                "member pressure recipe context calibration differs from its exact Source5 condition scope")
    require(pressure_recipe["network"]["network_namespace_inode"] == member["network_namespace_inode"], "pressure recipe network namespace differs from the original member descriptor")
    require(pressure_recipe["process"]["application_tmpdir_path"] == member["tmpdir_path"] and pressure_recipe["process"]["executable_path"] == str(binary_path), "pressure recipe TMPDIR/executable differs from the original member descriptor")
    require(pressure_recipe["schedule"]["application_cpu_affinity"] == member["cpu_affinity"], "pressure recipe application affinity differs from the original member descriptor")

    condition_request = condition["request"]
    condition_schedule = condition_request["schedule"]
    pressure_schedule = pressure_recipe["schedule"]
    for key, value in condition_schedule.items():
        if key in ("duration_seconds", "total_deadline_seconds"):
            continue
        require(pressure_schedule.get(key) == value, f"pressure recipe changed original condition intensity field {key}")
    schedule_fields = set(condition_schedule)
    require(schedule_fields <= set(pressure_schedule), "pressure recipe omitted an original condition schedule field")
    expected_duration = max(
        uint(condition_schedule["duration_seconds"], "original condition pressure duration", positive=True),
        uint(condition_schedule["startup_deadline_seconds"], "pressure startup deadline", positive=True)
        + deadlines["application_wall_timeout_seconds"]
        + deadlines["pressure_exit_observation_seconds"],
    )
    require(pressure_schedule["duration_seconds"] == expected_duration == deadlines["pressure_duration_seconds"], "pressure recipe duration was not prospectively derived from startup, APP bound, and exit-observation margin")
    expected_total = max(
        condition_schedule["total_deadline_seconds"],
        pressure_schedule["startup_deadline_seconds"] + expected_duration
        + pressure_schedule["term_deadline_seconds"] + pressure_schedule["kill_deadline_seconds"],
    )
    require(pressure_schedule["total_deadline_seconds"] == expected_total == deadlines["pressure_total_seconds"], "pressure recipe total deadline differs from the independently derived enclosing bound")
    require(expected_duration <= 12_000 and expected_duration * 1000 // pressure_schedule["sample_interval_ms"] <= 120_000 and expected_total <= 14_400, "pressure recipe exceeds the SourceV5 pressure driver limits")
    typed_thresholds = recipe["pressure_condition"]["readiness_thresholds"]
    require(pressure_schedule["minimum_overlap_seconds"] >= typed_thresholds["minimum_overlap_seconds"], "pressure recipe overlap is below the original SourceV5 readiness requirement")
    require(expected_duration * 1000 // pressure_schedule["sample_interval_ms"] >= typed_thresholds["minimum_ready_samples"], "pressure recipe cannot meet the original SourceV5 readiness sample count")
    require(pressure_schedule["sample_interval_ms"] <= typed_thresholds["maximum_sample_gap_ms"], "pressure recipe cadence exceeds the original SourceV5 readiness gap")
    try:
        _verify_pressure_recipe_host_inputs(
            pressure_reader, pressure_driver, recipe_value, pressure_recipe,
            offline_origin=offline_origin, offline_context=offline_context,
            source_root=(Path(inputs["source_root"])
                         if offline_context is not None else None),
        )
    except Exception as error:
        raise PressurePairError(f"pinned pressure validator rejected member recipe inputs or current host facts: {error}") from error
    require(binary_info.st_mode & 0o111 != 0, "SourceV5 APP binary is not executable")
    return {
        "path": str(path), "raw_sha256": raw_sha,
        "recipe_path": str(path),
        "recipe_sha256": recipe_sha,
        "semantic_sha256": reference["semantic_sha256"],
        "condition_sha256": reference["condition_sha256"],
        "value": pressure_recipe,
        "reader": pressure_reader,
        "driver_path": str(safe_child(inputs["source_root"], inputs["source"]["qualification_harness"]["pressure_driver"]["path"], "SourceV5 pressure driver")),
        "driver_sha256": inputs["source"]["qualification_harness"]["pressure_driver"]["sha256"],
        "output_dir": member["outputs"]["root"] + "/pressure",
        "launch_record_path": member["outputs"]["root"] + "/pressure/launch-record.json",
        "ready_path": member["outputs"]["root"] + "/pressure/pressure-ready.json",
        "source_root": str(inputs["source_root"]),
        "readiness_thresholds": recipe["pressure_condition"]["readiness_thresholds"],
        "driver_readiness_thresholds": pressure_recipe["readiness_thresholds"],
    }


def _verify_pressure_recipe_host_inputs(
    pressure_reader: Any, pressure_driver: Any,
    pressure_summary: dict[str, Any], pressure_recipe: dict[str, Any],
    *, offline_origin: dict[str, Any] | None = None,
    offline_context: dict[str, Any] | None = None,
    source_root: Path | None = None,
) -> None:
    """Use summary-only reader helpers and full-recipe host/calibration APIs."""
    pressure_reader._verify_script_hashes(pressure_summary)
    pressure_reader._verify_raw_inputs(pressure_summary)
    if offline_origin is None:
        require(offline_context is None and source_root is None,
                "strict local pressure calibration cannot accept an offline context")
        pressure_reader._validate_calibration(pressure_recipe)
        pressure_driver._verify_live_environment(pressure_recipe)
    else:
        offline = exact(offline_context, {
            "schema", "source_root", "evidence_path_map",
        }, "closed offline pressure calibration context")
        offline_source_root = _source5_absolute_path(
            offline["source_root"], "offline pressure calibration SourceRoot",
        )
        require(offline["schema"] == OFFLINE_CALIBRATION_CONTEXT_SCHEMA and
                source_root is not None and source_root.is_absolute() and
                str(source_root) == offline_source_root,
                "offline pressure calibration context changed the frozen SourceV5 root")
        pressure_reader._validate_calibration(
            pressure_recipe, offline_context={
                "source_root": offline["source_root"],
                "evidence_path_map": offline["evidence_path_map"],
            },
        )
        exact(offline_origin, {
            "schema", "host_id", "observed_host_raw_sha256", "before", "after",
            "storage_sha256", "origin_facts_sha256",
        }, "strict pressure origin facts for offline member")
        fact_fields = {
            "boot_id_sha256", "kernel_release", "cpu_affinity",
            "network_namespace_inode",
        }
        before = exact(offline_origin["before"], fact_fields,
                       "pressure origin before facts")
        after = exact(offline_origin["after"], fact_fields,
                      "pressure origin after facts")
        host = pressure_recipe.get("host")
        network = pressure_recipe.get("network")
        require(type(host) is dict and type(network) is dict,
                "offline pressure recipe host/network facts are malformed")
        require(offline_origin["host_id"] == pressure_recipe["identity"]["host_id"] and
                before == after and
                before["boot_id_sha256"] == host["boot_id_sha256"] and
                before["kernel_release"] == host["kernel_release"] and
                before["cpu_affinity"] == host["allowed_cpu_affinity"] and
                before["network_namespace_inode"] == network["network_namespace_inode"],
                "offline pressure recipe host facts differ from the strict origin receipt")


def _verify_members(
    recipe: dict[str, Any], inputs: dict[str, Any], condition: dict[str, Any],
    capacity: dict[str, Any], shared: dict[str, Any], modules: dict[str, Any], output_root: Path,
    *, offline_origin: dict[str, Any] | None = None,
    offline_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    inputs["recipe"] = recipe
    inputs["condition"] = condition["value"]
    job = inputs["job"]
    spec = inputs["spec"]
    source = inputs["source"]
    descriptors = pressure_process_descriptors(job)
    require([member["descriptor"] for member in recipe["members"]] == descriptors, "pressure members differ from the exact original process descriptor order")
    predecessor_ids = job.get("predecessor_run_ids")
    require(type(predecessor_ids) is list and len(predecessor_ids) == 1, "pressure job does not name exactly one original fixed-policy predecessor")
    require(type(job.get("ordinal")) is int and job["ordinal"] > 0, "pressure job ordinal is malformed")
    cell_matches = [cell for cell in spec["cells"] if cell["family"] == job["family"] and cell["profile"] == job["profile"]]
    require(len(cell_matches) == 1, "pressure job has no unique original resource-ceiling cell")
    cell = cell_matches[0]
    require(job["workload"] == cell["workload"], "pressure job workload differs from its exact original cell")
    expected_trace = spec["deadlines"]["trace_seconds"]
    expected_drain = spec["deadlines"]["drain_seconds"]
    expected_shutdown = spec["deadlines"]["shutdown_seconds"]
    expected_process = spec["deadlines"]["process_seconds"]
    deadlines = recipe["deadlines"]
    for key, original in (
        ("trace_seconds", expected_trace), ("drain_seconds", expected_drain),
        ("shutdown_seconds", expected_shutdown), ("process_seconds", expected_process),
        ("outer_seconds", spec["deadlines"]["outer_seconds"]),
    ):
        require(deadlines[key] == original, f"pressure pair {key} differs from the original campaign deadlines")
    require(deadlines["application_wall_timeout_seconds"] == expected_process, "APP wall bound differs from the frozen original process deadline")
    require(deadlines["application_wall_timeout_seconds"] > deadlines["application_term_grace_seconds"] + 0.75, "pressure APP wall bound has no room for bounded TERM/KILL cleanup")

    result: list[dict[str, Any]] = []
    for index, member in enumerate(recipe["members"]):
        descriptor = member["descriptor"]
        identity = member["identity"]
        template = _member_feedback_template(inputs, member, condition["normalized_inputs"])
        template_identity = template["identity"]
        require(template["nonce_scope"] == "reusable_template" and template["nonce_instantiation_schema"] == "allocatbelt.application-process-nonce-instantiation.v1" and template["nonce_instantiation_rule"] == "sha256(template_nonce,campaign_id,job_run_id,pair_member,ordinal)", "feedback template nonce rule differs from the original SourceV5 contract")
        report_nonce = instantiate_feedback_nonce(
            template_identity["prospective_nonce"], spec["campaign_id"], job["run_id"], descriptor["pair"], job["ordinal"],
        )
        require(identity["report_nonce"] == report_nonce, "APP report nonce is not instantiated from the original feedback template/job/member ordinal")
        require(template_identity["source_sha256"] == source["source"]["source_tree_sha256"] and template_identity["binary_sha256"] == identity["binary_sha256"], "original feedback template source/binary differs from the target APP")
        require(template_identity["host_id"] == inputs["host_id"] and template_identity["workload"] == job["workload"] and template_identity["profile"] == job["profile"] and template_identity["comparison_family"] == "external_pressure", "original feedback template context differs from pressure job")
        require(template_identity["allocator"] == descriptor["allocator"] and template_identity["executor"] == identity["executor"] and template_identity["pressure_condition_id"] == recipe["pressure_condition"]["condition_id"], "original feedback template member differs from pressure descriptor/condition")
        require(identity["host_id"] == inputs["host_id"] and identity["run_id"] == job["run_id"] and identity["allocator"] == descriptor["allocator"] and identity["executor"] == EXECUTOR_LABELS[descriptor["executor"]], "normal APP identity differs from its original pressure member")
        require(identity["workload"] == job["workload"] and identity["profile"] == job["profile"] and identity["mode"] == job["mode"], "normal APP workload/profile/mode differs from the original pressure job")
        require(identity["rate_per_second"] == job["rate_per_second"] and identity["arrivals"] == job["arrivals"], "normal APP rate/arrivals differ from the original pressure job")
        require(identity["source_sha256"] == source["source"]["source_tree_sha256"] and identity["resource_ceiling_sha256"] == cell["resource_ceiling_sha256"], "normal APP source or ceiling identity differs from SourceV5")
        require(identity["policy_sha256"] == shared["value"]["member_resolutions"][index]["resolved_policy_sha256"], "normal APP policy identity differs from its target-specific composer resolution")

        source_artifact = exact(source["artifacts"].get(descriptor["allocator"]), {"path", "sha256"}, "SourceV5 normal APP artifact")
        binary_path = safe_child(inputs["source_root"], source_artifact["path"], "SourceV5 normal APP binary")
        require(member["application_binary"] == {"path": str(binary_path), "raw_sha256": source_artifact["sha256"]} and identity["binary_sha256"] == source_artifact["sha256"], "pressure member binary pin differs from the selected original SourceV5 artifact")
        argv = _derive_member_argv(inputs, member, deadlines, binary_path)
        require(member["argv"] == argv, "pressure member argv differs from the original workload/profile/mode/rate/arrival/deadline command")

        oracle_entry = job.get("oracle")
        if job.get("comparison_kind") == "allocator":
            oracle_entry = job.get("oracles", {}).get(descriptor["allocator"])
        if job["mode"] == "open_loop":
            require(type(oracle_entry) is dict and member["oracle"] is not None and member["oracle"]["entry"] == oracle_entry, "pressure member oracle differs from its original campaign plan entry")
            oracle_path = Path(member["oracle"]["artifact"]["path"])
            oracle_raw, oracle_sha, _info = read_stable(oracle_path, "original normal APP oracle", MAX_TRACE_BYTES)
            require(oracle_sha == oracle_entry["sha256"] == member["oracle"]["artifact"]["raw_sha256"], "normal APP oracle differs from the original plan pin")
            controller = modules["campaign_controller"]
            try:
                controller.validate_oracle(oracle_path, source["source"]["source_tree_sha256"], identity["binary_sha256"], job["workload"], job["profile"], job["rate_per_second"], job["arrivals"])
            except Exception as error:
                raise PressurePairError(f"pinned campaign controller rejected the normal APP oracle: {error}") from error
            oracle_info: dict[str, Any] | None = {"path": str(oracle_path), "raw_sha256": oracle_sha, "entry": oracle_entry}
        else:
            require(oracle_entry is None and member["oracle"] is None, "capacity-mode pressure member unexpectedly contains an oracle")
            oracle_info = None

        pressure_info = _verify_pressure_recipe(
            member, recipe, inputs, shared["value"], modules, condition,
            capacity, deadlines, offline_origin=offline_origin,
            offline_context=offline_context,
        )
        require(identity["pressure_nonce"] == pressure_info["value"]["identity"]["nonce"], "normal APP pressure nonce differs from its frozen pressure recipe")
        require(member["cwd"] in pressure_info["value"]["storage"]["application_io_paths"], "normal APP cwd differs from the frozen pressure storage paths")
        require(member["tmpdir_path"] == pressure_info["value"]["process"]["application_tmpdir_path"], "normal APP TMPDIR differs from the frozen pressure recipe")
        require(member["cpu_affinity"] == pressure_info["value"]["schedule"]["application_cpu_affinity"], "normal APP affinity differs from the frozen pressure recipe")
        require(member["network_namespace_inode"] == pressure_info["value"]["network"]["network_namespace_inode"], "normal APP namespace differs from the frozen pressure recipe")
        require(sorted(modules["soak_supervisor"]._parse_cpu_set(member["cpu_set"])) == member["cpu_affinity"], "normal APP CPU-set string differs from its numeric affinity list")
        expected_environment = _expected_member_environment(inputs, member, shared["value"], modules)
        require(member["environment"] == expected_environment, "normal APP full environment differs from the exact SourceV5 identity, trace, capacity, and runtime outputs")
        require(member["environment"]["ALLOCATBELT_APP_FEEDBACK_TRACE_DIR"] == member["outputs"]["trace_directory"], "feedback trace environment differs from the pinned trace output")
        require(member["outputs"]["root"] == str(output_root / f"{index:02d}-{descriptor['pair']}-{descriptor['executor']}-{descriptor['allocator']}"), "pressure member output root differs from the frozen pair layout")
        for path_key in ("stdout", "stderr", "timing", "ids", "shutdown", "capacity_families", "runtime_binding", "feedback_manifest", "feedback_events", "feedback_samples", "feedback_validation", "pressure_readback", "app_launch_attestation", "supervision_receipt", "cleanup_receipt", "runtime_expectation", "finalization_request", "finalization_receipt"):
            path = Path(member["outputs"][path_key])
            expected_parent = Path(member["outputs"]["trace_directory"]) if path_key in ("feedback_manifest", "feedback_events", "feedback_samples") else Path(member["outputs"]["root"])
            require(path.parent == expected_parent, f"pressure member {path_key} path is outside its private output root")
        require(member["outputs"]["trace_directory"] == str(Path(member["outputs"]["root"]) / "feedback-trace"), "feedback trace directory differs from its dedicated private output")
        require(member["outputs"]["feedback_manifest"] == str(Path(member["outputs"]["trace_directory"]) / "feedback-trace-manifest.tsv") and member["outputs"]["feedback_events"] == str(Path(member["outputs"]["trace_directory"]) / "feedback-events.jsonl") and member["outputs"]["feedback_samples"] == str(Path(member["outputs"]["trace_directory"]) / "resource-samples.tsv"), "feedback trace output file names differ from the SourceV5 closed three-file layout")
        require(member["outputs"]["pressure_readback"] == str(Path(member["outputs"]["root"]) / "pressure-readback.json"), "pressure readback path differs from its private member output")
        result.append({
            "member": member,
            "template": template,
            "binary_path": binary_path,
            "oracle": oracle_info,
            "pressure_info": pressure_info,
        })
    require(len({item["member"]["identity"]["pressure_nonce"] for item in result}) == 2, "paired pressure recipes repeat the member nonce")
    require(len({item["member"]["identity"]["report_nonce"] for item in result}) == 2, "paired feedback templates instantiate the same report nonce")
    return result


def _verify_fixed_predecessor(
    recipe: dict[str, Any], inputs: dict[str, Any], modules: dict[str, Any], output_root: Path,
    *, chronology_module: Any | None = None, lock: Any | None = None,
    authorization_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    path, raw, raw_sha = read_pin(recipe["fixed_predecessor"]["record"], "original fixed-policy predecessor record", MAX_RECIPE_BYTES)
    try:
        record = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PressurePairError(f"fixed predecessor record is invalid JSON: {error}") from error
    require(type(record) is dict and raw == canonical_bytes(record), "fixed predecessor record is not canonical JSON")
    require(record.get("job", {}).get("run_id") == inputs["job"]["predecessor_run_ids"][0], "fixed predecessor record run ID differs from the exact original pressure job reference")
    if record.get("schema") == "allocatbelt.application-source5-job-record.v1":
        require(chronology_module is not None and lock is not None and
                authorization_context is not None,
                "Source5 fixed predecessor requires the same locked chronology context as its pressure APPs")
        manifest_ref = _artifact_reference(
            authorization_context["execution_manifest"],
            "Source5 execution manifest",
        )
        try:
            chain = chronology_module.verify_source5_completed_job_locked(
                lock,
                {"path": manifest_ref["path"],
                 "sha256": manifest_ref["raw_sha256"]},
                authorization_context,
                {"path": str(path), "raw_sha256": raw_sha},
            )
        except Exception as error:
            raise PressurePairError(f"Source5 fixed predecessor chronology replay failed: {error}") from error
        require(chain["record_sha256"] == record.get("record_sha256") and
                chain["process_metrics"] == record.get("process_metrics"),
                "Source5 fixed predecessor record differs from its completed journal metrics")
    else:
        require(record.get("state") == "valid_pair" and
                record.get("runner_sha256_before") == inputs["spec"].get("runner_sha256") and
                record.get("runner_sha256_after") == inputs["spec"].get("runner_sha256"),
                "archived fixed predecessor is not the exact historical shell-runner branch")
    try:
        rebuilt = modules["campaign_controller"].fixed_pressure_predecessor_receipt(
            inputs["job"], record, inputs["spec"], inputs["source"],
        )
    except Exception as error:
        raise PressurePairError(f"captured SourceV5 controller could not reconstruct the fixed-pressure predecessor receipt: {error}") from error
    expected_path = output_root / "preflight" / "fixed-pressure-predecessor.json"
    rebuilt_raw = canonical_bytes(rebuilt)
    if expected_path.exists():
        existing, existing_raw, rebuilt_sha = read_json(expected_path, "stored reconstructed fixed-pressure predecessor receipt", MAX_SMALL_BYTES)
        require(existing == rebuilt and existing_raw == rebuilt_raw, "stored fixed-pressure predecessor receipt differs from fresh exact reconstruction")
    else:
        rebuilt_sha = write_new(expected_path, rebuilt_raw, "reconstructed fixed-pressure predecessor receipt")
    return {
        "record": {"path": str(path), "raw_sha256": raw_sha},
        "receipt": {"path": str(expected_path), "raw_sha256": rebuilt_sha},
        "value": rebuilt,
    }


def _parse_runtime_binding(raw: bytes) -> dict[str, str]:
    require(raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw, "V2 runtime binding has invalid framing")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise PressurePairError(f"V2 runtime binding is not UTF-8: {error}") from error
    require(lines and lines[0] == "schema\tallocatbelt.application-runtime-binding.v2", "normal APP did not emit runtime-binding V2")
    result: dict[str, str] = {}
    for line in lines[1:]:
        fields = line.split("\t")
        require(len(fields) == 2 and fields[0] and fields[1], "runtime-binding V2 row is malformed")
        key, value = fields
        require(key not in result, f"runtime-binding V2 repeats {key}")
        result[key] = value
    return result


def pressure_numeric_runtime_snapshot(
    controller: Any, fields: dict[str, str], policy: dict[str, Any], validator_sha256: str,
) -> dict[str, Any]:
    """Adapt V5 runtime-binding V2 through the existing numeric snapshot projection."""
    snapshot = controller.numeric_runtime_snapshot(
        fields,
        {"contract": {"scope_limits": policy["scope_limits"]}},
        validator_sha256,
    )
    require(snapshot["schema"] == "allocatbelt.application-runtime-numeric-snapshot.v2", "pressure runtime readback lacks numeric snapshot V2")
    after = exact(snapshot["after_release"], {
        "global_live_tenants", "global_used_control", "expected_global_control_baseline", "global_used_application",
    }, "V2 after-release numeric runtime snapshot")
    baseline = policy["collector"]["expected_global_control_baseline"]
    require(after["global_live_tenants"] == 0 and after["global_used_control"] == baseline and after["expected_global_control_baseline"] == baseline, "V2 runtime snapshot did not return to the fixed global Control baseline with zero tenants")
    require(after["global_used_application"] == {name: 0 for name in ("cpu", "memory", "disk", "network", "tasks")}, "V2 runtime snapshot retains global application usage after owner release")
    return snapshot


_APP_STDOUT_HEADER = (
    "schema allocator executor workload mode async_workers blocking_workers topology logical_window global_task_limit "
    "retained_window arrival_rate_per_second requested_arrivals attempted admitted rejected_full rejected_resource "
    "completed_on_time completed_late errors cancellations unresolved lost result_digest expected_digest "
    "capacity_publications_per_second successful_throughput_through_drain_per_second setup_ns timer_pair_median_ns "
    "wall_through_drain_ns drain_tail_ns response_p50_ns response_p95_ns response_p99_ns "
    "producer_lateness_mean_ns producer_lateness_max_ns max_observed_managed_bytes retained_managed_bytes "
    "managed_limit_bytes disk_limit_ops network_limit_ops final_managed_bytes final_disk_ops final_network_ops "
    "rss_before_kib rss_after_drain_kib rss_after_shutdown_kib hwm_before_kib hwm_after_drain_kib "
    "hwm_after_shutdown_kib shutdown_ns rejected_logical_window rejected_backend_full"
).split()


def _tabular_bytes(raw: bytes, label: str, expected_rows: int) -> tuple[list[str], list[dict[str, str]]]:
    require(raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw, f"{label} has invalid TSV framing")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise PressurePairError(f"{label} is not UTF-8: {error}") from error
    require(lines and len(lines) == expected_rows + 1, f"{label} row count differs from its closed contract")
    header = lines[0].split("\t")
    require(len(set(header)) == len(header) and all(header), f"{label} header is malformed")
    rows: list[dict[str, str]] = []
    for line in lines[1:]:
        values = line.split("\t")
        require(len(values) == len(header), f"{label} row width differs from its header")
        rows.append(dict(zip(header, values, strict=True)))
    return header, rows


def _validate_shutdown_report(
    raw: bytes, member: dict[str, Any], inputs: dict[str, Any], deadlines: dict[str, Any], output_row: dict[str, str],
) -> dict[str, int | str]:
    job = inputs["job"]
    identity = member["identity"]
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise PressurePairError(f"normal APP shutdown report is not UTF-8: {error}") from error
    require(raw.endswith(b"\n") and b"\r" not in raw and lines and lines[0] == "schema\tallocatbelt-app-phase-v1\t", "normal APP shutdown report schema/framing differs")
    executor = identity["executor"]
    workload = job["workload"]
    drivers = (
        ["allocatbelt owning HTTP runtime"]
        if executor == "allocatbelt" and workload in ("http", "mixed")
        else ["allocatbelt application driver"]
        if executor == "allocatbelt"
        else ["Tokio HTTP runtime", "Tokio resource feedback", "Tokio fixed rate timer"]
        if workload in ("http", "mixed")
        else ["Tokio runtime", "Tokio resource feedback"]
    )
    require(len(lines) == len(drivers) + 15, "normal APP shutdown report row count differs")
    expected_identity = [
        ["identity", "report_nonce", identity["report_nonce"]], ["identity", "run_id", job["run_id"]],
        ["identity", "executor", identity["executor"]], ["identity", "allocator", identity["allocator"]],
        ["identity", "workload", identity["workload"]], ["identity", "profile", identity["profile"]],
        ["identity", "source_sha256", identity["source_sha256"]], ["identity", "binary_sha256", identity["binary_sha256"]],
    ]
    actual_identity = [line.split("\t") for line in lines[1:9]]
    require(actual_identity == expected_identity, "normal APP shutdown identity differs from the pinned pair member")
    phase_names = ["production_trace", "production_cpu_started_ns", "production_cpu_ended_ns", "production_through_drain_cpu_ns", "successful_completions", "cpu_ns_per_successful_completion"]
    phases = [line.split("\t") for line in lines[9:15]]
    require(all(len(row) == 3 and row[:2] == ["phase", name] for row, name in zip(phases, phase_names, strict=True)), "normal APP shutdown phase rows differ from the closed schema")
    for row in phases:
        uint(int(row[2]) if row[2].isdigit() else None, f"shutdown {row[1]}")
    trace_ns, cpu_started, cpu_ended, cpu_total, successes, cpu_per_completion = (int(row[2]) for row in phases)
    require(trace_ns <= deadlines["trace_seconds"] * 1_000_000_000, "normal APP trace exceeded the frozen trace deadline")
    if job["mode"] == "capacity":
        require(30_000_000_000 <= trace_ns <= min(deadlines["trace_seconds"] * 1_000_000_000, 31_000_000_000), "capacity APP trace duration differs from the fixed 30-second capacity phase")
    require(cpu_started > 0 and cpu_ended >= cpu_started and cpu_ended - cpu_started == cpu_total and 0 < cpu_total <= deadlines["process_seconds"] * 128 * 1_000_000_000, "normal APP CPU phase bounds do not reconcile")
    completed = int(output_row["completed_on_time"]) + int(output_row["completed_late"])
    require(successes == completed and successes > 0 and cpu_per_completion == cpu_total // successes and cpu_per_completion > 0, "normal APP shutdown success/CPU normalization differs from stdout")
    for line, expected in zip(lines[15:], drivers, strict=True):
        row = line.split("\t")
        require(len(row) == 3 and row[:2] == ["driver", expected], "normal APP shutdown driver row differs")
        duration = uint(int(row[2]) if row[2].isdigit() else None, "shutdown driver duration")
        require(duration <= deadlines["shutdown_seconds"] * 1_000_000_000, "normal APP shutdown driver exceeded its frozen bound")
    return {
        "raw_sha256": sha256_bytes(raw),
        "production_cpu_started_ns": cpu_started,
        "production_cpu_ended_ns": cpu_ended,
        "production_cpu_ns": cpu_total,
        "cpu_ns_per_completion": cpu_per_completion,
        "successful_completions": successes,
    }


def _validate_capacity_family_report(
    raw: bytes, member: dict[str, Any], inputs: dict[str, Any], output_row: dict[str, str], budget: int,
) -> dict[str, Any]:
    identity = member["identity"]
    job = inputs["job"]
    require(raw.endswith(b"\n") and b"\r" not in raw, "capacity-family report has invalid framing")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise PressurePairError(f"capacity-family report is not UTF-8: {error}") from error
    require(lines and lines[0] == "schema\tallocatbelt-app-capacity-families-v1\t", "capacity-family report schema differs")
    expected_identity = {
        "report_nonce": identity["report_nonce"], "run_id": job["run_id"],
        "executor": identity["executor"], "allocator": identity["allocator"],
        "workload": identity["workload"], "profile": identity["profile"],
        "source_sha256": identity["source_sha256"], "binary_sha256": identity["binary_sha256"],
    }
    observed_identity: dict[str, str] = {}
    families: dict[str, list[str]] = {}
    phases: dict[str, str] = {}
    for line in lines[1:]:
        row = line.split("\t")
        if len(row) == 3 and row[0] == "identity":
            require(row[1] not in observed_identity, "capacity-family report repeats identity")
            observed_identity[row[1]] = row[2]
        elif len(row) == 4 and row[0] == "family":
            require(row[1] not in families, "capacity-family report repeats a family")
            families[row[1]] = row[2:]
        elif len(row) == 3 and row[0] == "phase":
            require(row[1] not in phases, "capacity-family report repeats a phase")
            phases[row[1]] = row[2]
        else:
            raise PressurePairError("capacity-family report row has an unknown shape")
    require(observed_identity == expected_identity and set(families) == {"cpu", "memory", "http", "disk"}, "capacity-family report identity or family set differs")
    require(phases == {"trace_seconds": "30", "profile": job["profile"]}, "capacity-family report phase differs from the frozen profile")
    attempted = uint(int(output_row["attempted"]) if output_row["attempted"].isdigit() else None, "capacity-family attempted count", positive=True)
    completed = uint(int(output_row["completed_on_time"]) if output_row["completed_on_time"].isdigit() else None, "capacity-family completion count", positive=True)
    require(sum(int(values[0]) for values in families.values() if values[0].isdigit()) == attempted and sum(int(values[1]) for values in families.values() if values[1].isdigit()) == completed, "capacity-family totals differ from stdout")
    throughput_by_family: dict[str, float] = {}
    for index, family in enumerate(("cpu", "memory", "http", "disk")):
        scheduled_text, success_text = families[family]
        require(re.fullmatch(r"(?:0|[1-9][0-9]*)", scheduled_text) is not None and re.fullmatch(r"(?:0|[1-9][0-9]*)", success_text) is not None, "capacity-family count is malformed")
        scheduled, successes = int(scheduled_text), int(success_text)
        expected_count = attempted // 4 + int(index < attempted % 4)
        require(scheduled == expected_count and 0 < successes <= scheduled, f"capacity-family {family} count differs from the fixed interleave")
        throughput_by_family[family] = successes / 30.0
    require(len(raw) <= budget, "capacity-family report exceeds its frozen budget")
    return {"raw_sha256": sha256_bytes(raw), "capacity_throughput_by_family": throughput_by_family}


def _validate_arrival_rows(
    member: dict[str, Any], inputs: dict[str, Any], oracle: dict[str, Any],
    output_row: dict[str, str], deadlines: dict[str, Any], controller: Any, ids_budget_bytes: int,
) -> tuple[str, dict[str, Any]]:
    identity = member["identity"]
    job = inputs["job"]
    oracle_entry = oracle["entry"]
    duration, oracle_rows = controller.parse_oracle(Path(oracle["path"]), oracle_entry, inputs["source"], next(item for item in inputs["spec"]["cells"] if item["family"] == job["family"] and item["profile"] == job["profile"]), job["rate_per_second"])
    expected_count = job["arrivals"]
    require(len(oracle_rows) == expected_count, "normal APP oracle does not cover the exact original arrivals")
    lines_raw, lines_sha, _info = read_stable(Path(member["outputs"]["ids"]), "normal APP arrival IDs", ids_budget_bytes)
    try:
        lines = lines_raw.decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise PressurePairError(f"normal APP arrival IDs are not UTF-8: {error}") from error
    require(lines_raw.endswith(b"\n") and b"\r" not in lines_raw and len(lines) == expected_count + 3, "normal APP arrival ID row count/framing differs")
    require(lines[0] == "schema\tallocatbelt-app-arrivals-v3", "normal APP arrival report schema differs")
    require(lines[1].split("\t") == [
        "identity", identity["report_nonce"], job["run_id"], identity["executor"], identity["allocator"],
        identity["workload"], identity["profile"], identity["source_sha256"], identity["binary_sha256"],
    ], "normal APP arrival report identity differs")
    require(lines[2] == "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum", "normal APP arrival header differs")
    max_ns = deadlines["process_seconds"] * 1_000_000_000
    trace_ns = duration
    terminals = {"completed": 0, "rejected": 0, "error": 0}
    family_successes: dict[str, int] = {}
    latencies: list[int] = []
    family_latencies: dict[str, list[int]] = {}
    result_digest = 0
    expected_digest = 0
    completed_on_time = 0
    for sequence, (line, oracle_row) in enumerate(zip(lines[3:], oracle_rows, strict=True)):
        fields = line.split("\t")
        require(len(fields) == 7 and fields[0] == str(sequence), "normal APP arrival row index/width differs")
        require(fields[1] == oracle_row[1], "normal APP arrival workload differs from the oracle")
        scheduled = uint(int(fields[2]) if fields[2].isdigit() else None, "arrival scheduled time", maximum=U128_MAX)
        completed = uint(int(fields[3]) if fields[3].isdigit() else None, "arrival completion time", maximum=U128_MAX)
        checksum = uint(int(fields[5]) if fields[5].isdigit() else None, "arrival checksum")
        expected_checksum = uint(int(fields[6]) if fields[6].isdigit() else None, "arrival expected checksum")
        require(scheduled == oracle_row[0] and expected_checksum == oracle_row[2] and completed >= scheduled and completed <= max_ns and scheduled < trace_ns, "normal APP arrival schedule/checksum/time differs from the pinned oracle/deadline")
        terminal = fields[4]
        require(terminal in terminals, "normal APP arrival has an unsupported terminal state")
        terminals[terminal] += 1
        if terminal == "rejected":
            require(checksum == 0, "rejected APP arrival has a nonzero checksum")
        elif terminal == "completed":
            require(checksum == expected_checksum, "completed APP arrival checksum differs from oracle")
            latency = completed - scheduled
            latencies.append(latency)
            family_successes[fields[1]] = family_successes.get(fields[1], 0) + 1
            family_latencies.setdefault(fields[1], []).append(latency)
            result_digest = (result_digest + (checksum if job["workload"] == "http" else checksum ^ sequence)) % (1 << 64)
            expected_digest = (expected_digest + (expected_checksum if job["workload"] == "http" else expected_checksum ^ sequence)) % (1 << 64)
            if completed <= trace_ns:
                completed_on_time += 1
    require(all(terminals[name] == 0 for name in ("rejected", "error")), "normal APP arrival trace has a rejection or error")
    family_names = ("cpu", "memory", "http", "disk") if job["workload"] == "mixed" else (job["workload"],)
    family_minimum = inputs["spec"]["protocol"]["family_min_successes"] if job["workload"] == "mixed" else inputs["spec"]["protocol"]["standalone_min_successes"]
    require(
        all(family_successes.get(family, 0) >= family_minimum for family in family_names),
        "normal APP per-family successful arrival minimum differs from the original campaign gate",
    )
    require(result_digest == int(output_row["result_digest"]) == int(output_row["expected_digest"]) == expected_digest, "normal APP aggregate checksum differs from closed arrival rows")
    require(terminals["completed"] == int(output_row["completed_on_time"]) + int(output_row["completed_late"]), "normal APP completed arrival count differs from stdout")
    require(completed_on_time == int(output_row["completed_on_time"]), "normal APP on-time count differs from stdout")
    require(controller.nearest_rank(latencies, 50) == int(output_row["response_p50_ns"]) and controller.nearest_rank(latencies, 95) == int(output_row["response_p95_ns"]) and controller.nearest_rank(latencies, 99) == int(output_row["response_p99_ns"]), "normal APP response quantiles differ from the exact arrival latencies")
    return lines_sha, {
        "family_successes": family_successes,
        "latency_p99_by_family_ns": {
            family: controller.nearest_rank(values, 99)
            for family, values in family_latencies.items()
        },
        "oracle_trace_duration_ns": duration,
        "completed_arrivals": terminals["completed"],
        "completed_on_time": completed_on_time,
    }


def _validate_app_outputs(
    member_context: dict[str, Any], inputs: dict[str, Any], recipe: dict[str, Any], modules: dict[str, Any],
    supervision: dict[str, Any],
) -> dict[str, Any]:
    member = member_context["member"]
    identity = member["identity"]
    job = inputs["job"]
    outputs = member["outputs"]
    budgets = recipe["artifact_budgets"]
    stdout_raw, stdout_sha, _stdout_info = read_stable(Path(outputs["stdout"]), "normal APP stdout TSV", budgets["stdout_bytes"])
    header, rows = _tabular_bytes(stdout_raw, "normal APP stdout TSV", 1)
    require(header == _APP_STDOUT_HEADER and len(header) == 53, "normal APP stdout schema differs from the frozen pair row contract")
    row = rows[0]
    require((row["allocator"], row["executor"], row["workload"], row["mode"]) == (identity["allocator"], identity["executor"], job["workload"], job["mode"]), "normal APP stdout identity differs from the original pair member")
    expected_schema = "http-nonblocking-connect-v1" if job["workload"] == "http" else "mixed-application-v1" if job["workload"] == "mixed" else "2"
    require(row["schema"] == expected_schema, "normal APP stdout workload schema differs")
    integer_fields = """async_workers blocking_workers logical_window global_task_limit
retained_window attempted admitted rejected_full rejected_resource rejected_logical_window rejected_backend_full
completed_on_time completed_late errors cancellations unresolved lost result_digest expected_digest setup_ns
timer_pair_median_ns wall_through_drain_ns drain_tail_ns response_p50_ns response_p95_ns response_p99_ns
producer_lateness_mean_ns producer_lateness_max_ns max_observed_managed_bytes retained_managed_bytes
managed_limit_bytes disk_limit_ops network_limit_ops final_managed_bytes final_disk_ops final_network_ops
rss_before_kib rss_after_drain_kib rss_after_shutdown_kib hwm_before_kib hwm_after_drain_kib
hwm_after_shutdown_kib shutdown_ns""".split()
    numbers: dict[str, int] = {}
    for name in integer_fields:
        require(re.fullmatch(r"(?:0|[1-9][0-9]*)", row[name]) is not None, f"normal APP stdout {name} is malformed")
        number = int(row[name])
        require(number <= ((1 << 64) - 1 if name in ("result_digest", "expected_digest") else (1 << 53) - 1), f"normal APP stdout {name} exceeds its finite integer bound")
        numbers[name] = number
    decimals: dict[str, Decimal] = {}
    for name in ("capacity_publications_per_second", "successful_throughput_through_drain_per_second"):
        raw_value = row[name]
        if name == "capacity_publications_per_second" and job["mode"] == "open_loop" and raw_value == "":
            continue
        require(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", raw_value) is not None, f"normal APP stdout {name} is malformed")
        try:
            parsed = Decimal(raw_value)
        except InvalidOperation as error:
            raise PressurePairError(f"normal APP stdout {name} is not a finite decimal") from error
        require(parsed.is_finite() and 0 <= parsed <= Decimal("1000000000"), f"normal APP stdout {name} is outside its finite bound")
        decimals[name] = parsed

    async_workers = 2 if job["profile"] == "oversubscribed" else 4
    blocking_workers = 1 if job["workload"] == "http" else async_workers if job["workload"] in ("disk", "mixed") else 0
    task_limit = 17 if job["workload"] in ("http", "mixed") else 8
    retained = 8 if job["workload"] in ("memory", "mixed") else 0
    managed = {"cpu": 0, "memory": 163840, "http": 141312, "disk": 1573000, "mixed": 1638536}[job["workload"]]
    disk_limit = 8 if job["workload"] in ("disk", "mixed") else 0
    network_limit = 16 if job["workload"] in ("http", "mixed") else 0
    if job["workload"] == "http":
        topology = f"{async_workers} async + 1 owning blocking connector + owning reactor; NetHandle::connect_nonblocking" if identity["executor"] == "allocatbelt" else f"{async_workers} async + 1 reserved blocking worker (Tokio TcpSocket::connect) + integrated I/O driver"
    elif job["workload"] == "disk":
        topology = f"{async_workers} async + {async_workers} filesystem workers" if identity["executor"] == "allocatbelt" else f"{async_workers} async + {async_workers} blocking workers"
    elif job["workload"] == "mixed":
        topology = f"{async_workers} async + {async_workers} owning blocking workers (connector and filesystem) + owning reactor" if identity["executor"] == "allocatbelt" else f"{async_workers} async + Tokio blocking pool max{async_workers} (filesystem execution cap{async_workers}) + integrated I/O driver"
    else:
        topology = f"{async_workers} async workers"
    expected_config = {
        "async_workers": async_workers, "blocking_workers": blocking_workers, "logical_window": 8,
        "global_task_limit": task_limit, "topology": topology, "retained_window": retained,
        "managed_limit_bytes": managed, "disk_limit_ops": disk_limit, "network_limit_ops": network_limit,
    }
    require(all(row[name] == (str(value) if name != "topology" else value) for name, value in expected_config.items()), "normal APP stdout topology/resource configuration differs from the closed pair contract")
    completed = numbers["completed_on_time"] + numbers["completed_late"]
    expected_arrivals = job["arrivals"] if job["mode"] == "open_loop" else 5000
    require(numbers["attempted"] <= (10_000_000 if job["mode"] == "capacity" else expected_arrivals), "normal APP stdout exceeds its frozen arrival count")
    require(numbers["attempted"] == numbers["admitted"] + numbers["rejected_full"] + numbers["rejected_resource"], "normal APP stdout counts do not conserve attempted arrivals")
    require(numbers["rejected_full"] == numbers["rejected_logical_window"] + numbers["rejected_backend_full"], "normal APP stdout full-rejection subcounts do not reconcile")
    require(numbers["admitted"] == completed + numbers["errors"] + numbers["cancellations"] + numbers["unresolved"] and numbers["lost"] == numbers["attempted"] - completed, "normal APP stdout completion/loss counts do not reconcile")
    require(numbers["result_digest"] == numbers["expected_digest"] and numbers["errors"] == numbers["cancellations"] == numbers["unresolved"] == 0, "normal APP stdout has missing work, a mismatch, or an error")
    require(numbers["final_managed_bytes"] == numbers["final_disk_ops"] == numbers["final_network_ops"] == 0, "normal APP stdout retains application resource usage")
    require(numbers["max_observed_managed_bytes"] <= managed and numbers["retained_managed_bytes"] <= managed if job["workload"] in ("memory", "http", "mixed") else True, "normal APP stdout managed usage exceeds its ceiling")
    require(completed > 0 and decimals["successful_throughput_through_drain_per_second"] > 0, "normal APP stdout has no successful throughput")
    if job["mode"] == "open_loop":
        rate = uint(job["rate_per_second"], "normal APP original rate", positive=True)
        require(row["arrival_rate_per_second"] == str(rate) and row["requested_arrivals"] == str(expected_arrivals) and numbers["attempted"] == expected_arrivals, "normal APP stdout rate/arrival count differs from its original job")
        require(numbers["response_p50_ns"] <= numbers["response_p95_ns"] <= numbers["response_p99_ns"], "normal APP stdout latency quantiles are not monotone")
        require(member_context["oracle"] is not None, "normal APP open-loop member has no validated original oracle")
        ids_sha, arrival_metrics = _validate_arrival_rows(
            member, inputs, member_context["oracle"], row,
            recipe["deadlines"], modules["campaign_controller"], budgets["ids_bytes"],
        )
    else:
        require(not Path(outputs["ids"]).exists() and not Path(outputs["ids"]).is_symlink(), "capacity APP emitted an open-loop arrival report")
        require(row["arrival_rate_per_second"] == "" and row["requested_arrivals"] == "", "capacity APP stdout contains open-loop rate/arrival values")
        require(numbers["rejected_full"] == numbers["rejected_resource"] == numbers["lost"] == 0 and numbers["completed_on_time"] > 0, "capacity APP stdout contains missing work or no successful publication")
        require(numbers["response_p50_ns"] == numbers["response_p95_ns"] == numbers["response_p99_ns"] == 0, "capacity APP stdout unexpectedly reports open-loop latencies")
        expected_capacity = Decimal(numbers["completed_on_time"]) / Decimal(30)
        require(abs(decimals["capacity_publications_per_second"] - expected_capacity) <= max(Decimal("0.00000001"), expected_capacity * Decimal("0.00000001")), "capacity APP throughput differs from its completed publications")
        ids_sha, arrival_metrics = "not_applicable", {"family_successes": {}, "latency_p99_by_family_ns": {}}
    wall_ns = numbers["wall_through_drain_ns"]
    require(wall_ns > 0 and wall_ns <= recipe["deadlines"]["process_seconds"] * 1_000_000_000 and numbers["drain_tail_ns"] <= recipe["deadlines"]["drain_seconds"] * 1_000_000_000, "normal APP production/drain timing exceeds its frozen deadline")
    expected_throughput = Decimal(completed) * Decimal(1_000_000_000) / Decimal(wall_ns)
    require(abs(decimals["successful_throughput_through_drain_per_second"] - expected_throughput) <= max(Decimal("0.00000001"), expected_throughput * Decimal("0.00000001")), "normal APP successful throughput differs from its completed work and wall time")
    for field in (
        "setup_ns", "timer_pair_median_ns", "wall_through_drain_ns", "drain_tail_ns",
        "response_p50_ns", "response_p95_ns", "response_p99_ns",
        "producer_lateness_mean_ns", "producer_lateness_max_ns", "shutdown_ns",
    ):
        require(numbers[field] <= recipe["deadlines"]["process_seconds"] * 1_000_000_000, f"normal APP stdout timing field {field} exceeds its bound")
    require(numbers["drain_tail_ns"] <= recipe["deadlines"]["drain_seconds"] * 1_000_000_000, "normal APP stdout drain tail exceeds its bound")

    shutdown_raw, shutdown_sha, _shutdown_info = read_stable(Path(outputs["shutdown"]), "normal APP shutdown report", budgets["shutdown_bytes"])
    shutdown_metrics = _validate_shutdown_report(shutdown_raw, member, inputs, recipe["deadlines"], row)
    require(shutdown_sha == shutdown_metrics["raw_sha256"], "normal APP shutdown report digest differs")
    stderr_raw, stderr_sha, _stderr_info = read_stable(Path(outputs["stderr"]), "normal APP stderr", budgets["stdout_bytes"])
    require(stderr_raw == b"", "normal APP wrote diagnostics to stderr")
    capacity_family_pin: dict[str, str] | None = None
    capacity_throughput_by_family: dict[str, float] = {}
    if job["mode"] == "capacity" and job["workload"] == "mixed":
        family_raw, family_sha, _family_info = read_stable(Path(outputs["capacity_families"]), "normal APP capacity-family report", budgets["shutdown_bytes"])
        family_metrics = _validate_capacity_family_report(family_raw, member, inputs, row, budgets["shutdown_bytes"])
        require(family_sha == family_metrics["raw_sha256"], "normal APP capacity-family report digest differs")
        capacity_throughput_by_family = family_metrics["capacity_throughput_by_family"]
        capacity_family_pin = {"path": outputs["capacity_families"], "raw_sha256": family_sha}
    else:
        require(not Path(outputs["capacity_families"]).exists() and not Path(outputs["capacity_families"]).is_symlink(), "normal APP emitted a capacity-family report outside mixed capacity mode")
    timing, _timing_raw, timing_sha = read_json(Path(outputs["timing"]), "normal APP direct-launch timing", budgets["supervision_bytes"])
    require(timing.get("schema") == "allocatbelt.application-soak-launch-time.v1" and timing.get("exit_code") == 0 and timing.get("timed_out") is False and timing.get("artifact_budget_exceeded") is False, "normal APP direct-launch timing is not a clean bounded exit")
    require(supervision["status"] == 0 and timing.get("elapsed_ns", U128_MAX + 1) <= recipe["deadlines"]["application_wall_timeout_seconds"] * 1_000_000_000, "normal APP direct launch exceeded its wall bound")
    raw_app = {
        "stdout": {"path": outputs["stdout"], "raw_sha256": stdout_sha},
        "stderr": {"path": outputs["stderr"], "raw_sha256": stderr_sha},
        "timing": {"path": outputs["timing"], "raw_sha256": timing_sha},
        "ids": {"path": outputs["ids"], "raw_sha256": ids_sha} if job["mode"] == "open_loop" else None,
        "capacity_families": capacity_family_pin,
        "shutdown": {"path": outputs["shutdown"], "raw_sha256": shutdown_sha},
    }
    return {
        "stdout": row, "raw_artifacts": raw_app,
        "row_metrics": {
            **arrival_metrics,
            "production_cpu_started_ns": shutdown_metrics["production_cpu_started_ns"],
            "production_cpu_ended_ns": shutdown_metrics["production_cpu_ended_ns"],
            "production_cpu_ns": shutdown_metrics["production_cpu_ns"],
            "cpu_ns_per_completion": shutdown_metrics["cpu_ns_per_completion"],
            "capacity_throughput_by_family": capacity_throughput_by_family,
        },
    }


def _private_output_root(path: Path, inputs: dict[str, Any]) -> Path:
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_dir() and not path.is_symlink(), "pressure-pair output root must be an existing canonical directory")
    info = path.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "pressure-pair output root must be owned by this user and mode 0700")
    require(not path.is_relative_to(inputs["source_root"]) and not path.is_relative_to(inputs["input_root"]), "pressure-pair output root must remain outside SourceV5 and campaign inputs")
    return path


def _prepare_member_directories(
    recipe: dict[str, Any], output_root: Path,
) -> None:
    preflight = output_root / "preflight"
    if preflight.exists():
        require(preflight.is_dir() and not preflight.is_symlink() and stat.S_IMODE(preflight.stat().st_mode) == 0o700 and preflight.stat().st_uid == os.getuid(), "pressure-pair preflight output directory has unsafe ownership or mode")
    else:
        os.mkdir(preflight, 0o700)
    for member in recipe["members"]:
        root = Path(member["outputs"]["root"])
        require(root.parent == output_root and not root.exists() and not root.is_symlink(), "pressure-pair member output root already exists or escaped the selected output root")
        os.mkdir(root, 0o700)
        os.chmod(root, 0o700)
        trace_dir = Path(member["outputs"]["trace_directory"])
        require(trace_dir == root / "feedback-trace" and not trace_dir.exists() and not trace_dir.is_symlink(), "member feedback trace output directory already exists or differs from its private layout")
        for name, path_value in member["outputs"].items():
            if name == "root" or name == "trace_directory":
                continue
            path = Path(path_value)
            expected_parent = trace_dir if name in ("feedback_manifest", "feedback_events", "feedback_samples") else root
            require(path.parent == expected_parent and not path.exists() and not path.is_symlink(), f"member {name} output already exists or escaped its private root")
        pressure_dir = root / "pressure"
        require(not pressure_dir.exists() and not pressure_dir.is_symlink(), "member pressure artifact directory already exists")


def _prepare_prerequisites(
    recipe: dict[str, Any], output_root: Path, *, chronology_module: Any | None = None,
    lock: Any | None = None, authorization_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    inputs = _load_campaign_inputs(recipe, output_root)
    output_root = _private_output_root(output_root, inputs)
    preflight_dir = output_root / "preflight"
    if preflight_dir.exists():
        require(preflight_dir.is_dir() and not preflight_dir.is_symlink() and stat.S_IMODE(preflight_dir.stat().st_mode) == 0o700 and preflight_dir.stat().st_uid == os.getuid(), "pressure-pair preflight directory has unsafe ownership or mode")
    else:
        os.mkdir(preflight_dir, 0o700)
    modules = _load_validators(recipe, inputs, chronology_module)
    overlay = _verify_execution_overlay(
        recipe, inputs, modules["campaign_chronology"],
        lock=lock, authorization_context=authorization_context,
    )
    require(
        overlay["chronology"]["registration_head"] == recipe["capacity_completion"]["registration_head"]
        and overlay["chronology"]["capacity_schedule_sha256"] == recipe["capacity_completion"]["schedule_sha256"],
        "private pressure recipe capacity heads differ from the replayed execution overlay",
    )
    condition = _verify_pressure_condition(recipe, inputs, modules)
    capacity = _verify_capacity_bundle(recipe, inputs, modules)
    shared = _verify_policy_resolutions(recipe, inputs, modules, output_root, capacity)
    require(inputs["source"]["resource_domain_calibration"]["record"]["fixed_global_control_baseline"] == shared["value"]["baseline"], "shared numeric policy baseline differs from SourceV5 independent control calibration")
    predecessor = _verify_fixed_predecessor(
        recipe, inputs, modules, output_root,
        chronology_module=modules["campaign_chronology"], lock=lock,
        authorization_context=authorization_context,
    )
    members = _verify_members(recipe, inputs, condition, capacity, shared, modules, output_root)
    return {
        "recipe": recipe, "output_root": output_root, "inputs": inputs,
        "modules": modules, "overlay": overlay, "condition": condition,
        "capacity": capacity, "shared_policy": shared,
        "predecessor": predecessor, "members": members,
        "chronology_module": chronology_module, "chronology_lock": lock,
        "authorization_context": authorization_context,
    }


def _member_supervision_descriptor(
    member_context: dict[str, Any], recipe: dict[str, Any],
) -> dict[str, Any]:
    member = member_context["member"]
    identity = member["identity"]
    outputs = member["outputs"]
    budgets = recipe["artifact_budgets"]
    monitored = [
        {"path": outputs["stdout"], "maximum_bytes": budgets["stdout_bytes"]},
        {"path": outputs["stderr"], "maximum_bytes": budgets["stdout_bytes"]},
        {"path": outputs["shutdown"], "maximum_bytes": budgets["shutdown_bytes"]},
        {"path": outputs["runtime_binding"], "maximum_bytes": budgets["runtime_binding_bytes"]},
        {"path": outputs["feedback_manifest"], "maximum_bytes": budgets["feedback_manifest_bytes"]},
        {"path": outputs["feedback_events"], "maximum_bytes": budgets["feedback_events_bytes"]},
        {"path": outputs["feedback_samples"], "maximum_bytes": budgets["feedback_samples_bytes"]},
    ]
    if identity["mode"] == "open_loop":
        monitored.append({"path": outputs["ids"], "maximum_bytes": budgets["ids_bytes"]})
    if identity["mode"] == "capacity" and identity["workload"] == "mixed":
        monitored.append({"path": outputs["capacity_families"], "maximum_bytes": budgets["shutdown_bytes"]})
    return {
        "schema": APP_DESCRIPTOR_SCHEMA,
        "execution_kind": "normal_app",
        "argv": list(member["argv"]),
        "cpu_set": member["cpu_set"],
        "cwd": member["cwd"],
        "environment": dict(member["environment"]),
        "binary_path": str(member_context["binary_path"]),
        "binary_sha256": identity["binary_sha256"],
        "application_wall_timeout_seconds": recipe["deadlines"]["application_wall_timeout_seconds"],
        "term_grace_seconds": recipe["deadlines"]["application_term_grace_seconds"],
        "stdout_path": outputs["stdout"],
        "stderr_path": outputs["stderr"],
        "timing_path": outputs["timing"],
        "monitored_files": monitored,
    }


def _run_one_member(
    member_context: dict[str, Any], prepared: dict[str, Any],
    on_app_started: Any | None = None, on_app_terminal: Any | None = None,
) -> dict[str, Any]:
    recipe = prepared["recipe"]
    inputs = prepared["inputs"]
    modules = prepared["modules"]
    member = member_context["member"]
    outputs = member["outputs"]
    output_root = Path(outputs["root"])
    soak = modules["soak_supervisor"]
    require(callable(getattr(soak, "supervise_pressure_application", None)), "pinned SourceV5 soak reader has no exported shared pressure supervisor")
    cleanup_state: dict[str, Any] = {"value": None}
    launch_state: dict[str, Any] = {"value": None}
    interruption_path = output_root / "supervision-interruption.json"

    def on_started(attestation: dict[str, Any]) -> None:
        require(launch_state["value"] is None, "normal APP launch callback was repeated")
        launch_state["value"] = attestation
        write_new(Path(outputs["app_launch_attestation"]), canonical_bytes(attestation), "normal APP launch attestation")
        if on_app_started is not None:
            process = attestation.get("process")
            require(type(process) is dict, "pressure APP attestation lacks its direct process identity")
            on_app_started({
                "schema": "allocatbelt.application-source5-pressure-app-start.v1",
                "campaign_id": inputs["spec"]["campaign_id"],
                "host_id": inputs["host_id"],
                "run_id": inputs["job"]["run_id"],
                "member_ordinal": member["ordinal"],
                "descriptor": member["descriptor"],
                "proof": {
                    "pid": process.get("pid"),
                    "start_ticks": process.get("start_ticks"),
                    "attestation_sha256": attestation.get("attestation_sha256"),
                },
            })

    def on_cleanup(cleanup: dict[str, Any]) -> None:
        require(cleanup_state["value"] is None, "normal APP cleanup callback was repeated")
        cleanup_state["value"] = cleanup
        write_new(Path(outputs["cleanup_receipt"]), canonical_bytes(cleanup), "normal APP cleanup receipt")
        if on_app_terminal is not None:
            status, signal_number = _source5_normalized_terminal_status(cleanup)
            on_app_terminal({
                "schema": "allocatbelt.application-source5-pressure-app-terminal.v1",
                "campaign_id": inputs["spec"]["campaign_id"],
                "host_id": inputs["host_id"],
                "run_id": inputs["job"]["run_id"],
                "member_ordinal": member["ordinal"],
                "descriptor": member["descriptor"],
                "pid": cleanup.get("pid"),
                "status": status,
                "child_return_code": cleanup.get("return_code"),
                "signal": signal_number,
                "cleanup": cleanup,
                "terminal_monotonic_ns": time.monotonic_ns(),
            })

    def on_interrupted(value: dict[str, Any]) -> int:
        interruption = {
            "schema": "allocatbelt.application-pressure-pair-member-interruption.v1",
            "descriptor": member["descriptor"],
            "job_run_id": inputs["job"]["run_id"],
            "signal": value["signal"],
            "pressure_driver": {
                "pid": value["pressure_pid"], "start_ticks": value["pressure_start_ticks"],
                "return_code": value["pressure_return_code"],
            },
            "application_cleanup": value["application_cleanup"],
            "pressure_cleanup": value["pressure_cleanup"],
            "pressure_worker_sessions": value["workers"],
            "qualification_eligible": False,
        }
        interruption["interruption_sha256"] = sha256_bytes(canonical_bytes(interruption))
        write_new(interruption_path, canonical_bytes(interruption), "normal APP pressure interruption receipt")
        return 128 + value["signal"]

    app_descriptor = _member_supervision_descriptor(member_context, recipe)
    app_descriptor["on_interrupted"] = on_interrupted
    try:
        receipt = soak.supervise_pressure_application(
            app_descriptor,
            member_context["pressure_info"],
            output_root,
            on_started,
            on_cleanup,
        )
    except BaseException as error:
        failure = {
            "schema": "allocatbelt.application-pressure-pair-member-failure.v1",
            "descriptor": member["descriptor"],
            "job_run_id": inputs["job"]["run_id"],
            "error_type": type(error).__name__,
            "error_sha256": sha256_bytes(str(error).encode("utf-8", "replace")),
            "application_launch_attestation_sha256": None if launch_state["value"] is None else sha256_bytes(canonical_bytes(launch_state["value"])),
            "application_cleanup": cleanup_state["value"],
            "qualification_eligible": False,
        }
        failure_path = output_root / "member-failure.json"
        if not failure_path.exists() and not failure_path.is_symlink():
            write_new(failure_path, canonical_bytes(failure), "normal APP pressure member failure receipt")
        raise
    require(receipt.get("schema") == "allocatbelt.application-pressure-supervision.v1" and receipt.get("execution_kind") == "normal_app", "shared pressure supervisor returned an incompatible receipt")
    supervision_sha = write_new(Path(outputs["supervision_receipt"]), canonical_bytes(receipt), "normal APP pressure supervision receipt")
    require(receipt["status"] == 0 and receipt["interrupted"] is False and receipt["pressure_cleanup"] == "verified", "normal APP pressure supervision did not complete both owned lifecycles")
    require(receipt["application_cleanup"]["status"] == "verified" and cleanup_state["value"] == receipt["application_cleanup"], "normal APP cleanup callback differs from the supervisor receipt")
    require(launch_state["value"] == receipt["application_attestation"] and Path(outputs["app_launch_attestation"]).is_file(), "normal APP actual-Popen attestation was not atomically recorded")
    require(receipt["application_binding"]["process"]["pid"] == receipt["application_attestation"]["process"]["pid"], "pressure driver launch record belongs to a process other than the direct APP")
    require(receipt["application_binding"]["process"]["start_ticks"] == receipt["application_attestation"]["process"]["start_ticks"], "pressure driver launch record APP start identity differs")
    pressure_stdout_path = output_root / "pressure-driver.stdout.log"
    pressure_stderr_path = output_root / "pressure-driver.stderr.log"
    _pressure_stdout_raw, pressure_stdout_sha, _stdout_info = read_stable(pressure_stdout_path, "pressure driver stdout log", recipe["artifact_budgets"]["supervision_bytes"])
    _pressure_stderr_raw, pressure_stderr_sha, _stderr_info = read_stable(pressure_stderr_path, "pressure driver stderr log", recipe["artifact_budgets"]["supervision_bytes"])
    return {
        "receipt": receipt,
        "supervision_receipt": {"path": outputs["supervision_receipt"], "raw_sha256": supervision_sha},
        "application_launch_attestation": {"path": outputs["app_launch_attestation"], "raw_sha256": sha256_bytes(canonical_bytes(launch_state["value"]))},
        "cleanup_receipt": {"path": outputs["cleanup_receipt"], "raw_sha256": sha256_bytes(canonical_bytes(cleanup_state["value"]))},
        "pressure_readback": {"path": outputs["pressure_readback"], "raw_sha256": receipt["pressure_proof"]["raw_sha256"]},
        "pressure_driver_logs": {
            "stdout": {"path": str(pressure_stdout_path), "raw_sha256": pressure_stdout_sha},
            "stderr": {"path": str(pressure_stderr_path), "raw_sha256": pressure_stderr_sha},
        },
        "pressure_ready_sha256": receipt["pressure_ready_sha256"],
        "pressure_driver": receipt["pressure_driver"],
        "pressure_worker_sessions": receipt["pressure_worker_sessions"],
        "application_binding": receipt["application_binding"],
        "application_attestation": receipt["application_attestation"],
    }


def _finalize_feedback(
    member_context: dict[str, Any], member_run: dict[str, Any],
    prepared: dict[str, Any], app_result: dict[str, Any],
) -> dict[str, Any]:
    recipe = prepared["recipe"]
    inputs = prepared["inputs"]
    modules = prepared["modules"]
    member = member_context["member"]
    identity = member["identity"]
    outputs = member["outputs"]
    descriptor = member["descriptor"]
    expectation = member_run["receipt"]["pressure_proof"]
    require(type(expectation) is dict and type(expectation.get("proof")) is dict, "shared supervisor omitted the closed pressure proof")
    proof_path = Path(outputs["pressure_readback"])
    proof, proof_raw, proof_sha = read_json(proof_path, "member pressure readback", recipe["artifact_budgets"]["pressure_proof_bytes"])
    require(proof == expectation["proof"] and proof_sha == expectation["raw_sha256"], "member pressure readback differs from the supervisor's independently checked proof")
    runtime_path = Path(outputs["runtime_binding"])
    runtime_raw, runtime_sha, _runtime_info = read_stable(runtime_path, "normal APP runtime-binding V2", recipe["artifact_budgets"]["runtime_binding_bytes"])
    runtime_fields = _parse_runtime_binding(runtime_raw)
    require(
        runtime_fields.get("identity.report_nonce") == identity["report_nonce"]
        and runtime_fields.get("identity.run_id") == inputs["job"]["run_id"]
        and runtime_fields.get("identity.allocator") == descriptor["allocator"]
        and runtime_fields.get("identity.executor") == identity["executor"]
        and runtime_fields.get("identity.comparison_family") == "external_pressure"
        and runtime_fields.get("identity.source_sha256") == identity["source_sha256"]
        and runtime_fields.get("identity.binary_sha256") == identity["binary_sha256"],
        "normal APP runtime-binding V2 identity differs from the direct APP member",
    )

    oracle_duration = app_result["row_metrics"].get("oracle_trace_duration_ns")
    if inputs["job"]["mode"] == "open_loop":
        require(type(oracle_duration) is int and oracle_duration > 0, "normal APP open-loop oracle duration is missing")
        minimum_production_seconds = max(1, (oracle_duration + 999_999_999) // 1_000_000_000)
    else:
        minimum_production_seconds = min(recipe["deadlines"]["trace_seconds"], 30)
    minimum_overlap = recipe["pressure_condition"]["readiness_thresholds"]["minimum_overlap_seconds"]
    app_identity = {
        "host_id": inputs["host_id"],
        "run_id": inputs["job"]["run_id"],
        "report_nonce": identity["report_nonce"],
        "process_id": member_run["application_attestation"]["process"]["pid"],
        "allocator": descriptor["allocator"],
        "executor": identity["executor"],
        "workload": inputs["job"]["workload"],
        "profile": inputs["job"]["profile"],
        "mode": inputs["job"]["mode"],
        "source_sha256": inputs["source"]["source"]["source_tree_sha256"],
        "binary_sha256": identity["binary_sha256"],
        "pressure_qualification": True,
    }
    capacity_bundle = {
        name: {"path": recipe["capacity_bundle"][name]["path"], "raw_sha256": recipe["capacity_bundle"][name]["raw_sha256"]}
        for name in ("request", "artifact", "receipt")
    }
    expectation_header = {
        "identity": app_identity,
        "external_pressure_proof": {
            "path": str(proof_path), "raw_sha256": proof_sha,
            "validator_sha256": modules["pressure_validator_pin"]["sha256"],
            "recipe_raw_sha256": member["pressure_recipe"]["artifact"]["raw_sha256"],
        },
        "final_runtime_binding": {"path": str(runtime_path), "raw_sha256": runtime_sha},
        "minimum_production_seconds": minimum_production_seconds,
        "minimum_pressure_overlap_seconds": minimum_overlap,
    }
    request = {
        "schema": modules["feedback_composition"].FINALIZE_SCHEMA,
        "source_root": str(inputs["source_root"]),
        "source_manifest": {"path": str(inputs["manifest_path"]), "raw_sha256": inputs["manifest_raw_sha256"]},
        "resolved_policy": {
            "path": member["composition"]["policy"]["path"],
            "raw_sha256": member["composition"]["policy"]["raw_sha256"],
        },
        "composition_receipt": {
            "path": member["composition"]["receipt"]["path"],
            "raw_sha256": member["composition"]["receipt"]["raw_sha256"],
        },
        "construction_probe": {
            "path": member["construction_probe"]["path"],
            "raw_sha256": member["construction_probe"]["raw_sha256"],
            "allocator": member["construction_probe"]["allocator"],
            "binary_sha256": member["construction_probe"]["binary_sha256"],
        },
        "capacity_bundle": capacity_bundle,
        "expectation_header": expectation_header,
    }
    request_path = Path(outputs["finalization_request"])
    request_raw = canonical_bytes(request)
    request_sha = write_new(request_path, request_raw, "normal APP finalization request")
    finalization_result = _run_composer_cli(modules["feedback_composition"], [
        "finalize", "--request", str(request_path),
        "--expectation-output", outputs["runtime_expectation"],
        "--receipt-output", outputs["finalization_receipt"],
    ])
    final_expectation, _final_raw, final_sha = read_json(Path(outputs["runtime_expectation"]), "normal APP V5 feedback expectation", MAX_RECIPE_BYTES)
    finalization_receipt, _finalization_raw, finalization_sha = read_json(Path(outputs["finalization_receipt"]), "normal APP composer finalization receipt", MAX_SMALL_BYTES)
    require(final_sha == finalization_receipt["expectation_raw_sha256"] == finalization_result["expectation_raw_sha256"], "SourceV5 composer finalization receipt differs from its expectation bytes")
    require(finalization_receipt["qualification_eligible"] is False and finalization_receipt["execution_ready"] is False and finalization_receipt["controller_chronology_proven"] is False, "composer finalization attempted to set qualification or chronology readiness")

    feedback_files: dict[str, str] = {}
    for label, field in (("manifest", "feedback_manifest"), ("events", "feedback_events"), ("samples", "feedback_samples")):
        _raw, actual_sha, _info = read_stable(Path(outputs[field]), f"normal APP feedback {label}", {
            "manifest": recipe["artifact_budgets"]["feedback_manifest_bytes"],
            "events": recipe["artifact_budgets"]["feedback_events_bytes"],
            "samples": recipe["artifact_budgets"]["feedback_samples_bytes"],
        }[label])
        feedback_files[label] = actual_sha
    try:
        validation = modules["feedback_validator"].verify_feedback(
            Path(outputs["runtime_expectation"]), final_sha,
            Path(outputs["trace_directory"]), feedback_files,
        )
    except Exception as error:
        raise PressurePairError(f"pinned SourceV5 feedback V5 reader rejected the normal APP trace/runtime/pressure evidence: {error}") from error
    require(validation.get("schema") == "allocatbelt.application-feedback-validation.v1" and validation.get("mode") == "pressure_validation" and validation.get("validated") is True, "SourceV5 feedback V5 reader returned the wrong normal APP role")
    require(validation["qualification_eligible"] is False, "normal APP feedback V5 readback set qualification eligibility before the campaign gates")
    require(validation["identity"] == app_identity, "SourceV5 feedback validation identity differs from the actual direct APP Popen")
    validation_raw = canonical_bytes(validation)
    validation_sha = write_new(Path(outputs["feedback_validation"]), validation_raw, "normal APP feedback V5 validation")

    numeric_snapshot = pressure_numeric_runtime_snapshot(
        modules["campaign_controller"], runtime_fields,
        modules["feedback_composition"]._read_canonical(
            Path(member["composition"]["policy"]["path"]), "member resolved policy",
            member["composition"]["policy"]["raw_sha256"],
        )[0]["policy"],
        inputs["source"]["runtime_readback_validator"]["sha256"],
    )
    return {
        "expectation": {"path": outputs["runtime_expectation"], "raw_sha256": final_sha},
        "finalization_request": {"path": outputs["finalization_request"], "raw_sha256": request_sha},
        "finalization_receipt": {"path": outputs["finalization_receipt"], "raw_sha256": finalization_sha},
        "feedback_validation": {"path": outputs["feedback_validation"], "raw_sha256": validation_sha},
        "feedback_files": feedback_files,
        "runtime_binding": {"path": str(runtime_path), "raw_sha256": runtime_sha},
        "numeric_snapshot": numeric_snapshot,
        "validation": validation,
    }


def _process_row(
    member_context: dict[str, Any], member_run: dict[str, Any],
    app_result: dict[str, Any], feedback: dict[str, Any], prepared: dict[str, Any],
) -> dict[str, str]:
    member = member_context["member"]
    identity = member["identity"]
    descriptor = member["descriptor"]
    outputs = member["outputs"]
    source = prepared["inputs"]["source"]
    policy = member["composition"]["policy"]
    resolved, _resolved_raw, resolved_sha = read_json(Path(policy["path"]), "member resolved numeric policy", MAX_SMALL_BYTES, policy["raw_sha256"])
    expectation_path = Path(outputs["runtime_expectation"])
    expectation, expectation_raw, expectation_sha = read_json(expectation_path, "final normal APP feedback expectation", MAX_SMALL_BYTES)
    require(expectation.get("schema") == modules_feedback_expectation_schema(prepared["modules"]["feedback_validator"]), "final APP expectation schema differs from SourceV5 V5")
    runtime_path = Path(outputs["runtime_binding"])
    _runtime_raw, runtime_sha, _runtime_info = read_stable(runtime_path, "normal APP runtime-binding V2", prepared["recipe"]["artifact_budgets"]["runtime_binding_bytes"])
    validation_path = Path(outputs["feedback_validation"])
    _validation_raw, validation_sha, _validation_info = read_stable(validation_path, "normal APP feedback validation", prepared["recipe"]["artifact_budgets"]["feedback_validation_bytes"])
    shutdown_sha = app_result["raw_artifacts"]["shutdown"]["raw_sha256"]
    ids_sha = app_result["raw_artifacts"]["ids"]["raw_sha256"] if app_result["raw_artifacts"]["ids"] is not None else "not_applicable"
    family_sha = "not_applicable"
    if identity["mode"] == "capacity" and identity["workload"] == "mixed":
        _family_raw, family_sha, _family_info = read_stable(Path(outputs["capacity_families"]), "normal APP capacity-family report", prepared["recipe"]["artifact_budgets"]["shutdown_bytes"])
        require(type(app_result["raw_artifacts"]["capacity_families"]) is dict and app_result["raw_artifacts"]["capacity_families"]["raw_sha256"] == family_sha, "normal APP capacity-family report pin differs")
    calibration = source["resource_domain_calibration"]
    header = prepared["modules"]["campaign_controller"].PAIR_PROCESS_HEADER
    require(header == PAIR_PROCESS_HEADER_FALLBACK, "SourceV5 campaign controller changed the fixed base process row header")
    row = {
        "pair": descriptor["pair"],
        "executor": descriptor["executor"],
        "allocator": descriptor["allocator"],
        "exit_code": "0",
        "row_validation": "valid",
        "p99_qualification": "not_applicable",
        "argv": canonical_bytes(member["argv"]).decode("ascii").rstrip("\n"),
        "stdout": Path(outputs["stdout"]).name,
        "time_report": Path(outputs["timing"]).name,
        "ids_sha256": ids_sha,
        "shutdown_sha256": shutdown_sha,
        "capacity_family_sha256": family_sha,
        "stdout_sha256": app_result["raw_artifacts"]["stdout"]["raw_sha256"],
        "runtime_readback": Path(outputs["runtime_binding"]).name,
        "runtime_readback_sha256": runtime_sha,
        "runtime_expectation": Path(outputs["runtime_expectation"]).name,
        "runtime_expectation_sha256": expectation_sha,
        "runtime_validation": Path(outputs["feedback_validation"]).name,
        "runtime_validation_sha256": validation_sha,
        "runtime_recipe_sha256": digest(expectation.get("recipe_sha256"), "final expectation recipe SHA-256"),
        "resource_ceiling_sha256": identity["resource_ceiling_sha256"],
        "policy_sha256": resolved["policy_sha256"],
        "fixed_global_control_baseline": str(prepared["shared_policy"]["value"]["baseline"]),
        "validator_sha256": prepared["inputs"]["source"]["runtime_readback_validator"]["sha256"],
        "source_manifest_sha256": prepared["inputs"]["manifest_raw_sha256"],
        "calibration_binary_sha256": calibration["binary"]["sha256"],
        "calibration_output_sha256": calibration["output"]["sha256"],
    }
    require(set(row) == set(header), "pressure process row does not preserve the immutable campaign header")
    return row


def modules_feedback_expectation_schema(reader: Any) -> str:
    return reader.EXPECTATION_SCHEMA_V5


def _pressure_artifact_pins(pressure_dir: Path, pressure_recipe: dict[str, Any]) -> dict[str, str]:
    require(pressure_dir.is_dir() and not pressure_dir.is_symlink() and pressure_dir.resolve(strict=True) == pressure_dir, "pressure artifact directory is missing, aliased, or not a directory")
    info = pressure_dir.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "pressure artifact directory ownership or mode differs")
    names = {"run.json", "events.jsonl", "launch-record.json", "process-binding.json", "pressure-ready.json"}
    require({item.name for item in pressure_dir.iterdir()} == names, "pressure artifact directory does not have the driver's exact five-file contract")
    limits = {
        "run.json": MAX_SMALL_BYTES,
        "events.jsonl": min(MAX_TRACE_BYTES, pressure_recipe["artifact_budget"]["maximum_event_bytes"]),
        "launch-record.json": MAX_SMALL_BYTES,
        "process-binding.json": MAX_SMALL_BYTES,
        "pressure-ready.json": MAX_SMALL_BYTES,
    }
    result: dict[str, str] = {}
    for name in sorted(names):
        path = pressure_dir / name
        _raw, raw_sha, _file_info = read_stable(path, f"pressure artifact {name}", limits[name])
        result[{"run.json": "run", "events.jsonl": "events", "launch-record.json": "launch", "process-binding.json": "process_binding", "pressure-ready.json": "ready"}[name]] = raw_sha
    return result


def _member_evidence(
    member_context: dict[str, Any], member_run: dict[str, Any], app_result: dict[str, Any],
    feedback: dict[str, Any], process_row: dict[str, str], prepared: dict[str, Any],
) -> dict[str, Any]:
    member = member_context["member"]
    outputs = member["outputs"]
    pressure_dir = Path(outputs["root"]) / "pressure"
    pressure_pins = _pressure_artifact_pins(pressure_dir, member_context["pressure_info"]["value"])
    return {
        "descriptor": member["descriptor"],
        "identity": member["identity"],
        "feedback_template": member["feedback_template"],
        "composition": member["composition"],
        "construction_probe": member["construction_probe"],
        "application_binary": member["application_binary"],
        "argv_sha256": sha256_bytes(canonical_bytes(member["argv"])),
        "environment_sha256": sha256_bytes(canonical_bytes(member["environment"])),
        "cwd": member["cwd"],
        "tmpdir_path": member["tmpdir_path"],
        "cpu_affinity": member["cpu_affinity"],
        "network_namespace_inode": member["network_namespace_inode"],
        "oracle": member_context["oracle"],
        "application_identity": member_run["application_attestation"]["process"],
        "application_launch_attestation": member_run["application_launch_attestation"],
        "application_cleanup": member_run["cleanup_receipt"],
        "supervision_receipt": member_run["supervision_receipt"],
        "pressure_recipe": {
            "path": member_context["pressure_info"]["path"],
            "raw_sha256": member_context["pressure_info"]["raw_sha256"],
            "semantic_sha256": member_context["pressure_info"]["semantic_sha256"],
            "condition_sha256": member_context["pressure_info"]["condition_sha256"],
        },
        "pressure_artifacts": {
            "directory": str(pressure_dir),
            "pins": pressure_pins,
            "proof": member_run["pressure_readback"],
            "ready_sha256": member_run["pressure_ready_sha256"],
            "driver": member_run["pressure_driver"],
            "worker_sessions": member_run["pressure_worker_sessions"],
            "driver_logs": member_run["pressure_driver_logs"],
        },
        "app_artifacts": app_result["raw_artifacts"],
        "runtime_binding": feedback["runtime_binding"],
        "runtime_expectation": feedback["expectation"],
        "runtime_finalization_request": feedback["finalization_request"],
        "runtime_finalization_receipt": feedback["finalization_receipt"],
        "feedback_trace": {
            "directory": outputs["trace_directory"],
            "manifest": {"path": outputs["feedback_manifest"], "raw_sha256": feedback["feedback_files"]["manifest"]},
            "events": {"path": outputs["feedback_events"], "raw_sha256": feedback["feedback_files"]["events"]},
            "samples": {"path": outputs["feedback_samples"], "raw_sha256": feedback["feedback_files"]["samples"]},
            "validation": feedback["feedback_validation"],
        },
        "numeric_runtime_snapshot": feedback["numeric_snapshot"],
        "process_row": process_row,
        "validation_outcome": {
            "validated": True,
            "qualification_eligible": False,
            "reason": "per-job evidence is valid; campaign qualification gates remain open",
        },
    }


def _write_process_ledger(path: Path, rows: list[dict[str, str]], controller: Any) -> str:
    header = controller.PAIR_PROCESS_HEADER
    require(header == PAIR_PROCESS_HEADER_FALLBACK and len(rows) == 2, "pressure adapter changed the fixed two-row process ledger contract")
    require(all(set(row) == set(header) for row in rows), "pressure adapter row fields differ from the fixed campaign process header")
    require(len({(row["pair"], row["executor"], row["allocator"]) for row in rows}) == 2, "pressure pair process rows repeat an identity")
    raw = ("\t".join(header) + "\n" + "".join("\t".join(row[name] for name in header) + "\n" for row in rows)).encode("utf-8")
    return write_new(path, raw, "pressure pair-compatible process ledger")


def _read_process_ledger(path: Path, expected_sha256: str, controller: Any) -> list[dict[str, str]]:
    raw, raw_sha, _info = read_stable(path, "pressure pair process ledger", MAX_SMALL_BYTES)
    require(raw_sha == expected_sha256, "pressure pair process ledger raw pin differs")
    header, rows = _tabular_bytes(raw, "pressure pair process ledger", 2)
    require(header == controller.PAIR_PROCESS_HEADER == PAIR_PROCESS_HEADER_FALLBACK, "pressure pair process ledger changed the original fixed header")
    return rows


def _verify_self_digest(value: dict[str, Any], field: str, label: str) -> None:
    expected = digest(value.get(field), f"{label} self digest")
    body = {key: item for key, item in value.items() if key != field}
    require(expected == sha256_bytes(canonical_bytes(body)), f"{label} self digest is invalid")


def _validate_pair_member_artifacts(
    stored: dict[str, Any], member_context: dict[str, Any], prepared: dict[str, Any],
) -> dict[str, Any]:
    recipe = prepared["recipe"]
    modules = prepared["modules"]
    inputs = prepared["inputs"]
    member = member_context["member"]
    outputs = member["outputs"]
    descriptor = member["descriptor"]
    identity = member["identity"]
    evidence_fields = {
        "descriptor", "identity", "feedback_template", "construction_probe", "application_binary",
        "composition",
        "argv_sha256", "environment_sha256", "cwd", "tmpdir_path", "cpu_affinity", "network_namespace_inode",
        "oracle", "application_identity", "application_launch_attestation", "application_cleanup",
        "supervision_receipt", "pressure_recipe", "pressure_artifacts", "app_artifacts", "runtime_binding",
        "runtime_expectation", "runtime_finalization_request", "runtime_finalization_receipt",
        "feedback_trace", "numeric_runtime_snapshot", "process_row", "validation_outcome",
    }
    exact(stored, evidence_fields, "pressure-pair member readback")
    require(stored["descriptor"] == descriptor and stored["identity"] == identity, "pressure-pair member sidecar identity differs from the original plan descriptor")
    require(stored["feedback_template"] == member["feedback_template"], "pressure-pair member sidecar feedback template pin differs")
    require(stored["composition"] == member["composition"], "pressure-pair member sidecar resolver request/policy/receipt pins differ")
    require(stored["construction_probe"] == member["construction_probe"] and stored["application_binary"] == member["application_binary"], "pressure-pair member sidecar probe/binary pin differs")
    require(stored["argv_sha256"] == sha256_bytes(canonical_bytes(member["argv"])) and stored["environment_sha256"] == sha256_bytes(canonical_bytes(member["environment"])), "pressure-pair member argv/environment digest differs")
    require(stored["cwd"] == member["cwd"] and stored["tmpdir_path"] == member["tmpdir_path"] and stored["cpu_affinity"] == member["cpu_affinity"] and stored["network_namespace_inode"] == member["network_namespace_inode"], "pressure-pair member host/process binding differs")
    require(stored["oracle"] == member_context["oracle"], "pressure-pair member oracle pin differs")
    require(stored["validation_outcome"] == {
        "validated": True, "qualification_eligible": False,
        "reason": "per-job evidence is valid; campaign qualification gates remain open",
    }, "pressure-pair member outcome claims an unsupported readiness state")

    attestation_pin = exact(stored["application_launch_attestation"], {"path", "raw_sha256"}, "normal APP launch attestation pin")
    attestation_path, _attestation_raw, attestation_sha = read_pin(attestation_pin, "normal APP launch attestation", MAX_SMALL_BYTES)
    attestation, _attestation_bytes, _attestation_sha = read_json(attestation_path, "normal APP launch attestation", MAX_SMALL_BYTES, attestation_sha)
    exact(attestation, {"schema", "execution_kind", "process", "attestation_sha256"}, "normal APP launch attestation")
    require(attestation["schema"] == "allocatbelt.application-pressure-app-launch-attestation.v1" and attestation["execution_kind"] == "normal_app", "normal APP attestation role differs")
    _verify_self_digest(attestation, "attestation_sha256", "normal APP launch attestation")
    process = exact(attestation["process"], {
        "pid", "start_ticks", "executable_path", "executable_sha256", "executable_device", "executable_inode",
        "executable_size", "executable_fd_reference", "cwd", "argv", "argv_sha256", "cmdline_raw_sha256",
        "environment_sha256", "environment_raw_sha256",
    }, "normal APP direct process attestation")
    pid = uint(process["pid"], "normal APP direct PID", positive=True, maximum=(1 << 31) - 1)
    start_ticks = uint(process["start_ticks"], "normal APP direct start ticks", positive=True)
    binary_path = member_context["binary_path"]
    _binary_raw, binary_sha, binary_stat = read_stable(binary_path, "normal APP SourceV5 binary", MAX_BINARY_BYTES)
    require(
        process["executable_path"] == str(binary_path) and process["executable_sha256"] == identity["binary_sha256"] == binary_sha
        and process["executable_device"] == binary_stat.st_dev and process["executable_inode"] == binary_stat.st_ino
        and process["executable_size"] == binary_stat.st_size,
        "normal APP direct executable path/hash/fd identity differs from the pinned SourceV5 binary",
    )
    require(process["cwd"] == member["cwd"] and process["argv"] == member["argv"] and process["argv_sha256"] == sha256_bytes(canonical_bytes(member["argv"])), "normal APP direct cwd/argv differs from its full pinned descriptor")
    require(process["environment_sha256"] == sha256_bytes(canonical_bytes(member["environment"])), "normal APP direct full environment digest differs from its pinned descriptor")
    for name in ("cmdline_raw_sha256", "environment_raw_sha256"):
        digest(process[name], f"normal APP {name}")
    require(type(process["executable_fd_reference"]) is str and re.fullmatch(r"/proc/self/fd/[0-9]+", process["executable_fd_reference"]) is not None, "normal APP execution fd reference is malformed")

    cleanup_pin = exact(stored["application_cleanup"], {"path", "raw_sha256"}, "normal APP cleanup pin")
    cleanup_path, _cleanup_raw, cleanup_sha = read_pin(cleanup_pin, "normal APP cleanup receipt", MAX_SMALL_BYTES)
    cleanup, _cleanup_bytes, _cleanup_hash = read_json(cleanup_path, "normal APP cleanup receipt", MAX_SMALL_BYTES, cleanup_sha)
    exact(cleanup, {"schema", "status", "pid", "return_code", "received_signal", "cleanup_error"}, "normal APP cleanup receipt")
    require(cleanup["schema"] == "allocatbelt.application-soak-process-cleanup.v1" and cleanup["status"] == "verified" and cleanup["pid"] == pid and cleanup["return_code"] == 0 and cleanup["received_signal"] is None and cleanup["cleanup_error"] is None, "normal APP process cleanup receipt is incomplete or failed")

    supervision_pin = exact(stored["supervision_receipt"], {"path", "raw_sha256"}, "normal APP pressure supervision pin")
    supervision_path, _supervision_raw, supervision_sha = read_pin(supervision_pin, "normal APP pressure supervision receipt", MAX_SMALL_BYTES)
    supervision, _supervision_bytes, _supervision_hash = read_json(supervision_path, "normal APP pressure supervision receipt", MAX_SMALL_BYTES, supervision_sha)
    require(supervision.get("schema") == "allocatbelt.application-pressure-supervision.v1" and supervision.get("execution_kind") == "normal_app" and supervision.get("status") == 0 and supervision.get("interrupted") is False and supervision.get("pressure_cleanup") == "verified", "normal APP pressure supervision receipt is not a successful normal APP run")
    require(supervision.get("application_attestation") == attestation and supervision.get("application_cleanup") == cleanup, "supervision receipt differs from the independently pinned APP launch/cleanup receipts")
    require(supervision.get("application_binding")["process"]["pid"] == pid and supervision.get("application_binding")["process"]["start_ticks"] == start_ticks, "pressure driver launch record does not bind the direct APP PID/start")
    details = supervision.get("details")
    require(type(details) is dict, "pressure supervision receipt omits direct Popen details")
    require(
        details.get("status") == 0 and details.get("requested_argv") == member["argv"]
        and details.get("executed_argv") == member["argv"]
        and details.get("binary_path") == str(binary_path)
        and details.get("binary_sha256") == identity["binary_sha256"]
        and details.get("environment") == member["environment"]
        and details.get("environment_sha256") == sha256_bytes(canonical_bytes(member["environment"]))
        and details.get("cwd") == member["cwd"]
        and details.get("cpu_set") == member["cpu_set"],
        "verified direct Popen details differ from the full original member descriptor",
    )
    require(
        details.get("binary_device") == binary_stat.st_dev and details.get("binary_inode") == binary_stat.st_ino
        and details.get("binary_size") == binary_stat.st_size
        and details.get("executed_file_descriptor") == process["executable_fd_reference"],
        "verified executable fd identity differs between direct Popen and APP attestation",
    )
    require(details.get("requested_argv_sha256") == sha256_bytes(canonical_bytes(member["argv"])), "direct Popen argv hash differs")

    pressure_recipe_path = Path(member["pressure_recipe"]["artifact"]["path"])
    pressure_dir = Path(outputs["root"]) / "pressure"
    pressure_recipe = member_context["pressure_info"]["value"]
    require(stored["pressure_recipe"] == {
        "path": str(pressure_recipe_path),
        "raw_sha256": member["pressure_recipe"]["artifact"]["raw_sha256"],
        "semantic_sha256": member["pressure_recipe"]["semantic_sha256"],
        "condition_sha256": member["pressure_recipe"]["condition_sha256"],
    }, "pressure member recipe pin differs")
    pressure_info = stored["pressure_artifacts"]
    exact(pressure_info, {"directory", "pins", "proof", "ready_sha256", "driver", "worker_sessions", "driver_logs"}, "pressure member artifacts")
    require(pressure_info["directory"] == str(pressure_dir), "pressure artifacts escaped their dedicated pressure directory")
    artifact_pins = _pressure_artifact_pins(pressure_dir, pressure_recipe)
    require(pressure_info["pins"] == artifact_pins, "pressure member raw artifact hashes differ from the closed pressure directory")
    proof_pin = exact(pressure_info["proof"], {"path", "raw_sha256"}, "normal APP pressure proof pin")
    require(proof_pin["path"] == outputs["pressure_readback"] and proof_pin["raw_sha256"] == supervision.get("pressure_proof", {}).get("raw_sha256"), "pressure proof path/hash differs from the shared supervisor receipt")
    proof_value, _proof_raw, proof_sha = read_json(Path(proof_pin["path"]), "normal APP pressure proof", recipe["artifact_budgets"]["pressure_proof_bytes"], proof_pin["raw_sha256"])
    require(proof_sha == pressure_info["proof"]["raw_sha256"], "normal APP pressure proof raw pin differs")
    proof_expected = {"recipe": member["pressure_recipe"]["semantic_sha256"], **artifact_pins}
    try:
        pressure_result = modules["pressure_validator"].verify_pressure(
            pressure_recipe_path, member["pressure_recipe"]["semantic_sha256"], pressure_dir, proof_expected,
        )
        checked_proof = modules["soak_supervisor"].validate_pressure_proof_inputs(
            pressure_dir,
            member_context["pressure_info"],
            proof_expected,
            recipe["pressure_condition"]["readiness_thresholds"],
            Path(outputs["pressure_readback"]),
        )
    except Exception as error:
        raise PressurePairError(f"pinned pressure validators rejected the normal APP pressure proof: {error}") from error
    require(proof_value == pressure_result == checked_proof["proof"] and checked_proof["raw_sha256"] == proof_sha, "normal APP pressure proof differs between the driver reader and shared soak proof checker")
    require(pressure_info["ready_sha256"] == artifact_pins["ready"] and pressure_info["driver"] == supervision["pressure_driver"] and pressure_info["worker_sessions"] == supervision["pressure_worker_sessions"], "pressure readiness/driver/worker cleanup binding differs from supervision")
    driver_logs = exact(pressure_info["driver_logs"], {"stdout", "stderr"}, "pressure driver log pins")
    for label in ("stdout", "stderr"):
        item = exact(driver_logs[label], {"path", "raw_sha256"}, f"pressure driver {label} pin")
        log_path = Path(item["path"])
        require(log_path.parent == Path(outputs["root"]), "pressure driver log escaped its member root")
        _log_raw, log_sha, _log_info = read_stable(log_path, f"pressure driver {label}", recipe["artifact_budgets"]["supervision_bytes"])
        require(log_sha == item["raw_sha256"], f"pressure driver {label} raw pin differs")
    require(proof_value["application_process"]["pid"] == pid and proof_value["application_process"]["start_ticks"] == start_ticks, "pressure proof is bound to another APP PID/start identity")

    feedback_trace = exact(stored["feedback_trace"], {"directory", "manifest", "events", "samples", "validation"}, "normal APP feedback trace pins")
    require(feedback_trace["directory"] == outputs["trace_directory"], "feedback trace directory differs from the member descriptor")
    feedback_file_hashes: dict[str, str] = {}
    for label, field in (("manifest", "feedback_manifest"), ("events", "feedback_events"), ("samples", "feedback_samples")):
        trace_pin = exact(feedback_trace[label], {"path", "raw_sha256"}, f"feedback {label} pin")
        require(trace_pin["path"] == outputs[field], f"feedback {label} path differs from the member descriptor")
        maximum = recipe["artifact_budgets"][{
            "manifest": "feedback_manifest_bytes", "events": "feedback_events_bytes", "samples": "feedback_samples_bytes",
        }[label]]
        _trace_raw, actual_sha, _trace_info = read_stable(Path(trace_pin["path"]), f"normal APP feedback {label}", maximum)
        require(actual_sha == trace_pin["raw_sha256"], f"feedback {label} raw digest differs")
        feedback_file_hashes[label] = actual_sha
    expectation_pin = exact(stored["runtime_expectation"], {"path", "raw_sha256"}, "normal APP V5 expectation pin")
    require(expectation_pin["path"] == outputs["runtime_expectation"], "normal APP V5 expectation path differs")
    expectation_value, _expectation_raw, expectation_sha = read_json(Path(expectation_pin["path"]), "normal APP V5 expectation", MAX_SMALL_BYTES, expectation_pin["raw_sha256"])
    require(expectation_value.get("schema") == modules["feedback_validator"].EXPECTATION_SCHEMA_V5 and expectation_value.get("mode") == "pressure_validation", "normal APP expectation uses a timed-soak role or another schema")
    require(expectation_value["identity"]["process_id"] == pid and expectation_value["identity"]["report_nonce"] == identity["report_nonce"], "normal APP V5 expectation does not bind the actual direct APP PID/report nonce")
    validation_pin = exact(feedback_trace["validation"], {"path", "raw_sha256"}, "normal APP feedback V5 validation pin")
    require(validation_pin["path"] == outputs["feedback_validation"], "normal APP feedback validation path differs")
    validation_value, _validation_raw, _validation_sha = read_json(Path(validation_pin["path"]), "normal APP feedback V5 validation", recipe["artifact_budgets"]["feedback_validation_bytes"], validation_pin["raw_sha256"])
    try:
        replayed_validation = modules["feedback_validator"].verify_feedback(
            Path(expectation_pin["path"]), expectation_sha,
            Path(feedback_trace["directory"]), feedback_file_hashes,
        )
    except Exception as error:
        raise PressurePairError(f"pinned feedback V5 reader rejected the final normal APP trace/runtime binding: {error}") from error
    require(validation_value == replayed_validation and replayed_validation["qualification_eligible"] is False and replayed_validation["identity"] == expectation_value["identity"], "normal APP feedback readback differs from the final expectation or attempts qualification")
    require(replayed_validation["final_runtime_binding"]["validated"] is True, "normal APP feedback V5 readback did not validate owner release")
    runtime_pin = exact(stored["runtime_binding"], {"path", "raw_sha256"}, "normal APP runtime-binding V2 pin")
    require(runtime_pin["path"] == outputs["runtime_binding"], "normal APP runtime-binding V2 path differs")
    runtime_raw, runtime_sha, _runtime_info = read_stable(Path(runtime_pin["path"]), "normal APP runtime-binding V2", recipe["artifact_budgets"]["runtime_binding_bytes"])
    require(runtime_sha == runtime_pin["raw_sha256"] == replayed_validation["final_runtime_binding"]["raw_sha256"], "normal APP runtime binding raw digest differs from V5 readback")
    runtime_fields = _parse_runtime_binding(runtime_raw)
    resolved_policy, _policy_raw, _policy_sha = read_json(
        Path(member["composition"]["policy"]["path"]), "normal APP resolved policy", MAX_SMALL_BYTES,
        member["composition"]["policy"]["raw_sha256"],
    )
    numeric_snapshot = pressure_numeric_runtime_snapshot(
        modules["campaign_controller"], runtime_fields, resolved_policy["policy"],
        inputs["source"]["runtime_readback_validator"]["sha256"],
    )
    require(stored["numeric_runtime_snapshot"] == numeric_snapshot, "pressure metrics adapter numeric snapshot differs from runtime-binding V2 evidence")

    app_result = _validate_app_outputs(member_context, inputs, recipe, modules, supervision)
    require(stored["app_artifacts"] == app_result["raw_artifacts"], "normal APP artifact pins differ from the direct closed stdout/ID/shutdown reader")
    feedback = {
        "expectation": expectation_pin,
        "runtime_binding": runtime_pin,
        "feedback_validation": validation_pin,
        "finalization_request": stored["runtime_finalization_request"],
        "finalization_receipt": stored["runtime_finalization_receipt"],
    }
    for name in ("runtime_finalization_request", "runtime_finalization_receipt"):
        reference = exact(stored[name], {"path", "raw_sha256"}, f"{name} pin")
        artifact_raw, artifact_sha, _artifact_info = read_stable(Path(reference["path"]), name, MAX_SMALL_BYTES)
        require(artifact_sha == reference["raw_sha256"], f"{name} raw pin differs")
        if name == "runtime_finalization_receipt":
            receipt_value = json.loads(artifact_raw)
            require(receipt_value["qualification_eligible"] is False and receipt_value["execution_ready"] is False and receipt_value["controller_chronology_proven"] is False, "composer finalization receipt attempted to set readiness")
    request_value, request_raw, request_sha = read_json(
        Path(stored["runtime_finalization_request"]["path"]),
        "normal APP finalization request", MAX_SMALL_BYTES,
        stored["runtime_finalization_request"]["raw_sha256"],
    )
    require(request_value["expectation_header"]["identity"]["process_id"] == pid and request_value["expectation_header"]["identity"]["report_nonce"] == identity["report_nonce"], "finalization request differs from the actual normal APP PID/report nonce")
    with tempfile.TemporaryDirectory(
        prefix=f"finalize-replay-{member['ordinal']}-",
        dir=Path(prepared["output_root"]) / "preflight",
    ) as temporary:
        replay_expectation = Path(temporary) / "expectation.json"
        replay_receipt = Path(temporary) / "receipt.json"
        cli_result = _run_composer_cli(modules["feedback_composition"], [
            "finalize", "--request", str(Path(stored["runtime_finalization_request"]["path"])),
            "--expectation-output", str(replay_expectation),
            "--receipt-output", str(replay_receipt),
        ])
        _stored_expectation_raw, stored_expectation_sha, _stored_expectation_info = read_stable(
            Path(stored["runtime_expectation"]["path"]), "stored normal APP final expectation", MAX_RECIPE_BYTES,
        )
        replay_expectation_raw, replay_expectation_sha, _replay_expectation_info = read_stable(
            replay_expectation, "replayed normal APP V5 expectation", MAX_RECIPE_BYTES,
        )
        replay_receipt_value, replay_receipt_raw, replay_receipt_sha = read_json(replay_receipt, "replayed composer finalization receipt", MAX_SMALL_BYTES)
        stored_receipt_value, stored_receipt_raw, stored_receipt_sha = read_json(
            Path(stored["runtime_finalization_receipt"]["path"]), "stored composer finalization receipt", MAX_SMALL_BYTES,
        )
        require(replay_expectation_raw == _stored_expectation_raw and replay_expectation_sha == stored_expectation_sha, "pinned SourceV5 composer did not reproduce the final APP expectation")
        require(replay_receipt_raw == stored_receipt_raw and replay_receipt_sha == stored_receipt_sha and cli_result["expectation_raw_sha256"] == stored_expectation_sha, "pinned SourceV5 composer did not reproduce its finalization receipt")
        require(stored_receipt_value["finalization_request_raw_sha256"] == request_sha, "composer finalization receipt does not pin the raw request bytes")
    process_row = _process_row(member_context, {"receipt": supervision}, app_result, feedback, prepared)
    require(stored["process_row"] == process_row, "pressure-compatible base process row differs from independently revalidated artifacts")
    return {
        "process_row": process_row,
        "app_result": app_result,
        "feedback_validation": replayed_validation,
        "pressure_proof": proof_value,
        "runtime_numeric_snapshot": numeric_snapshot,
        "runtime_binding_sha256": runtime_sha,
        "source_manifest_raw_sha256": inputs["manifest_raw_sha256"],
        "fixed_global_control_baseline": prepared["shared_policy"]["value"]["baseline"],
        "pair_output_root": str(prepared["output_root"]),
        "application_pid": pid,
        "application_start_ticks": start_ticks,
    }


def controller_pressure_metrics_adapter(
    member: dict[str, Any], checked: dict[str, Any],
) -> dict[str, Any]:
    """Project verified normal-APP pressure evidence into controller metrics.

    This adapter deliberately leaves the fixed-only controller extractor and
    its process header alone. It reports measurements for this exact job and
    never marks the row or campaign performance-qualified.
    """
    descriptor = member["descriptor"]
    identity = member["identity"]
    row = checked["app_result"]["stdout"]
    proof = checked["pressure_proof"]
    row_metrics = checked["app_result"]["row_metrics"]
    id_artifact = checked["app_result"]["raw_artifacts"]["ids"]
    ids_path = None if id_artifact is None else str(Path(id_artifact["path"]).relative_to(Path(checked["pair_output_root"])))
    metrics = {
        "pair": descriptor["pair"],
        "executor": descriptor["executor"],
        "allocator": descriptor["allocator"],
        "mode": identity["mode"],
        "completed": int(row["completed_on_time"]) + int(row["completed_late"]),
        "completed_on_time": int(row["completed_on_time"]),
        "completed_late": int(row["completed_late"]),
        "capacity_per_second": None if row["capacity_publications_per_second"] == "" else float(Decimal(row["capacity_publications_per_second"])),
        "capacity_throughput_by_family": row_metrics["capacity_throughput_by_family"],
        "successful_throughput_per_second": float(Decimal(row["successful_throughput_through_drain_per_second"])),
        "response_p50_ns": int(row["response_p50_ns"]),
        "response_p95_ns": int(row["response_p95_ns"]),
        "response_p99_ns": int(row["response_p99_ns"]),
        "cpu_ns_per_completion": row_metrics["cpu_ns_per_completion"],
        "production_cpu_started_ns": row_metrics["production_cpu_started_ns"],
        "production_cpu_ended_ns": row_metrics["production_cpu_ended_ns"],
        "production_cpu_ns": row_metrics["production_cpu_ns"],
        "phase_sha256": checked["app_result"]["raw_artifacts"]["shutdown"]["raw_sha256"],
        "ids_sha256": None if id_artifact is None else id_artifact["raw_sha256"],
        "ids_path": ids_path,
        "family_successes": row_metrics["family_successes"],
        "latency_p99_by_family_ns": row_metrics["latency_p99_by_family_ns"],
        "rss_after_drain_kib": int(row["rss_after_drain_kib"]),
        "retained_managed_bytes": int(row["retained_managed_bytes"]),
        "max_observed_managed_bytes": int(row["max_observed_managed_bytes"]),
        "managed_limit_bytes": int(row["managed_limit_bytes"]),
        "pressure_sample_count": proof["sample_count"],
        "pressure_overlap_nanoseconds": proof["application_overlap_nanoseconds"],
        "runtime_numeric_snapshot_v2": checked["runtime_numeric_snapshot"],
        "runtime_readback": {
            "schema": "allocatbelt.application-pressure-runtime-readback.v1",
            "pair": descriptor["pair"],
            "executor": descriptor["executor"],
            "allocator": descriptor["allocator"],
            "report_nonce": identity["report_nonce"],
            "comparison_family": "external_pressure",
            "resource_ceiling_sha256": identity["resource_ceiling_sha256"],
            "policy_sha256": identity["policy_sha256"],
            "fixed_global_control_baseline": checked["fixed_global_control_baseline"],
            "source_manifest_sha256": checked["source_manifest_raw_sha256"],
            "runtime_readback_sha256": checked["runtime_binding_sha256"],
            "numeric_snapshot_v2": checked["runtime_numeric_snapshot"],
        },
        "execution_scope": "original_source_v5_pressure_job",
        "p99_qualification": "not_applicable",
        "qualification_eligible": False,
    }
    require(metrics["completed"] > 0 and metrics["pressure_sample_count"] > 0 and metrics["pressure_overlap_nanoseconds"] > 0, "pressure metrics adapter received incomplete per-job evidence")
    return metrics


def _verify_offline_normal_app_member(
    stored: dict[str, Any], host_fact: dict[str, Any], member_context: dict[str, Any],
    prepared: dict[str, Any], pressure_proof: dict[str, Any],
    feedback_result: dict[str, Any], feedback_validation_pin: dict[str, str],
    feedback_context: dict[str, Any],
) -> dict[str, Any]:
    """Replay the normal APP output/owner/finalization path without live process probes."""
    member = member_context["member"]
    identity = member["identity"]
    outputs = member["outputs"]
    modules = prepared["modules"]
    recipe = prepared["recipe"]
    budgets = recipe["artifact_budgets"]
    exact(stored, {
        "descriptor", "identity", "feedback_template", "construction_probe",
        "application_binary", "composition", "argv_sha256", "environment_sha256",
        "cwd", "tmpdir_path", "cpu_affinity", "network_namespace_inode", "oracle",
        "application_identity", "application_launch_attestation",
        "application_cleanup", "supervision_receipt", "pressure_recipe",
        "pressure_artifacts", "app_artifacts", "runtime_binding",
        "runtime_expectation", "runtime_finalization_request",
        "runtime_finalization_receipt", "feedback_trace", "numeric_runtime_snapshot",
        "process_row", "validation_outcome",
    }, "offline normal APP member evidence")
    require(stored["descriptor"] == member["descriptor"] and
            stored["identity"] == identity and
            stored["feedback_template"] == member["feedback_template"] and
            stored["composition"] == member["composition"] and
            stored["construction_probe"] == member["construction_probe"] and
            stored["application_binary"] == member["application_binary"] and
            stored["argv_sha256"] == sha256_bytes(canonical_bytes(member["argv"])) and
            stored["environment_sha256"] == sha256_bytes(canonical_bytes(member["environment"])) and
            stored["cwd"] == member["cwd"] and
            stored["tmpdir_path"] == member["tmpdir_path"] and
            stored["cpu_affinity"] == member["cpu_affinity"] and
            stored["network_namespace_inode"] == member["network_namespace_inode"] and
            stored["oracle"] == member_context["oracle"] and
            stored["validation_outcome"] == {
                "validated": True, "qualification_eligible": False,
                "reason": "per-job evidence is valid; campaign qualification gates remain open",
            }, "offline normal APP record differs from the exact original member descriptor")
    attestation_pin = exact(stored["application_launch_attestation"],
                            {"path", "raw_sha256"},
                            "offline normal APP attestation pin")
    attestation, _attestation_raw, attestation_sha = read_json(
        Path(attestation_pin["path"]), "offline normal APP launch attestation",
        MAX_SMALL_BYTES, attestation_pin["raw_sha256"],
    )
    origin_attestation_pin = exact(
        host_fact["application_launch_attestation"], {"path", "raw_sha256"},
        "origin normal APP launch attestation pin",
    )
    require(attestation_pin == origin_attestation_pin and
            attestation_sha == attestation_pin["raw_sha256"],
            "normal APP attestation differs from the strict origin-host receipt")
    exact(attestation, {
        "schema", "execution_kind", "process", "attestation_sha256",
    }, "offline normal APP launch attestation")
    require(attestation["schema"] == "allocatbelt.application-pressure-app-launch-attestation.v1" and
            attestation["execution_kind"] == "normal_app",
            "offline normal APP launch attestation has the wrong execution role")
    _verify_self_digest(attestation, "attestation_sha256",
                        "offline normal APP launch attestation")
    process = exact(attestation["process"], {
        "pid", "start_ticks", "executable_path", "executable_sha256",
        "executable_device", "executable_inode", "executable_size",
        "executable_fd_reference", "cwd", "argv", "argv_sha256",
        "cmdline_raw_sha256", "environment_sha256", "environment_raw_sha256",
    }, "offline normal APP direct process attestation")
    process_identity = exact(stored["application_identity"], {
        "pid", "start_ticks", "executable_path", "executable_sha256",
        "executable_device", "executable_inode", "executable_size",
        "executable_fd_reference", "cwd", "argv", "argv_sha256",
        "cmdline_raw_sha256", "environment_sha256", "environment_raw_sha256",
    }, "offline normal APP full process identity")
    receipt_identity = exact(host_fact["application_identity"],
                             {"pid", "start_ticks"},
                             "origin normal APP process identity")
    require(process_identity == process and
            {key: process_identity[key] for key in ("pid", "start_ticks")} ==
                receipt_identity == {
                "pid": process["pid"], "start_ticks": process["start_ticks"],
            } and pressure_proof["application_process"]["pid"] == process["pid"] and
            pressure_proof["application_process"]["start_ticks"] == process["start_ticks"] and
            process["executable_path"] == member["application_binary"]["path"] and
            process["executable_sha256"] == identity["binary_sha256"] and
            process["executable_size"] == Path(member["application_binary"]["path"]).stat().st_size and
            process["cwd"] == member["cwd"] and process["argv"] == member["argv"] and
            process["argv_sha256"] == sha256_bytes(canonical_bytes(member["argv"])) and
            process["environment_sha256"] == sha256_bytes(canonical_bytes(member["environment"])) and
            re.fullmatch(r"/proc/self/fd/[0-9]+", process["executable_fd_reference"]) is not None,
            "normal APP attestation differs from its exact captured process/member identity")
    cleanup_pin = exact(stored["application_cleanup"], {"path", "raw_sha256"},
                        "offline normal APP cleanup pin")
    cleanup, _cleanup_raw, cleanup_sha = read_json(
        Path(cleanup_pin["path"]), "offline normal APP cleanup receipt",
        MAX_SMALL_BYTES, cleanup_pin["raw_sha256"],
    )
    origin_cleanup_pin = exact(
        host_fact["application_cleanup"], {"path", "raw_sha256"},
        "origin normal APP cleanup pin",
    )
    require(cleanup_pin == origin_cleanup_pin and
            cleanup_sha == cleanup_pin["raw_sha256"],
            "normal APP cleanup receipt differs from the strict origin-host receipt")
    exact(cleanup, {
        "schema", "status", "pid", "return_code", "received_signal", "cleanup_error",
    }, "offline normal APP cleanup receipt")
    require(cleanup["schema"] == "allocatbelt.application-soak-process-cleanup.v1" and
            cleanup["status"] == "verified" and cleanup["pid"] == process["pid"] and
            cleanup["return_code"] == 0 and cleanup["received_signal"] is None and
            cleanup["cleanup_error"] is None,
            "normal APP cleanup was not exact and successful")
    supervision_pin = exact(stored["supervision_receipt"],
                            {"path", "raw_sha256"},
                            "offline normal APP supervision pin")
    supervision, _supervision_raw, supervision_sha = read_json(
        Path(supervision_pin["path"]), "offline normal APP supervision receipt",
        MAX_SMALL_BYTES, supervision_pin["raw_sha256"],
    )
    origin_supervision_pin = exact(
        host_fact["supervision_receipt"], {"path", "raw_sha256"},
        "origin normal APP supervision pin",
    )
    require(supervision_pin == origin_supervision_pin and
            supervision_sha == supervision_pin["raw_sha256"] and
            supervision.get("schema") == "allocatbelt.application-pressure-supervision.v1" and
            supervision.get("execution_kind") == "normal_app" and
            supervision.get("status") == 0 and
            supervision.get("interrupted") is False and
            supervision.get("pressure_cleanup") == "verified" and
            supervision.get("application_attestation") == attestation and
            supervision.get("application_cleanup") == cleanup,
            "normal APP supervision differs from its origin attestation/cleanup evidence")
    details = supervision.get("details")
    require(type(details) is dict,
            "offline direct APP supervisor details are malformed")
    require(details.get("status") == 0 and details.get("requested_argv") == member["argv"] and
            details.get("executed_argv") == member["argv"] and
            details.get("binary_path") == member["application_binary"]["path"] and
            details.get("binary_sha256") == identity["binary_sha256"] and
            details.get("environment") == member["environment"] and
            details.get("environment_sha256") == sha256_bytes(canonical_bytes(member["environment"])) and
            details.get("cwd") == member["cwd"] and details.get("cpu_set") == member["cpu_set"] and
            details.get("binary_device") == process["executable_device"] and
            details.get("binary_inode") == process["executable_inode"] and
            details.get("binary_size") == process["executable_size"] and
            details.get("executed_file_descriptor") == process["executable_fd_reference"] and
            details.get("requested_argv_sha256") == sha256_bytes(canonical_bytes(member["argv"])),
            "direct Popen owner facts differ from the frozen normal APP descriptor")

    request_pin = exact(stored["runtime_finalization_request"],
                        {"path", "raw_sha256"},
                        "offline V5 finalization request pin")
    request_value, request_raw, request_sha = read_json(
        Path(request_pin["path"]), "offline V5 finalization request",
        MAX_SMALL_BYTES, request_pin["raw_sha256"],
    )
    composer = modules["feedback_composition"]
    expected_body = composer.finalize_calibrated_feedback_expectation_v5_offline(
        request_value, request_sha, replay_context=feedback_context,
    )
    final_raw, final_sha = modules["feedback_validator"].build_pressure_expectation_recipe(
        expected_body,
    )
    expectation_pin = exact(stored["runtime_expectation"], {"path", "raw_sha256"},
                            "offline final V5 expectation pin")
    expectation_raw, expectation_sha, _expectation_info = read_stable(
        Path(expectation_pin["path"]), "offline final V5 expectation",
        MAX_RECIPE_BYTES,
    )
    require(expectation_pin["path"] == outputs["runtime_expectation"] and
            expectation_raw == final_raw and expectation_sha == final_sha ==
            expectation_pin["raw_sha256"],
            "stored final V5 expectation differs from the pure ProbeV2 finalization replay")
    finalization_pin = exact(stored["runtime_finalization_receipt"],
                             {"path", "raw_sha256"},
                             "offline V5 finalization receipt pin")
    receipt_body = {
        "schema": composer.FINALIZE_RECEIPT_SCHEMA,
        "validated": True, "execution_ready": False,
        "qualification_eligible": False,
        "controller_chronology_proven": False,
        "finalization_request_raw_sha256": request_sha,
        "composition_receipt_raw_sha256":
            member["composition"]["receipt"]["raw_sha256"],
        "expectation_header_sha256": modules["feedback_validator"].digest_object(
            request_value["expectation_header"],
        ),
        "expectation_raw_sha256": final_sha,
        "validator_sha256": composer._self_sha256(),
    }
    receipt_value = dict(receipt_body)
    receipt_value["receipt_sha256"] = composer.sha256(composer.canonical(receipt_body))
    stored_receipt, stored_receipt_raw, stored_receipt_sha = read_json(
        Path(finalization_pin["path"]), "offline V5 finalization receipt",
        MAX_SMALL_BYTES, finalization_pin["raw_sha256"],
    )
    require(finalization_pin["path"] == outputs["finalization_receipt"] and
            stored_receipt == receipt_value and
            stored_receipt_raw == composer.canonical(receipt_value) and
            stored_receipt_sha == finalization_pin["raw_sha256"],
            "stored V5 finalization receipt differs from its pure captured-input replay")

    app_result = _validate_app_outputs(
        member_context, prepared["inputs"], prepared["recipe"], modules,
        supervision,
    )
    require(stored["app_artifacts"] == app_result["raw_artifacts"],
            "normal APP output/IDs/oracle/shutdown pins differ from independent replay")
    runtime_pin = exact(stored["runtime_binding"], {"path", "raw_sha256"},
                        "offline normal APP runtime binding pin")
    runtime_raw, runtime_sha, _runtime_info = read_stable(
        Path(runtime_pin["path"]), "offline normal APP runtime binding",
        budgets["runtime_binding_bytes"],
    )
    require(runtime_pin["path"] == outputs["runtime_binding"] and
            runtime_sha == runtime_pin["raw_sha256"] and
            feedback_result["final_runtime_binding"]["raw_sha256"] == runtime_sha,
            "normal APP runtime binding differs from its final V5 validation")
    runtime_fields = _parse_runtime_binding(runtime_raw)
    policy_value, _policy_raw, _policy_sha = read_json(
        Path(member["composition"]["policy"]["path"]),
        "offline normal APP resolved policy", MAX_SMALL_BYTES,
        member["composition"]["policy"]["raw_sha256"],
    )
    numeric_snapshot = pressure_numeric_runtime_snapshot(
        modules["campaign_controller"], runtime_fields, policy_value["policy"],
        prepared["inputs"]["source"]["runtime_readback_validator"]["sha256"],
    )
    require(stored["numeric_runtime_snapshot"] == numeric_snapshot,
            "normal APP numeric runtime snapshot differs from the captured binding")
    feedback = {
        "expectation": expectation_pin,
        "finalization_request": request_pin,
        "finalization_receipt": finalization_pin,
        "feedback_validation": feedback_validation_pin,
        "runtime_binding": runtime_pin,
    }
    process_row = _process_row(
        member_context, {"receipt": supervision}, app_result, feedback, prepared,
    )
    require(stored["process_row"] == process_row,
            "normal APP reconstructed process row differs from the exact pair sidecar")
    checked = {
        "process_row": process_row, "app_result": app_result,
        "feedback_validation": feedback_result,
        "pressure_proof": pressure_proof,
        "runtime_numeric_snapshot": numeric_snapshot,
        "runtime_binding_sha256": runtime_sha,
        "source_manifest_raw_sha256": prepared["inputs"]["manifest_raw_sha256"],
        "fixed_global_control_baseline": prepared["shared_policy"]["value"]["baseline"],
        "pair_output_root": str(prepared["output_root"]),
        "application_pid": process["pid"],
        "application_start_ticks": process["start_ticks"],
    }
    return {
        "checked": checked, "process_row": process_row,
        "application_pid": process["pid"],
        "application_start_ticks": process["start_ticks"],
        "pressure_metric": controller_pressure_metrics_adapter(member, checked),
    }


def _pair_readback_body(prepared: dict[str, Any], processes_pin: dict[str, str], members: list[dict[str, Any]]) -> dict[str, Any]:
    inputs = prepared["inputs"]
    recipe = prepared["recipe"]
    return {
        "schema": READBACK_SCHEMA,
        "validated": True,
        "job_evidence_complete": True,
        "qualification_eligible": False,
        "execution_ready": False,
        "campaign_readiness": False,
        "controller_chronology_proven": False,
        "source_manifest": {
            "path": str(inputs["manifest_path"]),
            "raw_sha256": inputs["manifest_raw_sha256"],
            "semantic_sha256": inputs["manifest_semantic_sha256"],
            "source_tree_sha256": inputs["source"]["source"]["source_tree_sha256"],
        },
        "spec": {
            "path": str(inputs["spec_path"]),
            "raw_sha256": inputs["spec_raw_sha256"],
            "semantic_sha256": recipe["spec"]["semantic_sha256"],
        },
        "plan": {
            "path": str(inputs["plan_path"]),
            "raw_sha256": inputs["plan_raw_sha256"],
            "semantic_sha256": recipe["plan"]["semantic_sha256"],
        },
        "job": {
            "run_id": inputs["job"]["run_id"],
            "ordinal": inputs["job"]["ordinal"],
            "job_index": inputs["job_index"],
            "semantic_sha256": sha256_bytes(canonical_bytes(inputs["job"])),
        },
        "execution_overlay": {
            "path": prepared["overlay"]["path"],
            "raw_sha256": prepared["overlay"]["raw_sha256"],
            "overlay_sha256": prepared["overlay"]["value"]["overlay_sha256"],
            "journal_head": prepared["overlay"]["chronology"]["journal_head"],
            "registration_head": prepared["overlay"]["chronology"]["registration_head"],
        },
        "capacity_completion": {
            **recipe["capacity_completion"]["artifact"],
            "schedule_sha256": recipe["capacity_completion"]["schedule_sha256"],
            "registration_head": recipe["capacity_completion"]["registration_head"],
        },
        "capacity_bundle": recipe["capacity_bundle"],
        "shared_policy": {
            "path": prepared["shared_policy"]["path"],
            "raw_sha256": prepared["shared_policy"]["raw_sha256"],
            "policy_sha256": prepared["shared_policy"]["value"]["policy_sha256"],
            "baseline": prepared["shared_policy"]["value"]["baseline"],
            "member_resolutions": prepared["shared_policy"]["value"]["member_resolutions"],
        },
        "fixed_predecessor": {
            "record": prepared["predecessor"]["record"],
            "receipt": prepared["predecessor"]["receipt"],
            "receipt_value": prepared["predecessor"]["value"],
        },
        "pressure_condition": _pressure_condition_sidecar_value(recipe),
        "processes": processes_pin,
        "members": members,
    }


def _pressure_condition_sidecar_value(recipe: dict[str, Any]) -> dict[str, Any]:
    condition = recipe["pressure_condition"]
    result = {
        "condition_id": condition["condition_id"],
        "condition_sha256": condition["condition_sha256"],
        "readiness_thresholds": condition["readiness_thresholds"],
        "schedule": condition["schedule"],
    }
    if "pressure_calibration_v2" in condition:
        result["pressure_calibration_v2"] = condition["pressure_calibration_v2"]
    return result


def validate_pressure_pair_artifacts(
    recipe: dict[str, Any],
    output_root: Path,
    readback_path: Path | None = None,
    expected_readback_sha256: str | None = None,
    *, chronology_module: Any | None = None, lock: Any | None = None,
    authorization_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay a pair sidecar and all raw normal-APP, V5, pressure, and V2 artifacts."""
    recipe = _validate_recipe_shape(recipe)
    output_root = Path(output_root)
    prepared = _prepare_prerequisites(
        recipe, output_root, chronology_module=chronology_module,
        lock=lock, authorization_context=authorization_context,
    )
    output_root = prepared["output_root"]
    readback_path = output_root / PAIR_READBACK_FILE if readback_path is None else Path(readback_path)
    require(readback_path == output_root / PAIR_READBACK_FILE, "pressure-pair readback path differs from the frozen pair output layout")
    sidecar, sidecar_raw, sidecar_sha = read_json(
        readback_path, "pressure-pair readback sidecar", recipe["artifact_budgets"]["pair_sidecar_bytes"], expected_readback_sha256,
    )
    sidecar_fields = {
        "schema", "validated", "job_evidence_complete", "qualification_eligible", "execution_ready",
        "campaign_readiness", "controller_chronology_proven", "source_manifest", "spec", "plan", "job",
        "execution_overlay", "capacity_completion", "capacity_bundle", "shared_policy", "fixed_predecessor",
        "pressure_condition", "processes", "members", "readback_sha256",
    }
    exact(sidecar, sidecar_fields, "pressure-pair readback sidecar")
    require(sidecar["schema"] == READBACK_SCHEMA and sidecar["validated"] is True and sidecar["job_evidence_complete"] is True, "pressure-pair readback sidecar is not a complete per-job result")
    require(sidecar["qualification_eligible"] is False and sidecar["execution_ready"] is False and sidecar["campaign_readiness"] is False and sidecar["controller_chronology_proven"] is False, "per-job pressure readback attempts to set overall readiness")
    _verify_self_digest(sidecar, "readback_sha256", "pressure-pair readback")
    require(sidecar_raw == canonical_bytes(sidecar), "pressure-pair readback sidecar is not canonical")

    expected_source = {
        "path": str(prepared["inputs"]["manifest_path"]), "raw_sha256": prepared["inputs"]["manifest_raw_sha256"],
        "semantic_sha256": prepared["inputs"]["manifest_semantic_sha256"],
        "source_tree_sha256": prepared["inputs"]["source"]["source"]["source_tree_sha256"],
    }
    require(sidecar["source_manifest"] == expected_source, "pressure pair sidecar source manifest identity differs")
    require(sidecar["spec"] == {
        "path": str(prepared["inputs"]["spec_path"]), "raw_sha256": prepared["inputs"]["spec_raw_sha256"],
        "semantic_sha256": recipe["spec"]["semantic_sha256"],
    }, "pressure pair sidecar original spec pin differs")
    require(sidecar["plan"] == {
        "path": str(prepared["inputs"]["plan_path"]), "raw_sha256": prepared["inputs"]["plan_raw_sha256"],
        "semantic_sha256": recipe["plan"]["semantic_sha256"],
    }, "pressure pair sidecar original plan pin differs")
    require(sidecar["job"] == {
        "run_id": prepared["inputs"]["job"]["run_id"], "ordinal": prepared["inputs"]["job"]["ordinal"],
        "job_index": prepared["inputs"]["job_index"], "semantic_sha256": sha256_bytes(canonical_bytes(prepared["inputs"]["job"])),
    }, "pressure pair sidecar job index/run/ordinal differs from the original plan")
    expected_overlay = {
        "path": prepared["overlay"]["path"], "raw_sha256": prepared["overlay"]["raw_sha256"],
        "overlay_sha256": prepared["overlay"]["value"]["overlay_sha256"],
        "journal_head": prepared["overlay"]["chronology"]["journal_head"],
        "registration_head": prepared["overlay"]["chronology"]["registration_head"],
    }
    require(sidecar["execution_overlay"] == expected_overlay, "pressure pair sidecar execution overlay chronology heads differ")
    require(sidecar["capacity_completion"] == {
        **recipe["capacity_completion"]["artifact"],
        "schedule_sha256": recipe["capacity_completion"]["schedule_sha256"],
        "registration_head": recipe["capacity_completion"]["registration_head"],
    }, "pressure pair sidecar capacity completion pin differs")
    require(sidecar["capacity_bundle"] == recipe["capacity_bundle"], "pressure pair sidecar complete capacity bundle differs")
    require(sidecar["shared_policy"] == {
        "path": prepared["shared_policy"]["path"],
        "raw_sha256": prepared["shared_policy"]["raw_sha256"],
        "policy_sha256": prepared["shared_policy"]["value"]["policy_sha256"],
        "baseline": prepared["shared_policy"]["value"]["baseline"],
        "member_resolutions": prepared["shared_policy"]["value"]["member_resolutions"],
    }, "pressure pair sidecar shared numeric policy differs")
    require(sidecar["fixed_predecessor"] == {
        "record": prepared["predecessor"]["record"],
        "receipt": prepared["predecessor"]["receipt"],
        "receipt_value": prepared["predecessor"]["value"],
    }, "pressure pair sidecar fixed predecessor is not the exact controller reconstruction")
    require(sidecar["pressure_condition"] == _pressure_condition_sidecar_value(recipe),
            "pressure pair sidecar condition differs from the original SourceV5 input")
    processes_pin = exact(sidecar["processes"], {"path", "raw_sha256"}, "pressure-compatible process ledger pin")
    processes_path = output_root / "processes.tsv"
    require(processes_pin["path"] == str(processes_path), "pressure-compatible process ledger path differs")
    rows = _read_process_ledger(processes_path, processes_pin["raw_sha256"], prepared["modules"]["campaign_controller"])
    require(type(sidecar["members"]) is list and len(sidecar["members"]) == 2, "pressure pair readback does not contain exactly two members")
    require(len(rows) == 2, "pressure-compatible process ledger does not contain exactly two original APP rows")
    expected_identities = [
        (item["descriptor"]["pair"], item["descriptor"]["executor"], item["descriptor"]["allocator"])
        for item in recipe["members"]
    ]
    require([(row["pair"], row["executor"], row["allocator"]) for row in rows] == expected_identities, "pressure-compatible process rows changed original member order/identity")
    member_results = []
    pressure_metrics: list[dict[str, Any]] = []
    pids: set[tuple[int, int]] = set()
    for index, member_context in enumerate(prepared["members"]):
        checked = _validate_pair_member_artifacts(sidecar["members"][index], member_context, prepared)
        require(rows[index] == checked["process_row"], "base process row differs from the separately pinned pressure sidecar row")
        process_key = (checked["application_pid"], checked["application_start_ticks"])
        require(process_key not in pids, "paired normal APP members repeat a direct PID/start identity")
        pids.add(process_key)
        pressure_metrics.append(controller_pressure_metrics_adapter(recipe["members"][index], checked))
        member_results.append(checked)
    require(all(row["exit_code"] == "0" and row["row_validation"] == "valid" and row["p99_qualification"] == "not_applicable" for row in rows), "pressure base rows claim a failed APP or open-loop P99 qualification")
    return {
        "schema": READBACK_SCHEMA,
        "validated": True,
        "qualification_eligible": False,
        "execution_ready": False,
        "campaign_readiness": False,
        "controller_chronology_proven": False,
        "readback_sha256": sidecar_sha,
        "processes_sha256": processes_pin["raw_sha256"],
        "member_count": 2,
        "application_identities": [
            {"pid": row["application_pid"], "start_ticks": row["application_start_ticks"]}
            for row in member_results
        ],
        "pressure_metrics": pressure_metrics,
    }


HOST_VERIFICATION_SCHEMA = "allocatbelt.application-pressure-pair-host-verification.v1"
ORIGIN_FACTS_SCHEMA = "allocatbelt.application-pressure-pair-origin-facts.v1"


def _capture_pair_origin_facts(
    host_id: str, observed_host: dict[str, Any], pressure_recipes: list[dict[str, Any]],
    pressure_driver: Any,
) -> dict[str, Any]:
    exact(observed_host, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity", "network_namespace_inode",
    }, "strict Source5 observed-host context")
    require(observed_host["schema"] == "allocatbelt.application-capacity-host-context.v1" and
            observed_host["host_id"] == host_id,
            "strict Source5 observed-host schema or host identity differs")
    digest(observed_host["boot_id_sha256"], "strict observed boot identity digest")
    digest(observed_host["controls_sha256"], "strict observed controls digest")
    text(observed_host["kernel_release"], "strict observed kernel release", 256)
    controls = exact(observed_host["controls"], {
        "cpu_model", "microcode_sha256", "kernel_release", "governor",
        "frequency_policy", "boost_policy", "cpu_set", "numa_policy",
        "cgroup_policy_sha256", "background_load_policy_sha256",
        "x86_64_v3_capability_sha256", "target_triple", "target_cpu",
    }, "strict observed host controls")
    require(observed_host["controls_sha256"] == digest_object(controls) and
            observed_host["kernel_release"] == controls["kernel_release"] and
            observed_host["cpu_model"] == controls["cpu_model"],
            "strict observed host control digest/model differs")
    text(observed_host["cpu_model"], "strict observed CPU model", 256)
    uint(observed_host["network_namespace_inode"],
         "strict observed network namespace inode", positive=True)
    affinity = observed_host["cpu_affinity"]
    require(type(affinity) is list and affinity and
            affinity == sorted(set(uint(cpu, "strict observed CPU", maximum=65535)
                                   for cpu in affinity)),
            "strict observed CPU affinity is malformed")
    for pressure_recipe in pressure_recipes:
        pressure_driver._verify_live_environment(pressure_recipe)
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_bytes().strip().decode("ascii")
        require(re.fullmatch(r"[0-9a-f-]{36}", boot_id) is not None,
                "origin boot identity is malformed")
        facts = {
            "boot_id_sha256": hashlib.sha256(boot_id.encode("ascii")).hexdigest(),
            "kernel_release": os.uname().release,
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
            "network_namespace_inode": os.stat("/proc/self/ns/net").st_ino,
        }
    except (OSError, UnicodeError) as error:
        raise PressurePairError(f"cannot capture strict origin-host identity facts: {error}") from error
    require(facts["boot_id_sha256"] == observed_host["boot_id_sha256"] and
            facts["kernel_release"] == observed_host["kernel_release"] and
            facts["cpu_affinity"] == observed_host["cpu_affinity"] and
            facts["network_namespace_inode"] == observed_host["network_namespace_inode"],
            "strict pressure-pair host differs from its exact observed Source5 host")
    require(all(pressure_recipe["identity"]["host_id"] == host_id
                for pressure_recipe in pressure_recipes),
            "pressure-pair recipes do not share the original host identity")
    return facts


def _verify_pair_observed_host_pin(
    observed_host_pin_value: object, host_id: str,
    pressure_recipes: list[dict[str, Any]], pressure_reader: Any,
) -> tuple[dict[str, str], dict[str, Any]]:
    """Validate the original capacity-host context against both pressure recipes."""
    require(type(pressure_recipes) is list and len(pressure_recipes) == 2,
            "strict Source5 observed-host binding requires both original pressure members")
    observed_pin = _artifact_reference(observed_host_pin_value,
                                       "strict Source5 observed-host context")
    try:
        validated_pin, observed = pressure_reader._verify_observed_host_pin_v2(
            observed_pin, host_id,
        )
    except Exception as error:
        raise PressurePairError(
            f"pinned pressure reader rejected the original observed-host context: "
            f"{type(error).__name__}: {error}"
        ) from error
    require(validated_pin == observed_pin and type(observed) is dict,
            "strict Source5 observed-host reader changed the exact raw pin")
    for index, pressure_recipe in enumerate(pressure_recipes):
        scope_binding = exact(pressure_recipe.get("calibration_scope_v2"), {
            "schema", "scope_receipt", "validator_sha256", "condition",
            "context_policy", "capacity_bundle_pins", "observed_host",
            "context_policy_sha256",
        }, f"strict pressure member[{index}] context calibration binding")
        require(scope_binding["schema"] == "allocatbelt.application-pressure-calibration-binding.v2" and
                scope_binding["observed_host"] == observed_pin,
                f"strict pressure member[{index}] changed the exact observed-host raw pin")
        host = pressure_recipe["host"]
        network = pressure_recipe["network"]
        require(pressure_recipe["identity"]["host_id"] == host_id and
                observed["boot_id_sha256"] == host["boot_id_sha256"] and
                observed["kernel_release"] == host["kernel_release"] and
                observed["cpu_affinity"] == host["allowed_cpu_affinity"] and
                observed["network_namespace_inode"] == network["network_namespace_inode"],
                f"strict pressure member[{index}] host/boot/affinity/netns differs from its pinned observed host")
    return observed_pin, observed


def _read_pressure_member_recipe(
    pressure_reader: Any, reference_value: object,
    expected_identity: dict[str, Any], ordinal: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Keep the raw canonical recipe separate from the reader's summary return."""
    reference = exact(reference_value, {
        "artifact", "semantic_sha256", "condition_sha256",
    }, f"strict pressure member[{ordinal}] recipe reference")
    artifact = _artifact_reference(reference["artifact"],
                                   f"strict pressure member[{ordinal}] recipe")
    full_recipe, _raw, raw_sha = read_json(
        Path(artifact["path"]), f"strict pressure member[{ordinal}] recipe",
        MAX_RECIPE_BYTES, artifact["raw_sha256"],
    )
    require(raw_sha == artifact["raw_sha256"],
            f"strict pressure member[{ordinal}] recipe raw pin changed")
    try:
        summary = pressure_reader._validate_recipe(
            full_recipe, digest(reference["semantic_sha256"],
                                f"strict pressure member[{ordinal}] semantic SHA-256"),
        )
    except Exception as error:
        raise PressurePairError(
            f"SourceV5 pressure reader rejected full member recipe[{ordinal}]: "
            f"{type(error).__name__}: {error}"
        ) from error
    digest(reference["condition_sha256"],
           f"strict pressure member[{ordinal}] condition SHA-256")
    require(type(summary) is dict and
            summary.get("condition_sha256") == reference["condition_sha256"] and
            summary.get("identity") == full_recipe.get("identity"),
            f"strict pressure member[{ordinal}] reader summary differs from its full recipe pins")
    expected_identity = exact(expected_identity, {
        "host_id", "run_id", "pair_id", "condition_id", "member", "nonce",
        "allocator", "executor", "phase",
    }, f"strict pressure member[{ordinal}] expected identity")
    identity = exact(full_recipe.get("identity"), set(expected_identity),
                     f"strict pressure member[{ordinal}] full recipe identity")
    require(identity == expected_identity,
            f"strict pressure member[{ordinal}] full recipe identity differs from its original pair member")
    require({"schema", "host", "process", "recipe_sha256"} <= set(full_recipe) and
            "host" not in summary and "process" not in summary,
            f"strict pressure member[{ordinal}] full recipe was replaced by the reader summary")
    return full_recipe, summary


def _read_pressure_pair_member_recipes(
    recipe: dict[str, Any], inputs: dict[str, Any], pressure_reader: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate both original member recipes while retaining their full records."""
    require(type(recipe.get("members")) is list and len(recipe["members"]) == 2,
            "strict pressure recipe reader requires both original pair members")
    full_recipes: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for index, member in enumerate(recipe["members"]):
        identity, descriptor = member["identity"], member["descriptor"]
        expected_identity = {
            "host_id": inputs["host_id"], "run_id": inputs["job"]["run_id"],
            "pair_id": inputs["job"]["run_id"],
            "condition_id": recipe["pressure_condition"]["condition_id"],
            "member": descriptor["pair"], "nonce": identity["pressure_nonce"],
            "allocator": descriptor["allocator"], "executor": identity["executor"],
            "phase": "external_pressure",
        }
        full, summary = _read_pressure_member_recipe(
            pressure_reader, member["pressure_recipe"], expected_identity, index,
        )
        full_recipes.append(full)
        summaries.append(summary)
    return full_recipes, summaries


def _strict_probe_capture_identity_path_map(
    source: dict[str, Any], source_root: Path, source_manifest_pin: dict[str, Any],
    probe_pin: dict[str, Any], capacity_bundle: dict[str, Any], capture_pin: dict[str, Any],
) -> dict[str, Any]:
    """Build an origin-local map from exact ProbeV2 and capacity role pins.

    Only the explicitly typed JSON inputs are parsed. A filename suffix does
    not authorize opening another document.
    """
    paths: set[str] = {str(source_root), str(Path(capture_pin["path"]).parent)}
    normalized, inventory = _source5_source_inventory(
        source, "strict ProbeV2 SourceV5 manifest",
    )
    for entry in normalized:
        if entry["kind"] == "symlink":
            continue
        relative = PurePosixPath(entry["path"])
        paths.add(str(source_root.joinpath(*relative.parts)))
    for relative_text, _role, _raw_sha in _source5_manifest_artifacts(
            source, inventory, "strict ProbeV2 SourceV5 manifest"):
        relative = PurePosixPath(relative_text)
        paths.add(str(source_root.joinpath(*relative.parts)))
    typed_inputs = [
        (source_manifest_pin, "strict ProbeV2 SourceV5 manifest", MAX_MANIFEST_BYTES),
        (probe_pin, "strict ProbeV2 construction request", MAX_PLAN_BYTES),
        (capture_pin, "strict ProbeV2 capture receipt", MAX_PROBE_CAPTURE_RECEIPT_BYTES),
        (capacity_bundle["request"], "strict ProbeV2 capacity request", MAX_PLAN_BYTES),
        (capacity_bundle["receipt"], "strict ProbeV2 capacity receipt", MAX_PLAN_BYTES),
    ]
    documents = []
    for value, label, maximum in typed_inputs:
        pin = exact(value, {"path", "raw_sha256"}, f"{label} raw pin")
        path = Path(_source5_absolute_path(pin["path"], f"{label} path"))
        document, _raw, _raw_sha = read_json(
            path, label, maximum, digest(pin["raw_sha256"], f"{label} raw SHA-256"),
        )
        documents.append(document)
        paths.add(str(path))
    capacity_artifact = exact(capacity_bundle["artifact"], {"path", "raw_sha256"},
                              "strict ProbeV2 capacity artifact pin")
    paths.add(_source5_absolute_path(capacity_artifact["path"],
                                     "strict ProbeV2 capacity artifact path"))
    for document in documents:
        paths.update(_pair_absolute_paths(document))
        trace_directory = document.get("trace_directory")
        if type(trace_directory) is str:
            trace_root = Path(_source5_absolute_path(
                trace_directory, "strict ProbeV2 trace directory",
            ))
            for filename in ("feedback-trace-manifest.tsv", "feedback-events.jsonl",
                             "resource-samples.tsv"):
                paths.add(str(trace_root / filename))
    require(1 <= len(paths) <= 16_384,
            "strict ProbeV2 identity path map exceeds its finite entry limit")
    entries = []
    for raw_path in sorted(paths):
        path = Path(raw_path)
        try:
            info = path.lstat()
            require(path.resolve(strict=True) == path and not stat.S_ISLNK(info.st_mode) and
                    (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                    "strict ProbeV2 identity path traverses an alias or unsupported node")
        except OSError as error:
            raise PressurePairError(f"strict ProbeV2 evidence member is unavailable: {error}") from error
        entries.append({"origin": raw_path, "local": raw_path})
    return {"schema": "allocatbelt.application-pressure-evidence-path-map.v1",
            "entries": entries}


def _find_raw_path_pin(value: object, path: str) -> str | None:
    if type(value) is dict:
        if value.get("path") == path:
            for key in ("raw_sha256", "sha256"):
                candidate = value.get(key)
                if type(candidate) is str and re.fullmatch(r"[0-9a-f]{64}", candidate):
                    return candidate
        for child in value.values():
            found = _find_raw_path_pin(child, path)
            if found is not None:
                return found
    elif type(value) is list:
        for child in value:
            found = _find_raw_path_pin(child, path)
            if found is not None:
                return found
    return None


def _pair_member_origin_fact(
    index: int, member_value: dict[str, Any], pressure_reader: Any,
) -> dict[str, Any]:
    pressure_recipe_pin = member_value["pressure_recipe"]
    pressure_artifacts = member_value["pressure_artifacts"]
    pressure_run_path = Path(pressure_artifacts["directory"]) / "run.json"
    run, _run_raw, run_sha = read_json(
        pressure_run_path, f"strict pressure member[{index}] run", MAX_SMALL_BYTES,
        pressure_artifacts["pins"]["run"],
    )
    require(run_sha == pressure_artifacts["pins"]["run"],
            "strict pressure-pair worker run pin changed after replay")
    app_identity = member_value["application_identity"]
    app_key = {
        "pid": uint(app_identity["pid"], "strict pair APP PID", positive=True,
                    maximum=(1 << 31) - 1),
        "start_ticks": uint(app_identity["start_ticks"], "strict pair APP start ticks", positive=True),
    }
    proof, _proof_raw, proof_sha = read_json(
        Path(pressure_artifacts["proof"]["path"]), f"strict pressure member[{index}] proof",
        MAX_SMALL_BYTES, pressure_artifacts["proof"]["raw_sha256"],
    )
    require(proof_sha == pressure_artifacts["proof"]["raw_sha256"] and
            proof["application_process"]["pid"] == app_key["pid"] and
            proof["application_process"]["start_ticks"] == app_key["start_ticks"],
            "strict pressure proof differs from the exact normal APP identity")
    worker_values = pressure_artifacts["worker_sessions"]
    require(type(worker_values) is list and len(worker_values) == len(run["worker_cleanup"]),
            "strict pressure worker session set differs from its final cleanup")
    workers = []
    for worker_value in worker_values:
        worker = exact(worker_value, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id"},
                       "strict pressure worker identity")
        workers.append({key: worker[key] for key in (
            "role", "cpu", "pid", "start_ticks", "pgid", "session_id",
        )})
    expected_workers = {
        (record["role"], record["cpu"], record["pid"], record["start_ticks"],
         record["pgid"], record["session_id"])
        for record in run["worker_cleanup"]
    }
    require({(worker["role"], worker["cpu"], worker["pid"], worker["start_ticks"],
              worker["pgid"], worker["session_id"]) for worker in workers} == expected_workers,
            "strict pair host worker identities differ from the pressure run cleanup rows")
    origin_absence = []
    identities = [app_key, *(
        {"pid": worker["pid"], "start_ticks": worker["start_ticks"]} for worker in workers
    )]
    for identity in identities:
        pid = uint(identity["pid"], "strict pair absent PID", positive=True,
                   maximum=(1 << 31) - 1)
        ticks = uint(identity["start_ticks"], "strict pair absent start ticks", positive=True)
        require(not pressure_reader._pid_same(pid, ticks),
                "origin pressure PID/start identity remains alive after strict replay")
        origin_absence.append({
            "pid": pid, "start_ticks": ticks, "absent": True,
            "observed_monotonic_ns": time.monotonic_ns(),
        })
    pressure_recipe, _pressure_recipe_raw, pressure_recipe_sha = read_json(
        Path(pressure_recipe_pin["path"]), f"strict pressure member[{index}] recipe",
        MAX_RECIPE_BYTES, pressure_recipe_pin["raw_sha256"],
    )
    storage = {
        "application_tmpdir_path": pressure_recipe["process"]["application_tmpdir_path"],
        "pressure_scratch_path": pressure_recipe["storage"]["pressure_scratch_path"],
        "application_mount_id": pressure_recipe["storage"]["application_mount_id"],
        "storage_sha256": digest_object({
            "application_storage": pressure_recipe["host"]["application_storage"],
            "pressure_scratch": pressure_recipe["host"]["pressure_scratch"],
            "storage": pressure_recipe["storage"],
        }),
    }
    return {
        "ordinal": index,
        "descriptor": member_value["descriptor"],
        "identity": member_value["identity"],
        "pressure_recipe": {
            "path": pressure_recipe_pin["path"],
            "raw_sha256": pressure_recipe_sha,
            "semantic_sha256": pressure_recipe_pin["semantic_sha256"],
            "condition_sha256": pressure_recipe_pin["condition_sha256"],
        },
        "pressure_artifacts": pressure_artifacts,
        "application_identity": app_key,
        "worker_identities": workers,
        "pid_absence": origin_absence,
        "application_launch_attestation": member_value["application_launch_attestation"],
        "application_cleanup": member_value["application_cleanup"],
        "supervision_receipt": member_value["supervision_receipt"],
        "storage_proof": storage,
    }


def _write_pressure_host_receipt(path_value: object, body: dict[str, Any]) -> dict[str, str]:
    path = Path(text(path_value, "pressure-pair host receipt output path", 4096))
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)),
            "pressure-pair host receipt output path must be normalized and absolute")
    try:
        parent = path.parent.lstat()
        require(stat.S_ISDIR(parent.st_mode) and not stat.S_ISLNK(parent.st_mode) and
                parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700 and
                path.parent.resolve(strict=True) == path.parent,
                "pressure-pair host receipt parent must be a real owned mode-0700 directory")
    except OSError as error:
        raise PressurePairError(f"pressure-pair host receipt parent is unavailable: {error}") from error
    receipt_keys = {
        "schema", "campaign_id", "host_id", "job", "recipe", "readback",
        "source_manifest", "spec", "plan", "execution_manifest", "authorization_id",
        "journal_head", "registration_head", "observed_host", "origin_facts",
        "dependency_pins", "member_facts", "strict_result_sha256",
        "qualification_eligible", "execution_ready",
    }
    exact(body, receipt_keys, "pressure-pair strict host receipt body")
    require(body["schema"] == HOST_VERIFICATION_SCHEMA and
            body["qualification_eligible"] is False and body["execution_ready"] is False and
            type(body["member_facts"]) is list and len(body["member_facts"]) == 2,
            "pressure-pair strict host receipt body is incomplete or claims readiness")
    semantic_sha = digest_object(body)
    raw = canonical_bytes({**body, "receipt_sha256": semantic_sha})
    raw_sha = write_new(path, raw, "pressure-pair strict host-verification receipt", 0o600)
    written, written_raw, written_sha = read_json(path, "written pressure-pair host receipt", 16 * 1024 * 1024, raw_sha)
    info = path.lstat()
    require(written_raw == raw and written_sha == raw_sha and
            written.get("receipt_sha256") == semantic_sha and
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(),
            "new pressure-pair host receipt failed its exact raw/semantic post-write check")
    return {"path": str(path), "raw_sha256": raw_sha,
            "receipt_sha256": semantic_sha}


def verify_pressure_pair_with_host_receipt(
    recipe_pin: object,
    output_root: object,
    readback_pin: object,
    host_receipt_path: object,
    *, chronology_module: Any,
    lock: Any,
    authorization_context: dict[str, Any],
) -> dict[str, Any]:
    """Strictly replay one completed pair on its origin host and pin host facts.

    This additive API preserves the existing strict v1 pair verifier. The new
    receipt is emitted only after full pair replay, live environment/storage
    checks and post-cleanup PID/start absence checks succeed.
    """
    recipe_file = exact(recipe_pin, {"path", "raw_sha256"}, "strict pressure-pair recipe pin")
    recipe_path = Path(text(recipe_file["path"], "strict pressure-pair recipe path", 4096))
    require(recipe_path.is_absolute(), "strict pressure-pair recipe path must be absolute")
    recipe_raw, recipe_raw_sha, _recipe_info = read_stable(recipe_path, "strict pressure-pair recipe", MAX_RECIPE_BYTES)
    require(recipe_raw_sha == digest(recipe_file["raw_sha256"], "strict pressure-pair recipe raw SHA-256"),
            "strict pressure-pair recipe raw bytes differ from their pin")
    try:
        recipe_value = json.loads(recipe_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PressurePairError(f"strict pressure-pair recipe is invalid JSON: {error}") from error
    require(type(recipe_value) is dict and recipe_raw == canonical_bytes(recipe_value),
            "strict pressure-pair recipe is not canonical JSON")
    recipe = _validate_recipe_shape(recipe_value)
    require(recipe["schema"] == RECIPE_SCHEMA_V2,
            "strict Source5 host capture requires pressure-pair recipe v2 with prospective ProbeV2 budgets")
    output_path = Path(text(output_root, "strict pressure-pair output root", 4096))
    receipt_output = Path(text(host_receipt_path, "strict pressure-pair host receipt output", 4096))
    for immutable_root in (output_path, Path(recipe["source_manifest"]["source_root"]),
                           Path(recipe["spec"]["artifact"]["path"]).parent):
        try:
            receipt_output.relative_to(immutable_root)
            inside_immutable = True
        except ValueError:
            inside_immutable = False
        require(not inside_immutable,
                "strict pressure-pair host receipt must be outside immutable evidence roots")
    readback = exact(readback_pin, {"path", "raw_sha256"}, "strict pressure-pair readback pin")
    readback_path = Path(text(readback["path"], "strict pressure-pair readback path", 4096))
    require(readback_path == output_path / PAIR_READBACK_FILE,
            "strict pressure-pair readback is outside its frozen output layout")
    readback_value, _readback_raw, readback_sha = read_json(
        readback_path, "strict pressure-pair readback", recipe["artifact_budgets"]["pair_sidecar_bytes"],
        digest(readback["raw_sha256"], "strict pressure-pair readback raw SHA-256"),
    )
    inputs = _load_campaign_inputs(recipe, output_path)
    modules = _load_validators(recipe, inputs, chronology_module)
    require(type(authorization_context) is dict and
            authorization_context.get("phase") == "pressure" and
            authorization_context.get("job") == inputs["job"],
            "strict host receipt requires the exact active Source5 pressure authorization")
    authorization_id = token(authorization_context.get("authorization_id"),
                             "strict Source5 pressure authorization ID")
    origin_overlay = _verify_execution_overlay(
        recipe, inputs, modules["campaign_chronology"], lock=lock,
        authorization_context=authorization_context,
    )
    pressure_recipes, _pressure_recipe_summaries = _read_pressure_pair_member_recipes(
        recipe, inputs, modules["pressure_validator"],
    )
    origin_observed_pin, origin_observed_host = _verify_pair_observed_host_pin(
        origin_overlay["value"]["chronology"]["observed_host"], inputs["host_id"],
        pressure_recipes, modules["pressure_validator"],
    )
    before = _capture_pair_origin_facts(inputs["host_id"], origin_observed_host,
                                        pressure_recipes, modules["pressure_driver"])
    strict_result = validate_pressure_pair_artifacts(
        recipe, output_path, readback_path, readback_sha,
        chronology_module=chronology_module, lock=lock,
        authorization_context=authorization_context,
    )
    after = _capture_pair_origin_facts(inputs["host_id"], origin_observed_host,
                                       pressure_recipes, modules["pressure_driver"])
    require(before == after,
            "origin pressure-pair host/kernel/affinity/network facts changed during strict replay")
    current_observed_pin, current_observed_host = _verify_pair_observed_host_pin(
        origin_observed_pin, inputs["host_id"], pressure_recipes,
        modules["pressure_validator"],
    )
    require(current_observed_pin == origin_observed_pin and
            current_observed_host == origin_observed_host,
            "strict Source5 observed-host bytes changed during pressure-pair replay")
    overlay_ref = {"path": origin_overlay["path"],
                   "raw_sha256": origin_overlay["raw_sha256"]}
    overlay_after, _overlay_after_raw, _overlay_after_sha = read_json(
        Path(overlay_ref["path"]), "strict Source5 execution overlay after replay",
        MAX_RECIPE_BYTES, overlay_ref["raw_sha256"],
    )
    require(overlay_after == origin_overlay["value"],
            "strict Source5 execution overlay changed during pressure-pair replay")
    source_v5 = inputs["source"]
    source_entry = _inventory_record(
        source_v5, "scripts/application-pressure-pair.py",
        "pressure-pair runner",
    )
    helper_pin = _artifact_reference(authorization_context.get("helper_input"),
                                     "locked Source5 helper input")
    helper_input, _helper_raw, helper_input_sha = read_json(
        Path(helper_pin["path"]), "locked Source5 pressure helper input",
        MAX_PLAN_BYTES, helper_pin["raw_sha256"],
    )
    exact(helper_input, {
        "schema", "scope", "campaign_id", "host_id", "phase", "job_index", "job",
        "job_sha256", "members", "helper", "payload", "prerequisites",
        "outer_deadline_seconds", "effective_timeout_seconds",
        "input_snapshot_sha256", "qualification_eligible",
    }, "locked Source5 pressure helper input")
    helper_body = {key: value for key, value in helper_input.items()
                   if key not in {"input_snapshot_sha256", "qualification_eligible"}}
    expected_outer_deadline = inputs["spec"]["deadlines"]["outer_seconds"]
    expected_members = [member["descriptor"] for member in recipe["members"]]
    require(helper_input["schema"] == SOURCE5_HELPER_INPUT_SCHEMA and
            helper_input["scope"] == "final_frozen" and
            helper_input["phase"] == "pressure" and
            helper_input["campaign_id"] == inputs["spec"]["campaign_id"] and
            helper_input["host_id"] == inputs["host_id"] and
            helper_input["job_index"] == inputs["job_index"] and
            helper_input["job"] == inputs["job"] and
            helper_input["job_sha256"] == sha256_bytes(canonical_bytes(inputs["job"])) and
            helper_input["members"] == expected_members and
            helper_input["outer_deadline_seconds"] == expected_outer_deadline and
            helper_input["effective_timeout_seconds"] == expected_outer_deadline and
            helper_input["qualification_eligible"] is False and
            helper_input["input_snapshot_sha256"] == sha256_bytes(canonical_bytes(helper_body)),
            "locked Source5 helper input is not the exact prospective pressure generation")
    helper_payload = exact(helper_input["payload"], {
        "schema", "recipe_pin", "output_root", "probe_capture_bundle",
    }, "locked Source5 pressure helper payload v2")
    require(helper_payload["schema"] == SOURCE5_PRESSURE_HELPER_PAYLOAD_SCHEMA_V2 and
            helper_payload["recipe_pin"] == recipe_file and
            helper_payload["output_root"] == str(output_path),
            "locked Source5 helper payload differs from the exact recipe/output generation")
    helper_binding = exact(helper_input["helper"], {"path", "sha256", "entrypoint"},
                           "locked Source5 pressure helper binding")
    require(helper_binding == {
        "path": "scripts/application-pressure-pair.py",
        "sha256": source_entry["sha256"],
        "entrypoint": "run_pressure_pair_locked",
    }, "locked Source5 pressure helper binding differs from the pinned pressure-pair entrypoint")
    helper_module = exact(authorization_context.get("helper_module"), {
        "path", "sha256", "size", "mode", "kind",
    }, "locked Source5 pressure helper module")
    require(helper_module["path"] == "scripts/application-pressure-pair.py" and
            helper_module["sha256"] == source_entry["sha256"] and
            helper_module["kind"] == "file" and helper_module["mode"] in {"100644", "100755"} and
            helper_module["size"] == source_entry["size"],
            "locked Source5 helper module differs from the active typed pressure-pair file")
    capture_bundle = exact(helper_payload["probe_capture_bundle"], {"schema", "members"},
                           "locked Source5 ProbeV2 capture bundle")
    require(capture_bundle["schema"] == SOURCE5_PROBE_CAPTURE_BUNDLE_SCHEMA_V1 and
            type(capture_bundle["members"]) is list and len(capture_bundle["members"]) == 2,
            "locked Source5 ProbeV2 capture bundle is missing its exact two members")
    capture_rows = []
    for index, capture_value in enumerate(capture_bundle["members"]):
        capture_row = exact(capture_value, {
            "ordinal", "construction_probe", "capture_receipt", "capacity_bundle",
        }, f"locked Source5 ProbeV2 capture member[{index}]")
        require(capture_row["ordinal"] == index and
                capture_row["construction_probe"] == recipe["members"][index]["construction_probe"],
                "locked ProbeV2 capture member differs from its original ordered construction probe")
        capture_pin = exact(capture_row["capture_receipt"], {
            "path", "raw_sha256", "receipt_sha256",
        }, f"locked Source5 ProbeV2 capture receipt[{index}]")
        capture_path = Path(text(
            capture_pin["path"],
            f"locked Source5 ProbeV2 capture receipt[{index}] path", 4096,
        ))
        require(capture_path.is_absolute() and str(capture_path) == os.path.normpath(str(capture_path)),
                f"locked Source5 ProbeV2 capture receipt[{index}] path is not normalized and absolute")
        digest(capture_pin["raw_sha256"], f"locked Source5 ProbeV2 receipt[{index}] raw SHA-256")
        digest(capture_pin["receipt_sha256"], f"locked Source5 ProbeV2 receipt[{index}] semantic SHA-256")
        expected_capacity_bundle = {
            name: {"path": recipe["capacity_bundle"][name]["path"],
                   "raw_sha256": recipe["capacity_bundle"][name]["raw_sha256"]}
            for name in ("request", "artifact", "receipt")
        }
        capacity_bundle = exact(capture_row["capacity_bundle"],
                                {"request", "artifact", "receipt"},
                                f"locked ProbeV2 capacity bundle[{index}]")
        for name, pin_value in capacity_bundle.items():
            exact(pin_value, {"path", "raw_sha256"},
                  f"locked ProbeV2 capacity {name}[{index}]")
        require(capacity_bundle == expected_capacity_bundle,
                "locked ProbeV2 capture changed the exact prepared capacity producer bundle")
        capture_rows.append(capture_row)
    feedback_module = modules["feedback_validator"]
    for index, capture_row in enumerate(capture_rows):
        _verify_probe_capture_budget_receipt(
            feedback_module, capture_row["capture_receipt"], recipe["probe_capture"], index,
        )
    source_manifest_pin = {
        "path": str(inputs["manifest_path"]),
        "raw_sha256": inputs["manifest_raw_sha256"],
    }
    capacity_bundle = {
        name: {"path": recipe["capacity_bundle"][name]["path"],
               "raw_sha256": recipe["capacity_bundle"][name]["raw_sha256"]}
        for name in ("request", "artifact", "receipt")
    }
    for index, capture_row in enumerate(capture_rows):
        member = recipe["members"][index]
        policy_value, _policy_raw, _policy_sha = read_json(
            Path(member["composition"]["policy"]["path"]),
            f"strict pressure member[{index}] resolved feedback policy",
            MAX_SMALL_BYTES, member["composition"]["policy"]["raw_sha256"],
        )
        require(type(policy_value.get("policy")) is dict,
                f"strict pressure member[{index}] resolved policy has no numeric policy body")
        capture_paths = _strict_probe_capture_identity_path_map(
            inputs["source"], inputs["source_root"], source_manifest_pin,
            capture_row["construction_probe"], capacity_bundle,
            capture_row["capture_receipt"],
        )
        replay_context = {
            "schema": feedback_module.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
            "evidence_path_map": capture_paths,
            "probe_capture_pin": capture_row["capture_receipt"],
            "capacity_bundle": capacity_bundle,
        }
        try:
            replayed_probe_sha = feedback_module.validate_calibrated_construction_probe_v2_offline(
                capture_row["construction_probe"], source_manifest_pin,
                capacity_bundle["artifact"], member["identity"],
                replay_context=replay_context,
                expected_policy=policy_value["policy"],
            )
        except Exception as error:
            raise PressurePairError(
                f"SourceV5-pinned feedback reader rejected strict ProbeV2 capture[{index}]: "
                f"{type(error).__name__}: {error}"
            ) from error
        require(replayed_probe_sha == capture_row["construction_probe"]["raw_sha256"],
                f"strict ProbeV2 capture[{index}] replay changed its original probe bytes")
    sidecar, _sidecar_raw, sidecar_sha = read_json(
        readback_path, "strict pressure-pair readback after replay",
        recipe["artifact_budgets"]["pair_sidecar_bytes"], readback_sha,
    )
    require(sidecar_sha == readback_sha and sidecar == readback_value,
            "pressure-pair readback changed during strict origin verification")
    _current_runner_raw, current_runner_sha, _runner_info = read_stable(
        Path(__file__).resolve(), "strict pressure-pair runner", MAX_SOURCE_BYTES,
    )
    require(source_entry["sha256"] == current_runner_sha,
            "strict pressure-pair runner bytes differ from the SourceV5 inventory")
    dependency_pins = {
        name: {"path": pin["path"], "raw_sha256": pin["sha256"]}
        for name, pin in recipe["validators"].items()
    }
    harness = source_v5["qualification_harness"]
    driver_pin = exact(harness["pressure_driver"], {"path", "sha256"},
                       "strict SourceV5 pressure driver pin")
    inventory_module, inventory_pin = _pinned_source_module(
        source_v5, inputs["source_root"], "scripts/application-source-inventory.py",
        "strict SourceV5 inventory", MAX_SOURCE_BYTES,
    )
    del inventory_module
    fixed_entry = _inventory_record(source_v5, "scripts/application-fixed-pair.py", "fixed-pair verifier")
    dependency_pins.update({
        "pressure_pair": {"path": "scripts/application-pressure-pair.py", "raw_sha256": current_runner_sha},
        "pressure_driver": {"path": driver_pin["path"], "raw_sha256": driver_pin["sha256"]},
        "source_inventory": {"path": "scripts/application-source-inventory.py", "raw_sha256": inventory_pin["sha256"]},
        "fixed_pair": {"path": "scripts/application-fixed-pair.py", "raw_sha256": fixed_entry["sha256"]},
        "source5_helper_input": {"path": helper_pin["path"], "raw_sha256": helper_input_sha},
        "source5_helper_module": {"path": helper_module["path"], "raw_sha256": helper_module["sha256"]},
    })
    overlay = origin_overlay["value"]
    chronology = exact(overlay["chronology"], {
        "observed_host", "output_root", "capacity_output_root", "journal_head",
        "journal_record_count", "registration_head", "dispatch_event_count",
    }, "strict Source5 execution chronology")
    observed_pin = origin_observed_pin
    observed_sha = observed_pin["raw_sha256"]
    member_facts = []
    for index, sidecar_member in enumerate(sidecar["members"]):
        member_fact = _pair_member_origin_fact(
            index, sidecar_member, modules["pressure_validator"],
        )
        member_fact["probe_capture"] = {
            "construction_probe": capture_rows[index]["construction_probe"],
            "capture_receipt": capture_rows[index]["capture_receipt"],
            "capacity_bundle": capture_rows[index]["capacity_bundle"],
        }
        member_facts.append(member_fact)
    receipt_body = {
        "schema": HOST_VERIFICATION_SCHEMA,
        "campaign_id": inputs["spec"]["campaign_id"],
        "host_id": inputs["host_id"],
        "job": {
            "run_id": inputs["job"]["run_id"],
            "ordinal": inputs["job"]["ordinal"],
            "job_index": inputs["job_index"],
            "semantic_sha256": sha256_bytes(canonical_bytes(inputs["job"])),
        },
        "recipe": {
            "path": str(recipe_path), "raw_sha256": recipe_raw_sha,
            "semantic_sha256": digest_object(recipe_value),
        },
        "readback": {
            "path": str(readback_path), "raw_sha256": readback_sha,
            "semantic_sha256": sidecar["readback_sha256"],
        },
        "source_manifest": {
            "path": str(inputs["manifest_path"]), "raw_sha256": inputs["manifest_raw_sha256"],
            "semantic_sha256": source_v5["manifest_sha256"],
            "source_tree_sha256": source_v5["source"]["source_tree_sha256"],
        },
        "spec": {
            "path": str(inputs["spec_path"]), "raw_sha256": inputs["spec_raw_sha256"],
            "semantic_sha256": recipe["spec"]["semantic_sha256"],
        },
        "plan": {
            "path": str(inputs["plan_path"]), "raw_sha256": inputs["plan_raw_sha256"],
            "semantic_sha256": recipe["plan"]["semantic_sha256"],
        },
        "execution_manifest": {
            "path": overlay_ref["path"], "raw_sha256": overlay_ref["raw_sha256"],
            "semantic_sha256": overlay["overlay_sha256"],
        },
        "authorization_id": authorization_id,
        "journal_head": chronology["journal_head"],
        "registration_head": chronology["registration_head"],
        "observed_host": {"path": observed_pin["path"], "raw_sha256": observed_sha},
        "origin_facts": {
            "schema": ORIGIN_FACTS_SCHEMA,
            "host_id": inputs["host_id"],
            "observed_host_raw_sha256": observed_sha,
            "before": before,
            "after": after,
            "storage_sha256": digest_object([
                item["storage_proof"]["storage_sha256"] for item in member_facts
            ]),
        },
        "dependency_pins": dependency_pins,
        "member_facts": member_facts,
        "strict_result_sha256": digest_object(strict_result),
        "qualification_eligible": False,
        "execution_ready": False,
    }
    origin_body = receipt_body["origin_facts"]
    receipt_body["origin_facts"] = {
        **origin_body, "origin_facts_sha256": digest_object(origin_body),
    }
    return _write_pressure_host_receipt(host_receipt_path, receipt_body)



def _preflight_pair_json_path_closure(
    documents: list[dict[str, Any]], mapped: set[str], directories: set[str],
) -> None:
    """Check references declared by the already-pinned top-level documents.

    File suffixes do not define evidence roles: arbitrary application/source
    payloads that happen to end in ``.json`` remain opaque bytes here.
    """
    for document in documents:
        paths = _pair_absolute_paths(document)
        for raw_path in paths:
            require(raw_path in mapped,
                    f"offline pressure evidence map omits an exact nested original dependency: {raw_path}")


def validate_pressure_pair_artifacts_offline(
    recipe_pin: object,
    output_root: object,
    readback_pin: object,
    host_verification_pin: object,
    evidence_path_map: object,
    *, source5_journal_context: object | None = None,
) -> dict[str, Any]:
    """Replay peer pressure members from raw bytes and a strict host receipt.

    This function intentionally does not manufacture a partial pair result.
    The Source5 journal context is mandatory and is replayed from its exact
    captured role map before any captured module is compiled.
    """
    source5_context = exact(source5_journal_context, {
        "schema", "request", "captured_evidence", "job_record_pin",
    }, "offline Source5 pressure journal context")
    source5_preflight = _source5_preflight_capture_context(
        source5_context, evidence_path_map,
    )
    request = source5_preflight["request"]
    capture_rows = source5_preflight["capture_rows"]
    mapped = source5_preflight["mapped"]
    dirs = source5_preflight["directories"]
    path_map = source5_preflight["path_map"]
    source_symlink_snapshots = source5_preflight["source_symlink_snapshots"]
    recipe_file = exact(recipe_pin, {"path", "raw_sha256"}, "offline pressure-pair recipe pin")
    recipe_path = Path(text(recipe_file["path"], "offline pressure-pair recipe path", 4096))
    require(recipe_path.is_absolute(), "offline pressure-pair recipe path must be absolute")
    recipe_raw, recipe_sha, _recipe_info = read_stable(recipe_path, "offline pressure-pair recipe", MAX_RECIPE_BYTES)
    require(recipe_sha == digest(recipe_file["raw_sha256"], "offline pressure-pair recipe raw SHA-256"),
            "offline pressure-pair recipe raw bytes differ from their pin")
    try:
        recipe_value = json.loads(recipe_raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PressurePairError(f"offline pressure-pair recipe is invalid JSON: {error}") from error
    require(type(recipe_value) is dict and recipe_raw == canonical_bytes(recipe_value),
            "offline pressure-pair recipe is not canonical JSON")
    recipe = _validate_recipe_shape(recipe_value)
    require(recipe["schema"] == RECIPE_SCHEMA_V2,
            "offline Source5 pressure-pair replay requires pressure-pair recipe v2")
    readback_file = exact(readback_pin, {"path", "raw_sha256"}, "offline pressure-pair readback pin")
    readback_path = Path(text(readback_file["path"], "offline pressure-pair readback path", 4096))
    output_path = Path(text(output_root, "offline pressure-pair output root", 4096))
    require(readback_path == output_path / PAIR_READBACK_FILE,
            "offline pressure-pair readback is outside its original output layout")
    source_root = safe_root(recipe["source_manifest"]["source_root"], "offline pressure SourceV5 root")
    require(str(source_root) == source5_preflight["source_root"],
            "offline pressure recipe SourceRoot differs from the complete captured Source5 closure")
    source_manifest_path = Path(recipe["source_manifest"]["artifact"]["path"])
    require(str(source_manifest_path) in mapped,
            "offline pressure evidence map omits the pinned selected Source5 manifest")
    offline_calibration_context = {
        "schema": OFFLINE_CALIBRATION_CONTEXT_SCHEMA,
        "source_root": str(source_root),
        "evidence_path_map": path_map,
    }
    receipt_pin = exact(host_verification_pin, {"path", "raw_sha256", "receipt_sha256"},
                        "offline pressure-pair host receipt pin")
    for path in (str(recipe_path), str(readback_path), str(source_manifest_path), receipt_pin["path"]):
        require(path in mapped,
                f"offline pressure evidence map omits a top-level pinned input: {path}")
    # Parse all top-level immutable JSON pins and establish the complete typed
    # source membership before any captured SourceV5 module is compiled.
    for raw_path in _pair_absolute_paths(recipe_value):
        require(raw_path in mapped,
                f"offline pressure evidence map omits an exact nested recipe dependency: {raw_path}")
    require(str(source_root) in dirs, "offline pressure map omits its source-root directory")
    source_manifest, source_manifest_raw, source_raw_sha = read_json(
        source_manifest_path, "offline pressure SourceV5 manifest", MAX_MANIFEST_BYTES,
        recipe["source_manifest"]["artifact"]["raw_sha256"],
    )
    _semantic_manifest(
        source_manifest, source_manifest_raw,
        recipe["source_manifest"]["semantic_sha256"],
        "offline pressure SourceV5 manifest",
    )
    require(source_raw_sha == recipe["source_manifest"]["artifact"]["raw_sha256"],
            "offline pressure SourceV5 manifest raw pin differs")
    normalized_source, source_inventory = _source5_source_inventory(
        source_manifest, "offline selected SourceV5 manifest",
    )
    source_members: set[str] = {
        str(source_root.joinpath(*PurePosixPath(item["path"]).parts))
        for item in normalized_source if item["kind"] == "file"
    }
    symlink_members = {
        str(source_root.joinpath(*PurePosixPath(item["path"]).parts))
        for item in normalized_source if item["kind"] == "symlink"
    }
    artifact_members = {
        str(source_root.joinpath(*PurePosixPath(relative).parts))
        for relative, _role, _raw_sha in _source5_manifest_artifacts(
            source_manifest, source_inventory, "offline selected SourceV5 manifest",
        )
    }
    require(source_members | artifact_members <= mapped and
            symlink_members.isdisjoint(mapped),
            "offline pressure map does not preserve the exact regular/source-artifact closure and data-only symlink boundary")
    spec_pin = recipe["spec"]["artifact"]
    plan_pin = recipe["plan"]["artifact"]
    for label, pin_value in (("spec", spec_pin), ("plan", plan_pin)):
        pin = exact(pin_value, {"path", "raw_sha256"}, f"offline pressure {label} pin")
        require(pin["path"] in mapped, f"offline pressure evidence map omits original Source5 {label}")
    spec_path = Path(spec_pin["path"])
    plan_path = Path(plan_pin["path"])
    spec, _spec_raw, _spec_sha = read_json(spec_path, "offline original Source5 SpecV3", MAX_SPEC_BYTES, spec_pin["raw_sha256"])
    plan, _plan_raw, _plan_sha = read_json(plan_path, "offline original Source5 PlanV3", MAX_PLAN_BYTES, plan_pin["raw_sha256"])
    for document in (spec, plan):
        for raw_path in _pair_absolute_paths(document):
            require(raw_path in mapped,
                    f"offline pressure evidence map omits exact original spec/plan dependency: {raw_path}")
    require(type(spec.get("source_manifests")) is list and len(spec["source_manifests"]) == 3,
            "offline pressure replay requires all three original SourceV5 host manifests")
    for index, source_ref_value in enumerate(spec["source_manifests"]):
        source_ref = exact(source_ref_value, {"host_id", "relative_path", "sha256"},
                           f"offline original SourceV5 peer manifest[{index}]")
        peer_host_id = token(source_ref["host_id"],
                             f"offline original SourceV5 peer host[{index}]")
        peer_path = safe_child(spec_path.parent, source_ref["relative_path"],
                               f"offline original SourceV5 peer[{index}]")
        require(str(peer_path) in mapped,
                f"offline pressure evidence map omits original host manifest: {peer_path}")
        peer_manifest, peer_raw, _peer_raw_sha = read_json(
            peer_path, f"offline original SourceV5 peer manifest[{index}]",
            MAX_MANIFEST_BYTES,
        )
        _semantic_manifest(peer_manifest, peer_raw, source_ref["sha256"],
                           f"offline original SourceV5 peer manifest[{index}]")
        captured_peer = source5_preflight["source_docs"].get(peer_host_id)
        captured_peer_rows = [row for row in capture_rows.values()
                              if row["role"] == "source_manifest" and
                              row["host_id"] == peer_host_id]
        require(len(captured_peer_rows) == 1 and
                captured_peer_rows[0]["origin_path"] == str(peer_path) and
                captured_peer is not None and peer_manifest == captured_peer and
                source_ref["sha256"] == captured_peer["manifest_sha256"],
                "offline peer manifest differs from its complete captured source/artifact closure")
    sidecar, _sidecar_raw, sidecar_sha = read_json(
        readback_path, "offline pressure-pair readback", recipe["artifact_budgets"]["pair_sidecar_bytes"],
        digest(readback_file["raw_sha256"], "offline pressure-pair readback raw SHA-256"),
    )
    for raw_path in _pair_absolute_paths(sidecar):
        require(raw_path in mapped,
                f"offline pressure evidence map omits an exact readback dependency: {raw_path}")
    host_raw, host_raw_sha, _host_info = read_stable(
        Path(receipt_pin["path"]), "offline strict pressure-pair host receipt", 16 * 1024 * 1024,
    )
    require(host_raw_sha == digest(receipt_pin["raw_sha256"], "offline host receipt raw SHA-256") and
            host_raw == canonical_bytes(json.loads(host_raw.decode("utf-8"))),
            "offline strict pressure-pair host receipt raw bytes are malformed")
    host_document = json.loads(host_raw.decode("utf-8"))
    require(type(host_document) is dict and host_document.get("schema") == HOST_VERIFICATION_SCHEMA and
            host_document.get("qualification_eligible") is False and host_document.get("execution_ready") is False,
            "offline strict pressure-pair host receipt has the wrong schema or readiness fields")
    exact(host_document, {
        "schema", "campaign_id", "host_id", "job", "recipe", "readback",
        "source_manifest", "spec", "plan", "execution_manifest", "authorization_id",
        "journal_head", "registration_head", "observed_host", "origin_facts",
        "dependency_pins", "member_facts", "strict_result_sha256",
        "qualification_eligible", "execution_ready", "receipt_sha256",
    }, "offline strict pressure-pair host receipt")
    exact(host_document["dependency_pins"], {
        "campaign_controller", "campaign_chronology", "feedback_composition",
        "feedback_validator", "pressure_validator", "soak_supervisor",
        "capacity_producer", "pressure_pair", "pressure_driver",
        "source_inventory", "fixed_pair", "source5_helper_input",
        "source5_helper_module",
    }, "offline strict pressure-pair dependency pin map")
    for dependency_name, dependency_value in host_document["dependency_pins"].items():
        dependency = exact(dependency_value, {"path", "raw_sha256"},
                           f"offline pressure dependency {dependency_name}")
        text(dependency["path"], f"offline pressure dependency {dependency_name} path", 4096)
        digest(dependency["raw_sha256"],
               f"offline pressure dependency {dependency_name} raw SHA-256")
    host_body = {key: value for key, value in host_document.items() if key != "receipt_sha256"}
    require(host_document.get("receipt_sha256") == digest_object(host_body) == receipt_pin["receipt_sha256"],
            "offline strict pressure-pair host receipt semantic digest differs")
    for raw_path in _pair_absolute_paths(host_document):
        require(raw_path in mapped,
                f"offline pressure evidence map omits an exact host receipt dependency: {raw_path}")
    _preflight_pair_json_path_closure(
        [recipe_value, sidecar, host_document, source_manifest, spec, plan], mapped, dirs,
    )
    request_source = source5_preflight["request"]
    dispatcher_relative = SOURCE5_OFFLINE_DISPATCH_RELATIVE
    dispatcher_path = str(Path(source_root) / dispatcher_relative)
    dispatcher_capture = capture_rows.get(dispatcher_path)
    dispatcher_inventory = source5_preflight["selected_source"]["source"]["files"]
    dispatcher_records = [item for item in dispatcher_inventory
                          if item.get("path") == dispatcher_relative]
    require(dispatcher_capture is not None and
            dispatcher_capture["role"] == "typed_source_file" and
            dispatcher_capture["host_id"] == request_source["host_id"] and
            len(dispatcher_records) == 1 and
            dispatcher_records[0]["kind"] == "file" and
            dispatcher_capture["raw_sha256"] == dispatcher_records[0]["sha256"] and
            dispatcher_capture["byte_count"] == dispatcher_records[0]["size"],
            "captured Source5 dispatcher is not the exact preflighted regular source module")
    dispatcher_raw = _source5_capture_bytes(
        dispatcher_capture, MAX_SOURCE_BYTES,
        "selected captured Source5 offline dispatcher",
    )
    dispatcher_module = _load_module(
        dispatcher_raw, Path(dispatcher_path), "source5_offline_dispatch",
    )
    require(dispatcher_module.__file__ == dispatcher_path,
            "captured Source5 dispatcher was compiled under another original path")
    verify_prerequisites = getattr(
        dispatcher_module, "verify_source5_pressure_prerequisites_offline", None,
    )
    require(callable(verify_prerequisites) and
            verify_prerequisites.__code__.co_filename == dispatcher_path,
            "captured Source5 dispatcher lacks the exact prerequisite replay API")
    verified_source5_prerequisites = verify_prerequisites(
        request_source, source5_context["captured_evidence"],
        source5_context["job_record_pin"],
        recipe_pin={"path": str(recipe_path), "raw_sha256": recipe_sha},
        readback_pin={"path": str(readback_path), "raw_sha256": sidecar_sha},
        host_verification_pin=receipt_pin,
    )
    predecessor_replay = verified_source5_prerequisites["fixed_predecessor"]
    require(sidecar.get("fixed_predecessor") == {
                "record": predecessor_replay["job_record"],
                "receipt": predecessor_replay["receipt"],
                "receipt_value": predecessor_replay["receipt_value"],
            }, "pressure readback fixed predecessor differs from captured offline replay")
    _verify_source5_local_symlinks(rows=capture_rows,
                                   snapshots=source_symlink_snapshots)
    inputs = _load_campaign_inputs(recipe, output_path, offline_mapped_paths=mapped)
    host_receipt = host_document
    require(request_source["host_id"] == inputs["host_id"] and
            request_source["campaign_id"] == inputs["spec"]["campaign_id"] and
            request_source["source_root"] == str(inputs["source_root"]) and
            request_source["input_root"] == str(inputs["input_root"]),
            "offline pressure context differs from its original SourceV5 roots/host")
    expected_dependencies = {
        name: {"path": item["path"], "raw_sha256": item["sha256"]}
        for name, item in recipe["validators"].items()
    }
    for name, relative in (
        ("pressure_pair", "scripts/application-pressure-pair.py"),
        ("pressure_driver", "scripts/application-pressure-driver.py"),
        ("source_inventory", "scripts/application-source-inventory.py"),
        ("fixed_pair", "scripts/application-fixed-pair.py"),
    ):
        record = _inventory_record(inputs["source"], relative, f"offline {name} dependency")
        expected_dependencies[name] = {"path": relative, "raw_sha256": record["sha256"]}
    helper_pin = exact(host_receipt["dependency_pins"].get("source5_helper_input"),
                       {"path", "raw_sha256"},
                       "offline locked Source5 pressure helper-input dependency")
    if verified_source5_prerequisites is not None:
        require(helper_pin == verified_source5_prerequisites["helper_input"] and
                verified_source5_prerequisites["job"] == inputs["job"] and
                verified_source5_prerequisites["authorization_id"] ==
                    host_receipt["authorization_id"] and
                verified_source5_prerequisites["historical_head"] ==
                    host_receipt["journal_head"] and
                verified_source5_prerequisites["registration_head"] ==
                    host_receipt["registration_head"],
                "pressure origin receipt differs from captured Source5 authorization/predecessor ancestry")
    helper_module_record = _inventory_record(
        inputs["source"], "scripts/application-pressure-pair.py",
        "offline Source5 pressure helper module",
    )
    expected_dependencies.update({
        "source5_helper_input": helper_pin,
        "source5_helper_module": {
            "path": "scripts/application-pressure-pair.py",
            "raw_sha256": helper_module_record["sha256"],
        },
    })
    harness_driver = exact(inputs["source"]["qualification_harness"]["pressure_driver"],
                           {"path", "sha256"}, "offline SourceV5 pressure driver pin")
    require(expected_dependencies["pressure_driver"] == {
        "path": harness_driver["path"], "raw_sha256": harness_driver["sha256"],
    }, "offline pressure driver receipt pin differs from the SourceV5 harness")
    require(host_receipt["dependency_pins"] == expected_dependencies,
            "offline pressure host receipt dependency pins differ from the complete SourceV5 inventory")
    host_reader, host_reader_pin = _pinned_source_module(
        inputs["source"], inputs["source_root"], "scripts/application-pressure-readback.py",
        "offline pressure reader", MAX_SOURCE_BYTES,
    )
    require(host_reader_pin["sha256"] == recipe["validators"]["pressure_validator"]["sha256"],
            "offline pressure reader differs from the original SourceV5 validator pin")
    feedback_module, feedback_module_pin = _pinned_source_module(
        inputs["source"], inputs["source_root"], "scripts/application-feedback-readback.py",
        "offline feedback reader", MAX_SOURCE_BYTES,
    )
    require(feedback_module_pin["sha256"] == recipe["validators"]["feedback_validator"]["sha256"] ==
            host_document["dependency_pins"]["feedback_validator"]["raw_sha256"],
            "offline feedback reader differs from SourceV5/host receipt module pins")
    host_receipt, checked_host_raw_sha, _host_pin = host_reader._validate_pressure_pair_host_receipt(receipt_pin)
    require(checked_host_raw_sha == host_raw_sha and host_receipt == host_document,
            "offline pressure-pair host receipt changed during closed validation")
    require(verified_source5_prerequisites is not None,
            "offline pressure-pair replay is blocked: exact Source5 journal and fixed-predecessor context is required")
    overlay_pin = recipe["execution_overlay"]["artifact"]
    overlay, _overlay_raw, overlay_sha = read_json(
        Path(overlay_pin["path"]), "offline pressure execution overlay", MAX_RECIPE_BYTES,
        overlay_pin["raw_sha256"],
    )
    job = inputs["job"]
    require(
        host_receipt["campaign_id"] == inputs["spec"]["campaign_id"] and
        host_receipt["host_id"] == inputs["host_id"] and
        host_receipt["job"] == {
            "run_id": job["run_id"], "ordinal": job["ordinal"],
            "job_index": inputs["job_index"],
            "semantic_sha256": sha256_bytes(canonical_bytes(job)),
        } and host_receipt["recipe"] == {
            "path": str(recipe_path), "raw_sha256": recipe_sha,
            "semantic_sha256": digest_object(recipe_value),
        } and host_receipt["readback"] == {
            "path": str(readback_path), "raw_sha256": sidecar_sha,
            "semantic_sha256": sidecar["readback_sha256"],
        } and host_receipt["execution_manifest"] == {
            "path": overlay_pin["path"], "raw_sha256": overlay_pin["raw_sha256"],
            "semantic_sha256": overlay["overlay_sha256"],
        } and host_receipt["observed_host"] == overlay["chronology"]["observed_host"] and
        host_receipt["journal_head"] == overlay["chronology"]["journal_head"] and
        host_receipt["registration_head"] == overlay["chronology"]["registration_head"],
        "offline pressure-pair receipt differs from its exact original campaign/plan/overlay generation",
    )
    require(host_receipt["spec"] == {
        "path": str(inputs["spec_path"]), "raw_sha256": inputs["spec_raw_sha256"],
        "semantic_sha256": recipe["spec"]["semantic_sha256"],
    } and host_receipt["plan"] == {
        "path": str(inputs["plan_path"]), "raw_sha256": inputs["plan_raw_sha256"],
        "semantic_sha256": recipe["plan"]["semantic_sha256"],
    } and host_receipt["source_manifest"] == {
        "path": str(inputs["manifest_path"]), "raw_sha256": inputs["manifest_raw_sha256"],
        "semantic_sha256": inputs["source"]["manifest_sha256"],
        "source_tree_sha256": inputs["source"]["source"]["source_tree_sha256"],
    }, "offline pressure-pair receipt changed its original spec/plan/source generation")
    require(type(sidecar.get("members")) is list and len(sidecar["members"]) == 2,
            "offline pressure-pair readback lacks the exact two original members")
    helper_input, _helper_raw, helper_sha = read_json(
        Path(helper_pin["path"]), "offline locked Source5 pressure helper input",
        MAX_PLAN_BYTES, helper_pin["raw_sha256"],
    )
    exact(helper_input, {
        "schema", "scope", "campaign_id", "host_id", "phase", "job_index", "job",
        "job_sha256", "members", "helper", "payload", "prerequisites",
        "outer_deadline_seconds", "effective_timeout_seconds",
        "input_snapshot_sha256", "qualification_eligible",
    }, "offline locked Source5 pressure helper input")
    helper_body = {key: value for key, value in helper_input.items()
                   if key not in {"input_snapshot_sha256", "qualification_eligible"}}
    helper_payload = exact(helper_input["payload"], {
        "schema", "recipe_pin", "output_root", "probe_capture_bundle",
    }, "offline Source5 pressure helper payload v2")
    helper_binding = exact(helper_input["helper"], {"path", "sha256", "entrypoint"},
                           "offline Source5 pressure helper binding")
    expected_outer_deadline = inputs["spec"]["deadlines"]["outer_seconds"]
    expected_members = [member["descriptor"] for member in recipe["members"]]
    capture_bundle = exact(helper_payload["probe_capture_bundle"], {"schema", "members"},
                           "offline Source5 ProbeV2 capture bundle")
    require(helper_sha == helper_pin["raw_sha256"] and
            helper_input["schema"] == SOURCE5_HELPER_INPUT_SCHEMA and
            helper_input["scope"] == "final_frozen" and
            helper_input["phase"] == "pressure" and
            helper_input["campaign_id"] == inputs["spec"]["campaign_id"] and
            helper_input["host_id"] == inputs["host_id"] and
            helper_input["job_index"] == inputs["job_index"] and
            helper_input["job"] == inputs["job"] and
            helper_input["job_sha256"] == sha256_bytes(canonical_bytes(inputs["job"])) and
            helper_input["members"] == expected_members and
            helper_input["outer_deadline_seconds"] == expected_outer_deadline and
            helper_input["effective_timeout_seconds"] == expected_outer_deadline and
            helper_binding == {
                "path": "scripts/application-pressure-pair.py",
                "sha256": helper_module_record["sha256"],
                "entrypoint": "run_pressure_pair_locked",
            } and
            helper_input["qualification_eligible"] is False and
            helper_input["input_snapshot_sha256"] == sha256_bytes(canonical_bytes(helper_body)) and
            helper_payload["schema"] == SOURCE5_PRESSURE_HELPER_PAYLOAD_SCHEMA_V2 and
            helper_payload["recipe_pin"] == {"path": str(recipe_path), "raw_sha256": recipe_sha} and
            helper_payload["output_root"] == str(output_path) and
            capture_bundle["schema"] == SOURCE5_PROBE_CAPTURE_BUNDLE_SCHEMA_V1 and
            type(capture_bundle["members"]) is list and len(capture_bundle["members"]) == 2,
            "offline pair receipt is not bound to its exact locked helper-input/policy bundle")
    locked_capture_rows = capture_bundle["members"]
    for index, locked_row_value in enumerate(locked_capture_rows):
        locked_row = exact(locked_row_value, {
            "ordinal", "construction_probe", "capture_receipt", "capacity_bundle",
        }, f"offline locked ProbeV2 capture member[{index}]")
        host_capture = exact(host_receipt["member_facts"][index]["probe_capture"], {
            "construction_probe", "capture_receipt", "capacity_bundle",
        }, f"offline host ProbeV2 capture member[{index}]")
        require(locked_row == {"ordinal": index, **host_capture},
                "offline host receipt ProbeV2 capture differs from its exact locked helper bundle row")
    recipe_semantic = digest_object(recipe_value)
    require(host_receipt["recipe"]["semantic_sha256"] == recipe_semantic and
            host_receipt["strict_result_sha256"] != "0" * 64,
            "offline pressure-pair strict receipt does not bind the original recipe generation")
    validator_module = host_reader
    expected_reader = recipe["validators"]["pressure_validator"]
    require(expected_reader["path"] == "scripts/application-pressure-readback.py" and
            host_reader_pin["sha256"] == expected_reader["sha256"] ==
            host_receipt["dependency_pins"]["pressure_validator"]["raw_sha256"],
            "offline pressure reader differs from SourceV5/host receipt module pins")
    chronology_module, chronology_pin = _pinned_source_module(
        inputs["source"], inputs["source_root"],
        "scripts/application-campaign-chronology.py",
        "offline campaign chronology", MAX_SOURCE_BYTES,
    )
    require(chronology_pin["sha256"] ==
            recipe["validators"]["campaign_chronology"]["sha256"] ==
            host_receipt["dependency_pins"]["campaign_chronology"]["raw_sha256"],
            "offline chronology module differs from SourceV5/host receipt pins")
    modules = _load_validators(recipe, inputs, chronology_module)
    require(modules["pressure_validator"].__file__ == host_reader.__file__ and
            modules["feedback_validator"].__file__ == feedback_module.__file__,
            "offline strict readers differ from their selected SourceV5 modules")
    condition = _verify_pressure_condition(
        recipe, inputs, modules, offline_context=offline_calibration_context,
    )
    capacity = _verify_capacity_bundle(recipe, inputs, modules)
    policy_context = {
        "schema": "allocatbelt.application-pressure-policy-replay.v1",
        "evidence_path_map": evidence_path_map,
        "capture_members": [
            row["probe_capture"] for row in host_receipt["member_facts"]
        ],
    }
    shared = _verify_policy_resolutions(
        recipe, inputs, modules, output_path, capacity,
        offline_replay_context=policy_context,
    )
    members = _verify_members(
        recipe, inputs, condition, capacity, shared, modules, output_path,
        offline_origin=host_receipt["origin_facts"],
        offline_context=offline_calibration_context,
    )
    prepared = {
        "recipe": recipe, "output_root": output_path, "inputs": inputs,
        "modules": modules, "condition": condition,
        "capacity": capacity, "shared_policy": shared,
        "members": members,
    }
    process_pin = exact(sidecar.get("processes"), {"path", "raw_sha256"},
                        "offline pressure process-ledger pin")
    processes_path = output_path / PAIR_PROCESS_FILE
    require(process_pin["path"] == str(processes_path),
            "offline pressure process ledger path differs from its original output layout")
    process_rows = _read_process_ledger(
        processes_path, process_pin["raw_sha256"], modules["campaign_controller"],
    )
    require(len(process_rows) == 2 and len(sidecar["members"]) == 2,
            "offline pressure pair does not contain its exact two process/member rows")
    expected_order = [
        (item["descriptor"]["pair"], item["descriptor"]["executor"],
         item["descriptor"]["allocator"])
        for item in recipe["members"]
    ]
    require([(row["pair"], row["executor"], row["allocator"])
             for row in process_rows] == expected_order,
            "offline pressure process ledger changed its original member order")
    member_results = []
    seen_processes: set[tuple[int, int]] = set()
    for index, row in enumerate(sidecar["members"]):
        expected_host_row = host_receipt["member_facts"][index]
        original_member = recipe["members"][index]
        require(expected_host_row["ordinal"] == index and
                expected_host_row["descriptor"] == original_member["descriptor"] and
                expected_host_row["identity"] == original_member["identity"] and
                type(row["application_identity"]) is dict and
                row["application_identity"].get("pid") ==
                    expected_host_row["application_identity"]["pid"] and
                row["application_identity"].get("start_ticks") ==
                    expected_host_row["application_identity"]["start_ticks"] and
                row["application_launch_attestation"] ==
                    expected_host_row["application_launch_attestation"] and
                row["application_cleanup"] == expected_host_row["application_cleanup"] and
                row["supervision_receipt"] == expected_host_row["supervision_receipt"] and
                row["pressure_recipe"] == {
                    "path": original_member["pressure_recipe"]["artifact"]["path"],
                    "raw_sha256": original_member["pressure_recipe"]["artifact"]["raw_sha256"],
                    "semantic_sha256": original_member["pressure_recipe"]["semantic_sha256"],
                    "condition_sha256": original_member["pressure_recipe"]["condition_sha256"],
                } and expected_host_row["pressure_recipe"] == row["pressure_recipe"] and
                expected_host_row["pressure_artifacts"] == row["pressure_artifacts"],
                "offline pressure-pair host fact differs from its original ordered member")
        capture = exact(expected_host_row["probe_capture"], {
            "construction_probe", "capture_receipt", "capacity_bundle",
        }, "offline pressure-pair ProbeV2 capture binding")
        _verify_probe_capture_budget_receipt(
            feedback_module, capture["capture_receipt"], recipe["probe_capture"], index,
        )
        expected_bundle = {
            name: {"path": recipe["capacity_bundle"][name]["path"],
                   "raw_sha256": recipe["capacity_bundle"][name]["raw_sha256"]}
            for name in ("request", "artifact", "receipt")
        }
        require(capture["construction_probe"] == original_member["construction_probe"] and
                capture["capacity_bundle"] == expected_bundle,
                "offline pressure-pair probe capture differs from the exact original probe/capacity bytes")
        policy_pin = exact(original_member["composition"]["policy"], {"path", "raw_sha256"},
                           "offline pressure-pair resolved policy pin")
        policy_value, _policy_raw, _policy_sha = read_json(
            Path(policy_pin["path"]), "offline pressure-pair resolved policy", MAX_SMALL_BYTES,
            policy_pin["raw_sha256"],
        )
        require(type(policy_value.get("policy")) is dict,
                "offline pressure-pair resolved policy omits its policy body")
        feedback_context = {
            "schema": feedback_module.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
            "evidence_path_map": evidence_path_map,
            "probe_capture_pin": capture["capture_receipt"],
            "capacity_bundle": capture["capacity_bundle"],
        }
        probe_sha = feedback_module.validate_calibrated_construction_probe_v2_offline(
            capture["construction_probe"],
            {"path": str(inputs["manifest_path"]), "raw_sha256": inputs["manifest_raw_sha256"]},
            expected_bundle["artifact"], original_member["identity"],
            replay_context=feedback_context, expected_policy=policy_value["policy"],
        )
        require(probe_sha == capture["construction_probe"]["raw_sha256"],
                "offline pressure-pair captured ProbeV2 differs from original construction-probe bytes")
        pressure_result = validator_module.verify_pressure_offline(
            expected_host_row["pressure_recipe"], expected_host_row["pressure_artifacts"],
            receipt_pin, evidence_path_map=evidence_path_map, source_root=source_root,
        )
        trace = exact(row["feedback_trace"], {
            "directory", "manifest", "events", "samples", "validation",
        }, "offline pressure-pair feedback trace pins")
        feedback_hashes = {}
        for label in ("manifest", "events", "samples"):
            trace_pin = exact(trace[label], {"path", "raw_sha256"},
                              f"offline pressure-pair feedback {label} pin")
            feedback_hashes[label] = trace_pin["raw_sha256"]
        expectation_pin = exact(row["runtime_expectation"], {"path", "raw_sha256"},
                                "offline pressure-pair feedback expectation pin")
        feedback_result = feedback_module._verify_feedback_replay(
            Path(expectation_pin["path"]), expectation_pin["raw_sha256"],
            Path(trace["directory"]), feedback_hashes,
            offline_replay_context=feedback_context,
            offline_replayed_proof=pressure_result,
        )
        validation_pin = exact(trace["validation"], {"path", "raw_sha256"},
                               "offline pressure-pair feedback validation pin")
        validation_value, _validation_raw, validation_sha = read_json(
            Path(validation_pin["path"]), "offline pressure-pair stored feedback validation",
            recipe["artifact_budgets"]["feedback_validation_bytes"], validation_pin["raw_sha256"],
        )
        require(validation_sha == validation_pin["raw_sha256"] and validation_value == feedback_result and
                feedback_result["validated"] is True and feedback_result["qualification_eligible"] is False,
                "offline pressure-pair V5 feedback replay differs from its exact original readback")
        member_replay = _verify_offline_normal_app_member(
            row, expected_host_row, members[index], prepared, pressure_result,
            feedback_result, validation_pin, feedback_context,
        )
        process_key = (member_replay["application_pid"],
                       member_replay["application_start_ticks"])
        require(process_key not in seen_processes,
                "offline pressure members repeat a direct APP PID/start identity")
        seen_processes.add(process_key)
        require(process_rows[index] == member_replay["process_row"],
                "offline pressure base process row differs from full normal APP replay")
        member_results.append({
            "ordinal": index, "identity": original_member["identity"],
            "pressure_recipe": expected_host_row["pressure_recipe"],
            "proof_pin": expected_host_row["pressure_artifacts"]["proof"],
            "readback": pressure_result,
            **member_replay,
        })
    chronology_module, chronology_pin = _pinned_source_module(
        inputs["source"], inputs["source_root"],
        "scripts/application-campaign-chronology.py", "offline campaign chronology", MAX_SOURCE_BYTES,
    )
    require(chronology_pin["sha256"] == recipe["validators"]["campaign_chronology"]["sha256"] ==
            host_receipt["dependency_pins"]["campaign_chronology"]["raw_sha256"],
            "offline chronology module differs from its SourceV5/host receipt pins")
    offline_journal = getattr(chronology_module, "verify_source5_host_journal_offline", None)
    require(callable(offline_journal),
            "offline pressure-pair replay is blocked: the captured chronology module has no pure host-journal replay API")
    require(all(row["exit_code"] == "0" and row["row_validation"] == "valid" and
                row["p99_qualification"] == "not_applicable" for row in process_rows),
            "offline pressure base rows claim a failed APP or P99 qualification")
    result = {
        "schema": READBACK_SCHEMA,
        "validated": True,
        "qualification_eligible": False,
        "execution_ready": False,
        "campaign_readiness": False,
        "controller_chronology_proven": False,
        "readback_sha256": sidecar_sha,
        "processes_sha256": process_pin["raw_sha256"],
        "member_count": 2,
        "application_identities": [
            {"pid": row["application_pid"],
             "start_ticks": row["application_start_ticks"]}
            for row in member_results
        ],
        "pressure_metrics": [row["pressure_metric"] for row in member_results],
    }
    require(host_receipt["strict_result_sha256"] == digest_object(result),
            "full offline pressure result differs from the strict origin receipt digest")
    _verify_source5_local_symlinks(
        rows=capture_rows, snapshots=source_symlink_snapshots,
    )
    return result


def _pair_absolute_paths(value: object) -> set[str]:
    result: set[str] = set()
    path_keys = {
        "path", "source_root", "output_root", "directory", "root", "cwd",
        "tmpdir_path", "trace_directory", "pressure_scratch_path",
        "application_tmpdir_path", "mount_point",
    }

    def visit(item: object, argv_context: bool = False) -> None:
        if type(item) is dict:
            for key, child in item.items():
                if key in path_keys and type(child) is str and child.startswith("/"):
                    result.add(child)
                if key in {"argv", "requested_argv", "executed_argv"}:
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


def _run_pressure_pair_component(
    recipe_path: Path, expected_recipe_sha256: str, output_root: Path, *,
    chronology_module: Any | None = None, lock: Any | None = None,
    authorization_context: dict[str, Any] | None = None,
    on_app_started: Any | None = None, on_app_terminal: Any | None = None,
) -> dict[str, Any]:
    require(Path(recipe_path).resolve(strict=True) == Path(recipe_path), "private pressure-pair recipe path traverses a symlink or alias")
    recipe_value, recipe_raw, recipe_sha = read_json(recipe_path, "private pressure-pair recipe", MAX_RECIPE_BYTES, expected_recipe_sha256)
    require(recipe_sha == digest(expected_recipe_sha256, "expected pressure-pair recipe SHA-256"), "pressure-pair recipe raw digest differs")
    recipe = _validate_recipe_shape(recipe_value)
    output_root = Path(output_root)
    require(output_root.is_absolute() and output_root.resolve(strict=True) == output_root, "pressure-pair output root is not canonical")
    require(not (output_root / PAIR_PROCESS_FILE).exists() and not (output_root / PAIR_READBACK_FILE).exists(), "pressure-pair output already has final pair artifacts")
    prepared = _prepare_prerequisites(
        recipe, output_root, chronology_module=chronology_module,
        lock=lock, authorization_context=authorization_context,
    )
    _prepare_member_directories(recipe, prepared["output_root"])
    member_evidence: list[dict[str, Any]] = []
    rows: list[dict[str, str]] = []
    active_member_index: int | None = None
    try:
        for index, member_context in enumerate(prepared["members"]):
            active_member_index = index
            member_run = _run_one_member(
                member_context, prepared, on_app_started, on_app_terminal,
            )
            app_result = _validate_app_outputs(member_context, prepared["inputs"], recipe, prepared["modules"], member_run["receipt"])
            feedback = _finalize_feedback(member_context, member_run, prepared, app_result)
            row = _process_row(member_context, member_run, app_result, feedback, prepared)
            evidence = _member_evidence(member_context, member_run, app_result, feedback, row, prepared)
            require(len(canonical_bytes(evidence)) <= recipe["artifact_budgets"]["member_sidecar_bytes"], "normal APP member sidecar exceeds its frozen budget")
            member_evidence.append(evidence)
            rows.append(row)
        processes_path = prepared["output_root"] / PAIR_PROCESS_FILE
        processes_sha = _write_process_ledger(processes_path, rows, prepared["modules"]["campaign_controller"])
        processes_pin = {"path": str(processes_path), "raw_sha256": processes_sha}
        body = _pair_readback_body(prepared, processes_pin, member_evidence)
        readback = {**body, "readback_sha256": sha256_bytes(canonical_bytes(body))}
        require(len(canonical_bytes(readback)) <= recipe["artifact_budgets"]["pair_sidecar_bytes"], "pressure-pair sidecar exceeds its frozen budget")
        readback_path = prepared["output_root"] / PAIR_READBACK_FILE
        readback_sha = write_new(readback_path, canonical_bytes(readback), "pressure-pair readback sidecar")
        validation = validate_pressure_pair_artifacts(
            recipe, prepared["output_root"], readback_path, readback_sha,
            chronology_module=chronology_module, lock=lock,
            authorization_context=authorization_context,
        )
        return {
            "schema": READBACK_SCHEMA,
            "validated": validation["validated"],
            "qualification_eligible": False,
            "execution_ready": False,
            "campaign_readiness": False,
            "controller_chronology_proven": False,
            "readback_path": str(readback_path),
            "readback_sha256": readback_sha,
            "processes_path": str(processes_path),
            "processes_sha256": processes_sha,
            "member_count": 2,
            "pressure_metrics": validation["pressure_metrics"],
        }
    except BaseException as error:
        failure_path = prepared["output_root"] / "pressure-pair-attempt-failure.json"
        if not failure_path.exists() and not failure_path.is_symlink():
            failure = {
                "schema": "allocatbelt.application-pressure-pair-attempt-failure.v1",
                "recipe_sha256": recipe_sha,
                "job_run_id": prepared["inputs"]["job"]["run_id"],
                "active_member_ordinal": active_member_index,
                "completed_members": len(member_evidence),
                "error_type": type(error).__name__,
                "error_sha256": sha256_bytes(str(error).encode("utf-8", "replace")),
                "qualification_eligible": False,
            }
            write_new(failure_path, canonical_bytes(failure), "partial pressure-pair attempt failure")
        raise


def run_pressure_pair(recipe_path: Path, expected_recipe_sha256: str,
                      output_root: Path) -> dict[str, Any]:
    """Run the archived standalone component path with its existing false flags."""
    return _run_pressure_pair_component(recipe_path, expected_recipe_sha256,
                                         output_root)


def run_pressure_pair_locked(
    recipe_path: Path, expected_recipe_sha256: str, output_root: Path,
    chronology_module: Any, lock: Any, authorization_context: dict[str, Any],
    on_app_started: Any, on_app_terminal: Any,
) -> dict[str, Any]:
    """Run a pressure pair under its caller's already-owned Source5 lock."""
    require(type(authorization_context) is dict and callable(on_app_started) and
            callable(on_app_terminal),
            "locked Source5 pressure execution needs its durable authorization and APP callbacks")
    require(callable(getattr(chronology_module, "_lock_token_is_live", None)) and
            chronology_module._lock_token_is_live(lock),
            "locked Source5 pressure execution requires the same loaded chronology token registry")
    result = _run_pressure_pair_component(
        recipe_path, expected_recipe_sha256, output_root,
        chronology_module=chronology_module, lock=lock,
        authorization_context=authorization_context,
        on_app_started=on_app_started, on_app_terminal=on_app_terminal,
    )
    recipe, _recipe_raw, recipe_sha = read_json(
        Path(recipe_path), "Source5 validated pressure recipe", MAX_RECIPE_BYTES,
        expected_recipe_sha256,
    )
    require(result.get("validated") is True and
            result.get("qualification_eligible") is False,
            "locked Source5 pressure component did not remain component-only")
    return {
        "schema": "allocatbelt.application-source5-pressure-component.v1",
        "validated": True,
        "qualification_eligible": False,
        "recipe": {"path": str(Path(recipe_path)), "raw_sha256": recipe_sha},
        "overlay": recipe["execution_overlay"]["artifact"],
        "readback": {"path": result["readback_path"],
                     "raw_sha256": result["readback_sha256"]},
        "processes": {"path": result["processes_path"],
                      "raw_sha256": result["processes_sha256"]},
        "pressure_metrics": result["pressure_metrics"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="execute one original SourceV5 pressure job as two normal APPs")
    run.add_argument("--recipe", type=Path, required=True)
    run.add_argument("--expected-recipe-sha256", required=True)
    run.add_argument("--output-root", type=Path, required=True)
    validate = commands.add_parser("validate", help="independently replay a completed pressure-pair sidecar")
    validate.add_argument("--recipe", type=Path, required=True)
    validate.add_argument("--expected-recipe-sha256", required=True)
    validate.add_argument("--output-root", type=Path, required=True)
    validate.add_argument("--readback-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "run":
            result = run_pressure_pair(args.recipe, args.expected_recipe_sha256, args.output_root)
        else:
            require(args.recipe.resolve(strict=True) == args.recipe, "private pressure-pair recipe path traverses a symlink or alias")
            recipe, _raw, _sha = read_json(args.recipe, "private pressure-pair recipe", MAX_RECIPE_BYTES, args.expected_recipe_sha256)
            result = validate_pressure_pair_artifacts(
                _validate_recipe_shape(recipe), args.output_root,
                args.output_root / PAIR_READBACK_FILE, args.readback_sha256,
            )
        sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except (PressurePairError, OSError, ValueError, TypeError, KeyError, IndexError, RecursionError, AssertionError) as error:
        print(f"application-pressure-pair: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
