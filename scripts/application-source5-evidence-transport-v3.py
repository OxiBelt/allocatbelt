#!/usr/bin/env python3
"""Bounded Source5 v3 index and file-backed captured-evidence transport.

This module is deliberately independent of the campaign's component readers.
It writes content-addressed captured objects and streaming, sorted metadata so
the full original horizon never becomes one Python list or one giant JSON file.
"""
from __future__ import annotations

import bisect
import heapq
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
from collections import OrderedDict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator


INDEX_SCHEMA_V3 = "allocatbelt.application-source5-journal-evidence-index.v3"
INDEX_DATA_SCHEMA_V1 = "allocatbelt.application-source5-journal-evidence-index-data.v1"
INDEX_PAGE_SCHEMA_V1 = "allocatbelt.application-source5-journal-evidence-index-page.v1"
CAPTURED_STORE_SCHEMA_V2 = "allocatbelt.application-source5-captured-evidence.v2"
CAPTURED_CHUNK_SCHEMA_V1 = "allocatbelt.application-source5-captured-evidence-chunk.v1"
DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024
DEFAULT_FANOUT = 128
SORT_RUN_ROWS = 256
SORT_MERGE_FANOUT = 64
MAX_ROW_BYTES = 64 * 1024
MAX_PATH_BYTES = 4096
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_U64 = (1 << 64) - 1
MAX_STORE_ROWS = MAX_U64


class EvidenceTransportError(ValueError):
    """A v3 index or captured-store pin is malformed or incomplete."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceTransportError(message)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise EvidenceTransportError(f"{type(value).__name__} is not canonical JSON: {error}") from error


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    _require(type(value) is str and
             re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             f"{label} is not a lowercase SHA-256")
    return value


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    _require(type(value) is int and 0 <= value <= MAX_U64 and
             (not positive or value > 0), f"{label} is outside its finite integer bound")
    return value


def _path(value: object, label: str) -> str:
    _require(type(value) is str and value.startswith("/") and
             len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             ".." not in PurePosixPath(value).parts and "\x00" not in value and
             not any(ord(char) < 32 or ord(char) == 127 for char in value) and
             PurePosixPath(value).as_posix() == value,
             f"{label} is not a normalized bounded absolute path")
    return value


def _pin(value: object, label: str) -> dict[str, str]:
    row = _exact(value, {"path", "raw_sha256", "semantic_sha256"}, label)
    return {"path": _path(row["path"], f"{label} path"),
            "raw_sha256": _digest(row["raw_sha256"], f"{label} raw digest"),
            "semantic_sha256": _digest(row["semantic_sha256"],
                                        f"{label} semantic digest")}


def _write_new(path: Path, raw: bytes) -> None:
    _require(path.is_absolute() and path.parent.is_dir() and
             not path.exists() and not path.is_symlink(),
             f"refusing to replace immutable evidence at {path}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            _require(written > 0, "evidence transport writer made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_stable_regular_file(
    path_value: object, maximum: int, label: str, *,
    expected_bytes: int | None = None, collect: bool = True,
) -> tuple[bytes | None, str, int]:
    if (getattr(path_value, "source5_captured_object_v2", False) is True and
            callable(getattr(path_value, "open_stream", None))):
        stream = path_value.open_stream()
        try:
            descriptor = stream.raw.fileno()
            before = os.fstat(descriptor)
            if expected_bytes is not None:
                _require(before.st_size == expected_bytes,
                         f"{label} byte count differs from its exact descriptor")
            _require(stat.S_ISREG(before.st_mode) and
                     stat.S_IMODE(before.st_mode) == 0o600 and
                     before.st_nlink == 1 and before.st_size <= maximum and
                     (expected_bytes is None or before.st_size == expected_bytes),
                     f"{label} captured object is outside its exact read ceiling")
            hasher = hashlib.sha256()
            blocks: list[bytes] | None = [] if collect else None
            total = 0
            while total < before.st_size:
                block = stream.read(min(1024 * 1024, before.st_size - total))
                _require(bool(block), f"{label} ended before its pinned size")
                total += len(block)
                _require(total <= maximum and
                         (expected_bytes is None or total <= expected_bytes),
                         f"{label} grew beyond its byte ceiling")
                hasher.update(block)
                if blocks is not None:
                    blocks.append(block)
            _require(stream.read(1) == b"" and total == before.st_size,
                     f"{label} has trailing bytes or changed size while reading")
            after = os.fstat(descriptor)
            before_key = (before.st_dev, before.st_ino, before.st_mode,
                          before.st_size, before.st_mtime_ns, before.st_ctime_ns,
                          before.st_nlink)
            after_key = (after.st_dev, after.st_ino, after.st_mode,
                         after.st_size, after.st_mtime_ns, after.st_ctime_ns,
                         after.st_nlink)
            _require(before_key == after_key,
                     f"{label} changed during its captured-object read")
            raw = b"".join(blocks) if blocks is not None else None
            return raw, hasher.hexdigest(), total
        finally:
            stream.close()
    path = Path(_path(str(path_value), f"{label} path"))
    _require(path.resolve(strict=True) == path,
             f"{label} traverses a symlink or path alias")
    try:
        before_path = path.lstat()
        if expected_bytes is not None:
            _require(before_path.st_size == expected_bytes,
                     f"{label} byte count differs from its exact descriptor")
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and
                 before_path.st_size <= maximum and
                 (expected_bytes is None or
                  before_path.st_size == expected_bytes),
                 f"{label} is not an exact bounded owned private regular file")
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise EvidenceTransportError(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        before_key = (before.st_dev, before.st_ino, before.st_mode,
                      before.st_size, before.st_mtime_ns, before.st_ctime_ns,
                      before.st_nlink)
        path_key = (before_path.st_dev, before_path.st_ino, before_path.st_mode,
                    before_path.st_size, before_path.st_mtime_ns,
                    before_path.st_ctime_ns, before_path.st_nlink)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                 stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
                 before_key == path_key and before.st_size <= maximum and
                 (expected_bytes is None or before.st_size == expected_bytes),
                 f"{label} changed identity before its bounded read")
        hasher = hashlib.sha256()
        blocks: list[bytes] | None = [] if collect else None
        total = 0
        while total < before.st_size:
            block = os.read(descriptor, min(1024 * 1024,
                                            before.st_size - total))
            _require(bool(block), f"{label} ended before its pinned size")
            total += len(block)
            _require(total <= maximum and
                     (expected_bytes is None or total <= expected_bytes),
                     f"{label} grew beyond its byte ceiling")
            hasher.update(block)
            if blocks is not None:
                blocks.append(block)
        _require(os.read(descriptor, 1) == b"" and total == before.st_size,
                 f"{label} has trailing bytes or changed size while reading")
        after = os.fstat(descriptor)
        after_path = path.lstat()
        after_key = (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
        after_path_key = (after_path.st_dev, after_path.st_ino,
                          after_path.st_mode, after_path.st_size,
                          after_path.st_mtime_ns, after_path.st_ctime_ns,
                          after_path.st_nlink)
        _require(before_key == after_key == after_path_key and
                 stat.S_ISREG(after.st_mode) and after.st_uid == os.getuid() and
                 stat.S_IMODE(after.st_mode) == 0o600,
                 f"{label} changed during its stable read")
        raw = b"".join(blocks) if blocks is not None else None
        return raw, hasher.hexdigest(), total
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_directory(path: Path) -> None:
    _require(path.is_absolute() and path.resolve(strict=True) == path and
             path.is_dir() and not path.is_symlink(),
             f"evidence transport directory is not canonical: {path}")
    info = path.lstat()
    _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
             f"evidence transport directory is not owned mode 0700: {path}")


def _index_row(value: object, label: str) -> dict[str, Any]:
    row = _exact(value, {
        "role", "host_id", "origin_path", "local_path", "raw_sha256",
        "semantic_sha256", "byte_count", "maximum_bytes",
    }, label)
    _require(type(row["role"]) is str and row["role"], f"{label} role is malformed")
    _require(row["host_id"] is None or
             (type(row["host_id"]) is str and bool(row["host_id"])),
             f"{label} host binding is malformed")
    _path(row["origin_path"], f"{label} origin path")
    _path(row["local_path"], f"{label} local path")
    _digest(row["raw_sha256"], f"{label} raw digest")
    _require(row["semantic_sha256"] is None or
             (type(row["semantic_sha256"]) is str and
              re.fullmatch(r"[0-9a-f]{64}", row["semantic_sha256"]) is not None),
             f"{label} semantic digest is malformed")
    count = _uint(row["byte_count"], f"{label} byte count")
    maximum = _uint(row["maximum_bytes"], f"{label} owner byte ceiling")
    _require(count <= maximum, f"{label} exceeds its exact owner byte ceiling")
    return row


def _descriptor(value: object, label: str) -> dict[str, Any]:
    row = _exact(value, {
        "kind", "path", "raw_sha256", "semantic_sha256", "byte_count",
        "entry_count", "first_path", "last_path", "level",
    }, label)
    _require(row["kind"] in {"data_chunk", "manifest_page"},
             f"{label} has an unsupported descriptor kind")
    _path(row["path"], f"{label} path")
    _digest(row["raw_sha256"], f"{label} raw digest")
    _digest(row["semantic_sha256"], f"{label} semantic digest")
    _uint(row["byte_count"], f"{label} byte count", positive=True)
    _uint(row["entry_count"], f"{label} entry count", positive=True)
    first = _path(row["first_path"], f"{label} first path")
    last = _path(row["last_path"], f"{label} last path")
    _require(first <= last, f"{label} path range is inverted")
    if row["kind"] == "data_chunk":
        _require(row["level"] is None, f"{label} data chunk has a manifest level")
    else:
        _uint(row["level"], f"{label} manifest level")
    return row


def _semantic_root(value: dict[str, Any], field: str) -> str:
    body = {key: item for key, item in value.items() if key != field}
    return _sha(_canonical(body))


def _minimum_index_chunk_bytes() -> int:
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    child = {
        "kind": "manifest_page", "path": maximum_path,
        "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
        "byte_count": MAX_U64, "entry_count": MAX_U64,
        "first_path": maximum_path, "last_path": maximum_path,
        "level": MAX_U64,
    }
    body = {
        "schema": INDEX_PAGE_SCHEMA_V1, "level": MAX_U64,
        "entry_count": MAX_U64, "entries": [child, child],
    }
    return len(_canonical({**body, "page_sha256": "f" * 64}))


def _validate_index_limits(
    chunk_bytes: object, fanout: object,
    maximum_entries: object | None = None,
    maximum_index_bytes: object | None = None,
) -> None:
    _require(type(chunk_bytes) is int and
             _minimum_index_chunk_bytes() <= chunk_bytes <= DEFAULT_CHUNK_BYTES and
             type(fanout) is int and 2 <= fanout <= DEFAULT_FANOUT,
             "v3 index chunk/fanout settings are outside the supported finite bounds")
    if maximum_entries is not None:
        _require(type(maximum_entries) is int and
                 0 < maximum_entries <= MAX_STORE_ROWS,
                 "v3 index entry ceiling is outside its finite bound")
    if maximum_index_bytes is not None:
        _require(type(maximum_index_bytes) is int and
                 0 < maximum_index_bytes <= MAX_U64,
                 "v3 index byte ceiling is outside its finite bound")


def _minimum_store_chunk_bytes() -> int:
    maximum_path = "/" + ("x" * (MAX_PATH_BYTES - 1))
    row = {
        "role": "x" * 64, "host_id": "x" * 96,
        "origin_path": maximum_path, "local_path": maximum_path,
        "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
        "byte_count": MAX_U64, "maximum_bytes": MAX_U64,
    }
    return max(len(_canonical(row)), 2 * MAX_ROW_BYTES)


def _write_sorted_run(path: Path, rows: Iterable[dict[str, Any]],
                      maximum_bytes: int) -> dict[str, Any]:
    _path(str(path), "Source5 index sort run path")
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    hasher = hashlib.sha256()
    total = count = 0
    prior = ""
    try:
        os.fchmod(descriptor, 0o600)
        for row in rows:
            _require(row["origin_path"] > prior,
                     "Source5 external index sort found duplicate paths")
            prior = row["origin_path"]
            raw = _canonical(row)
            _require(len(raw) <= MAX_ROW_BYTES and total + len(raw) <= maximum_bytes,
                     "Source5 external index sort run exceeds its source-pinned byte limit")
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                _require(written > 0, "Source5 external index sorter made no progress")
                view = view[written:]
            hasher.update(raw)
            total += len(raw)
            count += 1
        _require(count > 0, "Source5 external index sort produced an empty run")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"path": path, "byte_count": total, "entry_count": count,
            "raw_sha256": hasher.hexdigest()}


def _iter_sorted_run(run: dict[str, Any]) -> Iterator[dict[str, Any]]:
    path = run["path"]
    try:
        before_path = path.lstat()
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and
                 before_path.st_size == run["byte_count"],
                 "Source5 index sort run is not exact private data")
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise EvidenceTransportError(f"cannot open Source5 index sort run: {error}") from error
    try:
        before = os.fstat(descriptor)
        before_key = (before.st_dev, before.st_ino, before.st_mode,
                      before.st_size, before.st_mtime_ns, before.st_ctime_ns,
                      before.st_nlink)
        path_key = (before_path.st_dev, before_path.st_ino, before_path.st_mode,
                    before_path.st_size, before_path.st_mtime_ns,
                    before_path.st_ctime_ns, before_path.st_nlink)
        _require(before_key == path_key,
                 "Source5 index sort run changed before reading")
        hasher = hashlib.sha256()
        total = count = 0
        prior = ""
        pending = bytearray()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            _require(total <= run["byte_count"],
                     "Source5 index sort run grew during reading")
            hasher.update(block)
            pending.extend(block)
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    _require(len(pending) <= MAX_ROW_BYTES,
                             "Source5 index sort row exceeds its bounded width")
                    break
                line_end = newline + 1
                line = bytes(pending[:line_end])
                del pending[:line_end]
                _require(len(line) <= MAX_ROW_BYTES and b"\r" not in line,
                         "Source5 index sort row framing differs")
                try:
                    value = json.loads(line.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise EvidenceTransportError(
                        "Source5 index sort row is malformed",
                    ) from error
                row = _index_row(value, "Source5 external index sort row")
                _require(line == _canonical(row) and row["origin_path"] > prior,
                         "Source5 index sort run is noncanonical or unordered")
                prior = row["origin_path"]
                count += 1
                yield row
        _require(not pending and total == run["byte_count"] and
                 count == run["entry_count"] and
                 hasher.hexdigest() == run["raw_sha256"],
                 "Source5 index sort run raw/count/range pin differs")
        after = os.fstat(descriptor)
        after_path = path.lstat()
        after_key = (after.st_dev, after.st_ino, after.st_mode,
                     after.st_size, after.st_mtime_ns, after.st_ctime_ns,
                     after.st_nlink)
        after_path_key = (after_path.st_dev, after_path.st_ino,
                          after_path.st_mode, after_path.st_size,
                          after_path.st_mtime_ns, after_path.st_ctime_ns,
                          after_path.st_nlink)
        _require(before_key == after_key == after_path_key,
                 "Source5 index sort run changed during reading")
    finally:
        os.close(descriptor)


def sort_index_rows_v3(
    entries: Iterable[object], *, scratch_directory: Path,
    maximum_entries: int, maximum_data_bytes: int,
) -> Iterator[dict[str, Any]]:
    """Sort exact owner rows in bounded multi-pass disk runs."""
    _require(type(maximum_entries) is int and
             0 < maximum_entries <= MAX_STORE_ROWS and
             type(maximum_data_bytes) is int and
             0 < maximum_data_bytes <= MAX_U64,
             "Source5 external index sort limits are malformed")
    _private_directory(scratch_directory)
    temporary = Path(tempfile.mkdtemp(prefix="source5-index-sort-",
                                      dir=scratch_directory))
    os.chmod(temporary, 0o700)
    runs: list[dict[str, Any]] = []
    batch: list[dict[str, Any]] = []
    input_count = 0
    input_bytes = 0

    def flush_batch() -> None:
        if not batch:
            return
        ordered = sorted(batch, key=lambda row: row["origin_path"])
        run = _write_sorted_run(
            temporary / f"run-{len(runs):08d}.jsonl", ordered,
            maximum_data_bytes,
        )
        runs.append(run)
        batch.clear()

    try:
        for position, value in enumerate(entries):
            row = _index_row(value, f"Source5 unsorted index row[{position}]")
            row_bytes = len(_canonical(row))
            _require(row_bytes <= MAX_ROW_BYTES and
                     input_bytes + row_bytes <= maximum_data_bytes and
                     input_count < maximum_entries,
                     "Source5 unsorted index input exceeds its exact row/byte ceiling")
            input_bytes += row_bytes
            input_count += 1
            batch.append(row)
            if len(batch) >= SORT_RUN_ROWS:
                flush_batch()
        flush_batch()
        _require(input_count > 0 and bool(runs),
                 "Source5 external index sort input is empty")
        pass_number = 0
        while len(runs) > SORT_MERGE_FANOUT:
            next_runs: list[dict[str, Any]] = []
            for group_number, offset in enumerate(
                    range(0, len(runs), SORT_MERGE_FANOUT)):
                group = runs[offset:offset + SORT_MERGE_FANOUT]
                merged = heapq.merge(
                    *(_iter_sorted_run(run) for run in group),
                    key=lambda row: row["origin_path"],
                )
                next_run = _write_sorted_run(
                    temporary /
                    f"merge-{pass_number:04d}-{group_number:08d}.jsonl",
                    merged, maximum_data_bytes,
                )
                next_runs.append(next_run)
                for run in group:
                    run["path"].unlink()
            runs = next_runs
            pass_number += 1
        merged = heapq.merge(
            *(_iter_sorted_run(run) for run in runs),
            key=lambda row: row["origin_path"],
        )
        previous = ""
        count = 0
        for row in merged:
            _require(row["origin_path"] > previous,
                     "Source5 external index rows are duplicate or unordered")
            previous = row["origin_path"]
            count += 1
            yield row
        _require(count == input_count,
                 "Source5 external index sort lost rows during merge")
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def write_index_v3(
    *, campaign_id: str, host_id: str, source_root: str,
    input_root: str, output_root: str, host_evidence_budget: object,
    entries: Iterable[object], directory: Path,
    maximum_entries: int, maximum_index_bytes: int,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    fanout: int = DEFAULT_FANOUT,
) -> tuple[dict[str, Any], dict[str, str], list[dict[str, Any]]]:
    """Write an ordered v3 index as bounded JSONL chunks plus fanout pages."""
    _validate_index_limits(
        chunk_bytes, fanout, maximum_entries, maximum_index_bytes,
    )
    _private_directory(directory)
    _require(not any(directory.iterdir()), "v3 index output directory must start empty")
    budget_pin = _pin(host_evidence_budget, "v3 host budget pin")
    root_values = {
        "source_root": _path(source_root, "v3 source root"),
        "input_root": _path(input_root, "v3 input root"),
        "output_root": _path(output_root, "v3 output root"),
    }
    for token_name, token_value in (("campaign ID", campaign_id), ("host ID", host_id)):
        _require(type(token_value) is str and
                 re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", token_value),
                 f"v3 {token_name} is malformed")

    descriptors: list[dict[str, Any]] = []
    output_files: list[dict[str, Any]] = []
    buffer = bytearray()
    chunk_rows = 0
    first_path = ""
    last_path = ""
    prior_path = ""
    count = 0
    total_bytes = 0
    hasher = hashlib.sha256()

    def flush_chunk() -> None:
        nonlocal buffer, chunk_rows, first_path, last_path, hasher, total_bytes
        if not buffer:
            return
        raw = bytes(buffer)
        digest = _sha(raw)
        path = directory / f"data-{digest}.jsonl"
        _path(str(path), "v3 index data chunk path")
        _require(total_bytes + len(raw) <= maximum_index_bytes,
                 "v3 index data exceeds its source-pinned byte ceiling")
        _write_new(path, raw)
        descriptor = {
            "kind": "data_chunk", "path": str(path),
            "raw_sha256": digest, "semantic_sha256": digest,
            "byte_count": len(raw), "entry_count": chunk_rows,
            "first_path": first_path, "last_path": last_path, "level": None,
        }
        descriptors.append(descriptor)
        output_files.append({"path": str(path), "role": "evidence_index_data_chunk",
                             "raw_sha256": digest, "semantic_sha256": digest,
                             "byte_count": len(raw)})
        total_bytes += len(raw)
        buffer = bytearray()
        chunk_rows = 0
        first_path = ""
        last_path = ""
        hasher = hashlib.sha256()

    try:
        for position, value in enumerate(entries):
            row = _index_row(value, f"v3 index row[{position}]")
            _require(row["origin_path"] > prior_path,
                     "v3 index paths are not strictly ordered and unique")
            prior_path = row["origin_path"]
            line = _canonical(row)
            _require(len(line) <= MAX_ROW_BYTES,
                     "v3 index row exceeds its fixed maximum width")
            _require(len(line) <= chunk_bytes,
                     "v3 index row cannot fit its caller-selected data chunk")
            _require(count < maximum_entries and
                     total_bytes + len(buffer) + len(line) <= maximum_index_bytes,
                     "v3 index row exceeds its source-pinned entry/byte ceiling")
            if buffer and len(buffer) + len(line) > chunk_bytes:
                flush_chunk()
            if not buffer:
                first_path = row["origin_path"]
            buffer.extend(line)
            hasher.update(line)
            chunk_rows += 1
            last_path = row["origin_path"]
            count += 1
        flush_chunk()
        _require(count > 0 and descriptors,
                 "v3 evidence index cannot be empty")

        level_nodes = descriptors
        level = 0
        page_count = 0
        while len(level_nodes) > fanout:
            next_nodes: list[dict[str, Any]] = []

            def emit_page(children: list[dict[str, Any]]) -> None:
                nonlocal total_bytes, page_count
                page_body = {
                    "schema": INDEX_PAGE_SCHEMA_V1,
                    "level": level,
                    "entry_count": sum(item["entry_count"] for item in children),
                    "entries": children,
                }
                page_sha = _sha(_canonical(page_body))
                page = {**page_body, "page_sha256": page_sha}
                raw = _canonical(page)
                _require(len(raw) <= chunk_bytes,
                         "v3 manifest page exceeds its bounded page byte ceiling")
                _require(total_bytes + len(raw) <= maximum_index_bytes,
                         "v3 index manifest exceeds its source-pinned byte ceiling")
                page_path = directory / f"page-{page_sha}.json"
                _path(str(page_path), "v3 manifest page path")
                _write_new(page_path, raw)
                descriptor = {
                    "kind": "manifest_page", "path": str(page_path),
                    "raw_sha256": _sha(raw), "semantic_sha256": page_sha,
                    "byte_count": len(raw), "entry_count": page_body["entry_count"],
                    "first_path": children[0]["first_path"],
                    "last_path": children[-1]["last_path"], "level": level,
                }
                next_nodes.append(descriptor)
                output_files.append({
                    "path": str(page_path), "role": "evidence_index_manifest_page",
                    "raw_sha256": descriptor["raw_sha256"],
                    "semantic_sha256": page_sha, "byte_count": len(raw),
                })
                total_bytes += len(raw)
                page_count += 1

            group: list[dict[str, Any]] = []
            for child in level_nodes:
                candidate = [*group, child]
                candidate_body = {
                    "schema": INDEX_PAGE_SCHEMA_V1, "level": level,
                    "entry_count": sum(item["entry_count"] for item in candidate),
                    "entries": candidate,
                }
                candidate_bytes = len(_canonical({
                    **candidate_body, "page_sha256": "0" * 64,
                }))
                if group and (len(candidate) > fanout or
                              candidate_bytes > chunk_bytes):
                    emit_page(group)
                    group = [child]
                    single_body = {
                        "schema": INDEX_PAGE_SCHEMA_V1, "level": level,
                        "entry_count": child["entry_count"],
                        "entries": group,
                    }
                    _require(len(_canonical({
                        **single_body, "page_sha256": "0" * 64,
                    })) <= chunk_bytes,
                             "one v3 manifest child cannot fit its caller page byte ceiling")
                else:
                    group = candidate
            if group:
                emit_page(group)
            level_nodes = next_nodes
            level += 1
        root_body = {
            "schema": INDEX_SCHEMA_V3,
            "campaign_id": campaign_id, "host_id": host_id,
            **root_values, "host_evidence_budget": budget_pin,
            "entry_count": count, "chunk_count": len(descriptors),
            "manifest_page_count": page_count,
            "manifest_pages": level_nodes,
        }
        root = {**root_body, "index_sha256": _sha(_canonical(root_body))}
        root_raw = _canonical(root)
        total_bytes += len(root_raw)
        _require(total_bytes <= maximum_index_bytes,
                 "v3 index root exceeds its source-pinned byte ceiling")
        root_path = directory / f"source5-evidence-index-v3-{root['index_sha256']}.json"
        _path(str(root_path), "v3 evidence-index root path")
        _write_new(root_path, root_raw)
        root_pin = {"path": str(root_path), "raw_sha256": _sha(root_raw),
                    "semantic_sha256": root["index_sha256"]}
        output_files.append({"path": str(root_path), "role": "evidence_index",
                             "raw_sha256": root_pin["raw_sha256"],
                             "semantic_sha256": root_pin["semantic_sha256"],
                             "byte_count": len(root_raw)})
        _fsync_directory(directory)
        return root, root_pin, output_files
    except BaseException:
        for candidate in directory.iterdir():
            if candidate.is_file() and not candidate.is_symlink():
                candidate.unlink()
        raise


def _resolved_path(path_value: object, read_path, label: str) -> Path:
    origin = _path(path_value, f"{label} path")
    selected = Path(origin) if read_path is None else read_path(origin)
    selected_path = Path(selected)
    _require(selected_path.is_absolute(), f"{label} resolved path is not absolute")
    return selected


def _read_canonical_file(
    path_value: object, maximum: int, label: str, *, read_path=None,
    expected_bytes: int | None = None,
) -> tuple[dict[str, Any], bytes, str]:
    path = _resolved_path(path_value, read_path, label)
    raw_value, raw_sha, _byte_count = _read_stable_regular_file(
        path, maximum, label, expected_bytes=expected_bytes,
    )
    _require(raw_value is not None, f"{label} regular-file reader returned no bytes")
    raw = raw_value
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise EvidenceTransportError(f"{label} is not bounded UTF-8 JSON") from error
    _require(type(value) is dict and raw == _canonical(value),
             f"{label} is not one canonical JSON object")
    return value, raw, raw_sha


def _read_descriptor_file(descriptor_value: object, expected_kind: str,
                          maximum: int, *, read_path=None
                          ) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    descriptor = _descriptor(descriptor_value, f"v3 {expected_kind} descriptor")
    _require(descriptor["kind"] == expected_kind,
             f"v3 index descriptor kind differs from {expected_kind}")
    if expected_kind == "data_chunk":
        path = _resolved_path(descriptor["path"], read_path,
                              "v3 data chunk descriptor")
        raw_value, raw_sha, byte_count = _read_stable_regular_file(
            path, maximum, "v3 data chunk",
            expected_bytes=descriptor["byte_count"],
        )
        _require(raw_value is not None,
                 "v3 data chunk reader returned no authenticated bytes")
        _require(byte_count == descriptor["byte_count"] and
                 raw_sha == descriptor["raw_sha256"] == descriptor["semantic_sha256"],
                 "v3 data chunk raw/semantic pin differs")
        return {}, raw_value, descriptor
    value, raw, raw_sha = _read_canonical_file(
        descriptor["path"], maximum, "v3 manifest page", read_path=read_path,
        expected_bytes=descriptor["byte_count"],
    )
    _exact(value, {"schema", "level", "entry_count", "entries", "page_sha256"},
           "v3 index manifest page")
    body = {key: item for key, item in value.items() if key != "page_sha256"}
    _require(value["schema"] == INDEX_PAGE_SCHEMA_V1 and
             value["level"] == descriptor["level"] and
             value["entry_count"] == descriptor["entry_count"] and
             value["page_sha256"] == descriptor["semantic_sha256"] ==
                _sha(_canonical(body)) and
             raw_sha == descriptor["raw_sha256"],
             "v3 manifest page body/raw/semantic pin differs")
    return value, raw, descriptor


def _walk_descriptors(root: dict[str, Any], maximum_chunk_bytes: int,
                      fanout: int, *, read_path=None,
                      maximum_total_bytes: int = MAX_U64
                      ) -> Iterator[dict[str, Any]]:
    total_bytes = 0

    def walk(items: list[dict[str, Any]], parent_level: int | None,
             depth: int) -> Iterator[dict[str, Any]]:
        nonlocal total_bytes
        _require(depth <= 32, "v3 manifest page tree exceeds its fixed depth limit")
        previous = ""
        for raw_descriptor in items:
            descriptor = _descriptor(raw_descriptor, "v3 index child descriptor")
            _require(descriptor["first_path"] > previous,
                     "v3 index descriptor ranges overlap or reorder")
            previous = descriptor["last_path"]
            total_bytes += descriptor["byte_count"]
            _require(total_bytes <= maximum_total_bytes,
                     "v3 index descriptors exceed their aggregate byte ceiling")
            if descriptor["kind"] == "data_chunk":
                _require(parent_level is None or parent_level == 0,
                         "v3 data chunk is below the wrong manifest level")
                _read_descriptor_file(
                    descriptor, "data_chunk", maximum_chunk_bytes,
                    read_path=read_path,
                )
                yield descriptor
            else:
                _require(parent_level is None or descriptor["level"] < parent_level,
                         "v3 manifest page tree level does not decrease")
                page, _raw, _descriptor_value = _read_descriptor_file(
                    descriptor, "manifest_page", maximum_chunk_bytes,
                    read_path=read_path,
                )
                yield descriptor
                children = page["entries"]
                _require(type(children) is list and 1 <= len(children) <= fanout,
                         "v3 manifest page fanout exceeds its frozen bound")
                _require(sum(_descriptor(item, "v3 page child")["entry_count"]
                             for item in children) == page["entry_count"] and
                         children[0]["first_path"] == descriptor["first_path"] and
                         children[-1]["last_path"] == descriptor["last_path"],
                         "v3 page child counts/range do not close")
                yield from walk(children, descriptor["level"], depth + 1)

    descriptors = root["manifest_pages"]
    _require(type(descriptors) is list and 1 <= len(descriptors) <= fanout,
             "v3 index root manifest frontier is empty or exceeds fanout")
    yield from walk(descriptors, None, 0)


def validate_index_v3(
    value: object, *, budget_pin: object, campaign_id: str,
    host_id: str, source_root: str, input_root: str, output_root: str,
    maximum_entries: int, maximum_index_bytes: int,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    fanout: int = DEFAULT_FANOUT,
    read_path=None,
) -> dict[str, Any]:
    """Validate root, page tree, every ordered row, and all raw chunk pins."""
    _validate_index_limits(
        chunk_bytes, fanout, maximum_entries, maximum_index_bytes,
    )
    root = _exact(value, {
        "schema", "campaign_id", "host_id", "source_root", "input_root",
        "output_root", "host_evidence_budget", "entry_count", "chunk_count",
        "manifest_page_count", "manifest_pages", "index_sha256",
    }, "Source5 journal evidence index v3")
    expected_budget = _pin(budget_pin, "request host budget pin")
    _require(root["schema"] == INDEX_SCHEMA_V3 and
             root["campaign_id"] == campaign_id and root["host_id"] == host_id and
             root["source_root"] == source_root and root["input_root"] == input_root and
             root["output_root"] == output_root and
             root["host_evidence_budget"] == expected_budget,
             "v3 index identity/roots/budget pin differs from its host request")
    count = _uint(root["entry_count"], "v3 index entry count", positive=True)
    _require(count <= maximum_entries and
             _uint(root["chunk_count"], "v3 data chunk count", positive=True) > 0 and
             _uint(root["manifest_page_count"], "v3 manifest page count") <= maximum_entries,
             "v3 index counts exceed their source-pinned limits")
    _require(root["index_sha256"] == _semantic_root(root, "index_sha256"),
             "v3 index root semantic digest differs")
    total_entries = 0
    total_bytes = 0
    page_count = 0
    chunk_count = 0
    previous_path = ""
    for descriptor in _walk_descriptors(
            root, chunk_bytes, fanout, read_path=read_path,
            maximum_total_bytes=maximum_index_bytes):
        total_bytes += descriptor["byte_count"]
        if descriptor["kind"] == "manifest_page":
            page_count += 1
        else:
            chunk_count += 1
            total_entries += descriptor["entry_count"]
            _chunk, chunk_raw, _checked = _read_descriptor_file(
                descriptor, "data_chunk", chunk_bytes, read_path=read_path,
            )
            with io.BytesIO(chunk_raw) as stream:
                seen = 0
                first = ""
                last = ""
                while True:
                    line = stream.readline(MAX_ROW_BYTES + 1)
                    if not line:
                        break
                    _require(len(line) <= MAX_ROW_BYTES and line.endswith(b"\n") and
                             b"\r" not in line,
                             "v3 index data row framing or width differs")
                    try:
                        row_value = json.loads(line.decode("ascii"))
                    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                        raise EvidenceTransportError("v3 index data row is malformed") from error
                    row = _index_row(row_value, f"v3 index data row[{seen}]")
                    _require(line == _canonical(row) and row["origin_path"] > previous_path,
                             "v3 index rows are noncanonical, duplicated, or unordered")
                    previous_path = row["origin_path"]
                    if seen == 0:
                        first = row["origin_path"]
                    last = row["origin_path"]
                    seen += 1
                _require(seen == descriptor["entry_count"] and
                         first == descriptor["first_path"] and
                         last == descriptor["last_path"],
                         "v3 index data-chunk row count/path range differs")
    total_bytes += len(_canonical(root))
    _require(total_entries == count and chunk_count == root["chunk_count"] and
             total_bytes <= maximum_index_bytes,
             "v3 index data count or aggregate byte ceiling differs")
    _require(page_count == root["manifest_page_count"],
             "v3 index manifest-page count differs")
    return root


def iter_index_entries_v3(root: dict[str, Any], *, chunk_bytes: int = DEFAULT_CHUNK_BYTES,
                          fanout: int = DEFAULT_FANOUT,
                          read_path=None) -> Iterator[dict[str, Any]]:
    """Yield authenticated ordered v3 rows with bounded memory."""
    _validate_index_limits(chunk_bytes, fanout)
    prior = ""
    for descriptor in _walk_descriptors(
            root, chunk_bytes, fanout, read_path=read_path):
        if descriptor["kind"] != "data_chunk":
            continue
        _chunk, chunk_raw, _checked = _read_descriptor_file(
            descriptor, "data_chunk", chunk_bytes, read_path=read_path,
        )
        chunk_count = 0
        first = ""
        last = ""
        with io.BytesIO(chunk_raw) as stream:
            while True:
                line = stream.readline(MAX_ROW_BYTES + 1)
                if not line:
                    break
                position = chunk_count
                _require(len(line) <= MAX_ROW_BYTES and line.endswith(b"\n") and
                         b"\r" not in line,
                         "v3 index data row framing or width differs")
                try:
                    value = json.loads(line.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise EvidenceTransportError(
                        f"v3 index row {position} is malformed"
                    ) from error
                row = _index_row(value, f"v3 index row {position}")
                _require(line == _canonical(row),
                         "v3 index data row is not canonical")
                _require(row["origin_path"] > prior,
                         "v3 index rows are not globally ordered")
                prior = row["origin_path"]
                if chunk_count == 0:
                    first = row["origin_path"]
                last = row["origin_path"]
                chunk_count += 1
        _require(chunk_count == descriptor["entry_count"] and
                 first == descriptor["first_path"] and
                 last == descriptor["last_path"],
                 "v3 index data-chunk row count/path range differs")
        with io.BytesIO(chunk_raw) as stream:
            while True:
                line = stream.readline(MAX_ROW_BYTES + 1)
                if not line:
                    break
                try:
                    value = json.loads(line.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise EvidenceTransportError(
                        "v3 index data row changed after chunk validation",
                    ) from error
                yield _index_row(value, "v3 authenticated index data row")


def validate_index_against_catalogue_v3(
    entries: Iterable[dict[str, Any]],
    catalogue_rows: Iterable[dict[str, Any]],
) -> dict[str, int]:
    """Prove every captured index row has one exact bounded producer declaration."""
    index = iter(entries)
    current = next(index, None)
    aggregate_usage: dict[str, tuple[int, int]] = {}
    file_count = 0
    tree_file_count = 0
    tree_bytes = 0

    def require_row_for_file(row: dict[str, Any], declaration: dict[str, Any]) -> None:
        nonlocal file_count
        _require(row["role"] == declaration["role"] and
                 row["maximum_bytes"] == declaration["max_file_bytes"] and
                 row["byte_count"] <= declaration["max_file_bytes"] and
                 (declaration["host_id"] is None or
                  row["host_id"] == declaration["host_id"]),
                 f"indexed evidence differs from its owner path ceiling: {row['origin_path']}")
        pin = declaration["origin_pin"]
        if pin is not None:
            _require(row["raw_sha256"] == pin["raw_sha256"] and
                     row["semantic_sha256"] == pin["semantic_sha256"],
                     f"indexed immutable source differs from its raw/semantic pin: {row['origin_path']}")
        aggregate = declaration["aggregate_id"]
        if aggregate is not None:
            maximum = declaration["aggregate_max_bytes"]
            prior_limit, prior_bytes = aggregate_usage.get(aggregate, (maximum, 0))
            _require(prior_limit == maximum,
                     f"producer aggregate ceiling changes between paths: {aggregate}")
            observed = prior_bytes + row["byte_count"]
            _require(observed <= maximum,
                     f"producer aggregate output exceeds its exact owner limit: {aggregate}")
            aggregate_usage[aggregate] = (maximum, observed)
        file_count += 1

    previous_catalogue_path = ""
    for position, declaration in enumerate(catalogue_rows):
        _require(type(declaration) is dict and
                 type(declaration.get("path")) is str and
                 declaration["path"] > previous_catalogue_path,
                 f"owner path catalogue row[{position}] is not ordered")
        previous_catalogue_path = declaration["path"]
        kind = declaration.get("kind")
        if declaration.get("role") == "directory_node":
            continue
        if kind == "file":
            if current is not None and current["origin_path"] < declaration["path"]:
                raise EvidenceTransportError(
                    f"indexed evidence is outside the producer path catalogue: {current['origin_path']}"
                )
            if current is not None and current["origin_path"] == declaration["path"]:
                require_row_for_file(current, declaration)
                current = next(index, None)
            elif declaration["origin_pin"] is not None:
                raise EvidenceTransportError(
                    f"captured evidence omits its pinned immutable input: {declaration['path']}"
                )
            continue
        _require(kind == "tree", f"owner path catalogue row[{position}] has unknown kind")
        prefix = declaration["path"].rstrip("/") + "/"
        tree_file_count = 0
        tree_bytes = 0
        while current is not None and current["origin_path"].startswith(prefix):
            _require(current["role"] == declaration["role"] and
                     current["maximum_bytes"] == declaration["max_file_bytes"] and
                     current["byte_count"] <= declaration["max_file_bytes"] and
                     (declaration["host_id"] is None or
                      current["host_id"] == declaration["host_id"]),
                     f"dynamic tree entry differs from its owner ceiling: {current['origin_path']}")
            tree_file_count += 1
            tree_bytes += current["byte_count"]
            _require(tree_file_count <= declaration["max_inodes"] - 1 and
                     tree_bytes <= declaration["max_bytes"],
                     f"dynamic tree exceeds its owner byte/inode ceiling: {declaration['path']}")
            file_count += 1
            current = next(index, None)
    if current is not None:
        raise EvidenceTransportError(
            "indexed evidence remains outside the producer path catalogue: "
            f"{current['origin_path']}"
        )
    return {"entry_count": file_count,
            "tree_file_count": tree_file_count,
            "tree_bytes": tree_bytes}


class EvidenceIndexEntriesV3:
    """Sorted lazy lookup over already authenticated v3 data-chunk descriptors."""

    def __init__(self, root: dict[str, Any], descriptors: list[dict[str, Any]],
                 chunk_bytes: int, fanout: int, root_pin: dict[str, str],
                 root_byte_count: int, read_path=None):
        self.root = root
        self.content_descriptors = descriptors
        self.descriptors = [item for item in descriptors
                            if item["kind"] == "data_chunk"]
        self.first_paths = [item["first_path"] for item in self.descriptors]
        self.chunk_bytes = chunk_bytes
        self.fanout = fanout
        self.root_pin = root_pin
        self.root_byte_count = root_byte_count
        self.read_path = read_path

    def __len__(self) -> int:
        return self.root["entry_count"]

    def __iter__(self) -> Iterator[str]:
        for row in self.iter_rows():
            yield row["origin_path"]

    def iter_rows(self) -> Iterator[dict[str, Any]]:
        yield from iter_index_entries_v3(
            self.root, chunk_bytes=self.chunk_bytes, fanout=self.fanout,
            read_path=self.read_path,
        )

    def get(self, path_value: object, default: Any = None) -> dict[str, Any] | Any:
        target = _path(path_value, "v3 index lookup path")
        index = bisect.bisect_right(self.first_paths, target) - 1
        if index < 0 or target > self.descriptors[index]["last_path"]:
            return default
        descriptor = self.descriptors[index]
        _value, raw, _checked = _read_descriptor_file(
            descriptor, "data_chunk", self.chunk_bytes,
            read_path=self.read_path,
        )
        previous = ""
        with io.BytesIO(raw) as stream:
            while True:
                line = stream.readline(MAX_ROW_BYTES + 1)
                if not line:
                    break
                _require(len(line) <= MAX_ROW_BYTES and line.endswith(b"\n") and
                         b"\r" not in line,
                         "v3 index lookup row framing or width differs")
                try:
                    value = json.loads(line.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise EvidenceTransportError("v3 index data row is malformed") from error
                row = _index_row(value, "v3 index lookup row")
                _require(line == _canonical(row) and row["origin_path"] > previous,
                         "v3 index lookup chunk is noncanonical or unordered")
                previous = row["origin_path"]
                if previous == target:
                    return row
                if previous > target:
                    break
        return default

    def items(self) -> Iterator[tuple[str, dict[str, Any]]]:
        for row in self.iter_rows():
            yield row["origin_path"], row

    def values(self) -> Iterator[dict[str, Any]]:
        yield from self.iter_rows()

    def external_files(self, host_id: str) -> Iterator[dict[str, Any]]:
        yield {
            "role": "evidence_index", "host_id": host_id,
            "path": self.root_pin["path"],
            "raw_sha256": self.root_pin["raw_sha256"],
            "semantic_sha256": self.root_pin["semantic_sha256"],
            "byte_count": self.root_byte_count,
        }
        for descriptor in self.content_descriptors:
            yield {
                "role": ("evidence_index_data_chunk"
                         if descriptor["kind"] == "data_chunk" else
                         "evidence_index_manifest_page"),
                "host_id": host_id, "path": descriptor["path"],
                "raw_sha256": descriptor["raw_sha256"],
                "semantic_sha256": descriptor["semantic_sha256"],
                "byte_count": descriptor["byte_count"],
            }


def open_index_v3(
    pin_value: object, *, budget_pin: object,
    campaign_id: str, host_id: str, source_root: str,
    input_root: str, output_root: str,
    maximum_entries: int, maximum_index_bytes: int,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    fanout: int = DEFAULT_FANOUT,
    read_path=None,
) -> tuple[dict[str, Any], EvidenceIndexEntriesV3]:
    """Verify a pinned root/page tree and return bounded-memory path lookup."""
    pin = _pin(pin_value, "Source5 v3 evidence index pin")
    root, raw, raw_sha = _read_canonical_file(
        pin["path"], MAX_MANIFEST_BYTES, "Source5 v3 evidence index root",
        read_path=read_path,
    )
    _require(raw_sha == pin["raw_sha256"] and
             root.get("index_sha256") == pin["semantic_sha256"],
             "Source5 v3 index root differs from its external raw/semantic pin")
    checked = validate_index_v3(
        root, budget_pin=budget_pin, campaign_id=campaign_id,
        host_id=host_id, source_root=source_root,
        input_root=input_root, output_root=output_root,
        maximum_entries=maximum_entries, maximum_index_bytes=maximum_index_bytes,
        chunk_bytes=chunk_bytes, fanout=fanout, read_path=read_path,
    )
    all_descriptors = list(_walk_descriptors(
        checked, chunk_bytes, fanout, read_path=read_path,
    ))
    return checked, EvidenceIndexEntriesV3(
        checked, all_descriptors, chunk_bytes, fanout, pin, len(raw), read_path,
    )


def build_captured_store_v2(
    *, campaign_id: str, host_id: str, budget_pin: object,
    index_pin: object, origin_receipt_pin: object,
    entries: Iterable[object], root: Path,
    maximum_entries: int, maximum_payload_bytes: int,
    maximum_metadata_bytes: int,
    maximum_root_bytes: int = MAX_MANIFEST_BYTES,
    chunk_bytes: int = DEFAULT_CHUNK_BYTES,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Copy a closed file stream into content-addressed objects and JSONL metadata."""
    _require(type(maximum_entries) is int and
             0 < maximum_entries <= MAX_STORE_ROWS and
             type(maximum_payload_bytes) is int and
             0 < maximum_payload_bytes <= MAX_U64 and
             type(maximum_metadata_bytes) is int and
             0 < maximum_metadata_bytes <= MAX_U64 and
             type(maximum_root_bytes) is int and
             0 < maximum_root_bytes <= MAX_MANIFEST_BYTES and
             type(chunk_bytes) is int and
             _minimum_store_chunk_bytes() <= chunk_bytes <= DEFAULT_CHUNK_BYTES,
             "captured-store caller ceilings are outside their finite limits")
    _private_directory(root)
    _require(not any(root.iterdir()), "captured-store root must start empty")
    budget = _pin(budget_pin, "captured-store budget pin")
    index = _pin(index_pin, "captured-store index pin")
    receipt = _pin(origin_receipt_pin, "captured-store receipt pin")
    objects = root / "objects"
    metadata = root / "metadata"
    maximum_metadata_chunks = (
        (maximum_metadata_bytes + (chunk_bytes - MAX_ROW_BYTES) - 1) //
        (chunk_bytes - MAX_ROW_BYTES)
    )
    descriptor = {
        "path": "/" + ("x" * (MAX_PATH_BYTES - 1)),
        "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
        "byte_count": MAX_U64, "entry_count": MAX_U64,
        "first_path": "/" + ("x" * (MAX_PATH_BYTES - 1)),
        "last_path": "/" + ("x" * (MAX_PATH_BYTES - 1)),
    }
    root_body_fixed = {
        "schema": CAPTURED_STORE_SCHEMA_V2,
        "campaign_id": campaign_id, "host_id": host_id,
        "host_evidence_budget": budget, "evidence_index": index,
        "origin_receipt": receipt, "entry_count": maximum_entries,
        "payload_bytes": maximum_payload_bytes,
        "metadata_bytes": maximum_metadata_bytes,
        "metadata_chunks": [],
        "object_directory": str(objects),
    }
    empty_root_size = len(_canonical({
        **root_body_fixed, "store_sha256": "f" * 64,
    }))
    descriptor_size = len(_canonical(descriptor))
    root_size_bound = empty_root_size + maximum_metadata_chunks * (
        descriptor_size + 1
    )
    _require(root_size_bound <= maximum_root_bytes,
             "captured-store caller metadata/root ceilings cannot fit the bounded root manifest")
    objects.mkdir(mode=0o700)
    metadata.mkdir(mode=0o700)
    buffer = bytearray()
    chunks: list[dict[str, Any]] = []
    prior_path = ""
    count = 0
    payload_bytes = 0
    metadata_bytes = 0
    first_path = ""
    last_path = ""
    chunk_count = 0

    def flush_chunk() -> None:
        nonlocal buffer, first_path, last_path, chunk_count, metadata_bytes
        nonlocal chunk_count_rows
        if not buffer:
            return
        _require(metadata_bytes + len(buffer) <= maximum_metadata_bytes,
                 "captured-store metadata exceeds its caller budget")
        raw = bytes(buffer)
        digest = _sha(raw)
        path = metadata / f"entries-{digest}.jsonl"
        _write_new(path, raw)
        descriptor = {
            "path": str(path), "raw_sha256": digest,
            "semantic_sha256": digest, "byte_count": len(raw),
            "entry_count": chunk_count_rows, "first_path": first_path,
            "last_path": last_path,
        }
        chunks.append(descriptor)
        metadata_bytes += len(raw)
        chunk_count += 1
        buffer = bytearray()
        first_path = ""
        last_path = ""
        chunk_count_rows = 0

    chunk_count_rows = 0
    try:
        for position, value in enumerate(entries):
            row_value = _exact(value, {
                "role", "host_id", "origin_path", "raw_sha256",
                "semantic_sha256", "byte_count", "maximum_bytes",
                "source_path", "source_kind",
            }, f"captured-store source row[{position}]")
            origin = _path(row_value["origin_path"], "captured origin path")
            _require(origin > prior_path, "captured-store origins are not ordered unique")
            prior_path = origin
            _require(row_value["role"] and type(row_value["role"]) is str and
                     (row_value["host_id"] is None or
                      (type(row_value["host_id"]) is str and row_value["host_id"])),
                     "captured-store role/host binding is malformed")
            raw_sha = _digest(row_value["raw_sha256"], "captured-store source raw digest")
            semantic_sha = row_value["semantic_sha256"]
            _require(semantic_sha is None or
                     (type(semantic_sha) is str and
                      re.fullmatch(r"[0-9a-f]{64}", semantic_sha) is not None),
                     "captured-store source semantic digest is malformed")
            byte_count = _uint(row_value["byte_count"], "captured-store source byte count")
            maximum = _uint(row_value["maximum_bytes"],
                            "captured-store owner byte ceiling")
            _require(byte_count <= maximum and count < maximum_entries and
                     payload_bytes + byte_count <= maximum_payload_bytes,
                     "captured-store row exceeds its prospective count/payload ceiling")
            origin_name = hashlib.sha256(origin.encode("utf-8")).hexdigest()
            object_name = f"{origin_name}-{raw_sha}"
            object_dir = objects / object_name[:2]
            object_path = object_dir / f"{object_name}.bin"
            source_path = Path(_path(row_value["source_path"], "captured source file"))
            local_path = str(object_path)
            row = {
                "role": row_value["role"], "host_id": row_value["host_id"],
                "origin_path": origin, "local_path": local_path,
                "raw_sha256": raw_sha, "semantic_sha256": semantic_sha,
                "byte_count": byte_count, "maximum_bytes": maximum,
            }
            line = _canonical(row)
            _require(len(line) <= MAX_ROW_BYTES and len(line) <= chunk_bytes,
                     "captured-store metadata row cannot fit its bounded chunk")
            _require(metadata_bytes + len(buffer) + len(line) <= maximum_metadata_bytes,
                     "captured-store metadata row exceeds its prospective byte ceiling")
            if buffer and len(buffer) + len(line) > chunk_bytes:
                flush_chunk()
            if not object_dir.exists():
                object_dir.mkdir(mode=0o700)
            _private_directory(object_dir)
            _require(not object_path.exists() and not object_path.is_symlink(),
                     "captured object path already exists")
            try:
                info = source_path.lstat()
                if row_value["source_kind"] == "symlink":
                    _require(stat.S_ISLNK(info.st_mode),
                             "captured literal-link source changed kind")
                    raw_source = os.readlink(source_path).encode("utf-8", "strict")
                    _require(len(raw_source) == byte_count and _sha(raw_source) == raw_sha,
                             "captured literal-link bytes differ from their typed source pin")
                    after = source_path.lstat()
                    _require((info.st_dev, info.st_ino, info.st_mode,
                              info.st_mtime_ns, info.st_ctime_ns) ==
                             (after.st_dev, after.st_ino, after.st_mode,
                              after.st_mtime_ns, after.st_ctime_ns),
                             "captured literal-link source changed during snapshot")
                    _write_new(object_path, raw_source)
                else:
                    _require(row_value["source_kind"] == "file" and
                             stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                             "captured source is not its declared regular file")
                    source_fd = os.open(
                        source_path, os.O_RDONLY |
                        getattr(os, "O_CLOEXEC", 0) |
                        getattr(os, "O_NOFOLLOW", 0),
                    )
                    fd = None
                    try:
                        source_info = os.fstat(source_fd)
                        _require(stat.S_ISREG(source_info.st_mode) and
                                 (source_info.st_dev, source_info.st_ino) ==
                                 (info.st_dev, info.st_ino),
                                 "captured source changed identity before open")
                        fd = os.open(object_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                     getattr(os, "O_CLOEXEC", 0) |
                                     getattr(os, "O_NOFOLLOW", 0), 0o600)
                        hasher = hashlib.sha256()
                        total = 0
                        os.fchmod(fd, 0o600)
                        while True:
                            block = os.read(source_fd, 1024 * 1024)
                            if not block:
                                break
                            total += len(block)
                            _require(total <= maximum and total <= byte_count,
                                     "captured source grew beyond its original byte ceiling")
                            hasher.update(block)
                            view = memoryview(block)
                            while view:
                                written = os.write(fd, view)
                                _require(written > 0,
                                         "captured object writer made no progress")
                                view = view[written:]
                        os.fsync(fd)
                        after = os.fstat(source_fd)
                        _require((source_info.st_dev, source_info.st_ino,
                                  source_info.st_mode, source_info.st_size,
                                  source_info.st_mtime_ns, source_info.st_ctime_ns) ==
                                 (after.st_dev, after.st_ino, after.st_mode,
                                  after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                                 "captured source changed during snapshot")
                        _require(total == byte_count and hasher.hexdigest() == raw_sha,
                                 "captured source bytes changed from their exact raw pin")
                    finally:
                        if fd is not None:
                            os.close(fd)
                        os.close(source_fd)
            except OSError as error:
                raise EvidenceTransportError(
                    f"cannot capture original evidence {origin}: {error}"
                ) from error
            if not buffer:
                first_path = origin
            buffer.extend(line)
            chunk_count_rows += 1
            count += 1
            payload_bytes += byte_count
            last_path = origin
        flush_chunk()
        _require(count > 0, "captured-store evidence closure is empty")
        body = {
            "schema": CAPTURED_STORE_SCHEMA_V2,
            "campaign_id": campaign_id, "host_id": host_id,
            "host_evidence_budget": budget, "evidence_index": index,
            "origin_receipt": receipt, "entry_count": count,
            "payload_bytes": payload_bytes, "metadata_bytes": metadata_bytes,
            "metadata_chunks": chunks,
            "object_directory": str(objects),
        }
        store = {**body, "store_sha256": _sha(_canonical(body))}
        raw_store = _canonical(store)
        _require(len(raw_store) <= maximum_root_bytes,
                 "captured-store root manifest exceeds its finite metadata ceiling")
        store_path = root / f"captured-evidence-v2-{store['store_sha256']}.json"
        _write_new(store_path, raw_store)
        for object_directory in objects.iterdir():
            _fsync_directory(object_directory)
        _fsync_directory(objects)
        _fsync_directory(metadata)
        _fsync_directory(root)
        pin = {"path": str(store_path), "raw_sha256": _sha(raw_store),
               "semantic_sha256": store["store_sha256"]}
        return store, pin
    except BaseException:
        shutil.rmtree(objects, ignore_errors=True)
        shutil.rmtree(metadata, ignore_errors=True)
        for candidate in root.iterdir():
            if candidate.is_file() and not candidate.is_symlink():
                candidate.unlink()
        raise


class CapturedEvidenceStoreV2:
    """Lazy path lookup over authenticated captured-store metadata chunks."""

    def __init__(self, root: dict[str, Any], root_pin: dict[str, str],
                 root_byte_count: int):
        self.root = root
        self.schema = root["schema"]
        self.root_pin = root_pin
        self.root_byte_count = root_byte_count
        self.object_root = Path(root["object_directory"])
        self.chunks = root["metadata_chunks"]
        self.first_paths = [item["first_path"] for item in self.chunks]
        self._cache: OrderedDict[int, list[dict[str, Any]]] = OrderedDict()
        self._count = root["entry_count"]

    def __len__(self) -> int:
        return self._count

    def __iter__(self) -> Iterator[str]:
        for index in range(len(self.chunks)):
            for row in self._chunk_rows(index):
                yield row["origin_path"]

    def _chunk_rows(self, index: int) -> list[dict[str, Any]]:
        cached = self._cache.get(index)
        if cached is not None:
            self._cache.move_to_end(index)
            return cached
        descriptor = self.chunks[index]
        path = Path(descriptor["path"])
        _private_directory(path.parent.parent)
        _private_directory(path.parent)
        chunk_raw, chunk_digest, byte_count = _read_stable_regular_file(
            path, DEFAULT_CHUNK_BYTES, "captured-store metadata chunk",
            expected_bytes=descriptor["byte_count"],
        )
        _require(chunk_raw is not None and
                 chunk_digest == descriptor["raw_sha256"] ==
                    descriptor["semantic_sha256"] and
                 byte_count <= DEFAULT_CHUNK_BYTES,
                 "captured-store metadata chunk raw/semantic pin differs")
        rows: list[dict[str, Any]] = []
        prior = ""
        with io.BytesIO(chunk_raw) as stream:
            while True:
                line = stream.readline(MAX_ROW_BYTES + 1)
                if not line:
                    break
                _require(len(line) <= MAX_ROW_BYTES and line.endswith(b"\n") and
                         b"\r" not in line,
                         "captured-store metadata row framing/width differs")
                try:
                    value = json.loads(line.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise EvidenceTransportError(
                        "captured-store metadata row is malformed"
                    ) from error
                row = _exact(value, {
                    "role", "host_id", "origin_path", "local_path", "raw_sha256",
                    "semantic_sha256", "byte_count", "maximum_bytes",
                }, "captured-store metadata row")
                origin = _path(row["origin_path"], "captured-store origin path")
                local = _path(row["local_path"], "captured-store local path")
                _require(line == _canonical(row) and origin > prior and
                         type(row["role"]) is str and bool(row["role"]) and
                         (row["host_id"] is None or
                          (type(row["host_id"]) is str and bool(row["host_id"]))),
                         "captured-store lazy row is noncanonical or malformed")
                _digest(row["raw_sha256"], "captured-store lazy row raw digest")
                semantic = row["semantic_sha256"]
                _require(semantic is None or
                         (type(semantic) is str and
                          re.fullmatch(r"[0-9a-f]{64}", semantic) is not None),
                         "captured-store lazy row semantic digest is malformed")
                count = _uint(row["byte_count"], "captured-store lazy row byte count")
                maximum = _uint(row["maximum_bytes"],
                                "captured-store lazy row byte ceiling")
                _require(count <= maximum,
                         "captured-store lazy row exceeds its owner byte ceiling")
                origin_name = hashlib.sha256(origin.encode("utf-8")).hexdigest()
                expected_object = (self.object_root / origin_name[:2] /
                                   f"{origin_name}-{row['raw_sha256']}.bin")
                _require(local == str(expected_object),
                         "captured-store lazy object path differs from its content address")
                prior = origin
                rows.append(row)
        _require(bool(rows) and len(rows) == descriptor["entry_count"] and
                 rows[0]["origin_path"] == descriptor["first_path"] and
                 rows[-1]["origin_path"] == descriptor["last_path"] and
                 len(chunk_raw) == descriptor["byte_count"],
                 "captured-store metadata chunk digest/range/count differs")
        self._cache[index] = rows
        if len(self._cache) > 1:
            self._cache.popitem(last=False)
        return rows

    def get(self, path_value: object, default: Any = None) -> dict[str, Any] | Any:
        path = _path(path_value, "captured-store lookup path")
        index = bisect.bisect_right(self.first_paths, path) - 1
        if index < 0 or path > self.chunks[index]["last_path"]:
            return default
        rows = self._chunk_rows(index)
        starts = [row["origin_path"] for row in rows]
        position = bisect.bisect_left(starts, path)
        if position >= len(rows) or starts[position] != path:
            return default
        row = dict(rows[position])
        row["raw_bytes"] = CapturedObjectV2(
            self.object_root, Path(row["local_path"]), row["byte_count"],
        )
        return row

    def __getitem__(self, path: str) -> dict[str, Any]:
        result = self.get(path)
        if result is None:
            raise KeyError(path)
        return result

    def items(self) -> Iterator[tuple[str, dict[str, Any]]]:
        for index in range(len(self.chunks)):
            for raw_row in self._chunk_rows(index):
                row = dict(raw_row)
                row["raw_bytes"] = CapturedObjectV2(
                    self.object_root, Path(row["local_path"]), row["byte_count"],
                )
                yield row["origin_path"], row


class CapturedObjectV2:
    """Reopen one captured object through no-follow directory descriptors."""

    source5_captured_object_v2 = True

    def __init__(self, object_root: Path, path: Path, byte_count: int):
        self.object_root = object_root
        self.path = path
        self.byte_count = byte_count

    def __fspath__(self) -> str:
        return str(self.path)

    def __str__(self) -> str:
        return str(self.path)

    def open_stream(self) -> io.BufferedReader:
        root = self.object_root
        relative = self.path.relative_to(root)
        _require(len(relative.parts) == 2,
                 "captured object path is outside its one-level shard layout")
        root_fd = None
        current_fd = None
        descriptor = None
        try:
            _require(root.resolve(strict=True) == root,
                     "captured object root traverses an alias")
            root_info = root.lstat()
            root_fd = os.open(
                root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            opened_root = os.fstat(root_fd)
            _require(stat.S_ISDIR(opened_root.st_mode) and
                     opened_root.st_uid == os.getuid() and
                     stat.S_IMODE(opened_root.st_mode) == 0o700 and
                     (opened_root.st_dev, opened_root.st_ino) ==
                     (root_info.st_dev, root_info.st_ino),
                     "captured object root is not stable private directory custody")
            shard_name, object_name = relative.parts
            current_fd = os.open(
                shard_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            shard_info = os.fstat(current_fd)
            _require(stat.S_ISDIR(shard_info.st_mode) and
                     shard_info.st_uid == os.getuid() and
                     stat.S_IMODE(shard_info.st_mode) == 0o700,
                     "captured object shard is not an owned mode-0700 directory")
            descriptor = os.open(
                object_name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=current_fd,
            )
            info = os.fstat(descriptor)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o600 and
                     info.st_nlink == 1 and info.st_size == self.byte_count,
                     "captured object is not an exact owned private regular file")
            stream = io.BufferedReader(io.FileIO(descriptor, mode="rb", closefd=True))
            descriptor = None
            return stream
        except OSError as error:
            raise EvidenceTransportError(
                f"cannot safely open captured object {self.path}: {error}"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if current_fd is not None:
                os.close(current_fd)
            if root_fd is not None:
                os.close(root_fd)

    def open(self, mode: str = "rb") -> io.BufferedReader:
        _require(mode == "rb", "captured objects are read-only")
        return self.open_stream()


def open_captured_store_v2(
    pin_value: object, *, budget_pin: object,
    index_pin: object, origin_receipt_pin: object,
    maximum_entries: int, maximum_payload_bytes: int,
    maximum_metadata_bytes: int,
    maximum_root_bytes: int = MAX_MANIFEST_BYTES,
) -> CapturedEvidenceStoreV2:
    """Verify the complete metadata/object closure before returning a lazy store."""
    _require(type(maximum_entries) is int and
             0 < maximum_entries <= MAX_STORE_ROWS and
             type(maximum_payload_bytes) is int and
             0 < maximum_payload_bytes <= MAX_U64 and
             type(maximum_metadata_bytes) is int and
             0 < maximum_metadata_bytes <= MAX_U64 and
             type(maximum_root_bytes) is int and
             0 < maximum_root_bytes <= MAX_MANIFEST_BYTES,
             "captured-store reader ceilings are outside their finite bounds")
    pin = _pin(pin_value, "captured-store root pin")
    path = Path(pin["path"])
    value, raw, raw_sha = _read_canonical_file(
        pin["path"], maximum_root_bytes, "captured-store root manifest",
    )
    body = {key: item for key, item in value.items() if key != "store_sha256"}
    _exact(value, {
        "schema", "campaign_id", "host_id", "host_evidence_budget",
        "evidence_index", "origin_receipt", "entry_count", "payload_bytes",
        "metadata_bytes", "metadata_chunks", "object_directory", "store_sha256",
    }, "captured-store v2 root")
    _require(value["schema"] == CAPTURED_STORE_SCHEMA_V2 and
             value["host_evidence_budget"] == _pin(budget_pin, "request budget pin") and
             value["evidence_index"] == _pin(index_pin, "request index pin") and
             value["origin_receipt"] == _pin(origin_receipt_pin, "request receipt pin") and
             value["store_sha256"] == pin["semantic_sha256"] == _sha(_canonical(body)) and
             raw_sha == pin["raw_sha256"],
             "captured-store root schema/digest/external pins differ")
    count = _uint(value["entry_count"], "captured-store entry count", positive=True)
    payload = _uint(value["payload_bytes"], "captured-store payload bytes")
    metadata_size = _uint(value["metadata_bytes"], "captured-store metadata bytes")
    _require(count <= maximum_entries and payload <= maximum_payload_bytes and
             metadata_size <= maximum_metadata_bytes and
             type(value["metadata_chunks"]) is list and
             bool(value["metadata_chunks"]),
             "captured-store count/payload/metadata exceeds its pinned budget")
    previous = ""
    observed_count = 0
    observed_metadata = 0
    observed_payload = 0
    object_root = Path(_path(value["object_directory"],
                             "captured-store object directory"))
    _require(path.resolve(strict=True) == path and
             object_root == path.parent / "objects",
             "captured-store root/object paths differ from their fixed private layout")
    _private_directory(object_root)
    _private_directory(path.parent)
    metadata_root = path.parent / "metadata"
    _private_directory(metadata_root)
    for position, descriptor_value in enumerate(value["metadata_chunks"]):
        descriptor = _exact(descriptor_value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "entry_count", "first_path", "last_path",
        }, f"captured-store metadata descriptor[{position}]")
        _path(descriptor["path"], "captured-store metadata chunk path")
        _digest(descriptor["raw_sha256"], "captured-store metadata raw digest")
        _digest(descriptor["semantic_sha256"], "captured-store metadata semantic digest")
        chunk_path = Path(descriptor["path"])
        _require(chunk_path.is_relative_to(metadata_root) and
                 chunk_path.resolve(strict=True) == chunk_path,
                 "captured-store metadata chunk escapes its fixed private directory")
        descriptor_bytes = _uint(
            descriptor["byte_count"],
            "captured-store metadata chunk byte count", positive=True,
        )
        _require(descriptor_bytes <= DEFAULT_CHUNK_BYTES and
                 observed_metadata + descriptor_bytes <= metadata_size and
                 observed_metadata + descriptor_bytes <= maximum_metadata_bytes,
                 "captured-store metadata chunk exceeds its remaining byte budget")
        descriptor_entries = _uint(
            descriptor["entry_count"],
            "captured-store chunk entry count", positive=True,
        )
        _require(descriptor_entries <= count - observed_count,
                 "captured-store metadata chunk exceeds its remaining root entry count")
        first = _path(descriptor["first_path"], "captured-store chunk first path")
        last = _path(descriptor["last_path"], "captured-store chunk last path")
        _require(first > previous and first <= last,
                 "captured-store metadata ranges are not sorted/disjoint")
        previous = last
        chunk_raw, chunk_digest, actual_chunk_bytes = _read_stable_regular_file(
            chunk_path, DEFAULT_CHUNK_BYTES,
            f"captured-store metadata chunk[{position}]",
            expected_bytes=descriptor_bytes,
        )
        _require(chunk_raw is not None,
                 "captured-store metadata chunk reader returned no bytes")
        rows = 0
        first_observed = ""
        last_observed = ""
        with io.BytesIO(chunk_raw) as stream:
            while True:
                line = stream.readline(MAX_ROW_BYTES + 1)
                if not line:
                    break
                _require(len(line) <= MAX_ROW_BYTES and line.endswith(b"\n") and
                         b"\r" not in line,
                         "captured-store metadata framing/row width differs")
                try:
                    row_value = json.loads(line.decode("ascii"))
                except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                    raise EvidenceTransportError("captured-store metadata is malformed") from error
                row = _exact(row_value, {
                    "role", "host_id", "origin_path", "local_path", "raw_sha256",
                    "semantic_sha256", "byte_count", "maximum_bytes",
                }, "captured-store metadata row")
                origin = _path(row["origin_path"], "captured origin path")
                local = _path(row["local_path"], "captured local path")
                _require(line == _canonical(row) and origin > last_observed and
                         type(row["role"]) is str and bool(row["role"]) and
                         (row["host_id"] is None or
                          (type(row["host_id"]) is str and row["host_id"])),
                         "captured-store rows are noncanonical, unordered or have malformed roles")
                _digest(row["raw_sha256"], "captured object raw digest")
                semantic = row["semantic_sha256"]
                _require(semantic is None or
                         (type(semantic) is str and
                          re.fullmatch(r"[0-9a-f]{64}", semantic) is not None),
                         "captured object semantic digest is malformed")
                object_bytes = _uint(row["byte_count"], "captured object byte count")
                maximum = _uint(row["maximum_bytes"],
                                "captured object byte ceiling")
                _require(object_bytes <= maximum and
                         observed_count < count and
                         observed_count + 1 <= maximum_entries and
                         observed_payload + object_bytes <= payload and
                         observed_payload + object_bytes <= maximum_payload_bytes,
                         "captured object exceeds its owner byte ceiling")
                object_path = Path(local)
                origin_name = hashlib.sha256(origin.encode("utf-8")).hexdigest()
                expected_object_path = (object_root / origin_name[:2] /
                                        f"{origin_name}-{row['raw_sha256']}.bin")
                _require(object_path == expected_object_path and
                         object_path.is_relative_to(object_root),
                         "captured object path differs from its content-addressed identity")
                object_hasher = hashlib.sha256()
                object_count = 0
                object_ref = CapturedObjectV2(
                    object_root, object_path, object_bytes,
                )
                with object_ref.open_stream() as object_stream:
                    while True:
                        block = object_stream.read(1024 * 1024)
                        if not block:
                            break
                        object_count += len(block)
                        _require(object_count <= maximum and
                                 object_count <= object_bytes and
                                 observed_payload + object_count <= payload and
                                 observed_payload + object_count <= maximum_payload_bytes,
                                 "captured object grew beyond its owner ceiling")
                        object_hasher.update(block)
                _require(object_count == object_bytes and
                         object_hasher.hexdigest() == row["raw_sha256"],
                         "captured object raw bytes differ from their exact pin")
                observed_payload += object_count
                rows += 1
                observed_count += 1
                _require(observed_count <= count and
                         observed_count <= maximum_entries and
                         observed_payload <= payload and
                         observed_payload <= maximum_payload_bytes,
                         "captured-store rows exceed their remaining root count/payload budget")
                if rows == 1:
                    first_observed = origin
                last_observed = origin
        _require(rows == descriptor_entries and
                 first_observed == first and last_observed == last and
                 actual_chunk_bytes == descriptor_bytes and
                 chunk_digest == descriptor["raw_sha256"] ==
                    descriptor["semantic_sha256"],
                 "captured-store chunk digest/range/count differs")
        observed_metadata += descriptor_bytes
        _require(observed_metadata <= metadata_size and
                 observed_metadata <= maximum_metadata_bytes,
                 "captured-store metadata exceeds its root byte ceiling")
    _require(observed_count == count and observed_metadata == metadata_size and
             observed_payload == payload,
             "captured-store root count/byte totals differ from its exact streamed closure")
    return CapturedEvidenceStoreV2(value, pin, len(raw))
