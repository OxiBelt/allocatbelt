#!/usr/bin/env python3
"""Run bounded functional-only native pair receipts from an explicitly pinned build.

This helper never creates qualification evidence. It checks out one signed
source revision, freezes a functional-only build/calibration overlay, and writes
its logs and output outside the source checkout.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import resource
import secrets
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


SIGNED_SOURCE_COMMIT = "9290a2b194a667aba8816020214230d111ab80a3"
SIGNED_CONTROLLER_SHA256 = "1947fe29efa932bf4b8a3bc30a7390151f2f21cb940b18204c8da5225bc157e4"
SOURCE_INVENTORY_MODULE_SHA256 = "09557087a64e83bc81e4116f8e8f6b59e42a59beb500108e57d66942bd05f950"
FUNCTIONAL_LIMITS = {
    "max_arrivals": 1000,
    "max_rate_per_second": 1000,
    "max_trace_deadline_seconds": 30,
    "max_drain_deadline_seconds": 30,
    "max_shutdown_deadline_seconds": 15,
    "max_process_deadline_seconds": 300,
}
WORKLOAD = "cpu"
PROFILE = "steady"
MODE = "open_loop"
_CAMPAIGN: Any | None = None
_SOURCE_INVENTORY: Any | None = None
MAX_SMALL_ARTIFACT_BYTES = 128 * 1024
MAX_CAMPAIGN_SOURCE_BYTES = 4 * 1024 * 1024
SOURCE_MANIFEST_SCHEMA_V4 = "allocatbelt.application-source-manifest.v4"
SOURCE_V4_REPORT_SCHEMA = "allocatbelt.application-functional-v4-report.v1"
SOURCE_V4_PAIR_OVERLAY_SCHEMA = "allocatbelt.application-functional-pair-overlay.v3"
SOURCE_V4_SOURCE_OVERLAY_SCHEMA = "allocatbelt.application-functional-source-overlay.v3"
SOURCE_V4_FUNCTIONAL_LIMITS = {
    "max_arrivals": 1000,
    "max_rate_per_second": 1000,
    "max_trace_deadline_seconds": 30,
    "max_drain_deadline_seconds": 30,
    "max_shutdown_deadline_seconds": 15,
    "max_process_deadline_seconds": 300,
    "max_pair_deadline_seconds": 600,
    "capacity_horizon_seconds": 30,
    "max_source_manifest_bytes": 16 * 1024 * 1024,
    "max_file_bytes": 16 * 1024 * 1024,
    "max_output_files": 512,
    "max_output_directories": 128,
    "max_output_entries": 1024,
    "max_output_bytes": 256 * 1024 * 1024,
    "minimum_free_bytes": 256 * 1024 * 1024,
}
MAX_STABLE_HASH_BYTES = 512 * 1024 * 1024
TRUSTED_TOOL_PATH = "/usr/bin:/bin"
TRUSTED_GIT = "/usr/bin/git"
TRUSTED_GPG = "/usr/bin/gpg"
SOURCE_V4_CELL_PROFILES = {
    "cpu": ("steady", "burst", "oversubscribed"),
    "memory": ("steady", "burst", "oversubscribed"),
    "http": ("steady", "burst", "oversubscribed"),
    "disk": ("steady", "burst", "oversubscribed"),
    "mixed": ("mixed", "burst", "oversubscribed"),
}
SOURCE_V4_CELLS = tuple(
    (workload, profile)
    for workload, profiles in SOURCE_V4_CELL_PROFILES.items()
    for profile in profiles
)
SOURCE_V4_BASELINES = ("mimalloc-secure", "mimalloc-standard", "system")
RUNNER_RESULT_HEADER = (
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


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
        require(before.st_size <= maximum, f"{label} exceeds its finite size bound")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(descriptor, min(64 * 1024, maximum + 1 - count))
            if not block:
                break
            count += len(block)
            require(count <= maximum, f"{label} exceeds its finite size bound")
            chunks.append(block)
            digest.update(block)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        require(
            (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and count == before.st_size
            and stat.S_ISREG(current.st_mode)
            and (current.st_dev, current.st_ino, current.st_mode)
            == (before.st_dev, before.st_ino, before.st_mode),
            f"{label} changed while taking its bounded snapshot",
        )
    finally:
        os.close(descriptor)
    return b"".join(chunks), digest.hexdigest()


def hash_stable(path: Path, maximum: int = MAX_STABLE_HASH_BYTES) -> tuple[str, int]:
    require(0 <= maximum <= MAX_STABLE_HASH_BYTES, "streaming hash ceiling is outside its finite bound")
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    count = 0
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"hash input is not a regular file: {path}")
        require(before.st_size <= maximum, f"hash input exceeds its finite size bound: {path}")
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - count))
            if not block:
                break
            count += len(block)
            require(count <= maximum, f"hash input exceeded its finite size bound: {path}")
            digest.update(block)
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        require(
            (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            and count == before.st_size
            and stat.S_ISREG(current.st_mode)
            and (current.st_dev, current.st_ino, current.st_mode)
            == (before.st_dev, before.st_ino, before.st_mode),
            f"hash input changed while streaming: {path}",
        )
    finally:
        os.close(descriptor)
    return digest.hexdigest(), count


def fail(message: str) -> None:
    raise RuntimeError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_campaign_module(source_root: Path) -> Any:
    path = source_root / "scripts" / "application-campaign.py"
    source, source_sha256 = read_stable(path, "signed campaign controller source", MAX_CAMPAIGN_SOURCE_BYTES)
    require(source_sha256 == SIGNED_CONTROLLER_SHA256, "campaign controller differs from the pinned signed source")
    module = types.ModuleType("functional_e2e_application_campaign")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def load_source_inventory_module() -> Any:
    path = Path(__file__).with_name("application-source-inventory.py")
    source, source_sha256 = read_stable(path, "shared source inventory module", MAX_CAMPAIGN_SOURCE_BYTES)
    require(source_sha256 == SOURCE_INVENTORY_MODULE_SHA256, "shared source inventory module differs from its frozen SHA-256")
    module = types.ModuleType("functional_e2e_source_inventory")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise RuntimeError(f"shared source inventory module cannot be compiled: {error}") from error
    require(module.SCHEMA == "allocatbelt.application-source-inventory.v1", "shared source inventory module has an unexpected schema")
    return module


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_stdlib(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"source manifest is not canonical JSON data: {error}") from error


def _stable_link_target(path: Path) -> bytes:
    before = path.lstat()
    require(stat.S_ISLNK(before.st_mode), f"source inventory link is not a symlink: {path}")
    target = os.readlink(os.fsencode(path))
    if isinstance(target, str):
        target = os.fsencode(target)
    after = path.lstat()
    require(
        (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        and stat.S_ISLNK(after.st_mode),
        f"source inventory symlink changed during capture: {path}",
    )
    return target


def _tree_record_path(root: Path, relative: str) -> Path:
    require(type(relative) is str and relative and "\\" not in relative and "\0" not in relative,
            "source inventory path is malformed")
    rel = Path(relative)
    require(not rel.is_absolute() and ".." not in rel.parts and rel.as_posix() == relative,
            "source inventory path is not normalized")
    cursor = root
    for part in rel.parts[:-1]:
        cursor /= part
        require(not cursor.is_symlink() and cursor.is_dir(), f"source inventory parent is not a regular directory: {relative}")
    return cursor / rel.parts[-1]


def verify_source_tree_before_controller_exec(source_root: Path, source: dict[str, Any], commit: str) -> None:
    """Use stdlib snapshots and inert Git listings to bind the live tree before executing source code."""
    records = source.get("files")
    require(type(records) is list and 0 < len(records) <= 100_000,
            "SourceSchemaV4 inventory is missing or exceeds the finite entry bound")
    require(all(type(record) is dict and type(record.get("path")) is str for record in records),
            "SourceSchemaV4 inventory paths are malformed")
    require(records == sorted(records, key=lambda record: record["path"].encode("utf-8")),
            "SourceSchemaV4 inventory records are not UTF-8 byte sorted")
    record_by_path: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for record in records:
        require(type(record) is dict, "SourceSchemaV4 inventory record is malformed")
        path_text = record.get("path")
        require(type(path_text) is str and path_text not in record_by_path,
                "SourceSchemaV4 inventory repeats or malforms a path")
        _tree_record_path(source_root, path_text)
        require(record.get("kind") in ("file", "symlink")
                and record.get("mode") in ("100644", "100755", "120000")
                and type(record.get("size")) is int and 0 <= record["size"] <= 64 * 1024 * 1024
                and type(record.get("sha256")) is str
                and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None,
                f"SourceSchemaV4 inventory record fields are malformed: {path_text}")
        require((record["kind"], record["mode"]) in (("file", "100644"), ("file", "100755"), ("symlink", "120000")),
                f"SourceSchemaV4 inventory kind/mode differs: {path_text}")
        if record["kind"] == "symlink":
            require(set(record) == {"path", "kind", "mode", "target", "sha256", "size"}
                    and type(record["target"]) is str and len(record["target"].encode("utf-8")) <= 4096,
                    f"SourceSchemaV4 symlink record is malformed: {path_text}")
        else:
            require(set(record) == {"path", "kind", "mode", "sha256", "size"}
                    and record["size"] <= 64 * 1024 * 1024,
                    f"SourceSchemaV4 file record is malformed: {path_text}")
        total_bytes += record["size"]
        require(total_bytes <= 2 * 1024 * 1024 * 1024,
                "SourceSchemaV4 inventory exceeds the finite total-byte bound")
        record_by_path[path_text] = record

    git_object_width = len(commit)
    require(git_object_width in (40, 64), "SourceSchemaV4 Git object format is unsupported")
    tree_raw = _run_trusted_git(["ls-tree", "-r", "-z", "--full-tree", commit], source_root, 60).stdout
    committed: dict[str, tuple[str, str, str]] = {}
    for framed in tree_raw.split(b"\0"):
        if not framed:
            continue
        header, separator, path_raw = framed.partition(b"\t")
        require(bool(separator), "Git committed-tree listing is malformed")
        fields = header.split(b" ")
        require(len(fields) == 3 and fields[1] == b"blob", "Git committed source contains a non-blob entry")
        try:
            path_text = path_raw.decode("utf-8", errors="strict")
            mode, object_id = fields[0].decode("ascii"), fields[2].decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError("Git committed source path/mode is not UTF-8/ASCII") from error
        require(path_text not in committed and mode in ("100644", "100755", "120000")
                and len(object_id) == git_object_width and re.fullmatch(r"[0-9a-f]+", object_id) is not None,
                "Git committed source record is duplicated or malformed")
        committed[path_text] = (mode, object_id, "blob")
    require(set(committed) == set(record_by_path),
            "SourceSchemaV4 inventory paths differ from the pinned Git commit tree")

    staged_raw = _run_trusted_git(["ls-files", "--stage", "-z"], source_root, 60).stdout
    staged: dict[str, tuple[str, str]] = {}
    for framed in staged_raw.split(b"\0"):
        if not framed:
            continue
        header, separator, path_raw = framed.partition(b"\t")
        require(bool(separator), "Git index listing is malformed")
        fields = header.split(b" ")
        require(len(fields) == 3 and fields[2] == b"0", "Git index has an unmerged or malformed source entry")
        try:
            path_text = path_raw.decode("utf-8", errors="strict")
            mode, object_id = fields[0].decode("ascii"), fields[1].decode("ascii")
        except UnicodeDecodeError as error:
            raise RuntimeError("Git index path/mode is not UTF-8/ASCII") from error
        require(path_text not in staged and len(object_id) == git_object_width
                and re.fullmatch(r"[0-9a-f]+", object_id) is not None,
                "Git index entry is duplicated or malformed")
        staged[path_text] = (mode, object_id)
    require(staged == {path: (mode, object_id) for path, (mode, object_id, _kind) in committed.items()},
            "Git index differs from the caller-pinned commit")
    untracked_raw = _run_trusted_git(["ls-files", "--others", "--exclude-standard", "-z"], source_root, 60).stdout
    require(not untracked_raw, "SourceSchemaV4 source root has non-ignored untracked files")

    for path_text, record in record_by_path.items():
        path = _tree_record_path(source_root, path_text)
        expected_mode, expected_object_id, _kind = committed[path_text]
        require(record["mode"] == expected_mode, f"SourceSchemaV4 inventory mode differs from signed Git tree: {path_text}")
        if expected_mode == "120000":
            target_raw = _stable_link_target(path)
            try:
                target_text = target_raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise RuntimeError(f"SourceSchemaV4 symlink target is not UTF-8: {path_text}") from error
            require(target_text == record["target"] and len(target_raw) == record["size"]
                    and hashlib.sha256(target_raw).hexdigest() == record["sha256"],
                    f"SourceSchemaV4 symlink differs from signed record: {path_text}")
            hash_module = hashlib.sha1 if git_object_width == 40 else hashlib.sha256
            git_blob = hash_module(b"blob " + str(len(target_raw)).encode("ascii") + b"\0" + target_raw).hexdigest()
        else:
            raw, digest = read_stable(path, f"pre-controller signed source file {path_text}", 64 * 1024 * 1024)
            file_mode = "100755" if path.stat(follow_symlinks=False).st_mode & 0o111 else "100644"
            require(file_mode == expected_mode and digest == record["sha256"] and len(raw) == record["size"],
                    f"SourceSchemaV4 file differs from signed record: {path_text}")
            hash_module = hashlib.sha1 if git_object_width == 40 else hashlib.sha256
            git_blob = hash_module(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        require(git_blob == expected_object_id, f"working tree bytes differ from the signed Git blob: {path_text}")

    inventory_digest = hashlib.sha256(canonical_stdlib({
        "schema": "allocatbelt.application-source-inventory.v1", "entries": records,
    })).hexdigest()
    require(inventory_digest == source.get("source_tree_sha256"),
            "SourceSchemaV4 typed inventory digest is invalid before controller execution")
    inventory_engine = record_by_path.get("scripts/application-source-inventory.py")
    require(inventory_engine is not None and inventory_engine["kind"] == "file"
            and inventory_engine["sha256"] == SOURCE_INVENTORY_MODULE_SHA256,
            "SourceSchemaV4 inventory does not bind the independently pinned inventory engine")


class BytesArtifactPath:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def open(self, mode: str = "rb") -> io.BytesIO:
        require(mode == "rb", "receipt adapter only supports read-only binary access")
        return io.BytesIO(self.raw)


def read_metadata(path: Path) -> dict[str, str]:
    _header, rows = _CAMPAIGN.read_tsv(path)
    result: dict[str, str] = {}
    for row in rows:
        key = row["key"]
        require(key not in result, f"metadata repeats key {key}")
        result[key] = row["value"]
    return result


def run_bounded(
    argv: list[str], cwd: Path, stdout_path: Path, stderr_path: Path, timeout_seconds: int,
    *, env: dict[str, str] | None = None, file_size_limit_bytes: int | None = None,
    watch_root: Path | None = None,
) -> int:
    require(0 < timeout_seconds <= 600, "child timeout exceeds the functional envelope")
    process: subprocess.Popen[bytes] | None = None
    received_signal: int | None = None
    stop_started: float | None = None
    timed_out = False
    failure: str | None = None
    grace_seconds = 1.0
    code: int | None = None
    old_handlers: dict[int, Any] = {}

    def send_to_group(signum: int) -> None:
        if process is not None:
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass

    def request_stop(signum: int, _frame: Any) -> None:
        nonlocal received_signal, stop_started
        if received_signal is None:
            received_signal = signum
        if stop_started is None:
            stop_started = time.monotonic()
        send_to_group(signal.SIGTERM)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, request_stop)
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            os.fchmod(stdout.fileno(), 0o600)
            os.fchmod(stderr.fileno(), 0o600)
            def set_file_size_limit() -> None:
                if file_size_limit_bytes is None:
                    return
                require(file_size_limit_bytes > 0, "child file-size limit must be positive")
                _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
                require(hard == resource.RLIM_INFINITY or hard >= file_size_limit_bytes,
                        "child hard file-size limit cannot provide the requested exact bound")
                resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_limit_bytes, file_size_limit_bytes))
                actual_soft, actual_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
                require((actual_soft, actual_hard) == (file_size_limit_bytes, file_size_limit_bytes),
                        "child file-size soft/hard limits differ from the exact requested bound")

            process = subprocess.Popen(
                argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                close_fds=True, start_new_session=True, env=env,
                preexec_fn=set_file_size_limit if file_size_limit_bytes is not None else None,
            )
            if stop_started is not None:
                send_to_group(signal.SIGTERM)
            deadline = time.monotonic() + timeout_seconds
            while True:
                now = time.monotonic()
                if now >= deadline and stop_started is None:
                    timed_out = True
                    stop_started = now
                    send_to_group(signal.SIGTERM)
                if watch_root is not None and failure is None:
                    try:
                        enforce_functional_tree_budget(watch_root)
                    except Exception as error:
                        failure = f"functional output budget exceeded while child was running: {error}"
                        if stop_started is None:
                            stop_started = now
                            send_to_group(signal.SIGTERM)
                if stop_started is not None and now >= stop_started + grace_seconds:
                    send_to_group(signal.SIGKILL)
                if stop_started is not None and now >= stop_started + 3 * grace_seconds and process.poll() is None:
                    failure = failure or "child did not exit after bounded process-group termination"
                    break
                try:
                    code = process.wait(timeout=0.05)
                    # A normal leader exit must not leave helpers in its process group.
                    if stop_started is None:
                        try:
                            os.killpg(process.pid, 0)
                        except ProcessLookupError:
                            pass
                        else:
                            stop_started = time.monotonic()
                            send_to_group(signal.SIGTERM)
                    break
                except subprocess.TimeoutExpired:
                    continue
    finally:
        if process is not None:
            if stop_started is None:
                stop_started = time.monotonic()
                send_to_group(signal.SIGTERM)
            cleanup_deadline = time.monotonic() + grace_seconds
            while time.monotonic() < cleanup_deadline:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    break
                try:
                    process.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    pass
            # The reaped leader can leave descendants in its original process group.
            send_to_group(signal.SIGKILL)
            if process.poll() is None:
                try:
                    process.wait(timeout=grace_seconds)
                except subprocess.TimeoutExpired:
                    failure = failure or "child leader remained alive after SIGKILL"
        for signum, old_handler in old_handlers.items():
            signal.signal(signum, old_handler)
    if received_signal is not None:
        return 128 + received_signal
    if failure is not None:
        raise RuntimeError(failure)
    if timed_out:
        return 124
    return 1 if code is None else code


def hash_path(path: Path) -> str:
    return hash_stable(path)[0]


def functional_tree_usage(
    root: Path, *, max_files: int, max_bytes: int, max_directories: int,
    max_entries: int,
) -> dict[str, int]:
    """Count every output-tree entry without following links or special files."""
    require(root.is_dir() and not root.is_symlink(), f"functional output tree is missing or symlinked: {root}")
    files = 0
    directories = 0
    entries = 0
    size = 0
    for path in root.rglob("*"):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), f"functional output tree contains a symlink: {path}")
        entries += 1
        require(entries <= max_entries, "functional output tree exceeds its finite entry-count budget")
        if stat.S_ISDIR(info.st_mode):
            directories += 1
            require(directories <= max_directories,
                    "functional output tree exceeds its finite directory-count budget")
            continue
        require(stat.S_ISREG(info.st_mode), f"functional output tree contains a special file: {path}")
        files += 1
        size += info.st_size
        require(files <= max_files, "functional output tree exceeds its finite file-count budget")
        require(size <= max_bytes, "functional output tree exceeds its finite byte budget")
    return {"files": files, "directories": directories, "entries": entries, "bytes": size}


def enforce_functional_tree_budget(root: Path) -> dict[str, Any]:
    usage = functional_tree_usage(
        root, max_files=SOURCE_V4_FUNCTIONAL_LIMITS["max_output_files"],
        max_bytes=SOURCE_V4_FUNCTIONAL_LIMITS["max_output_bytes"],
        max_directories=SOURCE_V4_FUNCTIONAL_LIMITS["max_output_directories"],
        max_entries=SOURCE_V4_FUNCTIONAL_LIMITS["max_output_entries"],
    )
    filesystem = filesystem_context(root)
    require(filesystem["free_bytes"] >= SOURCE_V4_FUNCTIONAL_LIMITS["minimum_free_bytes"],
            "functional output filesystem fell below its live free-space reserve")
    return {**usage, "filesystem_free_bytes": filesystem["free_bytes"]}


def _mount_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def filesystem_context(path: Path) -> dict[str, Any]:
    """Return the mount and capacity context that contains a functional path."""
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    mountinfo = Path("/proc/self/mountinfo").read_bytes()
    require(len(mountinfo) <= 2 * 1024 * 1024, "mount table exceeds its finite bound")
    selected: tuple[int, str, str, str, str] | None = None
    for line in mountinfo.decode("utf-8", errors="strict").splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        before = left.split()
        after = right.split()
        if len(before) < 5 or len(after) < 2:
            continue
        mount_point = _mount_unescape(before[4])
        if resolved == Path(mount_point) or Path(mount_point) in resolved.parents:
            candidate = (len(mount_point), mount_point, after[0], after[1], before[2])
            if selected is None or candidate[0] > selected[0]:
                selected = candidate
    require(selected is not None, f"cannot determine the mounted filesystem for {resolved}")
    _length, mount_point, filesystem_type, source, device = selected
    stats = os.statvfs(resolved)
    return {
        "path": str(resolved),
        "mount_point": mount_point,
        "filesystem_type": filesystem_type,
        "source": source,
        "mount_device": device,
        "st_dev": info.st_dev,
        "free_bytes": stats.f_bavail * stats.f_frsize,
    }


def require_rootfs_storage_context(output_root: Path, temporary_root: Path) -> dict[str, Any]:
    output_context = filesystem_context(output_root)
    temporary_context = filesystem_context(temporary_root)
    require(
        temporary_context["st_dev"] == output_context["st_dev"]
        and temporary_context["mount_point"] == output_context["mount_point"]
        and temporary_context["filesystem_type"] == output_context["filesystem_type"]
        and temporary_context["filesystem_type"] not in ("tmpfs", "ramfs"),
        "functional TMPDIR must use the output root filesystem rather than a memory-backed mount",
    )
    require(
        output_context["free_bytes"] >= (
            SOURCE_V4_FUNCTIONAL_LIMITS["max_output_bytes"]
            + SOURCE_V4_FUNCTIONAL_LIMITS["minimum_free_bytes"]
        ),
        "output root filesystem lacks the finite functional storage reserve",
    )
    return {"output_root": output_context, "tmpdir_root": temporary_context}


def safe_source_file(source_root: Path, relative: str, label: str) -> tuple[Path, str, int]:
    require(type(relative) is str and relative and "\\" not in relative, f"{label} path is malformed")
    rel = Path(relative)
    require(not rel.is_absolute() and ".." not in rel.parts and rel.as_posix() == relative, f"{label} path is not portable")
    cursor = source_root
    for part in rel.parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), f"{label} path traverses a symlink: {relative}")
    resolved = cursor.resolve(strict=True)
    require(resolved.is_file(), f"{label} is not a regular file: {relative}")
    sha256, size = hash_stable(resolved)
    return resolved, sha256, size


def strict_nonsymlink_path(path: Path, label: str) -> Path:
    absolute = path.expanduser().absolute()
    require(".." not in absolute.parts, f"{label} path is not normalized")
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor /= part
        require(not cursor.is_symlink(), f"{label} path traverses a symlink: {cursor}")
    return absolute.resolve(strict=True)


def safe_external_path(source_root: Path) -> str:
    """Expose only the selected Cargo tool directory and standard system binaries."""
    root = source_root.resolve(strict=True)
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).expanduser()
    tool_bin = cargo_home / "bin"
    paths = ["/usr/bin", "/bin"]
    try:
        resolved_tool_bin = tool_bin.resolve(strict=True)
    except OSError:
        resolved_tool_bin = None
    if (resolved_tool_bin is not None and resolved_tool_bin.is_dir()
        and resolved_tool_bin != root and root not in resolved_tool_bin.parents
        and not (resolved_tool_bin / "git").exists()):
        paths.insert(0, str(resolved_tool_bin))
    return os.pathsep.join(paths)


def run_capture_bounded(
    argv: list[str], cwd: Path, timeout_seconds: int = 60, *,
    env: dict[str, str] | None = None,
    max_stdout_bytes: int = 16 * 1024 * 1024,
    max_stderr_bytes: int = 2 * 1024 * 1024,
) -> subprocess.CompletedProcess[bytes]:
    require(argv and 0 < timeout_seconds <= 600, "preflight command has an invalid finite deadline")
    require(0 <= max_stdout_bytes <= 16 * 1024 * 1024 and 0 <= max_stderr_bytes <= 2 * 1024 * 1024,
            "preflight command capture ceiling exceeds its fixed bounds")
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max_stdout_bytes, "stderr": max_stderr_bytes}
    eof: set[str] = set()
    failure: str | None = None
    received_signal: int | None = None
    stop_started: float | None = None
    kill_sent = False
    leader_exit_seen: float | None = None
    grace_seconds = 1.0
    old_handlers: dict[int, Any] = {}

    def signal_group(signum: int) -> None:
        if process is None:
            return
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass

    def request_stop(signum: int, _frame: Any) -> None:
        nonlocal received_signal, stop_started
        if received_signal is None:
            received_signal = signum
        if stop_started is None:
            stop_started = time.monotonic()
        signal_group(signal.SIGTERM)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, request_stop)
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
        )
        if stop_started is not None:
            signal_group(signal.SIGTERM)
        assert process.stdout is not None and process.stderr is not None
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout_seconds
        while True:
            now = time.monotonic()
            if now >= deadline and stop_started is None:
                failure = "preflight command exceeded its finite deadline"
                stop_started = now
                signal_group(signal.SIGTERM)
            if stop_started is not None and now >= stop_started + grace_seconds and not kill_sent:
                signal_group(signal.SIGKILL)
                kill_sent = True
            if (kill_sent and now >= stop_started + 2 * grace_seconds
                    and (process.poll() is None or len(eof) != 2)):
                failure = failure or "preflight command did not finish bounded process-group cleanup"
                break

            for key, _mask in selector.select(0.05):
                name = key.data
                try:
                    block = os.read(key.fileobj.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    eof.add(name)
                    continue
                remaining = limits[name] - len(buffers[name])
                if len(block) > remaining:
                    failure = failure or f"preflight {name} exceeded its finite capture ceiling"
                    if stop_started is None:
                        stop_started = time.monotonic()
                        signal_group(signal.SIGTERM)
                else:
                    buffers[name].extend(block)

            code = process.poll()
            if code is not None and len(eof) == 2:
                break
            if code is not None and len(eof) != 2 and stop_started is None:
                if leader_exit_seen is None:
                    leader_exit_seen = time.monotonic()
                elif time.monotonic() >= leader_exit_seen + 0.25:
                    # A command leader must not leave a helper or pipe holder behind.
                    stop_started = time.monotonic()
                    signal_group(signal.SIGTERM)

        code = process.poll()
        if code is None:
            failure = failure or "preflight command remained alive after bounded cleanup"
    except (OSError, ValueError) as error:
        failure = failure or f"cannot run bounded preflight command: {error}"
    finally:
        if process is not None:
            if process.poll() is None:
                if stop_started is None:
                    stop_started = time.monotonic()
                    signal_group(signal.SIGTERM)
                try:
                    process.wait(timeout=grace_seconds)
                except subprocess.TimeoutExpired:
                    signal_group(signal.SIGKILL)
                    try:
                        process.wait(timeout=grace_seconds)
                    except subprocess.TimeoutExpired:
                        failure = failure or "preflight leader did not stop after SIGKILL"
            # The leader can exit while a descendant keeps its process group or pipe open.
            signal_group(signal.SIGKILL)
            if process.poll() is None:
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    failure = failure or "preflight leader remained unreaped after bounded cleanup"
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        selector.close()
        for signum, old_handler in old_handlers.items():
            signal.signal(signum, old_handler)

    if received_signal is not None:
        raise RuntimeError(f"preflight command interrupted by signal {received_signal}")
    if failure is not None:
        raise RuntimeError(f"{failure}: {argv[0]}")
    assert process is not None
    result = subprocess.CompletedProcess(argv, process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[:2048]
        raise RuntimeError(f"preflight command failed ({result.returncode}): {argv[0]}: {detail}")
    return result


def _git_environment() -> dict[str, str]:
    environment = {
        "PATH": TRUSTED_TOOL_PATH,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    pinned_config = {
        "core.fsmonitor": "false",
        "core.hooksPath": "/dev/null",
        "core.attributesFile": "/dev/null",
        "core.excludesFile": "/dev/null",
        "core.pager": "cat",
        "gpg.program": TRUSTED_GPG,
        "gpg.format": "openpgp",
        "protocol.ext.allow": "never",
    }
    environment["GIT_CONFIG_COUNT"] = str(len(pinned_config))
    for index, (key, value) in enumerate(pinned_config.items()):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    gnupg_home = os.environ.get("GNUPGHOME")
    if gnupg_home:
        environment["GNUPGHOME"] = gnupg_home
    return environment


@contextlib.contextmanager
def _trusted_git_environment():
    """Suppress checkout and inherited Git helpers while the authorized controller verifies artifacts."""
    environment = _git_environment()
    pinned_config = {
        "core.fsmonitor": "false",
        "core.hooksPath": "/dev/null",
        "core.attributesFile": "/dev/null",
        "core.excludesFile": "/dev/null",
        "core.pager": "cat",
        "gpg.program": TRUSTED_GPG,
        "gpg.format": "openpgp",
        "protocol.ext.allow": "never",
    }
    modified = {key for key in os.environ if key.startswith("GIT_")} | set(environment) | {"GIT_CONFIG_COUNT"}
    for index in range(len(pinned_config)):
        modified.update((f"GIT_CONFIG_KEY_{index}", f"GIT_CONFIG_VALUE_{index}"))
    old = {key: (key in os.environ, os.environ.get(key)) for key in modified}
    for key in list(os.environ):
        if key.startswith("GIT_"):
            os.environ.pop(key, None)
    for key, value in environment.items():
        os.environ[key] = value
    os.environ["GIT_CONFIG_COUNT"] = str(len(pinned_config))
    for index, (key, value) in enumerate(pinned_config.items()):
        os.environ[f"GIT_CONFIG_KEY_{index}"] = key
        os.environ[f"GIT_CONFIG_VALUE_{index}"] = value
    try:
        yield
    finally:
        for key in modified:
            existed, previous = old[key]
            if not existed:
                os.environ.pop(key, None)
            else:
                assert previous is not None
                os.environ[key] = previous


def _run_trusted_git(arguments: list[str], cwd: Path, timeout_seconds: int = 60) -> subprocess.CompletedProcess[bytes]:
    git_options = [
        "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
        "-c", "core.pager=cat", "-c", "core.attributesFile=/dev/null",
        "-c", "core.excludesFile=/dev/null",
    ]
    if "verify-commit" in arguments:
        git_options.extend(("-c", f"gpg.program={TRUSTED_GPG}", "-c", "gpg.format=openpgp"))
    return run_capture_bounded(
        [TRUSTED_GIT, *git_options, *arguments], cwd, timeout_seconds,
        env=_git_environment(), max_stdout_bytes=16 * 1024 * 1024, max_stderr_bytes=2 * 1024 * 1024,
    )


def run_checked(argv: list[str], cwd: Path, timeout_seconds: int = 60) -> bytes:
    if argv and argv[0] == "git":
        result = _run_trusted_git(argv[1:], cwd, timeout_seconds)
    else:
        result = run_capture_bounded(argv, cwd, timeout_seconds)
    return result.stdout


def verify_signed_source_commit(source_root: Path, commit: str, expected_fingerprint: str) -> None:
    require(re.fullmatch(r"[A-F0-9]{40,64}", expected_fingerprint) is not None,
            "SourceSchemaV4 signer fingerprint must be an uppercase OpenPGP fingerprint")
    gnupg_home = os.environ.get("GNUPGHOME")
    require(gnupg_home is not None,
            "SourceSchemaV4 signature checks require a caller-provided private GNUPGHOME")
    gnupg_path = strict_nonsymlink_path(Path(gnupg_home), "SourceSchemaV4 GNUPGHOME")
    require(gnupg_path.is_dir() and stat.S_IMODE(gnupg_path.stat().st_mode) == 0o700,
            "SourceSchemaV4 GNUPGHOME must be a private 0700 directory")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "SourceSchemaV4 signature commit does not use the pinned SHA-1 Git object format")
    try:
        result = _run_trusted_git(["verify-commit", "--raw", commit], source_root, 60)
    except RuntimeError as error:
        raise RuntimeError(f"cannot verify signed SourceSchemaV4 commit: {error}") from error
    status = (result.stdout + result.stderr).decode("utf-8", errors="replace").splitlines()
    valid_signatures: list[tuple[str, str]] = []
    rejected_statuses = {"BADSIG", "ERRSIG", "NO_PUBKEY", "REVKEYSIG", "EXPKEYSIG", "EXPSIG"}
    for line in status:
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "[GNUPG:]" and fields[1] in rejected_statuses:
            raise RuntimeError("SourceSchemaV4 commit signature has a GPG rejection status")
        if len(fields) >= 2 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            require(len(fields) in (11, 12), "GPG VALIDSIG status record is malformed")
            signing_fingerprint = fields[2].upper()
            primary_fingerprint = (fields[11] if len(fields) == 12 else fields[2]).upper()
            require(re.fullmatch(r"[A-F0-9]{40,64}", signing_fingerprint) is not None
                    and re.fullmatch(r"[A-F0-9]{40,64}", primary_fingerprint) is not None,
                    "GPG VALIDSIG fingerprint fields are malformed")
            valid_signatures.append((signing_fingerprint, primary_fingerprint))
    require(result.returncode == 0 and len(valid_signatures) == 1,
            "SourceSchemaV4 commit did not produce exactly one valid OpenPGP signature")
    signing_fingerprint, primary_fingerprint = valid_signatures[0]
    require(expected_fingerprint in (signing_fingerprint, primary_fingerprint),
            "SourceSchemaV4 VALIDSIG signing/primary fingerprint differs from the caller-pinned signer")


def functional_source_overlay(
    source_root: Path,
    output_root: Path,
    logs: Path,
    attempt_id: str,
    host_id: str,
    candidate_relative: str,
    baseline_relative: str,
    calibration_relative: str,
    calibration_output_relative: str,
) -> tuple[dict[str, Any], dict[str, tuple[Path, str]], dict[str, Any]]:
    commit = run_checked(["git", "rev-parse", "HEAD"], source_root).decode("ascii").strip()
    require(commit == SIGNED_SOURCE_COMMIT, "functional E2E source is not the signed immutable 9290 commit")
    status = run_checked(["git", "status", "--porcelain", "--untracked-files=no"], source_root)
    require(status == b"", "tracked signed source changed before functional E2E")
    require(_SOURCE_INVENTORY is not None, "shared source inventory module was not loaded")
    typed_inventory = _SOURCE_INVENTORY.inventory(source_root)
    tree_sha256 = _SOURCE_INVENTORY.digest_inventory(typed_inventory)
    source_files = typed_inventory["entries"]
    cargo_lock_path, cargo_lock_sha256, _cargo_lock_size = safe_source_file(source_root, "Cargo.lock", "Cargo.lock")
    require(tree_sha256 == _SOURCE_INVENTORY.digest_records(source_files), "functional source inventory digest does not reconcile")

    calibration_path, calibration_binary_sha256, _ = safe_source_file(
        source_root, calibration_relative, "resource-domain calibration binary"
    )
    candidate_path, candidate_sha256, _ = safe_source_file(source_root, candidate_relative, "allocatbelt benchmark binary")
    baseline_path, baseline_sha256, _ = safe_source_file(source_root, baseline_relative, "secure mimalloc benchmark binary")
    require(os.access(candidate_path, os.X_OK) and os.access(baseline_path, os.X_OK) and os.access(calibration_path, os.X_OK), "one or more pinned functional binaries are not executable")
    calibration_output_path = source_root / calibration_output_relative
    require(not calibration_output_path.exists() and not calibration_output_path.is_symlink(), "calibration output path must be fresh")
    calibration_output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not calibration_output_path.parent.is_symlink(), "calibration output directory may not be a symlink")
    calibration_status = run_bounded(
        [str(calibration_path)], source_root, calibration_output_path,
        logs / "calibration.stderr.log", 60,
    )
    (logs / "calibration.exit").write_text(f"{calibration_status}\n", encoding="ascii")
    require(calibration_status == 0, "independent native resource-domain calibration failed")
    calibration_raw, calibration_output_sha256 = read_stable(
        calibration_output_path, "independent calibration output", MAX_SMALL_ARTIFACT_BYTES
    )
    calibration_record = _CAMPAIGN.validate_calibration_record(
        _CAMPAIGN.parse_json_object_bytes(calibration_raw, "independent calibration output", MAX_SMALL_ARTIFACT_BYTES)
    )
    validator_path, validator_sha256, _ = safe_source_file(
        source_root, "scripts/application-runtime-readback.py", "runtime readback validator"
    )
    validator_module = _CAMPAIGN.runtime_readback_module(validator_sha256)
    fixed_policy = _CAMPAIGN.fixed_runtime_policy_artifact(validator_sha256)
    cargo_version = run_checked(["cargo", "-V"], source_root).decode("utf-8").strip()
    rustc_verbose = run_checked(["rustc", "-Vv"], source_root).decode("utf-8").splitlines()
    rustc_release = next(
        (line.removeprefix("release: ") for line in rustc_verbose if line.startswith("release: ")),
        "",
    )
    require(rustc_release == "1.99.0", "functional E2E requires Rust 1.99.0")
    target_triple = "x86_64-unknown-linux-gnu"
    target_cpu = "x86-64-v3"
    require("x86-64-v3" in (source_root / ".cargo" / "config.toml").read_text(encoding="utf-8"), "signed Cargo config does not pin x86-64-v3")

    feature_tree_path = output_root / "cargo-features.tree.txt"
    features_status = run_bounded(
        ["cargo", "tree", "--locked", "--target", target_triple, "--edges", "features", "-p", "allocatbelt-bench", "-p", "allocatbelt-qualification-tools"],
        source_root, feature_tree_path, logs / "cargo-features.stderr.log", 90,
    )
    (logs / "cargo-features.exit").write_text(f"{features_status}\n", encoding="ascii")
    require(features_status == 0, "cannot freeze exact release dependency feature tree")
    feature_tree_sha256, feature_tree_size = hash_stable(feature_tree_path)
    feature_manifest = {
        "schema": "allocatbelt.functional-build-features.v1",
        "cargo_tree_path": feature_tree_path.name,
        "cargo_tree_sha256": feature_tree_sha256,
        "cargo_tree_bytes": feature_tree_size,
        "packages": ["allocatbelt-bench", "allocatbelt-qualification-tools"],
        "profile": "release",
        "locked": True,
    }
    feature_manifest_path = output_root / "build-features.json"
    write_canonical(feature_manifest_path, feature_manifest)
    features_sha256 = hashlib.sha256(_CAMPAIGN.canonical_bytes(feature_manifest)).hexdigest()

    build_command = [
        "cargo", "build", "--release", "--locked", "-p", "allocatbelt-bench",
        "--bin", "bench-application-allocatbelt", "--bin", "bench-application-mimalloc",
        "--bin", "bench-resource-domain-calibration", "-p", "allocatbelt-qualification-tools",
        "--bin", "application-analyze",
    ]
    build_inputs = {
        "schema": "allocatbelt.functional-build-inputs.v1",
        "build_provenance": "externally_built_signed_source",
        "helper_executed_build": False,
        "build_command": build_command,
        "target_triple": target_triple,
        "target_cpu": target_cpu,
        "profile": "release",
        "cargo_lock_sha256": cargo_lock_sha256,
        "cargo_config_sha256": hash_path(source_root / ".cargo" / "config.toml"),
        "workspace_manifest_sha256": hash_path(source_root / "Cargo.toml"),
        "features_manifest_sha256": features_sha256,
        "rustc_verbose": rustc_verbose,
        "cargo_version": cargo_version,
        "environment": {
            key: os.environ.get(key, "")
            for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS")
        },
    }
    build_inputs_path = output_root / "build-inputs.json"
    write_canonical(build_inputs_path, build_inputs)
    build_inputs_sha256 = hashlib.sha256(_CAMPAIGN.canonical_bytes(build_inputs)).hexdigest()
    source_identity = {
        "git_commit": commit,
        "source_tree_sha256": tree_sha256,
        "cargo_lock_sha256": cargo_lock_sha256,
        "files": source_files,
    }
    build_identity = {
        "host_id": host_id,
        "rustc_release": rustc_release,
        "rustc_verbose": rustc_verbose,
        "cargo_version": cargo_version,
        "target_triple": target_triple,
        "target_cpu": target_cpu,
        "profile": "release",
        "features_sha256": features_sha256,
        "build_inputs_sha256": build_inputs_sha256,
    }
    calibration = {
        "binary": {"path": calibration_relative, "sha256": calibration_binary_sha256},
        "output": {"path": calibration_output_relative, "sha256": calibration_output_sha256},
        "record": calibration_record,
        "source": {key: source_identity[key] for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")},
        "build": build_identity,
        "build_sha256": _CAMPAIGN.digest_object(build_identity),
    }
    source: dict[str, Any] = {
        "schema": "allocatbelt.application-functional-source-overlay.v2",
        "execution_scope": "functional_only",
        "source_inventory_module_sha256": SOURCE_INVENTORY_MODULE_SHA256,
        "source_inventory": typed_inventory,
        "source": source_identity,
        "build": build_identity,
        "artifacts": {
            "allocatbelt": {"path": candidate_relative, "sha256": candidate_sha256},
            "mimalloc-secure": {"path": baseline_relative, "sha256": baseline_sha256},
        },
        "fixed_runtime_policy": fixed_policy,
        "runtime_readback_validator": {"path": "scripts/application-runtime-readback.py", "sha256": validator_sha256},
        "resource_domain_calibration": calibration,
        "build_evidence": {
            "features": {"path": feature_manifest_path.name, "sha256": hash_path(feature_manifest_path)},
            "feature_tree": {"path": feature_tree_path.name, "sha256": feature_tree_sha256},
            "build_inputs": {"path": build_inputs_path.name, "sha256": hash_path(build_inputs_path)},
        },
    }
    source["manifest_sha256"] = _CAMPAIGN.digest_object(source)
    source_path = output_root / "functional-source-overlay.json"
    source_raw = write_canonical(source_path, source)
    require(source_raw and hashlib.sha256(source_raw).hexdigest() == hash_path(source_path), "functional source overlay did not persist canonically")
    _CAMPAIGN.validate_fixed_runtime_policy_artifact(source["fixed_runtime_policy"], validator_sha256)
    require(calibration_path.resolve(strict=True) == (source_root / calibration_relative).resolve(strict=True), "calibration binary path changed during source overlay construction")
    require(validator_module is not None, "runtime validator module did not load from its pinned source bytes")
    artifacts = {
        "candidate_binary": (candidate_path, candidate_sha256),
        "secure_baseline_binary": (baseline_path, baseline_sha256),
        "calibration_binary": (calibration_path, calibration_binary_sha256),
        "calibration_output": (calibration_output_path, calibration_output_sha256),
        "runtime_validator": (validator_path, validator_sha256),
        "cargo_lock": (cargo_lock_path, cargo_lock_sha256),
    }
    build_info = {
        "build_provenance": "externally_built_signed_source",
        "helper_executed_build": False,
        "features_manifest_sha256": features_sha256,
        "build_inputs_sha256": build_inputs_sha256,
        "feature_tree_sha256": feature_tree_sha256,
        "build_command": build_command,
        "output_path": source_path,
        "output_sha256": hash_path(source_path),
    }
    return source, artifacts, build_info

def write_canonical(path: Path, value: Any) -> bytes:
    raw = _CAMPAIGN.canonical_bytes(value)
    require(not path.exists() and not path.is_symlink(), f"refusing to replace E2E artifact: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    os.chmod(path, 0o600, follow_symlinks=False)
    return raw


def write_report(path: Path, value: Any) -> None:
    require(not path.is_symlink(), "functional E2E report path may not be a symlink")
    raw = _CAMPAIGN.canonical_bytes(value)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".functional-report-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def emit_oracle(
    source_root: Path,
    binary: Path,
    binary_sha256: str,
    source_sha256: str,
    oracle_path: Path,
    rate: int,
    arrivals: int,
    logs: Path,
    name: str,
) -> str:
    command = [
        str(binary), "--emit-oracle-only", str(oracle_path),
        "--source-sha256", source_sha256,
        "--binary-sha256", binary_sha256,
        "--workload", WORKLOAD,
        "--profile", PROFILE,
        "--rate", str(rate),
        "--arrivals", str(arrivals),
        "--trace-deadline-seconds", str(FUNCTIONAL_LIMITS["max_trace_deadline_seconds"]),
    ]
    status = run_bounded(
        command, source_root, logs / f"oracle-{name}.stdout.log",
        logs / f"oracle-{name}.stderr.log", 60,
    )
    (logs / f"oracle-{name}.exit").write_text(f"{status}\n", encoding="ascii")
    require(status == 0 and oracle_path.is_file() and not oracle_path.is_symlink(), f"oracle producer failed for {name}; see captured native log")
    oracle_sha256 = hash_path(oracle_path)
    _CAMPAIGN.validate_oracle(
        oracle_path, source_sha256, binary_sha256, WORKLOAD, PROFILE, rate, arrivals,
    )
    return oracle_sha256


def bindings_for_case(
    source: dict[str, Any], spec: dict[str, Any], run_id: str, pair_kind: str,
    rate: int, arrivals: int,
) -> dict[str, Any]:
    host_id = source["build"]["host_id"]
    job: dict[str, Any] = {
        "host_id": host_id,
        "phase": "confirmation",
        "comparison_family": "fixed_policy",
        "run_id": run_id,
        "family": WORKLOAD,
        "workload": WORKLOAD,
        "profile": PROFILE,
        "mode": MODE,
        "rate_per_second": rate,
        "arrivals": arrivals,
        "ordinal": 1,
        "pair_kind": pair_kind,
        "allocator": "allocatbelt",
        "comparison_kind": "executor",
    }
    if pair_kind in ("aa-bounded", "aa-tokio"):
        executor = "bounded" if pair_kind == "aa-bounded" else "tokio"
        job.update({
            "phase": "aa", "executor": executor, "control_id": f"functional-{executor}-aa",
            "comparison_kind": None,
        })
        job.pop("comparison_kind")
    elif pair_kind == "allocator-match":
        job.update({
            "comparison_kind": "allocator", "baseline_allocator": "mimalloc-secure",
        })
    bindings = _CAMPAIGN.build_runtime_process_bindings(job, spec, source)
    return {"job": job, "bindings": bindings}


def process_overlay(
    source: dict[str, Any], run_id: str, pair_kind: str, rate: int, arrivals: int,
    runner_sha256: str, runtime_bindings_sha256: str, bindings: list[dict[str, Any]],
    candidate_binary_sha256: str, baseline_binary_sha256: str | None,
    oracle_sha256: str, baseline_oracle_sha256: str | None,
) -> dict[str, Any]:
    calibration = source["resource_domain_calibration"]
    first = bindings[0]
    require(all(item["resource_ceiling_sha256"] == first["resource_ceiling_sha256"] for item in bindings), "functional pair recipes changed resource ceiling within the process set")
    require(all(item["policy_sha256"] == first["policy_sha256"] for item in bindings), "functional pair recipes changed policy within the process set")
    require(all(item["fixed_global_control_baseline"] == first["fixed_global_control_baseline"] for item in bindings), "functional pair recipes changed the numeric Control baseline")
    return {
        "schema": "allocatbelt.application-functional-pair-overlay.v2",
        "execution_scope": "functional_only",
        "run_id": run_id,
        "source_head": source["source"]["git_commit"],
        "source_tree_sha256": source["source"]["source_tree_sha256"],
        "source_inventory_module_sha256": source["source_inventory_module_sha256"],
        "source_manifest_sha256": source["manifest_sha256"],
        "pair_runner_sha256": runner_sha256,
        "runtime_bindings_sha256": runtime_bindings_sha256,
        "runtime_validator_sha256": source["runtime_readback_validator"]["sha256"],
        "candidate_binary_sha256": candidate_binary_sha256,
        "baseline_binary_sha256": baseline_binary_sha256,
        "oracle_sha256": oracle_sha256,
        "baseline_oracle_sha256": baseline_oracle_sha256,
        "workload": WORKLOAD,
        "profile": PROFILE,
        "mode": MODE,
        "rate_per_second": rate,
        "arrivals": arrivals,
        "pair_kind": pair_kind,
        "resource_ceiling_sha256": first["resource_ceiling_sha256"],
        "policy_sha256": first["policy_sha256"],
        "fixed_global_control_baseline": first["fixed_global_control_baseline"],
        "calibration_binary_sha256": calibration["binary"]["sha256"],
        "calibration_output_sha256": calibration["output"]["sha256"],
        "processes": [
            {name: item[name] for name in ("pair", "executor", "allocator")}
            for item in bindings
        ],
        "functional_limits": FUNCTIONAL_LIMITS,
    }


def parse_canonical_object(raw: bytes, label: str, maximum: int = 1024 * 1024) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its functional receipt size bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} is not duplicate-free UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must be a JSON object")
    return value


def validate_functional_pair(
    pair_dir: Path, source: dict[str, Any], spec: dict[str, Any], job: dict[str, Any],
    bindings: list[dict[str, Any]], overlay_sha256: str, runner_sha256: str,
    runtime_bindings_sha256: str, oracle_sha256: str,
    baseline_binary_sha256: str | None, baseline_oracle_sha256: str | None,
) -> dict[str, Any]:
    require(pair_dir.is_dir() and not pair_dir.is_symlink(), "functional pair output directory is missing or symlinked")
    complete = {}
    for line in (pair_dir / "pair.complete").read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("\t")
        require(separator and key not in complete, "functional completion record is malformed or repeats a key")
        complete[key] = value
    require(complete == {"pair_status": "functional_only", "execution_scope": "functional_only"}, "functional pair completion record promoted or changed scope")
    metadata = read_metadata(pair_dir / "metadata.tsv")
    require(metadata.get("execution_scope") == "functional_only" and metadata.get("execution_scope_after") == "functional_only", "functional metadata scope is missing or changed")
    require(metadata.get("functional_overlay_sha256_before") == overlay_sha256 == metadata.get("functional_overlay_sha256_after"), "functional overlay hash changed across native pair")
    require(metadata.get("pair_runner_sha256_before") == runner_sha256 == metadata.get("pair_runner_sha256_after"), "functional runner hash changed across native pair")
    require(metadata.get("source_tree_sha256_before") == source["source"]["source_tree_sha256"] == metadata.get("source_tree_sha256_after"), "signed source tree changed across functional pair")
    require(metadata.get("source_inventory_schema") == "allocatbelt.application-source-inventory.v1", "functional metadata has the wrong source inventory schema")
    require(
        metadata.get("source_inventory_module_sha256") == SOURCE_INVENTORY_MODULE_SHA256
        == metadata.get("source_inventory_module_sha256_before") == metadata.get("source_inventory_module_sha256_after"),
        "shared source inventory module changed across native pair",
    )
    require(metadata.get("binary_sha256_before") == source["artifacts"]["allocatbelt"]["sha256"] == metadata.get("binary_sha256_after"), "candidate binary hash changed across functional pair")
    require(metadata.get("runtime_bindings_sha256_before") == runtime_bindings_sha256 == metadata.get("runtime_bindings_sha256_after"), "runtime binding hash changed across functional pair")
    require(metadata.get("runtime_validator_sha256_before") == source["runtime_readback_validator"]["sha256"] == metadata.get("runtime_validator_sha256_after"), "runtime validator hash changed across functional pair")
    require(metadata.get("oracle_sha256_before") == oracle_sha256 == metadata.get("oracle_sha256_after"), "candidate oracle hash changed across functional pair")
    require(metadata.get("baseline_binary_sha256_before") == (baseline_binary_sha256 or "") == metadata.get("baseline_binary_sha256_after"), "baseline binary hash changed across functional pair")
    require(metadata.get("baseline_oracle_sha256_before") == (baseline_oracle_sha256 or "") == metadata.get("baseline_oracle_sha256_after"), "baseline oracle hash changed across functional pair")
    require(metadata.get("fixed_global_control_baseline") == str(source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"]), "functional metadata changed the independent Control baseline")

    header, rows = _CAMPAIGN.read_tsv(pair_dir / "processes.tsv", 2)
    require(header == _CAMPAIGN.PAIR_PROCESS_HEADER, "functional process ledger header differs from the current runtime schema")
    _CAMPAIGN.require_exact_pair_process_rows(rows, job)
    expected_by_descriptor = {
        (item["pair"], item["executor"], item["allocator"]): item for item in bindings
    }
    require(len(expected_by_descriptor) == 2, "functional runtime bindings do not have two unique descriptors")
    module = _CAMPAIGN.runtime_readback_module(source["runtime_readback_validator"]["sha256"])
    process_results = []
    for row in rows:
        descriptor = (row["pair"], row["executor"], row["allocator"])
        binding = expected_by_descriptor[descriptor]
        require(row["exit_code"] == "0" and row["row_validation"] == "valid", "native functional process did not pass the row and sidecar validators")
        require(row["p99_qualification"] == "functional_only", "functional process acquired a qualification p99 label")
        require(row["runtime_recipe_sha256"] == binding["recipe_sha256"], "functional process recipe hash differs from its frozen binding")
        require(row["resource_ceiling_sha256"] == binding["resource_ceiling_sha256"], "functional process ceiling hash differs from its frozen recipe")
        require(row["policy_sha256"] == binding["policy_sha256"], "functional process policy hash differs from its frozen source")
        require(row["fixed_global_control_baseline"] == str(binding["fixed_global_control_baseline"]), "functional process baseline differs from its independent calibration")
        require(row["validator_sha256"] == source["runtime_readback_validator"]["sha256"], "functional process validator pin differs")
        require(row["source_manifest_sha256"] == source["manifest_sha256"], "functional process source-manifest pin differs")
        require(row["calibration_binary_sha256"] == source["resource_domain_calibration"]["binary"]["sha256"], "functional process calibration binary pin differs")
        require(row["calibration_output_sha256"] == source["resource_domain_calibration"]["output"]["sha256"], "functional process calibration output pin differs")

        output_path, output_raw, output_sha = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "stdout", "stdout_sha256")
        output_header, output_rows = _CAMPAIGN.read_tsv_bytes(output_raw, str(output_path), 1)
        require(len(output_header) == 53, "functional benchmark stdout has the wrong output schema width")
        output = output_rows[0]
        runtime_name = "allocatbelt" if row["executor"] == "bounded" else "tokio-1.53.1"
        require((output["allocator"], output["executor"], output["workload"], output["mode"]) == (row["allocator"], runtime_name, WORKLOAD, MODE), "functional benchmark row identity differs")
        require(int(output["attempted"]) == job["arrivals"] and int(output["admitted"]) == job["arrivals"], "functional benchmark did not admit its full bounded trace")
        require(int(output["completed_on_time"]) + int(output["completed_late"]) == job["arrivals"], "functional benchmark completion count differs")
        require(int(output["errors"]) == int(output["cancellations"]) == int(output["unresolved"]) == int(output["lost"]) == 0, "functional benchmark reported errors or lost work")
        require(output["result_digest"] == output["expected_digest"], "functional benchmark aggregate digest differs")
        require(all(int(output[field]) == 0 for field in ("final_managed_bytes", "final_disk_ops", "final_network_ops")), "functional benchmark retained final resource charges")

        _receipt_path, receipt_raw, receipt_sha = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_readback", "runtime_readback_sha256")
        _expectation_path, expectation_raw, expectation_sha = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_expectation", "runtime_expectation_sha256")
        _validation_path, validation_raw, validation_sha = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_validation", "runtime_validation_sha256")
        expected = module.build_fixed_expectation(binding["recipe"])
        require(expectation_sha == binding["expectation_sha256"] and expectation_raw == module.canonical_bytes(expected), "functional expectation differs from the controller recipe")
        receipt_schema, fields = module.read_receipt_versioned(BytesArtifactPath(receipt_raw))
        validation = module.validate_runtime_readback(fields, expected, receipt_schema)
        stored_validation = _CAMPAIGN.parse_json_object_bytes(validation_raw, "functional runtime validation output", _CAMPAIGN.MAX_READBACK_ARTIFACT_BYTES)
        require(_CAMPAIGN.canonical_bytes(stored_validation) == _CAMPAIGN.canonical_bytes(validation), "functional CLI validation output differs from independent receipt validation")
        require(validation["validated"] is True and validation["expectation_sha256"] == binding["expectation_sha256"], "functional receipt was not independently validated")
        require(validation["field_count"] == len(fields), "functional receipt field count differs")
        process_results.append({
            "pair": row["pair"], "executor": row["executor"], "allocator": row["allocator"],
            "output_sha256": output_sha, "runtime_readback_sha256": receipt_sha,
            "runtime_expectation_sha256": expectation_sha, "runtime_validation_sha256": validation_sha,
            "validated": True, "p99_qualification": row["p99_qualification"],
        })
    return {"execution_scope": "functional_only", "pair_status": complete["pair_status"], "processes": process_results}


def authorize_source_v4_manifest(
    source_root: Path, manifest_path: Path, expected_file_sha256: str, expected_signer_fingerprint: str,
) -> dict[str, Any]:
    """Authenticate raw manifest, signed commit, clean source and exact controller bytes without executing source code."""
    require(re.fullmatch(r"[0-9a-f]{64}", expected_file_sha256) is not None,
            "SourceSchemaV4 raw file SHA-256 is required")
    require(re.fullmatch(r"[A-F0-9]{40,64}", expected_signer_fingerprint) is not None,
            "SourceSchemaV4 signer fingerprint must be an uppercase OpenPGP fingerprint")
    raw, actual_file_sha256 = read_stable(
        manifest_path, "SourceSchemaV4 manifest file", SOURCE_V4_FUNCTIONAL_LIMITS["max_source_manifest_bytes"]
    )
    require(actual_file_sha256 == expected_file_sha256,
            "SourceSchemaV4 raw manifest SHA-256 differs from its caller pin")
    try:
        manifest = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=no_duplicate_keys,
            parse_constant=lambda value: fail(f"non-finite SourceSchemaV4 JSON constant: {value}"),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"SourceSchemaV4 manifest is not duplicate-free UTF-8 JSON: {error}") from error
    require(type(manifest) is dict and raw == canonical_stdlib(manifest),
            "SourceSchemaV4 manifest is not canonical JSON")
    require(manifest.get("schema") == SOURCE_MANIFEST_SCHEMA_V4,
            "functional v4 mode requires SourceSchemaV4")
    unsigned = dict(manifest)
    semantic_sha256 = unsigned.pop("manifest_sha256", None)
    require(type(semantic_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", semantic_sha256) is not None
            and hashlib.sha256(canonical_stdlib(unsigned)).hexdigest() == semantic_sha256,
            "SourceSchemaV4 semantic manifest SHA-256 differs")
    source = manifest.get("source")
    require(type(source) is dict, "SourceSchemaV4 source identity is malformed")
    commit = source.get("git_commit")
    require(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
            "SourceSchemaV4 commit ID is malformed for the pinned Git object format")
    source_tree_sha256 = source.get("source_tree_sha256")
    require(type(source_tree_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", source_tree_sha256) is not None,
            "SourceSchemaV4 source tree digest is malformed")
    records = source.get("files")
    require(type(records) is list, "SourceSchemaV4 file inventory is malformed")
    controller_record = next(
        (item for item in records if type(item) is dict and item.get("path") == "scripts/application-campaign.py"),
        None,
    )
    require(type(controller_record) is dict and controller_record.get("kind") == "file"
            and controller_record.get("mode") in ("100644", "100755")
            and type(controller_record.get("size")) is int
            and 0 <= controller_record["size"] <= MAX_CAMPAIGN_SOURCE_BYTES
            and type(controller_record.get("sha256")) is str
            and re.fullmatch(r"[0-9a-f]{64}", controller_record["sha256"]) is not None,
            "SourceSchemaV4 inventory does not pin a bounded regular campaign controller")

    head = run_checked(["git", "rev-parse", "HEAD"], source_root).decode("ascii", errors="strict").strip()
    require(head == commit, "signed SourceSchemaV4 root HEAD differs from the caller-pinned manifest")
    git_root = Path(run_checked(["git", "rev-parse", "--show-toplevel"], source_root)
                    .decode("utf-8", errors="strict").rstrip("\n")).resolve(strict=True)
    require(git_root == source_root.resolve(strict=True),
            "SourceSchemaV4 source root is not the exact Git worktree root")
    verify_signed_source_commit(source_root, commit, expected_signer_fingerprint)
    verify_source_tree_before_controller_exec(source_root, source, commit)

    controller_path = _tree_record_path(source_root, "scripts/application-campaign.py")
    controller_raw, controller_sha256 = read_stable(
        controller_path, "caller-authorized campaign controller", MAX_CAMPAIGN_SOURCE_BYTES
    )
    require(controller_sha256 == controller_record["sha256"]
            and len(controller_raw) == controller_record["size"],
            "captured campaign controller differs from its raw-pinned source record")
    committed_controller = _run_trusted_git(
        ["cat-file", "blob", f"{commit}:scripts/application-campaign.py"], source_root, 60,
    ).stdout
    require(controller_raw == committed_controller,
            "captured campaign controller differs from the blob at the verified signed commit")
    head_after = run_checked(["git", "rev-parse", "HEAD"], source_root).decode("ascii", errors="strict").strip()
    require(head_after == commit, "SourceSchemaV4 HEAD changed during bootstrap authorization")
    return {
        "manifest": manifest,
        "manifest_raw": raw,
        "manifest_file_sha256": actual_file_sha256,
        "manifest_semantic_sha256": semantic_sha256,
        "commit": commit,
        "signer_fingerprint": expected_signer_fingerprint,
        "controller_path": controller_path,
        "controller_raw": controller_raw,
        "controller_sha256": controller_sha256,
    }


def load_campaign_module_v4(source_root: Path, authorized: dict[str, Any]) -> Any:
    """Execute only the controller snapshot authorized against a signed commit blob."""
    require(authorized.get("controller_path") == source_root / "scripts" / "application-campaign.py"
            and authorized.get("controller_sha256") == hashlib.sha256(authorized.get("controller_raw", b"")).hexdigest(),
            "SourceSchemaV4 controller bytes lack a valid bootstrap authorization")
    raw = authorized["controller_raw"]
    path = authorized["controller_path"]
    caller_path = safe_external_path(source_root)
    toolchain_bins = {name: shutil.which(name, path=caller_path) for name in ("cargo", "rustc")}
    require(all(toolchain_bins.values()), "SourceSchemaV4 verification requires caller-provided cargo and rustc")
    toolchain_environment = {
        key: os.environ[key]
        for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")
        if key in os.environ
    }
    module = types.ModuleType("functional_v4_application_campaign")
    module.__file__ = str(path)
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise RuntimeError(f"source-pinned campaign controller cannot be compiled: {error}") from error
    require(module.SOURCE_SCHEMA == SOURCE_MANIFEST_SCHEMA_V4, "source controller does not implement SourceSchemaV4")
    require(
        module.SOURCE_INVENTORY_MODULE_SHA256 == SOURCE_INVENTORY_MODULE_SHA256,
        "source controller pins a different source inventory engine",
    )
    def trusted_controller_run_checked(argv: list[str], cwd: Path | None = None,
                                       timeout_seconds: float = 120.0) -> bytes:
        if argv and argv[0] == "git":
            return run_checked(argv, cwd or source_root, min(600, max(1, int(timeout_seconds))))
        if argv and argv[0] in toolchain_bins:
            environment = _git_environment()
            environment.update(toolchain_environment)
            result = run_capture_bounded(
                [toolchain_bins[argv[0]], *argv[1:]], cwd or source_root,
                min(600, max(1, int(timeout_seconds))), env=environment,
                max_stdout_bytes=16 * 1024 * 1024, max_stderr_bytes=2 * 1024 * 1024,
            )
            return result.stdout
        result = run_capture_bounded(
            argv, cwd or source_root, min(600, max(1, int(timeout_seconds))),
            max_stdout_bytes=16 * 1024 * 1024, max_stderr_bytes=2 * 1024 * 1024,
        )
        return result.stdout

    module.run_checked = trusted_controller_run_checked
    return module


def load_source_manifest_v4(
    source_root: Path, manifest_path: Path, expected_file_sha256: str, expected_signer_fingerprint: str,
) -> tuple[dict[str, Any], bytes, str]:
    """Authenticate before controller exec, then run its full tree/artifact verification."""
    global _CAMPAIGN
    authorized = authorize_source_v4_manifest(
        source_root, manifest_path, expected_file_sha256, expected_signer_fingerprint,
    )
    _CAMPAIGN = load_campaign_module_v4(source_root, authorized)
    require(_CAMPAIGN.SOURCE_SCHEMA == SOURCE_MANIFEST_SCHEMA_V4
            and _CAMPAIGN.SOURCE_INVENTORY_MODULE_SHA256 == SOURCE_INVENTORY_MODULE_SHA256,
            "authorized SourceSchemaV4 controller has an unexpected schema or inventory engine pin")
    with _trusted_git_environment():
        _CAMPAIGN.verify_source_manifest(authorized["manifest"], source_root, verify_artifacts=True)
    require(read_stable(manifest_path, "SourceSchemaV4 manifest after controller verification",
                        SOURCE_V4_FUNCTIONAL_LIMITS["max_source_manifest_bytes"])
            == (authorized["manifest_raw"], authorized["manifest_file_sha256"]),
            "SourceSchemaV4 manifest changed during controller verification")
    require(run_checked(["git", "rev-parse", "HEAD"], source_root).decode("ascii", errors="strict").strip()
            == authorized["commit"], "SourceSchemaV4 HEAD changed during controller verification")
    return authorized["manifest"], authorized["manifest_raw"], authorized["manifest_file_sha256"]


def validate_source_v4_context(
    *, workload: str, profile: str, mode: str, pair_kind: str,
    baseline_allocator: str | None, rate_per_second: int | None, arrivals: int | None,
    trace_deadline_seconds: int, drain_deadline_seconds: int,
    shutdown_deadline_seconds: int, process_deadline_seconds: int,
    pair_deadline_seconds: int,
) -> dict[str, Any]:
    require((workload, profile) in SOURCE_V4_CELLS, "workload/profile must select one of the original 15 fixed-policy contexts")
    require(mode in ("open_loop", "capacity"), "functional v4 mode must be open_loop or capacity")
    require(pair_kind in ("matched", "aa-bounded", "aa-tokio", "allocator-match"), "functional v4 pair kind is unsupported")
    if pair_kind == "allocator-match":
        require(baseline_allocator in SOURCE_V4_BASELINES, "allocator-match requires a real secure, standard, or system manifest artifact")
    else:
        require(baseline_allocator is None, "a baseline allocator is only valid for allocator-match")
    if mode == "open_loop":
        require(type(rate_per_second) is int and 1 <= rate_per_second <= SOURCE_V4_FUNCTIONAL_LIMITS["max_rate_per_second"],
                "functional open-loop rate must be in 1..=1000 arrivals per second")
        require(type(arrivals) is int and 1 <= arrivals <= SOURCE_V4_FUNCTIONAL_LIMITS["max_arrivals"],
                "functional open-loop arrivals must be in 1..=1000")
        trace = (arrivals + rate_per_second - 1) // rate_per_second
        require(trace <= trace_deadline_seconds <= SOURCE_V4_FUNCTIONAL_LIMITS["max_trace_deadline_seconds"],
                "functional open-loop trace exceeds its finite deadline")
    else:
        require(rate_per_second is None, "capacity mode has no selected arrival rate")
        capacity_arrivals = _CAMPAIGN.runtime_readback_module().CAPACITY_ARRIVALS
        require(arrivals is None or arrivals == capacity_arrivals,
                "capacity mode accepts only the runner's fixed 5000 sentinel")
        require(trace_deadline_seconds == SOURCE_V4_FUNCTIONAL_LIMITS["capacity_horizon_seconds"],
                "functional capacity mode preserves the exact 30-second horizon")
        trace = SOURCE_V4_FUNCTIONAL_LIMITS["capacity_horizon_seconds"]
    require(1 <= drain_deadline_seconds <= SOURCE_V4_FUNCTIONAL_LIMITS["max_drain_deadline_seconds"],
            "functional drain deadline exceeds its finite limit")
    require(1 <= shutdown_deadline_seconds <= SOURCE_V4_FUNCTIONAL_LIMITS["max_shutdown_deadline_seconds"],
            "functional shutdown deadline exceeds its finite limit")
    require(1 <= process_deadline_seconds <= SOURCE_V4_FUNCTIONAL_LIMITS["max_process_deadline_seconds"],
            "functional process deadline exceeds its finite limit")
    require(1 <= pair_deadline_seconds <= SOURCE_V4_FUNCTIONAL_LIMITS["max_pair_deadline_seconds"],
            "functional pair deadline exceeds its finite limit")
    shutdown_units = {"http": 3, "disk": 2, "mixed": 4}.get(workload, 1)
    minimum_process = 120 + (31 if mode == "capacity" else trace_deadline_seconds) + drain_deadline_seconds + shutdown_deadline_seconds * shutdown_units
    require(process_deadline_seconds >= minimum_process, "functional process deadline does not cover setup, horizon, drain, and shutdown")
    require(pair_deadline_seconds >= process_deadline_seconds * 2, "functional pair deadline must cover both bounded process deadlines")
    return {
        "workload": workload,
        "profile": profile,
        "mode": mode,
        "pair_kind": pair_kind,
        "baseline_allocator": baseline_allocator,
        "rate_per_second": rate_per_second,
        "arrivals": arrivals if mode == "open_loop" else capacity_arrivals,
        "horizon_seconds": trace,
        "process_deadline_seconds": process_deadline_seconds,
        "pair_deadline_seconds": pair_deadline_seconds,
    }


def source_v4_process_descriptors(pair_kind: str, baseline_allocator: str | None) -> list[dict[str, str]]:
    if pair_kind == "matched":
        return [
            {"pair": "bounded", "executor": "bounded", "allocator": "allocatbelt"},
            {"pair": "tokio", "executor": "tokio", "allocator": "allocatbelt"},
        ]
    if pair_kind == "aa-bounded":
        return [
            {"pair": "bounded-a", "executor": "bounded", "allocator": "allocatbelt"},
            {"pair": "bounded-b", "executor": "bounded", "allocator": "allocatbelt"},
        ]
    if pair_kind == "aa-tokio":
        return [
            {"pair": "tokio-a", "executor": "tokio", "allocator": "allocatbelt"},
            {"pair": "tokio-b", "executor": "tokio", "allocator": "allocatbelt"},
        ]
    require(pair_kind == "allocator-match" and baseline_allocator in SOURCE_V4_BASELINES,
            "allocator-match descriptors need a supported pinned baseline")
    return [
        {"pair": "candidate", "executor": "bounded", "allocator": "allocatbelt"},
        {"pair": "baseline", "executor": "bounded", "allocator": baseline_allocator},
    ]


def source_v4_runtime_bindings(
    source: dict[str, Any], context: dict[str, Any], run_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    validator_sha256 = source["runtime_readback_validator"]["sha256"]
    module = _CAMPAIGN.runtime_readback_module(validator_sha256)
    calibration = source["resource_domain_calibration"]
    baseline = calibration["record"]["fixed_global_control_baseline"]
    limits = _CAMPAIGN.fixed_resource_limits_for_cell(context["workload"], context["profile"], validator_sha256)
    resource_ceiling_sha256 = hashlib.sha256(_CAMPAIGN.canonical_bytes(limits)).hexdigest()
    policy_sha256 = source["fixed_runtime_policy"]["policy_sha256"]
    descriptors = source_v4_process_descriptors(context["pair_kind"], context["baseline_allocator"])
    bindings: list[dict[str, Any]] = []
    for descriptor in descriptors:
        allocator = descriptor["allocator"]
        binary_sha256 = source["artifacts"][allocator]["sha256"]
        nonce = secrets.token_hex(16)
        recipe_input = {
            "schema": module.RECIPE_SCHEMA,
            "identity": {
                "report_nonce": nonce,
                "run_id": run_id,
                "allocator": allocator,
                "executor": "allocatbelt" if descriptor["executor"] == "bounded" else "tokio-1.53.1",
                "source_sha256": source["source"]["source_tree_sha256"],
                "binary_sha256": binary_sha256,
                "comparison_family": "fixed_policy",
                "resource_ceiling_sha256": resource_ceiling_sha256,
                "policy_sha256": policy_sha256,
            },
            "run": {
                "workload": context["workload"],
                "profile": context["profile"],
                "mode": context["mode"],
                "rate_per_second": context["rate_per_second"],
                "arrivals": context["arrivals"],
            },
            "fixed_global_control_baseline": baseline,
        }
        expected = module.build_fixed_expectation(recipe_input)
        recipe = expected["recipe"]
        bindings.append({
            **descriptor,
            "report_nonce": nonce,
            "recipe": recipe,
            "recipe_sha256": hashlib.sha256(_CAMPAIGN.canonical_bytes(recipe)).hexdigest(),
            "expectation_sha256": hashlib.sha256(module.canonical_bytes(expected)).hexdigest(),
            "resource_ceiling_sha256": resource_ceiling_sha256,
            "policy_sha256": policy_sha256,
            "fixed_global_control_baseline": baseline,
        })
    binding_manifest: dict[str, Any] = {
        "schema": _CAMPAIGN.RUNTIME_BINDINGS_SCHEMA,
        "run_id": run_id,
        "comparison_family": "fixed_policy",
        "source_manifest_sha256": source["manifest_sha256"],
        "source_sha256": source["source"]["source_tree_sha256"],
        "source": calibration["source"],
        "build": calibration["build"],
        "fixed_runtime_policy": source["fixed_runtime_policy"],
        "resource_domain_calibration": {
            key: calibration[key]
            for key in ("binary", "output", "record", "source", "build", "build_sha256")
        },
        "runtime_readback_validator": source["runtime_readback_validator"],
        "fixed_global_control_baseline": baseline,
        "processes": bindings,
    }
    binding_manifest["manifest_sha256"] = _CAMPAIGN.digest_object(binding_manifest)
    return binding_manifest, bindings


def source_v4_artifact_hashes(source: dict[str, Any]) -> dict[str, str]:
    return {
        **{name: record["sha256"] for name, record in source["artifacts"].items()},
        **{f"soak-{name}": record["sha256"] for name, record in source["soak_artifacts"].items()},
        "analysis-engine": source["analysis_artifact"]["sha256"],
        "resource-domain-calibration": source["resource_domain_calibration"]["binary"]["sha256"],
        "resource-domain-calibration-output": source["resource_domain_calibration"]["output"]["sha256"],
    }


def functional_source_overlay_v4(
    source: dict[str, Any], context: dict[str, Any], source_manifest_path: str,
    source_manifest_file_sha256: str, filesystem: dict[str, Any], tmpdir_relative_path: str,
    signer_fingerprint: str,
) -> dict[str, Any]:
    overlay = {
        "schema": SOURCE_V4_SOURCE_OVERLAY_SCHEMA,
        "execution_scope": "functional_only",
        "source_manifest_schema": SOURCE_MANIFEST_SCHEMA_V4,
        "source_manifest_path": source_manifest_path,
        "source_manifest_file_sha256": source_manifest_file_sha256,
        "signer_fingerprint": signer_fingerprint,
        "source_manifest_sha256": source["manifest_sha256"],
        "source": {
            key: source["source"][key]
            for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")
        },
        "build": source["build"],
        "artifacts": source["artifacts"],
        "soak_artifacts": source["soak_artifacts"],
        "analysis_artifact": source["analysis_artifact"],
        "fixed_runtime_policy": source["fixed_runtime_policy"],
        "runtime_readback_validator": source["runtime_readback_validator"],
        "resource_domain_calibration": source["resource_domain_calibration"],
        "artifact_sha256s": source_v4_artifact_hashes(source),
        "functional_context": context,
        "functional_limits": SOURCE_V4_FUNCTIONAL_LIMITS,
        "temporary_storage_root_relative_path": tmpdir_relative_path,
        "temporary_storage_context": filesystem,
    }
    overlay["overlay_sha256"] = _CAMPAIGN.digest_object(overlay)
    return overlay


def functional_pair_overlay_v4(
    source: dict[str, Any], context: dict[str, Any], run_id: str, pair_runner_sha256: str,
    bindings_sha256: str, bindings: list[dict[str, Any]], source_manifest_path: str,
    source_manifest_file_sha256: str, candidate_binary_sha256: str,
    baseline_binary_sha256: str | None, oracle_sha256: str | None,
    baseline_oracle_sha256: str | None, filesystem: dict[str, Any], tmpdir_relative_path: str,
    signer_fingerprint: str,
) -> dict[str, Any]:
    first = bindings[0]
    require(all(item["resource_ceiling_sha256"] == first["resource_ceiling_sha256"] for item in bindings),
            "functional v4 process recipes changed the numeric resource ceiling")
    require(all(item["policy_sha256"] == first["policy_sha256"] for item in bindings),
            "functional v4 process recipes changed the fixed policy")
    calibration = source["resource_domain_calibration"]
    overlay = {
        "schema": SOURCE_V4_PAIR_OVERLAY_SCHEMA,
        "execution_scope": "functional_only",
        "run_id": run_id,
        "source_manifest_schema": SOURCE_MANIFEST_SCHEMA_V4,
        "source_manifest_path": source_manifest_path,
        "source_manifest_file_sha256": source_manifest_file_sha256,
        "signer_fingerprint": signer_fingerprint,
        "source_manifest_sha256": source["manifest_sha256"],
        "source_head": source["source"]["git_commit"],
        "source_tree_sha256": source["source"]["source_tree_sha256"],
        "source_inventory_module_sha256": SOURCE_INVENTORY_MODULE_SHA256,
        "pair_runner_sha256": pair_runner_sha256,
        "runtime_bindings_sha256": bindings_sha256,
        "runtime_validator_sha256": source["runtime_readback_validator"]["sha256"],
        "candidate_binary_sha256": candidate_binary_sha256,
        "baseline_binary_sha256": baseline_binary_sha256,
        "baseline_allocator": context["baseline_allocator"],
        "oracle_sha256": oracle_sha256,
        "baseline_oracle_sha256": baseline_oracle_sha256,
        "workload": context["workload"],
        "profile": context["profile"],
        "mode": context["mode"],
        "rate_per_second": context["rate_per_second"],
        "arrivals": context["arrivals"],
        "pair_kind": context["pair_kind"],
        "resource_ceiling_sha256": first["resource_ceiling_sha256"],
        "policy_sha256": first["policy_sha256"],
        "fixed_global_control_baseline": first["fixed_global_control_baseline"],
        "calibration_binary_sha256": calibration["binary"]["sha256"],
        "calibration_output_sha256": calibration["output"]["sha256"],
        "artifact_sha256s": source_v4_artifact_hashes(source),
        "processes": [{key: item[key] for key in ("pair", "executor", "allocator")} for item in bindings],
        "functional_limits": SOURCE_V4_FUNCTIONAL_LIMITS,
        "temporary_storage_root_relative_path": tmpdir_relative_path,
        "temporary_storage_context": filesystem,
    }
    return overlay


def emit_oracle_v4(
    source_root: Path, binary: Path, binary_sha256: str, source_sha256: str,
    oracle_path: Path, workload: str, profile: str, rate: int, arrivals: int,
    logs: Path, label: str, watch_root: Path,
) -> str:
    command = [
        str(binary), "--emit-oracle-only", str(oracle_path),
        "--source-sha256", source_sha256, "--binary-sha256", binary_sha256,
        "--workload", workload, "--profile", profile,
        "--rate", str(rate), "--arrivals", str(arrivals),
        "--trace-deadline-seconds", str(SOURCE_V4_FUNCTIONAL_LIMITS["max_trace_deadline_seconds"]),
    ]
    status = run_bounded(
        command, source_root, logs / f"oracle-{label}.stdout.log",
        logs / f"oracle-{label}.stderr.log", 60,
        file_size_limit_bytes=SOURCE_V4_FUNCTIONAL_LIMITS["max_file_bytes"],
        watch_root=watch_root,
    )
    (logs / f"oracle-{label}.exit").write_text(f"{status}\n", encoding="ascii")
    require(status == 0 and oracle_path.is_file() and not oracle_path.is_symlink(),
            f"functional v4 oracle generation failed for {label}")
    digest = hash_path(oracle_path)
    _CAMPAIGN.validate_oracle(oracle_path, source_sha256, binary_sha256, workload, profile, rate, arrivals)
    return digest


def _read_bounded_text(path: Path, label: str, maximum: int) -> tuple[str, str]:
    raw, digest = read_stable(path, label, maximum)
    try:
        return raw.decode("utf-8"), digest
    except UnicodeError as error:
        raise RuntimeError(f"{label} is not UTF-8: {error}") from error


def validate_v4_shutdown_report(
    path: Path, binding: dict[str, Any], source: dict[str, Any], binary_sha256: str,
    workload: str, profile: str, process_deadline: int, drain_deadline: int,
    shutdown_deadline: int, trace_deadline: int, output: dict[str, str],
) -> str:
    text, digest = _read_bounded_text(path, "functional shutdown report", MAX_SMALL_ARTIFACT_BYTES)
    lines = text.splitlines()
    require(lines and lines[0] == "schema\tallocatbelt-app-phase-v1\t", "functional shutdown report schema differs")
    expected_executor = "allocatbelt" if binding["executor"] == "bounded" else "tokio-1.53.1"
    identity = [line.split("\t") for line in lines[1:9]]
    expected_identity = [
        ["identity", "report_nonce", binding["report_nonce"]],
        ["identity", "run_id", binding["recipe"]["identity"]["run_id"]],
        ["identity", "executor", expected_executor],
        ["identity", "allocator", binding["allocator"]],
        ["identity", "workload", workload],
        ["identity", "profile", profile],
        ["identity", "source_sha256", source["source"]["source_tree_sha256"]],
        ["identity", "binary_sha256", binary_sha256],
    ]
    require(identity == expected_identity, "functional shutdown report identity differs from its recipe")
    drivers = (
        ["allocatbelt owning HTTP runtime"] if workload in ("http", "mixed") else ["allocatbelt application driver"]
    ) if binding["executor"] == "bounded" else (
        ["Tokio HTTP runtime", "Tokio fixed rate timer"] if workload in ("http", "mixed") else ["Tokio runtime"]
    )
    require(len(lines) == len(drivers) + 15, "functional shutdown report row count differs")
    phases = [line.split("\t") for line in lines[9:15]]
    names = [
        "production_trace", "production_cpu_started_ns", "production_cpu_ended_ns",
        "production_through_drain_cpu_ns", "successful_completions", "cpu_ns_per_successful_completion",
    ]
    require(all(len(row) == 3 and row[:2] == ["phase", name] for row, name in zip(phases, names, strict=True)),
            "functional shutdown phase ledger differs")
    require(all(re.fullmatch(r"(?:0|[1-9][0-9]*)", row[2]) for row in phases), "functional shutdown phase value is malformed")
    actual_trace_ns = int(phases[0][2])
    require(actual_trace_ns == capacity_actual_duration_ns(output),
            "functional production phase differs from stdout wall time less drain tail")
    if output["mode"] == "capacity":
        validate_v4_capacity_liveness(workload, actual_trace_ns, int(output["completed_on_time"]), trace_deadline)
    else:
        require(actual_trace_ns <= trace_deadline * 1_000_000_000,
                "functional production horizon exceeded its watchdog")
    started, ended, cpu_ns, successes = (int(phases[index][2]) for index in (1, 2, 3, 4))
    require(ended >= started and ended - started == cpu_ns, "functional production CPU interval is inconsistent")
    require(cpu_ns <= process_deadline * 128 * 1_000_000_000, "functional production CPU exceeds its finite envelope")
    expected_successes = int(output["completed_on_time"]) + int(output["completed_late"])
    require(successes == expected_successes, "functional shutdown completion count differs from the result row")
    require(int(phases[5][2]) == (cpu_ns // successes if successes else 0), "functional normalized production CPU differs")
    for line, expected_driver in zip(lines[15:], drivers, strict=True):
        fields = line.split("\t")
        require(len(fields) == 3 and fields[:2] == ["driver", expected_driver], "functional shutdown driver order differs")
        require(re.fullmatch(r"(?:0|[1-9][0-9]*)", fields[2]) is not None
                and int(fields[2]) <= shutdown_deadline * 1_000_000_000,
                "functional shutdown exceeded its finite deadline")
    require(int(output["drain_tail_ns"]) <= drain_deadline * 1_000_000_000,
            "functional drain exceeded its finite deadline")
    return digest


def validate_v4_capacity_liveness(
    workload: str, trace_ns: int, completed_on_time: int, trace_deadline_seconds: int,
    family_successes: dict[str, int] | None = None,
) -> None:
    minimum_trace_ns = SOURCE_V4_FUNCTIONAL_LIMITS["capacity_horizon_seconds"] * 1_000_000_000
    maximum_trace_ns = trace_deadline_seconds * 1_000_000_000
    require(minimum_trace_ns <= trace_ns <= maximum_trace_ns <= 31_000_000_000,
            "capacity receipt did not measure a real 30-to-31-second trace")
    require(completed_on_time > 0, "capacity receipt contains no completed work")
    if workload == "mixed" and family_successes is not None:
        require(set(family_successes) == {"cpu", "memory", "http", "disk"}
                and all(value > 0 for value in family_successes.values()),
                "mixed capacity trace did not complete work in every family")


def capacity_actual_duration_ns(output: dict[str, str]) -> int:
    wall_text = output.get("wall_through_drain_ns", "")
    drain_text = output.get("drain_tail_ns", "")
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)", wall_text) is not None
            and re.fullmatch(r"(?:0|[1-9][0-9]*)", drain_text) is not None,
            "capacity wall/drain duration fields are malformed")
    wall_ns, drain_ns = int(wall_text), int(drain_text)
    require(wall_ns > 0 and drain_ns < wall_ns,
            "capacity production duration is not a positive checked wall/drain subtraction")
    return wall_ns - drain_ns


def validate_v4_open_loop_ids(
    pair_dir: Path, row: dict[str, str], binding: dict[str, Any], source: dict[str, Any],
    context: dict[str, Any], binary_sha256: str, oracle_path: Path, oracle_sha256: str, output: dict[str, str],
    process_deadline: int, trace_deadline: int,
) -> str:
    path = pair_dir / f"{row['pair']}-{row['executor']}.ids.tsv"
    text, digest = _read_bounded_text(path, "functional per-ID ledger", SOURCE_V4_FUNCTIONAL_LIMITS["max_file_bytes"])
    require(digest == row["ids_sha256"], "functional per-ID ledger SHA-256 differs from the process ledger")
    fields = text.splitlines()
    require(len(fields) >= 3 and fields[0] == "schema\tallocatbelt-app-arrivals-v3", "functional per-ID ledger schema differs")
    expected_executor = "allocatbelt" if binding["executor"] == "bounded" else "tokio-1.53.1"
    require(fields[1].split("\t") == [
        "identity", binding["report_nonce"], binding["recipe"]["identity"]["run_id"],
        expected_executor, binding["allocator"], context["workload"], context["profile"],
        source["source"]["source_tree_sha256"], binary_sha256,
    ], "functional per-ID ledger identity differs")
    require(fields[2] == "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum",
            "functional per-ID ledger header differs")
    arrivals = context["arrivals"]
    require(len(fields) == arrivals + 3, "functional per-ID ledger row count differs")
    _CAMPAIGN.validate_oracle(
        oracle_path, source["source"]["source_tree_sha256"], binary_sha256,
        context["workload"], context["profile"], context["rate_per_second"], arrivals,
    )
    oracle_lines, actual_oracle_sha = _read_bounded_text(oracle_path, "functional source/binary oracle", SOURCE_V4_FUNCTIONAL_LIMITS["max_file_bytes"])
    require(actual_oracle_sha == oracle_sha256, "functional oracle changed after execution")
    oracle_rows = oracle_lines.splitlines()
    require(len(oracle_rows) == arrivals + 12, "functional oracle row count differs")
    trace_ns = int(oracle_rows[9].split("\t", 1)[1])
    family_order = ("cpu", "memory", "http", "disk")
    digest_value = 0
    expected_digest = 0
    latencies: list[int] = []
    max_ns = process_deadline * 1_000_000_000
    for expected_id, (oracle_line, ledger_line) in enumerate(zip(oracle_rows[12:], fields[3:], strict=True)):
        expected_fields = oracle_line.split("\t")
        observed_fields = ledger_line.split("\t")
        require(len(expected_fields) == 4 and len(observed_fields) == 7, "functional ID/oracle row width differs")
        require(expected_fields[0] == str(expected_id) and observed_fields[0] == str(expected_id), "functional IDs are not contiguous")
        expected_family = family_order[expected_id % len(family_order)] if context["workload"] == "mixed" else context["workload"]
        require(expected_fields[2] == expected_family and observed_fields[1] == expected_family,
                "functional ID workload differs from its independent oracle")
        scheduled = int(expected_fields[1])
        completion = int(observed_fields[3])
        checksum = int(observed_fields[5])
        expected_checksum = int(expected_fields[3])
        require(observed_fields[2] == str(scheduled) and observed_fields[6] == str(expected_checksum),
                "functional per-ID schedule/checksum differs from the independent oracle")
        require(observed_fields[4] == "completed" and checksum == expected_checksum,
                "functional open-loop request was rejected, errored, or returned the wrong checksum")
        require(scheduled <= completion <= max_ns and scheduled < trace_ns,
                "functional per-ID timestamp is outside its bounded process/trace")
        latencies.append(completion - scheduled)
        digest_value = (digest_value + (checksum if context["workload"] == "http" else checksum ^ expected_id)) % (1 << 64)
        expected_digest = (expected_digest + (expected_checksum if context["workload"] == "http" else expected_checksum ^ expected_id)) % (1 << 64)
    require(digest_value == int(output["result_digest"]) == expected_digest == int(output["expected_digest"]),
            "functional per-ID aggregate digest differs")
    latencies.sort()
    def percentile(p: int) -> int:
        if not latencies:
            return 0
        rank = max(1, (p * len(latencies) + 99) // 100)
        return latencies[rank - 1]
    require(all(int(output[f"response_p{p}_ns"]) == percentile(p) for p in (50, 95, 99)),
            "functional output quantiles differ from the per-ID ledger")
    return digest


def validate_v4_capacity_family(
    pair_dir: Path, row: dict[str, str], binding: dict[str, Any], source: dict[str, Any],
    context: dict[str, Any], binary_sha256: str, output: dict[str, str],
) -> str:
    if context["workload"] != "mixed":
        require(row["capacity_family_sha256"] == "not_applicable", "standalone capacity process emitted a mixed-family ledger")
        return "not_applicable"
    path = pair_dir / f"{row['pair']}-{row['executor']}.capacity-families.tsv"
    text, digest = _read_bounded_text(path, "functional mixed capacity family ledger", MAX_SMALL_ARTIFACT_BYTES)
    require(digest == row["capacity_family_sha256"], "mixed capacity family ledger SHA-256 differs")
    lines = text.splitlines()
    require(lines and lines[0] == "schema\tallocatbelt-app-capacity-families-v1\t", "mixed capacity family ledger schema differs")
    expected_executor = "allocatbelt" if binding["executor"] == "bounded" else "tokio-1.53.1"
    identity_expected = {
        "report_nonce": binding["report_nonce"],
        "run_id": binding["recipe"]["identity"]["run_id"],
        "executor": expected_executor,
        "allocator": binding["allocator"],
        "workload": context["workload"],
        "profile": context["profile"],
        "source_sha256": source["source"]["source_tree_sha256"],
        "binary_sha256": binary_sha256,
    }
    identity: dict[str, str] = {}
    families: dict[str, tuple[int, int]] = {}
    phases: dict[str, str] = {}
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) == 3 and parts[0] == "identity":
            require(parts[1] not in identity, "mixed capacity identity repeats a field")
            identity[parts[1]] = parts[2]
        elif len(parts) == 4 and parts[0] == "family":
            require(parts[1] not in families, "mixed capacity family repeats a workload")
            require(all(re.fullmatch(r"(?:0|[1-9][0-9]*)", value) for value in parts[2:]),
                    "mixed capacity family count is malformed")
            families[parts[1]] = (int(parts[2]), int(parts[3]))
        elif len(parts) == 3 and parts[0] == "phase":
            require(parts[1] not in phases, "mixed capacity phase repeats a field")
            phases[parts[1]] = parts[2]
        else:
            fail("mixed capacity family ledger contains an unknown row")
    require(identity == identity_expected and set(families) == {"cpu", "memory", "http", "disk"},
            "mixed capacity family identity or set differs")
    require(phases == {"trace_seconds": "30", "profile": context["profile"]},
            "mixed capacity family ledger does not retain the 30-second horizon")
    attempted = int(output["attempted"])
    completed = int(output["completed_on_time"])
    require(attempted > 0 and completed > 0,
            "mixed capacity trace scheduled or completed no work")
    require(sum(value[0] for value in families.values()) == attempted
            and sum(value[1] for value in families.values()) == completed,
            "mixed capacity family counts do not reconcile to the process row")
    for index, family in enumerate(("cpu", "memory", "http", "disk")):
        scheduled, successes = families[family]
        require(scheduled == attempted // 4 + int(index < attempted % 4)
                and 0 < successes <= scheduled,
                "mixed capacity family count is not the real equal-interleave schedule")
    return digest


def validate_v4_process_argv(
    row: dict[str, str], binding: dict[str, Any], binary_path: Path, tmpdir: Path,
    context: dict[str, Any], cpu_set: str, raw_root: Path,
    trace_deadline: int, drain_deadline: int, shutdown_deadline: int, process_deadline: int,
    oracle_path: Path | None, oracle_sha256: str | None,
) -> list[str]:
    try:
        argv = json.loads(row["argv"])
    except (json.JSONDecodeError, KeyError) as error:
        raise RuntimeError("functional process argv is not valid JSON") from error
    require(type(argv) is list and all(type(item) is str for item in argv), "functional process argv is not a string array")
    pair = binding["pair"]
    executor = binding["executor"]
    expected_executor = "allocatbelt" if executor == "bounded" else "tokio-1.53.1"
    timing_path = str(Path(raw_root) / binding["recipe"]["identity"]["run_id"] / f"{pair}-{executor}.time.txt")
    prefix = [
        "taskset", "-c", cpu_set, "/usr/bin/time", "-v", "-o", timing_path,
        "timeout", "--foreground", "--signal=TERM", "--kill-after=3s", f"{process_deadline}s", "env",
    ]
    require(argv[:len(prefix)] == prefix, "functional process argv does not retain affinity/time/watchdog controls")
    binary_text = str(binary_path.resolve(strict=True))
    require(binary_text in argv, "functional process argv lacks the source-manifest-pinned executable")
    binary_index = argv.index(binary_text)
    assignments = argv[len(prefix):binary_index]
    require(all("=" in item for item in assignments), "functional process argv environment binding is malformed")
    environment: dict[str, str] = {}
    for item in assignments:
        key, value = item.split("=", 1)
        require(key not in environment, "functional process argv repeats an environment key")
        environment[key] = value
    expected_environment = {
        "TMPDIR": str(tmpdir),
        "ALLOCATBELT_APP_SHUTDOWN_REPORT": str(raw_root / binding["recipe"]["identity"]["run_id"] / f"{pair}-{executor}.shutdown.tsv"),
        "ALLOCATBELT_APP_ID_REPORT": str(raw_root / binding["recipe"]["identity"]["run_id"] / f"{pair}-{executor}.ids.tsv"),
        "ALLOCATBELT_APP_FAMILY_REPORT": str(raw_root / binding["recipe"]["identity"]["run_id"] / f"{pair}-{executor}.capacity-families.tsv"),
        "ALLOCATBELT_APP_RUNTIME_REPORT": str(raw_root / binding["recipe"]["identity"]["run_id"] / f"{pair}-{executor}.runtime.tsv"),
        "ALLOCATBELT_APP_COMPARISON_FAMILY": "fixed_policy",
        "ALLOCATBELT_APP_RESOURCE_CEILING_SHA256": binding["resource_ceiling_sha256"],
        "ALLOCATBELT_APP_POLICY_SHA256": binding["policy_sha256"],
        "ALLOCATBELT_APP_REPORT_NONCE": binding["report_nonce"],
        "ALLOCATBELT_APP_RUN_ID": binding["recipe"]["identity"]["run_id"],
        "ALLOCATBELT_APP_EXECUTOR": expected_executor,
        "ALLOCATBELT_APP_ALLOCATOR": binding["allocator"],
        "ALLOCATBELT_APP_WORKLOAD": context["workload"],
        "ALLOCATBELT_APP_PROFILE": context["profile"],
        "ALLOCATBELT_APP_SOURCE_SHA256": binding["recipe"]["identity"]["source_sha256"],
        "ALLOCATBELT_APP_BINARY_SHA256": binding["recipe"]["identity"]["binary_sha256"],
        "ALLOCATBELT_APP_ORACLE_FILE": "" if oracle_path is None else str(oracle_path),
        "ALLOCATBELT_APP_ORACLE_SHA256": "" if oracle_sha256 is None else oracle_sha256,
    }
    for key, value in expected_environment.items():
        require(environment.get(key) == value, f"functional process argv changed its {key} binding")
    expected_args = [
        "--executor", executor, "--workload", context["workload"],
        "--profile", context["profile"], "--mode", context["mode"],
        "--trace-deadline-seconds", str(trace_deadline),
        "--drain-deadline-seconds", str(drain_deadline),
        "--shutdown-deadline-seconds", str(shutdown_deadline),
        "--process-deadline-seconds", str(process_deadline),
    ]
    if context["mode"] == "open_loop":
        expected_args.extend(["--rate", str(context["rate_per_second"]), "--arrivals", str(context["arrivals"])])
    require(argv[binary_index + 1:] == expected_args, "functional process argv differs from the selected bounded context")
    return argv


def validate_v4_output_row(
    raw: bytes, label: str, process_row: dict[str, str], context: dict[str, Any],
    process_deadline: int, drain_deadline: int,
) -> dict[str, str]:
    header, rows = _CAMPAIGN.read_tsv_bytes(raw, label, 1)
    require(header == RUNNER_RESULT_HEADER and len(header) == 53, "functional application result header differs")
    output = rows[0]
    runtime_name = "allocatbelt" if process_row["executor"] == "bounded" else "tokio-1.53.1"
    require(
        (output["allocator"], output["executor"], output["workload"], output["mode"])
        == (process_row["allocator"], runtime_name, context["workload"], context["mode"]),
        "functional application result identity differs from the selected manifest/context",
    )
    resource_limits = context["resource_limits"]
    async_workers = 2 if context["profile"] == "oversubscribed" else 4
    blocking_workers = {"http": 1, "disk": async_workers, "mixed": async_workers}.get(context["workload"], 0)
    retained_window = 8 if context["workload"] in ("memory", "mixed") else 0
    task_limit = 17 if context["workload"] in ("http", "mixed") else 8
    expected_schema = {"http": "http-nonblocking-connect-v1", "mixed": "mixed-application-v1"}.get(context["workload"], "2")
    expected_result_contract = {
        "schema": expected_schema,
        "async_workers": str(async_workers),
        "blocking_workers": str(blocking_workers),
        "logical_window": "8",
        "global_task_limit": str(task_limit),
        "retained_window": str(retained_window),
        "managed_limit_bytes": str(resource_limits["managed_bytes"]),
        "disk_limit_ops": str(resource_limits["disk_ops"]),
        "network_limit_ops": str(resource_limits["network_ops"]),
    }
    require(all(output.get(key) == value for key, value in expected_result_contract.items()),
            "functional result topology/resource ceilings differ from the source-pinned fixed recipe")
    integer_names = (
        "async_workers", "blocking_workers", "logical_window", "global_task_limit", "retained_window",
        "attempted", "admitted", "rejected_full", "rejected_resource", "completed_on_time", "completed_late",
        "errors", "cancellations", "unresolved", "lost", "result_digest", "expected_digest", "setup_ns",
        "timer_pair_median_ns", "wall_through_drain_ns", "drain_tail_ns", "response_p50_ns", "response_p95_ns",
        "response_p99_ns", "producer_lateness_mean_ns", "producer_lateness_max_ns", "max_observed_managed_bytes",
        "retained_managed_bytes", "managed_limit_bytes", "disk_limit_ops", "network_limit_ops", "final_managed_bytes",
        "final_disk_ops", "final_network_ops", "rss_before_kib", "rss_after_drain_kib", "rss_after_shutdown_kib",
        "hwm_before_kib", "hwm_after_drain_kib", "hwm_after_shutdown_kib", "shutdown_ns",
        "rejected_logical_window", "rejected_backend_full",
    )
    numeric: dict[str, int] = {}
    for name in integer_names:
        value = output[name]
        require(re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is not None, f"functional result integer is malformed: {name}")
        numeric[name] = int(value)
    require(output["result_digest"] == output["expected_digest"], "functional application aggregate checksum differs")
    require(numeric["errors"] == numeric["cancellations"] == numeric["unresolved"] == 0,
            "functional application reported errors, cancellations, or unresolved work")
    require(numeric["lost"] == 0 and numeric["rejected_full"] == numeric["rejected_resource"] == 0,
            "functional application lost or rejected work")
    require(numeric["attempted"] == numeric["admitted"] == numeric["completed_on_time"] + numeric["completed_late"],
            "functional application attempts/admissions/completions do not reconcile")
    require(numeric["rejected_full"] == numeric["rejected_logical_window"] + numeric["rejected_backend_full"],
            "functional logical/backend rejection subtotals do not reconcile")
    require(all(numeric[key] == 0 for key in ("final_managed_bytes", "final_disk_ops", "final_network_ops")),
            "functional application retained final managed/disk/network charges")
    if context["workload"] in ("memory", "http", "mixed"):
        require(numeric["max_observed_managed_bytes"] <= numeric["managed_limit_bytes"]
                and numeric["retained_managed_bytes"] <= numeric["managed_limit_bytes"],
                "functional application exceeded its managed-memory ceiling")
    require(numeric["wall_through_drain_ns"] > 0
            and numeric["wall_through_drain_ns"] <= process_deadline * 1_000_000_000
            and numeric["drain_tail_ns"] <= drain_deadline * 1_000_000_000,
            "functional process/drain time exceeded its finite deadline")
    require(numeric["response_p50_ns"] <= numeric["response_p95_ns"] <= numeric["response_p99_ns"],
            "functional response quantiles are not monotone")
    try:
        drained = Decimal(output["successful_throughput_through_drain_per_second"])
    except (InvalidOperation, KeyError) as error:
        raise RuntimeError("functional drained-throughput result is malformed") from error
    require(drained.is_finite() and drained >= 0, "functional drained-throughput result is not finite")
    expected_drained = (Decimal(numeric["completed_on_time"] + numeric["completed_late"])
                        * Decimal(1_000_000_000) / Decimal(numeric["wall_through_drain_ns"]))
    require(abs(drained - expected_drained) <= max(Decimal("0.00000001"), expected_drained * Decimal("0.00000001")),
            "functional drained throughput does not reconcile with completions and wall time")
    if context["mode"] == "capacity":
        require(output["arrival_rate_per_second"] == "" and output["requested_arrivals"] == "",
                "capacity result falsely carries an open-loop rate or requested-arrival count")
        require(numeric["response_p50_ns"] == numeric["response_p95_ns"] == numeric["response_p99_ns"] == 0,
                "capacity result unexpectedly carries open-loop response quantiles")
        require(numeric["completed_on_time"] > 0,
                "capacity functional result contains no completed work")
        actual_duration_ns = capacity_actual_duration_ns(output)
        expected_capacity = (Decimal(numeric["completed_on_time"]) * Decimal(1_000_000_000)
                             / Decimal(actual_duration_ns))
        try:
            actual_capacity = Decimal(output["capacity_publications_per_second"])
        except InvalidOperation as error:
            raise RuntimeError("functional capacity throughput is malformed") from error
        require(actual_capacity.is_finite() and abs(actual_capacity - expected_capacity)
                <= max(Decimal("0.00000001"), expected_capacity * Decimal("0.00000001")),
                "capacity throughput does not use the reconciled actual production duration")
    else:
        require(output["arrival_rate_per_second"] == str(context["rate_per_second"])
                and output["requested_arrivals"] == str(context["arrivals"])
                and numeric["attempted"] == context["arrivals"],
                "open-loop result differs from its finite selected rate/arrival count")
        require(output["capacity_publications_per_second"] == "",
                "open-loop functional result carries a capacity throughput value")
    return output


def validate_v4_process_ledger(
    pair_dir: Path, source_root: Path, source: dict[str, Any], context: dict[str, Any],
    bindings: list[dict[str, Any]], overlay_sha256: str, pair_runner_sha256: str,
    bindings_sha256: str, source_manifest_file_sha256: str, source_manifest_semantic_sha256: str,
    signer_fingerprint: str,
    source_manifest_path: Path, source_manifest_raw: bytes, oracle_paths: dict[str, Path],
    oracle_hashes: dict[str, str], baseline_oracle_sha256: str | None,
    pair_runner_path: Path, cpu_set: str, raw_root: Path, tmpdir_root: Path,
    trace_deadline: int, drain_deadline: int, shutdown_deadline: int, process_deadline: int,
) -> dict[str, Any]:
    require(pair_dir.is_dir() and not pair_dir.is_symlink(), "functional v4 pair output directory is missing or symlinked")
    completion = (pair_dir / "pair.complete").read_text(encoding="ascii").splitlines()
    require(completion == ["pair_status\tfunctional_only", "execution_scope\tfunctional_only"],
            "functional v4 pair completion scope changed")
    metadata = read_metadata(pair_dir / "metadata.tsv")
    require(metadata.get("execution_scope") == "functional_only"
            and metadata.get("execution_scope_after") == "functional_only",
            "functional v4 runner metadata does not retain functional_only scope")
    require(metadata.get("source_manifest_schema") == SOURCE_MANIFEST_SCHEMA_V4
            and metadata.get("source_manifest_file_sha256_before") == source_manifest_file_sha256
            and metadata.get("source_manifest_file_sha256_after") == source_manifest_file_sha256,
            "functional v4 runner metadata changed its raw SourceSchemaV4 manifest pin")
    require(metadata.get("source_manifest_sha256") == source_manifest_semantic_sha256,
            "functional v4 runner metadata changed the semantic SourceSchemaV4 pin")
    require(metadata.get("source_signer_fingerprint") == signer_fingerprint,
            "functional v4 runner metadata changed the caller-pinned signer fingerprint")
    require(metadata.get("binary_sha256_before") == source["artifacts"]["allocatbelt"]["sha256"]
            and metadata.get("binary_sha256_after") == source["artifacts"]["allocatbelt"]["sha256"],
            "functional v4 candidate binary changed across execution")
    baseline_allocator = context["baseline_allocator"]
    if baseline_allocator is None:
        require(metadata.get("baseline_binary_sha256_before") == ""
                and metadata.get("baseline_binary_sha256_after") == "",
                "non-allocator functional v4 pair carries an unselected baseline binary")
    else:
        baseline_sha256 = source["artifacts"][baseline_allocator]["sha256"]
        require(metadata.get("baseline_binary_sha256_before") == baseline_sha256
                and metadata.get("baseline_binary_sha256_after") == baseline_sha256,
                "functional v4 comparison baseline changed across execution")
    if context["mode"] == "open_loop":
        require(metadata.get("oracle_sha256_before") == oracle_hashes["allocatbelt"]
                and metadata.get("oracle_sha256_after") == oracle_hashes["allocatbelt"],
                "functional v4 candidate oracle changed across execution")
        expected_baseline_oracle = oracle_hashes.get(baseline_allocator, "") if baseline_allocator is not None else ""
        require(metadata.get("baseline_oracle_sha256_before") == expected_baseline_oracle
                and metadata.get("baseline_oracle_sha256_after") == expected_baseline_oracle,
                "functional v4 baseline oracle changed across execution")
    else:
        require(metadata.get("oracle_sha256_before") == ""
                and metadata.get("oracle_sha256_after") == ""
                and metadata.get("baseline_oracle_sha256_before") == ""
                and metadata.get("baseline_oracle_sha256_after") == "",
                "functional v4 capacity pair unexpectedly carries open-loop oracles")
    require(metadata.get("functional_tmpdir_root") == str(tmpdir_root),
            "functional v4 runner metadata changed its rootfs TMPDIR root")
    try:
        runner_tmp_root_context = json.loads(metadata["functional_tmpdir_root_context"])
    except (KeyError, json.JSONDecodeError) as error:
        raise RuntimeError("functional v4 runner TMPDIR root context is malformed") from error
    expected_tmp_root_context = filesystem_context(tmpdir_root)
    for key in ("path", "mount_point", "filesystem_type", "source", "mount_device", "st_dev"):
        require(runner_tmp_root_context.get(key) == expected_tmp_root_context[key],
                "functional v4 runner TMPDIR root filesystem context differs")
    require(expected_tmp_root_context["filesystem_type"] not in ("tmpfs", "ramfs"),
            "functional v4 TMPDIR root is memory-backed")
    require(metadata.get("source_tree_sha256_before") == source["source"]["source_tree_sha256"]
            and metadata.get("source_tree_sha256_after") == source["source"]["source_tree_sha256"],
            "functional v4 source tree changed across the native pair")
    require(metadata.get("source_inventory_module_sha256_before") == SOURCE_INVENTORY_MODULE_SHA256
            and metadata.get("source_inventory_module_sha256_after") == SOURCE_INVENTORY_MODULE_SHA256,
            "functional v4 source inventory module changed across the pair")
    require(metadata.get("pair_runner_sha256_before") == pair_runner_sha256
            and metadata.get("pair_runner_sha256_after") == pair_runner_sha256,
            "signed functional pair runner changed across the pair")
    require(metadata.get("functional_overlay_sha256_before") == overlay_sha256
            and metadata.get("functional_overlay_sha256_after") == overlay_sha256,
            "functional pair overlay changed across execution")
    require(metadata.get("runtime_bindings_sha256_after") == bindings_sha256,
            "functional runtime binding manifest changed across execution")
    require(metadata.get("runtime_validator_sha256_before") == source["runtime_readback_validator"]["sha256"]
            and metadata.get("runtime_validator_sha256_after") == source["runtime_readback_validator"]["sha256"],
            "source-pinned runtime validator changed across execution")
    require(metadata.get("functional_file_size_limit_bytes") == str(SOURCE_V4_FUNCTIONAL_LIMITS["max_file_bytes"])
            and metadata.get("functional_file_size_limit_soft_bytes") == str(SOURCE_V4_FUNCTIONAL_LIMITS["max_file_bytes"])
            and metadata.get("functional_file_size_limit_hard_bytes") == str(SOURCE_V4_FUNCTIONAL_LIMITS["max_file_bytes"]),
            "functional runner did not retain the exact per-file soft/hard limit")
    require(metadata.get("fixed_global_control_baseline") == str(source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"]),
            "runner metadata changed the independent Control baseline")
    require(hash_path(source_manifest_path) == source_manifest_file_sha256
            and source_manifest_path.read_bytes() == source_manifest_raw,
            "copied raw SourceSchemaV4 manifest changed during the pair")

    header, rows = _CAMPAIGN.read_tsv(pair_dir / "processes.tsv", 2)
    require(header == _CAMPAIGN.PAIR_PROCESS_HEADER, "functional v4 process ledger header differs from the controller")
    expected_by_descriptor = {(item["pair"], item["executor"], item["allocator"]): item for item in bindings}
    require(len(expected_by_descriptor) == 2, "functional v4 binding does not contain exactly two processes")
    observed = [(row["pair"], row["executor"], row["allocator"]) for row in rows]
    require(len(set(observed)) == 2 and set(observed) == set(expected_by_descriptor),
            "functional v4 process ledger does not match the selected pair kind")
    module = _CAMPAIGN.runtime_readback_module(source["runtime_readback_validator"]["sha256"])
    expected_processes: list[dict[str, Any]] = []
    for row in rows:
        descriptor = (row["pair"], row["executor"], row["allocator"])
        binding = expected_by_descriptor[descriptor]
        require(row["exit_code"] == "0" and row["row_validation"] == "valid"
                and row["p99_qualification"] == "functional_only",
                "functional v4 process was not valid or acquired a qualification label")
        require(row["runtime_recipe_sha256"] == binding["recipe_sha256"]
                and row["resource_ceiling_sha256"] == binding["resource_ceiling_sha256"]
                and row["policy_sha256"] == binding["policy_sha256"],
                "functional v4 process ledger differs from its numeric recipe")
        require(row["fixed_global_control_baseline"] == str(binding["fixed_global_control_baseline"])
                and row["validator_sha256"] == source["runtime_readback_validator"]["sha256"]
                and row["source_manifest_sha256"] == source_manifest_semantic_sha256,
                "functional v4 process ledger changed source/policy/calibration identity")
        calibration = source["resource_domain_calibration"]
        require(row["calibration_binary_sha256"] == calibration["binary"]["sha256"]
                and row["calibration_output_sha256"] == calibration["output"]["sha256"],
                "functional v4 process ledger differs from independent calibration artifacts")

        artifact_path, stdout_raw, stdout_sha256 = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "stdout", "stdout_sha256")
        output = validate_v4_output_row(stdout_raw, str(artifact_path), row, context, process_deadline, drain_deadline)
        binary_path, binary_sha256, _ = safe_source_file(
            source_root, source["artifacts"][row["allocator"]]["path"], "application binary"
        )
        require(binary_sha256 == source["artifacts"][row["allocator"]]["sha256"], "functional v4 application binary no longer matches SourceSchemaV4")
        expected_oracle_path = oracle_paths.get(row["allocator"])
        expected_oracle_sha256 = oracle_hashes.get(row["allocator"])
        require((expected_oracle_path is None) == (context["mode"] == "capacity"), "functional v4 oracle presence differs from mode")
        validate_v4_process_argv(
            row, binding, binary_path, tmpdir_root / f"{row['pair']}-{row['executor']}", context,
            cpu_set, raw_root, trace_deadline, drain_deadline, shutdown_deadline, process_deadline,
            expected_oracle_path, expected_oracle_sha256,
        )
        nonce_key = f"report_nonce_{row['pair']}_{row['executor']}"
        require(metadata.get(nonce_key) == binding["report_nonce"], "functional v4 report nonce differs from its fresh recipe")
        tmp_key = f"functional_tmpdir_{row['pair']}_{row['executor']}"
        expected_tmp = tmpdir_root / f"{row['pair']}-{row['executor']}"
        require(metadata.get(tmp_key) == str(expected_tmp), "runner used a different private per-process TMPDIR")
        process_tmpdir = expected_tmp
        require(process_tmpdir.is_dir() and not process_tmpdir.is_symlink()
                and not any(process_tmpdir.iterdir()), "disk workload left files in its private per-process TMPDIR")
        try:
            context_before = json.loads(metadata[f"functional_tmpdir_context_before_{row['pair']}_{row['executor']}"])
            context_after = json.loads(metadata[f"functional_tmpdir_context_after_{row['pair']}_{row['executor']}"])
        except (KeyError, json.JSONDecodeError) as error:
            raise RuntimeError("functional per-process TMPDIR context is missing or malformed") from error
        actual_process_context = filesystem_context(process_tmpdir)
        for recorded in (context_before, context_after):
            for key in ("path", "mount_point", "filesystem_type", "source", "mount_device", "st_dev"):
                require(recorded.get(key) == actual_process_context[key],
                        "functional per-process TMPDIR filesystem changed during execution")
            require(recorded["filesystem_type"] not in ("tmpfs", "ramfs"),
                    "functional per-process TMPDIR used a memory-backed filesystem")

        shutdown_path = pair_dir / f"{row['pair']}-{row['executor']}.shutdown.tsv"
        require(hash_path(shutdown_path) == row["shutdown_sha256"], "functional shutdown receipt SHA-256 differs")
        shutdown_sha256 = validate_v4_shutdown_report(
            shutdown_path, binding, source, binary_sha256, context["workload"], context["profile"],
            process_deadline, drain_deadline, shutdown_deadline,
            31 if context["mode"] == "capacity" else trace_deadline, output,
        )

        family_sha256 = validate_v4_capacity_family(
            pair_dir, row, binding, source, context, binary_sha256, output,
        ) if context["mode"] == "capacity" else "not_applicable"
        require(row["capacity_family_sha256"] == family_sha256, "capacity family receipt differs from its process-ledger pin")
        oracle_sha256 = "not_applicable"
        ids_sha256 = "not_applicable"
        if context["mode"] == "open_loop":
            require(expected_oracle_path is not None and expected_oracle_sha256 is not None,
                    "open-loop functional process lacks its source/binary oracle")
            oracle_sha256 = expected_oracle_sha256
            ids_sha256 = validate_v4_open_loop_ids(
                pair_dir, row, binding, source, context, binary_sha256, expected_oracle_path, expected_oracle_sha256,
                output, process_deadline, trace_deadline,
            )
            require(metadata.get(f"oracle_sha256_{row['pair']}_{row['executor']}") == oracle_sha256,
                    "functional runner metadata changed its per-process oracle pin")
        else:
            require(row["ids_sha256"] == "not_applicable", "capacity mode unexpectedly emitted an open-loop ID ledger")

        _receipt_path, receipt_raw, receipt_sha256 = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_readback", "runtime_readback_sha256")
        _expectation_path, expectation_raw, expectation_sha256 = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_expectation", "runtime_expectation_sha256")
        _validation_path, validation_raw, validation_sha256 = _CAMPAIGN.process_artifact_bytes(pair_dir, row, "runtime_validation", "runtime_validation_sha256")
        expected = module.build_fixed_expectation(binding["recipe"])
        require(expectation_sha256 == binding["expectation_sha256"]
                and expectation_raw == module.canonical_bytes(expected),
                "source-pinned runtime expectation differs from the direct functional recipe")
        receipt_schema, fields = module.read_receipt_versioned(BytesArtifactPath(receipt_raw))
        validation = module.validate_runtime_readback(fields, expected, receipt_schema)
        stored_validation = _CAMPAIGN.parse_json_object_bytes(validation_raw, "functional v4 receipt validation", _CAMPAIGN.MAX_READBACK_ARTIFACT_BYTES)
        _CAMPAIGN.exact_keys(stored_validation, {"schema", "validated", "expectation_sha256", "field_count"}, "functional receipt validation")
        require(_CAMPAIGN.canonical_bytes(stored_validation) == _CAMPAIGN.canonical_bytes(validation)
                and validation["validated"] is True
                and validation["expectation_sha256"] == binding["expectation_sha256"]
                and validation["field_count"] == len(fields),
                "runtime receipt was not independently revalidated by the source-pinned validator")
        require(set(module.DIMENSIONS) == {"cpu", "memory", "disk", "network", "tasks", "control"},
                "runtime validator resource ledger dimensions changed")
        require(set(module.DIRECTIONS) == {"disk", "upload", "download"},
                "runtime validator directional byte buckets changed")
        expected_baseline = str(source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"])
        require(fields["after_release.global.live_tenants"] == "0"
                and fields["after_release.global.used.control"] == expected_baseline
                and fields["after_release.expected_global_control_baseline"] == expected_baseline
                and fields["after_release.control_matches_fixed_baseline"] == "true",
                "runtime receipt did not return all owners to the independently calibrated Control baseline")
        expected_processes.append({
            "pair": row["pair"], "executor": row["executor"], "allocator": row["allocator"],
            "binary_sha256": binary_sha256, "argv": json.loads(row["argv"]),
            "report_nonce": binding["report_nonce"], "output_sha256": stdout_sha256,
            "runtime_readback_sha256": receipt_sha256, "runtime_expectation_sha256": expectation_sha256,
            "runtime_validation_sha256": validation_sha256, "ids_sha256": ids_sha256,
            "capacity_family_sha256": family_sha256, "shutdown_sha256": shutdown_sha256,
            "oracle_sha256": oracle_sha256, "validated_resource_dimensions": list(module.DIMENSIONS),
            "validated_directional_buckets": list(module.DIRECTIONS),
            "final_global_control_baseline": int(expected_baseline),
        })
    require(hash_path(pair_runner_path) == pair_runner_sha256, "signed functional runner changed after the pair")
    return {
        "pair_status": "functional_only",
        "execution_scope": "functional_only",
        "processes": expected_processes,
        "fixed_global_control_baseline": source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"],
        "resource_dimensions": ["cpu", "memory", "disk", "network", "tasks", "control"],
        "directional_byte_buckets": ["disk", "upload", "download"],
    }


def source_v4_pinned_artifacts(
    source_root: Path, source: dict[str, Any],
) -> dict[str, tuple[Path, str]]:
    records: dict[str, dict[str, str]] = {
        **source["artifacts"],
        **{f"soak-{name}": value for name, value in source["soak_artifacts"].items()},
        "analysis-engine": source["analysis_artifact"],
        "resource-domain-calibration": source["resource_domain_calibration"]["binary"],
        "resource-domain-calibration-output": source["resource_domain_calibration"]["output"],
        "runtime-readback-validator": source["runtime_readback_validator"],
    }
    result: dict[str, tuple[Path, str]] = {}
    for name, record in records.items():
        path, digest, _size = safe_source_file(source_root, record["path"], name)
        require(digest == record["sha256"], f"SourceSchemaV4 {name} artifact changed after controller verification")
        if name in {
            "allocatbelt", "mimalloc-secure", "mimalloc-standard", "system",
            "soak-allocatbelt", "analysis-engine", "resource-domain-calibration",
        }:
            require(os.access(path, os.X_OK), f"SourceSchemaV4 {name} executable is not executable")
        result[name] = (path, digest)
    return result


def _require_signed_source_member(source: dict[str, Any], source_root: Path, path: Path, label: str) -> tuple[str, str]:
    try:
        relative = path.resolve(strict=True).relative_to(source_root.resolve(strict=True)).as_posix()
    except ValueError as error:
        raise RuntimeError(f"{label} must be a committed member of the SourceSchemaV4 root") from error
    entry = next((row for row in source["source"]["files"] if row["path"] == relative), None)
    require(entry is not None and entry["kind"] == "file", f"{label} is not a regular SourceSchemaV4 inventory member")
    digest, _size = hash_stable(path)
    require(digest == entry["sha256"], f"{label} bytes differ from the SourceSchemaV4 inventory")
    return relative, digest


def _copy_exact_bytes(path: Path, raw: bytes, expected_sha256: str, label: str) -> None:
    require(not path.exists() and not path.is_symlink(), f"refusing to replace {label}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600, follow_symlinks=False)
    digest, size = hash_stable(path)
    require(digest == expected_sha256 and size == len(raw), f"copied {label} differs from its pinned input")


def run_source_v4_mode(args: argparse.Namespace, source_root: Path) -> int:
    require(args.source_manifest is not None and args.source_manifest_sha256 is not None,
            "SourceSchemaV4 mode requires a manifest path and its exact raw-file SHA-256")
    source_manifest_path = strict_nonsymlink_path(args.source_manifest, "SourceSchemaV4 manifest")
    source, source_manifest_raw, source_manifest_file_sha256 = load_source_manifest_v4(
        source_root, source_manifest_path, args.source_manifest_sha256, args.signer_fingerprint
    )
    actual_host_id = source["build"]["host_id"]
    require(args.host_id is None or args.host_id == actual_host_id,
            "requested host ID differs from the SourceSchemaV4 build identity")
    host_id = actual_host_id
    context = validate_source_v4_context(
        workload=args.workload, profile=args.profile, mode=args.mode, pair_kind=args.pair_kind,
        baseline_allocator=args.baseline_allocator, rate_per_second=args.rate_per_second,
        arrivals=args.arrivals, trace_deadline_seconds=args.trace_deadline_seconds,
        drain_deadline_seconds=args.drain_deadline_seconds,
        shutdown_deadline_seconds=args.shutdown_deadline_seconds,
        process_deadline_seconds=args.process_deadline_seconds,
        pair_deadline_seconds=args.pair_deadline_seconds,
    )
    context["resource_limits"] = _CAMPAIGN.fixed_resource_limits_for_cell(
        context["workload"], context["profile"], source["runtime_readback_validator"]["sha256"]
    )
    context["resource_ceiling_sha256"] = hashlib.sha256(
        _CAMPAIGN.canonical_bytes(context["resource_limits"])
    ).hexdigest()
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", args.attempt_id) is not None,
            "functional v4 attempt ID must be a safe token of at most 32 characters")
    require(re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", args.cpu_set) is not None,
            "CPU set is not a portable taskset list")
    run_id = "functional-v4-" + "-".join((
        args.attempt_id, context["workload"], context["profile"], context["mode"], context["pair_kind"], "01",
    ))
    require(len(run_id) <= 128, "functional v4 run ID exceeds the runtime recipe bound")

    pair_runner = strict_nonsymlink_path(args.pair_runner, "SourceSchemaV4 pair runner")
    pair_runner_relative, pair_runner_sha256 = _require_signed_source_member(source, source_root, pair_runner, "pair runner")
    require(pair_runner_relative == "scripts/run-application-pair.sh",
            "SourceSchemaV4 mode requires the committed application pair runner")
    helper_path = Path(__file__).resolve(strict=True)
    helper_relative, helper_sha256 = _require_signed_source_member(source, source_root, helper_path, "functional v4 helper")
    require(helper_relative == "scripts/test-application-pair-functional-e2e.py",
            "SourceSchemaV4 mode requires the committed functional helper")
    pinned_artifacts = source_v4_pinned_artifacts(source_root, source)
    output_root = args.output_root.expanduser().absolute()
    cursor = Path(output_root.anchor)
    for part in output_root.parts[1:-1]:
        cursor /= part
        require(not cursor.is_symlink(), f"functional v4 output path traverses a symlink: {cursor}")
    require(not _CAMPAIGN.within(source_root, output_root), "functional v4 outputs must remain outside signed source")
    require(not output_root.exists() and not output_root.is_symlink(), "functional v4 output root must be fresh and nonsymlinked")
    output_root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_root.mkdir(mode=0o700, parents=False, exist_ok=False)

    logs = output_root / "logs"
    raw_root = output_root / "raw"
    functional_inputs = raw_root / ".functional-inputs"
    oracles_dir = raw_root / ".functional-oracles"
    tmpdir_root = raw_root / ".functional-tmp"
    for directory in (logs, raw_root, functional_inputs, oracles_dir, tmpdir_root):
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    storage_context = require_rootfs_storage_context(output_root, tmpdir_root)
    manifest_relative_path = ".functional-inputs/source-manifest.json"
    copied_manifest_path = raw_root / manifest_relative_path
    _copy_exact_bytes(copied_manifest_path, source_manifest_raw, source_manifest_file_sha256, "raw SourceSchemaV4 manifest")

    report_path = output_root / "functional-v4-report.json"
    report: dict[str, Any] = {
        "schema": SOURCE_V4_REPORT_SCHEMA,
        "execution_scope": "functional_only",
        "attempt_id": args.attempt_id,
        "run_id": run_id,
        "source_manifest_schema": SOURCE_MANIFEST_SCHEMA_V4,
        "source_manifest_path": str(source_manifest_path),
        "source_manifest_file_sha256": source_manifest_file_sha256,
        "signer_fingerprint": args.signer_fingerprint,
        "source_manifest_sha256": source["manifest_sha256"],
        "source_head": source["source"]["git_commit"],
        "source_tree_sha256": source["source"]["source_tree_sha256"],
        "host_id": host_id,
        "build": source["build"],
        "functional_context": context,
        "pair_runner_path": str(pair_runner),
        "pair_runner_sha256": pair_runner_sha256,
        "helper_source_path": helper_relative,
        "helper_source_sha256": helper_sha256,
        "artifact_sha256s": source_v4_artifact_hashes(source),
        "fixed_runtime_policy_sha256": source["fixed_runtime_policy"]["policy_sha256"],
        "resource_domain_calibration": source["resource_domain_calibration"],
        "functional_limits": SOURCE_V4_FUNCTIONAL_LIMITS,
        "qualification_flag": 0,
        "pressure_flag": 0,
        "temporary_storage_context": storage_context,
        "temporary_storage_root": str(tmpdir_root),
        "cases": [],
        "passed_functional_checks": False,
    }
    write_report(report_path, report)
    try:
        source_overlay = functional_source_overlay_v4(
            source, context, manifest_relative_path, source_manifest_file_sha256,
            storage_context, ".functional-tmp", args.signer_fingerprint,
        )
        source_overlay_path = output_root / "functional-source-overlay.json"
        source_overlay_raw = write_canonical(source_overlay_path, source_overlay)
        source_overlay_sha256 = hashlib.sha256(source_overlay_raw).hexdigest()
        report["functional_source_overlay_path"] = str(source_overlay_path)
        report["functional_source_overlay_sha256"] = source_overlay_sha256
        report["functional_source_overlay_schema"] = source_overlay["schema"]

        bindings_manifest, bindings = source_v4_runtime_bindings(source, context, run_id)
        binding_path = functional_inputs / f"{run_id}.runtime-bindings.json"
        bindings_raw = write_canonical(binding_path, bindings_manifest)
        bindings_sha256 = hashlib.sha256(bindings_raw).hexdigest()
        require(bindings_sha256 == hashlib.sha256(_CAMPAIGN.canonical_bytes(bindings_manifest)).hexdigest(),
                "functional v4 runtime binding file is not canonical")

        candidate_binary = source_root / source["artifacts"]["allocatbelt"]["path"]
        candidate_sha256 = source["artifacts"]["allocatbelt"]["sha256"]
        baseline_allocator = context["baseline_allocator"]
        baseline_binary: Path | None = None
        baseline_binary_sha256: str | None = None
        if baseline_allocator is not None:
            baseline_binary = source_root / source["artifacts"][baseline_allocator]["path"]
            baseline_binary_sha256 = source["artifacts"][baseline_allocator]["sha256"]
        validator = source["runtime_readback_validator"]
        validator_path = source_root / validator["path"]

        oracle_paths: dict[str, Path] = {}
        oracle_hashes: dict[str, str] = {}
        if context["mode"] == "open_loop":
            unique_allocators = sorted({item["allocator"] for item in bindings})
            for allocator in unique_allocators:
                binary = source_root / source["artifacts"][allocator]["path"]
                oracle_path = oracles_dir / f"{allocator}.oracle.tsv"
                oracle_hashes[allocator] = emit_oracle_v4(
                    source_root, binary, source["artifacts"][allocator]["sha256"],
                    source["source"]["source_tree_sha256"], oracle_path,
                    context["workload"], context["profile"], context["rate_per_second"],
                    context["arrivals"], logs, allocator, output_root,
                )
                oracle_paths[allocator] = oracle_path

        pair_overlay = functional_pair_overlay_v4(
            source, context, run_id, pair_runner_sha256, bindings_sha256, bindings,
            manifest_relative_path, source_manifest_file_sha256, candidate_sha256,
            baseline_binary_sha256, oracle_hashes.get("allocatbelt"),
            oracle_hashes.get(baseline_allocator) if baseline_allocator is not None else None,
            storage_context, ".functional-tmp", args.signer_fingerprint,
        )
        pair_overlay_path = functional_inputs / f"{run_id}.functional-overlay.json"
        pair_overlay_raw = write_canonical(pair_overlay_path, pair_overlay)
        pair_overlay_sha256 = hashlib.sha256(pair_overlay_raw).hexdigest()

        trace_deadline = context["horizon_seconds"] if context["mode"] == "capacity" else args.trace_deadline_seconds
        rate_text = "-" if context["mode"] == "capacity" else str(context["rate_per_second"])
        arrivals_text = str(context["arrivals"])
        candidate_oracle = oracle_paths.get("allocatbelt")
        candidate_oracle_sha = oracle_hashes.get("allocatbelt")
        baseline_oracle = oracle_paths.get(baseline_allocator) if baseline_allocator is not None else None
        baseline_oracle_sha = oracle_hashes.get(baseline_allocator) if baseline_allocator is not None else None
        baseline_args = (
            [str(baseline_binary), baseline_allocator, str(baseline_oracle) if baseline_oracle else "",
             baseline_oracle_sha or ""]
            if baseline_allocator is not None else ["", "", "", ""]
        )
        command = [
            str(pair_runner), "--functional-only", str(candidate_binary), "allocatbelt",
            context["workload"], context["mode"], rate_text, args.cpu_set, run_id, str(raw_root),
            arrivals_text, str(trace_deadline), str(args.drain_deadline_seconds),
            str(args.shutdown_deadline_seconds), str(args.process_deadline_seconds),
            str(candidate_oracle) if candidate_oracle else "", candidate_oracle_sha or "",
            context["profile"], context["pair_kind"], *baseline_args,
            "--runtime-bindings", str(binding_path), "--runtime-bindings-sha256", bindings_sha256,
            "--runtime-validator", str(validator_path), "--runtime-validator-sha256", validator["sha256"],
            "--fixed-global-control-baseline", str(source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"]),
            "--functional-overlay", str(pair_overlay_path), "--functional-overlay-sha256", pair_overlay_sha256,
        ]
        case_logs = logs / "selected-case"
        case_logs.mkdir(mode=0o700)
        child_env = os.environ.copy()
        child_env["PATH"] = safe_external_path(source_root)
        child_env["TMPDIR"] = str(tmpdir_root)
        exit_code = run_bounded(
            command, source_root, case_logs / "runner.stdout.log", case_logs / "runner.stderr.log",
            args.pair_deadline_seconds, env=child_env,
            file_size_limit_bytes=SOURCE_V4_FUNCTIONAL_LIMITS["max_file_bytes"],
            watch_root=output_root,
        )
        (case_logs / "runner.exit").write_text(f"{exit_code}\n", encoding="ascii")
        case: dict[str, Any] = {
            "run_id": run_id,
            "functional_context": context,
            "execution_scope": "functional_only",
            "runner_argv": command,
            "pair_runner_sha256": pair_runner_sha256,
            "runtime_bindings_path": str(binding_path),
            "runtime_bindings_sha256": bindings_sha256,
            "functional_overlay_path": str(pair_overlay_path),
            "functional_overlay_sha256": pair_overlay_sha256,
            "oracle_sha256_by_allocator": oracle_hashes,
            "exit_code": exit_code,
        }
        report["cases"].append(case)
        report["output_budget_after_runner"] = enforce_functional_tree_budget(output_root)
        write_report(report_path, report)
        require(exit_code == 0, "functional v4 runner failed; its failed process tree and logs are retained")

        pair_dir = raw_root / run_id
        case["validation"] = validate_v4_process_ledger(
            pair_dir, source_root, source, context, bindings, pair_overlay_sha256,
            pair_runner_sha256, bindings_sha256, source_manifest_file_sha256,
            source["manifest_sha256"], args.signer_fingerprint, copied_manifest_path, source_manifest_raw,
            oracle_paths, oracle_hashes, baseline_oracle_sha, pair_runner,
            args.cpu_set, raw_root, tmpdir_root, trace_deadline,
            args.drain_deadline_seconds, args.shutdown_deadline_seconds,
            args.process_deadline_seconds,
        )
        case["validated_processes"] = len(case["validation"]["processes"])
        case["temporary_process_filesystems"] = {
            f"{item['pair']}-{item['executor']}": filesystem_context(tmpdir_root / f"{item['pair']}-{item['executor']}")
            for item in bindings
        }
        require(all(
            item["st_dev"] == storage_context["tmpdir_root"]["st_dev"]
            and item["mount_point"] == storage_context["tmpdir_root"]["mount_point"]
            and item["filesystem_type"] == storage_context["tmpdir_root"]["filesystem_type"]
            and item["filesystem_type"] not in ("tmpfs", "ramfs")
            for item in case["temporary_process_filesystems"].values()
        ), "per-process TMPDIR filesystem changed during the functional pair")
        require(hash_path(pair_overlay_path) == pair_overlay_sha256, "functional v4 pair overlay changed during execution")
        require(hash_path(source_overlay_path) == source_overlay_sha256,
                "functional v4 source overlay changed during execution")
        require(hash_path(binding_path) == bindings_sha256, "functional v4 runtime bindings changed during execution")
        for name, (artifact_path, artifact_sha256) in pinned_artifacts.items():
            require(hash_path(artifact_path) == artifact_sha256, f"SourceSchemaV4 input changed during execution: {name}")
        _CAMPAIGN.verify_source_manifest(source, source_root, verify_artifacts=True)
        require(hash_path(source_manifest_path) == source_manifest_file_sha256,
                "original SourceSchemaV4 manifest file changed during execution")
        require(hash_path(pair_runner) == pair_runner_sha256 and hash_path(helper_path) == helper_sha256,
                "signed functional helper or runner changed during execution")
        for allocator, oracle_path in oracle_paths.items():
            require(hash_path(oracle_path) == oracle_hashes[allocator], f"functional v4 oracle changed: {allocator}")
        report["passed_functional_checks"] = True
        report["output_budget_final"] = enforce_functional_tree_budget(output_root)
        write_report(report_path, report)
        return 0
    except Exception as error:
        report["passed_functional_checks"] = False
        report["error"] = str(error)
        try:
            report["output_budget_at_failure"] = enforce_functional_tree_budget(output_root)
        except Exception as budget_error:
            report["output_budget_error"] = str(budget_error)
        try:
            write_report(report_path, report)
        except Exception:
            pass
        print(f"functional v4 E2E stopped: {error}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    global _CAMPAIGN, _SOURCE_INVENTORY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--pair-runner", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--cpu-set", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--host-id")
    parser.add_argument("--candidate-binary")
    parser.add_argument("--secure-baseline-binary")
    parser.add_argument("--calibration-binary")
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--source-manifest-sha256")
    parser.add_argument("--signer-fingerprint")
    parser.add_argument("--workload", choices=("cpu", "memory", "http", "disk", "mixed"))
    parser.add_argument("--profile", choices=("steady", "mixed", "burst", "oversubscribed"))
    parser.add_argument("--mode", choices=("open_loop", "capacity"))
    parser.add_argument("--pair-kind", choices=("matched", "aa-bounded", "aa-tokio", "allocator-match"))
    parser.add_argument("--baseline-allocator", choices=SOURCE_V4_BASELINES)
    parser.add_argument("--arrivals", type=int)
    parser.add_argument("--rate-per-second", type=int)
    parser.add_argument("--trace-deadline-seconds", type=int)
    parser.add_argument("--drain-deadline-seconds", type=int)
    parser.add_argument("--shutdown-deadline-seconds", type=int)
    parser.add_argument("--process-deadline-seconds", type=int)
    parser.add_argument("--pair-deadline-seconds", type=int)
    args = parser.parse_args(argv)

    v4_requested = args.source_manifest is not None or args.source_manifest_sha256 is not None
    source_root = strict_nonsymlink_path(args.source_root, "SourceSchemaV4 source root") if v4_requested else args.source_root.resolve(strict=True)
    v4_options = (
        args.workload, args.profile, args.mode, args.pair_kind, args.baseline_allocator,
    )
    if args.source_manifest is not None or args.source_manifest_sha256 is not None:
        try:
            require(args.source_manifest is not None and args.source_manifest_sha256 is not None,
                    "SourceSchemaV4 mode requires both --source-manifest and --source-manifest-sha256")
            require(args.signer_fingerprint is not None,
                    "SourceSchemaV4 mode requires a caller-frozen --signer-fingerprint")
            require(all(item is not None for item in v4_options[:4]),
                    "SourceSchemaV4 mode requires workload, profile, mode, and pair kind")
            args.trace_deadline_seconds = args.trace_deadline_seconds if args.trace_deadline_seconds is not None else (30 if args.mode == "capacity" else 10)
            args.drain_deadline_seconds = args.drain_deadline_seconds if args.drain_deadline_seconds is not None else 10
            args.shutdown_deadline_seconds = args.shutdown_deadline_seconds if args.shutdown_deadline_seconds is not None else 5
            shutdown_units = {"http": 3, "disk": 2, "mixed": 4}.get(args.workload, 1)
            phase_trace_deadline = 31 if args.mode == "capacity" else args.trace_deadline_seconds
            minimum_process_deadline = (120 + phase_trace_deadline + args.drain_deadline_seconds
                                        + args.shutdown_deadline_seconds * shutdown_units)
            args.process_deadline_seconds = (
                args.process_deadline_seconds
                if args.process_deadline_seconds is not None
                else max(150, minimum_process_deadline)
            )
            args.pair_deadline_seconds = (
                args.pair_deadline_seconds
                if args.pair_deadline_seconds is not None
                else max(360, args.process_deadline_seconds * 2)
            )
            if args.mode == "capacity":
                args.rate_per_second = args.rate_per_second
                args.arrivals = args.arrivals
            else:
                args.rate_per_second = args.rate_per_second if args.rate_per_second is not None else 1000
                args.arrivals = args.arrivals if args.arrivals is not None else 1000
            return run_source_v4_mode(args, source_root)
        except Exception as error:
            print(f"functional v4 E2E stopped: {error}", file=sys.stderr)
            return 1

    require(args.signer_fingerprint is None, "--signer-fingerprint is only valid with SourceSchemaV4 mode")
    require(not any(item is not None for item in v4_options) and args.baseline_allocator is None,
            "workload/profile/pair selection requires a SourceSchemaV4 manifest")
    _SOURCE_INVENTORY = load_source_inventory_module()
    _CAMPAIGN = load_campaign_module(source_root)
    args.host_id = args.host_id if args.host_id is not None else "agent-9700x-baremetal"
    args.candidate_binary = args.candidate_binary if args.candidate_binary is not None else "target/release/bench-application-allocatbelt"
    args.secure_baseline_binary = args.secure_baseline_binary if args.secure_baseline_binary is not None else "target/release/bench-application-mimalloc"
    args.calibration_binary = args.calibration_binary if args.calibration_binary is not None else "target/release/bench-resource-domain-calibration"
    args.arrivals = args.arrivals if args.arrivals is not None else 1000
    args.rate_per_second = args.rate_per_second if args.rate_per_second is not None else 1000
    args.trace_deadline_seconds = args.trace_deadline_seconds if args.trace_deadline_seconds is not None else 10
    args.drain_deadline_seconds = args.drain_deadline_seconds if args.drain_deadline_seconds is not None else 10
    args.shutdown_deadline_seconds = args.shutdown_deadline_seconds if args.shutdown_deadline_seconds is not None else 5
    args.process_deadline_seconds = args.process_deadline_seconds if args.process_deadline_seconds is not None else 150
    args.pair_deadline_seconds = args.pair_deadline_seconds if args.pair_deadline_seconds is not None else 360
    pair_runner = args.pair_runner.resolve(strict=True)
    output_root = args.output_root.expanduser().absolute()
    cursor = Path(output_root.anchor)
    for part in output_root.parts[1:-1]:
        cursor /= part
        require(not cursor.is_symlink(), f"functional E2E output path traverses a symlink: {cursor}")
    output_root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not output_root.exists() and not output_root.is_symlink(), "functional E2E output root must be a fresh nonsymlink path")
    require(not _CAMPAIGN.within(source_root, output_root), "functional E2E output root must remain outside signed source")
    require(not _CAMPAIGN.within(source_root, pair_runner), "pair runner overlay must remain outside signed source")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.attempt_id) is not None, "attempt ID is not a safe bounded token")
    require(re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", args.cpu_set) is not None, "CPU set is not a portable taskset list")
    require(args.arrivals == 1000 and args.rate_per_second == 1000, "functional E2E pins the exact bounded 1000-arrival/second CPU smoke")
    require(
        1 <= args.trace_deadline_seconds <= 30
        and 1 <= args.drain_deadline_seconds <= 30
        and 1 <= args.shutdown_deadline_seconds <= 15
        and 1 <= args.process_deadline_seconds <= 300
        and 1 <= args.pair_deadline_seconds <= 600,
        "functional E2E deadline exceeds its finite envelope",
    )
    require(pair_runner.is_file() and not pair_runner.is_symlink() and os.access(pair_runner, os.X_OK), "pair runner overlay must be an executable regular file")
    pair_runner_sha256 = hash_path(pair_runner)

    output_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    logs = output_root / "logs"
    raw_root = output_root / "raw"
    functional_inputs = raw_root / ".functional-inputs"
    oracles_dir = raw_root / ".functional-oracles"
    logs.mkdir(mode=0o700)
    raw_root.mkdir(mode=0o700)
    functional_inputs.mkdir(mode=0o700)
    oracles_dir.mkdir(mode=0o700)
    report_path = output_root / "functional-e2e-report.json"
    report: dict[str, Any] = {
        "schema": "allocatbelt.application-functional-pair-e2e-report.v1",
        "execution_scope": "functional_only",
        "attempt_id": args.attempt_id,
        "signed_source_commit": SIGNED_SOURCE_COMMIT,
        "pair_runner_sha256": pair_runner_sha256,
        "functional_source_overlay_schema": "allocatbelt.application-functional-source-overlay.v2",
        "functional_limits": FUNCTIONAL_LIMITS,
        "cases": [],
    }
    write_report(report_path, report)

    try:
        calibration_output_relative = f"target/functional-e2e-calibration/{args.attempt_id}/calibration-output.json"
        source, pinned_artifacts, build_info = functional_source_overlay(
            source_root,
            output_root,
            logs,
            args.attempt_id,
            args.host_id,
            args.candidate_binary,
            args.secure_baseline_binary,
            args.calibration_binary,
            calibration_output_relative,
        )
        source_tree_sha256 = source["source"]["source_tree_sha256"]
        calibration = source["resource_domain_calibration"]
        baseline = calibration["record"]["fixed_global_control_baseline"]
        validator = source["runtime_readback_validator"]
        validator_path = source_root / validator["path"]
        candidate_binary = source_root / source["artifacts"]["allocatbelt"]["path"]
        secure_binary = source_root / source["artifacts"]["mimalloc-secure"]["path"]
        candidate_sha = source["artifacts"]["allocatbelt"]["sha256"]
        secure_sha = source["artifacts"]["mimalloc-secure"]["sha256"]
        source_overlay_path = output_root / "functional-source-overlay.json"
        source_overlay_sha256 = hash_path(source_overlay_path)
        report.update({
            "source_tree_sha256": source_tree_sha256,
            "functional_source_overlay_sha256": source_overlay_sha256,
            "functional_source_overlay_manifest_sha256": source["manifest_sha256"],
            "runtime_validator_sha256": validator["sha256"],
            "candidate_binary_sha256": candidate_sha,
            "secure_baseline_binary_sha256": secure_sha,
            "calibration_binary_sha256": calibration["binary"]["sha256"],
            "calibration_output_sha256": calibration["output"]["sha256"],
            "fixed_global_control_baseline": baseline,
            "build_features_sha256": build_info["features_manifest_sha256"],
            "build_inputs_sha256": build_info["build_inputs_sha256"],
            "build_command": build_info["build_command"],
            "feature_tree_sha256": build_info["feature_tree_sha256"],
        })
        write_report(report_path, report)

        rate = args.rate_per_second
        arrivals = args.arrivals
        oracle_paths: dict[str, Path] = {}
        oracle_hashes: dict[str, str] = {}
        for allocator, binary, binary_sha in (
            ("allocatbelt", candidate_binary, candidate_sha),
            ("mimalloc-secure", secure_binary, secure_sha),
        ):
            oracle_path = oracles_dir / f"{allocator}.oracle.tsv"
            oracle_hashes[allocator] = emit_oracle(
                source_root, binary, binary_sha, source_tree_sha256, oracle_path,
                rate, arrivals, logs, allocator,
            )
            oracle_paths[allocator] = oracle_path

        cell_limits = _CAMPAIGN.fixed_resource_limits_for_cell(WORKLOAD, PROFILE, validator["sha256"])
        cell = {
            "family": WORKLOAD,
            "workload": WORKLOAD,
            "profile": PROFILE,
            "arrivals": arrivals,
            "async_workers": 4,
            "resource_limits": cell_limits,
            "resource_ceiling_sha256": hashlib.sha256(_CAMPAIGN.canonical_bytes(cell_limits)).hexdigest(),
            "capacity_horizon_seconds": 30,
        }
        spec = {"campaign_id": f"functional-e2e-{args.attempt_id}", "cells": [cell]}
        cases = (("matched", "matched"), ("aa-bounded", "aa-bounded"), ("aa-tokio", "aa-tokio"), ("allocator-match", "allocator-match"))
        for case_name, pair_kind in cases:
            run_id = f"functional-{case_name}-{args.attempt_id}-01"
            job_data = bindings_for_case(source, spec, run_id, pair_kind, rate, arrivals)
            job = job_data["job"]
            bindings = job_data["bindings"]
            binding_path = functional_inputs / f"{run_id}.runtime-bindings.json"
            binding_sha256 = _CAMPAIGN.write_runtime_binding_manifest(binding_path, bindings, job, spec, source)
            baseline_binary_sha = secure_sha if pair_kind == "allocator-match" else None
            baseline_oracle_sha = oracle_hashes["mimalloc-secure"] if pair_kind == "allocator-match" else None
            overlay = process_overlay(
                source, run_id, pair_kind, rate, arrivals, pair_runner_sha256, binding_sha256,
                bindings, candidate_sha, baseline_binary_sha, oracle_hashes["allocatbelt"], baseline_oracle_sha,
            )
            overlay_path = functional_inputs / f"{run_id}.functional-overlay.json"
            overlay_raw = write_canonical(overlay_path, overlay)
            overlay_sha256 = hashlib.sha256(overlay_raw).hexdigest()
            baseline_args = (
                [str(secure_binary), "mimalloc-secure", str(oracle_paths["mimalloc-secure"]), baseline_oracle_sha]
                if pair_kind == "allocator-match" else ["", "", "", ""]
            )
            command = [
                str(pair_runner), "--functional-only", str(candidate_binary), "allocatbelt",
                WORKLOAD, MODE, str(rate), args.cpu_set, run_id, str(raw_root),
                str(arrivals), str(args.trace_deadline_seconds), str(args.drain_deadline_seconds),
                str(args.shutdown_deadline_seconds), str(args.process_deadline_seconds),
                str(oracle_paths["allocatbelt"]), oracle_hashes["allocatbelt"], PROFILE, pair_kind,
                *baseline_args,
                "--runtime-bindings", str(binding_path),
                "--runtime-bindings-sha256", binding_sha256,
                "--runtime-validator", str(validator_path),
                "--runtime-validator-sha256", validator["sha256"],
                "--fixed-global-control-baseline", str(baseline),
                "--functional-overlay", str(overlay_path),
                "--functional-overlay-sha256", overlay_sha256,
            ]
            case_logs = logs / case_name
            case_logs.mkdir(mode=0o700)
            exit_code = run_bounded(
                command, source_root, case_logs / "runner.stdout.log",
                case_logs / "runner.stderr.log", args.pair_deadline_seconds,
            )
            (case_logs / "runner.exit").write_text(f"{exit_code}\n", encoding="ascii")
            case_result: dict[str, Any] = {
                "run_id": run_id,
                "pair_kind": pair_kind,
                "execution_scope": "functional_only",
                "pair_runner_sha256": pair_runner_sha256,
                "runtime_bindings_path": str(binding_path),
                "runtime_bindings_sha256": binding_sha256,
                "functional_overlay_path": str(overlay_path),
                "functional_overlay_sha256": overlay_sha256,
                "oracle_sha256": oracle_hashes["allocatbelt"],
                "baseline_oracle_sha256": baseline_oracle_sha,
                "exit_code": exit_code,
            }
            report["cases"].append(case_result)
            if exit_code != 0:
                report["passed_functional_checks"] = False
                write_report(report_path, report)
                fail(f"native functional pair failed for {case_name}; see {case_logs}")
            pair_dir = raw_root / run_id
            case_result["validation"] = validate_functional_pair(
                pair_dir, source, spec, job, bindings, overlay_sha256,
                pair_runner_sha256, binding_sha256, oracle_hashes["allocatbelt"],
                baseline_binary_sha, baseline_oracle_sha,
            )
            case_result["validated_processes"] = len(case_result["validation"]["processes"])
            write_report(report_path, report)

        current_commit = run_checked(["git", "rev-parse", "HEAD"], source_root).decode("ascii").strip()
        require(current_commit == source["source"]["git_commit"], "signed source commit changed across functional E2E")
        current_status = run_checked(["git", "status", "--porcelain", "--untracked-files=no"], source_root)
        require(current_status == b"", "tracked signed source changed across functional E2E")
        require(_SOURCE_INVENTORY is not None, "shared source inventory module was not loaded")
        current_inventory = _SOURCE_INVENTORY.inventory(source_root)
        current_tree_sha256 = _SOURCE_INVENTORY.digest_inventory(current_inventory)
        current_source_files = current_inventory["entries"]
        require(
            current_tree_sha256 == source_tree_sha256 and current_source_files == source["source"]["files"],
            "signed source inventory changed across functional E2E",
        )
        source_inventory_module_path = Path(__file__).with_name("application-source-inventory.py")
        require(hash_path(source_inventory_module_path) == SOURCE_INVENTORY_MODULE_SHA256, "shared source inventory module changed across functional E2E")
        require(hash_path(pair_runner) == pair_runner_sha256, "functional runner draft changed across E2E runs")
        require(hash_path(source_overlay_path) == source_overlay_sha256, "functional source overlay changed during E2E")
        for allocator, oracle_path in oracle_paths.items():
            require(hash_path(oracle_path) == oracle_hashes[allocator], f"frozen oracle changed during E2E: {allocator}")
        for artifact_name, (artifact_path, artifact_sha256) in pinned_artifacts.items():
            require(hash_path(artifact_path) == artifact_sha256, f"frozen input changed during functional E2E: {artifact_name}")
        for artifact_name, evidence in source["build_evidence"].items():
            evidence_path = output_root / evidence["path"]
            require(hash_path(evidence_path) == evidence["sha256"], f"build evidence changed during functional E2E: {artifact_name}")
        for item in report["cases"]:
            require(hash_path(Path(item["runtime_bindings_path"])) == item["runtime_bindings_sha256"], "runtime binding manifest changed during E2E")
            require(hash_path(Path(item["functional_overlay_path"])) == item["functional_overlay_sha256"], "functional pair overlay changed during E2E")
        report["passed_functional_checks"] = True
        write_report(report_path, report)
        return 0
    except Exception as error:
        report["passed_functional_checks"] = False
        report["error"] = str(error)
        try:
            write_report(report_path, report)
        except Exception:
            pass
        print(f"functional E2E stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
