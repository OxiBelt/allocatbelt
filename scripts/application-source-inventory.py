#!/usr/bin/env python3
"""Capture a bounded, typed identity for a Git worktree's source files.

Tracked terminal symlinks are included by hashing their literal link text.
They may point directly to another tracked regular file inside the worktree.
All other symlinks and all symlinked parent directories are rejected.

Records are sorted by UTF-8 path bytes. File modes are ``100644`` or
``100755``; terminal links use ``120000`` and include their UTF-8 target.
The tree digest is SHA-256 over the inventory object encoded as ASCII JSON
with sorted keys, compact separators, and one trailing LF.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


SCHEMA = "allocatbelt.application-source-inventory.v1"
MAX_FILES = 100_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SYMLINK_BYTES = 4 * 1024
MAX_GIT_CAPTURE_BYTES = 16 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 120.0


class InventoryError(ValueError):
    """The source tree cannot be represented by the inventory contract."""


def _signal_process_group(group_id: int, signum: int) -> None:
    try:
        os.killpg(group_id, signum)
    except ProcessLookupError:
        pass


def _process_group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop_process_group(process: subprocess.Popen[bytes], term_seconds: float = 0.25, kill_seconds: float = 1.0) -> None:
    """Stop every process in the child session, even if its leader exited."""
    group_id = process.pid
    _signal_process_group(group_id, signal.SIGTERM)
    deadline = time.monotonic() + term_seconds
    while _process_group_exists(group_id) and time.monotonic() < deadline:
        process.poll()
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    if _process_group_exists(group_id):
        _signal_process_group(group_id, signal.SIGKILL)
    deadline = time.monotonic() + kill_seconds
    while _process_group_exists(group_id) and time.monotonic() < deadline:
        process.poll()
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
    if _process_group_exists(group_id):
        _signal_process_group(group_id, signal.SIGKILL)
    try:
        process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
        _signal_process_group(group_id, signal.SIGKILL)
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InventoryError(message)


def _sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _encode_utf8(value: str, label: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise InventoryError(f"{label} is not valid Unicode text") from error


def _canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise InventoryError(f"inventory is not canonical JSON: {error}") from error
    return (text + "\n").encode("ascii")


def _checked_capture(args: list[str], cwd: Path, timeout_seconds: float) -> bytes:
    """Capture stdout with a hard byte limit and a finite process deadline."""
    _require(timeout_seconds > 0 and timeout_seconds < float("inf"), "Git command timeout must be finite and positive")
    process: subprocess.Popen[bytes] | None = None
    output = bytearray()
    previous_handlers: dict[int, Any] = {}
    pending_signals: list[int] = []
    cleanup_started = False

    def interrupt(signum: int, _frame: Any) -> None:
        pending_signals.append(signum)
        if process is None:
            return
        _signal_process_group(process.pid, signum)
        if cleanup_started:
            return
        raise InventoryError(f"{args[0]} interrupted by signal {signum}")

    main_thread = threading.current_thread() is threading.main_thread()
    try:
        if main_thread:
            for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.signal(signum, interrupt)
        try:
            process = subprocess.Popen(
                args,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            raise InventoryError(f"cannot start {args[0]}: {error}") from error
        if pending_signals:
            for signum in pending_signals:
                _signal_process_group(process.pid, signum)
            raise InventoryError(f"{args[0]} interrupted during process startup")
        assert process.stdout is not None
        deadline = time.monotonic() + timeout_seconds
        descriptor = process.stdout.fileno()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InventoryError(f"{args[0]} exceeded its finite deadline")
            readable, _writable, _exceptional = select.select([descriptor], [], [], remaining)
            if not readable:
                raise InventoryError(f"{args[0]} exceeded its finite deadline")
            block = os.read(descriptor, min(64 * 1024, MAX_GIT_CAPTURE_BYTES + 1 - len(output)))
            if not block:
                break
            output.extend(block)
            if len(output) > MAX_GIT_CAPTURE_BYTES:
                raise InventoryError(f"{args[0]} output exceeds its finite capture bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InventoryError(f"{args[0]} exceeded its finite deadline")
        try:
            status = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise InventoryError(f"{args[0]} exceeded its finite deadline") from error
        _require(status == 0, f"{args[0]} failed with exit status {status}")
        cleanup_started = True
        try:
            _stop_process_group(process, term_seconds=0.05, kill_seconds=0.25)
        finally:
            cleanup_started = False
        if pending_signals:
            raise InventoryError(f"{args[0]} interrupted by signal {pending_signals[0]} during capture cleanup")
        return bytes(output)
    except BaseException:
        if process is not None:
            cleanup_started = True
            try:
                _stop_process_group(process)
            finally:
                cleanup_started = False
        raise
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _nul_records(raw: bytes, label: str, allow_empty: bool = False) -> list[bytes]:
    if not raw and allow_empty:
        return []
    _require(raw.endswith(b"\0"), f"{label} is not NUL framed")
    records = raw[:-1].split(b"\0")
    _require(all(records), f"{label} contains an empty path")
    return records


def _git_paths(root: Path, timeout_seconds: float) -> tuple[list[bytes], dict[bytes, str]]:
    listed = _nul_records(
        _checked_capture(["git", "ls-files", "-co", "--exclude-standard", "-z"], root, timeout_seconds),
        "Git source path list",
        allow_empty=True,
    )
    _require(len(listed) <= MAX_FILES, "source tree exceeds its finite file-count bound")
    listed = sorted(set(listed))
    _require(listed, "source tree contains no files")

    staged = _nul_records(
        _checked_capture(["git", "ls-files", "--stage", "-z"], root, timeout_seconds),
        "Git tracked mode list",
        allow_empty=True,
    )
    tracked: dict[bytes, str] = {}
    for record in staged:
        header, separator, path = record.partition(b"\t")
        _require(bool(separator), "Git tracked mode record is malformed")
        fields = header.split(b" ")
        _require(len(fields) == 3 and fields[2] == b"0", "Git index has an unmerged or malformed source path")
        try:
            mode = fields[0].decode("ascii")
        except UnicodeDecodeError as error:
            raise InventoryError("Git tracked mode is not ASCII") from error
        _require(mode in ("100644", "100755", "120000"), "Git tracked path has an unsupported mode")
        _require(path not in tracked, "Git index repeats a tracked source path")
        tracked[path] = mode

    _require(set(tracked).issubset(listed), "Git tracked source path is absent from the source path list")
    return listed, tracked


def _decode_path(raw: bytes) -> str:
    _require(raw.startswith(b"/") is False and b"\\" not in raw and b"\n" not in raw and b"\r" not in raw and b"\0" not in raw,
             "source path contains a forbidden character")
    parts = raw.split(b"/")
    _require(all(part not in (b"", b".", b"..") for part in parts), "source path is not normalized and relative")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InventoryError("source path is not valid UTF-8") from error


def _root_fd(root: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fsencode(root), flags)
    except OSError as error:
        raise InventoryError(f"cannot open source root without following links: {error}") from error
    _require(stat.S_ISDIR(os.fstat(descriptor).st_mode), "source root is not a directory")
    return descriptor


def _directory_fingerprint(result: os.stat_result) -> tuple[int, int, int]:
    return result.st_dev, result.st_ino, stat.S_IFMT(result.st_mode)


def _open_parent(root_fd: int, components: list[bytes]) -> tuple[int, tuple[tuple[int, int, int], ...]]:
    current = os.dup(root_fd)
    identities: list[tuple[int, int, int]] = []
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for component in components:
            try:
                following = os.open(component, flags, dir_fd=current)
            except OSError as error:
                raise InventoryError(f"source parent is missing, non-directory, or symlinked: {os.fsdecode(component)}") from error
            result = os.fstat(following)
            _require(stat.S_ISDIR(result.st_mode), "source parent is not a directory")
            identities.append(_directory_fingerprint(result))
            os.close(current)
            current = following
        return current, tuple(identities)
    except BaseException:
        os.close(current)
        raise


def _path_stat(root_fd: int, components: list[bytes]) -> tuple[os.stat_result, tuple[tuple[int, int, int], ...]]:
    parent, identities = _open_parent(root_fd, components[:-1])
    try:
        try:
            result = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise InventoryError(f"cannot restat source path {os.fsdecode(components[-1])}: {error}") from error
    finally:
        os.close(parent)
    return result, identities


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _read_regular(
    root_fd: int,
    root_path: Path,
    root_identity: tuple[int, int, int],
    raw_path: bytes,
    expected_mode: str | None,
) -> tuple[int, str, str]:
    components = raw_path.split(b"/")
    parent, parent_ids = _open_parent(root_fd, components[:-1])
    descriptor = -1
    try:
        try:
            before_path = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise InventoryError(f"cannot stat source file {os.fsdecode(raw_path)}: {error}") from error
        _require(stat.S_ISREG(before_path.st_mode), f"source path is not a regular file: {os.fsdecode(raw_path)}")
        actual_mode = "100755" if before_path.st_mode & 0o111 else "100644"
        _require(expected_mode in (None, actual_mode), f"tracked Git mode differs from the source file mode: {os.fsdecode(raw_path)}")
        _require(before_path.st_size <= MAX_FILE_BYTES, f"source file exceeds its finite size bound: {os.fsdecode(raw_path)}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(components[-1], flags, dir_fd=parent)
        except OSError as error:
            raise InventoryError(f"cannot open source file without following links {os.fsdecode(raw_path)}: {error}") from error
        before_fd = os.fstat(descriptor)
        _require(stat.S_ISREG(before_fd.st_mode), f"source path changed to a non-regular file: {os.fsdecode(raw_path)}")
        _require(_same_stat(before_path, before_fd), f"source file changed before its stable read: {os.fsdecode(raw_path)}")
        digest = hashlib.sha256()
        count = 0
        while True:
            try:
                block = os.read(descriptor, min(1024 * 1024, MAX_FILE_BYTES + 1 - count))
            except OSError as error:
                raise InventoryError(f"cannot read source file {os.fsdecode(raw_path)}: {error}") from error
            if not block:
                break
            count += len(block)
            _require(count <= MAX_FILE_BYTES, f"source file exceeds its finite size bound: {os.fsdecode(raw_path)}")
            digest.update(block)
        after_fd = os.fstat(descriptor)
        _require(count == before_fd.st_size and _same_stat(before_fd, after_fd), f"source file changed during its stable read: {os.fsdecode(raw_path)}")
        try:
            after_path = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise InventoryError(f"source file disappeared after its stable read: {os.fsdecode(raw_path)}") from error
        _require(_same_stat(before_fd, after_path), f"source file path was replaced during its stable read: {os.fsdecode(raw_path)}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)

    reopened_root = _root_fd(root_path)
    try:
        _require(_directory_fingerprint(os.fstat(reopened_root)) == root_identity, "source root moved during its stable read")
        path_after, parent_ids_after = _path_stat(reopened_root, components)
        _require(parent_ids_after == parent_ids and _same_stat(before_fd, path_after), f"source path moved during its stable read: {os.fsdecode(raw_path)}")
    finally:
        os.close(reopened_root)
    stable_mode = "100755" if before_fd.st_mode & 0o111 else "100644"
    return count, digest.hexdigest(), stable_mode


def _resolve_link_target(root_fd: int, source_parts: list[bytes], target: bytes) -> bytes:
    _require(bool(target) and not target.startswith(b"/"), "source symlink target must be relative and nonempty")
    _require(len(target) <= MAX_SYMLINK_BYTES, "source symlink target exceeds its finite size bound")
    _require(b"\\" not in target and b"\n" not in target and b"\r" not in target and b"\0" not in target,
             "source symlink target contains a forbidden character")
    try:
        target.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InventoryError("source symlink target is not valid UTF-8") from error
    tokens = target.split(b"/")
    _require(all(tokens), "source symlink target is not a normalized relative path")
    resolved = source_parts[:-1].copy()
    for index, token in enumerate(tokens):
        if token == b".":
            continue
        if token == b"..":
            _require(resolved, "source symlink target escapes the worktree")
            resolved.pop()
            continue
        resolved.append(token)
        if index < len(tokens) - 1:
            result, _parents = _path_stat(root_fd, resolved)
            _require(stat.S_ISDIR(result.st_mode), "source symlink target traverses a symlink or non-directory parent")
    _require(resolved, "source symlink target resolves to the worktree directory")
    return b"/".join(resolved)


def _read_symlink(
    root_fd: int,
    root_path: Path,
    root_identity: tuple[int, int, int],
    raw_path: bytes,
    tracked_mode: str | None,
    tracked_modes: dict[bytes, str],
    listed_paths: set[bytes],
) -> tuple[str, int, str]:
    _require(tracked_mode == "120000", f"untracked or incorrectly-modeled symlink is forbidden: {os.fsdecode(raw_path)}")
    components = raw_path.split(b"/")
    parent, parent_ids = _open_parent(root_fd, components[:-1])
    try:
        try:
            before = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise InventoryError(f"cannot stat source symlink {os.fsdecode(raw_path)}: {error}") from error
        _require(stat.S_ISLNK(before.st_mode), f"tracked symlink mode differs from the source path: {os.fsdecode(raw_path)}")
        try:
            target = os.readlink(components[-1], dir_fd=parent)
        except OSError as error:
            raise InventoryError(f"cannot read source symlink {os.fsdecode(raw_path)}: {error}") from error
        _require(isinstance(target, bytes), "platform did not return literal symlink bytes")
        _require(len(target) <= MAX_SYMLINK_BYTES, "source symlink target exceeds its finite size bound")
        try:
            target_text = target.decode("utf-8")
        except UnicodeDecodeError as error:
            raise InventoryError("source symlink target is not valid UTF-8") from error
        try:
            after = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise InventoryError(f"source symlink disappeared while reading it: {os.fsdecode(raw_path)}") from error
        _require(_same_stat(before, after), f"source symlink changed while reading it: {os.fsdecode(raw_path)}")
    finally:
        os.close(parent)

    reopened_root = _root_fd(root_path)
    try:
        _require(_directory_fingerprint(os.fstat(reopened_root)) == root_identity, "source root moved while reading a symlink")
        path_after, parent_ids_after = _path_stat(reopened_root, components)
        _require(parent_ids_after == parent_ids and _same_stat(before, path_after), f"source symlink path moved while reading it: {os.fsdecode(raw_path)}")
        target_path = _resolve_link_target(reopened_root, components, target)
    finally:
        os.close(reopened_root)
    _require(target_path in listed_paths and tracked_modes.get(target_path) in ("100644", "100755"),
             "source symlink must point directly to a tracked regular inventory file")
    return target_text, len(target), hashlib.sha256(target).hexdigest()


def inventory(root: Path | str, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Return the typed source inventory for a Git worktree root."""
    try:
        root_path = Path(root).resolve(strict=True)
    except OSError as error:
        raise InventoryError(f"cannot resolve source root: {error}") from error
    git_root_raw = _checked_capture(["git", "rev-parse", "--show-toplevel"], root_path, timeout_seconds)
    try:
        git_root = Path(git_root_raw.decode("utf-8").rstrip("\n")).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as error:
        raise InventoryError("Git worktree root is malformed") from error
    _require(git_root == root_path, "source root must be the Git worktree root")

    paths, tracked_modes = _git_paths(root_path, timeout_seconds)
    listed_paths = set(paths)
    root_descriptor = _root_fd(root_path)
    root_identity = _directory_fingerprint(os.fstat(root_descriptor))
    entries: list[dict[str, Any]] = []
    total = 0
    try:
        for raw_path in paths:
            path_text = _decode_path(raw_path)
            tracked_mode = tracked_modes.get(raw_path)
            components = raw_path.split(b"/")
            parent, _parents = _open_parent(root_descriptor, components[:-1])
            try:
                try:
                    mode_result = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
                except OSError as error:
                    raise InventoryError(f"source file is missing or unreadable: {path_text}: {error}") from error
            finally:
                os.close(parent)

            if stat.S_ISLNK(mode_result.st_mode):
                target, size, digest = _read_symlink(
                    root_descriptor, root_path, root_identity, raw_path, tracked_mode, tracked_modes, listed_paths
                )
                total += size
                _require(total <= MAX_TOTAL_BYTES, "source tree exceeds its finite total byte bound")
                entries.append({
                    "path": path_text,
                    "kind": "symlink",
                    "mode": "120000",
                    "target": target,
                    "sha256": digest,
                    "size": size,
                })
            else:
                _require(tracked_mode != "120000", f"tracked symlink mode differs from the source path: {path_text}")
                _require(stat.S_ISREG(mode_result.st_mode), f"source path is not a regular file: {path_text}")
                size, digest, mode = _read_regular(root_descriptor, root_path, root_identity, raw_path, tracked_mode)
                total += size
                _require(total <= MAX_TOTAL_BYTES, "source tree exceeds its finite total byte bound")
                entries.append({"path": path_text, "kind": "file", "mode": mode, "sha256": digest, "size": size})
    finally:
        os.close(root_descriptor)

    result = {"schema": SCHEMA, "entries": entries}
    validate_records(result)
    return result


def _resolved_record_target(path: str, target: str, records: dict[str, dict[str, Any]]) -> str:
    _require(isinstance(target, str) and target and not target.startswith("/"), "source symlink target must be relative and nonempty")
    target_bytes = _encode_utf8(target, "source symlink target")
    _require(len(target_bytes) <= MAX_SYMLINK_BYTES, "source symlink target exceeds its finite size bound")
    _require("\\" not in target and "\n" not in target and "\r" not in target and "\0" not in target,
             "source symlink target contains a forbidden character")
    tokens = target.split("/")
    _require(all(tokens), "source symlink target is not a normalized relative path")
    resolved = path.split("/")[:-1]
    for index, token in enumerate(tokens):
        if token == ".":
            continue
        if token == "..":
            _require(resolved, "source symlink target escapes the worktree")
            resolved.pop()
        else:
            resolved.append(token)
            if index < len(tokens) - 1:
                prefix = "/".join(resolved)
                _require(prefix not in records, "source symlink target traverses a known non-directory inventory entry")
    _require(resolved, "source symlink target resolves to the worktree directory")
    return "/".join(resolved)


def validate_records(value: Any) -> list[dict[str, Any]]:
    """Validate a typed inventory object and return its canonical entries."""
    _require(type(value) is dict and set(value) == {"schema", "entries"}, "source inventory must contain exactly schema and entries")
    _require(value["schema"] == SCHEMA, "unsupported source inventory schema")
    entries = value["entries"]
    _require(type(entries) is list and 0 < len(entries) <= MAX_FILES, "source inventory entry list is missing or exceeds its finite count bound")
    paths: list[str] = []
    by_path: dict[str, dict[str, Any]] = {}
    total = 0
    normalized: list[dict[str, Any]] = []
    for index, record_value in enumerate(entries):
        _require(type(record_value) is dict, f"source inventory entry {index} must be an object")
        kind = record_value.get("kind")
        expected_keys = {"path", "kind", "mode", "sha256", "size"}
        if kind == "symlink":
            expected_keys.add("target")
        _require(set(record_value) == expected_keys, f"source inventory entry {index} has unknown or missing keys")
        path = record_value["path"]
        _require(type(path) is str and path, f"source inventory path {index} is malformed")
        path_bytes = _encode_utf8(path, f"source inventory path {index}")
        _decode_path(path_bytes)
        _require(path not in by_path, f"source inventory repeats path {path}")
        mode = record_value["mode"]
        digest = record_value["sha256"]
        size = record_value["size"]
        _require(_sha256(digest) and type(size) is int and size >= 0, f"source inventory entry {path} has an invalid digest or size")
        if kind == "file":
            _require(mode in ("100644", "100755"), f"source file has an invalid mode: {path}")
            _require(size <= MAX_FILE_BYTES, f"source file exceeds its finite size bound: {path}")
            normalized_record = {"path": path, "kind": "file", "mode": mode, "sha256": digest, "size": size}
        else:
            _require(kind == "symlink" and mode == "120000", f"source inventory entry has an invalid kind or mode: {path}")
            target = record_value["target"]
            _require(type(target) is str, f"source symlink target is malformed: {path}")
            target_bytes = _encode_utf8(target, f"source symlink target {path}")
            _require(size == len(target_bytes) and size <= MAX_SYMLINK_BYTES and _sha256(digest) and hashlib.sha256(target_bytes).hexdigest() == digest,
                     f"source symlink hash or size is invalid: {path}")
            normalized_record = {"path": path, "kind": "symlink", "mode": "120000", "target": target, "sha256": digest, "size": size}
        total += size
        _require(total <= MAX_TOTAL_BYTES, "source inventory exceeds its finite total byte bound")
        paths.append(path)
        by_path[path] = normalized_record
        normalized.append(normalized_record)

    _require(paths == sorted(paths, key=lambda path: path.encode("utf-8")), "source inventory entries are not UTF-8 byte sorted")
    symlink_paths = {path for path, entry in by_path.items() if entry["kind"] == "symlink"}
    for path, entry in by_path.items():
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent_path = "/".join(parts[:index])
            _require(parent_path not in symlink_paths, f"source inventory has a symlinked parent: {path}")
            _require(parent_path not in by_path, f"source inventory has a non-directory parent: {path}")
        if entry["kind"] == "symlink":
            target_path = _resolved_record_target(path, entry["target"], by_path)
            target_entry = by_path.get(target_path)
            _require(target_entry is not None and target_entry["kind"] == "file",
                     f"source symlink must point directly to a regular inventory file: {path}")
    return normalized


def digest_inventory(value: Any) -> str:
    """Hash canonical JSON for a validated typed inventory."""
    entries = validate_records(value)
    return hashlib.sha256(_canonical_bytes({"schema": SCHEMA, "entries": entries})).hexdigest()


def digest_records(records: list[dict[str, Any]]) -> str:
    """Hash canonical JSON for a list of source inventory records."""
    return digest_inventory({"schema": SCHEMA, "entries": records})


def source_tree_digest(root: Path | str, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> str:
    return digest_inventory(inventory(root, timeout_seconds))


def verify_source_tree(
    root: Path | str,
    expected_digest: str,
    expected_records: list[dict[str, Any]] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Recompute a worktree identity and require it to match frozen records."""
    _require(_sha256(expected_digest), "expected source tree digest is malformed")
    current = inventory(root, timeout_seconds)
    current_digest = digest_inventory(current)
    _require(current_digest == expected_digest, "source tree digest differs from the frozen inventory")
    if expected_records is not None:
        expected = validate_records({"schema": SCHEMA, "entries": expected_records})
        _require(current["entries"] == expected, "source tree entries differ from the frozen inventory")
    return current


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    digest_parser = commands.add_parser("digest", help="print the canonical source inventory SHA-256")
    digest_parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        print(source_tree_digest(args.root))
    except InventoryError as error:
        print(f"application-source-inventory: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
