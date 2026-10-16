#!/usr/bin/env python3
"""Closed physical capture storage for Source5 historical lineage metadata.

This module consumes a Source-owned finite declaration of exact origin pins,
then reads only a separately captured local tree. It performs no signature
verification, owner replay, application execution, or qualification decision.
A caller must still validate returned bytes with its own Source-pinned
algorithms.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from typing import Any


DECLARATION_SCHEMA = \
    "allocatbelt.application-source5-lineage-capture-declaration.v1"
CAPTURE_MANIFEST_SCHEMA = \
    "allocatbelt.application-source5-lineage-capture-manifest.v1"
STORAGE_USAGE_SCHEMA = \
    "allocatbelt.application-source5-lineage-capture-storage-usage.v1"
HOST_JOB_COUNT = 360
MAX_PATH_BYTES = 4096
MAX_INTEGER = (1 << 63) - 1
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

_ROLE_TOKEN = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")


class PreparedExplorationLineageCaptureError(ValueError):
    """A lineage capture declaration or local capture tree is invalid."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise PreparedExplorationLineageCaptureError(message)


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _token(value: object, label: str) -> str:
    _require(type(value) is str and _TOKEN.fullmatch(value) is not None,
             f"{label} is not a canonical token")
    return value


def _digest(value: object, label: str) -> str:
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None,
             f"{label} is not a lowercase SHA-256 digest")
    return value


def _absolute_origin(value: object) -> str:
    _require(type(value) is str and value.startswith("/") and
             "\\" not in value and "\x00" not in value,
             "origin path is not a bounded absolute POSIX path")
    try:
        path_bytes = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PreparedExplorationLineageCaptureError(
            "origin path is not valid UTF-8",
        ) from error
    _require(len(path_bytes) <= MAX_PATH_BYTES,
             "origin path exceeds its finite byte bound")
    parts = value.split("/")
    _require(parts[0] == "" and len(parts) > 1 and
             all(part not in {"", ".", ".."} for part in parts[1:]),
             "origin path is not lexically normalized")
    _require(all(ord(char) >= 0x20 and ord(char) != 0x7f for char in value),
             "origin path contains a control character")
    return value


def _relative_local(value: object) -> str:
    _require(type(value) is str and value and not value.startswith("/") and
             "\\" not in value and "\x00" not in value,
             "capture path is not a bounded relative POSIX path")
    try:
        path_bytes = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PreparedExplorationLineageCaptureError(
            "capture path is not valid UTF-8",
        ) from error
    _require(len(path_bytes) <= MAX_PATH_BYTES,
             "capture path exceeds its finite byte bound")
    parts = value.split("/")
    _require(all(part not in {"", ".", ".."} for part in parts) and
             all(ord(char) >= 0x20 and ord(char) != 0x7f for char in value),
             "capture path is not lexically normalized")
    return value


def _pin(value: object, label: str = "origin pin") -> dict[str, str]:
    pin = _exact(value, {"path", "raw_sha256"}, label)
    return {"path": _absolute_origin(pin["path"]),
            "raw_sha256": _digest(pin["raw_sha256"], f"{label} digest")}


def _raw_pin(value: object, label: str) -> dict[str, str]:
    _require(type(value) is dict and {"path", "raw_sha256"} <= set(value),
             f"{label} omits its raw origin pin")
    return {"path": _absolute_origin(value["path"]),
            "raw_sha256": _digest(value["raw_sha256"], f"{label} digest")}


def _pin_key(pin: dict[str, str]) -> tuple[str, str]:
    return pin["path"], pin["raw_sha256"]


def _absolute_stage_root(value: object) -> str:
    _require(type(value) is str and value.startswith("/") and
             "\\" not in value and "\x00" not in value,
             "lineage capture root is not a bounded absolute POSIX path")
    try:
        path_bytes = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PreparedExplorationLineageCaptureError(
            "lineage capture root is not valid UTF-8",
        ) from error
    _require(len(path_bytes) <= MAX_PATH_BYTES,
             "lineage capture root exceeds its finite byte bound")
    parts = value.split("/")
    _require(parts[0] == "" and len(parts) > 1 and
             all(part not in {"", ".", ".."} for part in parts[1:]),
             "lineage capture root is not lexically normalized")
    return value


def _open_absolute_directory(path: str) -> tuple[int, tuple[tuple[int, int], ...]]:
    root_fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    current_fd = root_fd
    identities: list[tuple[int, int]] = []
    try:
        for component in path.split("/")[1:]:
            next_fd = os.open(
                component, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                dir_fd=current_fd,
            )
            info = os.fstat(next_fd)
            _require(stat.S_ISDIR(info.st_mode),
                     "lineage capture ancestor is not a directory")
            identities.append((info.st_dev, info.st_ino))
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        if current_fd != root_fd:
            os.close(root_fd)
        return current_fd, tuple(identities)
    except BaseException:
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
        raise


def _manifest_rows(declaration: object, manifest: object) -> tuple[
    dict[str, Any], dict[tuple[str, str], dict[str, Any]], dict[str, dict[str, Any]],
]:
    decl = _exact(declaration, {"schema", "cohort_host_ids", "objects"},
                  "lineage capture declaration")
    _require(decl["schema"] == DECLARATION_SCHEMA and
             type(decl["cohort_host_ids"]) is list and
             len(decl["cohort_host_ids"]) in {2, 3},
             "lineage capture declaration schema/cohort is invalid")
    hosts = [_token(host, "lineage declaration host ID")
             for host in decl["cohort_host_ids"]]
    _require(len(set(hosts)) == len(hosts),
             "lineage capture declaration repeats a cohort host")
    _require(type(decl["objects"]) is list and decl["objects"],
             "lineage capture declaration has no objects")
    expected: dict[tuple[str, str], dict[str, Any]] = {}
    for index, item in enumerate(decl["objects"]):
        row = _exact(item, {
            "origin_pin", "role", "host_id", "maximum_bytes", "byte_count",
            "phase", "run_id", "row_index", "job_sha256",
        }, f"lineage capture declaration object[{index}]")
        pin = _pin(row["origin_pin"])
        _require(type(row["role"]) is str and _ROLE_TOKEN.fullmatch(row["role"]) is not None,
                 "lineage capture role is malformed")
        host_id = row["host_id"]
        _require(host_id is None or
                 (type(host_id) is str and host_id in hosts),
                 "lineage capture object names an unknown cohort host")
        maximum = row["maximum_bytes"]
        count = row["byte_count"]
        _require(type(maximum) is int and 0 < maximum <= MAX_INTEGER and
                 (count is None or (type(count) is int and 0 < count <= maximum)),
                 "lineage capture declaration has an invalid byte cap/count")
        if row["phase"] is None:
            _require(row["run_id"] is None and row["row_index"] is None and
                     row["job_sha256"] is None,
                     "global lineage object has indexed job fields")
        else:
            _require(row["phase"] == "exploration" and
                     type(row["run_id"]) is str and
                     _TOKEN.fullmatch(row["run_id"]) is not None and
                     type(row["row_index"]) is int and
                     0 <= row["row_index"] < HOST_JOB_COUNT,
                     "indexed lineage object job join is malformed")
            _digest(row["job_sha256"], "indexed lineage job digest")
        key = _pin_key(pin)
        _require(key not in expected, "lineage declaration repeats an origin pin")
        expected[key] = {
            "origin_pin": pin, "role": row["role"], "host_id": host_id,
            "maximum_bytes": maximum, "byte_count": count,
            "phase": row["phase"], "run_id": row["run_id"],
            "row_index": row["row_index"], "job_sha256": row["job_sha256"],
        }

    man = _exact(manifest, {"schema", "objects"}, "lineage capture manifest")
    _require(man["schema"] == CAPTURE_MANIFEST_SCHEMA and
             type(man["objects"]) is list and len(man["objects"]) == len(expected),
             "lineage capture manifest schema or cardinality differs")
    captured: dict[tuple[str, str], dict[str, Any]] = {}
    local_paths: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(man["objects"]):
        row = _exact(item, {"origin_pin", "local_relative_path", "byte_count"},
                     f"lineage capture manifest object[{index}]")
        pin = _pin(row["origin_pin"])
        key = _pin_key(pin)
        _require(key in expected and key not in captured,
                 "lineage capture manifest has an unknown or repeated origin")
        local = _relative_local(row["local_relative_path"])
        _require(local not in local_paths,
                 "lineage capture manifest aliases a local path")
        count = row["byte_count"]
        descriptor = expected[key]
        _require(type(count) is int and 0 < count <= descriptor["maximum_bytes"] and
                 (descriptor["byte_count"] is None or
                  count == descriptor["byte_count"]),
                 "captured byte count differs from Source count/cap")
        normalized = {"origin_pin": pin, "local_relative_path": local,
                      "byte_count": count}
        captured[key] = normalized
        local_paths[local] = normalized
    _require(set(captured) == set(expected),
             "lineage capture manifest omits a declared origin")
    normalized_declaration = {
        "schema": DECLARATION_SCHEMA,
        "cohort_host_ids": hosts,
        "objects": list(expected.values()),
    }
    return normalized_declaration, expected, captured


class PreparedExplorationLineageCaptureReaderV1:
    """Read exact pinned bytes from one private, immutable local capture tree."""

    def __init__(self, declaration: object, capture_manifest: object,
                 stage_root: str):
        self._declaration, self._expected, self._captured = _manifest_rows(
            declaration, capture_manifest,
        )
        self._stage_root = _absolute_stage_root(stage_root)
        self._root_fd, self._root_chain = _open_absolute_directory(self._stage_root)
        self._closed = False
        self._uid = os.geteuid()
        self._root_device = 0
        self._file_identity: dict[str, tuple[int, int, int, int, int]] = {}
        self._directory_identity: dict[str, tuple[int, int]] = {}
        try:
            root_info = os.fstat(self._root_fd)
            self._require_private_directory(root_info, "capture root")
            self._root_device = root_info.st_dev
            self._root_identity = (root_info.st_dev, root_info.st_ino)
            self._scan_tree(record_identities=True)
        except BaseException:
            os.close(self._root_fd)
            self._closed = True
            raise

    @staticmethod
    def _require_private_directory(info: os.stat_result, label: str) -> None:
        _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                 info.st_uid == os.geteuid(),
                 f"{label} is not a current-user-owned mode-0700 directory")

    def _open_root_checked(self) -> int:
        _require(not self._closed, "lineage capture reader is closed")
        fd, chain = _open_absolute_directory(self._stage_root)
        try:
            info = os.fstat(fd)
            _require(chain == self._root_chain and
                     (info.st_dev, info.st_ino) == self._root_identity,
                     "lineage capture root or an ancestor was replaced")
            self._require_private_directory(info, "capture root")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _open_local_parent(self, root_fd: int, relative: str) -> tuple[int, str]:
        parts = relative.split("/")
        current = os.dup(root_fd)
        prefix: list[str] = []
        try:
            for component in parts[:-1]:
                prefix.append(component)
                child = os.open(
                    component, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                    dir_fd=current,
                )
                try:
                    info = os.fstat(child)
                    self._require_private_directory(info, "capture subdirectory")
                    _require(info.st_dev == self._root_device,
                             "lineage capture directory crosses a device boundary")
                    self._check_directory_identity("/".join(prefix), info)
                except BaseException:
                    os.close(child)
                    raise
                os.close(current)
                current = child
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    def _check_directory_identity(self, relative: str, info: os.stat_result) -> None:
        key = relative
        identity = (info.st_dev, info.st_ino)
        if key in self._directory_identity:
            _require(self._directory_identity[key] == identity,
                     "lineage capture directory was replaced")

    def _read_relative(self, root_fd: int, relative: str, expected_count: int,
                       expected_pin: dict[str, str]) -> bytes:
        parent_fd, leaf = self._open_local_parent(root_fd, relative)
        fd = -1
        try:
            before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            _require(stat.S_ISREG(before.st_mode) and
                     stat.S_IMODE(before.st_mode) == 0o400 and
                     before.st_uid == self._uid and before.st_nlink == 1 and
                     before.st_dev == self._root_device and
                     before.st_size == expected_count,
                     "captured object is not a regular owned mode-0400 single-link file")
            fd = os.open(leaf, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK,
                         dir_fd=parent_fd)
            opened = os.fstat(fd)
            _require((opened.st_dev, opened.st_ino, opened.st_size) ==
                     (before.st_dev, before.st_ino, before.st_size) and
                     stat.S_ISREG(opened.st_mode) and
                     stat.S_IMODE(opened.st_mode) == 0o400 and
                     opened.st_uid == self._uid and opened.st_nlink == 1,
                     "captured object changed while it was opened")
            remembered = self._file_identity.get(relative)
            identity = (opened.st_dev, opened.st_ino, opened.st_size,
                        opened.st_mtime_ns, opened.st_ctime_ns)
            _require(remembered is None or remembered == identity,
                     "captured object changed identity after reader custody")
            chunks: list[bytes] = []
            remaining = expected_count
            while remaining:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                _require(bool(chunk), "captured object ended before its declared size")
                chunks.append(chunk)
                remaining -= len(chunk)
            _require(os.read(fd, 1) == b"", "captured object exceeds its declared size")
            raw = b"".join(chunks)
            after = os.fstat(fd)
            entry_after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            after_identity = (after.st_dev, after.st_ino, after.st_size,
                              after.st_mtime_ns, after.st_ctime_ns)
            _require(after_identity == identity and
                     (entry_after.st_dev, entry_after.st_ino, entry_after.st_size) ==
                     (after.st_dev, after.st_ino, after.st_size) and
                     stat.S_IMODE(after.st_mode) == 0o400 and
                     after.st_uid == self._uid and after.st_nlink == 1,
                     "captured object changed during its read")
            # Reopen the parent chain from the capture root: the held parent
            # descriptor alone cannot witness a rename away from that tree.
            current_parent, current_leaf = self._open_local_parent(root_fd, relative)
            try:
                current = os.fstat(current_parent)
                held = os.fstat(parent_fd)
                current_entry = os.stat(current_leaf, dir_fd=current_parent,
                                        follow_symlinks=False)
                _require((current.st_dev, current.st_ino) ==
                         (held.st_dev, held.st_ino) and
                         (current_entry.st_dev, current_entry.st_ino) ==
                         (after.st_dev, after.st_ino),
                         "captured object parent custody changed during its read")
            finally:
                os.close(current_parent)
            _require(hashlib.sha256(raw).hexdigest() == expected_pin["raw_sha256"],
                     "captured bytes differ from the exact Source raw pin")
            return raw
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(parent_fd)

    def _scan_tree(self, *, record_identities: bool) -> dict[str, int]:
        expected_paths = {
            row["local_relative_path"]: (key, row)
            for key, row in self._captured.items()
        }
        expected_dirs = {
            "/".join(path.split("/")[:index])
            for path in expected_paths
            for index in range(1, len(path.split("/")))
        }
        expected_children: dict[str, set[str]] = {"": set()}
        for relative in expected_dirs | set(expected_paths):
            parent, _, leaf = relative.rpartition("/")
            expected_children.setdefault(parent, set()).add(leaf)
        root_fd = self._open_root_checked()
        pending: list[str] = []
        observed_files: set[str] = set()
        observed_dirs: set[str] = set()
        inode_ids: set[tuple[int, int]] = set()
        total_bytes = 0
        allocated_bytes = 0
        try:
            root_info = os.fstat(root_fd)
            self._require_private_directory(root_info, "capture root")
            inode_ids.add((root_info.st_dev, root_info.st_ino))
            allocated_bytes = root_info.st_blocks * 512
            pending.append("")
            while pending:
                prefix = pending.pop()
                directory_fd = (self._open_local_parent(root_fd, prefix + "/sentinel")[0]
                                if prefix else os.dup(root_fd))
                try:
                    allowed = expected_children.get(prefix, set())
                    seen: set[str] = set()
                    # Stream only this declaration's finite direct children.
                    # Unknown subtrees are rejected before stat/open/descent.
                    with os.scandir(directory_fd) as entries:
                        for entry_name in entries:
                            name = entry_name.name
                            _require(name in allowed and name not in seen and
                                     len(seen) < len(allowed),
                                     "capture tree contains an undeclared entry")
                            seen.add(name)
                            relative = name if not prefix else prefix + "/" + name
                            entry = os.stat(name, dir_fd=directory_fd,
                                            follow_symlinks=False)
                            _require(entry.st_dev == self._root_device,
                                     "lineage capture entry crosses a device boundary")
                            inode = (entry.st_dev, entry.st_ino)
                            _require(inode not in inode_ids,
                                     "lineage capture contains aliased physical inodes")
                            inode_ids.add(inode)
                            allocated_bytes += entry.st_blocks * 512
                            if relative in expected_dirs:
                                self._require_private_directory(entry, "capture subdirectory")
                                if record_identities:
                                    self._directory_identity[relative] = inode
                                else:
                                    self._check_directory_identity(relative, entry)
                                child_fd = os.open(
                                    name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                                    dir_fd=directory_fd,
                                )
                                try:
                                    opened = os.fstat(child_fd)
                                    self._require_private_directory(opened, "capture subdirectory")
                                    _require((opened.st_dev, opened.st_ino) == inode,
                                             "capture directory changed while opening")
                                except BaseException:
                                    os.close(child_fd)
                                    raise
                                os.close(child_fd)
                                observed_dirs.add(relative)
                                pending.append(relative)
                            else:
                                _require(relative in expected_paths and stat.S_ISREG(entry.st_mode),
                                         "capture tree has a symlink or special file")
                                key, captured = expected_paths[relative]
                                descriptor = self._expected[key]
                                raw = self._read_relative(
                                    root_fd, relative, captured["byte_count"],
                                    descriptor["origin_pin"],
                                )
                                del raw
                                after = os.stat(name, dir_fd=directory_fd,
                                                follow_symlinks=False)
                                identity = (after.st_dev, after.st_ino, after.st_size,
                                            after.st_mtime_ns, after.st_ctime_ns)
                                _require((after.st_dev, after.st_ino) == inode and
                                         stat.S_ISREG(after.st_mode) and
                                         stat.S_IMODE(after.st_mode) == 0o400 and
                                         after.st_uid == self._uid and after.st_nlink == 1 and
                                         after.st_size == captured["byte_count"],
                                         "capture file changed while the tree was scanned")
                                observed_files.add(relative)
                                total_bytes += after.st_size
                                if record_identities:
                                    self._file_identity[relative] = identity
                                else:
                                    _require(self._file_identity.get(relative) == identity,
                                             "captured object was replaced after reader custody")
                    _require(seen == allowed, "capture directory omits a declared child")
                    if prefix:
                        current_parent, _ = self._open_local_parent(root_fd, prefix + "/sentinel")
                        try:
                            current = os.fstat(current_parent)
                            held = os.fstat(directory_fd)
                            _require((current.st_dev, current.st_ino) ==
                                     (held.st_dev, held.st_ino),
                                     "capture directory custody changed during its scan")
                        finally:
                            os.close(current_parent)
                finally:
                    os.close(directory_fd)
            _require(observed_files == set(expected_paths) and observed_dirs == expected_dirs,
                     "capture tree omits a declared file or directory")
            _require(len(inode_ids) == 1 + len(observed_dirs) + len(observed_files),
                     "capture tree contains a physical inode alias")
            current_root_fd = self._open_root_checked()
            os.close(current_root_fd)
        finally:
            os.close(root_fd)
        return {"file_count": len(observed_files), "directory_count": len(observed_dirs),
                "inode_count": len(inode_ids), "byte_count": total_bytes,
                "allocated_byte_count": allocated_bytes}

    def __call__(self, pin: dict[str, str], maximum_bytes: int) -> bytes:
        return self.read(pin, maximum_bytes)

    def read(self, pin: dict[str, str], maximum_bytes: int) -> bytes:
        _require(not self._closed, "lineage capture reader is closed")
        checked_pin = _pin(pin)
        key = _pin_key(checked_pin)
        _require(key in self._expected and key in self._captured,
                 "lineage capture reader refuses an uncaptured origin")
        descriptor = self._expected[key]
        captured = self._captured[key]
        _require(type(maximum_bytes) is int and maximum_bytes > 0 and
                 captured["byte_count"] <= min(maximum_bytes, descriptor["maximum_bytes"]),
                 "lineage capture read exceeds its Source cap or caller bound")
        root_fd = self._open_root_checked()
        try:
            raw = self._read_relative(
                root_fd, captured["local_relative_path"], captured["byte_count"],
                checked_pin,
            )
            current_root_fd = self._open_root_checked()
            os.close(current_root_fd)
            return raw
        finally:
            os.close(root_fd)

    def storage_usage(self) -> dict[str, Any]:
        """Return actual current physical file/inode/byte counts for this tree."""
        counts = self._scan_tree(record_identities=False)
        return {"schema": STORAGE_USAGE_SCHEMA, **counts}

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._closed = True

    def __enter__(self) -> "PreparedExplorationLineageCaptureReaderV1":
        _require(not self._closed, "lineage capture reader is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


__all__ = [
    "CAPTURE_MANIFEST_SCHEMA", "DECLARATION_SCHEMA", "HOST_JOB_COUNT",
    "PreparedExplorationLineageCaptureError",
    "PreparedExplorationLineageCaptureReaderV1", "STORAGE_USAGE_SCHEMA",
]
