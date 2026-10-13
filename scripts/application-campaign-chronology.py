#!/usr/bin/env python3
"""Serialize SourceV5 capacity registration and fixed-confirmation launches.

This module records transactions made through its locked APIs. It does not
change campaign readiness, validate work launched outside these APIs, or claim
that the existing controller ledger proves pre-Popen ordering.
"""
from __future__ import annotations

import fcntl
import functools
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple


SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v5"
SPEC_SCHEMA = "allocatbelt.application-campaign-spec.v3"
PLAN_SCHEMA = "allocatbelt.application-campaign-plan.v3"
CAPACITY_COMPLETION_SCHEMA = "allocatbelt.application-capacity-stage-completion.v1"
CHRONOLOGY_SCHEMA = "allocatbelt.application-campaign-chronology.v2"
JOURNAL_SCHEMA = "allocatbelt.application-campaign-dispatch-event.v2"
CHRONOLOGY_SOURCE_PATH = "scripts/application-campaign-chronology.py"
CAPACITY_STAGE_SOURCE_PATH = "scripts/application-capacity-stage.py"
CONTROLLER_SOURCE_PATH = "scripts/application-campaign.py"
PAIR_RUNNER_SOURCE_PATH = "scripts/run-application-pair.sh"

MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_COMPLETION_BYTES = 16 * 1024 * 1024
MAX_JOURNAL_BYTES = 256 * 1024 * 1024
MAX_JOURNAL_EVENTS = 100_000
MAX_EVENT_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_ENVIRONMENT_BYTES = 60 * 1024
MAX_PATH_BYTES = 4096
MAX_TIMEOUT_SECONDS = 24 * 60 * 60
DISPATCH_TERM_GRACE_SECONDS = 0.2
DISPATCH_KILL_GRACE_SECONDS = 1.0
DISPATCH_REAP_GRACE_SECONDS = 0.25
DISPATCH_POLL_INTERVAL_SECONDS = 0.01
DISPATCH_CLEANUP_TOTAL_SECONDS = (
    DISPATCH_TERM_GRACE_SECONDS + DISPATCH_KILL_GRACE_SECONDS +
    DISPATCH_REAP_GRACE_SECONDS
)
U64_MAX = (1 << 64) - 1
PROCESS_GROUP_CLEANUP_STATES = {"not_started", "clean", "unclean", "unverified"}
PROCESS_REAP_STATUSES = {"not_started", "owned_reaped", "not_reaped", "unverified"}

EVENTS = (
    "capacity_stage_completed", "capacity_registered", "dispatch_authorized",
    "dispatch_bound", "dispatch_exited", "dispatch_failed",
    "dispatch_interrupted", "dispatch_timeout",
)
DETAIL_FIELDS = {
    "capacity_stage_completed": {
        "capacity_completion", "capacity_ledger", "capacity_schedule_sha256",
        "entry_count", "entries", "qualification_eligible",
        "controller_chronology_proven",
    },
    "capacity_registered": {
        "capacity_completion", "capacity_ledger", "capacity_schedule_sha256",
        "entry_count", "entries", "qualification_eligible",
        "controller_chronology_proven", "capacity_stage_event_head",
    },
    "dispatch_authorized": {
        "authorization_id", "job_index", "job", "job_sha256", "member_role",
        "pair_members", "pair_members_sha256", "capacity_registration_head",
        "capacity_completion_raw_sha256", "capacity_ledger_raw_sha256",
        "capacity_ledger_terminal_head", "capacity_schedule_sha256", "runner",
        "argv", "cwd", "environment", "environment_sha256", "runner_output",
        "campaign_artifacts_root", "shebang_interpreter",
        "runtime_bindings", "runtime_validator", "fixed_global_control_baseline",
        "outer_deadline_seconds", "effective_timeout_seconds", "stdout_path", "stderr_path",
        "confirmation_owner_marker",
        "qualification_eligible",
    },
    "dispatch_bound": {
        "authorization_id", "job_run_id", "member_role", "pid", "start_ticks",
        "runner_path", "runner_sha256", "process_executable_path",
        "process_executable_sha256", "cwd", "cpu_affinity",
        "network_namespace_inode", "environment", "environment_sha256",
        "actual_environment_sha256",
        "process_report_nonce", "member_report_nonces", "caller_role",
        "pair_members_sha256", "capacity_registration_head",
        "qualification_eligible",
    },
    "dispatch_exited": {
        "authorization_id", "job_run_id", "member_role", "pid", "return_code",
        "status", "signal", "elapsed_ns", "stdout", "stderr",
        "stdout_sha256", "stderr_sha256", "stdout_size", "stderr_size",
        "process_reaped", "process_reap_status", "process_group_cleanup_status",
        "cleanup_error_sha256",
        "capacity_registration_head", "qualification_eligible",
    },
    "dispatch_failed": {
        "authorization_id", "job_run_id", "member_role", "pid", "return_code",
        "error_type", "error_sha256", "elapsed_ns", "process_reaped",
        "process_reap_status", "process_group_cleanup_status", "cleanup_error_sha256",
        "capacity_registration_head", "qualification_eligible",
    },
    "dispatch_interrupted": {
        "authorization_id", "job_run_id", "member_role", "pid", "signal",
        "return_code", "elapsed_ns", "process_reaped",
        "process_reap_status", "process_group_cleanup_status", "cleanup_error_sha256",
        "capacity_registration_head", "qualification_eligible",
    },
    "dispatch_timeout": {
        "authorization_id", "job_run_id", "member_role", "pid", "return_code",
        "elapsed_ns", "effective_timeout_seconds", "process_reaped",
        "process_reap_status", "process_group_cleanup_status", "cleanup_error_sha256",
        "capacity_registration_head", "qualification_eligible",
    },
}


class ChronologyError(ValueError):
    """A pinned input, private lock, dispatch transaction, or journal is invalid."""


class ProcessCleanupResult(NamedTuple):
    process_reaped: bool
    process_reap_status: str
    return_code: int | None
    process_group_cleanup_status: str
    error_message: str | None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ChronologyError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ChronologyError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def _json_copy(value: object) -> Any:
    return json.loads(canonical_bytes(value))


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            f"{label} is not a lower-case SHA-256 digest")
    return value


def _token(value: object, label: str, maximum: int = 128) -> str:
    require(type(value) is str and 0 < len(value) <= maximum and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is not None,
            f"{label} is malformed")
    return value


def _uint(value: object, label: str, *, positive: bool = False,
          maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum,
            f"{label} is not a bounded unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys,
            f"{label} has an unexpected field set")
    return value


def _path_text(path: Path, label: str) -> str:
    value = str(path)
    encoded = value.encode("utf-8", "strict")
    require(len(encoded) <= MAX_PATH_BYTES and "\x00" not in value and
            not any(ord(character) < 32 or ord(character) == 127 for character in value),
            f"{label} is not bounded path text")
    return value


def _relative(value: object, label: str) -> PurePosixPath:
    require(type(value) is str and value and "\\" not in value and "\x00" not in value,
            f"{label} is malformed")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            all(part not in ("", ".", "..") for part in path.parts),
            f"{label} is not a normalized relative path")
    return path


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ChronologyError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                            item.st_mtime_ns, item.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and key(before) == key(before_path),
                f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its finite size bound")
        chunks: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated while reading")
            chunks.append(block)
            count += len(block)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        require(key(before) == key(after) == key(after_path) and count == before.st_size,
                f"{label} changed while reading")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def _parse_object(raw: bytes, label: str, maximum: int, *, canonical: bool = True) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its finite byte bound")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ChronologyError(f"{label} is not valid JSON: {error}") from error
    require(type(value) is dict, f"{label} must be an object")
    if canonical:
        require(canonical_bytes(value) == raw, f"{label} is not canonical JSON")
    return value


def _read_pin(pin: object, label: str, maximum: int) -> tuple[dict[str, Any], Path, bytes, str]:
    value = _exact(pin, {"path", "sha256"}, f"{label} pin")
    path = Path(value["path"])
    _path_text(path, f"{label} path")
    require(path.is_absolute(), f"{label} path must be absolute")
    try:
        require(path.resolve(strict=True) == path,
                f"{label} path contains a symlink or path alias")
    except OSError as error:
        raise ChronologyError(f"{label} path is unavailable: {error}") from error
    expected = _digest(value["sha256"], f"{label} raw SHA-256")
    raw, _info = _read_stable(path, label, maximum)
    raw_sha = sha256_bytes(raw)
    require(raw_sha == expected, f"{label} differs from its caller pin")
    return _parse_object(raw, label, maximum), path, raw, raw_sha


def _safe_root(path: Path, label: str) -> Path:
    _path_text(path, label)
    try:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode), f"{label} must be a real directory")
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ChronologyError(f"{label} is unavailable: {error}") from error
    require(resolved == path, f"{label} contains a symlink or path alias")
    return resolved


def _ensure_private_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                info.st_uid == os.getuid(),
                f"private directory {path} must be an owned real directory with mode 0700")
        require(path.resolve(strict=True) == path, f"private directory {path} is aliased")
        return
    path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
            info.st_uid == os.getuid(), f"cannot establish private directory {path}")
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                         getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, raw: bytes, mode: int = 0o600) -> None:
    require(not path.exists() and not path.is_symlink(), f"refusing to replace {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


_LOCK_OWNER = object()
_LIVE_LOCK_TOKENS: dict[int, tuple[object, int, int, int, Any, Path, str, str, Path, Path]] = {}
_LOCK_CACHED_STATES: dict[int, tuple[object, dict[str, Any]]] = {}


class CampaignHostLock:
    """An fd-owned flock token; locked APIs reject caller booleans and other objects."""

    __slots__ = (
        "output_root", "campaign_id", "host_id", "directory", "lock_path", "fd",
        "active", "held", "_owner", "_fd_key", "_operation_lock",
    )

    def __init__(self, output_root: Path, campaign_id: str, host_id: str,
                 directory: Path, lock_path: Path, fd: int):
        self.output_root = output_root
        self.campaign_id = campaign_id
        self.host_id = host_id
        self.directory = directory
        self.lock_path = lock_path
        self.fd = fd
        self.active = True
        self.held = True
        self._owner = _LOCK_OWNER
        self._operation_lock = threading.Lock()
        info = os.fstat(fd)
        self._fd_key = (info.st_dev, info.st_ino)
        _LIVE_LOCK_TOKENS[id(self)] = (self, fd, info.st_dev, info.st_ino,
                                       self._operation_lock, output_root, campaign_id,
                                       host_id, directory, lock_path)

    def __enter__(self) -> CampaignHostLock:
        require(self.active and _lock_token_is_live(self),
                "campaign/host fd-owned lock token is not active")
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if not self.active:
            return
        token = _LIVE_LOCK_TOKENS.get(id(self))
        operation_lock = token[4] if token is not None and token[0] is self else self._operation_lock
        with operation_lock:
            if not self.active:
                return
            try:
                if self.held:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                token = _LIVE_LOCK_TOKENS.get(id(self))
                if token is not None and token[0] is self:
                    del _LIVE_LOCK_TOKENS[id(self)]
                state_token = _LOCK_CACHED_STATES.get(id(self))
                if state_token is not None and state_token[0] is self:
                    del _LOCK_CACHED_STATES[id(self)]
                os.close(self.fd)
                self.active = False
                self.held = False


def _lock_token_is_live(lock: object) -> bool:
    if type(lock) is not CampaignHostLock or getattr(lock, "_owner", None) is not _LOCK_OWNER:
        return False
    token = _LIVE_LOCK_TOKENS.get(id(lock))
    if token is None or token[0] is not lock:
        return False
    try:
        info = os.fstat(token[1])
    except OSError:
        return False
    return token[1] == getattr(lock, "fd", None) and \
        (info.st_dev, info.st_ino) == (token[2], token[3]) == getattr(lock, "_fd_key", None) and \
        getattr(lock, "_operation_lock", None) is token[4] and \
        (getattr(lock, "output_root", None), getattr(lock, "campaign_id", None),
         getattr(lock, "host_id", None), getattr(lock, "directory", None),
         getattr(lock, "lock_path", None)) == token[5:]


def _serialize_locked_api(function: Any) -> Any:
    @functools.wraps(function)
    def invoke(lock: CampaignHostLock, *args: Any, **kwargs: Any) -> Any:
        require(_lock_token_is_live(lock),
                "locked chronology API requires its active fd-owned CampaignHostLock token")
        token = _LIVE_LOCK_TOKENS[id(lock)]
        with token[4]:
            return function(lock, *args, **kwargs)
    return invoke


def _cached_lock_state(lock: CampaignHostLock) -> dict[str, Any] | None:
    token = _LOCK_CACHED_STATES.get(id(lock))
    return token[1] if token is not None and token[0] is lock else None


def _set_cached_lock_state(lock: CampaignHostLock, state: dict[str, Any]) -> None:
    _LOCK_CACHED_STATES[id(lock)] = (lock, state)


_AUTH_OWNER = object()
_AUTHORIZATION_TOKENS: dict[int, dict[str, Any]] = {}
_AUTHORIZATION_TOKEN_LOCK = threading.Lock()


class DispatchAuthorization:
    """One-use in-process capability produced by a durable authorization event."""

    __slots__ = ("lock", "prepared", "plan_pin", "spec_pin", "source_root",
                 "input_root", "observed_host_pin", "capacity_output_root",
                 "completion_pin", "_details", "start_monotonic_ns", "used", "_owner")

    def __init__(self, lock: CampaignHostLock, prepared: dict[str, Any],
                 plan_pin: dict[str, Any], spec_pin: dict[str, Any],
                 source_root: Path, input_root: Path, observed_host_pin: dict[str, Any],
                 capacity_output_root: Path, completion_pin: dict[str, Any],
                 details: dict[str, Any], start_monotonic_ns: int):
        self.lock = lock
        self.prepared = prepared
        self.plan_pin = plan_pin
        self.spec_pin = spec_pin
        self.source_root = source_root
        self.input_root = input_root
        self.observed_host_pin = observed_host_pin
        self.capacity_output_root = capacity_output_root
        self.completion_pin = completion_pin
        self._details = _json_copy(details)
        self.start_monotonic_ns = start_monotonic_ns
        self.used = False
        self._owner = _AUTH_OWNER
        with _AUTHORIZATION_TOKEN_LOCK:
            _AUTHORIZATION_TOKENS[id(self)] = {
                "object": self, "lock": lock,
                "snapshot": _authorization_snapshot(self), "consumed": False,
            }

    @property
    def details(self) -> dict[str, Any]:
        """Return a detached copy of the durable authorization details."""
        return _json_copy(self._details)


def _authorization_snapshot(authorization: DispatchAuthorization) -> bytes:
    prepared = authorization.prepared
    value = {
        "plan_pin": authorization.plan_pin, "spec_pin": authorization.spec_pin,
        "source_root": str(authorization.source_root),
        "input_root": str(authorization.input_root),
        "host_id": prepared["host_id"], "output_root": str(prepared["output_root"]),
        "observed_host_pin": authorization.observed_host_pin,
        "capacity_output_root": str(authorization.capacity_output_root),
        "completion_pin": authorization.completion_pin,
        "details": authorization.details,
        "start_monotonic_ns": authorization.start_monotonic_ns,
        "original_pins": prepared["original_pins"],
    }
    return canonical_bytes(value)


def _consume_authorization(lock: CampaignHostLock, authorization: object) -> DispatchAuthorization:
    require(type(authorization) is DispatchAuthorization and
            getattr(authorization, "_owner", None) is _AUTH_OWNER,
            "launch requires a module-issued one-use DispatchAuthorization")
    with _AUTHORIZATION_TOKEN_LOCK:
        token = _AUTHORIZATION_TOKENS.get(id(authorization))
        require(token is not None and token["object"] is authorization and
                token["lock"] is lock and not token["consumed"] and not authorization.used,
                "dispatch authorization is foreign, belongs to another lock, or was already consumed")
        require(token["snapshot"] == _authorization_snapshot(authorization),
                "dispatch authorization was modified after its durable journal event")
        token["consumed"] = True
        authorization.used = True
    return authorization


def _ensure_private_tree(root: Path, directory: Path) -> None:
    root = _safe_root(root, "private campaign output root")
    _path_text(directory, "private output directory")
    require(directory.is_absolute() and _within(root, directory),
            "private output directory escaped its campaign root")
    relative = directory.relative_to(root)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.exists() or cursor.is_symlink():
            info = cursor.lstat()
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                    info.st_uid == os.getuid() and cursor.resolve(strict=True) == cursor,
                    f"private output path component {cursor} is not an owned mode-0700 directory")
        else:
            cursor.mkdir(mode=0o700)
            info = cursor.lstat()
            require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
                    f"cannot establish private output directory {cursor}")
            _fsync_directory(cursor.parent)


def _verify_owner_marker(prepared: dict[str, Any], owner_pin: object,
                         registration_head: str, *, create: bool) -> None:
    pin = _exact(owner_pin, {"path", "sha256"}, "confirmation ownership marker pin")
    phase_dir = _phase_directory(prepared)
    expected_path = phase_dir / ".chronology-owner.json"
    require(pin["path"] == str(expected_path),
            "confirmation owner marker path differs from the selected host directory")
    body = _owner_body(prepared, registration_head)
    raw = canonical_bytes(body)
    raw_sha = sha256_bytes(raw)
    require(pin["sha256"] == raw_sha, "confirmation owner marker hash differs")
    path = expected_path
    if not path.exists() and not path.is_symlink() and create:
        _write_exclusive(path, raw, 0o400)
    captured, info = _read_stable(path, "confirmation chronology owner marker", 64 * 1024)
    require(stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == os.getuid() and
            captured == raw and sha256_bytes(captured) == raw_sha,
            "confirmation directory is owned by a different or prior transaction")


def _ensure_confirmation_host_directory(prepared: dict[str, Any], owner_pin: object,
                                        registration_head: str) -> None:
    phase_dir = _phase_directory(prepared)
    _ensure_private_tree(prepared["output_root"], phase_dir.parent)
    _ensure_private_tree(prepared["output_root"], phase_dir)
    _verify_owner_marker(prepared, owner_pin, registration_head, create=True)


def _write_runtime_binding_file(output_root: Path, path: Path, raw: bytes) -> dict[str, str]:
    require(len(raw) <= 16 * 1024 * 1024, "runtime process binding manifest exceeds its finite bound")
    _ensure_private_tree(output_root, path.parent)
    _write_exclusive(path, raw, 0o600)
    captured, info = _read_stable(path, "chronology runtime binding manifest", 16 * 1024 * 1024)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and captured == raw,
            "runtime binding manifest was not atomically persisted with private permissions")
    return {"path": str(path), "sha256": sha256_bytes(raw)}


def _verify_runtime_binding_file(pin: object, expected_raw: bytes,
                                 output_root: Path) -> None:
    value = _exact(pin, {"path", "sha256", "size"}, "runtime bindings file pin")
    path = Path(value["path"])
    _path_text(path, "runtime bindings file path")
    require(_within(output_root, path), "runtime binding manifest escaped campaign output")
    raw, info = _read_stable(path, "chronology runtime binding manifest", 16 * 1024 * 1024)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and
            raw == expected_raw and len(raw) == value["size"] and
            sha256_bytes(raw) == _digest(value["sha256"], "runtime bindings raw SHA-256"),
            "runtime binding manifest bytes differ from the pinned original recipes")


def _live_process_identity(
    process: subprocess.Popen[bytes], stage_module: types.ModuleType,
    expected_executable: dict[str, str],
    expected_cwd: str, affinity: list[int], network_namespace_inode: int,
    expected_environment: dict[str, str],
    timeout_seconds: float = 1.0,
) -> dict[str, Any]:
    pid = process.pid
    require(type(pid) is int and 0 < pid <= (1 << 31) - 1,
            "direct pair-runner Popen returned an invalid PID")
    proc = Path(f"/proc/{pid}")
    deadline = time.monotonic() + timeout_seconds
    first_start_ticks: int | None = None
    while time.monotonic() < deadline:
        if _leader_exit_status_unreaped(process) is not None:
            break
        try:
            stat_text = (proc / "stat").read_text(encoding="ascii")
            tail = stat_text[stat_text.rfind(")") + 2:].split()
            require(len(tail) > 19, "pair-runner proc stat is truncated")
            start_ticks = int(tail[19])
            if first_start_ticks is None:
                first_start_ticks = start_ticks
            require(first_start_ticks == start_ticks,
                    "pair-runner PID was reused during process binding")
            executable = Path(os.readlink(proc / "exe")).resolve(strict=True)
            observed_cwd = os.readlink(proc / "cwd")
            if (str(executable) == expected_executable["path"] and
                    observed_cwd == expected_cwd):
                observer = getattr(stage_module, "_read_pid_identity", None)
                require(callable(observer), "captured stage lacks live process observation")
                observed = observer(
                    pid, executable, expected_executable["sha256"], expected_environment,
                )
                require(observed["start_ticks"] == start_ticks and observed["cwd"] == expected_cwd and
                        observed["executable_sha256"] == expected_executable["sha256"],
                        "captured stage process observer returned a different runner identity")
                require(observed["cpu_affinity"] == affinity and
                        observed["network_namespace_inode"] == network_namespace_inode and
                        observed["environment"] == expected_environment,
                        "actual pair-runner affinity or network namespace differs from the observed host")
                check_stat = (proc / "stat").read_text(encoding="ascii")
                check_tail = check_stat[check_stat.rfind(")") + 2:].split()
                require(int(check_tail[19]) == start_ticks and
                        _leader_exit_status_unreaped(process) is None,
                        "pair-runner PID/start identity changed during live observation")
                return {
                    "pid": pid, "start_ticks": start_ticks,
                    "process_executable_path": str(executable),
                    "process_executable_sha256": observed["executable_sha256"],
                    "cwd": observed["cwd"], "cpu_affinity": observed["cpu_affinity"],
                    "network_namespace_inode": observed["network_namespace_inode"],
                    "environment": observed["environment"],
                }
        except FileNotFoundError:
            break
        except (OSError, UnicodeError, ValueError, IndexError) as error:
            if _leader_exit_status_unreaped(process) is not None:
                break
            raise ChronologyError(f"cannot bind live pair-runner process: {error}") from error
        time.sleep(0.005)
    raise ChronologyError("direct pair-runner exited or failed live PID/start/executable binding")


def _leader_exit_status_unreaped(process: subprocess.Popen[bytes]) -> Any | None:
    """Observe runner exit while retaining its PID as the process-group owner."""
    _require_owned_child_wait_semantics()
    require(process.returncode is None,
            "pair-runner leader was reaped before process-group cleanup completed")
    try:
        result = os.waitid(os.P_PID, process.pid,
                          os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        raise ChronologyError(
            "pair-runner ownership was lost before its process group was verified"
        ) from error
    except OSError as error:
        raise ChronologyError(f"cannot observe unreaped pair-runner exit: {error}") from error
    if result is not None and result.si_pid == process.pid:
        return result
    return None


def _require_owned_child_wait_semantics() -> None:
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            "fixed dispatch requires the default SIGCHLD disposition to preserve child ownership")
    require(callable(getattr(os, "waitid", None)) and hasattr(os, "WNOWAIT"),
            "fixed dispatch requires waitid(WNOWAIT) process ownership")


def _owned_session_members(session_id: int) -> tuple[list[int], list[int]]:
    """Return live PIDs in the runner PGID and live session members that escaped it."""
    group_members: list[int] = []
    escaped_members: list[int] = []
    try:
        entries = list(os.scandir("/proc"))
    except OSError as error:
        raise ChronologyError(f"cannot inspect process ownership during runner cleanup: {error}") from error
    saw_leader = False
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        try:
            with open(f"/proc/{entry.name}/stat", encoding="ascii") as stat_file:
                stat_line = stat_file.read(8192)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ChronologyError(
                f"cannot inspect process {pid} during runner cleanup: {error}"
            ) from error
        closing = stat_line.rfind(")")
        require(closing >= 0, f"cannot parse process {pid} during runner cleanup")
        fields = stat_line[closing + 1 :].split()
        require(len(fields) >= 4, f"cannot parse process identity for {pid} during runner cleanup")
        state = fields[0]
        try:
            process_group_id = int(fields[2])
            observed_session_id = int(fields[3])
        except ValueError as error:
            raise ChronologyError(f"cannot parse process group for {pid} during runner cleanup") from error
        if pid == session_id:
            require(process_group_id == session_id and observed_session_id == session_id,
                    "pair-runner leader no longer anchors its original session")
            saw_leader = True
        if observed_session_id != session_id or state in {"Z", "X"}:
            continue
        if process_group_id == session_id:
            group_members.append(pid)
        else:
            escaped_members.append(pid)
    require(saw_leader, "pair-runner session leader disappeared before it was safely reaped")
    return group_members, escaped_members


def _signal_unreaped_owned_group(process: subprocess.Popen[bytes], signum: int) -> None:
    """Signal the isolated PGID only while its direct leader remains unreaped."""
    _leader_exit_status_unreaped(process)
    group_members, _escaped_members = _owned_session_members(process.pid)
    if not group_members:
        return
    # Procfs inspection does not preserve child ownership. Recheck SIGCHLD,
    # Popen state, and WNOWAIT after the scan immediately before killpg.
    _leader_exit_status_unreaped(process)
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        return
    except OSError as error:
        raise ChronologyError(f"cannot signal the unreaped pair-runner group: {error}") from error


def _wait_owned_group_quiescent(process: subprocess.Popen[bytes], timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        _leader_exit_status_unreaped(process)
        group_members, _escaped_members = _owned_session_members(process.pid)
        if not group_members:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(DISPATCH_POLL_INTERVAL_SECONDS, remaining))


def _bounded_emergency_reap(
    process: subprocess.Popen[bytes],
) -> ProcessCleanupResult:
    """Use the still-unreaped session leader to KILL and reap without procfs scans."""
    global _ACTIVE_DISPATCH_PROCESS
    try:
        _require_owned_child_wait_semantics()
    except BaseException as error:
        # Without default SIGCHLD disposition, WNOWAIT cannot reserve the PID
        # through exit. Refuse all numeric process-group signals and all Popen
        # waits; ECHILD under an ignored/custom handler is not exit status.
        _ACTIVE_DISPATCH_PROCESS = None
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            f"emergency PGID signal refused without wait ownership: {type(error).__name__}",
        )
    try:
        _leader_exit_status_unreaped(process)
    except BaseException as error:
        _ACTIVE_DISPATCH_PROCESS = None
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            f"cannot verify unreaped runner ownership: {type(error).__name__}",
        )
    signal_error: str | None = None
    try:
        # start_new_session=True makes this Popen PID the group/session leader.
        # Re-observe ownership immediately before using its numeric group ID.
        _leader_exit_status_unreaped(process)
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException as error:
        if isinstance(error, ChronologyError) and "default SIGCHLD disposition" in str(error):
            _ACTIVE_DISPATCH_PROCESS = None
            return ProcessCleanupResult(
                False, "unverified", None, "unverified",
                f"emergency PGID signal refused without wait ownership: {type(error).__name__}",
            )
        signal_error = f"emergency SIGKILL failed: {type(error).__name__}"
    _ACTIVE_DISPATCH_PROCESS = None
    reaped = _bounded_owned_wait(process, DISPATCH_REAP_GRACE_SECONDS,
                                 "unverified", signal_error,
                                 "bounded emergency reap")
    return reaped


def _bounded_owned_wait(
    process: subprocess.Popen[bytes], timeout_seconds: float,
    group_status: str, prior_error: str | None, operation: str,
) -> ProcessCleanupResult:
    """Reap only while this caller still has verifiable default-SIGCHLD ownership."""
    try:
        _require_owned_child_wait_semantics()
        # Confirm this process still owns an unreaped child immediately before
        # Popen.wait. An ignored/custom SIGCHLD disposition can auto-reap the
        # child, and Popen.wait may translate ECHILD into a fabricated zero.
        _leader_exit_status_unreaped(process)
    except BaseException as error:
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            ";".join(item for item in (
                prior_error,
                f"{operation} refused without verifiable child ownership: {type(error).__name__}",
            ) if item),
        )
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        return ProcessCleanupResult(
            False, "not_reaped", None, group_status,
            ";".join(item for item in (
                prior_error,
                f"{operation} timed out: {type(error).__name__}",
            ) if item),
        )
    except BaseException as error:
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            ";".join(item for item in (
                prior_error,
                f"{operation} failed without a verified wait status: {type(error).__name__}",
            ) if item),
        )
    if type(return_code) is not int:
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            ";".join(item for item in (
                prior_error, f"{operation} returned a non-integer wait status",
            ) if item),
        )
    return ProcessCleanupResult(
        True, "owned_reaped", return_code, group_status, prior_error,
    )


def _terminate_process_group(
    process: subprocess.Popen[bytes],
) -> ProcessCleanupResult:
    """Return separate leader-reap and verified group-cleanup outcomes."""
    global _ACTIVE_DISPATCH_PROCESS
    try:
        _require_owned_child_wait_semantics()
        _leader_exit_status_unreaped(process)
        cleanup_deadline = time.monotonic() + DISPATCH_CLEANUP_TOTAL_SECONDS
        _signal_unreaped_owned_group(process, signal.SIGTERM)
        term_budget = min(DISPATCH_TERM_GRACE_SECONDS,
                          max(0.0, cleanup_deadline - time.monotonic()))
        group_quiescent = _wait_owned_group_quiescent(process, term_budget)
        if not group_quiescent:
            _signal_unreaped_owned_group(process, signal.SIGKILL)
            kill_budget = min(DISPATCH_KILL_GRACE_SECONDS,
                              max(0.0, cleanup_deadline - time.monotonic()))
            group_quiescent = _wait_owned_group_quiescent(process, kill_budget)
        _leader_exit_status_unreaped(process)
        group_members, escaped_members = _owned_session_members(process.pid)
        group_clean = group_quiescent and not group_members and not escaped_members
        cleanup_status = "clean" if group_clean else "unclean"
        if group_clean:
            error_message = None
        else:
            error_message = "owned session cleanup left live group or escaped session members"
        remaining = cleanup_deadline - time.monotonic()
        reap_timeout = (min(DISPATCH_REAP_GRACE_SECONDS, remaining)
                        if remaining > 0 else DISPATCH_REAP_GRACE_SECONDS)
        # This pointer is the only signal-time reference to the runner. Clear it
        # before wait() releases the PID that anchors the fresh PGID.
        _ACTIVE_DISPATCH_PROCESS = None
        return _bounded_owned_wait(
            process, reap_timeout, cleanup_status, error_message,
            "bounded direct-runner reap",
        )
    except BaseException as error:
        # Inspection/signaling errors cannot certify the session tree. Keep the
        # unreaped leader as the ownership boundary for one bounded SIGKILL and
        # reap attempt, then report the tree as unverified regardless of reap.
        fallback = _bounded_emergency_reap(process)
        message = f"{type(error).__name__}:{str(error)[:512]}"
        if fallback.error_message:
            message = f"{message};{fallback.error_message}"
        return fallback._replace(
            process_group_cleanup_status="unverified", error_message=message,
        )


_ACTIVE_DISPATCH_PROCESS: subprocess.Popen[bytes] | None = None
_PENDING_DISPATCH_SIGNAL: int | None = None


def _install_dispatch_signal_handlers() -> dict[int, Any]:
    global _PENDING_DISPATCH_SIGNAL
    _PENDING_DISPATCH_SIGNAL = None
    require(threading.current_thread() is threading.main_thread(),
            "bounded chronology launch must run on the main thread for signal cleanup")
    previous: dict[int, Any] = {}

    def handler(signum: int, _frame: Any) -> None:
        global _PENDING_DISPATCH_SIGNAL
        if _PENDING_DISPATCH_SIGNAL is None:
            _PENDING_DISPATCH_SIGNAL = signum

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.signal(signum, handler)
    return previous


def _restore_dispatch_signal_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _capture_output(path: Path) -> tuple[dict[str, str], bytes, int]:
    raw, info = _read_stable(path, "fixed pair-runner output", MAX_OUTPUT_BYTES)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(),
            "fixed pair-runner output is not a private mode-0600 regular file")
    pin = {"path": str(path), "sha256": sha256_bytes(raw)}
    return pin, raw, info.st_size


def _flush_close_streams(*streams: Any, ignore_errors: bool = False) -> None:
    first_error: BaseException | None = None
    for stream in streams:
        if stream is None or getattr(stream, "closed", False):
            continue
        try:
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException as error:
            if first_error is None:
                first_error = error
        try:
            stream.close()
        except BaseException as error:
            if first_error is None:
                first_error = error
    if first_error is not None and not ignore_errors:
        raise first_error


def _cleanup_is_safe(cleanup: ProcessCleanupResult) -> bool:
    if cleanup.process_reap_status == "not_started":
        return (not cleanup.process_reaped and cleanup.return_code is None and
                cleanup.process_group_cleanup_status == "not_started")
    return (cleanup.process_reap_status == "owned_reaped" and cleanup.process_reaped and
            type(cleanup.return_code) is int and
            cleanup.process_group_cleanup_status == "clean")


def _cleanup_error_sha256(cleanup: ProcessCleanupResult) -> str | None:
    if _cleanup_is_safe(cleanup):
        return None
    message = cleanup.error_message or (
        f"process_reaped={cleanup.process_reaped};"
        f"process_reap_status={cleanup.process_reap_status};"
        f"return_code={cleanup.return_code};"
        f"process_group_cleanup_status={cleanup.process_group_cleanup_status}"
    )
    return sha256_bytes(message.encode("utf-8", "replace"))


def _failed_dispatch_details(authorization: dict[str, Any], pid: int | None,
                             error: BaseException, elapsed_ns: int,
                             cleanup: ProcessCleanupResult) -> dict[str, Any]:
    message = f"{type(error).__name__}:{str(error)[:1024]}"
    return {
        "authorization_id": authorization["authorization_id"],
        "job_run_id": authorization["job"]["run_id"],
        "member_role": "campaign_pair_runner", "pid": pid,
        "return_code": cleanup.return_code,
        "error_type": type(error).__name__, "error_sha256": sha256_bytes(message.encode("utf-8", "replace")),
        "elapsed_ns": max(0, elapsed_ns), "process_reaped": cleanup.process_reaped,
        "process_reap_status": cleanup.process_reap_status,
        "process_group_cleanup_status": cleanup.process_group_cleanup_status,
        "cleanup_error_sha256": _cleanup_error_sha256(cleanup),
        "capacity_registration_head": authorization["capacity_registration_head"],
        "qualification_eligible": False,
    }


def _interrupted_dispatch_details(authorization: dict[str, Any], pid: int | None,
                                  signum: int, elapsed_ns: int,
                                  cleanup: ProcessCleanupResult) -> dict[str, Any]:
    return {
        "authorization_id": authorization["authorization_id"],
        "job_run_id": authorization["job"]["run_id"],
        "member_role": "campaign_pair_runner", "pid": pid,
        "signal": signum, "return_code": cleanup.return_code,
        "elapsed_ns": max(0, elapsed_ns), "process_reaped": cleanup.process_reaped,
        "process_reap_status": cleanup.process_reap_status,
        "process_group_cleanup_status": cleanup.process_group_cleanup_status,
        "cleanup_error_sha256": _cleanup_error_sha256(cleanup),
        "capacity_registration_head": authorization["capacity_registration_head"],
        "qualification_eligible": False,
    }


def _timeout_dispatch_details(authorization: dict[str, Any], pid: int | None,
                              elapsed_ns: int,
                              cleanup: ProcessCleanupResult) -> dict[str, Any]:
    return {
        "authorization_id": authorization["authorization_id"],
        "job_run_id": authorization["job"]["run_id"],
        "member_role": "campaign_pair_runner", "pid": pid,
        "return_code": cleanup.return_code, "elapsed_ns": max(0, elapsed_ns),
        "effective_timeout_seconds": authorization["effective_timeout_seconds"],
        "process_reaped": cleanup.process_reaped,
        "process_reap_status": cleanup.process_reap_status,
        "process_group_cleanup_status": cleanup.process_group_cleanup_status,
        "cleanup_error_sha256": _cleanup_error_sha256(cleanup),
        "capacity_registration_head": authorization["capacity_registration_head"],
        "qualification_eligible": False,
    }


@_serialize_locked_api
def launch_authorized_locked(
    lock: CampaignHostLock, authorization: DispatchAuthorization,
) -> dict[str, Any]:
    """Popen one authorized original pair runner and durably bind/reap its direct process."""
    authorization = _consume_authorization(lock, authorization)
    prepared = authorization.prepared
    token_details = _json_copy(authorization.details)
    details = token_details
    start_ns = authorization.start_monotonic_ns
    deadline_ns = start_ns + token_details["effective_timeout_seconds"] * 1_000_000_000
    process: subprocess.Popen[bytes] | None = None
    process_reaped = False
    cleanup_result: ProcessCleanupResult | None = None
    bound: dict[str, Any] | None = None
    stdout_stream: Any = None
    stderr_stream: Any = None
    stdout_path = Path(token_details["stdout_path"])
    stderr_path = Path(token_details["stderr_path"])
    context: dict[str, Any] | None = None
    previous_handlers: dict[int, Any] = {}
    outcome: dict[str, Any] | None = None
    error: BaseException | None = None
    global _ACTIVE_DISPATCH_PROCESS, _PENDING_DISPATCH_SIGNAL
    try:
        previous_handlers = _install_dispatch_signal_handlers()
        context = _prepare_inputs(
            authorization.plan_pin, authorization.spec_pin, authorization.source_root,
            authorization.input_root, prepared["host_id"], authorization.observed_host_pin,
            prepared["output_root"],
        )
        _check_lock(lock, context["output_root"], context["campaign_id"], context["host_id"])
        require(context["original_pins"] == prepared["original_pins"],
                "original SourceV5/spec/plan/host pins changed after authorization")
        state = _read_journal(lock, context)
        registration = state["registration"]
        authorization_id = token_details["authorization_id"]
        prior = state["authorized"].get(authorization_id)
        require(state["pending"] == authorization_id and registration is not None and
                prior is not None,
                "one-use dispatch authorization is no longer the journal head")
        details = prior["details"]
        require(details == token_details,
                "dispatch token differs from its fsynced authorization record")
        capacity_details, _completion = _capacity_completion(
            context, authorization.capacity_output_root, authorization.completion_pin,
        )
        require(_registration_fields(capacity_details) == _registration_fields(registration),
                "capacity completion changed after dispatch authorization")
        spec = _validate_dispatch_authorization(
            details, context, registration, state["registration_head"],
        )
        require(time.monotonic_ns() < deadline_ns,
                "fixed confirmation outer deadline expired before direct Popen")
        _ensure_confirmation_host_directory(
            context, details["confirmation_owner_marker"],
            state["registration_head"],
        )
        runtime_pin = _write_runtime_binding_file(
            context["output_root"], Path(spec["runtime_bindings"]["path"]),
            spec["runtime_manifest_raw"],
        )
        require(runtime_pin == {
            "path": details["runtime_bindings"]["path"],
            "sha256": details["runtime_bindings"]["sha256"],
        }, "runtime binding output differs from the frozen authorization pin")
        _ensure_private_tree(context["output_root"], stdout_path.parent)
        stdout_fd = os.open(
            stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        os.fchmod(stdout_fd, 0o600)
        stdout_stream = os.fdopen(stdout_fd, "wb", buffering=0)
        stderr_fd = os.open(
            stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        os.fchmod(stderr_fd, 0o600)
        stderr_stream = os.fdopen(stderr_fd, "wb", buffering=0)
        if _PENDING_DISPATCH_SIGNAL is not None:
            raise ChronologyError("dispatch was interrupted before direct Popen")
        _require_owned_child_wait_semantics()
        if time.monotonic_ns() >= deadline_ns:
            cleanup_result = ProcessCleanupResult(
                False, "not_started", None, "not_started", None,
            )
            outcome = _timeout_dispatch_details(
                authorization.details, None, time.monotonic_ns() - start_ns,
                cleanup_result,
            )
            _append_event(lock, context, "dispatch_timeout", outcome)
            return {"authorization_id": authorization.details["authorization_id"],
                    "job_run_id": authorization.details["job"]["run_id"],
                    "status": "timeout", "pid": None, "process_reaped": False,
                    "process_reap_status": cleanup_result.process_reap_status,
                    "return_code": cleanup_result.return_code,
                    "process_group_cleanup_status": "not_started",
                    "cleanup_error_sha256": None,
                    "qualification_eligible": False,
                    "controller_chronology_proven": False}
        try:
            process = subprocess.Popen(
                authorization.details["argv"], cwd=authorization.details["cwd"],
                env=authorization.details["environment"], stdin=subprocess.DEVNULL,
                stdout=stdout_stream, stderr=stderr_stream, close_fds=True,
                shell=False, start_new_session=True,
            )
        except OSError as launch_error:
            elapsed_ns = time.monotonic_ns() - start_ns
            _flush_close_streams(stdout_stream, stderr_stream, ignore_errors=True)
            stdout_stream = stderr_stream = None
            cleanup_result = ProcessCleanupResult(
                False, "not_started", None, "not_started", None,
            )
            failure = _failed_dispatch_details(
                authorization.details, None, launch_error, elapsed_ns,
                cleanup_result,
            )
            _append_event(lock, context, "dispatch_failed", failure)
            return {"authorization_id": authorization.details["authorization_id"],
                    "job_run_id": authorization.details["job"]["run_id"],
                    "status": "launch_failed", "pid": None, "process_reaped": False,
                    "process_reap_status": cleanup_result.process_reap_status,
                    "return_code": cleanup_result.return_code,
                    "process_group_cleanup_status": "not_started",
                    "cleanup_error_sha256": None,
                    "error_sha256": failure["error_sha256"],
                    "qualification_eligible": False,
                    "controller_chronology_proven": False}
        _ACTIVE_DISPATCH_PROCESS = process
        try:
            bound = _live_process_identity(
                process, context["stage"], authorization.details["shebang_interpreter"],
                authorization.details["cwd"],
                context["prepared"]["current_host"]["cpu_affinity"],
                context["prepared"]["current_host"]["network_namespace_inode"],
                authorization.details["environment"],
                timeout_seconds=max(0.01, min(1.0, (deadline_ns - time.monotonic_ns()) / 1e9)),
            )
        except BaseException as binding_error:
            error = binding_error
            raise
        environment_sha = authorization.details["environment_sha256"]
        bound_details = {
            "authorization_id": authorization.details["authorization_id"],
            "job_run_id": authorization.details["job"]["run_id"],
            "member_role": "campaign_pair_runner", "pid": bound["pid"],
            "start_ticks": bound["start_ticks"],
            "runner_path": authorization.details["runner"]["path"],
            "runner_sha256": authorization.details["runner"]["sha256"],
            "process_executable_path": bound["process_executable_path"],
            "process_executable_sha256": bound["process_executable_sha256"],
            "cwd": bound["cwd"], "cpu_affinity": bound["cpu_affinity"],
            "network_namespace_inode": bound["network_namespace_inode"],
            "environment": authorization.details["environment"],
            "environment_sha256": environment_sha,
            "actual_environment_sha256": sha256_bytes(canonical_bytes(bound["environment"])),
            "process_report_nonce": None,
            "member_report_nonces": [item["report_nonce"] for item in authorization.details["pair_members"]],
            "caller_role": "campaign_pair_runner",
            "pair_members_sha256": authorization.details["pair_members_sha256"],
            "capacity_registration_head": authorization.details["capacity_registration_head"],
            "qualification_eligible": False,
        }
        _validate_bound_details(bound_details, authorization.details, context)
        _append_event(lock, context, "dispatch_bound", bound_details)

        status = "completed"
        signum: int | None = None
        while _leader_exit_status_unreaped(process) is None:
            if _PENDING_DISPATCH_SIGNAL is not None:
                status = "interrupted"
                signum = _PENDING_DISPATCH_SIGNAL
                break
            if time.monotonic_ns() >= deadline_ns:
                status = "timeout"
                break
            stdout_info = os.fstat(stdout_stream.fileno())
            stderr_info = os.fstat(stderr_stream.fileno())
            require(stdout_info.st_size <= MAX_OUTPUT_BYTES and
                    stderr_info.st_size <= MAX_OUTPUT_BYTES,
                    "fixed pair-runner output exceeded its finite capture bound")
            time.sleep(min(0.02, max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9)))
        if status == "completed" and time.monotonic_ns() >= deadline_ns:
            status = "timeout"
        if status == "completed" and _PENDING_DISPATCH_SIGNAL is not None:
            status = "interrupted"
            signum = _PENDING_DISPATCH_SIGNAL
        cleanup_result = _terminate_process_group(process)
        process_reaped = cleanup_result.process_reaped
        if status == "completed" and time.monotonic_ns() >= deadline_ns:
            status = "timeout"
        if status == "completed" and _PENDING_DISPATCH_SIGNAL is not None:
            status = "interrupted"
            signum = _PENDING_DISPATCH_SIGNAL
        return_code = cleanup_result.return_code
        _flush_close_streams(stdout_stream, stderr_stream)
        stdout_stream = stderr_stream = None
        elapsed_ns = max(0, time.monotonic_ns() - start_ns)
        if status == "timeout":
            terminal = _timeout_dispatch_details(
                authorization.details, bound["pid"], elapsed_ns,
                cleanup_result,
            )
            _append_event(lock, context, "dispatch_timeout", terminal)
            cleanup_safe = _cleanup_is_safe(cleanup_result)
            outcome = {"authorization_id": authorization.details["authorization_id"],
                       "job_run_id": authorization.details["job"]["run_id"],
                       "status": "timeout" if cleanup_safe else "cleanup_failed",
                       "dispatch_status": "timeout",
                       "pid": bound["pid"],
                       "process_reaped": process_reaped,
                       "process_reap_status": cleanup_result.process_reap_status,
                       "return_code": cleanup_result.return_code,
                       "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                       "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                       "qualification_eligible": False,
                       "controller_chronology_proven": False}
        elif status == "interrupted":
            terminal = _interrupted_dispatch_details(
                authorization.details, bound["pid"], signum or signal.SIGTERM,
                elapsed_ns, cleanup_result,
            )
            _append_event(lock, context, "dispatch_interrupted", terminal)
            cleanup_safe = _cleanup_is_safe(cleanup_result)
            outcome = {"authorization_id": authorization.details["authorization_id"],
                       "job_run_id": authorization.details["job"]["run_id"],
                       "status": "interrupted" if cleanup_safe else "cleanup_failed",
                       "dispatch_status": "interrupted",
                       "pid": bound["pid"],
                       "signal": signum, "process_reaped": process_reaped,
                       "process_reap_status": cleanup_result.process_reap_status,
                       "return_code": cleanup_result.return_code,
                       "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                       "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                       "qualification_eligible": False,
                       "controller_chronology_proven": False}
        elif not _cleanup_is_safe(cleanup_result):
            failure = ChronologyError(cleanup_result.error_message or
                                      "pair-runner group cleanup was not verified clean")
            terminal = _failed_dispatch_details(
                authorization.details, bound["pid"], failure, elapsed_ns,
                cleanup_result,
            )
            _append_event(lock, context, "dispatch_failed", terminal)
            outcome = {"authorization_id": authorization.details["authorization_id"],
                       "job_run_id": authorization.details["job"]["run_id"],
                       "status": "cleanup_failed", "pid": bound["pid"],
                       "process_reaped": process_reaped,
                       "process_reap_status": cleanup_result.process_reap_status,
                       "return_code": cleanup_result.return_code,
                       "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                       "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                       "error_sha256": terminal["error_sha256"],
                       "qualification_eligible": False,
                       "controller_chronology_proven": False}
        else:
            stdout_pin, stdout_raw, stdout_size = _capture_output(stdout_path)
            stderr_pin, stderr_raw, stderr_size = _capture_output(stderr_path)
            if return_code is not None and return_code < 0:
                exit_status = "signaled"
                exit_signal: int | None = -return_code
            else:
                exit_status = "completed"
                exit_signal = None
            terminal = {
                "authorization_id": authorization.details["authorization_id"],
                "job_run_id": authorization.details["job"]["run_id"],
                "member_role": "campaign_pair_runner", "pid": bound["pid"],
                "return_code": return_code, "status": exit_status,
                "signal": exit_signal, "elapsed_ns": elapsed_ns,
                "stdout": stdout_pin, "stderr": stderr_pin,
                "stdout_sha256": stdout_pin["sha256"],
                "stderr_sha256": stderr_pin["sha256"],
                "stdout_size": stdout_size, "stderr_size": stderr_size,
                "process_reaped": cleanup_result.process_reaped,
                "process_reap_status": cleanup_result.process_reap_status,
                "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                "cleanup_error_sha256": _cleanup_error_sha256(cleanup_result),
                "capacity_registration_head": authorization.details["capacity_registration_head"],
                "qualification_eligible": False,
            }
            _append_event(lock, context, "dispatch_exited", terminal)
            outcome = {"authorization_id": authorization.details["authorization_id"],
                       "job_run_id": authorization.details["job"]["run_id"],
                       "status": exit_status, "return_code": return_code,
                       "pid": bound["pid"], "start_ticks": bound["start_ticks"],
                       "process_executable_path": bound["process_executable_path"],
                       "process_executable_sha256": bound["process_executable_sha256"],
                       "process_reaped": process_reaped,
                       "process_reap_status": cleanup_result.process_reap_status,
                       "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                       "cleanup_error_sha256": _cleanup_error_sha256(cleanup_result),
                       "qualification_eligible": False,
                       "controller_chronology_proven": False}
    except BaseException as caught:
        error = caught
        elapsed_ns = max(0, time.monotonic_ns() - start_ns)
        pid = process.pid if process is not None else None
        if process is not None:
            if cleanup_result is None:
                cleanup_result = _terminate_process_group(process)
            process_reaped = cleanup_result.process_reaped
            return_code = cleanup_result.return_code
        else:
            process_reaped = False
            return_code = None
            cleanup_result = ProcessCleanupResult(
                False, "not_started", None, "not_started", None,
            )
        _flush_close_streams(stdout_stream, stderr_stream, ignore_errors=True)
        stdout_stream = stderr_stream = None
        signal_value = _PENDING_DISPATCH_SIGNAL
        cleanup_safe = _cleanup_is_safe(cleanup_result)
        transaction_context = context if context is not None else prepared
        try:
            current = _read_journal(lock, transaction_context)
            if current["pending"] == authorization.details["authorization_id"]:
                if signal_value is not None:
                    terminal = _interrupted_dispatch_details(
                        authorization.details, pid, signal_value, elapsed_ns,
                        cleanup_result,
                    )
                    _append_event(lock, transaction_context, "dispatch_interrupted", terminal)
                    outcome = {"authorization_id": authorization.details["authorization_id"],
                               "job_run_id": authorization.details["job"]["run_id"],
                               "status": "interrupted" if cleanup_safe else "cleanup_failed",
                               "dispatch_status": "interrupted",
                               "pid": pid, "signal": signal_value,
                               "process_reaped": process_reaped,
                               "process_reap_status": cleanup_result.process_reap_status,
                               "return_code": cleanup_result.return_code,
                               "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                               "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                               "qualification_eligible": False,
                               "controller_chronology_proven": False}
                elif time.monotonic_ns() >= deadline_ns:
                    terminal = _timeout_dispatch_details(
                        authorization.details, pid, elapsed_ns,
                        cleanup_result,
                    )
                    _append_event(lock, transaction_context, "dispatch_timeout", terminal)
                    outcome = {"authorization_id": authorization.details["authorization_id"],
                               "job_run_id": authorization.details["job"]["run_id"],
                               "status": "timeout" if cleanup_safe else "cleanup_failed",
                               "dispatch_status": "timeout", "pid": pid,
                               "process_reaped": process_reaped,
                               "process_reap_status": cleanup_result.process_reap_status,
                               "return_code": cleanup_result.return_code,
                               "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                               "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                               "qualification_eligible": False,
                               "controller_chronology_proven": False}
                else:
                    dispatch_error = caught if cleanup_safe else ChronologyError(
                        f"{type(caught).__name__}: dispatch cleanup is not verified safe"
                    )
                    terminal = _failed_dispatch_details(
                        authorization.details, pid, dispatch_error, elapsed_ns,
                        cleanup_result,
                    )
                    _append_event(lock, transaction_context, "dispatch_failed", terminal)
                    outcome = {"authorization_id": authorization.details["authorization_id"],
                               "job_run_id": authorization.details["job"]["run_id"],
                               "status": "launch_failed" if cleanup_safe else "cleanup_failed",
                               "dispatch_status": "launch_failed", "pid": pid,
                               "process_reaped": process_reaped,
                               "process_reap_status": cleanup_result.process_reap_status,
                               "return_code": cleanup_result.return_code,
                               "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                               "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                               "error_sha256": terminal["error_sha256"],
                               "qualification_eligible": False,
                               "controller_chronology_proven": False}
        except BaseException:
            raise
    finally:
        if stdout_stream is not None or stderr_stream is not None:
            _flush_close_streams(stdout_stream, stderr_stream, ignore_errors=True)
        if process is not None:
            _ACTIVE_DISPATCH_PROCESS = None
        if previous_handlers:
            _restore_dispatch_signal_handlers(previous_handlers)
        _PENDING_DISPATCH_SIGNAL = None
        with _AUTHORIZATION_TOKEN_LOCK:
            _AUTHORIZATION_TOKENS.pop(id(authorization), None)
    require(outcome is not None, "bounded launch ended without a durable terminal result")
    return outcome






def _check_lock(lock: object, output_root: Path, campaign_id: str, host_id: str) -> CampaignHostLock:
    require(_lock_token_is_live(lock),
            "locked chronology API requires its active fd-owned CampaignHostLock token")
    assert isinstance(lock, CampaignHostLock)
    require(lock.active and lock.campaign_id == campaign_id and
            lock.host_id == host_id and lock.output_root == output_root,
            "campaign/host lock token does not own these inputs")
    try:
        fd_info = os.fstat(lock.fd)
        path_info = lock.lock_path.lstat()
    except OSError as error:
        raise ChronologyError(f"campaign/host lock descriptor is no longer valid: {error}") from error
    require(stat.S_ISREG(fd_info.st_mode) and stat.S_ISREG(path_info.st_mode) and
            (fd_info.st_dev, fd_info.st_ino) == lock._fd_key == (path_info.st_dev, path_info.st_ino) and
            stat.S_IMODE(fd_info.st_mode) == stat.S_IMODE(path_info.st_mode) == 0o600 and
            fd_info.st_uid == path_info.st_uid == os.getuid(),
            "campaign/host lock must remain an owned regular O_NOFOLLOW file with mode 0600")
    return lock


def campaign_host_lock(
    output_root: Path, campaign_id: str, host_id: str, *,
    timeout_seconds: float | None = None,
) -> CampaignHostLock:
    """Open and hold the one private per-campaign/per-host flock context."""
    root = _safe_root(Path(output_root), "campaign chronology output root")
    require(stat.S_IMODE(root.stat().st_mode) == 0o700 and root.stat().st_uid == os.getuid(),
            "campaign chronology output root must be owned and mode 0700")
    campaign_id = _token(campaign_id, "campaign ID")
    host_id = _token(host_id, "host ID")
    campaign_dir = root / campaign_id
    _ensure_private_directory(campaign_dir)
    chronology_dir = campaign_dir / "chronology"
    _ensure_private_directory(chronology_dir)
    host_dir = chronology_dir / host_id
    _ensure_private_directory(host_dir)
    lock_path = host_dir / "campaign-host.lock"
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        fd = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        fd = os.open(lock_path, flags)
    try:
        if created:
            os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        path_info = lock_path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_ISREG(path_info.st_mode) and
                (info.st_dev, info.st_ino) == (path_info.st_dev, path_info.st_ino) and
                stat.S_IMODE(info.st_mode) == stat.S_IMODE(path_info.st_mode) == 0o600 and
                info.st_uid == path_info.st_uid == os.getuid(),
                "campaign/host lock must be an owned regular O_NOFOLLOW file with mode 0600")
        if timeout_seconds is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            require(type(timeout_seconds) in (int, float) and 0 <= timeout_seconds <= 3600,
                    "lock acquisition timeout exceeds its finite bound")
            deadline = time.monotonic() + float(timeout_seconds)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ChronologyError("campaign/host flock acquisition timed out")
                    time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        return CampaignHostLock(root, campaign_id, host_id, host_dir, lock_path, fd)
    except BaseException:
        os.close(fd)
        raise


def _safe_child(root: Path, value: object, label: str) -> Path:
    relative = _relative(value, label)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError as error:
            raise ChronologyError(f"{label} is unavailable: {error}") from error
        require(not stat.S_ISLNK(info.st_mode), f"{label} traverses a symlink")
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ChronologyError(f"{label} is missing or escaped its pinned root") from error
    return resolved


def _source_file(source_root: Path, source: dict[str, Any], relative: str,
                 label: str, maximum: int = MAX_SOURCE_BYTES) -> tuple[bytes, str, dict[str, Any]]:
    files = source.get("source", {}).get("files")
    require(type(files) is list and files, "SourceV5 regular-file inventory is missing")
    matches = [item for item in files if type(item) is dict and item.get("path") == relative]
    require(len(matches) == 1, f"SourceV5 has no unique regular inventory entry for {relative}")
    record = _exact(matches[0], {"path", "kind", "mode", "sha256", "size"},
                    f"SourceV5 {label} inventory entry")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755"),
            f"SourceV5 {label} is not a regular file inventory entry")
    expected_sha = _digest(record["sha256"], f"SourceV5 {label} digest")
    size = _uint(record["size"], f"SourceV5 {label} size", maximum=maximum)
    path = _safe_child(source_root, relative, f"SourceV5 {label}")
    raw, info = _read_stable(path, f"SourceV5 {label}", maximum)
    mode = stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode)
    require(mode == int(record["mode"], 8) and len(raw) == size and sha256_bytes(raw) == expected_sha,
            f"SourceV5 {label} bytes, mode, or size differ from the typed inventory")
    return raw, expected_sha, record


def _load_module(raw: bytes, path: Path, label: str) -> types.ModuleType:
    module = types.ModuleType(f"chronology_{label}_{sha256_bytes(raw)}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except Exception as error:
        raise ChronologyError(f"captured SourceV5 {label} cannot be loaded: {error}") from error
    return module


def _prepare_inputs(
    plan_pin: object, spec_pin: object, source_root_arg: Path, input_root_arg: Path,
    host_id: str, observed_host_pin: object, output_root: Path,
) -> dict[str, Any]:
    spec, spec_path, spec_raw, spec_raw_sha = _read_pin(spec_pin, "campaign spec", MAX_SPEC_BYTES)
    plan, plan_path, plan_raw, plan_raw_sha = _read_pin(plan_pin, "campaign plan", MAX_PLAN_BYTES)
    require(spec.get("schema") == SPEC_SCHEMA and plan.get("schema") == PLAN_SCHEMA,
            "chronology requires the pinned SourceV5 specV3 and planV3")
    require(spec.get("campaign_id") == plan.get("campaign_id"), "spec/plan campaign IDs differ")
    campaign_id = _token(spec.get("campaign_id"), "campaign ID")
    host_id = _token(host_id, "host ID")
    require(host_id in plan.get("host_ids", []), "selected host is absent from the frozen plan")
    source_root = _safe_root(Path(source_root_arg), "SourceV5 root")
    input_root = _safe_root(Path(input_root_arg), "campaign input root")
    output_root = _safe_root(Path(output_root), "campaign chronology output root")
    require(not _within(source_root, input_root) and not _within(source_root, output_root),
            "campaign inputs and transaction outputs must remain outside SourceV5")
    active_path = Path(__file__).resolve(strict=True)
    require(active_path == source_root / CHRONOLOGY_SOURCE_PATH,
            "active chronology module is not executing from the supplied SourceV5 root")

    refs = spec.get("source_manifests")
    require(type(refs) is list and len(refs) == 3,
            "SourceV5 spec must pin all three host source manifests")
    raw_refs: dict[str, dict[str, Any]] = {}
    sources: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(refs):
        ref = _exact(value, {"host_id", "relative_path", "sha256"},
                     f"SourceV5 manifest ref[{index}]")
        ref_host = _token(ref["host_id"], f"SourceV5 manifest host[{index}]")
        require(ref_host not in raw_refs, f"duplicate SourceV5 manifest host {ref_host}")
        relative = _relative(ref["relative_path"], f"SourceV5 manifest relative path[{index}]")
        manifest_path = spec_path.parent / relative
        raw, _info = _read_stable(manifest_path, f"SourceV5 manifest {ref_host}", MAX_MANIFEST_BYTES)
        raw_sha = sha256_bytes(raw)
        semantic_pin = _digest(ref["sha256"], f"SourceV5 semantic manifest pin {ref_host}")
        manifest = _parse_object(raw, f"SourceV5 manifest {ref_host}", MAX_MANIFEST_BYTES)
        require(manifest.get("schema") == SOURCE_SCHEMA and
                _digest(manifest.get("manifest_sha256"), f"SourceV5 semantic manifest {ref_host}") ==
                semantic_pin and
                hashlib.sha256(canonical_bytes({key: item for key, item in manifest.items()
                                                if key != "manifest_sha256"})).hexdigest() ==
                manifest["manifest_sha256"],
                f"SourceV5 semantic manifest pin is invalid for {ref_host}")
        raw_refs[ref_host] = {
            "host_id": ref_host, "path": str(manifest_path),
            "raw_sha256": raw_sha, "semantic_sha256": manifest["manifest_sha256"],
            "source_tree_sha256": manifest["source"]["source_tree_sha256"],
        }
        sources[ref_host] = manifest
    require(host_id in sources, "selected host has no SourceV5 source manifest")
    selected_source = sources[host_id]

    stage_raw, stage_sha, stage_record = _source_file(
        source_root, selected_source, CAPACITY_STAGE_SOURCE_PATH, "capacity-stage module",
        maximum=MAX_SCRIPT_BYTES,
    )
    chronology_raw, chronology_sha, chronology_record = _source_file(
        source_root, selected_source, CHRONOLOGY_SOURCE_PATH, "chronology module",
        maximum=MAX_SCRIPT_BYTES,
    )
    active_raw, active_info = _read_stable(active_path, "active chronology module", MAX_SCRIPT_BYTES)
    require(active_raw == chronology_raw and sha256_bytes(active_raw) == chronology_sha,
            "active chronology module differs from its exact regular SourceV5 inventory pin")
    require(active_info.st_mode & 0o111 == 0 or stat.S_IMODE(active_info.st_mode) in (0o644, 0o755),
            "active chronology module has an unsupported file mode")
    for other_host, source in sources.items():
        for rel, expected_sha in ((CAPACITY_STAGE_SOURCE_PATH, stage_sha),
                                  (CHRONOLOGY_SOURCE_PATH, chronology_sha)):
            _raw, other_sha, other_record = _source_file(source_root, source, rel,
                                                          f"{other_host} {rel}",
                                                          maximum=MAX_SCRIPT_BYTES)
            require(other_sha == expected_sha and other_record["mode"] ==
                    (stage_record if rel == CAPACITY_STAGE_SOURCE_PATH else chronology_record)["mode"],
                    f"SourceV5 host {other_host} captures a different {rel}")
    runner_raw, runner_sha, _runner_record = _source_file(
        source_root, selected_source, PAIR_RUNNER_SOURCE_PATH, "fixed pair runner",
        maximum=MAX_SCRIPT_BYTES,
    )
    require(runner_sha == spec.get("runner_sha256"),
            "fixed pair runner source entry differs from the unchanged spec hash")
    for other_host, source in sources.items():
        _other_raw, other_runner_sha, _other_record = _source_file(
            source_root, source, PAIR_RUNNER_SOURCE_PATH,
            f"{other_host} fixed pair runner", maximum=MAX_SCRIPT_BYTES,
        )
        require(other_runner_sha == runner_sha,
                f"SourceV5 host {other_host} captures a different fixed pair runner")
    stage_module = _load_module(stage_raw, source_root / CAPACITY_STAGE_SOURCE_PATH, "capacity_stage")
    require(callable(getattr(stage_module, "_prepare_pins", None)) and
            callable(getattr(stage_module, "run_capacity_stage", None)) and
            callable(getattr(stage_module, "verify_capacity_completion", None)),
            "captured capacity-stage API is unsupported")
    try:
        prepared = stage_module._prepare_pins(
            plan_pin, spec_pin, source_root, input_root, host_id, observed_host_pin,
        )
    except Exception as error:
        raise ChronologyError(f"captured SourceV5 stage rejected its original pins/host context: {error}") from error
    require(prepared["spec_raw_sha256"] == spec_raw_sha and
            prepared["plan_raw_sha256"] == plan_raw_sha and prepared["host_id"] == host_id,
            "captured stage returned a different original input context")
    controller = prepared["stack"]["controller"]
    refs_by_host = stage_module._source_manifest_refs(spec, spec_path)
    source_pins = []
    for ref in refs:
        ref_host = ref["host_id"]
        path, source, raw, raw_sha = refs_by_host[ref_host]
        source_pins.append({
            "host_id": ref_host, "path": str(path), "raw_sha256": raw_sha,
            "semantic_sha256": source["manifest_sha256"],
            "source_tree_sha256": source["source"]["source_tree_sha256"],
        })
    host_context_pin = _exact(observed_host_pin, {"path", "sha256"}, "observed host pin")
    original_pins = {
        "schema": CHRONOLOGY_SCHEMA,
        "campaign_id": campaign_id, "host_id": host_id,
        "spec": {"path": str(spec_path), "raw_sha256": spec_raw_sha,
                 "semantic_sha256": prepared["spec_semantic_sha256"]},
        "plan": {"path": str(plan_path), "raw_sha256": plan_raw_sha,
                 "semantic_sha256": prepared["plan_semantic_sha256"]},
        "source_manifests": source_pins,
        "observed_host": {
            "path": str(prepared["host_context_path"]),
            "raw_sha256": prepared["host_context_raw_sha256"],
            "boot_id_sha256": prepared["current_host"]["boot_id_sha256"],
            "controls_sha256": prepared["host"]["host_fingerprint_sha256"],
            "controls": prepared["host_context"]["controls"],
            "cpu_affinity": prepared["current_host"]["cpu_affinity"],
            "network_namespace_inode": prepared["current_host"]["network_namespace_inode"],
        },
        "capacity_stage": {"path": CAPACITY_STAGE_SOURCE_PATH, "sha256": stage_sha},
        "chronology_module": {"path": CHRONOLOGY_SOURCE_PATH, "sha256": chronology_sha},
        "pair_runner": {"path": PAIR_RUNNER_SOURCE_PATH, "sha256": runner_sha},
        "captured_modules": [
            {"role": "campaign_controller", "path": CONTROLLER_SOURCE_PATH,
             "sha256": prepared["stack"]["controller_sha256"]},
            {"role": "campaign_inputs", "path": "scripts/application-campaign-inputs.py",
             "sha256": prepared["stack"]["inputs_sha256"]},
            {"role": "feedback_reader", "path": "scripts/application-feedback-readback.py",
             "sha256": prepared["stack"]["feedback_reader_sha256"]},
            {"role": "capacity_producer", "path": "scripts/application-byte-capacity.py",
             "sha256": prepared["stack"]["capacity_producer_sha256"]},
        ],
    }
    require(host_context_pin["path"] == str(prepared["host_context_path"]) and
            host_context_pin["sha256"] == prepared["host_context_raw_sha256"],
            "observed host path/raw pin changed during SourceV5 preparation")
    require(controller is prepared["stack"]["controller"],
            "captured SourceV5 controller object changed during preparation")
    return {
        "campaign_id": campaign_id, "host_id": host_id,
        "spec_pin": {"path": str(spec_path), "sha256": spec_raw_sha},
        "plan_pin": {"path": str(plan_path), "sha256": plan_raw_sha},
        "source_root": source_root, "input_root": input_root, "output_root": output_root,
        "spec": spec, "plan": plan, "sources": sources,
        "source": selected_source, "source_manifest_raw_refs": raw_refs,
        "prepared": prepared, "stage": stage_module, "controller": controller,
        "original_pins": original_pins,
        "original_pins_sha256": sha256_bytes(canonical_bytes(original_pins)),
        "boot_id_sha256": prepared["current_host"]["boot_id_sha256"],
    }


def _journal_path(lock: CampaignHostLock) -> Path:
    return lock.directory / "dispatch-journal.jsonl"


def _empty_journal(original_pins: dict[str, Any]) -> dict[str, Any]:
    return {
        "original_pins": _json_copy(original_pins), "record_count": 0,
        "dispatch_event_count": 0, "head": "0" * 64,
        "registration": None, "registration_head": None, "stage_completion": None,
        "stage_head": None,
        "authorized": {}, "finished": set(), "pending": None,
        "cleanup_blocked": False, "process_cleanup": [],
        "last_monotonic_ns": 0, "file_stat": None,
    }


def _auth_detail_identity(details: dict[str, Any]) -> tuple[str, str]:
    return details["authorization_id"], details["job"]["run_id"]


def _validate_process_cleanup_details(details: dict[str, Any]) -> bool:
    process_reaped = details.get("process_reaped")
    require(type(process_reaped) is bool,
            "dispatch terminal omitted the direct leader reap result")
    reap_status = details.get("process_reap_status")
    require(type(reap_status) is str and reap_status in PROCESS_REAP_STATUSES,
            "dispatch terminal has an unknown direct leader reap status")
    return_code = details.get("return_code")
    cleanup_status = details.get("process_group_cleanup_status")
    require(type(cleanup_status) is str and cleanup_status in PROCESS_GROUP_CLEANUP_STATES,
            "dispatch terminal has an unknown process-group cleanup status")
    pid = details.get("pid")
    if pid is None:
        require(reap_status == "not_started" and not process_reaped and
                return_code is None and cleanup_status == "not_started",
                "dispatch without a direct Popen has contradictory cleanup metadata")
    else:
        _uint(pid, "dispatch cleanup direct Popen PID", positive=True,
              maximum=(1 << 31) - 1)
        require(cleanup_status != "not_started",
                "dispatch with a direct Popen claims cleanup never started")
        if reap_status == "owned_reaped":
            require(process_reaped and type(return_code) is int,
                    "owned direct leader reap lacks its exact integer wait status")
        else:
            require(reap_status in {"not_reaped", "unverified"} and
                    not process_reaped and return_code is None,
                    "unreaped or unverified direct leader has contradictory reap metadata")
    safe = ((reap_status == "not_started" and pid is None and not process_reaped and
             return_code is None and cleanup_status == "not_started") or
            (reap_status == "owned_reaped" and process_reaped and
             type(return_code) is int and cleanup_status == "clean"))
    error_sha256 = details.get("cleanup_error_sha256")
    if safe:
        require(error_sha256 is None,
                "verified clean process cleanup has contradictory error metadata")
    else:
        _digest(error_sha256, "process-group cleanup failure digest")
    return safe


def _check_event_semantics(
    state: dict[str, Any], event: str, details_value: object, record_sha: str,
    prepared: dict[str, Any], *, replay: bool, apply: bool = True,
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS[event], f"chronology {event} details")
    if event == "capacity_stage_completed":
        require(state["stage_completion"] is None and state["registration"] is None and
                not state["authorized"], "capacity stage completion is not the first journal event")
        _validate_capacity_details(details, prepared)
        if apply:
            state["stage_completion"] = details
            state["stage_head"] = record_sha
    elif event == "capacity_registered":
        stage = state.get("stage_completion")
        require(stage is not None and state["registration"] is None and not state["authorized"],
                "capacity registration lacks one prior locked stage completion")
        _validate_capacity_details(details, prepared)
        require(details["capacity_stage_event_head"] == state.get("stage_head") and
                _registration_fields(details) == _registration_fields(stage),
                "capacity registration differs from the locked stage completion")
        if apply:
            state["registration"] = details
            state["registration_head"] = record_sha
    elif event == "dispatch_authorized":
        registration = state.get("registration")
        require(registration is not None, "fixed confirmation dispatch lacks a capacity registration")
        require(state.get("cleanup_blocked") is False,
                "prior pair-runner cleanup is unclean or unverified; later dispatch is blocked")
        require(state.get("pending") is None, "an earlier dispatch authorization remains unresolved")
        _validate_dispatch_authorization(details, prepared, registration,
                                         state["registration_head"])
        auth_id, run_id = _auth_detail_identity(details)
        require(auth_id not in state["authorized"] and run_id not in state["finished"],
                "original confirmation authorization was already consumed and cannot be retried")
        if apply:
            state["authorized"][auth_id] = {"details": details, "bound": None}
            state["pending"] = auth_id
    else:
        authorization_id = _token(details.get("authorization_id"), "dispatch authorization ID")
        prior = state["authorized"].get(authorization_id)
        require(prior is not None and state.get("pending") == authorization_id,
                f"chronology {event} has no active one-use authorization")
        authorization = prior["details"]
        require(details["job_run_id"] == authorization["job"]["run_id"] and
                details["member_role"] == authorization["member_role"] and
                details["capacity_registration_head"] == state["registration_head"],
                f"chronology {event} differs from its original authorization")
        cleanup_safe = True
        if event == "dispatch_bound":
            require(prior["bound"] is None, "dispatch process was bound more than once")
            _validate_bound_details(details, authorization, prepared)
            if apply:
                prior["bound"] = details
        else:
            require(event in ("dispatch_exited", "dispatch_failed", "dispatch_interrupted", "dispatch_timeout"),
                    "unknown dispatch terminal event")
            cleanup_safe = _validate_process_cleanup_details(details)
            bound = prior["bound"]
            if event == "dispatch_exited":
                require(bound is not None, "dispatch exit lacks a durable post-Popen process binding")
                _validate_exit_details(details, bound, authorization, prepared)
            elif event in ("dispatch_interrupted", "dispatch_timeout"):
                if bound is not None:
                    require(details.get("pid") == bound["pid"],
                            f"{event} PID differs from the bound direct process")
                elif details.get("pid") is not None:
                    _uint(details.get("pid"), f"{event} direct Popen PID", positive=True,
                          maximum=(1 << 31) - 1)
                require(type(details.get("process_reaped")) is bool,
                        f"{event} lacks the direct process reap result")
                elapsed_ns = _uint(details.get("elapsed_ns"), f"{event} elapsed nanoseconds")
                require(elapsed_ns <= authorization["effective_timeout_seconds"] * 1_000_000_000 +
                        10_000_000_000,
                        f"{event} cleanup elapsed time exceeds its finite dispatch bound")
                if event == "dispatch_interrupted":
                    _uint(details.get("signal"), "dispatch interruption signal", positive=True,
                          maximum=255)
                    if details.get("pid") is None:
                        require(details.get("return_code") is None,
                                "interruption without a direct process has a fabricated exit code")
                    else:
                        require(details.get("return_code") is None or
                                type(details.get("return_code")) is int,
                                "interrupted direct process has a malformed wait status")
                else:
                    _uint(details.get("effective_timeout_seconds"),
                          "dispatch timeout effective bound", positive=True,
                          maximum=MAX_TIMEOUT_SECONDS)
                    require(details["effective_timeout_seconds"] ==
                            authorization["effective_timeout_seconds"],
                            "dispatch timeout differs from its authorized finite bound")
                    require(elapsed_ns >= authorization["effective_timeout_seconds"] * 1_000_000_000,
                            "dispatch timeout was recorded before its authorized deadline")
                    if details.get("pid") is None:
                        require(details.get("return_code") is None,
                                "timeout without a direct process has a fabricated exit code")
                    else:
                        require(details.get("return_code") is None or
                                type(details.get("return_code")) is int,
                                "timed-out direct process has a malformed wait status")
            else:
                if bound is None:
                    if details.get("pid") is None:
                        require(details.get("return_code") is None,
                                "failed dispatch without a direct process has an exit code")
                    else:
                        _uint(details.get("pid"), "failed direct Popen PID", positive=True,
                              maximum=(1 << 31) - 1)
                        require(details.get("return_code") is None or
                                type(details.get("return_code")) is int,
                                "failed direct process has a malformed wait status")
                    require(type(details.get("process_reaped")) is bool,
                            "failed direct Popen omitted its reap status")
                else:
                    require(details.get("pid") == bound["pid"] and
                            type(details.get("process_reaped")) is bool and
                            ((details["process_reaped"] and
                              type(details.get("return_code")) is int) or
                             (not details["process_reaped"] and
                              details.get("return_code") is None)),
                            "failed bound dispatch omitted its direct process reap status")
                _token(details.get("error_type"), "dispatch failure error type", maximum=128)
                elapsed_ns = _uint(details.get("elapsed_ns"), "failed dispatch elapsed nanoseconds")
                require(elapsed_ns <= authorization["effective_timeout_seconds"] * 1_000_000_000 +
                        10_000_000_000,
                        "failed dispatch cleanup elapsed time exceeds its finite bound")
                _digest(details.get("error_sha256"), "dispatch failure digest")
            if apply:
                state["pending"] = None
                state["finished"].add(authorization["job"]["run_id"])
                state["process_cleanup"].append({
                    "authorization_id": authorization_id,
                    "job_run_id": authorization["job"]["run_id"],
                    "process_reaped": details["process_reaped"],
                    "process_reap_status": details["process_reap_status"],
                    "return_code": details["return_code"],
                    "process_group_cleanup_status": details["process_group_cleanup_status"],
                    "cleanup_error_sha256": details["cleanup_error_sha256"],
                })
                if not cleanup_safe:
                    state["cleanup_blocked"] = True
                del state["authorized"][authorization_id]
    return details


def _registration_fields(details: dict[str, Any]) -> dict[str, Any]:
    return {
        key: details[key] for key in (
            "capacity_completion", "capacity_ledger", "capacity_schedule_sha256",
            "entry_count", "entries", "qualification_eligible",
            "controller_chronology_proven",
        )
    }


def _validate_capacity_details(details: dict[str, Any], prepared: dict[str, Any]) -> None:
    completion = _exact(details["capacity_completion"], {"path", "sha256"},
                        "capacity completion raw pin")
    ledger = _exact(details["capacity_ledger"], {"path", "raw_sha256", "terminal_head"},
                    "capacity sealed ledger pin")
    _digest(completion["sha256"], "capacity completion raw SHA-256")
    _path_text(Path(completion["path"]), "capacity completion path")
    _digest(ledger["raw_sha256"], "capacity ledger raw SHA-256")
    _digest(ledger["terminal_head"], "capacity ledger terminal head")
    _path_text(Path(ledger["path"]), "capacity ledger path")
    _digest(details["capacity_schedule_sha256"], "capacity schedule SHA-256")
    require(details["entry_count"] == 15 and type(details["entry_count"]) is int and
            type(details["entries"]) is list and len(details["entries"]) == 15,
            "capacity registration must retain exactly 15 verified entries")
    require(details["qualification_eligible"] is False and
            details["controller_chronology_proven"] is False,
            "capacity registration cannot change eligibility or assert controller chronology")
    require(details["capacity_schedule_sha256"] ==
            prepared["plan"]["capacity_process_templates_sha256"],
            "capacity registration schedule differs from the original PlanV3 digest")


def _read_journal(lock: CampaignHostLock, prepared: dict[str, Any]) -> dict[str, Any]:
    _check_lock(lock, prepared["output_root"], prepared["campaign_id"], prepared["host_id"])
    path = _journal_path(lock)
    state_cached = _cached_lock_state(lock)
    try:
        info = path.lstat()
    except FileNotFoundError:
        require(state_cached is None or state_cached["file_stat"] is None,
                "chronology journal disappeared while its lock was held")
        state = state_cached or _empty_journal(prepared["original_pins"])
        require(state["original_pins"] == prepared["original_pins"],
                "chronology journal original pins changed")
        _set_cached_lock_state(lock, state)
        return state
    except OSError as error:
        raise ChronologyError(f"cannot inspect chronology journal: {error}") from error
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
            info.st_uid == os.getuid(),
            "chronology journal must be an owned mode-0600 regular file")
    key = (info.st_dev, info.st_ino, info.st_mode, info.st_size,
           info.st_mtime_ns, info.st_ctime_ns)
    if state_cached is not None and state_cached["file_stat"] == key:
        require(state_cached["original_pins"] == prepared["original_pins"],
                "chronology journal is already bound to different original pins")
        return state_cached
    raw, read_info = _read_stable(path, "campaign dispatch journal", MAX_JOURNAL_BYTES)
    require(stat.S_IMODE(read_info.st_mode) == 0o600 and read_info.st_uid == os.getuid(),
            "chronology journal permissions changed while reading")
    lines = raw.splitlines(keepends=True)
    require(len(lines) <= MAX_JOURNAL_EVENTS and all(
        line.endswith(b"\n") and b"\r" not in line and len(line) <= MAX_EVENT_BYTES
        for line in lines
    ), "chronology journal framing or event count exceeds its finite bound")
    state = _empty_journal(prepared["original_pins"])
    previous = "0" * 64
    last_monotonic = 0
    for sequence, line in enumerate(lines, 1):
        record_envelope = _parse_object(line, f"chronology journal line {sequence}",
                                        MAX_EVENT_BYTES)
        envelope = _exact(record_envelope,
                          {"previous_sha256", "record", "record_sha256"},
                          f"chronology journal envelope {sequence}")
        _digest(envelope["previous_sha256"], "journal previous SHA-256")
        record = _exact(envelope["record"], {
            "schema", "sequence", "monotonic_ns", "campaign_id", "host_id",
            "boot_id_sha256", "original_pins", "event", "details",
        }, f"chronology journal record {sequence}")
        require(record["schema"] == JOURNAL_SCHEMA and record["sequence"] == sequence and
                record["campaign_id"] == prepared["campaign_id"] and
                record["host_id"] == prepared["host_id"] and
                record["original_pins"] == prepared["original_pins"] and
                record["boot_id_sha256"] == prepared["boot_id_sha256"],
                f"chronology journal record {sequence} changed campaign/source/host pins")
        monotonic_ns = _uint(record["monotonic_ns"], "journal monotonic timestamp", positive=True)
        require(monotonic_ns > last_monotonic and monotonic_ns <= time.monotonic_ns() + 1_000_000_000,
                f"chronology journal record {sequence} has invalid monotonic order")
        event = record["event"]
        require(type(event) is str and event in DETAIL_FIELDS,
                f"chronology journal record {sequence} has unknown event")
        require(envelope["previous_sha256"] == previous,
                f"chronology journal chain breaks at record {sequence}")
        unsigned = {"previous_sha256": previous, "record": record}
        expected_record_sha = sha256_bytes(canonical_bytes(unsigned))
        require(envelope["record_sha256"] == expected_record_sha,
                f"chronology journal record digest is invalid at {sequence}")
        _check_event_semantics(state, event, record["details"], expected_record_sha,
                               prepared, replay=True)
        state["record_count"] += 1
        if event.startswith("dispatch_"):
            state["dispatch_event_count"] += 1
        previous = expected_record_sha
        last_monotonic = monotonic_ns
    after = path.lstat()
    after_key = (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns)
    require(after_key == key, "chronology journal changed during chain replay")
    state["head"] = previous
    state["last_monotonic_ns"] = last_monotonic
    state["file_stat"] = key
    _set_cached_lock_state(lock, state)
    return state


def _append_event(lock: CampaignHostLock, prepared: dict[str, Any], event: str,
                  details: dict[str, Any]) -> dict[str, Any]:
    _check_lock(lock, prepared["output_root"], prepared["campaign_id"], prepared["host_id"])
    state = _read_journal(lock, prepared)
    require(event in DETAIL_FIELDS, f"unknown chronology event {event}")
    record = {
        "schema": JOURNAL_SCHEMA, "sequence": state["record_count"] + 1,
        "monotonic_ns": max(time.monotonic_ns(), state["last_monotonic_ns"] + 1),
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "boot_id_sha256": prepared["boot_id_sha256"],
        "original_pins": _json_copy(prepared["original_pins"]), "event": event,
        "details": _json_copy(details),
    }
    unsigned = {"previous_sha256": state["head"], "record": record}
    record_sha = sha256_bytes(canonical_bytes(unsigned))
    _check_event_semantics(state, event, record["details"], record_sha,
                           prepared, replay=False, apply=False)
    line = canonical_bytes({**unsigned, "record_sha256": record_sha})
    require(len(line) <= MAX_EVENT_BYTES, f"chronology {event} record exceeds its finite line bound")
    path = _journal_path(lock)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0),
        )
    try:
        if created:
            os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        path_info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_ISREG(path_info.st_mode) and
                (info.st_dev, info.st_ino) == (path_info.st_dev, path_info.st_ino) and
                info.st_uid == path_info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == stat.S_IMODE(path_info.st_mode) == 0o600,
                "chronology journal must remain an owned mode-0600 regular file")
        require(info.st_size + len(line) <= MAX_JOURNAL_BYTES,
                "chronology journal exceeds its finite byte bound")
        offset = 0
        while offset < len(line):
            offset += os.write(descriptor, line[offset:])
        os.fsync(descriptor)
        after_info = os.fstat(descriptor)
        require(stat.S_ISREG(after_info.st_mode) and
                (after_info.st_dev, after_info.st_ino) == (info.st_dev, info.st_ino) and
                after_info.st_uid == os.getuid() and stat.S_IMODE(after_info.st_mode) == 0o600 and
                after_info.st_size == info.st_size + len(line),
                "chronology journal metadata changed during durable append")
    finally:
        os.close(descriptor)
    if created:
        _fsync_directory(path.parent)
    after_path = path.lstat()
    require((after_path.st_dev, after_path.st_ino, after_path.st_size) ==
            (after_info.st_dev, after_info.st_ino, after_info.st_size),
            "chronology journal path changed after its durable append")
    _check_event_semantics(state, event, record["details"], record_sha,
                           prepared, replay=False)
    state["record_count"] += 1
    if event.startswith("dispatch_"):
        state["dispatch_event_count"] += 1
    state["head"] = record_sha
    state["last_monotonic_ns"] = record["monotonic_ns"]
    state["file_stat"] = (
        after_path.st_dev, after_path.st_ino, after_path.st_mode, after_path.st_size,
        after_path.st_mtime_ns, after_path.st_ctime_ns,
    )
    _set_cached_lock_state(lock, state)
    return {**record, "record_sha256": record_sha}


def _capacity_completion(
    prepared: dict[str, Any], capacity_output_root: Path, completion_pin: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    capacity_output_root = _safe_root(Path(capacity_output_root), "capacity evidence output root")
    require(not _within(prepared["source_root"], capacity_output_root),
            "capacity evidence output root must be outside SourceV5")
    completion_pin_value = _exact(completion_pin, {"path", "sha256"}, "capacity completion pin")
    completion_path = Path(completion_pin_value["path"])
    completion_sha = _digest(completion_pin_value["sha256"], "capacity completion raw SHA-256")
    try:
        verification = prepared["stage"].verify_capacity_completion(
            prepared["plan_pin"], prepared["spec_pin"], prepared["source_root"],
            prepared["input_root"], prepared["host_id"],
            {"path": str(prepared["prepared"]["host_context_path"]),
             "sha256": prepared["prepared"]["host_context_raw_sha256"]},
            capacity_output_root, {"path": str(completion_path), "sha256": completion_sha},
        )
    except Exception as error:
        raise ChronologyError(f"captured full capacity completion verifier rejected registration: {error}") from error
    verification = _exact(verification, {
        "completion_raw_sha256", "ledger_raw_sha256", "terminal_head", "complete",
        "qualification_eligible", "controller_chronology_proven", "entry_count",
        "capacity_process_templates_sha256",
    }, "captured capacity verifier result")
    require(verification["complete"] is True and
            verification["qualification_eligible"] is False and
            verification["controller_chronology_proven"] is False and
            verification["entry_count"] == 15 and type(verification["entry_count"]) is int and
            verification["capacity_process_templates_sha256"] ==
            prepared["plan"]["capacity_process_templates_sha256"],
            "captured capacity verifier result does not prove the exact ineligible 15-entry replay")
    raw, completion_stat = _read_stable(completion_path, "capacity completion overlay", MAX_COMPLETION_BYTES)
    require(stat.S_IMODE(completion_stat.st_mode) == 0o600 and completion_stat.st_uid == os.getuid(),
            "capacity completion overlay must remain an owned mode-0600 file")
    require(sha256_bytes(raw) == completion_sha == verification["completion_raw_sha256"],
            "capacity completion changed during full replay")
    completion = _parse_object(raw, "capacity completion overlay", MAX_COMPLETION_BYTES)
    _exact(completion, {
        "schema", "complete", "qualification_eligible", "controller_chronology_proven",
        "campaign_id", "host_id", "spec", "plan", "source", "observed_host", "stage",
        "controller", "inputs", "feedback_reader", "capacity_producer",
        "capacity_process_templates_sha256", "stage_directory", "ledger", "entries",
    }, "capacity completion overlay")
    require(completion["schema"] == CAPACITY_COMPLETION_SCHEMA and completion["complete"] is True and
            completion["qualification_eligible"] is False and
            completion["controller_chronology_proven"] is False and
            completion["campaign_id"] == prepared["campaign_id"] and
            completion["host_id"] == prepared["host_id"] and
            type(completion["entries"]) is list and len(completion["entries"]) == 15,
            "capacity completion must be complete for 15 entries and remain ineligible")
    require(completion["spec"] == {
        "path": str(prepared["prepared"]["spec_path"]),
        "raw_sha256": prepared["prepared"]["spec_raw_sha256"],
        "semantic_sha256": prepared["prepared"]["spec_semantic_sha256"],
    } and completion["plan"] == {
        "path": str(prepared["prepared"]["plan_path"]),
        "raw_sha256": prepared["prepared"]["plan_raw_sha256"],
        "semantic_sha256": prepared["prepared"]["plan_semantic_sha256"],
    }, "capacity completion original raw/semantic spec/plan pins differ")
    require(completion["capacity_process_templates_sha256"] ==
            prepared["plan"]["capacity_process_templates_sha256"],
            "capacity completion schedule differs from original PlanV3")
    ledger_value = _exact(completion["ledger"], {"path", "raw_sha256", "terminal_head"},
                          "capacity sealed ledger")
    ledger = {
        "path": _path_text(Path(ledger_value["path"]), "capacity ledger path"),
        "raw_sha256": _digest(ledger_value["raw_sha256"], "capacity ledger raw SHA-256"),
        "terminal_head": _digest(ledger_value["terminal_head"], "capacity ledger terminal head"),
    }
    require(ledger["raw_sha256"] == verification["ledger_raw_sha256"] and
            ledger["terminal_head"] == verification["terminal_head"],
            "capacity registration ledger pins differ from the full replay result")
    details = {
        "capacity_completion": {"path": str(completion_path), "sha256": completion_sha},
        "capacity_ledger": ledger,
        "capacity_schedule_sha256": completion["capacity_process_templates_sha256"],
        "entry_count": len(completion["entries"]), "entries": completion["entries"],
        "qualification_eligible": False, "controller_chronology_proven": False,
    }
    return details, completion


def _phase_directory(prepared: dict[str, Any]) -> Path:
    return (prepared["output_root"] / prepared["campaign_id"] / "confirmation" /
            prepared["host_id"])


def _require_no_legacy_confirmation(prepared: dict[str, Any]) -> None:
    phase_dir = _phase_directory(prepared)
    require(not phase_dir.exists() and not phase_dir.is_symlink(),
            "an existing original confirmation host directory blocks chronology registration")
    legacy_journal = phase_dir / "controller-ledger.jsonl"
    require(not legacy_journal.exists() and not legacy_journal.is_symlink(),
            "an existing original confirmation ledger blocks chronology registration")


@_serialize_locked_api
def run_capacity_stage_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object, source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: object, output_root: Path,
) -> dict[str, Any]:
    """Invoke the captured stage while the same private campaign/host flock is held."""
    prepared = _prepare_inputs(plan_pin, spec_pin, source_root, input_root, host_id,
                               observed_host_pin, output_root)
    lock = _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    state = _read_journal(lock, prepared)
    require(state["record_count"] == 0 and state["pending"] is None,
            "capacity stage invocation must precede every chronology registration/dispatch")
    _require_no_legacy_confirmation(prepared)
    try:
        result = prepared["stage"].run_capacity_stage(
            prepared["plan_pin"], prepared["spec_pin"], prepared["source_root"],
            prepared["input_root"], prepared["host_id"],
            {"path": str(prepared["prepared"]["host_context_path"]),
             "sha256": prepared["prepared"]["host_context_raw_sha256"]},
            prepared["output_root"],
        )
    except Exception as error:
        raise ChronologyError(f"captured capacity stage failed under the campaign/host lock: {error}") from error
    result = _exact(result, {
        "completion", "ledger", "complete", "qualification_eligible",
        "entry_count", "controller_chronology_proven",
    }, "captured capacity stage result")
    require(result["complete"] is True and result["qualification_eligible"] is False and
            result["controller_chronology_proven"] is False and
            result["entry_count"] == 15 and type(result["entry_count"]) is int,
            "captured capacity stage did not return its exact ineligible 15-entry completion")
    details, completion = _capacity_completion(
        prepared, prepared["output_root"], result.get("completion"),
    )
    stage_completion_pin = _exact(result["completion"], {"path", "sha256"},
                                  "captured capacity stage completion pin")
    stage_ledger_pin = _exact(result["ledger"], {"path", "raw_sha256", "terminal_head"},
                              "captured capacity stage sealed ledger pin")
    require(stage_completion_pin == details["capacity_completion"] and
            stage_ledger_pin == completion["ledger"],
            "captured capacity stage result disagrees with its full completion replay")
    _append_event(lock, prepared, "capacity_stage_completed", details)
    return {
        **result, "capacity_stage_verified": True,
        "capacity_schedule_sha256": details["capacity_schedule_sha256"],
        "entry_count": 15, "qualification_eligible": False,
        "controller_chronology_proven": False,
    }


@_serialize_locked_api
def register_capacity_completion_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object, source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: object, output_root: Path,
    completion_pin: object, *, capacity_output_root: Path | None = None,
) -> dict[str, Any]:
    """Fully replay the 15-entry completion and seal its head before any confirmation directory exists."""
    prepared = _prepare_inputs(plan_pin, spec_pin, source_root, input_root, host_id,
                               observed_host_pin, output_root)
    lock = _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    state = _read_journal(lock, prepared)
    require(state["stage_completion"] is not None,
            "capacity completion must be produced by run_capacity_stage_locked under this same lock")
    require(not state["authorized"] and state["pending"] is None,
            "capacity registration is too late because a confirmation dispatch was already authorized")
    _require_no_legacy_confirmation(prepared)
    evidence_root = Path(capacity_output_root) if capacity_output_root is not None else prepared["output_root"]
    details, completion = _capacity_completion(prepared, evidence_root, completion_pin)
    require(_registration_fields(details) ==
            _registration_fields(state["stage_completion"]),
            "capacity registration differs from the locked stage completion")
    if state["registration"] is not None:
        require(details == _registration_fields(state["registration"]),
                "conflicting capacity completion registration already exists")
        return {
            "registered": True, "registration_head": state["registration_head"],
            "capacity_ledger_raw_sha256": details["capacity_ledger"]["raw_sha256"],
            "capacity_ledger_terminal_head": details["capacity_ledger"]["terminal_head"],
            "entry_count": 15, "qualification_eligible": False,
            "controller_chronology_proven": False,
            "api_transaction_order_proven": True,
        }
    _require_no_legacy_confirmation(prepared)
    details["capacity_stage_event_head"] = state["stage_head"]
    record = _append_event(lock, prepared, "capacity_registered", details)
    return {
        "registered": True, "registration_head": record["record_sha256"],
        "capacity_ledger_raw_sha256": details["capacity_ledger"]["raw_sha256"],
        "capacity_ledger_terminal_head": details["capacity_ledger"]["terminal_head"],
        "entry_count": 15, "qualification_eligible": False,
        "controller_chronology_proven": False,
        "api_transaction_order_proven": True,
    }


def _inventory_runner_pin(prepared: dict[str, Any], runner_path_arg: Path) -> dict[str, str]:
    source_root = prepared["source_root"]
    expected_path = source_root / PAIR_RUNNER_SOURCE_PATH
    runner_path = Path(runner_path_arg)
    _path_text(runner_path, "fixed pair-runner path")
    require(runner_path.is_absolute() and runner_path == expected_path,
            "fixed confirmation must execute the original SourceV5 pair-runner path")
    raw, raw_sha, record = _source_file(
        source_root, prepared["source"], PAIR_RUNNER_SOURCE_PATH, "fixed pair runner",
        maximum=MAX_SCRIPT_BYTES,
    )
    require(record["mode"] == "100755" and os.access(runner_path, os.X_OK) and
            raw_sha == prepared["spec"]["runner_sha256"],
            "pair-runner executable differs from its original SourceV5 inventory/spec pin")
    return {"path": str(runner_path), "sha256": raw_sha}


def _pinned_binary(prepared: dict[str, Any], allocator: object, label: str) -> tuple[Path, str]:
    name = _token(allocator, f"{label} allocator")
    artifacts = prepared["source"].get("artifacts")
    require(type(artifacts) is dict and name in artifacts,
            f"SourceV5 has no {label} application artifact for {name}")
    artifact = _exact(artifacts[name], {"path", "sha256"}, f"{label} SourceV5 artifact")
    relative = _relative(artifact["path"], f"{label} SourceV5 binary path")
    path = _safe_child(prepared["source_root"], relative.as_posix(), f"{label} SourceV5 binary")
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 != 0,
            f"{label} SourceV5 binary is not executable")
    raw, _info = _read_stable(path, f"{label} SourceV5 binary", 1024 * 1024 * 1024)
    raw_sha = sha256_bytes(raw)
    expected_sha = _digest(artifact["sha256"], f"{label} SourceV5 binary SHA-256")
    require(raw_sha == expected_sha, f"{label} binary changed after SourceV5 capture")
    return path, expected_sha


def _oracle_pin(controller: types.ModuleType, job: dict[str, Any], allocator: str,
                artifacts_root: Path | None) -> tuple[Path, str] | None:
    if job["mode"] != "open_loop":
        return None
    require(artifacts_root is not None,
            "original fixed open-loop dispatch requires its frozen campaign artifact root")
    oracle_map = controller.oracle_map_for_job(job)
    oracle = oracle_map.get(allocator)
    require(type(oracle) is dict, f"original plan has no {allocator} oracle for {job['run_id']}")
    relative = _relative(oracle.get("relative_path"), "fixed confirmation oracle path")
    path = _safe_child(artifacts_root, relative.as_posix(), "fixed confirmation oracle")
    raw, _info = _read_stable(path, "fixed confirmation oracle", 16 * 1024 * 1024)
    expected = _digest(oracle.get("sha256"), "fixed confirmation oracle SHA-256")
    require(sha256_bytes(raw) == expected, "fixed confirmation oracle differs from its frozen plan pin")
    return path, expected


def _job_for_authorization(prepared: dict[str, Any], exact_job: object) -> tuple[int, dict[str, Any], list[dict[str, Any]]]:
    jobs = prepared["plan"]["jobs"]["confirmation"]
    host_jobs = [(index, job) for index, job in enumerate(
        item for item in jobs if item["host_id"] == prepared["host_id"]
    )]
    matches = [(index, job) for index, job in host_jobs
               if canonical_bytes(job) == canonical_bytes(exact_job)]
    if not matches:
        pressure_jobs = prepared["plan"].get("jobs", {}).get("pressure", [])
        is_pressure = any(
            type(item) is dict and item.get("host_id") == prepared["host_id"] and
            canonical_bytes(item) == canonical_bytes(exact_job)
            for item in pressure_jobs
        )
        require(not is_pressure,
                "pressure dispatch is explicitly unsupported by the fixed confirmation journal")
    require(len(matches) == 1,
            "dispatch must name exactly one original PlanV3 fixed-confirmation job")
    index, job = matches[0]
    require(job.get("phase") == "confirmation" and
            job.get("comparison_family") == "fixed_policy" and
            job.get("host_id") == prepared["host_id"],
            "pressure or foreign jobs are not enabled by the fixed confirmation journal")
    controller = prepared["controller"]
    descriptors = controller.process_descriptors(job)
    require(type(descriptors) is list and len(descriptors) == 2,
            "fixed pair runner must preserve the two original plan members")
    bindings = prepared["plan"]["runtime_process_bindings"].get(job["run_id"])
    require(type(bindings) is list and len(bindings) == 2 and
            controller.build_runtime_process_bindings(job, prepared["spec"], prepared["source"]) == bindings,
            "fixed confirmation runtime recipes differ from the original PlanV3")
    for descriptor, binding in zip(descriptors, bindings, strict=True):
        require(all(binding.get(key) == value for key, value in descriptor.items()),
                "fixed runner member differs from its original process descriptor")
    return index, job, bindings


def _expected_shebang_interpreter(runner_raw: bytes, environment: dict[str, str]) -> dict[str, str]:
    first_line = runner_raw.splitlines()[0] if runner_raw else b""
    require(first_line == b"#!/usr/bin/env bash",
            "fixed pair runner interpreter line differs from the pinned shell contract")
    path_text = environment.get("PATH")
    require(type(path_text) is str and path_text,
            "fixed runner environment must pin a nonempty PATH")
    found = shutil.which("bash", path=path_text)
    require(found is not None, "fixed runner's pinned PATH cannot resolve bash")
    path = Path(found).resolve(strict=True)
    raw, _info = _read_stable(path, "fixed pair-runner interpreter", 256 * 1024 * 1024)
    return {"path": str(path), "sha256": sha256_bytes(raw)}


def _environment_snapshot(environment: dict[str, str]) -> tuple[dict[str, str], str]:
    require(type(environment) is dict and environment,
            "fixed pair-runner environment must be a nonempty mapping")
    for key, value in environment.items():
        require(type(key) is str and type(value) is str and key and "=" not in key and
                "\x00" not in key and "\x00" not in value,
                "fixed pair-runner environment contains an invalid key/value")
        require(key not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"} and
                not key.startswith("BASH_FUNC_"),
                "fixed pair-runner environment contains an unpinned Bash startup or function import control")
        try:
            key.encode("ascii", "strict")
            value.encode("utf-8", "strict")
        except UnicodeError as error:
            raise ChronologyError("fixed pair-runner environment key/value encoding is unsupported") from error
    raw = canonical_bytes(environment)
    require(len(raw) <= MAX_ENVIRONMENT_BYTES,
            "fixed pair-runner environment exceeds its finite byte bound")
    return environment, sha256_bytes(raw)


def _owner_marker(prepared: dict[str, Any], registration_head: str) -> dict[str, Any]:
    body = {
        "schema": "allocatbelt.application-campaign-chronology-owner.v1",
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "original_pins_sha256": prepared["original_pins_sha256"],
        "registration_head": registration_head,
        "qualification_eligible": False,
    }
    return {"path": str(_phase_directory(prepared) / ".chronology-owner.json"),
            "sha256": sha256_bytes(canonical_bytes(body))}


def _launch_spec(
    prepared: dict[str, Any], job_index: int, job: dict[str, Any],
    bindings: list[dict[str, Any]], runner_pin: dict[str, str],
    campaign_artifacts_root_arg: Path | None, environment: dict[str, str],
    registration_head: str,
) -> dict[str, Any]:
    environment, environment_sha = _environment_snapshot(environment)
    runner_path = Path(runner_pin["path"])
    require(runner_path == prepared["source_root"] / PAIR_RUNNER_SOURCE_PATH,
            "fixed pair runner path differs from the regular SourceV5 path")
    runner_raw, runner_sha, runner_record = _source_file(
        prepared["source_root"], prepared["source"], PAIR_RUNNER_SOURCE_PATH,
        "fixed pair runner", maximum=MAX_SCRIPT_BYTES,
    )
    require(runner_record["mode"] == "100755" and os.access(runner_path, os.X_OK) and
            runner_sha == runner_pin["sha256"] == prepared["spec"]["runner_sha256"],
            "fixed pair runner pin differs from the original spec/source files")
    interpreter = _expected_shebang_interpreter(runner_raw, environment)
    artifacts_root = None
    if job["mode"] == "open_loop":
        require(campaign_artifacts_root_arg is not None,
                "original fixed open-loop dispatch requires its campaign artifact root")
        artifacts_root = _safe_root(Path(campaign_artifacts_root_arg), "campaign artifact root")
        require(not _within(prepared["source_root"], artifacts_root),
                "campaign oracle artifacts must remain outside SourceV5")
    else:
        require(campaign_artifacts_root_arg is None,
                "capacity-mode fixed dispatch does not consume a campaign artifact root")

    binary, _binary_sha = _pinned_binary(prepared, job["allocator"], "candidate")
    candidate_oracle = _oracle_pin(prepared["controller"], job, job["allocator"], artifacts_root)
    baseline_binary: Path | None = None
    baseline_allocator: str | None = None
    baseline_oracle: tuple[Path, str] | None = None
    if job.get("comparison_kind") == "allocator":
        baseline_allocator = _token(job.get("baseline_allocator"), "fixed baseline allocator")
        baseline_binary, _baseline_sha = _pinned_binary(prepared, baseline_allocator, "baseline")
        if job["mode"] == "open_loop":
            baseline_oracle = _oracle_pin(prepared["controller"], job, baseline_allocator, artifacts_root)

    output_root = prepared["output_root"]
    phase_dir = _phase_directory(prepared)
    control = _token(job.get("control_id", job["family"]), "fixed confirmation control")
    profile = _token(job["profile"], "fixed confirmation profile")
    mode = _token(job["mode"], "fixed confirmation mode")
    allocator = _token(job["allocator"], "fixed confirmation allocator")
    runner_output = phase_dir / "pairs" / control / profile / mode / allocator
    binding_path = runner_output / ".runtime-bindings" / f"{job['run_id']}.json"
    controller = prepared["controller"]
    manifest = controller.runtime_binding_manifest_value(bindings, job, prepared["spec"],
                                                         prepared["source"])
    manifest_raw = canonical_bytes(manifest)
    manifest_sha = sha256_bytes(manifest_raw)
    validator_pin = _exact(prepared["source"]["runtime_readback_validator"],
                           {"path", "sha256"}, "SourceV5 fixed runtime validator pin")
    validator_path = _safe_child(prepared["source_root"], validator_pin["path"],
                                 "SourceV5 fixed runtime validator")
    validator_raw, _validator_info = _read_stable(validator_path, "SourceV5 runtime validator",
                                                  MAX_SOURCE_BYTES)
    validator_sha = _digest(validator_pin["sha256"], "SourceV5 runtime validator SHA-256")
    require(sha256_bytes(validator_raw) == validator_sha,
            "SourceV5 runtime validator differs from its pin")
    control_baseline = _uint(
        prepared["source"]["resource_domain_calibration"]["record"]["fixed_global_control_baseline"],
        "fixed global control baseline", positive=True,
    )
    argv = controller.build_pair_runner_argv(
        runner_path, binary, job, prepared["prepared"]["host"]["controls"]["cpu_set"], runner_output,
        prepared["spec"]["deadlines"], job.get("arrivals") or 5000,
        candidate_oracle, baseline_binary, baseline_allocator, baseline_oracle,
        binding_path, manifest_sha, validator_path, validator_sha, control_baseline,
    )
    require(type(argv) is list and len(argv) <= 64 and all(
        type(item) is str and "\x00" not in item and len(item.encode("utf-8")) <= MAX_PATH_BYTES
        for item in argv
    ), "fixed pair runner argv exceeds its finite string/argument bounds")
    require(argv[0] == str(runner_path) and Path(argv[0]).is_absolute(),
            "fixed runner argv[0] differs from the pinned executable script")
    deadline = _uint(prepared["spec"]["deadlines"]["outer_seconds"],
                     "original fixed job outer deadline", positive=True,
                     maximum=MAX_TIMEOUT_SECONDS)
    phase_jobs = [item for item in prepared["plan"]["jobs"]["confirmation"]
                  if item["host_id"] == prepared["host_id"]]
    require(0 <= job_index < len(phase_jobs) and phase_jobs[job_index] == job,
            "fixed dispatch index differs from the original host job order")
    run_id = _token(job["run_id"], "fixed confirmation run ID")
    stdout_path = phase_dir / f"{job_index:06d}-{run_id}.stdout.log"
    stderr_path = phase_dir / f"{job_index:06d}-{run_id}.stderr.log"
    owner = _owner_marker(prepared, registration_head)
    return {
        "job_index": job_index, "job": job,
        "job_sha256": sha256_bytes(canonical_bytes(job)),
        "member_role": "campaign_pair_runner",
        "pair_members": bindings,
        "pair_members_sha256": sha256_bytes(canonical_bytes(bindings)),
        "runner": runner_pin,
        "argv": argv, "cwd": str(prepared["source_root"]),
        "environment": environment, "environment_sha256": environment_sha,
        "runner_output": str(runner_output),
        "runtime_bindings": {"path": str(binding_path), "sha256": manifest_sha,
                             "size": len(manifest_raw)},
        "runtime_manifest_raw": manifest_raw,
        "runtime_validator": {"path": str(validator_path), "sha256": validator_sha},
        "fixed_global_control_baseline": control_baseline,
        "outer_deadline_seconds": deadline,
        "campaign_artifacts_root": str(artifacts_root) if artifacts_root is not None else None,
        "shebang_interpreter": interpreter,
        "stdout_path": str(stdout_path), "stderr_path": str(stderr_path),
        "confirmation_owner_marker": owner,
        "phase_directory": str(phase_dir),
        "source_manifest_raw_sha256": prepared["prepared"]["source_raw_sha256"],
        "spec_raw_sha256": prepared["prepared"]["spec_raw_sha256"],
        "plan_raw_sha256": prepared["prepared"]["plan_raw_sha256"],
        "registration_head": registration_head,
        "qualification_eligible": False,
    }


def _owner_body(prepared: dict[str, Any], registration_head: str) -> dict[str, Any]:
    return {
        "schema": "allocatbelt.application-campaign-chronology-owner.v1",
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "original_pins_sha256": prepared["original_pins_sha256"],
        "registration_head": registration_head,
        "qualification_eligible": False,
    }


def _ensure_confirmation_directory(
    prepared: dict[str, Any], owner_pin: dict[str, str], registration_head: str,
) -> None:
    phase_dir = _phase_directory(prepared)
    campaign_dir = phase_dir.parent.parent
    _ensure_private_directory(campaign_dir)
    confirmation_parent = phase_dir.parent
    _ensure_private_directory(confirmation_parent)
    if phase_dir.exists() or phase_dir.is_symlink():
        info = phase_dir.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                info.st_uid == os.getuid() and phase_dir.resolve(strict=True) == phase_dir,
                "confirmation host directory is not the private directory owned by this transaction")
    else:
        phase_dir.mkdir(mode=0o700)
        info = phase_dir.lstat()
        require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
                "cannot establish private confirmation host directory")
        _fsync_directory(confirmation_parent)
    marker_path = Path(owner_pin["path"])
    require(marker_path == phase_dir / ".chronology-owner.json",
            "confirmation ownership marker escaped its host directory")
    expected_raw = canonical_bytes(_owner_body(prepared, registration_head))
    expected_sha = sha256_bytes(expected_raw)
    require(owner_pin["sha256"] == expected_sha, "confirmation ownership marker digest changed")
    if marker_path.exists() or marker_path.is_symlink():
        raw, info = _read_stable(marker_path, "confirmation chronology owner marker", 64 * 1024)
        require(stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == os.getuid() and
                raw == expected_raw and sha256_bytes(raw) == expected_sha,
                "confirmation directory is owned by a different chronology registration")
    else:
        _write_exclusive(marker_path, expected_raw, 0o400)


def _validate_dispatch_authorization(
    details_value: object, prepared: dict[str, Any], registration: dict[str, Any],
    registration_head: str,
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS["dispatch_authorized"],
                     "authorized fixed confirmation dispatch")
    job_index = _uint(details["job_index"], "fixed confirmation job index")
    index, job, bindings = _job_for_authorization(prepared, details["job"])
    require(index == job_index and details["job_sha256"] ==
            sha256_bytes(canonical_bytes(job)),
            "dispatch job bytes/index differ from the exact original PlanV3 job")
    runner_pin = _exact(details["runner"], {"path", "sha256"},
                        "fixed confirmation runner pin")
    environment, environment_sha = _environment_snapshot(details["environment"])
    artifacts_root_value = details["campaign_artifacts_root"]
    artifacts_root = None if artifacts_root_value is None else Path(artifacts_root_value)
    spec = _launch_spec(
        prepared, index, job, bindings, runner_pin, artifacts_root, environment,
        registration_head,
    )
    expected_auth_material = {
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "run_id": job["run_id"], "job_sha256": spec["job_sha256"],
        "capacity_registration_head": registration_head,
    }
    expected_auth_id = "dispatch-" + sha256_bytes(canonical_bytes(expected_auth_material))[:48]
    outer_deadline = _uint(details["outer_deadline_seconds"],
                           "fixed confirmation outer deadline", positive=True,
                           maximum=MAX_TIMEOUT_SECONDS)
    effective_timeout = _uint(details["effective_timeout_seconds"],
                              "effective fixed dispatch timeout", positive=True,
                              maximum=MAX_TIMEOUT_SECONDS)
    require(effective_timeout <= outer_deadline == spec["outer_deadline_seconds"],
            "dispatch timeout exceeds its original fixed job deadline")
    require(details["authorization_id"] == expected_auth_id and
            details["member_role"] == "campaign_pair_runner" and
            details["pair_members"] == bindings and
            details["pair_members_sha256"] == spec["pair_members_sha256"] and
            details["capacity_registration_head"] == registration_head and
            details["capacity_completion_raw_sha256"] == registration["capacity_completion"]["sha256"] and
            details["capacity_ledger_raw_sha256"] == registration["capacity_ledger"]["raw_sha256"] and
            details["capacity_ledger_terminal_head"] == registration["capacity_ledger"]["terminal_head"] and
            details["capacity_schedule_sha256"] == registration["capacity_schedule_sha256"] and
            details["argv"] == spec["argv"] and details["cwd"] == spec["cwd"] and
            details["environment"] == environment and details["environment_sha256"] == environment_sha and
            details["runner_output"] == spec["runner_output"] and
            details["runtime_bindings"] == spec["runtime_bindings"] and
            details["runtime_validator"] == spec["runtime_validator"] and
            details["fixed_global_control_baseline"] == spec["fixed_global_control_baseline"] and
            details["outer_deadline_seconds"] == spec["outer_deadline_seconds"] and
            details["stdout_path"] == spec["stdout_path"] and
            details["stderr_path"] == spec["stderr_path"] and
            details["campaign_artifacts_root"] == spec["campaign_artifacts_root"] and
            details["shebang_interpreter"] == spec["shebang_interpreter"] and
            details["confirmation_owner_marker"] == spec["confirmation_owner_marker"] and
            details["qualification_eligible"] is False,
            "dispatch authorization differs from the original fixed job/capacity/source/runtime roles")
    return spec


@_serialize_locked_api
def authorize_dispatch_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object, source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: object, output_root: Path,
    completion_pin: object, exact_job: object, pair_runner_path: Path,
    *, campaign_artifacts_root: Path | None = None,
    capacity_output_root: Path | None = None,
    effective_timeout_seconds: int | None = None,
) -> DispatchAuthorization:
    """Record/fsync one unique original fixed-pair authorization before Popen."""
    _require_owned_child_wait_semantics()
    prepared = _prepare_inputs(plan_pin, spec_pin, source_root, input_root, host_id,
                               observed_host_pin, output_root)
    lock = _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    state = _read_journal(lock, prepared)
    registration = state["registration"]
    require(registration is not None and state["pending"] is None,
            "fixed confirmation authorization requires one sealed capacity registration")
    require(state.get("cleanup_blocked") is False,
            "prior pair-runner cleanup is unclean or unverified; later dispatch is blocked")
    capacity_output = _safe_root(Path(capacity_output_root), "capacity evidence output root") \
        if capacity_output_root is not None else prepared["output_root"]
    capacity_details, _completion = _capacity_completion(prepared, capacity_output, completion_pin)
    require(_registration_fields(capacity_details) == _registration_fields(registration),
            "capacity completion changed after its locked registration")
    job_index, job, bindings = _job_for_authorization(prepared, exact_job)
    runner_pin = _inventory_runner_pin(prepared, pair_runner_path)
    environment, environment_sha = _environment_snapshot(dict(os.environ))
    _require_owned_child_wait_semantics()
    artifacts_root = Path(campaign_artifacts_root) if campaign_artifacts_root is not None else None
    dispatch = _launch_spec(
        prepared, job_index, job, bindings, runner_pin, artifacts_root, environment,
        state["registration_head"],
    )
    effective_timeout = dispatch["outer_deadline_seconds"] if effective_timeout_seconds is None else _uint(
        effective_timeout_seconds, "effective fixed dispatch timeout", positive=True,
        maximum=MAX_TIMEOUT_SECONDS,
    )
    require(effective_timeout <= dispatch["outer_deadline_seconds"],
            "effective dispatch timeout cannot exceed the original fixed job deadline")
    phase_dir = _phase_directory(prepared)
    if phase_dir.exists() or phase_dir.is_symlink():
        _verify_owner_marker(prepared, dispatch["confirmation_owner_marker"],
                             state["registration_head"], create=False)
    else:
        _require_no_legacy_confirmation(prepared)
    require(not Path(dispatch["runtime_bindings"]["path"]).exists() and
            not Path(dispatch["runtime_bindings"]["path"]).is_symlink() and
            not Path(dispatch["stdout_path"]).exists() and not Path(dispatch["stdout_path"]).is_symlink() and
            not Path(dispatch["stderr_path"]).exists() and not Path(dispatch["stderr_path"]).is_symlink(),
            "original confirmation job output already exists and cannot be retried")
    auth_material = {
        "campaign_id": prepared["campaign_id"], "host_id": host_id,
        "run_id": job["run_id"], "job_sha256": dispatch["job_sha256"],
        "capacity_registration_head": state["registration_head"],
    }
    authorization_id = "dispatch-" + sha256_bytes(canonical_bytes(auth_material))[:48]
    details = {
        "authorization_id": authorization_id,
        "job_index": job_index, "job": job, "job_sha256": dispatch["job_sha256"],
        "member_role": "campaign_pair_runner",
        "pair_members": bindings, "pair_members_sha256": dispatch["pair_members_sha256"],
        "capacity_registration_head": state["registration_head"],
        "capacity_completion_raw_sha256": registration["capacity_completion"]["sha256"],
        "capacity_ledger_raw_sha256": registration["capacity_ledger"]["raw_sha256"],
        "capacity_ledger_terminal_head": registration["capacity_ledger"]["terminal_head"],
        "capacity_schedule_sha256": registration["capacity_schedule_sha256"],
        "runner": runner_pin, "argv": dispatch["argv"], "cwd": dispatch["cwd"],
        "environment": environment, "environment_sha256": environment_sha,
        "runner_output": dispatch["runner_output"],
        "campaign_artifacts_root": dispatch["campaign_artifacts_root"],
        "shebang_interpreter": dispatch["shebang_interpreter"],
        "runtime_bindings": dispatch["runtime_bindings"],
        "runtime_validator": dispatch["runtime_validator"],
        "fixed_global_control_baseline": dispatch["fixed_global_control_baseline"],
        "outer_deadline_seconds": dispatch["outer_deadline_seconds"],
        "effective_timeout_seconds": effective_timeout,
        "stdout_path": dispatch["stdout_path"], "stderr_path": dispatch["stderr_path"],
        "confirmation_owner_marker": dispatch["confirmation_owner_marker"],
        "qualification_eligible": False,
    }
    _validate_dispatch_authorization(details, prepared, registration,
                                     state["registration_head"])
    record = _append_event(lock, prepared, "dispatch_authorized", details)
    return DispatchAuthorization(
        lock, prepared, prepared["plan_pin"], prepared["spec_pin"],
        prepared["source_root"], prepared["input_root"],
        {"path": str(prepared["prepared"]["host_context_path"]),
         "sha256": prepared["prepared"]["host_context_raw_sha256"]},
        capacity_output, capacity_details["capacity_completion"],
        details, record["monotonic_ns"],
    )


def _validate_bound_details(
    details_value: object, authorization: dict[str, Any], prepared: dict[str, Any],
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS["dispatch_bound"],
                     "fixed pair-runner process binding")
    _verify_owner_marker(prepared, authorization["confirmation_owner_marker"],
                         authorization["capacity_registration_head"], create=False)
    pid = _uint(details["pid"], "actual pair-runner PID", positive=True,
                maximum=(1 << 31) - 1)
    start_ticks = _uint(details["start_ticks"], "actual pair-runner start ticks", positive=True)
    expected_interpreter = authorization["shebang_interpreter"]
    environment, environment_sha = _environment_snapshot(authorization["environment"])
    expected_members = [item["report_nonce"] for item in authorization["pair_members"]]
    runtime_manifest = prepared["controller"].runtime_binding_manifest_value(
        authorization["pair_members"], authorization["job"], prepared["spec"],
        prepared["source"],
    )
    runtime_raw = canonical_bytes(runtime_manifest)
    _verify_runtime_binding_file(authorization["runtime_bindings"], runtime_raw,
                                 prepared["output_root"])
    require(details["authorization_id"] == authorization["authorization_id"] and
            details["job_run_id"] == authorization["job"]["run_id"] and
            details["member_role"] == "campaign_pair_runner" and
            details["runner_path"] == authorization["runner"]["path"] and
            details["runner_sha256"] == authorization["runner"]["sha256"] and
            details["process_executable_path"] == expected_interpreter["path"] and
            details["process_executable_sha256"] == expected_interpreter["sha256"] and
            details["cwd"] == authorization["cwd"] and
            details["cpu_affinity"] == prepared["prepared"]["current_host"]["cpu_affinity"] and
            details["network_namespace_inode"] == prepared["prepared"]["current_host"]["network_namespace_inode"] and
            details["environment"] == environment and details["environment_sha256"] == environment_sha and
            details["actual_environment_sha256"] == environment_sha and
            details["process_report_nonce"] is None and
            details["member_report_nonces"] == expected_members and
            details["caller_role"] == "campaign_pair_runner" and
            details["pair_members_sha256"] == authorization["pair_members_sha256"] and
            details["capacity_registration_head"] == authorization["capacity_registration_head"] and
            details["qualification_eligible"] is False,
            "actual pair-runner PID/start/executable/cwd/affinity/environment binding differs from dispatch")
    return details


def _validate_exit_details(
    details_value: object, bound: dict[str, Any], authorization: dict[str, Any],
    prepared: dict[str, Any],
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS["dispatch_exited"],
                     "fixed pair-runner exit record")
    pid = _uint(details["pid"], "pair-runner exit PID", positive=True,
                maximum=(1 << 31) - 1)
    return_code = details["return_code"]
    require(type(return_code) is int and pid == bound["pid"] and
            details["authorization_id"] == authorization["authorization_id"] and
            details["job_run_id"] == authorization["job"]["run_id"] and
            details["member_role"] == "campaign_pair_runner" and
            details["process_reaped"] is True and
            details["process_reap_status"] == "owned_reaped" and
            details["process_group_cleanup_status"] == "clean" and
            details["cleanup_error_sha256"] is None and
            details["capacity_registration_head"] == authorization["capacity_registration_head"] and
            details["qualification_eligible"] is False,
            "pair-runner exit differs from the actual bound process")
    elapsed_ns = _uint(details["elapsed_ns"], "pair-runner elapsed nanoseconds")
    require(elapsed_ns <= authorization["effective_timeout_seconds"] * 1_000_000_000,
            "pair-runner exit exceeded its authorized finite deadline")
    if return_code >= 0:
        require(details["status"] == "completed" and details["signal"] is None,
                "normally exited pair runner has contradictory signal metadata")
    else:
        require(details["status"] == "signaled" and details["signal"] == -return_code,
                "signaled pair runner has contradictory wait status")
    phase_dir = _phase_directory(prepared)
    expected = {
        "stdout": Path(authorization["stdout_path"]),
        "stderr": Path(authorization["stderr_path"]),
    }
    for name in ("stdout", "stderr"):
        pin = _exact(details[name], {"path", "sha256"}, f"pair-runner {name} pin")
        path = Path(pin["path"])
        require(path == expected[name] and _within(phase_dir, path),
                f"pair-runner {name} path escaped its host output")
        raw, info = _read_stable(path, f"pair-runner {name}", MAX_OUTPUT_BYTES)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and
                sha256_bytes(raw) == _digest(pin["sha256"], f"pair-runner {name} SHA-256") and
                details[f"{name}_sha256"] == pin["sha256"] and
                len(raw) == details[f"{name}_size"] == _uint(
                    details[f"{name}_size"], f"pair-runner {name} size", maximum=MAX_OUTPUT_BYTES),
                f"pair-runner {name} bytes differ from the durable exit capture")
    return details


@_serialize_locked_api
def verify_campaign_chronology_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object, source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: object, output_root: Path,
    completion_pin: object, *, capacity_output_root: Path | None = None,
) -> dict[str, Any]:
    """Replay the private transaction journal and reverify the registered capacity completion."""
    prepared = _prepare_inputs(plan_pin, spec_pin, source_root, input_root, host_id,
                               observed_host_pin, output_root)
    _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    state = _read_journal(lock, prepared)
    registration = state["registration"]
    require(registration is not None, "chronology journal has no sealed capacity registration")
    evidence_root = Path(capacity_output_root) if capacity_output_root is not None else prepared["output_root"]
    details, _completion = _capacity_completion(prepared, evidence_root, completion_pin)
    require(_registration_fields(details) == _registration_fields(registration),
            "chronology registration differs from a fresh full 15-entry capacity replay")
    pending = state["pending"]
    return {
        "schema": CHRONOLOGY_SCHEMA,
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "journal_path": str(_journal_path(lock)), "journal_head": state["head"],
        "journal_record_count": state["record_count"],
        "registration_head": state["registration_head"],
        "capacity_completion_raw_sha256": details["capacity_completion"]["sha256"],
        "capacity_ledger_raw_sha256": details["capacity_ledger"]["raw_sha256"],
        "capacity_ledger_terminal_head": details["capacity_ledger"]["terminal_head"],
        "capacity_schedule_sha256": details["capacity_schedule_sha256"],
        "entry_count": 15,
        "dispatch_event_count": state["dispatch_event_count"],
        "pending_authorization": pending is not None,
        "cleanup_blocked": state["cleanup_blocked"],
        "terminal_process_cleanup": state["process_cleanup"],
        "qualification_eligible": False,
        "execution_ready": False,
        "controller_chronology_proven": False,
        "api_transaction_order_proven": True,
    }


def _cli_pin(path: Path, raw_sha256: str) -> dict[str, str]:
    return {"path": str(path), "sha256": raw_sha256}


def _parser() -> Any:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "register", "launch", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--plan-sha256", required=True)
        command.add_argument("--spec", type=Path, required=True)
        command.add_argument("--spec-sha256", required=True)
        command.add_argument("--source-root", type=Path, required=True)
        command.add_argument("--input-root", type=Path, required=True)
        command.add_argument("--host-id", required=True)
        command.add_argument("--observed-host", type=Path, required=True)
        command.add_argument("--observed-host-sha256", required=True)
        command.add_argument("--output-root", type=Path, required=True)
        if name != "run":
            command.add_argument("--capacity-output-root", type=Path)
        command.add_argument("--lock-timeout-seconds", type=float, default=30.0)
        if name != "run":
            command.add_argument("--completion", type=Path, required=True)
            command.add_argument("--completion-sha256", required=True)
        if name == "launch":
            command.add_argument("--job-run-id", required=True)
            command.add_argument("--pair-runner", type=Path, required=True)
            command.add_argument("--campaign-artifacts-root", type=Path)
            command.add_argument("--effective-timeout-seconds", type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan_pin = _cli_pin(args.plan, args.plan_sha256)
        spec_pin = _cli_pin(args.spec, args.spec_sha256)
        observed_pin = _cli_pin(args.observed_host, args.observed_host_sha256)
        spec, _spec_path, _spec_raw, _spec_sha = _read_pin(
            spec_pin, "campaign spec", MAX_SPEC_BYTES,
        )
        campaign_id = _token(spec.get("campaign_id"), "campaign ID")
        source_root = _safe_root(args.source_root, "SourceV5 root")
        input_root = _safe_root(args.input_root, "campaign input root")
        output_root = _safe_root(args.output_root, "campaign chronology output root")
        require(not _within(source_root, input_root) and
                not _within(source_root, output_root),
                "campaign inputs and transaction outputs must remain outside SourceV5")
        completion_pin = None if args.command == "run" else _cli_pin(
            args.completion, args.completion_sha256,
        )
        with campaign_host_lock(
            output_root, campaign_id, args.host_id,
            timeout_seconds=args.lock_timeout_seconds,
        ) as lock:
            if args.command == "run":
                result = run_capacity_stage_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root,
                )
            elif args.command == "register":
                assert completion_pin is not None
                result = register_capacity_completion_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root, completion_pin,
                    capacity_output_root=args.capacity_output_root,
                )
            elif args.command == "verify":
                assert completion_pin is not None
                result = verify_campaign_chronology_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root, completion_pin,
                    capacity_output_root=args.capacity_output_root,
                )
            else:
                assert completion_pin is not None
                plan, _plan_path, _plan_raw, _plan_sha = _read_pin(
                    plan_pin, "campaign plan", MAX_PLAN_BYTES,
                )
                host_jobs = [job for job in plan.get("jobs", {}).get("confirmation", [])
                             if type(job) is dict and job.get("host_id") == args.host_id]
                matches = [job for job in host_jobs if job.get("run_id") == args.job_run_id]
                if not matches:
                    pressure_jobs = [job for job in plan.get("jobs", {}).get("pressure", [])
                                     if type(job) is dict and job.get("host_id") == args.host_id and
                                     job.get("run_id") == args.job_run_id]
                    require(not pressure_jobs,
                            "pressure dispatch is explicitly unsupported by the fixed confirmation journal")
                require(len(matches) == 1,
                        "CLI dispatch run ID is not unique in the original host confirmation plan")
                authorization = authorize_dispatch_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root, completion_pin,
                    matches[0], args.pair_runner,
                    campaign_artifacts_root=args.campaign_artifacts_root,
                    capacity_output_root=args.capacity_output_root,
                    effective_timeout_seconds=args.effective_timeout_seconds,
                )
                result = launch_authorized_locked(lock, authorization)
            sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except (ChronologyError, OSError, subprocess.SubprocessError, ValueError,
            TypeError, KeyError, UnicodeError, AssertionError) as error:
        print(f"application campaign chronology: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
