#!/usr/bin/env python3
"""Independently audit a frozen continuous-soak run and its streamed artifacts.

The parent recipe is pinned before launch.  This tool checks the live source,
build manifest, candidate and oracle-producer binaries, and external oracle
ring both before and after the run.  It validates the child's receipt and
streams against those parent-owned inputs; receipt fields never create their
own expectations.

The current contract intentionally supports only the allocatbelt/bounded,
fixed-policy mixed workload.  A short functional run can be audited, but its
qualification eligibility is always false.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import secrets
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterator


RECIPE_SCHEMA = "allocatbelt.application-soak-parent-recipe.v1"
RECIPE_SCHEMA_V2 = "allocatbelt.application-soak-parent-recipe.v2"
PREFLIGHT_SCHEMA = "allocatbelt.application-soak-preflight.v2"
POSTFLIGHT_SCHEMA = "allocatbelt.application-soak-postflight.v2"
LAUNCH_SCHEMA = "allocatbelt.application-soak-launch.v1"
LAUNCH_SCHEMA_V2 = "allocatbelt.application-soak-launch.v2"
LAUNCH_SCHEMA_V3 = "allocatbelt.application-soak-launch.v3"
RESULT_SCHEMA = "allocatbelt.application-soak-readback.v1"
RESULT_SCHEMA_V2 = "allocatbelt.application-soak-readback.v2"
SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v4"
SOURCE_SCHEMA_V5 = "allocatbelt.application-source-manifest.v5"
SOURCE_INVENTORY_SCHEMA = "allocatbelt.application-source-inventory.v1"
SOURCE_INVENTORY_RELATIVE_PATH = "scripts/application-source-inventory.py"
SOURCE_INVENTORY_MODULE_SHA256 = "09557087a64e83bc81e4116f8e8f6b59e42a59beb500108e57d66942bd05f950"
POLICY_SCHEMA = "allocatbelt.application-fixed-policy-artifact.v1"
CALIBRATION_SCHEMA = "allocatbelt.resource-domain-calibration.v1"
RUNTIME_SOAK_SCHEMA = "allocatbelt.runtime-soak.v1"
RUNTIME_SOAK_SCHEMA_V2 = "allocatbelt.runtime-soak.v2"
RING_SCHEMA = "allocatbelt-app-oracle-v2"
TERMINAL_SCHEMA = "allocatbelt.runtime-soak-terminals.v1"
SOAK_RECEIPT_CLOCK_PHASES = ("started", "trace_ended", "drain_ended", "shutdown_ended", "postprocess_ended")
SOURCE_V5_APP_SETUP_BUDGET_SECONDS = 120
SOURCE_V5_TRACE_OVERRUN_SECONDS = 5
SOURCE_V5_DRAIN_BUDGET_SECONDS = 5
SOURCE_V5_SHUTDOWN_BUDGET_SECONDS = 60
SOURCE_V5_POSTPROCESS_BUDGET_SECONDS = 60
SOURCE_V5_PRESSURE_EXIT_OBSERVATION_SECONDS = 1
SOURCE_V5_PRESSURE_MAX_DURATION_SECONDS = 12_000
SOURCE_V5_PRESSURE_MAX_SAMPLES = 120_000
SOURCE_V5_PRESSURE_MAX_TOTAL_SECONDS = 14_400
SOURCE_V5_PRESSURE_OWNERSHIP_PROTOCOL = "allocatbelt.pressure-worker-ownership.v1"
SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA = "allocatbelt.application-source5-soak-offline-replay-context.v1"
SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA_V2 = "allocatbelt.application-source5-soak-offline-replay-context.v2"
SOAK_RESOURCE_BUDGET_SCHEMA = "allocatbelt.application-source5-soak-resource-budget.v2"
SOAK_RESOURCE_MONITOR_SCHEMA = "allocatbelt.application-source5-soak-resource-monitor-stream.v1"
SOAK_RESOURCE_MONITOR_ROW_SCHEMA = "allocatbelt.application-source5-soak-resource-monitor-row.v1"
SOAK_RESOURCE_MONITOR_FOOTER_SCHEMA = "allocatbelt.application-source5-soak-resource-monitor-footer.v1"
SOAK_RESOURCE_BUDGET_CEILING_FIELDS = {
    "maximum_output_bytes", "maximum_output_inodes",
    "maximum_application_tmpdir_bytes", "maximum_application_tmpdir_inodes",
    "maximum_pressure_scratch_bytes", "maximum_pressure_scratch_inodes",
    "maximum_probe_output_bytes", "maximum_probe_output_inodes",
    "maximum_probe_tmpdir_bytes", "maximum_probe_tmpdir_inodes",
    "minimum_free_bytes", "minimum_free_inodes",
    "durable_receipt_reserve_bytes", "durable_receipt_reserve_inodes",
    "maximum_monitor_stream_bytes", "maximum_monitor_rows",
    "maximum_monitor_row_bytes",
}
SOAK_RESOURCE_BUDGET_ARTIFACT_FIELDS = {
    "terminal_stream_bytes", "resource_samples_bytes",
    "application_stdout_bytes", "application_stderr_bytes",
    "application_timing_bytes", "soak_receipt_bytes",
    "launch_receipt_bytes", "launch_authorization_bytes",
    "preflight_receipt_bytes",
    "postflight_receipt_bytes", "readback_receipt_bytes",
    "source5_supervisor_bytes", "pressure_events_bytes",
    "pressure_readback_bytes", "pressure_run_receipt_bytes",
    "pressure_launch_bytes",
    "pressure_binding_bytes", "pressure_ready_bytes",
    "pressure_driver_stdout_bytes", "pressure_driver_stderr_bytes",
    "pressure_worker_stderr_bytes", "probe_stdout_bytes",
    "probe_stderr_bytes", "probe_owner_receipt_bytes",
    "probe_inventory_bytes", "probe_failure_bytes",
    "probe_capture_receipt_bytes", "resource_monitor_stream_bytes",
    "owner_return_receipt_bytes", "host_receipt_bytes",
    "failure_receipt_bytes", "component_receipt_bytes",
}
SOAK_RESOURCE_BUDGET_LAYOUT_FIELDS = {
    "output_root", "application_tmpdir", "pressure_scratch",
    "probe_capture_root", "probe_tmpdir", "host_receipt_path",
}
SOAK_RESOURCE_BUDGET_SCHEDULE_FIELDS = {
    "production_seconds", "application_sample_interval_ms",
    "application_sample_tolerance_ns", "application_sample_count",
    "application_wall_timeout_seconds", "pressure_total_deadline_seconds",
    "authorization_effective_timeout_seconds", "probe_timeout_seconds",
    "resource_monitor_interval_ms", "resource_monitor_tolerance_ns",
}

ALLOCATORS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
DOMAINS = ("cpu", "memory", "disk", "network", "tasks", "control")
APP_DOMAINS = DOMAINS[:-1]
OWNERS = ("global", "tenant")
DIRECTIONS = ("disk", "upload", "download")
FAMILIES = ("cpu", "memory", "http", "disk")
PROFILES = ("mixed", "burst", "oversubscribed")

U64_MAX = (1 << 64) - 1
U128_MAX = (1 << 128) - 1
MAX_RECIPE_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_RING_BYTES = 16 * 1024 * 1024
MAX_RING_ROWS = 65_536
MIN_RING_ROWS = 8
# Budget discovery samples show 30,783 mixed terminals in 2s. At the observed
# average row size, linearized 10,800s is about 10.5 GiB. Each frozen recipe
# supplies an explicit per-run budget (currently planned at 16 GiB); this
# larger parser ceiling only provides a hard global bound. These are storage
# estimates, not throughput or performance claims.
MAX_TERMINAL_BYTES = 32 * 1024 * 1024 * 1024
MAX_SAMPLE_BYTES = 96 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
# Environment snapshots are retained in both launch bindings and attestations.
# Keep this ceiling aligned with the existing bounded launch-environment reads.
MAX_ENVIRONMENT_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 8192
MAX_SOAK_RESOURCE_MONITOR_STREAM_BYTES = 1024 * 1024 * 1024
MAX_SOAK_RESOURCE_MONITOR_ROWS = 1_000_000
MAX_SOAK_RESOURCE_MONITOR_ROW_BYTES = 2 * 1024 * 1024
MAX_SOAK_RESOURCE_OWNER_POLL_NS = 100_000_000
_SOURCE_INVENTORY_MODULE_CACHE: dict[str, Any] = {}
_PRESSURE_SUBREAPER_ACTIVE = False
OWNED_GROUP_SCAN_MAX_SECONDS = 0.05

QUALIFIED_SECONDS = 10_800
SAMPLE_INTERVAL_MS = 100
SAMPLE_INTERVAL_NS = 100_000_000
SAMPLE_TOLERANCE_NS = 10_000_000
WARMUP_SECONDS = 300
RSS_GROWTH_PERCENT = 5
LOGICAL_WINDOW = 8
TASK_CEILING = 64
CONTROL_CEILING = 64 * 1024 * 1024
CONTROL_MAX_TENANTS = 1
CONTROL_MAX_WAITERS = 256
RATE_BYTES_PER_SECOND = 16 * 1024 * 1024 * 1024
RATE_BURST_BYTES = 64 * 1024
RATE_RESERVATIONS = 64

SAMPLE_HEADER = ["monotonic_ns", "rss_kib"]
for _owner in OWNERS:
    for _dimension in DOMAINS:
        SAMPLE_HEADER.extend(
            f"{_owner}_{_dimension}_{_field}" for _field in ("ceiling", "limit", "used")
        )
SAMPLE_HEADER.extend(
    [
        "scope_memory_limit",
        "scope_memory_used",
        "scope_disk_limit",
        "scope_disk_used",
        "scope_network_limit",
        "scope_network_used",
    ]
)
for _direction in DIRECTIONS:
    SAMPLE_HEADER.extend(
        [
            f"{_direction}_rate_limit_bps",
            f"{_direction}_rate_burst_bytes",
            f"{_direction}_rate_ceiling_bps",
            f"{_direction}_rate_ceiling_burst_bytes",
            f"{_direction}_rate_max_reservations",
            f"{_direction}_rate_available_bytes",
            f"{_direction}_rate_reserved_bytes",
            f"{_direction}_rate_reservations",
        ]
    )
SAMPLE_HEADER = tuple(SAMPLE_HEADER)
TERMINAL_HEADER = (
    "global_id",
    "reference_work_id",
    "family",
    "status",
    "observed_checksum",
    "ring_expected_checksum",
)


class SoakReadbackError(ValueError):
    """A malformed recipe, changed input, or invalid soak artifact."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SoakReadbackError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise SoakReadbackError(f"value is not canonical JSON: {error}") from error
    return (text + "\n").encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SoakReadbackError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise SoakReadbackError(f"non-finite JSON number is forbidden: {value}")


def exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == keys, f"{label} keys differ from the frozen contract")
    return value


def text(value: object, label: str, *, maximum: int = 512) -> str:
    require(type(value) is str, f"{label} must be a string")
    require(0 < len(value) <= maximum, f"{label} is empty or oversized")
    require(not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value), f"{label} contains a control character")
    return value


def uint(value: object, label: str, *, maximum: int = U64_MAX, positive: bool = False) -> int:
    require(type(value) is int, f"{label} must be an integer, not a boolean or other JSON type")
    require(0 <= value <= maximum, f"{label} is outside its finite unsigned bound")
    if positive:
        require(value > 0, f"{label} must be positive")
    return value


def digest(value: object, label: str) -> str:
    item = text(value, label, maximum=64)
    require(re.fullmatch(r"[0-9a-f]{64}", item) is not None, f"{label} must be a lowercase SHA-256 digest")
    return item


def parse_uint(value: str, label: str, *, maximum: int = U64_MAX) -> int:
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is not None, f"{label} is not a canonical unsigned integer")
    parsed = int(value)
    require(parsed <= maximum, f"{label} exceeds its finite bound")
    return parsed


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


class StableInput:
    """Read a bounded regular file through one no-follow descriptor and hash those bytes."""

    def __init__(self, path: Path, label: str, maximum: int, *,
                 artifact_view: Any | None = None):
        self.path = path
        self.label = label
        self.maximum = maximum
        self.fd: int | None = None
        self.stream: BinaryIO | None = None
        self.before: tuple[int, int, int, int, int] | None = None
        self.size = 0
        self.consumed = 0
        self.hasher = hashlib.sha256()
        self.finished = False
        self.artifact_view = artifact_view
        self._capture_manager: Any | None = None
        self._capture_entered = False
        self._capture_sha256: str | None = None

    def __enter__(self) -> StableInput:
        if self.artifact_view is not None:
            try:
                snapshot = getattr(self.artifact_view, "open_snapshot", None)
                require(callable(snapshot), f"{self.label} has no explicit capture snapshot reader")
                self._capture_manager = snapshot(self.path, self.label, self.maximum)
                captured = self._capture_manager.__enter__()
                self._capture_entered = True
                self.stream, checksum, size = captured
                require(type(size) is int and 0 <= size <= self.maximum,
                        f"{self.label} capture exceeds its finite byte bound")
                self._capture_sha256 = digest(checksum, f"{self.label} capture raw pin")
                self.size = size
                return self
            except BaseException:
                self.close()
                raise
        try:
            path_info = self.path.lstat()
            require(stat.S_ISREG(path_info.st_mode), f"{self.label} must be a regular non-symlink file")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            self.fd = os.open(self.path, flags)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode), f"{self.label} descriptor is not a regular file")
            require(_fingerprint(path_info) == _fingerprint(info), f"{self.label} changed while it was opened")
            require(info.st_size <= self.maximum, f"{self.label} exceeds its finite byte bound")
            self.before = _fingerprint(info)
            self.size = info.st_size
            self.stream = os.fdopen(self.fd, "rb", closefd=False)
            return self
        except SoakReadbackError:
            self.close()
            raise
        except OSError as error:
            self.close()
            raise SoakReadbackError(f"cannot safely open {self.label}: {error}") from error

    def read(self, count: int = -1) -> bytes:
        require(self.stream is not None, f"{self.label} is not open")
        remaining = self.size - self.consumed
        amount = remaining if count < 0 else min(count, remaining)
        if amount == 0:
            return b""
        try:
            block = self.stream.read(amount)
        except OSError as error:
            raise SoakReadbackError(f"cannot read {self.label}: {error}") from error
        require(block and len(block) <= amount, f"{self.label} was truncated while being read")
        self.consumed += len(block)
        self.hasher.update(block)
        return block

    def readline(self, maximum: int = MAX_LINE_BYTES) -> bytes:
        require(self.stream is not None, f"{self.label} is not open")
        remaining = self.size - self.consumed
        if remaining == 0:
            return b""
        try:
            line = self.stream.readline(min(maximum + 1, remaining))
        except OSError as error:
            raise SoakReadbackError(f"cannot read {self.label}: {error}") from error
        require(line, f"{self.label} was truncated while being read")
        require(len(line) <= maximum, f"{self.label} contains an oversized line")
        self.consumed += len(line)
        self.hasher.update(line)
        return line

    def finish(self) -> str:
        require(self.consumed == self.size, f"{self.label} was not completely read")
        if self.artifact_view is not None:
            require(self._capture_entered and self.stream is not None,
                    f"{self.label} capture is not open")
            checksum = self.hasher.hexdigest()
            require(self.stream.read(1) == b"" and checksum == self._capture_sha256,
                    f"{self.label} capture consumed bytes differ from its exact raw pin")
            # The capture owner checks its actual file/stage metadata on exit.
            # No original-host descriptor or stat result is fabricated here.
            self.close()
            self.finished = True
            return checksum
        require(self.fd is not None and self.before is not None, f"{self.label} is not open")
        try:
            descriptor_after = os.fstat(self.fd)
            path_after = self.path.lstat()
        except OSError as error:
            raise SoakReadbackError(f"cannot restat {self.label}: {error}") from error
        require(stat.S_ISREG(path_after.st_mode), f"{self.label} path changed to a non-regular file")
        require(_fingerprint(descriptor_after) == self.before, f"{self.label} changed during the read")
        require(_fingerprint(path_after) == self.before, f"{self.label} path was replaced during the read")
        self.finished = True
        return self.hasher.hexdigest()

    def close(self) -> None:
        if self._capture_entered:
            manager = self._capture_manager
            self._capture_entered = False
            self._capture_manager = None
            self.stream = None
            manager.__exit__(None, None, None)
            return
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def __exit__(self, *_exc: object) -> None:
        self.close()


def read_stable_bytes(
    path: Path, label: str, maximum: int, *, artifact_view: Any | None = None,
) -> tuple[bytes, str]:
    with StableInput(path, label, maximum, artifact_view=artifact_view) as source:
        blocks = bytearray()
        while source.consumed < source.size:
            blocks.extend(source.read(min(1024 * 1024, source.size - source.consumed)))
        checksum = source.finish()
    return bytes(blocks), checksum


def read_json(
    path: Path, label: str, maximum: int, *, artifact_view: Any | None = None,
) -> tuple[dict[str, Any], str, bytes]:
    raw, checksum = read_stable_bytes(path, label, maximum, artifact_view=artifact_view)
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise SoakReadbackError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must contain a JSON object")
    return value, checksum, raw


def sha256_file(path: Path, label: str, maximum: int = MAX_EXECUTABLE_BYTES) -> str:
    with StableInput(path, label, maximum) as source:
        while source.consumed < source.size:
            source.read(min(1024 * 1024, source.size - source.consumed))
        return source.finish()


def source_inventory_module(expected_sha256: str | None = None) -> Any:
    path = Path(__file__).with_name("application-source-inventory.py")
    raw, source_sha256 = read_stable_bytes(path, "shared source inventory module", MAX_SOURCE_FILE_BYTES)
    require(source_sha256 == SOURCE_INVENTORY_MODULE_SHA256, "shared source inventory module differs from its frozen SHA-256")
    require(expected_sha256 is None or source_sha256 == expected_sha256, "shared source inventory module differs from the source inventory pin")
    cached = _SOURCE_INVENTORY_MODULE_CACHE.get(source_sha256)
    if cached is not None:
        return cached
    module_name = f"application_source_inventory_{source_sha256}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        code = compile(raw, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise SoakReadbackError(f"shared source inventory module cannot be compiled from its pinned bytes: {error}") from error
    require(module.SCHEMA == SOURCE_INVENTORY_SCHEMA, "shared source inventory module has an unexpected schema")
    if len(_SOURCE_INVENTORY_MODULE_CACHE) >= 4:
        _SOURCE_INVENTORY_MODULE_CACHE.pop(next(iter(_SOURCE_INVENTORY_MODULE_CACHE)))
    _SOURCE_INVENTORY_MODULE_CACHE[source_sha256] = module
    return module


def token(value: object, label: str, *, pattern: str = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}") -> str:
    item = text(value, label, maximum=128)
    require(re.fullmatch(pattern, item) is not None, f"{label} is malformed")
    return item


def safe_absolute_path(value: object, label: str) -> Path:
    raw = text(value, label, maximum=4096)
    require("\n" not in raw and "\t" not in raw and "\\" not in raw, f"{label} contains a non-portable path character")
    path = Path(raw)
    require(path.is_absolute(), f"{label} must be absolute")
    try:
        require(not stat.S_ISLNK(path.lstat().st_mode), f"{label} must not be a symlink")
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise SoakReadbackError(f"{label} does not resolve: {error}") from error
    return resolved


def relative_path(value: object, label: str) -> PurePosixPath:
    raw = text(value, label, maximum=4096)
    path = PurePosixPath(raw)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in raw and "\x00" not in raw, f"{label} must be a safe source-relative path")
    require(path.parts and all(part not in ("", ".") for part in path.parts), f"{label} is malformed")
    return path


def safe_child(root: Path, relative: object, label: str) -> Path:
    rel = relative_path(relative, label)
    current = root
    for part in rel.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise SoakReadbackError(f"{label} is missing: {error}") from error
        require(not stat.S_ISLNK(info.st_mode), f"{label} traverses a symlink")
    try:
        resolved = current.resolve(strict=True)
    except OSError as error:
        raise SoakReadbackError(f"{label} does not resolve: {error}") from error
    require(resolved.is_relative_to(root), f"{label} escapes the frozen source root")
    return resolved


def source_tree_digest(entries: list[dict[str, Any]]) -> str:
    inventory_module = source_inventory_module()
    return inventory_module.digest_records(entries)


class _LinuxSigSet(ctypes.Structure):
    _fields_ = [("_values", ctypes.c_ulong * 16)]


class _LinuxSigAction(ctypes.Structure):
    _fields_ = [
        ("handler", ctypes.c_void_p),
        ("mask", _LinuxSigSet),
        ("flags", ctypes.c_int),
        ("restorer", ctypes.c_void_p),
    ]


def _require_waitid_ownership_support() -> None:
    """Require waitid(WNOWAIT) and an unreaped, default-SIGCHLD child owner."""
    require(sys.platform.startswith("linux"), "owned process-group supervision requires Linux waitid semantics")
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "SIGCHLD disposition is not default; child wait ownership is unsupported")
    required = ("waitid", "waitpid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "waitstatus_to_exitcode")
    require(all(hasattr(os, name) for name in required), "owned process-group supervision lacks waitid(WNOWAIT) support")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        sigaction = libc.sigaction
        sigaction.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(_LinuxSigAction))
        sigaction.restype = ctypes.c_int
        action = _LinuxSigAction()
        if sigaction(signal.SIGCHLD, None, ctypes.byref(action)) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
    except (AttributeError, OSError) as error:
        raise SoakReadbackError(f"cannot verify default SIGCHLD wait ownership: {error}") from error
    require(action.handler in (None, 0), "SIGCHLD native handler is not default; child wait ownership is unsupported")
    require(action.flags & getattr(signal, "SA_NOCLDWAIT", 2) == 0, "SIGCHLD has SA_NOCLDWAIT; child wait ownership is unsupported")


def _parse_proc_stat(pid: int, raw: bytes, label: str) -> dict[str, Any]:
    require(len(raw) <= 65_536, f"{label} /proc stat exceeds its finite bound")
    try:
        text_value = raw.decode("ascii").strip()
    except UnicodeError as error:
        raise SoakReadbackError(f"{label} /proc stat is not ASCII") from error
    closing = text_value.rfind(")")
    require(closing > 0, f"{label} /proc stat has malformed command framing")
    head = text_value[:text_value.find("(")].strip()
    tail = text_value[closing + 1:].strip().split()
    require(head == str(pid) and len(tail) >= 20, f"{label} /proc stat has malformed identity fields")
    try:
        start_ticks, parent_pid, process_group, session_id = (int(tail[index]) for index in (19, 1, 2, 3))
    except ValueError as error:
        raise SoakReadbackError(f"{label} /proc stat identity is malformed") from error
    require(start_ticks > 0 and parent_pid >= 0 and process_group >= 0 and session_id >= 0, f"{label} /proc stat identity is outside its bound")
    return {
        "pid": pid, "state": tail[0], "start_ticks": start_ticks,
        "parent_pid": parent_pid, "pgid": process_group, "session_id": session_id,
    }


def _classify_owned_session_member(leader_pid: int, member: dict[str, Any]) -> str:
    """Classify proc records without treating valid foreign zero IDs as errors."""
    if member["session_id"] != leader_pid:
        return "foreign"
    require(leader_pid > 0 and member["session_id"] > 0 and member["pgid"] > 0, "owned session member has a zero or invalid process-group identity")
    return "owned_group" if member["pgid"] == leader_pid else "escaped_group"


class _OwnedProcessGroup:
    """Keep a Popen child unreaped until every numeric process-group operation is done."""

    def __init__(self, process: subprocess.Popen[bytes], label: str):
        self.process = process
        self.pid = process.pid
        self.label = label
        self.reaped = False
        self.return_code: int | None = None
        self.identity: dict[str, Any] | None = None
        self.identity_error: str | None = None
        self.last_signal: int | None = None
        self._wait_lock = getattr(process, "_waitpid_lock", None)
        require(self.pid > 0 and self._wait_lock is not None, f"{label} direct-child wait lock is unavailable")
        with self._wait_lock:
            first_status = self._peek_unlocked()
            try:
                identity = _parse_proc_stat(self.pid, Path(f"/proc/{self.pid}/stat").read_bytes(), label)
                require(identity["parent_pid"] == os.getpid(), f"{label} is not the directly owned child")
                require(identity["pgid"] == self.pid and identity["session_id"] == self.pid, f"{label} did not enter its owned process group and session")
                self.identity = identity
            except (OSError, SoakReadbackError) as error:
                # The session created by Popen still pins the intended PGID to
                # this unreaped child. Later group signals may use that fact as
                # an emergency fallback, but cleanup cannot be verified.
                self.identity_error = f"{label} process identity scan failed: {error}"
            self._peek_unlocked()
            if first_status is not None:
                self.return_code = first_status
        process._allocatbelt_owned_group = self

    def _peek_unlocked(self) -> int | None:
        _require_waitid_ownership_support()
        require(not self.reaped and self.process.returncode is None, f"{self.label} direct-child wait ownership was already consumed")
        try:
            result = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as error:
            raise SoakReadbackError(f"{self.label} direct-child ownership was lost (waitid returned ECHILD)") from error
        except OSError as error:
            if error.errno == errno.ECHILD:
                raise SoakReadbackError(f"{self.label} direct-child ownership was lost (waitid returned ECHILD)") from error
            raise SoakReadbackError(f"{self.label} cannot observe its unreaped child: {error}") from error
        if result is None or result.si_pid == 0:
            return None
        require(result.si_pid == self.pid, f"{self.label} waitid observed a different child")
        if result.si_code == getattr(os, "CLD_EXITED", 1):
            return result.si_status
        if result.si_code in (getattr(os, "CLD_KILLED", 2), getattr(os, "CLD_DUMPED", 3)):
            return -result.si_status
        raise SoakReadbackError(f"{self.label} waitid returned an unsupported child state")

    def observe(self) -> int | None:
        with self._wait_lock:
            return self._peek_unlocked()

    def _scan_group_unlocked(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
        if self.identity is None:
            return [], [], self.identity_error or f"{self.label} process identity is unavailable"
        deadline = time.monotonic() + OWNED_GROUP_SCAN_MAX_SECONDS
        members: list[dict[str, Any]] = []
        escaped: list[dict[str, Any]] = []
        leader_seen = False
        scanned = 0
        try:
            with os.scandir("/proc") as entries:
                for entry in entries:
                    if not entry.name.isdecimal():
                        continue
                    scanned += 1
                    if scanned % 32 == 0 and time.monotonic() >= deadline:
                        raise TimeoutError(f"process table scan exceeded {OWNED_GROUP_SCAN_MAX_SECONDS:g} seconds")
                    try:
                        raw = Path(entry.path, "stat").read_bytes()
                    except FileNotFoundError:
                        continue
                    except OSError as error:
                        raise SoakReadbackError(f"cannot inspect process {entry.name} during {self.label} group scan: {error}") from error
                    try:
                        pid = int(entry.name)
                    except ValueError:
                        continue
                    member = _parse_proc_stat(pid, raw, self.label)
                    classification = _classify_owned_session_member(self.pid, member)
                    if classification == "foreign":
                        continue
                    if pid == self.pid:
                        require(
                            member["start_ticks"] == self.identity["start_ticks"]
                            and member["parent_pid"] == self.identity["parent_pid"]
                            and member["pgid"] == self.pid
                            and member["session_id"] == self.pid,
                            f"{self.label} leader PID/start/parent/group/session identity changed",
                        )
                        leader_seen = True
                    if classification == "owned_group":
                        members.append(member)
                    else:
                        escaped.append(member)
        except SoakReadbackError as error:
            return [], [], str(error)
        except (OSError, TimeoutError) as error:
            return [], [], f"{self.label} process-group scan failed: {error}"
        if not leader_seen:
            return [], [], f"{self.label} unreaped leader was absent from its process-group scan"
        return members, escaped, None

    @staticmethod
    def _active_members(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [member for member in members if member["state"] not in ("Z", "X")]

    def signal_group(
        self, signum: int,
    ) -> tuple[list[dict[str, Any]] | None, list[dict[str, Any]] | None, str | None]:
        """Signal only after a fresh owned waitid check and a guarded /proc scan."""
        with self._wait_lock:
            self._peek_unlocked()
            members, escaped, scan_error = self._scan_group_unlocked()
            self._peek_unlocked()  # Recheck immediately after scanning, before killpg.
            active = self._active_members(members) if scan_error is None else None
            active_escaped = self._active_members(escaped) if scan_error is None else None
            if scan_error is not None or active:
                try:
                    os.killpg(self.pid, signum)
                    self.last_signal = signum
                except ProcessLookupError:
                    pass
                except OSError as error:
                    if error.errno != errno.ESRCH:
                        raise SoakReadbackError(f"{self.label} process-group signal failed: {error}") from error
            return active, active_escaped, scan_error

    def reap_if_ready(
        self, *, allow_unverified_group: bool = False,
    ) -> tuple[int | None, list[dict[str, Any]] | None, list[dict[str, Any]] | None, str | None]:
        """Reap only after the final guarded group scan; never inspect PGID afterward."""
        with self._wait_lock:
            child_status = self._peek_unlocked()
            if child_status is None:
                return None, None, None, None
            members, escaped, scan_error = self._scan_group_unlocked()
            self._peek_unlocked()  # Must be the last check before final owned waitpid.
            active = self._active_members(members) if scan_error is None else None
            active_escaped = self._active_members(escaped) if scan_error is None else None
            if (active or active_escaped) and not allow_unverified_group:
                return None, active, active_escaped, None
            if scan_error is not None and not allow_unverified_group:
                return None, None, None, scan_error
            if (active or scan_error is not None) and self.last_signal != signal.SIGKILL:
                return None, active, active_escaped, scan_error or "process group remained active without a final SIGKILL"
            try:
                waited_pid, wait_status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError as error:
                raise SoakReadbackError(f"{self.label} direct-child ownership was lost before final waitpid (ECHILD)") from error
            except OSError as error:
                raise SoakReadbackError(f"{self.label} final owned waitpid failed: {error}") from error
            require(waited_pid == self.pid, f"{self.label} exited waitid without a final waitpid status")
            wait_code = os.waitstatus_to_exitcode(wait_status)
            require(wait_code == child_status, f"{self.label} waitid and waitpid child statuses differ")
            self.process.returncode = wait_code
            self.return_code = wait_code
            self.reaped = True
            return wait_code, active, active_escaped, scan_error


def _owned_child_exit(process: subprocess.Popen[bytes]) -> int | None:
    owner = getattr(process, "_allocatbelt_owned_group", None)
    require(isinstance(owner, _OwnedProcessGroup) and owner.process is process, "application child has no unreaped direct-child owner")
    return owner.observe()


def _close_selector_streams(selector: selectors.BaseSelector) -> None:
    for key in list(selector.get_map().values()):
        try:
            selector.unregister(key.fileobj)
        except (KeyError, ValueError):
            pass
        try:
            key.fileobj.close()
        except OSError:
            pass


def _run_checked(
    argv: list[str],
    cwd: Path,
    label: str,
    timeout: float = 15.0,
    *,
    stdout_limit: int = MAX_MANIFEST_BYTES,
    stderr_limit: int = 64 * 1024,
) -> bytes:
    require(argv and all(type(item) is str for item in argv), f"{label} command is malformed")
    require(0 < timeout <= 120 and 0 < stdout_limit <= MAX_MANIFEST_BYTES and 0 < stderr_limit <= 1024 * 1024, f"{label} bounds are invalid")
    _require_waitid_ownership_support()
    process: subprocess.Popen[bytes] | None = None
    owner: _OwnedProcessGroup | None = None
    selector: selectors.BaseSelector | None = None
    old_handlers: dict[int, Any] = {}
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    failure: str | None = None
    cleanup_started: float | None = None
    kill_sent = False
    kill_sent_at: float | None = None
    term_sent = False
    term_sent_at: float | None = None
    hard_cleanup_attempted = False
    cleanup_failure: str | None = None
    received_signal: list[int] = []

    term_grace_seconds = 0.2
    kill_reap_seconds = 0.75

    def begin_cleanup(reason: str | None = None) -> None:
        nonlocal failure, cleanup_started
        if reason is not None and failure is None:
            failure = reason
        if cleanup_started is None:
            cleanup_started = time.monotonic()

    def interrupted(signum: int, _frame: Any) -> None:
        if not received_signal:
            received_signal.append(signum)

    def send_group_signal(signum: int) -> tuple[list[dict[str, Any]] | None, list[dict[str, Any]] | None]:
        nonlocal cleanup_failure
        assert owner is not None
        try:
            active, escaped, scan_error = owner.signal_group(signum)
        except SoakReadbackError:
            raise
        if scan_error is not None and cleanup_failure is None:
            cleanup_failure = f"{label} cleanup could not verify its process group: {scan_error}"
        if escaped and cleanup_failure is None:
            cleanup_failure = f"{label} cleanup found live same-session processes outside its owned process group"
        return active, escaped

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, interrupted)
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        owner = _OwnedProcessGroup(process, label)
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        streams = {"stdout": process.stdout, "stderr": process.stderr}
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        if received_signal:
            begin_cleanup(f"{label} interrupted by signal {received_signal[0]}")
        while True:
            if received_signal and failure is None:
                begin_cleanup(f"{label} interrupted by signal {received_signal[0]}")
            if time.monotonic() >= deadline and failure is None:
                begin_cleanup(f"{label} exceeded its {timeout:g}-second deadline")
            now = time.monotonic()
            child_status = owner.observe()
            if child_status is not None and cleanup_started is None:
                # The leader may leave descendants that still hold the pipes.
                # Give its process group the same bounded cleanup treatment.
                begin_cleanup()
            if cleanup_started is not None:
                if not term_sent:
                    send_group_signal(signal.SIGTERM)
                    term_sent = True
                    term_sent_at = time.monotonic()
                escalation_at = (term_sent_at if term_sent_at is not None else cleanup_started) + term_grace_seconds
                if not kill_sent and now >= escalation_at:
                    send_group_signal(signal.SIGKILL)
                    kill_sent = True
                    kill_sent_at = time.monotonic()
                hard_deadline = (
                    kill_sent_at + kill_reap_seconds - OWNED_GROUP_SCAN_MAX_SECONDS
                    if kill_sent_at is not None
                    else escalation_at + kill_reap_seconds + 2 * OWNED_GROUP_SCAN_MAX_SECONDS
                )
                if now >= hard_deadline:
                    if not kill_sent:
                        send_group_signal(signal.SIGKILL)
                        kill_sent = True
                        kill_sent_at = time.monotonic()
                    hard_cleanup_attempted = True
                    open_streams = list(selector.get_map().values())
                    if open_streams:
                        cleanup_failure = cleanup_failure or (
                            f"{label} cleanup failed: {len(open_streams)} capture pipe(s) remained open "
                            "at the hard deadline; output is incomplete"
                        )
                    _close_selector_streams(selector)
                    try:
                        return_code, active, escaped, scan_error = owner.reap_if_ready(allow_unverified_group=True)
                    except SoakReadbackError as error:
                        cleanup_failure = f"{cleanup_failure}; {error}" if cleanup_failure else str(error)
                        break
                    if return_code is None:
                        child_failure = f"{label} cleanup failed: child was not reaped by its hard deadline"
                        cleanup_failure = f"{cleanup_failure}; {child_failure}" if cleanup_failure else child_failure
                    if active:
                        cleanup_failure = cleanup_failure or f"{label} cleanup failed: process-group members remained live after bounded SIGKILL"
                    if escaped:
                        cleanup_failure = cleanup_failure or f"{label} cleanup found live same-session processes outside its owned process group"
                    if scan_error is not None:
                        cleanup_failure = cleanup_failure or f"{label} cleanup could not verify its process group: {scan_error}"
                    break
                if child_status is not None and not selector.get_map():
                    return_code, active, escaped, scan_error = owner.reap_if_ready()
                    if return_code is not None:
                        if scan_error is not None:
                            cleanup_failure = cleanup_failure or f"{label} cleanup could not verify its process group: {scan_error}"
                        if active:
                            cleanup_failure = cleanup_failure or f"{label} cleanup failed: live process-group members remained"
                        if escaped:
                            cleanup_failure = cleanup_failure or f"{label} cleanup found live same-session processes outside its owned process group"
                        break
                    if scan_error is not None:
                        cleanup_failure = cleanup_failure or f"{label} cleanup could not verify its process group: {scan_error}"
                    elif escaped and not active:
                        return_code, active, escaped, scan_error = owner.reap_if_ready(allow_unverified_group=True)
                        cleanup_failure = cleanup_failure or f"{label} cleanup found live same-session processes outside its owned process group"
                        if return_code is not None:
                            break
            if child_status is not None and not selector.get_map() and cleanup_started is None:
                # A clean, already-closed capture can be reaped only after the
                # final guarded group scan proves there are no live descendants.
                return_code, active, escaped, scan_error = owner.reap_if_ready()
                if return_code is not None:
                    break
                if scan_error is not None:
                    cleanup_failure = f"{label} cleanup could not verify its process group: {scan_error}"
                    begin_cleanup(cleanup_failure)
                elif active:
                    begin_cleanup()
                elif escaped:
                    cleanup_failure = f"{label} cleanup found live same-session processes outside its owned process group"
                    begin_cleanup(cleanup_failure)
            select_timeout = 0.05
            if cleanup_started is not None:
                escalation_at = (term_sent_at if term_sent_at is not None else cleanup_started) + term_grace_seconds
                hard_deadline = (
                    kill_sent_at + kill_reap_seconds - OWNED_GROUP_SCAN_MAX_SECONDS
                    if kill_sent_at is not None
                    else escalation_at + kill_reap_seconds + 2 * OWNED_GROUP_SCAN_MAX_SECONDS
                )
                select_timeout = min(select_timeout, max(0.0, hard_deadline - now))
            elif failure is None:
                select_timeout = min(select_timeout, max(0.0, deadline - now))
            for key, _mask in selector.select(select_timeout):
                name = key.data
                try:
                    block = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer = output[name]
                if len(buffer) + len(block) > limits[name]:
                    if failure is None:
                        begin_cleanup(f"{label} {name} exceeded its {limits[name]}-byte capture bound")
                elif failure is None or len(buffer) < limits[name]:
                    remaining = max(0, limits[name] - len(buffer))
                    buffer.extend(block[:remaining])
        return_code = owner.return_code
        if cleanup_failure is not None:
            raise SoakReadbackError(cleanup_failure)
        if failure is not None:
            raise SoakReadbackError(failure)
        assert return_code is not None
        if return_code != 0:
            detail = bytes(output["stderr"][:4096]).decode("utf-8", errors="replace")
            raise SoakReadbackError(f"{label} exited with status {return_code}: {detail}")
        return bytes(output["stdout"])
    except SoakReadbackError:
        raise
    except (OSError, subprocess.SubprocessError, InterruptedError) as error:
        raise SoakReadbackError(f"{label} failed: {error}") from error
    finally:
        active_exception = sys.exc_info()[1]
        final_cleanup_failure: str | None = None
        if owner is not None and not owner.reaped and not hard_cleanup_attempted:
            try:
                # Emergency fallback keeps the known session leader unreaped
                # while attempting bounded group termination. If wait
                # ownership has been lost, signal_group fails before killpg.
                _active, escaped, scan_error = owner.signal_group(signal.SIGTERM)
                if scan_error is not None:
                    final_cleanup_failure = f"{label} cleanup could not verify its process group: {scan_error}"
                if escaped:
                    final_cleanup_failure = final_cleanup_failure or f"{label} cleanup found live same-session processes outside its owned process group"
                emergency_deadline = time.monotonic() + 0.1
                while time.monotonic() < emergency_deadline and owner.observe() is None:
                    time.sleep(0.01)
                _active, escaped, scan_error = owner.signal_group(signal.SIGKILL)
                if scan_error is not None:
                    final_cleanup_failure = final_cleanup_failure or f"{label} cleanup could not verify its process group: {scan_error}"
                if escaped:
                    final_cleanup_failure = final_cleanup_failure or f"{label} cleanup found live same-session processes outside its owned process group"
                reap_deadline = time.monotonic() + 0.25
                while time.monotonic() < reap_deadline and owner.observe() is None:
                    time.sleep(0.01)
                return_code, active, escaped, scan_error = owner.reap_if_ready(allow_unverified_group=True)
                if return_code is None:
                    final_cleanup_failure = final_cleanup_failure or f"{label} cleanup failed: child remains unreaped after bounded SIGKILL"
                if active:
                    final_cleanup_failure = final_cleanup_failure or f"{label} cleanup failed: process-group members remained live after bounded SIGKILL"
                if escaped:
                    final_cleanup_failure = final_cleanup_failure or f"{label} cleanup found live same-session processes outside its owned process group"
                if scan_error is not None:
                    final_cleanup_failure = final_cleanup_failure or f"{label} cleanup could not verify its process group: {scan_error}"
            except SoakReadbackError as error:
                final_cleanup_failure = f"{label} cleanup failed: {error}"
        elif owner is not None and not owner.reaped and hard_cleanup_attempted:
            final_cleanup_failure = final_cleanup_failure or f"{label} cleanup failed: child remains unreaped after hard SIGKILL deadline"
        elif process is not None and owner is None:
            final_cleanup_failure = f"{label} cleanup failed: direct-child ownership was not established"
        if selector is not None:
            try:
                selector.close()
            except OSError as error:
                final_cleanup_failure = f"{final_cleanup_failure}; selector close failed: {error}" if final_cleanup_failure else f"selector close failed: {error}"
        for stream in (None if process is None else process.stdout, None if process is None else process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError as error:
                    final_cleanup_failure = f"{final_cleanup_failure}; capture pipe close failed: {error}" if final_cleanup_failure else f"capture pipe close failed: {error}"
        for signum, handler in old_handlers.items():
            try:
                signal.signal(signum, handler)
            except (OSError, ValueError) as error:
                final_cleanup_failure = f"{final_cleanup_failure}; signal handler restore failed: {error}" if final_cleanup_failure else f"signal handler restore failed: {error}"
        if final_cleanup_failure is not None:
            if active_exception is None:
                raise SoakReadbackError(final_cleanup_failure)
            raise SoakReadbackError(f"{active_exception}; {final_cleanup_failure}") from active_exception


def verify_source_tree(
    root: Path, source: dict[str, Any], *, offline_context: dict[str, Any] | None = None,
) -> str:
    require(root.is_dir() and not root.is_symlink(), "source root must be a real directory")
    commit = text(source["git_commit"], "source git commit", maximum=64)
    if offline_context is None:
        live_commit = _run_checked(["git", "rev-parse", "HEAD"], root, "source git identity").decode("ascii").strip()
        require(live_commit == commit, "live source Git commit differs from its frozen manifest")
    else:
        exact_object(offline_context, {
            "schema", "evidence_path_map", "construction_probe_capture",
            "host_verification_pin", "application_environment",
            "pressure_origin",
        }, "Source5 Soak offline replay context")
        require(offline_context["schema"] in {
                    SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA,
                    SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA_V2,
                },
                "Source5 Soak offline replay context schema differs")
        # Offline replay pins the recorded commit as part of the raw source
        # manifest and verifies every typed source-tree entry below. It never
        # asks the coordinator's Git worktree what commit it happens to be on.
        require(type(commit) is str and bool(commit),
                "Source5 offline source manifest has no recorded commit")
    inventory_module = source_inventory_module()
    expected_records = inventory_module.validate_records({
        "schema": inventory_module.SCHEMA,
        "entries": source["files"],
    })
    require(expected_records == source["files"], "source inventory records are not canonical")
    require(inventory_module.digest_records(expected_records) ==
            source["source_tree_sha256"],
            "typed source inventory does not produce its frozen tree digest")
    if offline_context is None:
        try:
            inventory_module.verify_source_tree(root, source["source_tree_sha256"], expected_records)
        except inventory_module.InventoryError as error:
            raise SoakReadbackError(f"live source inventory differs from its manifest: {error}") from error
    else:
        # `inventory_module.verify_source_tree` discovers files by invoking
        # Git. Offline replay instead checks the exact closed typed records
        # and their literal source bytes, so no coordinator Git/worktree probe
        # can affect the result.
        for index, entry in enumerate(expected_records):
            relative = PurePosixPath(entry["path"])
            candidate = root.joinpath(*relative.parts)
            parent = candidate.parent
            require(parent.resolve(strict=True) == parent,
                    f"offline source entry[{index}] has an aliased parent")
            if entry["kind"] == "file":
                before = candidate.lstat()
                raw, actual_sha = read_stable_bytes(
                    candidate, f"offline SourceV5 source file {entry['path']}",
                    MAX_SOURCE_FILE_BYTES,
                )
                info = candidate.lstat()
                mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
                require(stat.S_ISREG(before.st_mode) and stat.S_ISREG(info.st_mode) and
                        (before.st_dev, before.st_ino, before.st_size,
                         before.st_mtime_ns, before.st_ctime_ns) ==
                        (info.st_dev, info.st_ino, info.st_size,
                         info.st_mtime_ns, info.st_ctime_ns) and
                        actual_sha == entry["sha256"] and len(raw) == entry["size"] and
                        mode == entry["mode"],
                        f"offline SourceV5 source file differs from its typed record: {entry['path']}")
            else:
                try:
                    info = candidate.lstat()
                    target = os.readlink(candidate)
                except OSError as error:
                    raise SoakReadbackError(
                        f"offline SourceV5 symlink is unavailable: {entry['path']}: {error}",
                    ) from error
                target_raw = target.encode("utf-8")
                require(stat.S_ISLNK(info.st_mode) and
                        hashlib.sha256(target_raw).hexdigest() == entry["sha256"] and
                        len(target_raw) == entry["size"] and
                        target == entry["target"],
                        f"offline SourceV5 symlink differs from its typed record: {entry['path']}")
    cargo_lock = safe_child(root, "Cargo.lock", "Cargo.lock")
    lock_hash = sha256_file(cargo_lock, "Cargo.lock", MAX_SOURCE_FILE_BYTES)
    require(lock_hash == source["cargo_lock_sha256"], "live Cargo.lock differs from its source manifest")
    return inventory_module.digest_records(expected_records)


def _expected_mixed_limits(profile: str, policy: dict[str, Any]) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    require(profile in PROFILES, "unsupported soak profile")
    workers_by_profile = policy.get("workers_by_profile")
    require(type(workers_by_profile) is dict and workers_by_profile == {"ordinary": 4, "oversubscribed": 2} and all(type(value) is int for value in workers_by_profile.values()), "fixed policy worker map differs from the frozen profile contract")
    workers = workers_by_profile.get("oversubscribed" if profile == "oversubscribed" else "ordinary")
    workers = uint(workers, "fixed worker count", positive=True)
    require(workers == (2 if profile == "oversubscribed" else 4), "fixed policy worker count differs from the soak profile contract")
    workloads = policy.get("workloads")
    require(type(workloads) is dict and type(workloads.get("mixed")) is dict, "fixed policy omits mixed workload limits")
    mixed = workloads["mixed"]
    domain = exact_object(mixed.get("domain_ceiling"), set(DOMAINS), "mixed domain ceiling")
    scope = exact_object(mixed.get("scope_limits"), {"managed_memory_limit", "disk_operation_limit", "network_operation_limit"}, "mixed scope limits")
    for name, value in domain.items():
        uint(value, f"mixed domain ceiling {name}")
    for name, value in scope.items():
        uint(value, f"mixed scope limit {name}")
    require(domain == {
        "cpu": 4,
        "memory": 1_638_536,
        "disk": 8,
        "network": 16,
        "tasks": TASK_CEILING,
        "control": CONTROL_CEILING,
    }, "mixed workload domain ceiling differs from the frozen fixed policy")
    require(scope == {
        "managed_memory_limit": 1_638_536,
        "disk_operation_limit": 8,
        "network_operation_limit": 16,
    }, "mixed scope limits differ from the frozen fixed policy")
    # The canonical artifact records the ordinary ceiling. Derive the selected
    # profile from its separately frozen worker map without changing the artifact.
    domain = {**domain, "cpu": workers}
    limits = {
        "managed_bytes": domain["memory"],
        "disk_ops": domain["disk"],
        "network_ops": domain["network"],
        "tasks": domain["tasks"],
        "cpu_charges": domain["cpu"],
    }
    return limits, domain, scope


def _check_policy(policy_artifact: object, profile: str) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, dict[str, int]], str]:
    outer = exact_object(policy_artifact, {"schema", "policy", "policy_sha256"}, "fixed runtime policy artifact")
    require(outer["schema"] == POLICY_SCHEMA, "unsupported fixed runtime policy schema")
    policy = outer["policy"]
    require(type(policy) is dict and policy.get("schema") == POLICY_SCHEMA, "fixed runtime policy payload is malformed")
    policy_sha = hashlib.sha256(canonical_bytes(policy)).hexdigest()
    require(digest(outer["policy_sha256"], "fixed policy SHA-256") == policy_sha, "fixed policy digest is invalid")
    require(policy.get("comparison_family") == "fixed_policy" and policy.get("resource_policy") == "fixed_primary_v1", "soak fixed-policy contract differs")
    require(policy.get("logical_window") == LOGICAL_WINDOW and policy.get("task_ceiling") == TASK_CEILING, "fixed policy window/task ceiling differs")
    limits, domain, scope = _expected_mixed_limits(profile, policy)
    buckets = policy.get("byte_buckets")
    require(type(buckets) is dict and set(buckets) == set(DIRECTIONS), "fixed policy byte-bucket directions differ")
    normalized: dict[str, dict[str, int]] = {}
    for direction in DIRECTIONS:
        bucket = exact_object(
            buckets[direction],
            {"bytes_per_second", "ceiling_bytes_per_second", "burst_bytes", "ceiling_burst_bytes", "max_reservations"},
            f"fixed policy {direction} bucket",
        )
        expected = {
            "bytes_per_second": RATE_BYTES_PER_SECOND,
            "ceiling_bytes_per_second": RATE_BYTES_PER_SECOND,
            "burst_bytes": RATE_BURST_BYTES,
            "ceiling_burst_bytes": RATE_BURST_BYTES,
            "max_reservations": RATE_RESERVATIONS,
        }
        require(bucket == expected, f"fixed policy {direction} bucket differs from the frozen limits")
        normalized[direction] = expected
    return limits, domain, scope, normalized, policy_sha


def _validate_calibration(value: object, build: dict[str, Any], source: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    calibration = exact_object(
        value,
        {"binary", "output", "record", "source", "build", "build_sha256"},
        "resource-domain calibration",
    )
    require(calibration["source"] == {key: source[key] for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")}, "calibration source identity differs")
    require(calibration["build"] == build, "calibration build identity differs")
    build_sha = hashlib.sha256(canonical_bytes(build)).hexdigest()
    require(digest(calibration["build_sha256"], "calibration build SHA-256") == build_sha, "calibration build digest differs")
    baseline, record = _validate_calibration_record(calibration["record"])
    return baseline, calibration


def _validate_calibration_record(value: object) -> tuple[int, dict[str, Any]]:
    record = exact_object(
        value,
        {
            "schema", "architecture", "max_tenants", "max_waiters", "control_ceiling",
            "fixed_global_control_baseline", "tenant_owner_control_bytes", "final_live_tenants",
            "final_global_control_bytes",
        },
        "resource-domain calibration output record",
    )
    require(record["schema"] == CALIBRATION_SCHEMA and record["architecture"] == "x86_64", "calibration target/schema differs")
    for field, expected in (("max_tenants", CONTROL_MAX_TENANTS), ("max_waiters", CONTROL_MAX_WAITERS), ("control_ceiling", CONTROL_CEILING), ("final_live_tenants", 0)):
        require(uint(record[field], f"calibration {field}") == expected, f"calibration {field} differs from the fixed contract")
    baseline = uint(record["fixed_global_control_baseline"], "calibrated fixed global Control baseline", positive=True)
    require(baseline < CONTROL_CEILING, "calibrated Control baseline exceeds its ceiling")
    uint(record["tenant_owner_control_bytes"], "calibrated tenant Control bytes")
    require(uint(record["final_global_control_bytes"], "calibrated final global Control bytes") == baseline, "calibration did not return global Control to baseline")
    return baseline, record


def _audit_manifest_and_binaries(
    recipe: dict[str, Any], *, offline_context: dict[str, Any] | None = None,
    source5_probe_capture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if recipe["schema"] == RECIPE_SCHEMA_V2:
        return _audit_manifest_and_binaries_v5(
            recipe, offline_context=offline_context,
            source5_probe_capture=source5_probe_capture,
        )
    require(offline_context is None,
            "receipt-backed offline Soak replay supports only the original SourceV5 recipe")
    identity = recipe["identity"]
    source_config = recipe["source"]
    source_root = safe_absolute_path(source_config["root"], "source root")
    manifest_path = safe_absolute_path(source_config["manifest_path"], "source manifest path")
    manifest, manifest_sha, manifest_raw = read_json(manifest_path, "source manifest", MAX_MANIFEST_BYTES)
    require(manifest_raw == canonical_bytes(manifest), "source manifest is not canonical JSON")
    require(manifest_sha == source_config["manifest_sha256"], "source manifest bytes differ from the frozen SHA-256")
    expected_manifest_keys = {
        "schema", "source", "build", "artifacts", "soak_artifacts", "analysis_artifact",
        "fixed_runtime_policy", "runtime_readback_validator", "resource_domain_calibration", "manifest_sha256",
    }
    exact_object(manifest, expected_manifest_keys, "source manifest")
    require(manifest["schema"] == SOURCE_SCHEMA, "unsupported source manifest schema")
    manifest_without_hash = dict(manifest)
    manifest_without_hash.pop("manifest_sha256")
    manifest_hash = hashlib.sha256(canonical_bytes(manifest_without_hash)).hexdigest()
    require(digest(manifest["manifest_sha256"], "manifest internal digest") == manifest_hash, "source manifest internal digest is invalid")
    source = exact_object(manifest["source"], {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "source manifest source")
    build = exact_object(
        manifest["build"],
        {"host_id", "rustc_release", "rustc_verbose", "cargo_version", "target_triple", "target_cpu", "profile", "features_sha256", "build_inputs_sha256"},
        "source manifest build",
    )
    require(source["source_tree_sha256"] == identity["source_sha256"], "source tree pin differs from the parent recipe")
    build_sha = hashlib.sha256(canonical_bytes(build)).hexdigest()
    require(build_sha == identity["build_sha256"], "build identity differs from the parent recipe")
    require(build["host_id"] == identity["host_id"], "build manifest host differs from the soak host")
    require(build["rustc_release"] == "1.99.0" and build["profile"] == "release", "soak binary build is not the frozen Rust 1.99 release build")
    require(build["target_triple"] == "x86_64-unknown-linux-gnu" and build["target_cpu"] == "x86-64-v3", "soak target differs from the frozen amd64-v3 build")
    digest(build["features_sha256"], "build features SHA-256")
    digest(build["build_inputs_sha256"], "build inputs SHA-256")
    files = source["files"]
    inventory_module = source_inventory_module()
    try:
        validated_files = inventory_module.validate_records({
            "schema": inventory_module.SCHEMA,
            "entries": files,
        })
    except inventory_module.InventoryError as error:
        raise SoakReadbackError(f"source manifest has an invalid typed inventory: {error}") from error
    require(validated_files == files, "source manifest inventory records are not canonical")
    inventory_module_pin = next(
        (entry for entry in validated_files if entry["path"] == SOURCE_INVENTORY_RELATIVE_PATH),
        None,
    )
    require(
        type(inventory_module_pin) is dict
        and inventory_module_pin["kind"] == "file"
        and inventory_module_pin["sha256"] == SOURCE_INVENTORY_MODULE_SHA256,
        "source inventory does not bind the frozen regular shared inventory module bytes",
    )
    inventory_module_path = safe_child(source_root, SOURCE_INVENTORY_RELATIVE_PATH, "shared source inventory module")
    require(
        sha256_file(inventory_module_path, "shared source inventory module", MAX_SOURCE_FILE_BYTES)
        == SOURCE_INVENTORY_MODULE_SHA256,
        "source-root inventory module bytes differ from the module executed by the readback",
    )
    inventory_hash = inventory_module.digest_records(validated_files)
    require(inventory_hash == source["source_tree_sha256"], "typed source inventory does not produce its frozen digest")
    live_source_tree_sha = verify_source_tree(source_root, source)
    require(live_source_tree_sha == identity["source_sha256"], "live source tree differs from the parent recipe")

    artifacts = manifest["artifacts"]
    soak_artifacts = manifest["soak_artifacts"]
    require(type(artifacts) is dict and set(artifacts) == set(ALLOCATORS), "source manifest normal binary set is incomplete")
    require(
        type(soak_artifacts) is dict
        and "allocatbelt" in soak_artifacts
        and set(soak_artifacts).issubset(ALLOCATORS),
        "source manifest soak binaries require allocatbelt and may name only known allocators",
    )
    normal_pins: dict[str, tuple[Path, str]] = {}
    used_binary_paths: set[Path] = set()
    for allocator in ALLOCATORS:
        pin = exact_object(artifacts[allocator], {"path", "sha256"}, f"{allocator} application binary pin")
        path = safe_child(source_root, pin["path"], f"{allocator} application binary")
        checksum = digest(pin["sha256"], f"{allocator} application binary SHA-256")
        require(path not in used_binary_paths, "source manifest aliases normal application binaries")
        used_binary_paths.add(path)
        require(path.stat().st_mode & 0o111 != 0, f"{allocator} application binary is not executable")
        require(sha256_file(path, f"{allocator} application binary") == checksum, f"{allocator} application binary differs from its source-manifest pin")
        normal_pins[allocator] = (path, checksum)

    soak_pins: dict[str, tuple[Path, str]] = {}
    for allocator, pin_value in soak_artifacts.items():
        pin = exact_object(pin_value, {"path", "sha256"}, f"{allocator} soak binary pin")
        path = safe_child(source_root, pin["path"], f"{allocator} soak binary")
        checksum = digest(pin["sha256"], f"{allocator} soak binary SHA-256")
        require(path not in used_binary_paths, "source manifest aliases normal and dedicated soak binaries")
        used_binary_paths.add(path)
        require(path.stat().st_mode & 0o111 != 0, f"{allocator} soak binary is not executable")
        require(sha256_file(path, f"{allocator} soak binary") == checksum, f"{allocator} soak binary differs from its source-manifest pin")
        soak_pins[allocator] = (path, checksum)

    analysis_pin = exact_object(manifest["analysis_artifact"], {"path", "sha256"}, "analysis binary pin")
    analysis_path = safe_child(source_root, analysis_pin["path"], "analysis binary")
    analysis_sha = digest(analysis_pin["sha256"], "analysis binary SHA-256")
    require(analysis_path not in used_binary_paths, "source manifest aliases its analyzer with an application binary")
    require(sha256_file(analysis_path, "analysis binary") == analysis_sha, "analysis binary differs from its source-manifest pin")

    normal_pin_path, producer_sha = normal_pins["allocatbelt"]
    candidate_path, candidate_sha = soak_pins["allocatbelt"]
    producer_path = normal_pin_path
    require(candidate_sha == identity["binary_sha256"], "source-manifest soak binary differs from the parent recipe")
    oracle = recipe["oracle"]
    require(safe_absolute_path(oracle["producer_path"], "oracle producer path") == producer_path, "oracle producer path is not the separately pinned allocatbelt oracle binary")
    require(digest(oracle["producer_sha256"], "oracle producer SHA-256") == producer_sha, "oracle producer SHA differs from the source manifest")
    candidate_actual_sha = sha256_file(candidate_path, "candidate soak binary")
    producer_actual_sha = sha256_file(producer_path, "oracle producer binary")
    require(candidate_actual_sha == candidate_sha, "candidate soak binary changed before launch")
    require(producer_actual_sha == producer_sha, "oracle producer binary changed before launch")

    limits, domain, scope, buckets, policy_sha = _check_policy(manifest["fixed_runtime_policy"], identity["profile"])
    require(recipe["runtime"]["resource_limits"] == limits, "parent resource limits differ from the frozen fixed policy")
    ceiling_sha = hashlib.sha256(canonical_bytes(limits)).hexdigest()
    require(ceiling_sha == identity["resource_ceiling_sha256"], "resource-ceiling SHA does not bind the frozen numeric limits")
    baseline, calibration = _validate_calibration(manifest["resource_domain_calibration"], build, source)
    require(recipe["runtime"]["fixed_global_control_baseline"] == baseline, "parent Control baseline differs from the independent calibration")
    calibration_binary = exact_object(calibration["binary"], {"path", "sha256"}, "calibration binary")
    calibration_binary_path = safe_child(source_root, calibration_binary["path"], "calibration binary")
    calibration_binary_sha = digest(calibration_binary["sha256"], "calibration binary SHA-256")
    require(calibration_binary_path not in used_binary_paths and calibration_binary_path != analysis_path, "calibration binary aliases another source artifact")
    require(sha256_file(calibration_binary_path, "calibration binary") == calibration_binary_sha, "calibration binary differs from the source manifest")
    calibration_output = exact_object(calibration["output"], {"path", "sha256"}, "calibration output")
    calibration_output_path = safe_child(source_root, calibration_output["path"], "calibration output")
    require(calibration_output_path not in used_binary_paths and calibration_output_path != analysis_path and calibration_output_path != calibration_binary_path, "calibration output aliases another source artifact")
    calibration_output_sha = digest(calibration_output["sha256"], "calibration output SHA-256")
    actual_calibration, actual_calibration_sha, _actual_calibration_raw = read_json(
        calibration_output_path,
        "pinned resource-domain calibration output",
        MAX_RECEIPT_BYTES,
    )
    require(actual_calibration_sha == calibration_output_sha, "pinned calibration output bytes differ from their source-manifest SHA")
    actual_baseline, actual_calibration = _validate_calibration_record(actual_calibration)
    require(actual_calibration == calibration["record"], "pinned calibration output record differs from the source-manifest record")
    require(actual_baseline == baseline, "numeric Control baseline does not come from the pinned calibration output bytes")
    baseline = actual_baseline

    validator = exact_object(manifest["runtime_readback_validator"], {"path", "sha256"}, "runtime validator pin")
    validator_path = safe_child(source_root, validator["path"], "runtime validator source")
    require(sha256_file(validator_path, "runtime validator source") == digest(validator["sha256"], "runtime validator SHA"), "runtime validator source changed")
    for tool_name in ("validator", "runner"):
        tool = recipe[tool_name]
        path = safe_child(source_root, tool["path"], f"soak {tool_name} source")
        require(sha256_file(path, f"soak {tool_name} source") == digest(tool["sha256"], f"soak {tool_name} SHA"), f"soak {tool_name} differs from its parent pin")
    return {
        "source_manifest_sha256": manifest_sha,
        "source_tree_sha256": live_source_tree_sha,
        "build_sha256": build_sha,
        "candidate_binary_path": str(candidate_path),
        "candidate_binary_sha256": candidate_actual_sha,
        "normal_application_artifacts": {name: checksum for name, (_path, checksum) in normal_pins.items()},
        "declared_soak_artifacts": {name: checksum for name, (_path, checksum) in soak_pins.items()},
        "analysis_binary_sha256": analysis_sha,
        "oracle_producer_path": str(producer_path),
        "oracle_producer_binary_sha256": producer_actual_sha,
        "resource_limits": limits,
        "domain_ceilings": domain,
        "scope_limits": scope,
        "byte_buckets": buckets,
        "fixed_policy_sha256": policy_sha,
        "fixed_global_control_baseline": baseline,
        "calibration_binary_sha256": calibration_binary_sha,
        "calibration_output_sha256": actual_calibration_sha,
        "source_root": str(source_root),
        "source_manifest_path": str(manifest_path),
    }


def _audit_manifest_and_binaries_v5(
    recipe: dict[str, Any], *, offline_context: dict[str, Any] | None = None,
    source5_probe_capture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify SourceV5 through the exact controller bytes in its inventory."""
    identity = recipe["identity"]
    source_binding = recipe["source"]
    source_root = safe_absolute_path(source_binding["root"], "SourceV5 source root")
    manifest_path = safe_absolute_path(source_binding["manifest_path"], "SourceV5 source manifest path")
    manifest, manifest_raw_sha, manifest_raw = read_json(manifest_path, "SourceV5 source manifest", MAX_MANIFEST_BYTES)
    require(manifest_raw == canonical_bytes(manifest), "SourceV5 source manifest is not canonical JSON")
    require(manifest_raw_sha == source_binding["manifest_sha256"], "SourceV5 manifest raw bytes differ from the parent recipe")
    base_keys = {
        "schema", "source", "build", "artifacts", "soak_artifacts", "analysis_artifact",
        "fixed_runtime_policy", "runtime_readback_validator", "resource_domain_calibration", "manifest_sha256",
    }
    exact_object(manifest, base_keys | {"qualification_harness", "feedback_policy"}, "SourceV5 manifest")
    require(manifest["schema"] == SOURCE_SCHEMA_V5, "SourceV5 parent recipe requires SourceV5")
    body = dict(manifest)
    internal_sha = body.pop("manifest_sha256")
    require(digest(internal_sha, "SourceV5 manifest semantic digest") == hashlib.sha256(canonical_bytes(body)).hexdigest(), "SourceV5 manifest semantic digest is invalid")
    source = exact_object(manifest["source"], {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "SourceV5 source identity")
    require(source["source_tree_sha256"] == identity["source_sha256"], "SourceV5 source tree differs from parent identity")
    build = exact_object(manifest["build"], {
        "host_id", "rustc_release", "rustc_verbose", "cargo_version", "target_triple", "target_cpu", "profile", "features_sha256", "build_inputs_sha256",
    }, "SourceV5 build identity")
    require(build["host_id"] == identity["host_id"], "SourceV5 build host differs from parent identity")
    build_sha = hashlib.sha256(canonical_bytes(build)).hexdigest()
    require(build_sha == identity["build_sha256"], "SourceV5 build digest differs from parent identity")
    files = source["files"]
    inventory_module = source_inventory_module()
    try:
        validated_files = inventory_module.validate_records({"schema": inventory_module.SCHEMA, "entries": files})
    except inventory_module.InventoryError as error:
        raise SoakReadbackError(f"SourceV5 typed inventory is invalid: {error}") from error
    require(validated_files == files and inventory_module.digest_records(files) == source["source_tree_sha256"], "SourceV5 inventory does not produce its declared tree digest")
    inventory_entry = next((entry for entry in files if entry["path"] == SOURCE_INVENTORY_RELATIVE_PATH), None)
    require(type(inventory_entry) is dict and inventory_entry.get("kind") == "file" and inventory_entry.get("sha256") == SOURCE_INVENTORY_MODULE_SHA256, "SourceV5 inventory module pin differs from the reader")
    live_tree = verify_source_tree(source_root, source, offline_context=offline_context)
    require(live_tree == identity["source_sha256"], "live SourceV5 tree differs from the parent identity")

    harness = exact_object(manifest["qualification_harness"], {
        "campaign_controller", "feedback_validator", "byte_capacity_producer", "pressure_driver",
        "pressure_validator", "soak_recipe_builder", "soak_validator", "soak_runner",
    }, "SourceV5 qualification harness")
    harness_expected = {
        "campaign_controller": "scripts/application-campaign.py",
        "feedback_validator": "scripts/application-feedback-readback.py",
        "byte_capacity_producer": "scripts/application-byte-capacity.py",
        "pressure_driver": "scripts/application-pressure-driver.py",
        "pressure_validator": "scripts/application-pressure-readback.py",
        "soak_recipe_builder": "scripts/application-soak-recipe.py",
        "soak_validator": "scripts/application-soak-readback.py",
        "soak_runner": "scripts/run-application-soak.sh",
    }
    records = {item["path"]: item for item in files}
    for name, path_text in harness_expected.items():
        pin = exact_object(harness[name], {"path", "sha256"}, f"SourceV5 harness {name}")
        record = records.get(path_text)
        require(pin["path"] == path_text and type(record) is dict and record.get("kind") == "file" and record.get("sha256") == pin["sha256"], f"SourceV5 harness {name} is not bound to its exact regular inventory bytes")
    controller_pin = harness["campaign_controller"]
    controller_path = safe_child(source_root, controller_pin["path"], "captured SourceV5 controller")
    controller_raw, controller_sha = read_stable_bytes(controller_path, "captured SourceV5 controller", MAX_SOURCE_FILE_BYTES)
    require(controller_sha == controller_pin["sha256"], "captured SourceV5 controller differs from its inventory pin")
    controller = types.ModuleType(f"soak_source_v5_controller_{controller_sha}")
    controller.__file__ = str(controller_path)
    controller.__package__ = ""
    try:
        exec(compile(controller_raw, str(controller_path), "exec", dont_inherit=True), controller.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise SoakReadbackError(f"pinned SourceV5 controller cannot be compiled: {error}") from error
    require(getattr(controller, "SOURCE_SCHEMA_V5", None) == SOURCE_SCHEMA_V5 and callable(getattr(controller, "verify_source_manifest", None)), "captured SourceV5 controller has no full verifier")
    try:
        controller.verify_source_manifest(manifest, source_root=source_root, verify_artifacts=True)
    except (OSError, TypeError, ValueError, getattr(controller, "CampaignError", ValueError)) as error:
        raise SoakReadbackError(f"captured SourceV5 full verifier rejected the manifest: {error}") from error

    app_artifacts = exact_object(manifest["artifacts"], set(ALLOCATORS), "SourceV5 application artifacts")
    normal_pin = exact_object(app_artifacts["allocatbelt"], {"path", "sha256"}, "SourceV5 allocatbelt application artifact")
    normal_path = safe_child(source_root, normal_pin["path"], "SourceV5 allocatbelt application binary")
    normal_sha = digest(normal_pin["sha256"], "SourceV5 allocatbelt application binary SHA-256")
    require(normal_path.stat().st_mode & 0o111 != 0 and sha256_file(normal_path, "SourceV5 allocatbelt application binary") == normal_sha, "SourceV5 allocatbelt application artifact changed")
    soak_artifacts = manifest["soak_artifacts"]
    require(type(soak_artifacts) is dict and "allocatbelt" in soak_artifacts, "SourceV5 source omits the timed allocatbelt soak binary")
    soak_pin = exact_object(soak_artifacts["allocatbelt"], {"path", "sha256"}, "SourceV5 allocatbelt soak artifact")
    soak_path = safe_child(source_root, soak_pin["path"], "SourceV5 allocatbelt soak binary")
    soak_sha = digest(soak_pin["sha256"], "SourceV5 allocatbelt soak binary SHA-256")
    require(soak_path.stat().st_mode & 0o111 != 0 and sha256_file(soak_path, "SourceV5 allocatbelt soak binary") == soak_sha, "SourceV5 allocatbelt soak artifact changed")
    require(soak_sha == identity["binary_sha256"], "timed soak binary differs from the SourceV5 soak artifact pin")
    probe = recipe["construction_probe"]
    require(probe["allocator"] == "allocatbelt" and probe["binary_sha256"] == normal_sha, "construction probe is not tied to the SourceV5 normal allocatbelt artifact")
    require(normal_sha != soak_sha, "SourceV5 construction probe artifact and timed soak artifact must remain distinct")
    probe_path = safe_absolute_path(probe["path"], "SourceV5 construction policy probe")
    probe_value, probe_raw_sha, probe_raw = read_json(probe_path, "SourceV5 construction policy probe", 512 * 1024)
    require(probe_raw == canonical_bytes(probe_value) and probe_raw_sha == probe["raw_sha256"], "SourceV5 construction probe raw bytes differ from their frozen pin")
    floor_policy_id = recipe["feedback_expectation"]["policy"].get(
        "capacity_floor_policy_id",
    )
    require((floor_policy_id is None and probe_value.get("schema") ==
             "allocatbelt.application-feedback-policy-probe.v1") or
            (type(floor_policy_id) is str and probe_value.get("schema") ==
             "allocatbelt.application-feedback-policy-probe.v2"),
            "SourceV5 construction probe schema does not match the selected policy")
    require(probe_value.get("context", {}).get("workload") == "mixed" and probe_value.get("context", {}).get("profile") == identity["profile"], "SourceV5 construction probe context differs from the soak profile")
    selected_probe_context = None
    selected_capacity_artifact_pin = None
    if offline_context is None and floor_policy_id is None:
        probe_process = subprocess.run(
            [str(normal_path), "--emit-feedback-policy-only", "--workload", "mixed", "--profile", identity["profile"]],
            cwd=source_root,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        require(len(probe_process.stdout) <= 512 * 1024 and len(probe_process.stderr) <= 64 * 1024, "SourceV5 construction probe process exceeded its finite output bound")
        require(probe_process.returncode == 0 and probe_process.stdout == probe_raw, "pinned SourceV5 application binary no longer emits the caller-frozen construction probe")
    elif floor_policy_id is None:
        capture = exact_object(offline_context["construction_probe_capture"], {
            "schema", "source_manifest_raw_sha256", "source_tree_sha256",
            "normal_binary_sha256", "probe_raw_sha256", "owner_source_sha256",
            "owner_result", "stdout", "stderr", "argv", "environment",
            "cwd", "cpu_affinity", "network_namespace_inode",
            "tmpdir_path", "tmpdir_receipt_sha256",
        }, "Source5 origin construction-probe capture")
        expected_probe_argv = [
            str(normal_path), "--emit-feedback-policy-only", "--workload",
            "mixed", "--profile", identity["profile"],
        ]
        expected_environment = {
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "TMPDIR": capture["tmpdir_path"],
        }
        owner_result = exact_object(capture["owner_result"], {
            "status", "child_return_code", "start", "binary_path",
            "binary_sha256", "requested_argv", "requested_argv_sha256",
            "environment", "environment_sha256", "cwd", "cpu_affinity",
            "network_namespace_inode", "received_signal", "supervision",
            "timing", "started_monotonic_ns", "ended_monotonic_ns",
        }, "Source5 captured construction-probe owner result")
        start = exact_object(owner_result["start"], {
            "pid", "start_ticks", "requested_argv", "requested_argv_sha256",
            "environment_sha256",
        }, "Source5 captured construction-probe start identity")
        supervision = owner_result["supervision"]
        owner_source_record = records.get("scripts/application-fixed-pair.py")
        require(type(supervision) is dict and
                type(owner_source_record) is dict and
                owner_source_record.get("kind") == "file" and
                owner_source_record.get("sha256") == capture["owner_source_sha256"] and
                supervision.get("cleanup_status") == "verified" and
                supervision.get("leader_reaped") is True and
                supervision.get("group_signal_after_leader_reap_count") == 0 and
                supervision.get("timed_out") is False and
                supervision.get("artifact_budget_exceeded") is False and
                owner_result["status"] == owner_result["child_return_code"] == 0 and
                owner_result["received_signal"] is None and
                type(start["pid"]) is int and start["pid"] > 0 and
                type(start["start_ticks"]) is int and start["start_ticks"] > 0 and
                owner_result["binary_path"] == str(normal_path) and
                owner_result["binary_sha256"] == normal_sha and
                owner_result["requested_argv"] == start["requested_argv"] == expected_probe_argv and
                owner_result["requested_argv_sha256"] == hashlib.sha256(canonical_bytes(expected_probe_argv)).hexdigest() and
                owner_result["environment"] == expected_environment and
                owner_result["environment_sha256"] == hashlib.sha256(canonical_bytes(expected_environment)).hexdigest() and
                owner_result["cwd"] == str(source_root) and
                owner_result["cpu_affinity"] == capture["cpu_affinity"] and
                owner_result["network_namespace_inode"] == capture["network_namespace_inode"] and
                capture["schema"] == "allocatbelt.application-source5-soak-probe-capture.v1" and
                capture["source_manifest_raw_sha256"] == manifest_raw_sha and
                capture["source_tree_sha256"] == source["source_tree_sha256"] and
                capture["normal_binary_sha256"] == normal_sha and
                capture["probe_raw_sha256"] == probe_raw_sha and
                capture["argv"] == expected_probe_argv and
                capture["environment"] == expected_environment and
                capture["cwd"] == str(source_root) and
                type(capture["cpu_affinity"]) is list and
                capture["cpu_affinity"] == sorted(set(capture["cpu_affinity"])) and
                type(capture["network_namespace_inode"]) is int and
                capture["network_namespace_inode"] > 0 and
                type(capture["tmpdir_path"]) is str and
                Path(capture["tmpdir_path"]).is_absolute() and
                re.fullmatch(r"[0-9a-f]{64}", str(capture["owner_source_sha256"])) is not None and
                re.fullmatch(r"[0-9a-f]{64}", str(capture["tmpdir_receipt_sha256"])) is not None,
                "Source5 captured ProbeV1 owner/source/environment differs from the parent recipe")
        stdout = exact_object(capture["stdout"], {"path", "raw_sha256"},
                              "Source5 captured construction-probe stdout pin")
        stderr = exact_object(capture["stderr"], {"path", "raw_sha256"},
                              "Source5 captured construction-probe stderr pin")
        stdout_raw, stdout_sha = read_stable_bytes(
            Path(stdout["path"]), "Source5 captured construction-probe stdout",
            512 * 1024,
        )
        stderr_raw, stderr_sha = read_stable_bytes(
            Path(stderr["path"]), "Source5 captured construction-probe stderr",
            64 * 1024,
        )
        require(stdout_sha == stdout["raw_sha256"] == probe_raw_sha and
                stdout_raw == probe_raw and stderr_sha == stderr["raw_sha256"] and
                stderr_raw == b"",
                "Source5 origin ProbeV1 stdout/stderr differ from the source-pinned construction probe")
    else:
        selected_probe_context = source5_probe_capture
        if selected_probe_context is None and offline_context is not None:
            selected_probe_context = offline_context.get("construction_probe_capture")
        selected_probe_context = exact_object(selected_probe_context, {
            "schema", "capture_pin", "capture", "probe", "probe_raw",
            "probe_raw_sha256", "capacity_bundle", "capacity_floor_policy_id",
            "normal_binary_sha256", "request",
        }, "Source5 selected ProbeV2 audit context")
        require(selected_probe_context["schema"] ==
                    "allocatbelt.application-source5-soak-probe-audit-context.v2" and
                selected_probe_context["probe"] == probe_value and
                selected_probe_context["probe_raw"] == probe_raw and
                selected_probe_context["probe_raw_sha256"] == probe_raw_sha and
                selected_probe_context["capacity_floor_policy_id"] == floor_policy_id and
                selected_probe_context["normal_binary_sha256"] == normal_sha,
                "Source5 selected ProbeV2 context differs from its original pinned inputs")
        capture_pin = exact_object(selected_probe_context["capture_pin"], {
            "path", "raw_sha256", "receipt_sha256",
        }, "Source5 ProbeV2 capture receipt pin")
        capture, capture_raw, capture_raw_sha = read_json(
            Path(capture_pin["path"]), capture_pin["raw_sha256"],
            "Source5 selected ProbeV2 capture receipt", 16 * 1024 * 1024,
        )
        require(capture == selected_probe_context["capture"] and
                capture_raw_sha == capture_pin["raw_sha256"] and
                capture.get("schema") ==
                    "allocatbelt.application-feedback-probe-capture.v2" and
                capture.get("receipt_sha256") == capture_pin["receipt_sha256"] and
                capture.get("probe_pin") == probe and
                capture.get("probe_raw_sha256") == probe_raw_sha and
                capture.get("normal_binary_sha256") == normal_sha and
                capture.get("source_manifest", {}).get("raw_sha256") == manifest_raw_sha and
                capture.get("source_manifest", {}).get("source_tree_sha256") ==
                    source["source_tree_sha256"] and
                capture.get("capacity_bundle") ==
                    selected_probe_context["capacity_bundle"] and
                capture.get("exit_status") == 0 and
                capture.get("output_matches_probe") is True and
                capture.get("stderr_empty") is True,
                "Source5 selected ProbeV2 capture receipt differs from its owner/source context")
        bundle = exact_object(selected_probe_context["capacity_bundle"], {
            "request", "artifact", "receipt",
        }, "Source5 selected ProbeV2 capacity bundle")
        probe_request = exact_object(selected_probe_context["request"], {
            "schema", "source_root", "source_manifest", "context",
            "construction_probe", "capacity_bundle",
            "capacity_floor_policy_id",
        }, "Source5 selected ProbeV2 composition request")
        probe_request_source = exact_object(
            probe_request["source_manifest"], {"path", "raw_sha256"},
            "Source5 ProbeV2 request SourceV5 pin",
        )
        probe_request_context = exact_object(probe_request["context"], {
            "host_id", "workload", "profile", "calibration_id",
        }, "Source5 ProbeV2 request context")
        require(probe_request["schema"] ==
                    "allocatbelt.application-feedback-composition-request.v2" and
                probe_request["source_root"] == str(source_root) and
                probe_request_source == {
                    "path": recipe["source"]["manifest_path"],
                    "raw_sha256": manifest_raw_sha,
                } and
                probe_request_context == {
                    "host_id": identity["host_id"], "workload": "mixed",
                    "profile": identity["profile"],
                    "calibration_id": recipe["qualification"]["capacity_template"][
                        "calibration_id"],
                } and
                probe_request["construction_probe"] == probe and
                probe_request["capacity_bundle"] == bundle and
                probe_request["capacity_floor_policy_id"] == floor_policy_id,
                "Source5 selected ProbeV2 request differs from its captured receipt")
        for label, pin_value in bundle.items():
            capacity_pin = exact_object(pin_value, {"path", "raw_sha256"},
                                         f"Source5 selected ProbeV2 capacity {label}")
            safe_absolute_path(capacity_pin["path"],
                               f"Source5 selected ProbeV2 capacity {label} path")
            digest(capacity_pin["raw_sha256"],
                   f"Source5 selected ProbeV2 capacity {label} SHA-256")
        capacity_evidence = recipe["qualification"]["capacity_template"]["evidence"]
        input_root = Path(recipe["qualification"]["spec"]["path"]).resolve(strict=True).parent
        expected_capacity_artifact = safe_child(
            input_root, capacity_evidence["artifact"]["relative_path"],
            "Source5 selected ProbeV2 capacity artifact",
        )
        require(bundle["artifact"]["path"] == str(expected_capacity_artifact) and
                bundle["artifact"]["raw_sha256"] ==
                    capacity_evidence["artifact"]["raw_sha256"],
                "Source5 ProbeV2 capacity artifact differs from the original recipe evidence")
        selected_capacity_artifact_pin = bundle["artifact"]
        argv = [
            str(normal_path), "--emit-feedback-policy-only", "--workload", "mixed",
            "--profile", identity["profile"], "--capacity-calibration-file",
            selected_capacity_artifact_pin["path"], "--capacity-calibration-sha256",
            selected_capacity_artifact_pin["raw_sha256"], "--host-id",
            identity["host_id"], "--source-sha256", identity["source_sha256"],
            "--capacity-floor-policy-id", floor_policy_id,
        ]
        require(capture.get("probe_argv") == argv and
                type(capture.get("environment")) is dict and
                capture["environment"].get("PATH") == "/usr/bin:/bin" and
                capture["environment"].get("TMPDIR") ==
                    capture.get("tmpdir_initial", {}).get("path") and
                capture.get("cwd") == str(source_root) and
                type(capture.get("affinity")) is list and
                capture["affinity"] == sorted(set(capture["affinity"])) and
                type(capture.get("netns")) is int and capture["netns"] > 0,
                "Source5 selected ProbeV2 argv/environment/host identity differs from its frozen context")
        stdout_pin = exact_object(capture["stdout"], {"path", "raw_sha256"},
                                  "Source5 ProbeV2 stdout pin")
        stderr_pin = exact_object(capture["stderr"], {"path", "raw_sha256"},
                                  "Source5 ProbeV2 stderr pin")
        stdout_raw, stdout_sha = read_stable_bytes(
            Path(stdout_pin["path"]), "Source5 selected ProbeV2 stdout", 512 * 1024,
        )
        stderr_raw, stderr_sha = read_stable_bytes(
            Path(stderr_pin["path"]), "Source5 selected ProbeV2 stderr", 64 * 1024,
        )
        require(stdout_sha == stdout_pin["raw_sha256"] == probe_raw_sha and
                stdout_raw == probe_raw and stderr_sha == stderr_pin["raw_sha256"] and
                stderr_raw == b"",
                "Source5 actual ProbeV2 owner stdout/stderr differs from its pinned construction probe")
    feedback_validator_pin = manifest["qualification_harness"]["feedback_validator"]
    feedback_validator_path = safe_child(source_root, feedback_validator_pin["path"], "SourceV5 feedback validator")
    feedback_validator_raw, feedback_validator_sha = read_stable_bytes(feedback_validator_path, "SourceV5 feedback validator", MAX_SOURCE_FILE_BYTES)
    require(feedback_validator_sha == feedback_validator_pin["sha256"], "SourceV5 feedback validator differs from its harness pin")
    feedback_module = types.ModuleType(f"soak_source_v5_feedback_{feedback_validator_sha}")
    feedback_module.__file__ = str(feedback_validator_path)
    feedback_module.__package__ = ""
    try:
        exec(compile(feedback_validator_raw, str(feedback_validator_path), "exec", dont_inherit=True), feedback_module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise SoakReadbackError(f"captured SourceV5 feedback validator cannot be compiled: {error}") from error
    if selected_probe_context is not None:
        require(callable(getattr(feedback_module,
                                 "validate_probe_capture_receipt_envelope", None)),
                "captured SourceV5 feedback validator lacks ProbeV2 receipt validation")
        try:
            checked_capture = feedback_module.validate_probe_capture_receipt_envelope(
                capture_raw, capture_pin["raw_sha256"],
                capture_pin["receipt_sha256"],
            )
        except Exception as error:
            raise SoakReadbackError(
                f"captured SourceV5 feedback validator rejected the ProbeV2 owner receipt: {error}",
            ) from error
        require(checked_capture == capture,
                "captured SourceV5 feedback validator returned another ProbeV2 receipt")
    feedback_artifact = manifest["feedback_policy"]
    feedback_context_key = f"mixed/{identity['profile']}"
    contexts = feedback_artifact["policy"]["contexts"]
    require(feedback_context_key in contexts, "SourceV5 feedback policy omits the selected mixed context")
    feedback = recipe["feedback_expectation"]
    require(feedback["validator"] == harness["feedback_validator"], "SourceV5 feedback expectation validator differs from the source harness pin")
    trace_identity = feedback["trace_identity"]
    require(
        trace_identity["host_id"] == identity["host_id"]
        and trace_identity["run_id"] == identity["run_id"]
        and trace_identity["report_nonce"] == identity["nonce"]
        and trace_identity["allocator"] == "allocatbelt"
        and trace_identity["executor"] == "allocatbelt"
        and trace_identity["workload"] == "mixed"
        and trace_identity["profile"] == identity["profile"]
        and trace_identity["mode"] == "pressure_soak_validation"
        and trace_identity["source_sha256"] == identity["source_sha256"]
        and trace_identity["binary_sha256"] == identity["binary_sha256"]
        and trace_identity["pressure_qualification"] is True,
        "SourceV5 feedback trace identity does not bind the timed soak process role",
    )
    probe_policy = feedback["policy"]
    require(probe_policy["version"] == feedback_artifact["policy"]["version"], "constructed feedback policy version differs from SourceV5")
    if floor_policy_id is None:
        require(probe_policy["controls"] == contexts[feedback_context_key]["controls"], "constructed feedback controls differ from SourceV5 numeric context")
    else:
        require(selected_capacity_artifact_pin is not None and
                callable(getattr(feedback_module,
                                 "resolve_calibrated_feedback_policy_v5", None)) and
                callable(getattr(feedback_module,
                                 "_check_calibrated_construction_probe_v2_inputs", None)),
                "captured SourceV5 feedback validator lacks selected ProbeV2 APIs")
        probe_identity = {
            "host_id": identity["host_id"], "workload": "mixed",
            "profile": identity["profile"], "allocator": "allocatbelt",
            "source_sha256": identity["source_sha256"],
            "binary_sha256": normal_sha,
        }
        try:
            resolved_floor_policy = feedback_module.resolve_calibrated_feedback_policy_v5(
                manifest, probe_value, selected_capacity_artifact_pin,
                probe_identity, capacity_floor_policy_id=floor_policy_id,
            )
            feedback_module._check_calibrated_construction_probe_v2_inputs(
                probe, manifest, selected_capacity_artifact_pin, probe_identity,
                resolved_floor_policy, floor_policy_id,
            )
        except Exception as error:
            raise SoakReadbackError(
                f"captured SourceV5 feedback validator rejected the owned ProbeV2/capacity policy: {error}",
            ) from error
        require(probe_policy == resolved_floor_policy and
                probe_policy.get("capacity_floor_policy_id") == floor_policy_id and
                feedback_module.CAPACITY_FLOOR_POLICY_ID == floor_policy_id,
                "constructed SourceV5 feedback policy differs from independent ProbeV2 resolution")
        source_floor_policy = feedback_artifact["policy"].get(
            "capacity_floor_policy",
        )
        require(type(source_floor_policy) is dict and
                source_floor_policy.get("policy_id") == floor_policy_id,
                "selected capacity-floor policy is absent from SourceV5 numeric policy")
    require(probe_policy["sample_interval_ns"] == feedback_artifact["policy"]["reader_contract"]["sample_interval_ns"] and probe_policy["minimum_dense_observations"] == contexts[feedback_context_key]["minimum_dense_observations"], "constructed feedback reader policy differs from SourceV5 policy")
    if floor_policy_id is None:
        probe_expectation = {
            "schema": feedback_module.EXPECTATION_SCHEMA_V3,
            "identity": {"allocator": "allocatbelt", "binary_sha256": soak_sha, "workload": "mixed", "profile": identity["profile"]},
            "construction_probe": recipe["construction_probe"],
            "policy": probe_policy,
        }
        try:
            feedback_module.validate_construction_probe(probe_expectation, manifest)
        except (OSError, TypeError, ValueError, getattr(feedback_module, "ValidationError", ValueError)) as error:
            raise SoakReadbackError(f"captured SourceV5 feedback validator rejected the pinned construction probe/policy: {error}") from error
    expected_source_baseline = uint(manifest["resource_domain_calibration"]["record"]["fixed_global_control_baseline"], "SourceV5 calibrated global Control baseline", positive=True)
    require(probe_policy["collector"]["expected_global_control_baseline"] == expected_source_baseline, "feedback construction probe baseline differs from SourceV5 resource calibration")

    fixed_limits, domain, scope, buckets, fixed_policy_sha = _check_policy(manifest["fixed_runtime_policy"], identity["profile"])
    require(canonical_bytes(runtime_limits := recipe["runtime"]["resource_limits"]) == canonical_bytes(fixed_limits), "SourceV5 soak limits differ from the numeric source policy")
    ceiling_sha = hashlib.sha256(canonical_bytes(runtime_limits)).hexdigest()
    require(ceiling_sha == identity["resource_ceiling_sha256"], "SourceV5 resource ceiling digest differs from parent identity")
    calibration = manifest["resource_domain_calibration"]["record"]
    baseline = uint(calibration["fixed_global_control_baseline"], "SourceV5 calibrated global Control baseline", positive=True)
    require(baseline == recipe["runtime"]["fixed_global_control_baseline"], "SourceV5 Control baseline differs from the parent recipe")
    require(type(feedback_artifact) is dict and type(feedback_artifact.get("policy")) is dict, "SourceV5 numeric feedback policy artifact is malformed")
    feedback_policy_sha = digest(feedback_artifact.get("policy_sha256"), "SourceV5 numeric feedback policy digest")
    require(recipe["qualification"]["feedback_process_template"]["policy"]["context"] == contexts[feedback_context_key], "SourceV5 feedback template context differs from the source numeric policy")

    for name in ("application-soak-readback.py", "run-application-soak.sh"):
        expected_pin = recipe["validator"] if name.endswith("readback.py") else recipe["runner"]
        path = safe_child(source_root, expected_pin["path"], f"SourceV5 pinned soak {name}")
        record = records.get(expected_pin["path"])
        require(type(record) is dict and record.get("kind") == "file" and record.get("sha256") == expected_pin["sha256"], f"SourceV5 recipe {name} pin differs from its regular inventory entry")
        require(sha256_file(path, f"SourceV5 pinned soak {name}") == expected_pin["sha256"], f"SourceV5 pinned soak {name} bytes changed")
    for label in ("driver", "validator"):
        pressure_pin = recipe["pressure"][label]
        record = records.get(pressure_pin["path"])
        path = safe_child(source_root, pressure_pin["path"], f"SourceV5 pressure {label}")
        require(type(record) is dict and record.get("kind") == "file" and record.get("sha256") == pressure_pin["sha256"] and sha256_file(path, f"SourceV5 pressure {label}") == pressure_pin["sha256"], f"SourceV5 pressure {label} bytes differ from its harness pin")
    return {
        "source_manifest_sha256": manifest_raw_sha,
        "source_manifest_semantic_sha256": internal_sha,
        "source_tree_sha256": source["source_tree_sha256"],
        "build_sha256": build_sha,
        "candidate_binary_path": str(soak_path),
        "candidate_binary_sha256": soak_sha,
        "application_binary_path": str(normal_path),
        "application_binary_sha256": normal_sha,
        "oracle_producer_path": str(normal_path),
        "oracle_producer_binary_sha256": normal_sha,
        "normal_application_artifacts": {name: pin["sha256"] for name, pin in app_artifacts.items()},
        "declared_soak_artifacts": {name: pin["sha256"] for name, pin in soak_artifacts.items()},
        "resource_limits": fixed_limits,
        "domain_ceilings": domain,
        "scope_limits": scope,
        "byte_buckets": buckets,
        "fixed_policy_sha256": fixed_policy_sha,
        "feedback_policy_sha256": feedback_policy_sha,
        "feedback_context": contexts[feedback_context_key],
        "fixed_global_control_baseline": baseline,
        "source_root": str(source_root),
        "source_manifest_path": str(manifest_path),
        "manifest": manifest,
        "controller": controller,
        "controller_sha256": controller_sha,
        "source_records": records,
        "ring_context_binary_sha256": normal_sha,
    }


def _ring_header_value(line: str, key: str) -> str:
    fields = line.split("\t")
    require(len(fields) == 2 and fields[0] == key, f"oracle ring is missing canonical header {key}")
    return fields[1]


def _validate_ring(recipe: dict[str, Any], source_sha: str, binary_sha: str) -> dict[str, Any]:
    oracle = recipe["oracle"]
    ring_path = safe_absolute_path(oracle["ring_path"], "reference ring path")
    raw, ring_sha = read_stable_bytes(ring_path, "external reference ring", MAX_RING_BYTES)
    require(ring_sha == oracle["ring_sha256"], "external reference ring differs from its pre-run SHA pin")
    require(raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw, "external reference ring framing is not canonical")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise SoakReadbackError("external reference ring must be ASCII") from error
    require(len(lines) >= 12, "external reference ring is truncated")
    require(lines[0] == f"schema\t{RING_SCHEMA}", "external reference ring schema differs")
    require(_ring_header_value(lines[1], "source_sha256") == source_sha, "oracle source identity differs from the parent source pin")
    require(_ring_header_value(lines[2], "binary_sha256") == binary_sha, "oracle binary identity differs from the parent soak binary pin")
    profile = recipe["identity"]["profile"]
    require(_ring_header_value(lines[3], "profile") == profile, "oracle profile differs from the frozen treatment")
    require(lines[4] == "workload\tmixed" and lines[5] == "mode\topen_loop", "oracle ring workload/mode differs from the frozen contract")
    average = parse_uint(_ring_header_value(lines[6], "average_rate_per_second"), "oracle average rate")
    pulse = parse_uint(_ring_header_value(lines[7], "pulse_rate_per_second"), "oracle pulse rate")
    arrivals = parse_uint(_ring_header_value(lines[8], "arrivals"), "oracle arrivals")
    trace_ns = parse_uint(_ring_header_value(lines[9], "trace_duration_ns"), "oracle trace duration")
    require(lines[10] == "kernel_config\tinterleave=cpu,memory,http,disk", "oracle kernel configuration differs")
    require(lines[11] == "id\tscheduled_ns\tworkload\texpected_checksum", "oracle row header differs")
    require(0 < average <= 1_000_000_000 and (profile != "burst" or average <= 250_000_000), "oracle average rate exceeds its profile bound")
    expected_pulse = average * 4 if profile == "burst" else average
    require(pulse == expected_pulse, "oracle pulse rate differs from its profile")
    require(MIN_RING_ROWS <= arrivals <= MAX_RING_ROWS and arrivals % 4 == 0, "oracle row count is outside its fixed multiple-of-four bound")
    if profile == "burst":
        expected_trace = ((arrivals + average - 1) // average) * 1_000_000_000
    else:
        expected_trace = arrivals * 1_000_000_000 // average
    require(trace_ns == expected_trace, "oracle trace duration differs from its rate and count")
    rows = lines[12:]
    require(len(rows) == arrivals, "oracle row count differs from its header")
    expected: list[int] = []
    for row_id, line in enumerate(rows):
        fields = line.split("\t")
        require(len(fields) == 4, f"oracle row {row_id} has the wrong field count")
        require(parse_uint(fields[0], f"oracle row {row_id} ID") == row_id, f"oracle row {row_id} ID is reordered or missing")
        scheduled = parse_uint(fields[1], f"oracle row {row_id} schedule")
        family = FAMILIES[row_id % len(FAMILIES)]
        require(fields[2] == family, f"oracle row {row_id} breaks the frozen family interleave")
        if profile == "burst":
            cycle, slot = divmod(row_id, average)
            expected_schedule = cycle * 1_000_000_000 + slot * 250_000_000 // average
        else:
            expected_schedule = row_id * 1_000_000_000 // average
        require(scheduled == expected_schedule, f"oracle row {row_id} schedule differs from the frozen arrival profile")
        expected.append(parse_uint(fields[3], f"oracle row {row_id} checksum"))
    return {
        "path": str(ring_path),
        "sha256": ring_sha,
        "rows": arrivals,
        "average_rate_per_second": average,
        "pulse_rate_per_second": pulse,
        "trace_duration_ns": trace_ns,
        "expected_checksums": expected,
    }


def _validate_recipe(recipe_value: object, recipe_sha: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(recipe_value) is dict and recipe_value.get("schema") == RECIPE_SCHEMA_V2:
        return _validate_recipe_v2(recipe_value, recipe_sha)
    recipe = exact_object(
        recipe_value,
        {"schema", "identity", "source", "oracle", "runtime", "validator", "runner"},
        "parent soak recipe",
    )
    require(recipe["schema"] == RECIPE_SCHEMA, "unsupported parent soak recipe schema")
    identity = exact_object(
        recipe["identity"],
        {
            "campaign_id", "host_id", "run_id", "nonce", "allocator", "executor", "workload",
            "profile", "comparison_family", "source_sha256", "build_sha256", "binary_sha256",
            "resource_ceiling_sha256",
        },
        "parent soak identity",
    )
    token(identity["campaign_id"], "campaign ID")
    token(identity["host_id"], "host ID")
    token(identity["run_id"], "run ID")
    require(re.fullmatch(r"[a-f0-9]{32}", text(identity["nonce"], "soak nonce", maximum=32)) is not None, "soak nonce must be 32 lowercase hex characters")
    require(identity["allocator"] == "allocatbelt" and identity["executor"] == "bounded", "soak readback supports only allocatbelt/bounded")
    require(identity["workload"] == "mixed", "soak readback supports only the mixed workload")
    require(identity["comparison_family"] == "fixed_policy", "external-pressure and unknown comparison families are unsupported")
    require(identity["profile"] in PROFILES, "unknown fixed-policy soak profile")
    for name in ("source_sha256", "build_sha256", "binary_sha256", "resource_ceiling_sha256"):
        digest(identity[name], name)

    source = exact_object(recipe["source"], {"root", "manifest_path", "manifest_sha256"}, "recipe source binding")
    safe_absolute_path(source["root"], "source root")
    safe_absolute_path(source["manifest_path"], "source manifest path")
    digest(source["manifest_sha256"], "source manifest SHA-256")
    oracle = exact_object(recipe["oracle"], {"producer_path", "producer_sha256", "ring_path", "ring_sha256"}, "recipe oracle binding")
    safe_absolute_path(oracle["producer_path"], "oracle producer path")
    digest(oracle["producer_sha256"], "oracle producer SHA-256")
    safe_absolute_path(oracle["ring_path"], "reference ring path")
    digest(oracle["ring_sha256"], "reference ring SHA-256")

    runtime = exact_object(recipe["runtime"], {
        "mode", "duration_seconds", "sample_interval_ms", "resource_limits", "fixed_global_control_baseline",
        "terminal_budget_bytes", "sample_budget_bytes",
    }, "recipe runtime contract")
    require(runtime["mode"] in ("qualified", "functional"), "soak mode must be qualified or functional")
    duration = uint(runtime["duration_seconds"], "soak duration", positive=True)
    require(duration <= QUALIFIED_SECONDS, "soak duration exceeds its fixed horizon")
    require(runtime["mode"] != "qualified" or duration == QUALIFIED_SECONDS, "qualified mode requires exactly 10,800 seconds")
    require(runtime["mode"] != "functional" or duration < QUALIFIED_SECONDS, "functional mode must use a short, ineligible horizon")
    require(uint(runtime["sample_interval_ms"], "sample interval", positive=True) == SAMPLE_INTERVAL_MS, "soak sample interval is frozen at 100 ms")
    terminal_budget = uint(runtime["terminal_budget_bytes"], "frozen terminal artifact budget", positive=True)
    sample_budget = uint(runtime["sample_budget_bytes"], "frozen sample artifact budget", positive=True)
    require(terminal_budget <= MAX_TERMINAL_BYTES, "terminal artifact budget exceeds the global parser ceiling")
    require(sample_budget <= MAX_SAMPLE_BYTES, "sample artifact budget exceeds the global parser ceiling")
    min_sample_bytes = len("\t".join(SAMPLE_HEADER).encode("ascii")) + 1 + (duration * 1000 // SAMPLE_INTERVAL_MS + 1) * (2 * len(SAMPLE_HEADER))
    require(sample_budget >= min_sample_bytes, "sample artifact budget cannot hold the exact row count even at minimum numeric width")
    limits = exact_object(runtime["resource_limits"], {"managed_bytes", "disk_ops", "network_ops", "tasks", "cpu_charges"}, "parent resource limits")
    for name, value in limits.items():
        uint(value, f"parent resource limit {name}")
    uint(runtime["fixed_global_control_baseline"], "parent calibrated Control baseline", positive=True)
    tool_keys = {"path", "sha256"}
    for label in ("validator", "runner"):
        tool = exact_object(recipe[label], tool_keys, f"recipe {label} pin")
        relative_path(tool["path"], f"recipe {label} path")
        digest(tool["sha256"], f"recipe {label} SHA-256")
    return recipe, identity


def _validate_recipe_v2(recipe_value: dict[str, Any], recipe_sha: str) -> tuple[dict[str, Any], dict[str, Any]]:
    recipe = exact_object(recipe_value, {
        "schema", "identity", "source", "oracle", "runtime", "qualification",
        "construction_probe", "pressure", "feedback_expectation", "validator", "runner",
    }, "SourceV5 external-pressure parent soak recipe")
    require(recipe["schema"] == RECIPE_SCHEMA_V2, "unsupported SourceV5 parent soak recipe schema")
    body = dict(recipe)
    claimed = body.pop("recipe_sha256", None)
    # V2 recipes are pinned by their raw canonical file digest. They do not
    # contain a self-referential semantic digest.
    require(claimed is None, "SourceV5 parent recipe must use its separately pinned raw digest")
    identity = exact_object(recipe["identity"], {
        "campaign_id", "host_id", "run_id", "nonce", "allocator", "executor", "workload",
        "profile", "comparison_family", "source_sha256", "build_sha256", "binary_sha256",
        "resource_ceiling_sha256",
    }, "SourceV5 parent soak identity")
    for field in ("campaign_id", "host_id", "run_id"):
        token(identity[field], f"SourceV5 soak {field}")
    require(re.fullmatch(r"[0-9a-f]{32}", text(identity["nonce"], "SourceV5 soak nonce", maximum=32)) is not None, "SourceV5 soak nonce is malformed")
    require(identity["allocator"] == "allocatbelt" and identity["executor"] == "bounded", "SourceV5 soak supports only the pinned bounded allocatbelt candidate")
    require(identity["workload"] == "mixed" and identity["comparison_family"] == "external_pressure", "SourceV5 soak must preserve the original external-pressure mixed job")
    require(identity["profile"] in PROFILES, "SourceV5 soak profile is unsupported")
    for field in ("source_sha256", "build_sha256", "binary_sha256", "resource_ceiling_sha256"):
        digest(identity[field], f"SourceV5 soak {field}")
    source = exact_object(recipe["source"], {"root", "manifest_path", "manifest_sha256"}, "SourceV5 source binding")
    safe_absolute_path(source["root"], "SourceV5 source root")
    safe_absolute_path(source["manifest_path"], "SourceV5 source manifest path")
    digest(source["manifest_sha256"], "SourceV5 source manifest raw SHA-256")
    oracle = exact_object(recipe["oracle"], {"producer_path", "producer_sha256", "ring_path", "ring_sha256"}, "SourceV5 oracle binding")
    safe_absolute_path(oracle["producer_path"], "SourceV5 oracle producer path")
    digest(oracle["producer_sha256"], "SourceV5 oracle producer SHA-256")
    safe_absolute_path(oracle["ring_path"], "SourceV5 oracle ring path")
    digest(oracle["ring_sha256"], "SourceV5 oracle ring SHA-256")
    runtime = exact_object(recipe["runtime"], {
        "mode", "duration_seconds", "sample_interval_ms", "resource_limits", "fixed_global_control_baseline",
        "terminal_budget_bytes", "sample_budget_bytes",
    }, "SourceV5 soak runtime contract")
    require(runtime["mode"] in ("qualified", "functional"), "SourceV5 soak mode is unsupported")
    duration = uint(runtime["duration_seconds"], "SourceV5 soak duration", positive=True)
    require(duration <= QUALIFIED_SECONDS, "SourceV5 soak duration exceeds the original horizon")
    require((runtime["mode"] == "qualified" and duration == QUALIFIED_SECONDS) or (runtime["mode"] == "functional" and duration < QUALIFIED_SECONDS), "SourceV5 soak mode and duration disagree")
    require(uint(runtime["sample_interval_ms"], "SourceV5 sample interval", positive=True) == SAMPLE_INTERVAL_MS, "SourceV5 soak sample interval differs from 100 ms")
    terminal_budget = uint(runtime["terminal_budget_bytes"], "SourceV5 terminal budget", positive=True)
    sample_budget = uint(runtime["sample_budget_bytes"], "SourceV5 sample budget", positive=True)
    require(terminal_budget <= MAX_TERMINAL_BYTES and sample_budget <= MAX_SAMPLE_BYTES, "SourceV5 soak artifact budget exceeds the reader bound")
    minimum_sample_bytes = len("\t".join(SAMPLE_HEADER).encode("ascii")) + 1 + (duration * 1000 // SAMPLE_INTERVAL_MS + 1) * (2 * len(SAMPLE_HEADER))
    require(sample_budget >= minimum_sample_bytes, "SourceV5 sample budget cannot hold the exact cadence")
    limits = exact_object(runtime["resource_limits"], {"managed_bytes", "disk_ops", "network_ops", "tasks", "cpu_charges"}, "SourceV5 runtime limits")
    for field, value in limits.items():
        uint(value, f"SourceV5 runtime limit {field}")
    uint(runtime["fixed_global_control_baseline"], "SourceV5 fixed Control baseline", positive=True)

    qualification = exact_object(recipe["qualification"], {
        "spec", "plan", "campaign_inputs_module_sha256", "capacity_template", "pressure_condition",
        "feedback_process_template", "nonce_instantiation", "capacity_evidence_ready", "feedback_runtime_composition_ready",
        "execution_ready", "full_gate_ready", "launch_enabled", "full_gate_gaps",
    }, "SourceV5 qualification input binding")
    for label in ("spec", "plan"):
        pin = exact_object(qualification[label], {"path", "raw_sha256", "semantic_sha256"}, f"SourceV5 {label} pin")
        safe_absolute_path(pin["path"], f"SourceV5 {label} path")
        digest(pin["raw_sha256"], f"SourceV5 {label} raw SHA-256")
        digest(pin["semantic_sha256"], f"SourceV5 {label} semantic SHA-256")
    digest(qualification["campaign_inputs_module_sha256"], "SourceV5 campaign inputs module SHA-256")
    require(all(type(qualification[name]) is bool for name in (
        "capacity_evidence_ready", "feedback_runtime_composition_ready", "execution_ready", "full_gate_ready", "launch_enabled",
    )), "SourceV5 qualification readiness fields are not booleans")
    require(type(qualification["full_gate_gaps"]) is list and all(type(item) is str for item in qualification["full_gate_gaps"]), "SourceV5 qualification gaps are malformed")
    require(qualification["launch_enabled"] == (qualification["execution_ready"] and qualification["capacity_evidence_ready"] and qualification["feedback_runtime_composition_ready"] and recipe["pressure"]["recipe"] is not None), "SourceV5 launch readiness is not derived from its verified prerequisites")
    capacity = exact_object(qualification["capacity_template"], {
        "template_sha256", "calibration_id", "request_template", "context_template", "evidence",
    }, "SourceV5 capacity template")
    digest(capacity["template_sha256"], "SourceV5 capacity template digest")
    token(capacity["calibration_id"], "SourceV5 capacity calibration ID")
    for field in ("request_template", "context_template"):
        pin = exact_object(capacity[field], {"relative_path", "raw_sha256"}, f"SourceV5 capacity {field}")
        relative_path(pin["relative_path"], f"SourceV5 capacity {field} path")
        digest(pin["raw_sha256"], f"SourceV5 capacity {field} digest")
    if capacity["evidence"] is not None:
        evidence = exact_object(capacity["evidence"], {"artifact", "receipt", "stage_receipt"}, "SourceV5 capacity evidence pins")
        for field, pin_value in evidence.items():
            pin = exact_object(pin_value, {"relative_path", "raw_sha256"}, f"SourceV5 capacity evidence {field}")
            relative_path(pin["relative_path"], f"SourceV5 capacity evidence {field} path")
            digest(pin["raw_sha256"], f"SourceV5 capacity evidence {field} SHA-256")
    pressure_condition = exact_object(qualification["pressure_condition"], {
        "condition_id", "condition_sha256", "condition", "pressure_calibration", "readiness_thresholds", "schedule",
    }, "SourceV5 pressure condition")
    token(pressure_condition["condition_id"], "SourceV5 pressure condition ID")
    digest(pressure_condition["condition_sha256"], "SourceV5 pressure condition raw SHA-256")
    condition_pin = exact_object(pressure_condition["condition"], {"relative_path", "raw_sha256"}, "SourceV5 pressure request template pin")
    relative_path(condition_pin["relative_path"], "SourceV5 pressure request template path")
    digest(condition_pin["raw_sha256"], "SourceV5 pressure request template SHA-256")
    require(pressure_condition["condition_sha256"] == condition_pin["raw_sha256"], "SourceV5 pressure condition SHA is not its template raw digest")
    pressure_calibration = exact_object(pressure_condition["pressure_calibration"], {
        "calibration_id", "artifact", "receipt", "validator_sha256",
    }, "SourceV5 pressure calibration pins")
    token(pressure_calibration["calibration_id"], "SourceV5 pressure calibration ID")
    for field in ("artifact", "receipt"):
        pin = exact_object(pressure_calibration[field], {"relative_path", "raw_sha256"}, f"SourceV5 pressure calibration {field}")
        relative_path(pin["relative_path"], f"SourceV5 pressure calibration {field} path")
        digest(pin["raw_sha256"], f"SourceV5 pressure calibration {field} SHA-256")
    digest(pressure_calibration["validator_sha256"], "SourceV5 pressure validator SHA-256")
    exact_object(pressure_condition["readiness_thresholds"], {"minimum_overlap_seconds", "minimum_ready_samples", "maximum_sample_gap_ms"}, "SourceV5 pressure readiness thresholds")
    exact_object(pressure_condition["schedule"], {"duration_seconds", "sample_interval_ms", "seed"}, "SourceV5 pressure schedule")
    feedback_template = exact_object(qualification["feedback_process_template"], {
        "identity", "nonce_scope", "nonce_instantiation_schema", "nonce_instantiation_rule", "policy", "required_proofs", "template_sha256",
    }, "SourceV5 feedback process template")
    require(feedback_template["nonce_scope"] == "reusable_template" and feedback_template["nonce_instantiation_schema"] == "allocatbelt.application-process-nonce-instantiation.v1" and feedback_template["nonce_instantiation_rule"] == "sha256(template_nonce,campaign_id,job_run_id,pair_member,ordinal)", "SourceV5 feedback nonce template rule differs")
    digest(feedback_template["template_sha256"], "SourceV5 feedback template digest")
    require(type(feedback_template["required_proofs"]) is list and all(type(item) is str for item in feedback_template["required_proofs"]), "SourceV5 feedback proof requirements are malformed")
    nonce_instantiation = exact_object(qualification["nonce_instantiation"], {
        "schema", "template_nonce", "campaign_id", "job_run_id", "pair_member", "ordinal", "nonce",
    }, "SourceV5 process nonce instantiation")
    require(nonce_instantiation["schema"] == "allocatbelt.application-process-nonce-instantiation.v1", "SourceV5 process nonce instantiation schema differs")
    for field in ("template_nonce", "nonce"):
        require(re.fullmatch(r"[0-9a-f]{32}", text(nonce_instantiation[field], f"nonce instantiation {field}", maximum=32)) is not None, f"nonce instantiation {field} is malformed")
    for field in ("campaign_id", "job_run_id", "pair_member"):
        token(nonce_instantiation[field], f"nonce instantiation {field}")
    uint(nonce_instantiation["ordinal"], "nonce instantiation ordinal", positive=True)
    require(nonce_instantiation["pair_member"] == "soak", "SourceV5 nonce process member is not the planned soak member")
    require(nonce_instantiation["nonce"] == identity["nonce"], "SourceV5 process nonce instantiation differs from soak identity")
    derived_nonce_material = {
        "template_nonce": nonce_instantiation["template_nonce"],
        "campaign_id": nonce_instantiation["campaign_id"],
        "job_run_id": nonce_instantiation["job_run_id"],
        "pair_member": nonce_instantiation["pair_member"],
        "ordinal": nonce_instantiation["ordinal"],
    }
    derived_nonce = hashlib.sha256(b"allocatbelt.application-process-nonce-instantiation.v1\0" + canonical_bytes(derived_nonce_material)).hexdigest()[:32]
    require(derived_nonce == identity["nonce"] and nonce_instantiation["campaign_id"] == identity["campaign_id"] and nonce_instantiation["job_run_id"] == identity["run_id"], "SourceV5 nonce does not match its campaign/run/member/ordinal instantiation rule")
    probe = exact_object(recipe["construction_probe"], {"path", "raw_sha256", "allocator", "binary_sha256"}, "SourceV5 construction probe pin")
    safe_absolute_path(probe["path"], "SourceV5 construction probe path")
    digest(probe["raw_sha256"], "SourceV5 construction probe raw SHA-256")
    require(probe["allocator"] == "allocatbelt", "SourceV5 construction probe must bind the allocatbelt application artifact")
    digest(probe["binary_sha256"], "SourceV5 construction probe binary SHA-256")
    pressure = exact_object(recipe["pressure"], {
        "request_template", "recipe", "condition_sha256", "driver", "validator",
    }, "SourceV5 pressure driver binding")
    request_pin = exact_object(pressure["request_template"], {"path", "raw_sha256"}, "SourceV5 pressure request template binding")
    safe_absolute_path(request_pin["path"], "SourceV5 pressure request template path")
    digest(request_pin["raw_sha256"], "SourceV5 pressure request template raw SHA-256")
    if pressure["recipe"] is None:
        require(pressure["condition_sha256"] is None and not qualification["launch_enabled"], "SourceV5 pressure recipe may be absent only in a launch-disabled template")
    else:
        pressure_recipe_pin = exact_object(pressure["recipe"], {"path", "raw_sha256", "semantic_sha256"}, "SourceV5 instantiated pressure recipe binding")
        safe_absolute_path(pressure_recipe_pin["path"], "SourceV5 instantiated pressure recipe path")
        digest(pressure_recipe_pin["raw_sha256"], "SourceV5 pressure recipe raw SHA-256")
        digest(pressure_recipe_pin["semantic_sha256"], "SourceV5 pressure recipe semantic SHA-256")
        digest(pressure["condition_sha256"], "SourceV5 derived pressure condition SHA-256")
    require(pressure["request_template"]["raw_sha256"] == condition_pin["raw_sha256"], "SourceV5 pressure driver request differs from the pinned condition template")
    for label in ("driver", "validator"):
        pin = exact_object(pressure[label], {"path", "sha256"}, f"SourceV5 pressure {label} pin")
        relative_path(pin["path"], f"SourceV5 pressure {label} path")
        digest(pin["sha256"], f"SourceV5 pressure {label} SHA-256")
    feedback = exact_object(recipe["feedback_expectation"], {"template", "template_sha256", "trace_identity", "policy", "validator"}, "SourceV5 feedback expectation template")
    digest(feedback["template_sha256"], "SourceV5 feedback expectation template SHA-256")
    require(type(feedback["template"]) is dict, "SourceV5 feedback expectation template is malformed")
    require(digest(feedback["template"].get("template_sha256"), "SourceV5 feedback template digest") == feedback["template_sha256"], "feedback expectation and process template digests differ")
    require(canonical_bytes(feedback["template"]) == canonical_bytes(feedback_template), "feedback expectation source template differs from the validated SourceV5 plan template")
    trace_identity = exact_object(feedback["trace_identity"], {
        "host_id", "run_id", "report_nonce", "allocator", "executor", "workload", "profile", "mode",
        "source_sha256", "binary_sha256", "pressure_qualification",
    }, "SourceV5 prelaunch trace identity")
    for field in ("host_id", "run_id", "report_nonce", "allocator", "executor", "workload", "profile", "mode"):
        text(trace_identity[field], f"SourceV5 trace identity {field}")
    require(re.fullmatch(r"[0-9a-f]{32}", trace_identity["report_nonce"]) is not None, "SourceV5 feedback report nonce is malformed")
    digest(trace_identity["source_sha256"], "SourceV5 trace identity source SHA-256")
    digest(trace_identity["binary_sha256"], "SourceV5 trace identity binary SHA-256")
    require(trace_identity["pressure_qualification"] is True, "SourceV5 soak feedback identity must preserve pressure qualification")
    require(trace_identity["report_nonce"] == identity["nonce"], "SourceV5 trace report nonce differs from soak nonce")
    feedback_policy = exact_object(feedback["policy"], {
        "version", "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns", "required_breach_samples",
        "actuation_cooldown_ns", "minimum_dense_observations", "controls", "capacity_sources",
        "global_ceilings", "tenant_ceilings", "scope_limits", "rate_buckets", "collector", "meter_source_bounds",
    }, "SourceV5 constructed feedback policy")
    controls = exact_object(feedback_policy["controls"], {"cpu", "disk", "download"}, "SourceV5 feedback controls")
    for resource, control_value in controls.items():
        exact_object(control_value, {"floor", "initial", "ceiling", "low_bps", "high_bps"}, f"SourceV5 {resource} feedback control")
    exact_object(feedback_policy["capacity_sources"], {"disk", "download"}, "SourceV5 byte capacity sources")
    exact_object(feedback_policy["global_ceilings"], set(DOMAINS), "SourceV5 global hard ceilings")
    exact_object(feedback_policy["tenant_ceilings"], set(DOMAINS), "SourceV5 tenant hard ceilings")
    exact_object(feedback_policy["scope_limits"], {"managed_memory", "disk_operations", "network_operations"}, "SourceV5 scope limits")
    exact_object(feedback_policy["rate_buckets"], set(DIRECTIONS), "SourceV5 rate bucket bounds")
    exact_object(feedback_policy["collector"], {"task_lease_count", "control_charge_bytes", "expected_global_control_baseline"}, "SourceV5 feedback collector policy")
    exact_object(feedback_policy["meter_source_bounds"], set(DIRECTIONS), "SourceV5 meter source bounds")
    feedback_validator = exact_object(feedback["validator"], {"path", "sha256"}, "SourceV5 feedback validator pin")
    relative_path(feedback_validator["path"], "SourceV5 feedback validator path")
    digest(feedback_validator["sha256"], "SourceV5 feedback validator SHA-256")
    validator = exact_object(recipe["validator"], {"path", "sha256"}, "SourceV5 soak validator pin")
    runner = exact_object(recipe["runner"], {"path", "sha256"}, "SourceV5 soak runner pin")
    for label, pin in (("validator", validator), ("runner", runner)):
        relative_path(pin["path"], f"SourceV5 {label} path")
        digest(pin["sha256"], f"SourceV5 {label} SHA-256")
    require(recipe_sha and re.fullmatch(r"[0-9a-f]{64}", recipe_sha) is not None, "SourceV5 parent recipe raw SHA-256 is malformed")
    return recipe, identity


def _audit_inputs(
    recipe_path: Path,
    recipe_expected_sha: str,
    cli_identity: dict[str, str],
    binary_argument: Path,
    selected_mode: str | None,
    selected_duration: int | None,
    runner_path: Path | None = None,
    *,
    require_executing_reader_path: bool = False,
    offline_context: dict[str, Any] | None = None,
    source5_probe_capture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    recipe, recipe_sha, raw = read_json(recipe_path, "parent soak recipe", MAX_RECIPE_BYTES)
    require(raw == canonical_bytes(recipe), "parent soak recipe is not canonical JSON")
    require(recipe_sha == recipe_expected_sha, "parent soak recipe differs from its frozen SHA-256")
    recipe, identity = _validate_recipe(recipe, recipe_sha)
    for name, expected in cli_identity.items():
        require(identity[name] == expected, f"runner argument {name} differs from the parent recipe")
    if selected_mode is not None:
        require(recipe["runtime"]["mode"] == selected_mode, "runner mode differs from the frozen parent recipe")
    if selected_duration is not None:
        require(recipe["runtime"]["duration_seconds"] == selected_duration, "runner duration differs from the frozen parent recipe")
    if source5_probe_capture is None and offline_context is not None:
        source5_probe_capture = offline_context.get("construction_probe_capture")
    source_audit = _audit_manifest_and_binaries(
        recipe, offline_context=offline_context,
        source5_probe_capture=source5_probe_capture,
    )
    source_root = Path(source_audit["source_root"])
    expected_reader = safe_child(source_root, recipe["validator"]["path"], "recipe validator source")
    executing_reader = Path(__file__).resolve(strict=True)
    executing_reader_sha = sha256_file(executing_reader, "executing soak readback source")
    require(executing_reader_sha == recipe["validator"]["sha256"], "executing readback source differs from its parent recipe pin")
    if require_executing_reader_path:
        require(executing_reader == expected_reader, "executing __file__ path differs from the parent-pinned validator path")
    expected_runner = safe_child(source_root, recipe["runner"]["path"], "recipe soak runner source")
    require(runner_path is not None, "the executing run-application-soak.sh path must be supplied")
    executing_runner = safe_absolute_path(str(runner_path), "executing soak runner path")
    require(executing_runner == expected_runner, "executing runner $0 path differs from the parent-pinned runner path")
    executing_runner_sha = sha256_file(executing_runner, "executing soak runner source")
    require(executing_runner_sha == recipe["runner"]["sha256"], "executing runner source differs from its parent recipe pin")
    candidate_path = Path(source_audit["candidate_binary_path"])
    require(binary_argument.resolve(strict=True) == candidate_path, "runner binary path differs from the source manifest soak artifact")
    ring = _validate_ring(recipe, identity["source_sha256"], identity["binary_sha256"])
    require(hashlib.sha256(canonical_bytes(recipe["runtime"]["resource_limits"])).hexdigest() == identity["resource_ceiling_sha256"], "runtime limits do not match the source-bound resource ceiling SHA")
    require(recipe["runtime"]["fixed_global_control_baseline"] == source_audit["fixed_global_control_baseline"], "parent Control baseline differs from source calibration")
    if recipe["schema"] == RECIPE_SCHEMA_V2:
        qualification_validation = _verify_v5_campaign_inputs(recipe, source_audit)
        require(qualification_validation["capacity_evidence_ready"] == recipe["qualification"]["capacity_evidence_ready"], "SourceV5 capacity readiness differs from the full captured-controller validation")
        require(qualification_validation["feedback_runtime_composition_ready"] == recipe["qualification"]["feedback_runtime_composition_ready"], "SourceV5 feedback composition readiness differs from the full captured-controller validation")
        require(qualification_validation["execution_ready"] == recipe["qualification"]["execution_ready"], "SourceV5 execution readiness differs from the full captured-controller validation")
        require(qualification_validation["full_gate_ready"] == recipe["qualification"]["full_gate_ready"], "SourceV5 full-gate readiness differs from the full captured-controller validation")
        expected_launch_enabled = bool(
            qualification_validation["execution_ready"]
            and qualification_validation["capacity_evidence_ready"]
            and qualification_validation["feedback_runtime_composition_ready"]
            and recipe["pressure"]["recipe"] is not None
        )
        require(recipe["qualification"]["launch_enabled"] == expected_launch_enabled, "SourceV5 launch readiness is not derived from the full captured-controller validation")
        pressure_recipe = None
        if recipe["pressure"]["recipe"] is not None:
            pressure_recipe = _audit_pressure_recipe(recipe, source_audit)
            require(pressure_recipe["application_wall_timeout_seconds"] == qualification_validation["application_wall_timeout_seconds"], "pressure recipe application wall bound differs from the campaign-derived timeout")
            require(pressure_recipe["pressure_duration_seconds"] == qualification_validation["pressure_duration_seconds"], "pressure recipe horizon differs from the campaign-derived enclosing schedule")
        source_audit["pressure_recipe"] = pressure_recipe
        source_audit["qualification_validation"] = qualification_validation
        source_audit["application_supervision"] = {
            "application_wall_timeout_seconds": qualification_validation["application_wall_timeout_seconds"],
            "pressure_duration_seconds": qualification_validation["pressure_duration_seconds"],
            "pressure_schedule": qualification_validation["pressure_schedule"],
        }
    return {
        "recipe": recipe,
        "recipe_sha256": recipe_sha,
        "identity": identity,
        "source": source_audit,
        "ring": ring,
        "mode": recipe["runtime"]["mode"],
        "duration_seconds": recipe["runtime"]["duration_seconds"],
        "sample_interval_ms": recipe["runtime"]["sample_interval_ms"],
        "execution": {
            "reader_path": str(executing_reader),
            "reader_sha256": executing_reader_sha,
            "runner_path": str(executing_runner),
            "runner_sha256": executing_runner_sha,
        },
        "source_root": str(source_root),
        "comparison_family": identity["comparison_family"],
        "launch_enabled": recipe["qualification"]["launch_enabled"] if recipe["schema"] == RECIPE_SCHEMA_V2 else True,
    }


def _current_audit_offline(
    args: argparse.Namespace, offline_context: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rebuild the SourceV5 Soak audit without Git, APP, or procfs probes."""
    exact_object(offline_context, {
        "schema", "evidence_path_map", "construction_probe_capture",
            "host_verification_pin", "application_environment",
            "pressure_origin",
    }, "Source5 Soak offline replay context")
    require(offline_context["schema"] in {
                SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA,
                SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA_V2,
            },
            "Source5 Soak offline replay context schema differs")
    require(type(offline_context["application_environment"]) is dict and
            type(offline_context["application_environment"].get("PATH")) is str and
            bool(offline_context["application_environment"]["PATH"]),
            "Source5 offline replay lacks the exact origin launch environment")
    recipe_expected_sha = digest(args.recipe_sha256,
                                 "expected Source5 recipe SHA-256")
    recipe, _raw_sha, raw = read_json(
        args.recipe, "Source5 parent soak recipe", MAX_RECIPE_BYTES,
    )
    require(raw == canonical_bytes(recipe) and
            hashlib.sha256(raw).hexdigest() == recipe_expected_sha,
            "Source5 parent recipe raw bytes differ from the offline pin")
    normalized, identity = _validate_recipe(recipe, recipe_expected_sha)
    require(normalized == recipe and recipe["schema"] == RECIPE_SCHEMA_V2,
            "receipt-backed offline replay requires the original SourceV5 recipe")
    cli_identity = {name: identity[name] for name in (
        "campaign_id", "host_id", "run_id", "allocator", "executor",
        "profile", "source_sha256", "binary_sha256",
        "resource_ceiling_sha256",
    )}
    audit = _audit_inputs(
        args.recipe, recipe_expected_sha, cli_identity, args.binary, None,
        None, args.runner_path, require_executing_reader_path=True,
        offline_context=offline_context,
    )
    require(audit["recipe"] == recipe and audit["launch_enabled"] is
            recipe["qualification"]["launch_enabled"],
            "Source5 offline audit changed the original recipe or readiness")
    output_dir = _check_private_output_directory(args.output_dir)
    audit["launch_descriptor"] = _make_launch_descriptor(
        audit, output_dir, args.cpu_set,
    )
    # The original baseline preflight belongs to the immutable false legacy
    # audit, whose v2 descriptor intentionally has no environment. The actual
    # Soak environment is compared only after Source5 reconstructs its
    # separately authorized enabled overlay.
    require(audit["launch_enabled"] is False and
            audit["launch_descriptor"].get("launch_enabled") is False and
            audit["launch_descriptor"].get("environment") == {},
            "Source5 offline baseline audit no longer preserves false legacy readiness")
    preflight = _verify_preflight(output_dir / "soak-preflight.json", audit)
    audit["preflight"] = preflight
    return audit, preflight


def _read_json_raw(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_json_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise SoakReadbackError(f"{label} is not strict bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict and raw == canonical_bytes(value), f"{label} is not a canonical JSON object")
    return value


def _validate_v5_manifest_digest_roles(
    manifest: dict[str, Any], raw: bytes, semantic_reference: str,
    selected_manifest_raw_sha256: str | None = None,
) -> str:
    """Keep the spec's semantic manifest digest distinct from an optional raw pin."""
    require(raw == canonical_bytes(manifest), "SourceV5 source manifest raw bytes are not canonical")
    raw_sha = hashlib.sha256(raw).hexdigest()
    body = dict(manifest)
    claimed = body.pop("manifest_sha256", None)
    require(type(claimed) is str and re.fullmatch(r"[0-9a-f]{64}", claimed) is not None and claimed == hashlib.sha256(canonical_bytes(body)).hexdigest(), "SourceV5 source manifest internal semantic digest is invalid")
    require(claimed == semantic_reference, "SourceV5 spec/plan manifest reference is not its semantic digest")
    if selected_manifest_raw_sha256 is not None:
        require(raw_sha == selected_manifest_raw_sha256, "selected SourceV5 raw manifest bytes differ from the parent recipe pin")
    return raw_sha


def _derive_v5_pressure_schedule(
    duration_seconds: int, request: dict[str, Any], condition_schedule: dict[str, Any],
) -> dict[str, Any]:
    """Recompute the pressure horizon from the frozen app and driver bounds."""
    schedule_keys = {
        "seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds",
        "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds",
        "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points",
        "pressure_cpu_affinity", "application_cpu_affinity", "disk_bytes_per_second",
        "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes",
    }
    require(request.get("schema") == "allocatbelt.application-pressure-request.v1", "SourceV5 pressure template is not the canonical pressure-request schema")
    base = exact_object(request.get("schedule"), schedule_keys, "SourceV5 raw pressure request schedule")
    template_schedule = exact_object(condition_schedule, {"duration_seconds", "sample_interval_ms", "seed"}, "SourceV5 typed pressure condition schedule")
    base_duration = uint(base["duration_seconds"], "SourceV5 request-template pressure duration", positive=True, maximum=SOURCE_V5_PRESSURE_MAX_DURATION_SECONDS)
    template_duration = uint(template_schedule["duration_seconds"], "SourceV5 typed pressure duration", positive=True, maximum=SOURCE_V5_PRESSURE_MAX_DURATION_SECONDS)
    base_interval = uint(base["sample_interval_ms"], "SourceV5 request-template pressure interval", positive=True, maximum=1000)
    template_interval = uint(template_schedule["sample_interval_ms"], "SourceV5 typed pressure interval", positive=True, maximum=1000)
    base_seed = uint(base["seed"], "SourceV5 request-template pressure seed", positive=True, maximum=(1 << 63) - 1)
    template_seed = uint(template_schedule["seed"], "SourceV5 typed pressure seed", positive=True, maximum=(1 << 63) - 1)
    require(
        base_duration == template_duration
        and base_interval == template_interval == SAMPLE_INTERVAL_MS
        and base_seed == template_seed,
        "SourceV5 typed pressure schedule differs from the immutable request template or fixed sample interval",
    )
    startup = uint(base["startup_deadline_seconds"], "SourceV5 pressure startup deadline", positive=True, maximum=10)
    term = uint(base["term_deadline_seconds"], "SourceV5 pressure TERM deadline", positive=True, maximum=30)
    kill = uint(base["kill_deadline_seconds"], "SourceV5 pressure KILL deadline", positive=True, maximum=15)
    raw_total = uint(base["total_deadline_seconds"], "SourceV5 pressure total deadline", positive=True, maximum=SOURCE_V5_PRESSURE_MAX_TOTAL_SECONDS)
    duration = uint(duration_seconds, "SourceV5 timed app horizon", positive=True, maximum=QUALIFIED_SECONDS)
    app_wall = (
        SOURCE_V5_APP_SETUP_BUDGET_SECONDS
        + duration
        + SOURCE_V5_TRACE_OVERRUN_SECONDS
        + SOURCE_V5_DRAIN_BUDGET_SECONDS
        + SOURCE_V5_SHUTDOWN_BUDGET_SECONDS
        + SOURCE_V5_POSTPROCESS_BUDGET_SECONDS
    )
    pressure_duration = startup + app_wall + SOURCE_V5_PRESSURE_EXIT_OBSERVATION_SECONDS
    interval = base_interval
    require(interval >= SAMPLE_INTERVAL_MS and pressure_duration * 1000 % interval == 0, "derived SourceV5 pressure horizon does not align to its frozen sample interval")
    require(pressure_duration <= SOURCE_V5_PRESSURE_MAX_DURATION_SECONDS, "derived SourceV5 pressure horizon exceeds the driver duration bound")
    require(pressure_duration * 1000 // interval <= SOURCE_V5_PRESSURE_MAX_SAMPLES, "derived SourceV5 pressure horizon exceeds the driver sample bound")
    derived = dict(base)
    derived["duration_seconds"] = pressure_duration
    derived["total_deadline_seconds"] = max(raw_total, startup + pressure_duration + term + kill)
    require(derived["total_deadline_seconds"] <= SOURCE_V5_PRESSURE_MAX_TOTAL_SECONDS, "derived SourceV5 pressure total deadline exceeds the driver bound")
    return {
        "application_wall_timeout_seconds": app_wall,
        "pressure_duration_seconds": pressure_duration,
        "pressure_schedule": derived,
    }


def _verify_v5_manifest_set(
    controller: Any, sources: dict[str, dict[str, Any]], captured_controller_pin: dict[str, Any],
) -> None:
    """Run the selected inventory-pinned full verifier over every host manifest."""
    try:
        for host_id, manifest in sources.items():
            pin = exact_object(
                manifest["qualification_harness"]["campaign_controller"],
                {"path", "sha256"},
                f"SourceV5 {host_id} campaign controller pin",
            )
            require(pin == captured_controller_pin, f"SourceV5 {host_id} controller pin differs from the selected inventory-pinned verifier")
            controller.verify_source_manifest(manifest, verify_artifacts=False)
    except (OSError, TypeError, ValueError, getattr(controller, "CampaignError", ValueError)) as error:
        raise SoakReadbackError(f"captured SourceV5 full verifier rejected a campaign source manifest: {error}") from error


def _verify_v5_campaign_inputs(recipe: dict[str, Any], source_audit: dict[str, Any]) -> dict[str, Any]:
    controller = source_audit["controller"]
    qualification = recipe["qualification"]
    spec_pin, plan_pin = qualification["spec"], qualification["plan"]
    spec_raw, spec_raw_sha = read_stable_bytes(Path(spec_pin["path"]), "SourceV5 campaign spec", MAX_SPEC_BYTES)
    plan_raw, plan_raw_sha = read_stable_bytes(Path(plan_pin["path"]), "SourceV5 campaign plan", MAX_PLAN_BYTES)
    require(spec_raw_sha == spec_pin["raw_sha256"] and plan_raw_sha == plan_pin["raw_sha256"], "SourceV5 campaign spec or plan raw bytes differ from their parent pins")
    spec = _read_json_raw(spec_raw, "SourceV5 campaign spec")
    plan = _read_json_raw(plan_raw, "SourceV5 campaign plan")
    require(hashlib.sha256(canonical_bytes(spec)).hexdigest() == spec_pin["semantic_sha256"], "SourceV5 campaign spec semantic digest differs")
    plan_body = dict(plan)
    plan_semantic = plan_body.pop("plan_sha256", None)
    require(type(plan_semantic) is str and re.fullmatch(r"[0-9a-f]{64}", plan_semantic) is not None and plan_semantic == plan_pin["semantic_sha256"], "SourceV5 campaign plan semantic digest differs")
    input_root = Path(spec_pin["path"]).resolve(strict=True).parent
    source_refs = spec.get("source_manifests")
    require(type(source_refs) is list and len(source_refs) == 3, "SourceV5 spec must name exactly three source manifests")
    sources: dict[str, dict[str, Any]] = {}
    for index, reference_value in enumerate(source_refs):
        reference = exact_object(reference_value, {"host_id", "relative_path", "sha256"}, f"SourceV5 source reference[{index}]")
        host_id = token(reference["host_id"], f"SourceV5 source reference[{index}] host")
        require(host_id not in sources, "SourceV5 campaign spec repeats a source host")
        path = safe_child(input_root, reference["relative_path"], f"SourceV5 {host_id} source manifest")
        raw, raw_sha = read_stable_bytes(path, f"SourceV5 {host_id} source manifest", MAX_MANIFEST_BYTES)
        value = _read_json_raw(raw, f"SourceV5 {host_id} source manifest")
        selected_raw_pin = source_audit["source_manifest_sha256"] if host_id == recipe["identity"]["host_id"] else None
        _validate_v5_manifest_digest_roles(value, raw, reference["sha256"], selected_raw_pin)
        require(value.get("schema") == SOURCE_SCHEMA_V5, "SourceV5 plan includes a non-V5 source manifest")
        sources[host_id] = value
    _verify_v5_manifest_set(controller, sources, source_audit["manifest"]["qualification_harness"]["campaign_controller"])
    runtime_validator_sha = source_audit["manifest"]["runtime_readback_validator"]["sha256"]
    try:
        validation = controller.validate_spec(spec, sources, input_root=input_root)
        controller.verify_plan(plan, runtime_validator_sha, qualification["campaign_inputs_module_sha256"])
        inputs_module = controller.campaign_inputs_module(qualification["campaign_inputs_module_sha256"])
        normalized_inputs = inputs_module.validate_qualification_inputs(
            spec["qualification_inputs"], validation["host_ids"], spec["cells"], sources, input_root,
        )
    except (OSError, TypeError, ValueError, getattr(controller, "CampaignError", ValueError)) as error:
        raise SoakReadbackError(f"captured SourceV5 controller rejected the frozen spec/plan: {error}") from error
    require(plan.get("spec_sha256") == spec_pin["semantic_sha256"], "SourceV5 plan does not bind the frozen spec digest")
    require(plan.get("campaign_id") == recipe["identity"]["campaign_id"] and plan.get("source_manifests", {}).get(recipe["identity"]["host_id"]) == source_audit["manifest"]["manifest_sha256"], "SourceV5 campaign plan differs from the soak identity/source")
    job_matches = [item for item in plan["jobs"]["soak"] if type(item) is dict and item.get("run_id") == recipe["identity"]["run_id"]]
    require(len(job_matches) == 1, "SourceV5 soak identity is not a unique planned job")
    planned_job = job_matches[0]
    require(
        planned_job.get("phase") == "soak"
        and planned_job.get("host_id") == recipe["identity"]["host_id"]
        and planned_job.get("workload") == "mixed"
        and planned_job.get("profile") == recipe["identity"]["profile"]
        and planned_job.get("comparison_family") == "external_pressure"
        and planned_job.get("allocator") == "allocatbelt"
        and planned_job.get("executor") == "bounded"
        and planned_job.get("duration_seconds") == QUALIFIED_SECONDS,
        "SourceV5 planned soak job differs from the original 10,800-second bounded external-pressure candidate",
    )
    capacity_rows = [item for item in normalized_inputs["capacity_templates"] if item["host_id"] == recipe["identity"]["host_id"] and item["workload"] == "mixed" and item["profile"] == recipe["identity"]["profile"]]
    pressure_rows = [item for item in normalized_inputs["pressure_conditions"] if item["host_id"] == recipe["identity"]["host_id"] and item["capacity_key"]["workload"] == "mixed" and item["capacity_key"]["profile"] == recipe["identity"]["profile"]]
    require(len(capacity_rows) == len(pressure_rows) == 1, "SourceV5 selected soak capacity/pressure input is not unique")
    capacity, pressure = capacity_rows[0], pressure_rows[0]
    condition_path = safe_child(input_root, pressure["condition"]["relative_path"], "SourceV5 raw pressure request template")
    condition_raw, condition_raw_sha = read_stable_bytes(condition_path, "SourceV5 raw pressure request template", MAX_SPEC_BYTES)
    require(condition_raw_sha == pressure["condition"]["raw_sha256"], "SourceV5 raw pressure request template differs from its pinned digest")
    condition_value = _read_json_raw(condition_raw, "SourceV5 raw pressure request template")
    require(condition_value.get("identity", {}).get("condition_id") == pressure["condition_id"], "SourceV5 pressure request condition ID differs from its typed template")
    supervision = _derive_v5_pressure_schedule(recipe["runtime"]["duration_seconds"], condition_value, pressure["schedule"])
    planned_capacity = [item for item in plan["capacity_process_templates"] if item["capacity_key"]["host_id"] == recipe["identity"]["host_id"] and item["capacity_key"]["workload"] == "mixed" and item["capacity_key"]["profile"] == recipe["identity"]["profile"]]
    require(len(planned_capacity) == 1, "SourceV5 capacity process template is not unique for the soak")
    expected_capacity = {
        "template_sha256": planned_capacity[0]["template_sha256"],
        "calibration_id": capacity["calibration_id"],
        "request_template": capacity["request_template"],
        "context_template": capacity["context_template"],
        "evidence": capacity["evidence"],
    }
    require(canonical_bytes(expected_capacity) == canonical_bytes(qualification["capacity_template"]), "SourceV5 parent capacity template differs from captured spec/plan inputs")
    expected_pressure = {
        "condition_id": pressure["condition_id"], "condition_sha256": pressure["condition_sha256"],
        "condition": pressure["condition"], "pressure_calibration": pressure["pressure_calibration"],
        "readiness_thresholds": pressure["readiness_thresholds"], "schedule": pressure["schedule"],
    }
    require(canonical_bytes(expected_pressure) == canonical_bytes(qualification["pressure_condition"]), "SourceV5 parent pressure template differs from captured spec/plan inputs")
    feedback_rows = [item for item in plan["feedback_process_templates"] if (
        item["identity"]["host_id"] == recipe["identity"]["host_id"]
        and item["identity"]["workload"] == "mixed"
        and item["identity"]["profile"] == recipe["identity"]["profile"]
        and item["identity"]["comparison_family"] == "external_pressure"
        and item["identity"]["allocator"] == "allocatbelt"
        and item["identity"]["executor"] == "allocatbelt"
        and item["identity"]["pressure_condition_id"] == pressure["condition_id"]
    )]
    require(len(feedback_rows) == 1 and canonical_bytes(feedback_rows[0]) == canonical_bytes(qualification["feedback_process_template"]), "SourceV5 feedback template differs from the full frozen plan")
    nonce_binding = qualification["nonce_instantiation"]
    require(nonce_binding["campaign_id"] == plan["campaign_id"] and nonce_binding["job_run_id"] == planned_job["run_id"] and nonce_binding["ordinal"] == planned_job["ordinal"], "SourceV5 nonce scope differs from the exact planned soak job")
    require(nonce_binding["template_nonce"] == feedback_rows[0]["identity"]["prospective_nonce"], "SourceV5 nonce does not derive from the selected feedback template")
    return {
        "capacity_evidence_ready": bool(validation["capacity_evidence_ready"]),
        "feedback_runtime_composition_ready": bool(validation["feedback_runtime_composition_ready"]),
        "execution_ready": bool(validation["execution_ready"]),
        "full_gate_ready": bool(validation["full_gate_ready"]),
        "full_gate_gaps": validation["full_gate_gaps"],
        **supervision,
        "spec_sha256": spec_pin["semantic_sha256"],
        "plan_sha256": plan_pin["semantic_sha256"],
    }


def _audit_pressure_recipe(recipe: dict[str, Any], source_audit: dict[str, Any]) -> dict[str, Any]:
    binding = recipe["pressure"]
    pin = binding["recipe"]
    pressure_value, raw_sha, raw = read_json(Path(pin["path"]), "instantiated pressure recipe", MAX_RECIPE_BYTES)
    require(raw == canonical_bytes(pressure_value) and raw_sha == pin["raw_sha256"], "instantiated pressure recipe raw bytes differ from parent pin")
    pressure_reader_pin = binding["validator"]
    reader_path = safe_child(Path(source_audit["source_root"]), pressure_reader_pin["path"], "captured pressure validator")
    reader_raw, actual_reader_sha = read_stable_bytes(reader_path, "captured pressure validator", MAX_SOURCE_FILE_BYTES)
    require(actual_reader_sha == pressure_reader_pin["sha256"], "captured pressure validator differs from its SourceV5 inventory pin")
    module = types.ModuleType(f"soak_pressure_reader_{actual_reader_sha}")
    module.__file__ = str(reader_path)
    module.__package__ = ""
    try:
        exec(compile(reader_raw, str(reader_path), "exec", dont_inherit=True), module.__dict__)
        checked = module._validate_recipe(pressure_value, pin["semantic_sha256"])
    except (SyntaxError, ValueError, TypeError, KeyError) as error:
        raise SoakReadbackError(f"captured pressure validator rejected its instantiated recipe: {error}") from error
    identity = recipe["identity"]
    pressure_identity = checked["identity"]
    require(pressure_identity["host_id"] == identity["host_id"] and pressure_identity["run_id"] == identity["run_id"] and pressure_identity["nonce"] == identity["nonce"], "pressure recipe host/run/nonce differs from the soak parent identity")
    require(pressure_identity["allocator"] == "allocatbelt" and pressure_identity["executor"] == "allocatbelt" and pressure_identity["phase"] == "external_pressure", "pressure recipe role mapping differs from the feedback trace contract")
    require(pressure_identity["condition_id"] == recipe["qualification"]["pressure_condition"]["condition_id"], "pressure recipe condition ID differs from the SourceV5 condition template")
    require(checked["files"]["source_manifest"]["raw_sha256"] == source_audit["source_manifest_sha256"], "pressure recipe source-manifest raw pin differs from SourceV5")
    require(checked["files"]["application_binary"]["raw_sha256"] == source_audit["candidate_binary_sha256"], "pressure recipe application binary differs from timed soak artifact")
    capacity_evidence = recipe["qualification"]["capacity_template"]["evidence"]
    require(type(capacity_evidence) is dict, "pressure recipe has no validated SourceV5 capacity evidence reference")
    input_root = Path(recipe["qualification"]["spec"]["path"]).resolve(strict=True).parent
    capacity_path = safe_child(input_root, capacity_evidence["artifact"]["relative_path"], "SourceV5 app-byte capacity artifact")
    require(checked["files"]["application_capacity_calibration"]["raw_sha256"] == capacity_evidence["artifact"]["raw_sha256"] and checked["files"]["application_capacity_calibration"]["path"] == str(capacity_path), "pressure recipe app-byte calibration differs from SourceV5 capacity evidence")
    pressure_calibration = recipe["qualification"]["pressure_condition"]["pressure_calibration"]
    require(checked["calibration_sha256"] == pressure_calibration["artifact"]["raw_sha256"], "pressure recipe calibration digest differs from its SourceV5 pin")
    require(checked["schedule"]["seed"] == recipe["qualification"]["pressure_condition"]["schedule"]["seed"], "pressure recipe seed differs from SourceV5 condition schedule")
    require(checked["condition_sha256"] == binding["condition_sha256"], "pressure recipe semantic condition digest differs from parent pin")
    condition = recipe["qualification"]["pressure_condition"]
    request_pin = binding["request_template"]
    request_value, request_raw_sha, request_raw = read_json(Path(request_pin["path"]), "immutable SourceV5 pressure request template", MAX_SPEC_BYTES)
    require(request_raw == canonical_bytes(request_value) and request_raw_sha == request_pin["raw_sha256"] == condition["condition"]["raw_sha256"], "immutable SourceV5 pressure request template differs from its raw pin")
    supervision = _derive_v5_pressure_schedule(recipe["runtime"]["duration_seconds"], request_value, condition["schedule"])
    require(checked["schedule"] == supervision["pressure_schedule"], "pressure schedule does not preserve the raw condition while extending the complete soak and cleanup horizon")
    require(checked["schedule"]["duration_seconds"] == supervision["pressure_duration_seconds"], "pressure recipe duration differs from its independently derived enclosing horizon")
    require(checked["schedule"]["sample_interval_ms"] == condition["schedule"]["sample_interval_ms"] == 100, "pressure recipe cadence differs from SourceV5 condition schedule")
    require(checked["schedule"]["seed"] == condition["schedule"]["seed"], "pressure recipe seed differs from SourceV5 condition schedule")
    require(checked["schedule"]["minimum_overlap_seconds"] >= condition["readiness_thresholds"]["minimum_overlap_seconds"], "pressure recipe overlap threshold is below SourceV5")
    require(checked["schedule"]["duration_seconds"] * 1000 // checked["schedule"]["sample_interval_ms"] >= condition["readiness_thresholds"]["minimum_ready_samples"], "pressure recipe duration cannot meet the SourceV5 readiness sample count")
    require(checked["schedule"]["sample_interval_ms"] <= condition["readiness_thresholds"]["maximum_sample_gap_ms"], "pressure recipe cadence exceeds the SourceV5 readiness gap")
    return {"value": pressure_value, "reader": module, "recipe_sha256": pin["semantic_sha256"], "raw_sha256": raw_sha, "condition_sha256": checked["condition_sha256"], "reader_sha256": actual_reader_sha, **supervision}


def _stable_stream_lines(path: Path, label: str, maximum: int) -> Iterator[tuple[str, StableInput]]:
    """Compatibility helper is intentionally unused; each parser owns its stream context."""
    yield from ()


def _write_exclusive_json(path: Path, value: dict[str, Any]) -> str:
    parent = path.parent
    try:
        info = parent.stat()
    except OSError as error:
        raise SoakReadbackError(f"output parent is unavailable: {error}") from error
    require(stat.S_ISDIR(info.st_mode), "readback output parent is not a directory")
    require(info.st_mode & 0o077 == 0, "readback output directory must be private mode 0700")
    payload = canonical_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        raise SoakReadbackError(f"refusing to replace readback output {path}: {error}") from error
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(fd)
        checksum = hashlib.sha256(payload).hexdigest()
        dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return checksum
    finally:
        os.close(fd)


def _readback_json(path: Path, label: str, maximum: int = 256 * 1024) -> dict[str, Any]:
    value, _checksum, raw = read_json(path, label, maximum)
    require(raw == canonical_bytes(value), f"{label} is not canonical JSON")
    return value


def _make_launch_descriptor(
    audit: dict[str, Any],
    output_dir: Path,
    cpu_set: str,
    terminal_path: Path | None = None,
    samples_path: Path | None = None,
    *, path_value: str | None = None,
) -> dict[str, Any]:
    _parse_cpu_set(cpu_set)
    output_dir = _check_private_output_directory(output_dir)
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        return _make_launch_descriptor_v2(
            audit, output_dir, cpu_set, terminal_path, samples_path,
            path_value=path_value,
        )
    terminal = terminal_path or output_dir / "terminal-records.tsv"
    samples = samples_path or output_dir / "resource-samples.tsv"
    require(terminal.resolve(strict=False).parent == output_dir, "launch terminal path escaped its private output directory")
    require(samples.resolve(strict=False).parent == output_dir, "launch sample path escaped its private output directory")
    identity = audit["identity"]
    source = audit["source"]
    ring = audit["ring"]
    runtime = audit["recipe"]["runtime"]
    binary_path = source["candidate_binary_path"]
    argv = [
        binary_path,
        "--executor", "bounded",
        "--workload", "mixed",
        "--profile", identity["profile"],
        "--duration-seconds", str(audit["duration_seconds"]),
        "--sample-interval-ms", str(audit["sample_interval_ms"]),
        "--resource-ceiling-sha256", identity["resource_ceiling_sha256"],
        "--reference-ring", ring["path"],
        "--reference-ring-sha256", ring["sha256"],
        "--output-dir", str(output_dir),
    ]
    environment = {
        "ALLOCATBELT_APP_COMPARISON_FAMILY": "fixed_policy",
        "ALLOCATBELT_SOAK_REPORT": str(output_dir / "soak-receipt.json"),
        "ALLOCATBELT_SOAK_TERMINALS": str(terminal),
        "ALLOCATBELT_SOAK_SAMPLES": str(samples),
        "ALLOCATBELT_SOAK_CAMPAIGN_ID": identity["campaign_id"],
        "ALLOCATBELT_SOAK_HOST_ID": identity["host_id"],
        "ALLOCATBELT_SOAK_RUN_ID": identity["run_id"],
        "ALLOCATBELT_SOAK_ALLOCATOR": identity["allocator"],
        "ALLOCATBELT_SOAK_EXECUTOR": identity["executor"],
        "ALLOCATBELT_SOAK_PROFILE": identity["profile"],
        "ALLOCATBELT_SOAK_DURATION_SECONDS": str(audit["duration_seconds"]),
        "ALLOCATBELT_SOAK_SAMPLE_INTERVAL_MS": str(audit["sample_interval_ms"]),
        "ALLOCATBELT_SOAK_SOURCE_SHA256": identity["source_sha256"],
        "ALLOCATBELT_SOAK_BINARY_SHA256": identity["binary_sha256"],
        "ALLOCATBELT_SOAK_RESOURCE_CEILING_SHA256": identity["resource_ceiling_sha256"],
        "ALLOCATBELT_SOAK_REFERENCE_RING": ring["path"],
        "ALLOCATBELT_SOAK_REFERENCE_RING_SHA256": ring["sha256"],
        "ALLOCATBELT_SOAK_NONCE": identity["nonce"],
    }
    descriptor = {
        "schema": "allocatbelt.application-soak-launch-descriptor.v1",
        "recipe_sha256": audit["recipe_sha256"],
        "run_id": identity["run_id"],
        "execution_scope": "qualification" if runtime["mode"] == "qualified" else "functional_only",
        "binary_path": binary_path,
        "binary_sha256": source["candidate_binary_sha256"],
        "argv": argv,
        "argv_sha256": hashlib.sha256(canonical_bytes(argv)).hexdigest(),
        "environment": environment,
        "environment_sha256": hashlib.sha256(canonical_bytes(environment)).hexdigest(),
        "cpu_set": cpu_set,
        "cwd": audit["source_root"],
        "stdout_path": str(output_dir / "stdout.log"),
        "stderr_path": str(output_dir / "stderr.log"),
        "timing_path": str(output_dir / "time.txt"),
        "terminal_path": str(terminal),
        "samples_path": str(samples),
        "reader_path": audit["execution"]["reader_path"],
        "reader_sha256": audit["execution"]["reader_sha256"],
        "runner_path": audit["execution"]["runner_path"],
        "runner_sha256": audit["execution"]["runner_sha256"],
    }
    return descriptor


def _make_launch_descriptor_v2(
    audit: dict[str, Any], output_dir: Path, cpu_set: str,
    terminal_path: Path | None, samples_path: Path | None, *,
    path_value: str | None = None,
) -> dict[str, Any]:
    pressure_info = audit["source"].get("pressure_recipe")
    terminal = terminal_path or output_dir / "terminal-records.tsv"
    samples = samples_path or output_dir / "resource-samples.tsv"
    require(terminal.resolve(strict=False).parent == output_dir and samples.resolve(strict=False).parent == output_dir, "SourceV5 terminal/sample paths must be in the private soak output")
    identity = audit["identity"]
    ring = audit["ring"]
    source = audit["source"]
    binary = source["candidate_binary_path"]
    if audit["launch_enabled"] is False:
        return {
            "schema": "allocatbelt.application-soak-launch-descriptor.v2",
            "launch_enabled": False,
            "recipe_sha256": audit["recipe_sha256"],
            "run_id": identity["run_id"],
            "execution_scope": "disabled",
            "binary_path": binary,
            "binary_sha256": source["candidate_binary_sha256"],
            "argv": [],
            "argv_sha256": hashlib.sha256(canonical_bytes([])).hexdigest(),
            "environment": {},
            "environment_sha256": hashlib.sha256(canonical_bytes({})).hexdigest(),
            "cpu_set": cpu_set,
            "cwd": source["source_root"],
            "stdout_path": str(output_dir / "stdout.log"),
            "stderr_path": str(output_dir / "stderr.log"),
            "timing_path": str(output_dir / "time.txt"),
            "terminal_path": str(terminal),
            "samples_path": str(samples),
            "reader_path": audit["execution"]["reader_path"],
            "reader_sha256": audit["execution"]["reader_sha256"],
            "runner_path": audit["execution"]["runner_path"],
            "runner_sha256": audit["execution"]["runner_sha256"],
            "pressure_recipe_path": None,
            "pressure_recipe_sha256": None,
            "pressure_condition_sha256": None,
            "pressure_driver_path": None,
            "pressure_driver_sha256": None,
            "pressure_output_dir": None,
            "pressure_launch_path": None,
            "pressure_ready_path": None,
            "application_wall_timeout_seconds": source["application_supervision"]["application_wall_timeout_seconds"],
            "pressure_duration_seconds": source["application_supervision"]["pressure_duration_seconds"],
        }
    require(type(pressure_info) is dict, "SourceV5 soak recipe lacks a frozen driver recipe")
    pressure = pressure_info["value"]
    schedule = pressure["schedule"]
    application_cpus = schedule["application_cpu_affinity"]
    require(sorted(_parse_cpu_set(cpu_set)) == application_cpus, "runner CPU set differs from the frozen pressure application affinity")
    argv = [
        binary,
        "--executor", "bounded",
        "--workload", "mixed",
        "--profile", identity["profile"],
        "--duration-seconds", str(audit["duration_seconds"]),
        "--sample-interval-ms", str(audit["sample_interval_ms"]),
        "--resource-ceiling-sha256", identity["resource_ceiling_sha256"],
        "--reference-ring", ring["path"],
        "--reference-ring-sha256", ring["sha256"],
        "--output-dir", str(output_dir),
    ]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin") if path_value is None else path_value,
        "LANG": "C",
        "LC_ALL": "C",
        "ALLOCATBELT_APP_COMPARISON_FAMILY": "external_pressure",
        "ALLOCATBELT_APP_PRESSURE_NONCE": identity["nonce"],
        "ALLOCATBELT_APP_REPORT_NONCE": identity["nonce"],
        "ALLOCATBELT_APP_RUN_ID": identity["run_id"],
        "ALLOCATBELT_SOAK_REPORT": str(output_dir / "soak-receipt.json"),
        "ALLOCATBELT_SOAK_TERMINALS": str(terminal),
        "ALLOCATBELT_SOAK_SAMPLES": str(samples),
        "ALLOCATBELT_SOAK_CAMPAIGN_ID": identity["campaign_id"],
        "ALLOCATBELT_SOAK_HOST_ID": identity["host_id"],
        "ALLOCATBELT_SOAK_RUN_ID": identity["run_id"],
        "ALLOCATBELT_SOAK_ALLOCATOR": identity["allocator"],
        "ALLOCATBELT_SOAK_EXECUTOR": identity["executor"],
        "ALLOCATBELT_SOAK_PROFILE": identity["profile"],
        "ALLOCATBELT_SOAK_DURATION_SECONDS": str(audit["duration_seconds"]),
        "ALLOCATBELT_SOAK_SAMPLE_INTERVAL_MS": str(audit["sample_interval_ms"]),
        "ALLOCATBELT_SOAK_SOURCE_SHA256": identity["source_sha256"],
        "ALLOCATBELT_SOAK_BINARY_SHA256": identity["binary_sha256"],
        "ALLOCATBELT_SOAK_RESOURCE_CEILING_SHA256": identity["resource_ceiling_sha256"],
        "ALLOCATBELT_SOAK_REFERENCE_RING": ring["path"],
        "ALLOCATBELT_SOAK_REFERENCE_RING_SHA256": ring["sha256"],
        "ALLOCATBELT_SOAK_NONCE": identity["nonce"],
        "TMPDIR": pressure["process"]["application_tmpdir_path"],
    }
    return {
        "schema": "allocatbelt.application-soak-launch-descriptor.v2",
        "launch_enabled": True,
        "recipe_sha256": audit["recipe_sha256"],
        "run_id": identity["run_id"],
        "execution_scope": "qualification" if audit["mode"] == "qualified" else "functional_only",
        "binary_path": binary,
        "binary_sha256": source["candidate_binary_sha256"],
        "argv": argv,
        "argv_sha256": hashlib.sha256(canonical_bytes(argv)).hexdigest(),
        "environment": env,
        "environment_sha256": hashlib.sha256(canonical_bytes(env)).hexdigest(),
        "cpu_set": cpu_set,
        "cwd": pressure["process"]["application_tmpdir_path"],
        "stdout_path": str(output_dir / "stdout.log"),
        "stderr_path": str(output_dir / "stderr.log"),
        "timing_path": str(output_dir / "time.txt"),
        "terminal_path": str(terminal),
        "samples_path": str(samples),
        "reader_path": audit["execution"]["reader_path"],
        "reader_sha256": audit["execution"]["reader_sha256"],
        "runner_path": audit["execution"]["runner_path"],
        "runner_sha256": audit["execution"]["runner_sha256"],
        "pressure_recipe_path": audit["recipe"]["pressure"]["recipe"]["path"],
        "pressure_recipe_sha256": pressure_info["recipe_sha256"],
        "pressure_condition_sha256": pressure_info["condition_sha256"],
        "pressure_driver_path": str(safe_child(Path(source["source_root"]), audit["recipe"]["pressure"]["driver"]["path"], "SourceV5 pressure driver")),
        "pressure_driver_sha256": audit["recipe"]["pressure"]["driver"]["sha256"],
        "pressure_output_dir": str(output_dir / "pressure"),
        "pressure_launch_path": str(output_dir / "pressure" / "launch-record.json"),
        "pressure_ready_path": str(output_dir / "pressure" / "pressure-ready.json"),
        "application_wall_timeout_seconds": source["application_supervision"]["application_wall_timeout_seconds"],
        "pressure_duration_seconds": source["application_supervision"]["pressure_duration_seconds"],
    }


def _parse_cpu_set(value: str) -> set[int]:
    require(type(value) is str and 0 < len(value) <= 4096, "CPU set is empty or oversized")
    cpus: set[int] = set()
    for field in value.split(","):
        require(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*))?", field) is not None, "CPU set is not a canonical numeric affinity list")
        endpoints = field.split("-", 1)
        start = int(endpoints[0])
        end = int(endpoints[-1])
        require(start <= end and end < 1_000_000, "CPU set range is reversed or exceeds its finite bound")
        expanded = set(range(start, end + 1))
        require(not cpus.intersection(expanded), "CPU set repeats an affinity index")
        cpus.update(expanded)
    require(cpus, "CPU set is empty")
    return cpus


def _preflight_report(audit: dict[str, Any]) -> dict[str, Any]:
    identity = audit["identity"]
    source = audit["source"]
    ring = audit["ring"]
    report = {
        "schema": PREFLIGHT_SCHEMA,
        "recipe_sha256": audit["recipe_sha256"],
        "source_manifest_sha256": source["source_manifest_sha256"],
        "source_tree_sha256": source["source_tree_sha256"],
        "build_sha256": source["build_sha256"],
        "candidate_binary_sha256": source["candidate_binary_sha256"],
        "oracle_producer_binary_sha256": source["oracle_producer_binary_sha256"],
        "reference_ring_sha256": ring["sha256"],
        "reference_ring_rows": ring["rows"],
        "resource_ceiling_sha256": identity["resource_ceiling_sha256"],
        "fixed_policy_sha256": source["fixed_policy_sha256"],
        "fixed_global_control_baseline": source["fixed_global_control_baseline"],
        "mode": audit["mode"],
        "duration_seconds": audit["duration_seconds"],
        "sample_interval_ms": audit["sample_interval_ms"],
        "terminal_budget_bytes": audit["recipe"]["runtime"]["terminal_budget_bytes"],
        "sample_budget_bytes": audit["recipe"]["runtime"]["sample_budget_bytes"],
        "identity": identity,
        "execution": audit["execution"],
        "launch_descriptor": audit["launch_descriptor"],
        "reference_ring_path": ring["path"],
        "preflight_passed": True,
    }
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        report.update({
            "comparison_family": identity["comparison_family"],
            "launch_enabled": audit["launch_enabled"],
            "pressure_condition_sha256": audit["recipe"]["pressure"]["condition_sha256"],
            "feedback_template_sha256": audit["recipe"]["feedback_expectation"]["template_sha256"],
            "application_wall_timeout_seconds": audit["source"]["application_supervision"]["application_wall_timeout_seconds"],
            "pressure_duration_seconds": audit["source"]["application_supervision"]["pressure_duration_seconds"],
        })
    report["preflight_sha256"] = hashlib.sha256(canonical_bytes(report)).hexdigest()
    return report


def _verify_preflight(preflight_path: Path, current: dict[str, Any]) -> dict[str, Any]:
    preflight = _readback_json(preflight_path, "preflight receipt")
    expected_keys = {
        "schema", "recipe_sha256", "source_manifest_sha256", "source_tree_sha256", "build_sha256",
        "candidate_binary_sha256", "oracle_producer_binary_sha256", "reference_ring_sha256",
        "reference_ring_rows", "resource_ceiling_sha256", "fixed_policy_sha256",
        "fixed_global_control_baseline", "mode", "duration_seconds", "sample_interval_ms",
        "terminal_budget_bytes", "sample_budget_bytes",
        "identity", "execution", "launch_descriptor", "reference_ring_path",
        "preflight_passed", "preflight_sha256",
    }
    if current["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        expected_keys |= {"comparison_family", "launch_enabled", "pressure_condition_sha256", "feedback_template_sha256", "application_wall_timeout_seconds", "pressure_duration_seconds"}
    exact_object(preflight, expected_keys, "preflight receipt")
    require(preflight["schema"] == PREFLIGHT_SCHEMA and preflight["preflight_passed"] is True, "preflight receipt is not a passing soak preflight")
    material = dict(preflight)
    claimed = material.pop("preflight_sha256")
    require(digest(claimed, "preflight digest") == hashlib.sha256(canonical_bytes(material)).hexdigest(), "preflight receipt digest is invalid")
    expected = _preflight_report(current)
    require(preflight == expected, "source, build, binary, oracle, ring, identity, or runtime recipe changed after preflight")
    return preflight


def _launch_receipt_value(
    details: dict[str, Any],
    audit: dict[str, Any],
    preflight: dict[str, Any],
) -> dict[str, Any]:
    descriptor = audit["launch_descriptor"]
    require(details["requested_argv"] == descriptor["argv"], "supervisor launch argv differs from the frozen descriptor")
    require(details["executed_argv"] == descriptor["argv"], "executed child argv differs from the frozen descriptor")
    require(details["environment"] == descriptor["environment"], "supervisor child environment differs from the frozen descriptor")
    require(details["binary_path"] == descriptor["binary_path"], "supervisor executable path differs from the frozen descriptor")
    require(details["binary_sha256"] == descriptor["binary_sha256"], "supervisor executable bytes differ from the frozen descriptor")
    receipt = {
        "schema": LAUNCH_SCHEMA,
        "recipe_sha256": audit["recipe_sha256"],
        "preflight_sha256": preflight["preflight_sha256"],
        "run_id": audit["identity"]["run_id"],
        "execution_scope": descriptor["execution_scope"],
        "reader_path": descriptor["reader_path"],
        "reader_sha256": descriptor["reader_sha256"],
        "runner_path": descriptor["runner_path"],
        "runner_sha256": descriptor["runner_sha256"],
        "binary_path": details["binary_path"],
        "binary_sha256": details["binary_sha256"],
        "binary_device": details["binary_device"],
        "binary_inode": details["binary_inode"],
        "binary_size": details["binary_size"],
        "cpu_set": details["cpu_set"],
        "cwd": details["cwd"],
        "requested_argv": details["requested_argv"],
        "requested_argv_sha256": details["requested_argv_sha256"],
        "executed_argv": details["executed_argv"],
        "executed_file_descriptor": details["executed_file_descriptor"],
        "environment": details["environment"],
        "environment_sha256": details["environment_sha256"],
        "started_monotonic_ns": details["started_monotonic_ns"],
        "ended_monotonic_ns": details["ended_monotonic_ns"],
        "exit_code": details["status"],
        "child_return_code": details["child_return_code"],
        "timed_out": details["timed_out"],
        "artifact_budget_exceeded": details["artifact_budget_exceeded"],
        "received_signal": details["received_signal"],
    }
    resource_budget_pin = descriptor.get("resource_budget_pin")
    resource_monitor = descriptor.get("resource_monitor")
    resource_monitor_prefix = descriptor.get("resource_monitor_prefix")
    require(resource_budget_pin is None or
            (resource_monitor is not None) != (resource_monitor_prefix is not None),
            "Source5 bounded launch must bind one complete monitor or monitor prefix")
    require(resource_budget_pin is not None or
            (resource_monitor is None and resource_monitor_prefix is None),
            "historical Source5 launch cannot carry a resource monitor")
    if resource_budget_pin is not None:
        exact_object(resource_budget_pin, {"path", "raw_sha256", "semantic_sha256"},
                     "Source5 bounded launch resource-budget pin")
        if resource_monitor is not None:
            exact_object(resource_monitor, {
                "schema", "budget", "stream", "row_count", "high_water",
                "final_usage", "failure", "prefix_sha256",
            }, "Source5 bounded launch resource-monitor summary")
            require(resource_monitor["schema"] ==
                        "allocatbelt.application-source5-soak-resource-monitor-summary.v1" and
                    resource_monitor["budget"] == resource_budget_pin and
                    type(resource_monitor["row_count"]) is int and
                    resource_monitor["row_count"] > 0 and
                    (resource_monitor["failure"] is None or
                     type(resource_monitor["failure"]) is str),
                    "Source5 bounded launch monitor summary differs from its budget")
            receipt.update({
                "schema": LAUNCH_SCHEMA_V2,
                "resource_budget": resource_budget_pin,
                "resource_monitor": resource_monitor,
                "resource_budget_exceeded": details.get(
                    "resource_budget_exceeded", False,
                ),
            })
        else:
            prefix = exact_object(resource_monitor_prefix, {
                "schema", "path", "budget", "row_count", "prefix_sha256",
                "last_row_sha256", "high_water", "failure",
            }, "Source5 bounded launch resource-monitor prefix")
            require(prefix["schema"] ==
                        "allocatbelt.application-source5-soak-resource-monitor-prefix.v1" and
                    prefix["path"] == descriptor.get("resource_monitor_path") and
                    prefix["budget"] == resource_budget_pin and
                    type(prefix["row_count"]) is int and prefix["row_count"] > 0 and
                    type(prefix["prefix_sha256"]) is str and
                    re.fullmatch(r"[0-9a-f]{64}", prefix["prefix_sha256"]) is not None and
                    type(prefix["last_row_sha256"]) is str and
                    re.fullmatch(r"[0-9a-f]{64}", prefix["last_row_sha256"]) is not None and
                    prefix["failure"] is None,
                    "Source5 bounded launch monitor prefix differs from its budget")
            receipt.update({
                "schema": LAUNCH_SCHEMA_V3,
                "resource_budget": resource_budget_pin,
                "resource_monitor_prefix": prefix,
                "resource_budget_exceeded": details.get(
                    "resource_budget_exceeded", False,
                ),
            })
    receipt["launch_receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    return receipt


def _verify_launch_receipt(
    output_dir: Path,
    audit: dict[str, Any],
    preflight: dict[str, Any],
    *,
    require_success: bool,
) -> tuple[dict[str, Any], str]:
    path = _artifact_from_receipt(output_dir, "soak-launch.json", "parent launch receipt", MAX_RECEIPT_BYTES)
    receipt, checksum, raw = read_json(path, "parent launch receipt", MAX_RECEIPT_BYTES)
    require(raw == canonical_bytes(receipt), "parent launch receipt is not canonical JSON")
    expected_keys = {
        "schema", "recipe_sha256", "preflight_sha256", "run_id", "execution_scope",
        "reader_path", "reader_sha256", "runner_path", "runner_sha256", "binary_path",
        "binary_sha256", "binary_device", "binary_inode", "binary_size", "cpu_set", "cwd",
        "requested_argv", "requested_argv_sha256", "executed_argv", "environment",
        "executed_file_descriptor", "environment_sha256", "started_monotonic_ns", "ended_monotonic_ns", "exit_code",
        "child_return_code", "timed_out", "artifact_budget_exceeded", "received_signal",
        "launch_receipt_sha256",
    }
    resource_budget_pin = audit["launch_descriptor"].get("resource_budget_pin")
    monitor_prefix_mode = (
        resource_budget_pin is not None and
        receipt.get("schema") == LAUNCH_SCHEMA_V3
    )
    if resource_budget_pin is not None:
        expected_keys |= {
            "resource_budget", "resource_budget_exceeded",
            "resource_monitor_prefix" if monitor_prefix_mode else
                "resource_monitor",
        }
    exact_object(receipt, expected_keys, "parent launch receipt")
    material = dict(receipt)
    claimed = material.pop("launch_receipt_sha256")
    require(digest(claimed, "launch receipt digest") == hashlib.sha256(canonical_bytes(material)).hexdigest(), "parent launch receipt digest is invalid")
    descriptor = audit["launch_descriptor"]
    static_expected = {
        "schema": (LAUNCH_SCHEMA_V3 if monitor_prefix_mode else
                   LAUNCH_SCHEMA_V2 if resource_budget_pin is not None else
                   LAUNCH_SCHEMA),
        "recipe_sha256": audit["recipe_sha256"],
        "preflight_sha256": preflight["preflight_sha256"],
        "run_id": audit["identity"]["run_id"],
        "execution_scope": descriptor["execution_scope"],
        "reader_path": descriptor["reader_path"],
        "reader_sha256": descriptor["reader_sha256"],
        "runner_path": descriptor["runner_path"],
        "runner_sha256": descriptor["runner_sha256"],
        "binary_path": descriptor["binary_path"],
        "binary_sha256": descriptor["binary_sha256"],
        "cpu_set": descriptor["cpu_set"],
        "cwd": descriptor["cwd"],
        "requested_argv": descriptor["argv"],
        "requested_argv_sha256": descriptor["argv_sha256"],
        "environment": descriptor["environment"],
        "environment_sha256": descriptor["environment_sha256"],
    }
    for name, expected in static_expected.items():
        require(receipt[name] == expected, f"parent launch receipt {name} differs from the frozen launch descriptor")
    if resource_budget_pin is not None and not monitor_prefix_mode:
        monitor = exact_object(receipt["resource_monitor"], {
            "schema", "budget", "stream", "row_count", "high_water",
            "final_usage", "failure", "prefix_sha256",
        }, "Source5 launch resource-monitor summary")
        stream_pin = exact_object(monitor["stream"], {"path", "raw_sha256"},
                                  "Source5 launch resource-monitor stream pin")
        digest(stream_pin["raw_sha256"],
               "Source5 launch resource-monitor raw SHA-256")
        require(receipt["resource_budget"] == resource_budget_pin and
                monitor["schema"] ==
                    "allocatbelt.application-source5-soak-resource-monitor-summary.v1" and
                monitor["budget"] == resource_budget_pin and
                stream_pin["path"] == audit["launch_descriptor"].get(
                    "resource_monitor_path",
                ) and
                type(monitor["row_count"]) is int and monitor["row_count"] > 0 and
                type(receipt["resource_budget_exceeded"]) is bool and
                (monitor["failure"] is None or
                 type(monitor["failure"]) is str) and
                (monitor["failure"] is None or
                 receipt["resource_budget_exceeded"] is True),
                "Source5 bounded launch budget/monitor binding differs")
    elif monitor_prefix_mode:
        prefix = exact_object(receipt["resource_monitor_prefix"], {
            "schema", "path", "budget", "row_count", "prefix_sha256",
            "last_row_sha256", "high_water", "failure",
        }, "Source5 launch resource-monitor prefix")
        require(receipt["resource_budget"] == resource_budget_pin and
                prefix["schema"] ==
                    "allocatbelt.application-source5-soak-resource-monitor-prefix.v1" and
                prefix["path"] == audit["launch_descriptor"].get(
                    "resource_monitor_path",
                ) and
                prefix["budget"] == resource_budget_pin and
                type(prefix["row_count"]) is int and prefix["row_count"] > 0 and
                type(prefix["prefix_sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", prefix["prefix_sha256"]) is not None and
                type(prefix["last_row_sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", prefix["last_row_sha256"]) is not None and
                prefix["failure"] is None and
                type(receipt["resource_budget_exceeded"]) is bool and
                receipt["resource_budget_exceeded"] is False,
                "Source5 bounded launch prefix/budget pin differs")
    require(
        receipt["executed_argv"] == descriptor["argv"]
        and type(receipt["executed_file_descriptor"]) is str
        and re.fullmatch(r"/proc/self/fd/[1-9][0-9]{0,5}", receipt["executed_file_descriptor"]) is not None,
        "parent launch receipt does not bind execution through the verified open binary descriptor",
    )
    for name in ("binary_device", "binary_inode", "binary_size", "started_monotonic_ns", "ended_monotonic_ns", "exit_code"):
        uint(receipt[name], f"parent launch receipt {name}", maximum=U128_MAX if name.endswith("_ns") else U64_MAX)
    require(type(receipt["child_return_code"]) is int and -255 <= receipt["child_return_code"] <= U64_MAX, "parent launch receipt child status is outside its finite signed bound")
    require(receipt["binary_inode"] > 0 and receipt["binary_size"] > 0, "parent launch receipt binary file identity is empty")
    require(receipt["started_monotonic_ns"] < receipt["ended_monotonic_ns"], "parent launch receipt monotonic interval is empty or reversed")
    require(type(receipt["timed_out"]) is bool and type(receipt["artifact_budget_exceeded"]) is bool, "parent launch receipt status flags are not booleans")
    if resource_budget_pin is not None:
        require(type(receipt["resource_budget_exceeded"]) is bool,
                "Source5 bounded launch resource status flag is malformed")
    require(receipt["received_signal"] is None or type(receipt["received_signal"]) is int, "parent launch receipt signal is malformed")
    if receipt["received_signal"] is not None:
        uint(receipt["received_signal"], "parent launch receipt signal", maximum=64, positive=True)
    if receipt["timed_out"]:
        require(receipt["exit_code"] == 124, "timed launch must use the stable timeout status 124")
    elif receipt["artifact_budget_exceeded"]:
        require(receipt["exit_code"] == 125, "over-budget launch must use the stable refusal status 125")
    elif resource_budget_pin is not None and receipt["resource_budget_exceeded"]:
        require(receipt["exit_code"] == 125,
                "resource-budget launch refusal must use the stable status 125")
    elif receipt["received_signal"] is not None:
        require(receipt["exit_code"] == 128 + receipt["received_signal"], "signal-driven launch status differs from 128+signal")
    elif receipt["child_return_code"] < 0:
        require(receipt["exit_code"] == 128 - receipt["child_return_code"], "signal-terminated child status differs from 128+signal")
    else:
        require(receipt["exit_code"] == receipt["child_return_code"], "parent launch status differs from the child status")
    if require_success:
        require(
            receipt["exit_code"] == 0
            and receipt["child_return_code"] == 0
            and receipt["timed_out"] is False
            and receipt["artifact_budget_exceeded"] is False
            and (resource_budget_pin is None or
                 receipt["resource_budget_exceeded"] is False)
            and receipt["received_signal"] is None,
            "qualified readback requires a successful parent launch receipt",
        )
    return receipt, checksum


def _validate_receipt_json(
    receipt_path: Path,
    artifact_dir: Path,
    audit: dict[str, Any],
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    receipt, receipt_sha, _raw = read_json(receipt_path, "Rust soak receipt", MAX_RECEIPT_BYTES)
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        return _validate_receipt_json_v2(receipt, receipt_sha, _raw, audit)
    keys = {
        "actual_trace_duration_ns", "allocator", "attempted", "binary_sha256", "campaign_id",
        "comparison_family", "completed", "drain_duration_ns", "drain_ended_monotonic_ns",
        "duration_seconds", "ended_monotonic_ns", "errors", "executor", "final_global_control_used",
        "final_global_cpu_used", "final_global_disk_used", "final_global_live_tenants",
        "final_global_memory_used", "final_global_network_used", "final_global_tasks_used",
        "final_hour_rss_median_kib", "final_scope_disk_used", "final_scope_memory_used",
        "final_scope_network_used", "final_tenant_control_used", "final_tenant_cpu_used",
        "final_tenant_disk_used", "final_tenant_memory_used", "final_tenant_network_used",
        "final_tenant_tasks_used", "first_post_warmup_hour_rss_median_kib", "fixed_global_control_baseline",
        "host_id", "logical_window", "lost", "nonce", "postprocess_after_shutdown_ns",
        "postprocess_ended_monotonic_ns", "production_cpu_ended_ns", "production_cpu_ns",
        "production_cpu_started_ns", "profile", "qualified_horizon", "reference_average_rate_per_second",
        "reference_ring_rows", "reference_ring_sha256", "resource_ceiling_sha256",
        "resource_samples_count", "resource_samples_relative_path", "resource_samples_sha256",
        "run_id", "sample_interval_ms", "schema", "shutdown_duration_ns", "shutdown_ended_monotonic_ns",
        "source_sha256", "started_monotonic_ns", "terminal_records", "terminal_stream_relative_path",
        "terminal_stream_sha256", "trace_ended_monotonic_ns", "warmup_seconds", "workload",
    }
    exact_object(receipt, keys, "Rust soak receipt")
    require(receipt["schema"] == RUNTIME_SOAK_SCHEMA, "unsupported Rust soak receipt schema")
    identity = audit["identity"]
    recipe = audit["recipe"]
    for field in (
        "campaign_id", "host_id", "run_id", "allocator", "executor", "profile", "source_sha256",
        "binary_sha256", "resource_ceiling_sha256", "nonce",
    ):
        require(receipt[field] == identity[field], f"Rust soak receipt {field} differs from the independent parent recipe")
    require(receipt["comparison_family"] == "fixed_policy", "Rust soak receipt is not fixed-policy")
    require(receipt["workload"] == "mixed", "Rust soak receipt workload differs")
    require(receipt["duration_seconds"] == audit["duration_seconds"], "Rust soak receipt duration differs from the frozen mode")
    require(receipt["sample_interval_ms"] == SAMPLE_INTERVAL_MS, "Rust soak receipt sample interval differs")
    require(receipt["logical_window"] == LOGICAL_WINDOW and receipt["warmup_seconds"] == WARMUP_SECONDS, "Rust soak receipt window/warmup differs")
    require(receipt["reference_ring_sha256"] == audit["ring"]["sha256"], "Rust receipt reference ring SHA differs from the independent pre-run ring pin")
    require(receipt["reference_ring_rows"] == audit["ring"]["rows"], "Rust receipt reference ring row count differs")
    require(receipt["reference_average_rate_per_second"] == audit["ring"]["average_rate_per_second"], "Rust receipt oracle rate differs")
    require(receipt["fixed_global_control_baseline"] == audit["source"]["fixed_global_control_baseline"], "Rust receipt Control baseline differs from independent calibration")
    require(type(receipt["qualified_horizon"]) is bool, "Rust child qualification flag is not boolean")
    return receipt, receipt_sha, recipe


def _validate_receipt_json_v2(
    receipt: dict[str, Any], receipt_sha: str, raw: bytes, audit: dict[str, Any],
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    keys = {
        "schema", "campaign_id", "host_id", "run_id", "nonce", "allocator", "executor", "workload",
        "profile", "comparison_family", "mode", "qualification_eligible", "source_sha256", "binary_sha256",
        "resource_ceiling_sha256", "reference_ring_sha256", "reference_ring_rows", "reference_average_rate_per_second",
        "duration_seconds", "sample_interval_ms", "warmup_seconds", "logical_window", "attempted", "completed",
        "errors", "lost", "terminal_records", "terminal_stream_sha256", "terminal_stream_relative_path",
        "resource_samples_count", "resource_samples_sha256", "resource_samples_relative_path",
        "first_post_warmup_hour_rss_median_kib", "final_hour_rss_median_kib", "feedback_started",
        "feedback_worker_joined", "feedback_worker_failure", "feedback_trace_worker_joined", "qualified_horizon",
        "started_monotonic_ns", "started_monotonic_lower_ns", "started_monotonic_upper_ns",
        "trace_ended_monotonic_ns", "trace_ended_monotonic_lower_ns", "trace_ended_monotonic_upper_ns",
        "drain_ended_monotonic_ns", "drain_ended_monotonic_lower_ns", "drain_ended_monotonic_upper_ns",
        "shutdown_ended_monotonic_ns", "shutdown_ended_monotonic_lower_ns", "shutdown_ended_monotonic_upper_ns",
        "postprocess_ended_monotonic_ns", "postprocess_ended_monotonic_lower_ns", "postprocess_ended_monotonic_upper_ns",
        "ended_monotonic_ns", "actual_trace_duration_ns", "drain_duration_ns", "shutdown_duration_ns",
        "postprocess_after_shutdown_ns", "production_cpu_started_ns", "production_cpu_ended_ns", "production_cpu_ns",
        "final_global_live_tenants", "final_global_cpu_used", "final_global_memory_used", "final_global_disk_used",
        "final_global_network_used", "final_global_tasks_used", "final_global_control_used", "fixed_global_control_baseline",
        "final_tenant_cpu_used", "final_tenant_memory_used", "final_tenant_disk_used", "final_tenant_network_used",
        "final_tenant_tasks_used", "final_tenant_control_used", "final_scope_memory_used", "final_scope_disk_used",
        "final_scope_network_used",
    }
    exact_object(receipt, keys, "runtime-soak.v2 receipt")
    require(raw == canonical_bytes(receipt), "runtime-soak.v2 receipt is not canonical JSON")
    require(receipt["schema"] == RUNTIME_SOAK_SCHEMA_V2, "SourceV5 soak requires runtime-soak.v2")
    identity = audit["identity"]
    for field in ("campaign_id", "host_id", "run_id", "nonce", "allocator", "executor", "profile", "source_sha256", "binary_sha256", "resource_ceiling_sha256"):
        require(receipt[field] == identity[field], f"runtime-soak.v2 {field} differs from the frozen parent identity")
    require(receipt["workload"] == "mixed" and receipt["comparison_family"] == "external_pressure" and receipt["mode"] == "soak", "runtime-soak.v2 workload/family/mode differs from the original soak job")
    require(receipt["qualification_eligible"] is False, "runtime-soak.v2 child cannot author its own qualification eligibility")
    require(receipt["duration_seconds"] == audit["duration_seconds"] and receipt["sample_interval_ms"] == SAMPLE_INTERVAL_MS, "runtime-soak.v2 duration/cadence differs from the parent recipe")
    require(receipt["warmup_seconds"] == WARMUP_SECONDS and receipt["logical_window"] == LOGICAL_WINDOW, "runtime-soak.v2 warmup/window differs from the frozen contract")
    ring = audit["ring"]
    require(receipt["reference_ring_sha256"] == ring["sha256"] and receipt["reference_ring_rows"] == ring["rows"] and receipt["reference_average_rate_per_second"] == ring["average_rate_per_second"], "runtime-soak.v2 reference ring identity differs")
    require(receipt["fixed_global_control_baseline"] == audit["source"]["fixed_global_control_baseline"], "runtime-soak.v2 Control baseline differs from source calibration")
    for field in ("feedback_started", "feedback_worker_joined", "feedback_trace_worker_joined", "qualified_horizon"):
        require(type(receipt[field]) is bool, f"runtime-soak.v2 {field} is not boolean")
    require(receipt["feedback_started"] and receipt["feedback_worker_joined"] and receipt["feedback_trace_worker_joined"], "runtime-soak.v2 feedback service or trace worker did not complete")
    require(receipt["feedback_worker_failure"] is None, "runtime-soak.v2 feedback worker reported a failure")
    for phase in SOAK_RECEIPT_CLOCK_PHASES:
        scalar = uint(receipt[f"{phase}_monotonic_ns"], f"runtime-soak.v2 {phase} scalar", positive=True, maximum=U128_MAX)
        lower = uint(receipt[f"{phase}_monotonic_lower_ns"], f"runtime-soak.v2 {phase} lower bound", positive=True, maximum=U128_MAX)
        upper = uint(receipt[f"{phase}_monotonic_upper_ns"], f"runtime-soak.v2 {phase} upper bound", positive=True, maximum=U128_MAX)
        require(lower <= upper and scalar == lower, f"runtime-soak.v2 {phase} scalar is not the lower TraceClock endpoint")
    return receipt, receipt_sha, audit["recipe"]


def _artifact_from_receipt(artifact_dir: Path, basename: object, label: str, maximum: int) -> Path:
    name = text(basename, f"{label} relative path", maximum=256)
    require("/" not in name and "\\" not in name and name not in (".", ".."), f"{label} must be a single safe basename")
    path = artifact_dir / name
    try:
        parent_real = artifact_dir.resolve(strict=True)
        path_info = path.lstat()
    except OSError as error:
        raise SoakReadbackError(f"{label} is missing: {error}") from error
    require(stat.S_ISREG(path_info.st_mode) and not stat.S_ISLNK(path_info.st_mode), f"{label} must be a regular non-symlink file")
    require(path.resolve(strict=True).parent == parent_real, f"{label} escapes the soak output directory")
    require(path_info.st_mode & 0o077 == 0, f"{label} permissions are not private")
    require(path_info.st_size <= maximum, f"{label} exceeds its finite artifact bound")
    return path


def _parse_terminal_stream(path: Path, receipt: dict[str, Any], ring: dict[str, Any], maximum: int) -> tuple[str, int]:
    expected_checksums = ring["expected_checksums"]
    with StableInput(path, "terminal stream", maximum) as stream:
        first = stream.readline().decode("ascii", errors="strict").rstrip("\n")
        ring_hash_line = stream.readline().decode("ascii", errors="strict").rstrip("\n")
        rows_line = stream.readline().decode("ascii", errors="strict").rstrip("\n")
        header = stream.readline().decode("ascii", errors="strict").rstrip("\n")
        require(first == f"schema\t{TERMINAL_SCHEMA}", "terminal stream schema differs")
        require(ring_hash_line == f"reference_ring_sha256\t{ring['sha256']}", "terminal stream ring digest differs")
        require(rows_line == f"reference_ring_rows\t{ring['rows']}", "terminal stream reference row count differs")
        require(header == "\t".join(TERMINAL_HEADER), "terminal stream header differs")
        row_count = 0
        attempted = uint(receipt["attempted"], "soak attempted", positive=True)
        for line_number in range(attempted):
            raw = stream.readline()
            require(raw.endswith(b"\n") and b"\r" not in raw, f"terminal row {line_number} is not newline framed")
            try:
                line = raw[:-1].decode("ascii")
            except UnicodeError as error:
                raise SoakReadbackError(f"terminal row {line_number} is not ASCII") from error
            fields = line.split("\t")
            require(len(fields) == len(TERMINAL_HEADER), f"terminal row {line_number} has the wrong column count")
            global_id = parse_uint(fields[0], f"terminal row {line_number} global ID")
            reference_id = parse_uint(fields[1], f"terminal row {line_number} reference ID")
            require(global_id == line_number, f"terminal global ID {global_id} is reordered or missing")
            expected_reference_id = global_id % len(expected_checksums)
            require(reference_id == expected_reference_id, f"terminal {global_id} does not map to its independent reference work ID")
            expected_family = FAMILIES[reference_id % len(FAMILIES)]
            require(fields[2] == expected_family and fields[3] == "completed", f"terminal {global_id} family/status differs")
            observed = parse_uint(fields[4], f"terminal {global_id} observed checksum")
            ring_expected = parse_uint(fields[5], f"terminal {global_id} ring checksum")
            independent_expected = expected_checksums[reference_id]
            require(ring_expected == independent_expected, f"terminal {global_id} expected checksum is not from the pinned external ring")
            require(observed == independent_expected, f"terminal {global_id} result differs from the pinned external ring")
            row_count += 1
        require(stream.readline() == b"", "terminal stream has rows beyond the receipt's exact attempted count")
        checksum = stream.finish()
    require(row_count == attempted, "terminal stream count differs from attempted")
    require(checksum == receipt["terminal_stream_sha256"], "terminal stream SHA differs from the Rust receipt")
    require(row_count == receipt["completed"] == receipt["terminal_records"], "terminal records do not reconcile with completed count")
    return checksum, row_count


def _check_numeric_sample(row: dict[str, int], audit: dict[str, Any], index: int) -> None:
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        return _check_numeric_sample_v2(row, audit, index)
    source = audit["source"]
    domain = source["domain_ceilings"]
    scope = source["scope_limits"]
    baseline = source["fixed_global_control_baseline"]
    for owner in OWNERS:
        for dimension in DOMAINS:
            ceiling = row[f"{owner}_{dimension}_ceiling"]
            limit = row[f"{owner}_{dimension}_limit"]
            used = row[f"{owner}_{dimension}_used"]
            require(ceiling == domain[dimension] and limit == domain[dimension], f"sample {index} {owner} {dimension} ceiling/current limit differs from the frozen policy")
            require(used <= limit, f"sample {index} {owner} {dimension} usage exceeds its current limit")
    # Global, tenant, and scope snapshots are sampled independently.  Check
    # each ledger against its own frozen bounds instead of asserting a
    # cross-lock transactional relationship for one sample row.
    require(row["global_control_used"] >= baseline, f"sample {index} global Control is below its calibrated baseline")
    for field, expected in (
        ("scope_memory_limit", scope["managed_memory_limit"]),
        ("scope_disk_limit", scope["disk_operation_limit"]),
        ("scope_network_limit", scope["network_operation_limit"]),
    ):
        require(row[field] == expected, f"sample {index} {field} differs from the frozen scope limit")
    for used_name, limit_name in (
        ("scope_memory_used", "scope_memory_limit"),
        ("scope_disk_used", "scope_disk_limit"),
        ("scope_network_used", "scope_network_limit"),
    ):
        require(row[used_name] <= row[limit_name], f"sample {index} {used_name} exceeds its scope limit")
    for direction in DIRECTIONS:
        bucket = source["byte_buckets"][direction]
        names = {
            "rate": f"{direction}_rate_limit_bps",
            "burst": f"{direction}_rate_burst_bytes",
            "ceiling_rate": f"{direction}_rate_ceiling_bps",
            "ceiling_burst": f"{direction}_rate_ceiling_burst_bytes",
            "max_reservations": f"{direction}_rate_max_reservations",
            "available": f"{direction}_rate_available_bytes",
            "reserved": f"{direction}_rate_reserved_bytes",
            "reservations": f"{direction}_rate_reservations",
        }
        require(row[names["rate"]] == bucket["bytes_per_second"], f"sample {index} {direction} current byte rate differs from fixed policy")
        require(row[names["burst"]] == bucket["burst_bytes"], f"sample {index} {direction} current burst differs from fixed policy")
        require(row[names["ceiling_rate"]] == bucket["ceiling_bytes_per_second"], f"sample {index} {direction} rate ceiling differs from fixed policy")
        require(row[names["ceiling_burst"]] == bucket["ceiling_burst_bytes"], f"sample {index} {direction} burst ceiling differs from fixed policy")
        require(row[names["max_reservations"]] == bucket["max_reservations"], f"sample {index} {direction} reservation cap differs from fixed policy")
        available = row[names["available"]]
        reserved = row[names["reserved"]]
        reservations = row[names["reservations"]]
        require(available <= row[names["burst"]], f"sample {index} {direction} available credits exceed the burst")
        require(reservations <= reserved <= reservations * bucket["ceiling_burst_bytes"],
                f"sample {index} {direction} retained credits exceed owner bounds")
        require(reservations <= bucket["max_reservations"], f"sample {index} {direction} reservation owners exceed their cap")
        require((reserved == 0) == (reservations == 0), f"sample {index} {direction} reserved bytes and owner count disagree")


def _check_numeric_sample_v2(row: dict[str, int], audit: dict[str, Any], index: int) -> None:
    """Check SourceV5 hard bounds while allowing independently replayed controls to move."""
    source = audit["source"]
    domain = source["domain_ceilings"]
    scope = source["scope_limits"]
    baseline = source["fixed_global_control_baseline"]
    controls = source["feedback_context"]["controls"]
    for owner in OWNERS:
        for dimension in DOMAINS:
            ceiling = row[f"{owner}_{dimension}_ceiling"]
            limit = row[f"{owner}_{dimension}_limit"]
            used = row[f"{owner}_{dimension}_used"]
            require(ceiling == domain[dimension], f"sample {index} {owner} {dimension} hard ceiling differs from SourceV5")
            if dimension == "cpu":
                control = controls["cpu"]
                require(control["floor"] <= limit <= control["ceiling"], f"sample {index} {owner} CPU limit is outside feedback policy bounds")
            else:
                require(limit == ceiling, f"sample {index} {owner} {dimension} limit differs from its immutable ceiling")
            require(used <= limit, f"sample {index} {owner} {dimension} usage exceeds its observed current limit")
    require(row["global_control_used"] >= baseline, f"sample {index} global Control is below its calibrated baseline")
    for field, expected in (
        ("scope_memory_limit", scope["managed_memory_limit"]),
        ("scope_disk_limit", scope["disk_operation_limit"]),
        ("scope_network_limit", scope["network_operation_limit"]),
    ):
        require(row[field] == expected, f"sample {index} {field} differs from the frozen scope bound")
    for used_name, limit_name in (
        ("scope_memory_used", "scope_memory_limit"),
        ("scope_disk_used", "scope_disk_limit"),
        ("scope_network_used", "scope_network_limit"),
    ):
        require(row[used_name] <= row[limit_name], f"sample {index} {used_name} exceeds its scope bound")
    for direction in DIRECTIONS:
        bucket = source["byte_buckets"][direction]
        names = {
            "rate": f"{direction}_rate_limit_bps",
            "burst": f"{direction}_rate_burst_bytes",
            "ceiling_rate": f"{direction}_rate_ceiling_bps",
            "ceiling_burst": f"{direction}_rate_ceiling_burst_bytes",
            "max_reservations": f"{direction}_rate_max_reservations",
            "available": f"{direction}_rate_available_bytes",
            "reserved": f"{direction}_rate_reserved_bytes",
            "reservations": f"{direction}_rate_reservations",
        }
        if direction in ("disk", "download"):
            resource = "disk" if direction == "disk" else "download"
            control = controls[resource]
            require(control["floor"] <= row[names["rate"]] <= control["ceiling"], f"sample {index} {direction} rate is outside feedback policy bounds")
        else:
            require(row[names["rate"]] == bucket["bytes_per_second"], f"sample {index} upload rate differs from its unregulated fixed policy")
        require(row[names["burst"]] == bucket["burst_bytes"], f"sample {index} {direction} burst differs from the fixed policy")
        require(row[names["ceiling_rate"]] == bucket["ceiling_bytes_per_second"], f"sample {index} {direction} hard rate ceiling differs")
        require(row[names["ceiling_burst"]] == bucket["ceiling_burst_bytes"], f"sample {index} {direction} hard burst ceiling differs")
        require(row[names["max_reservations"]] == bucket["max_reservations"], f"sample {index} {direction} reservation cap differs")
        available, reserved, reservations = row[names["available"]], row[names["reserved"]], row[names["reservations"]]
        require(available <= row[names["burst"]], f"sample {index} {direction} available credits exceed the burst")
        require(reservations <= reserved <= reservations * bucket["ceiling_burst_bytes"],
                f"sample {index} {direction} retained credits exceed owner bounds")
        require(reservations <= bucket["max_reservations"], f"sample {index} {direction} reservations exceed their fixed cap")
        require((reserved == 0) == (reservations == 0), f"sample {index} {direction} reserved bytes and reservation count disagree")


def rss_window_for_index(index: int) -> str | None:
    elapsed_ns = index * SAMPLE_INTERVAL_NS
    if 300_000_000_000 <= elapsed_ns < 3_900_000_000_000:
        return "first_post_warmup_hour"
    if 7_200_000_000_000 <= elapsed_ns < QUALIFIED_SECONDS * 1_000_000_000:
        return "final_hour"
    return None


def _parse_samples(path: Path, receipt: dict[str, Any], audit: dict[str, Any], maximum: int) -> dict[str, Any]:
    duration = audit["duration_seconds"]
    expected_count = duration * 1000 // SAMPLE_INTERVAL_MS + 1
    require(expected_count <= QUALIFIED_SECONDS * 1000 // SAMPLE_INTERVAL_MS + 1, "sample count exceeds the fixed horizon bound")
    require(receipt["resource_samples_count"] == expected_count, "receipt sample count differs from its exact duration")
    required = uint(receipt["resource_samples_count"], "receipt resource sample count")
    require(required == expected_count, "resource sample count is not exact")
    first_window: list[int] = []
    final_window: list[int] = []
    last_timestamp = -1
    with StableInput(path, "resource sample stream", maximum) as stream:
        header_raw = stream.readline()
        require(header_raw.endswith(b"\n") and b"\r" not in header_raw, "sample header is not newline framed")
        try:
            header = header_raw[:-1].decode("ascii").split("\t")
        except UnicodeError as error:
            raise SoakReadbackError("sample header is not ASCII") from error
        require(header == list(SAMPLE_HEADER), "resource sample columns differ from the exact schema")
        started = uint(receipt["started_monotonic_ns"], "soak monotonic start", maximum=U128_MAX)
        for index in range(required):
            raw = stream.readline()
            require(raw.endswith(b"\n") and b"\r" not in raw, f"sample {index} is not newline framed")
            try:
                fields = raw[:-1].decode("ascii").split("\t")
            except UnicodeError as error:
                raise SoakReadbackError(f"sample {index} is not ASCII") from error
            require(len(fields) == len(SAMPLE_HEADER), f"sample {index} has the wrong field count")
            row: dict[str, int] = {}
            for name, value in zip(SAMPLE_HEADER, fields, strict=True):
                maximum = U128_MAX if name == "monotonic_ns" else U64_MAX
                row[name] = parse_uint(value, f"sample {index} {name}", maximum=maximum)
            timestamp = row["monotonic_ns"]
            expected_timestamp = started + index * SAMPLE_INTERVAL_NS
            require(abs(timestamp - expected_timestamp) <= SAMPLE_TOLERANCE_NS, f"sample {index} is missing, reordered, caught up, or later than the 10 ms cadence tolerance")
            require(timestamp > last_timestamp, f"sample {index} timestamp is not strictly increasing")
            last_timestamp = timestamp
            _check_numeric_sample(row, audit, index)
            window = rss_window_for_index(index)
            if window == "first_post_warmup_hour":
                first_window.append(row["rss_kib"])
            if window == "final_hour":
                final_window.append(row["rss_kib"])
        require(stream.readline() == b"", "sample stream has rows beyond its exact duration count")
        checksum = stream.finish()
    require(checksum == receipt["resource_samples_sha256"], "resource sample SHA differs from the Rust receipt")
    require(last_timestamp <= uint(receipt["trace_ended_monotonic_ns"], "trace end", maximum=U128_MAX) + SAMPLE_TOLERANCE_NS, "final sample lies after the trace phase")
    expected_first = _upper_median(first_window) if first_window else None
    expected_final = _upper_median(final_window) if final_window else None
    require(receipt["first_post_warmup_hour_rss_median_kib"] == expected_first, "receipt first-hour RSS median differs from its samples")
    require(receipt["final_hour_rss_median_kib"] == expected_final, "receipt final-hour RSS median differs from its samples")
    exact_windows = len(first_window) == 36_000 and len(final_window) == 36_000
    growth_passed = bool(
        expected_first is not None
        and expected_final is not None
        and expected_first > 0
        and expected_final * 100 <= expected_first * (100 + RSS_GROWTH_PERCENT)
    )
    if audit["mode"] == "qualified":
        require(exact_windows, "qualified horizon lacks the exact first/final RSS sample windows")
        require(growth_passed, "qualified horizon exceeds the five-percent RSS median bound")
    return {
        "sha256": checksum,
        "count": required,
        "first_hour_sample_count": len(first_window),
        "final_hour_sample_count": len(final_window),
        "first_hour_median_kib": expected_first,
        "final_hour_median_kib": expected_final,
        "rss_growth_passed": growth_passed,
        "exact_rss_windows": exact_windows,
    }


def _upper_median(values: list[int]) -> int:
    require(values, "cannot compute the median of an empty RSS window")
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def _validate_phase_and_receipt(receipt: dict[str, Any], audit: dict[str, Any], completed: int, samples: dict[str, Any]) -> dict[str, Any]:
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        return _validate_phase_and_receipt_v2(receipt, audit, completed, samples)
    uint_fields = (
        "actual_trace_duration_ns", "attempted", "completed", "drain_duration_ns", "drain_ended_monotonic_ns",
        "duration_seconds", "ended_monotonic_ns", "errors", "final_global_control_used", "final_global_cpu_used",
        "final_global_disk_used", "final_global_live_tenants", "final_global_memory_used", "final_global_network_used",
        "final_global_tasks_used", "final_scope_disk_used", "final_scope_memory_used", "final_scope_network_used",
        "final_tenant_control_used", "final_tenant_cpu_used", "final_tenant_disk_used", "final_tenant_memory_used",
        "final_tenant_network_used", "final_tenant_tasks_used", "fixed_global_control_baseline", "logical_window",
        "lost", "postprocess_after_shutdown_ns", "postprocess_ended_monotonic_ns", "production_cpu_ended_ns",
        "production_cpu_ns", "production_cpu_started_ns", "reference_average_rate_per_second", "reference_ring_rows",
        "resource_samples_count", "sample_interval_ms", "shutdown_duration_ns", "shutdown_ended_monotonic_ns",
        "started_monotonic_ns", "terminal_records", "trace_ended_monotonic_ns", "warmup_seconds",
    )
    numeric: dict[str, int] = {}
    for name in uint_fields:
        numeric[name] = uint(receipt[name], f"Rust receipt {name}", maximum=U128_MAX if name.endswith("_ns") else U64_MAX)
    require(numeric["attempted"] > 0 and numeric["attempted"] == numeric["completed"] == numeric["terminal_records"] == completed, "receipt/terminal counts do not reconcile")
    require(numeric["errors"] == 0 and numeric["lost"] == 0, "Rust receipt contains errors or lost work")
    start = numeric["started_monotonic_ns"]
    trace = numeric["trace_ended_monotonic_ns"]
    drain = numeric["drain_ended_monotonic_ns"]
    shutdown = numeric["shutdown_ended_monotonic_ns"]
    postprocess = numeric["postprocess_ended_monotonic_ns"]
    ended = numeric["ended_monotonic_ns"]
    require(start <= trace <= drain <= shutdown <= postprocess == ended, "trace/drain/shutdown/postprocess clocks are not ordered and distinct")
    trace_elapsed = trace - start
    drain_elapsed = drain - trace
    shutdown_elapsed = shutdown - drain
    postprocess_elapsed = postprocess - shutdown
    requested_ns = audit["duration_seconds"] * 1_000_000_000
    require(numeric["actual_trace_duration_ns"] == trace_elapsed, "receipt trace duration does not match its monotonic phase endpoints")
    require(numeric["drain_duration_ns"] == drain_elapsed, "receipt drain duration does not match its monotonic phase endpoints")
    require(numeric["shutdown_duration_ns"] == shutdown_elapsed, "receipt shutdown duration does not match its monotonic phase endpoints")
    require(numeric["postprocess_after_shutdown_ns"] == postprocess_elapsed, "receipt postprocessing duration does not match its monotonic phase endpoints")
    require(requested_ns <= trace_elapsed <= requested_ns + 5_000_000_000, "trace horizon is shorter than requested or exceeds five-second allowance")
    require(drain_elapsed <= 5_000_000_000, "admitted work drain exceeds five seconds")
    require(shutdown_elapsed <= 60_000_000_000, "runtime shutdown exceeds its sixty-second bound")
    require(numeric["production_cpu_ended_ns"] >= numeric["production_cpu_started_ns"], "production CPU clock moved backwards")
    require(numeric["production_cpu_ns"] == numeric["production_cpu_ended_ns"] - numeric["production_cpu_started_ns"], "production CPU interval does not reconcile")
    require(numeric["production_cpu_ns"] > 0, "production CPU interval is empty")
    # The CPU clock has a process-relative epoch, so do not compare its absolute
    # timestamps to CLOCK_MONOTONIC.  Its executable/source pins below bind the
    # implementation whose endpoint is recorded only after the drain predicate.
    if audit["mode"] == "qualified":
        require(receipt["qualified_horizon"] is True, "qualified run's child horizon flag is false")
        require(samples["count"] == QUALIFIED_SECONDS * 1000 // SAMPLE_INTERVAL_MS + 1, "qualified sample count differs from the exact 10,800-second cadence")
        require(samples["exact_rss_windows"] and samples["rss_growth_passed"], "qualified RSS window/growth guard failed")
    require(numeric["final_global_live_tenants"] == 0, "final global tenant count is nonzero")
    require(numeric["final_global_control_used"] == audit["source"]["fixed_global_control_baseline"], "final global Control does not equal its independently calibrated baseline")
    require(numeric["final_tenant_control_used"] == 0, "final tenant Control usage is nonzero")
    for name in (
        "final_global_cpu_used", "final_global_memory_used", "final_global_disk_used", "final_global_network_used", "final_global_tasks_used",
        "final_tenant_cpu_used", "final_tenant_memory_used", "final_tenant_disk_used", "final_tenant_network_used", "final_tenant_tasks_used",
        "final_scope_memory_used", "final_scope_disk_used", "final_scope_network_used",
    ):
        require(numeric[name] == 0, f"final application charge remains: {name}")
    qualification_eligible = bool(
        audit["mode"] == "qualified"
        and audit.get("launch_receipt", {}).get("exit_code") == 0
        and trace_elapsed >= requested_ns
        and trace_elapsed <= requested_ns + 5_000_000_000
        and drain_elapsed <= 5_000_000_000
        and samples["count"] == QUALIFIED_SECONDS * 1000 // SAMPLE_INTERVAL_MS + 1
        and samples["exact_rss_windows"]
        and samples["rss_growth_passed"]
    )
    return {
        "trace_duration_ns": trace_elapsed,
        "drain_duration_ns": drain_elapsed,
        "shutdown_duration_ns": shutdown_elapsed,
        "postprocess_after_shutdown_ns": postprocess_elapsed,
        "production_cpu_ns": numeric["production_cpu_ns"],
        "production_cpu_started_ns": numeric["production_cpu_started_ns"],
        "production_cpu_ended_ns": numeric["production_cpu_ended_ns"],
        "production_cpu_interval_source_pinned": True,
        "attempted": numeric["attempted"],
        "completed": numeric["completed"],
        "qualification_eligible": qualification_eligible,
        "child_qualified_horizon": receipt["qualified_horizon"],
    }


def _validate_phase_and_receipt_v2(receipt: dict[str, Any], audit: dict[str, Any], completed: int, samples: dict[str, Any]) -> dict[str, Any]:
    numeric_fields = (
        "attempted", "completed", "errors", "lost", "terminal_records", "duration_seconds", "sample_interval_ms",
        "warmup_seconds", "logical_window", "reference_ring_rows", "reference_average_rate_per_second",
        "resource_samples_count", "actual_trace_duration_ns", "drain_duration_ns", "shutdown_duration_ns",
        "postprocess_after_shutdown_ns", "production_cpu_started_ns", "production_cpu_ended_ns", "production_cpu_ns",
        "final_global_live_tenants", "final_global_cpu_used", "final_global_memory_used", "final_global_disk_used",
        "final_global_network_used", "final_global_tasks_used", "final_global_control_used", "fixed_global_control_baseline",
        "final_tenant_cpu_used", "final_tenant_memory_used", "final_tenant_disk_used", "final_tenant_network_used",
        "final_tenant_tasks_used", "final_tenant_control_used", "final_scope_memory_used", "final_scope_disk_used",
        "final_scope_network_used",
    )
    values = {field: uint(receipt[field], f"runtime-soak.v2 {field}", maximum=U128_MAX if field.endswith("_ns") else U64_MAX) for field in numeric_fields}
    require(values["attempted"] > 0 and values["attempted"] == values["completed"] == values["terminal_records"] == completed, "runtime-soak.v2 attempted/completed/terminal counts do not reconcile")
    require(values["errors"] == 0 and values["lost"] == 0, "runtime-soak.v2 reports errors or lost work")
    require(values["duration_seconds"] == audit["duration_seconds"] and values["sample_interval_ms"] == SAMPLE_INTERVAL_MS, "runtime-soak.v2 duration/cadence differs from the frozen parent")
    require(values["warmup_seconds"] == WARMUP_SECONDS and values["logical_window"] == LOGICAL_WINDOW, "runtime-soak.v2 warmup/window differs from the fixed resource contract")
    require(values["resource_samples_count"] == samples["count"], "runtime-soak.v2 sample count differs from the independently parsed stream")
    require(type(receipt["qualified_horizon"]) is bool, "runtime-soak.v2 child horizon flag is malformed")
    if audit["mode"] == "qualified":
        require(receipt["qualified_horizon"] is True, "qualified SourceV5 soak child horizon flag is false")
    else:
        require(receipt["qualified_horizon"] is False, "short functional SourceV5 soak cannot assert a qualified horizon")

    endpoints: dict[str, list[int]] = {}
    for phase in SOAK_RECEIPT_CLOCK_PHASES:
        lower = uint(receipt[f"{phase}_monotonic_lower_ns"], f"{phase} lower endpoint", positive=True, maximum=U128_MAX)
        upper = uint(receipt[f"{phase}_monotonic_upper_ns"], f"{phase} upper endpoint", positive=True, maximum=U128_MAX)
        scalar = uint(receipt[f"{phase}_monotonic_ns"], f"{phase} scalar", positive=True, maximum=U128_MAX)
        require(lower <= upper and scalar == lower, f"{phase} scalar is not the lower shared-clock endpoint")
        endpoints[phase] = [lower, upper]
    for previous, current in zip(SOAK_RECEIPT_CLOCK_PHASES, SOAK_RECEIPT_CLOCK_PHASES[1:]):
        require(endpoints[previous][0] < endpoints[current][0] and endpoints[previous][1] <= endpoints[current][1], f"runtime-soak.v2 {current} endpoint does not follow {previous}")

    started_lower, started_upper = endpoints["started"]
    trace_lower, trace_upper = endpoints["trace_ended"]
    drain_lower, drain_upper = endpoints["drain_ended"]
    shutdown_lower, shutdown_upper = endpoints["shutdown_ended"]
    post_lower, post_upper = endpoints["postprocess_ended"]
    trace_min = trace_lower - started_upper
    trace_max = trace_upper - started_lower
    drain_min = drain_lower - trace_upper
    drain_max = drain_upper - trace_lower
    shutdown_min = shutdown_lower - drain_upper
    shutdown_max = shutdown_upper - drain_lower
    postprocess_min = post_lower - shutdown_upper
    postprocess_max = post_upper - shutdown_lower
    require(min(trace_min, drain_min, shutdown_min, postprocess_min) >= 0, "runtime-soak.v2 shared-clock endpoint brackets do not preserve phase chronology")
    require(values["actual_trace_duration_ns"] == uint(receipt["trace_ended_monotonic_ns"], "trace scalar", maximum=U128_MAX) - uint(receipt["started_monotonic_ns"], "start scalar", maximum=U128_MAX), "runtime-soak.v2 trace scalar duration does not reconcile")
    require(values["drain_duration_ns"] == uint(receipt["drain_ended_monotonic_ns"], "drain scalar", maximum=U128_MAX) - uint(receipt["trace_ended_monotonic_ns"], "trace scalar", maximum=U128_MAX), "runtime-soak.v2 drain scalar duration does not reconcile")
    require(values["shutdown_duration_ns"] == uint(receipt["shutdown_ended_monotonic_ns"], "shutdown scalar", maximum=U128_MAX) - uint(receipt["drain_ended_monotonic_ns"], "drain scalar", maximum=U128_MAX), "runtime-soak.v2 shutdown scalar duration does not reconcile")
    require(values["postprocess_after_shutdown_ns"] == uint(receipt["postprocess_ended_monotonic_ns"], "postprocess scalar", maximum=U128_MAX) - uint(receipt["shutdown_ended_monotonic_ns"], "shutdown scalar", maximum=U128_MAX), "runtime-soak.v2 postprocess scalar duration does not reconcile")
    requested_ns = audit["duration_seconds"] * 1_000_000_000
    require(trace_min >= requested_ns and trace_max <= requested_ns + 5_000_000_000, "runtime-soak.v2 clock bounds do not cover the frozen horizon within five seconds")
    require(drain_max <= 5_000_000_000 and shutdown_max <= 60_000_000_000, "runtime-soak.v2 drain or shutdown exceeds its upper bound")
    require(values["production_cpu_ended_ns"] >= values["production_cpu_started_ns"] and values["production_cpu_ns"] == values["production_cpu_ended_ns"] - values["production_cpu_started_ns"] and values["production_cpu_ns"] > 0, "runtime-soak.v2 production CPU interval does not reconcile")

    require(values["final_global_live_tenants"] == 0, "runtime-soak.v2 final live-tenant count is nonzero")
    require(values["final_global_control_used"] == audit["source"]["fixed_global_control_baseline"], "runtime-soak.v2 final global Control does not equal its calibrated baseline")
    require(values["fixed_global_control_baseline"] == audit["source"]["fixed_global_control_baseline"], "runtime-soak.v2 baseline differs from source calibration")
    require(values["final_tenant_control_used"] == 0, "runtime-soak.v2 final tenant Control usage is nonzero")
    for field in (
        "final_global_cpu_used", "final_global_memory_used", "final_global_disk_used", "final_global_network_used", "final_global_tasks_used",
        "final_tenant_cpu_used", "final_tenant_memory_used", "final_tenant_disk_used", "final_tenant_network_used", "final_tenant_tasks_used",
        "final_scope_memory_used", "final_scope_disk_used", "final_scope_network_used",
    ):
        require(values[field] == 0, f"runtime-soak.v2 final application charge remains: {field}")
    require(receipt["first_post_warmup_hour_rss_median_kib"] == samples["first_hour_median_kib"], "runtime-soak.v2 first-hour RSS median differs from sample recomputation")
    require(receipt["final_hour_rss_median_kib"] == samples["final_hour_median_kib"], "runtime-soak.v2 final-hour RSS median differs from sample recomputation")
    qualification_eligible = bool(
        audit["mode"] == "qualified"
        and audit.get("launch_receipt", {}).get("exit_code") == 0
        and audit.get("launch_enabled") is True
        and trace_min >= requested_ns
        and trace_max <= requested_ns + 5_000_000_000
        and drain_max <= 5_000_000_000
        and samples["count"] == QUALIFIED_SECONDS * 1000 // SAMPLE_INTERVAL_MS + 1
        and samples["exact_rss_windows"]
        and samples["rss_growth_passed"]
    )
    return {
        "qualification_eligible": qualification_eligible,
        "monotonic_endpoints": endpoints,
        "trace_duration_lower_ns": trace_min,
        "trace_duration_upper_ns": trace_max,
        "drain_duration_upper_ns": drain_max,
        "shutdown_duration_upper_ns": shutdown_max,
        "postprocess_duration_upper_ns": postprocess_max,
    }


def _validate_artifacts(
    artifact_dir: Path,
    audit: dict[str, Any],
) -> dict[str, Any]:
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        return _validate_artifacts_v2(artifact_dir, audit)
    identity = audit["identity"]
    launch_receipt, launch_receipt_sha = _verify_launch_receipt(
        artifact_dir, audit, audit["preflight"], require_success=True
    )
    audit["launch_receipt"] = launch_receipt
    receipt_path = _artifact_from_receipt(artifact_dir, "soak-receipt.json", "Rust soak receipt", MAX_RECEIPT_BYTES)
    receipt, receipt_sha, _ = _validate_receipt_json(receipt_path, artifact_dir, audit)
    terminal_path = _artifact_from_receipt(
        artifact_dir,
        receipt["terminal_stream_relative_path"],
        "terminal stream",
        audit["recipe"]["runtime"]["terminal_budget_bytes"],
    )
    sample_path = _artifact_from_receipt(
        artifact_dir,
        receipt["resource_samples_relative_path"],
        "resource sample stream",
        audit["recipe"]["runtime"]["sample_budget_bytes"],
    )
    terminal_sha, terminal_count = _parse_terminal_stream(
        terminal_path,
        receipt,
        audit["ring"],
        audit["recipe"]["runtime"]["terminal_budget_bytes"],
    )
    samples = _parse_samples(
        sample_path,
        receipt,
        audit,
        audit["recipe"]["runtime"]["sample_budget_bytes"],
    )
    phases = _validate_phase_and_receipt(receipt, audit, terminal_count, samples)
    return {
        "schema": RESULT_SCHEMA,
        "validated": True,
        "passed": True,
        "qualification_eligible": phases["qualification_eligible"],
        "mode": audit["mode"],
        "identity": identity,
        "source_manifest_sha256": audit["source"]["source_manifest_sha256"],
        "source_tree_sha256": audit["source"]["source_tree_sha256"],
        "build_sha256": audit["source"]["build_sha256"],
        "candidate_binary_sha256": audit["source"]["candidate_binary_sha256"],
        "oracle_producer_binary_sha256": audit["source"]["oracle_producer_binary_sha256"],
        "reference_ring_sha256": audit["ring"]["sha256"],
        "reference_ring_rows": audit["ring"]["rows"],
        "resource_ceiling_sha256": identity["resource_ceiling_sha256"],
        "fixed_policy_sha256": audit["source"]["fixed_policy_sha256"],
        "fixed_global_control_baseline": audit["source"]["fixed_global_control_baseline"],
        "receipt_sha256": receipt_sha,
        "terminal_stream_sha256": terminal_sha,
        "resource_samples_sha256": samples["sha256"],
        "terminal_records": terminal_count,
        "resource_samples_count": samples["count"],
        "rss_first_hour_median_kib": samples["first_hour_median_kib"],
        "rss_final_hour_median_kib": samples["final_hour_median_kib"],
        "rss_growth_passed": samples["rss_growth_passed"],
        "rss_first_hour_sample_count": samples["first_hour_sample_count"],
        "rss_final_hour_sample_count": samples["final_hour_sample_count"],
        "trace_duration_ns": phases["trace_duration_ns"],
        "drain_duration_ns": phases["drain_duration_ns"],
        "shutdown_duration_ns": phases["shutdown_duration_ns"],
        "postprocess_after_shutdown_ns": phases["postprocess_after_shutdown_ns"],
        "production_cpu_ns": phases["production_cpu_ns"],
        "production_cpu_started_ns": phases["production_cpu_started_ns"],
        "production_cpu_ended_ns": phases["production_cpu_ended_ns"],
        "production_cpu_interval_source_pinned": phases["production_cpu_interval_source_pinned"],
        "child_qualified_horizon": phases["child_qualified_horizon"],
        "preflight_sha256": audit["preflight"]["preflight_sha256"],
        "launch_receipt_sha256": launch_receipt_sha,
    }


def _validate_artifacts_v2(artifact_dir: Path, audit: dict[str, Any]) -> dict[str, Any]:
    launch_receipt, _launch_receipt_sha = _verify_launch_receipt(
        artifact_dir, audit, audit["preflight"], require_success=True,
    )
    audit["launch_receipt"] = launch_receipt
    receipt_path = _artifact_from_receipt(artifact_dir, "soak-receipt.json", "runtime-soak.v2 receipt", MAX_RECEIPT_BYTES)
    receipt, receipt_sha, _raw = _validate_receipt_json(receipt_path, artifact_dir, audit)
    terminal_path = _artifact_from_receipt(artifact_dir, receipt["terminal_stream_relative_path"], "terminal stream", audit["recipe"]["runtime"]["terminal_budget_bytes"])
    sample_path = _artifact_from_receipt(artifact_dir, receipt["resource_samples_relative_path"], "resource sample stream", audit["recipe"]["runtime"]["sample_budget_bytes"])
    terminal_sha, terminal_count = _parse_terminal_stream(terminal_path, receipt, audit["ring"], audit["recipe"]["runtime"]["terminal_budget_bytes"])
    samples = _parse_samples(sample_path, receipt, audit, audit["recipe"]["runtime"]["sample_budget_bytes"])
    phases = _validate_phase_and_receipt(receipt, audit, terminal_count, samples)
    require(receipt["mode"] == "soak" and receipt["comparison_family"] == "external_pressure", "SourceV5 receipt is not the original external-pressure soak")
    if audit["launch_enabled"]:
        _validate_pressure_proof(artifact_dir, audit)
    return {
        "schema": RESULT_SCHEMA_V2,
        "validated": True,
        "passed": True,
        # This is eligibility of the independently audited soak component.
        # Campaign qualification also needs independent pressure and feedback receipts.
        "qualification_eligible": phases["qualification_eligible"],
        "mode": audit["mode"],
        "identity": audit["identity"],
        "source_manifest_sha256": audit["source"]["source_manifest_sha256"],
        "source_tree_sha256": audit["source"]["source_tree_sha256"],
        "build_sha256": audit["source"]["build_sha256"],
        "candidate_binary_sha256": audit["source"]["candidate_binary_sha256"],
        "resource_ceiling_sha256": audit["identity"]["resource_ceiling_sha256"],
        "fixed_global_control_baseline": audit["source"]["fixed_global_control_baseline"],
        "receipt_sha256": receipt_sha,
        "validator_sha256": audit["execution"]["reader_sha256"],
        "monotonic_endpoints": phases["monotonic_endpoints"],
    }


def _validate_pressure_proof_offline(
    artifact_dir: Path, audit: dict[str, Any], offline_context: dict[str, Any],
) -> dict[str, Any]:
    """Replay the original one-APP pressure run through its captured reader."""
    pressure_info = audit["source"].get("pressure_recipe")
    require(type(pressure_info) is dict,
            "SourceV5 offline Soak is missing its frozen pressure recipe")
    parent_pin = exact_object(audit["recipe"]["pressure"]["recipe"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "SourceV5 parent pressure recipe pin")
    recipe_pin = {
        **parent_pin,
        "condition_sha256": audit["recipe"]["pressure"]["condition_sha256"],
    }
    require(pressure_info.get("raw_sha256") == parent_pin["raw_sha256"] and
            pressure_info.get("recipe_sha256") == parent_pin["semantic_sha256"] and
            pressure_info.get("condition_sha256") == recipe_pin["condition_sha256"],
            "SourceV5 offline pressure recipe raw/semantic/condition roles differ")
    reader = pressure_info.get("reader")
    bounded_v3 = offline_context["schema"] == \
        SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA_V2
    verifier = getattr(
        reader,
        ("verify_source5_soak_pressure_offline_v3" if bounded_v3 else
         "verify_source5_soak_pressure_offline"),
        None,
    )
    require(callable(verifier),
            ("source5_soak_pressure_v3_offline_dependency_unavailable: "
             "captured pressure reader lacks its bounded host-v3 single-APP API"
             if bounded_v3 else
             "source5_soak_pressure_offline_dependency_unavailable: "
             "captured pressure reader lacks its single-APP offline API"))
    condition = audit["recipe"]["qualification"]["pressure_condition"]
    origin = exact_object(offline_context["pressure_origin"], {
        "schema", "recipe_pin", "recipe_dependency_paths",
        "application_tmpdir_path", "storage_before", "storage_after",
    }, "Source5 Soak origin pressure/storage receipt")
    storage_before = exact_object(origin["storage_before"], {
        "application_storage", "pressure_scratch", "recipe_storage",
    }, "Source5 Soak frozen pressure storage facts")
    storage_after = exact_object(origin["storage_after"], {
        "application_process", "pressure_artifacts", "pressure_readback_sha256",
        "pressure_cleanup", "pressure_driver_source_sha256",
        "application_storage", "pressure_scratch",
    }, "Source5 Soak post-run pressure storage facts")
    pressure_value = pressure_info["value"]
    require(origin["schema"] ==
            "allocatbelt.application-source5-soak-pressure-origin.v2" and
            origin["recipe_pin"] == recipe_pin and
            origin["application_tmpdir_path"] ==
                pressure_value["process"]["application_tmpdir_path"] and
            storage_before["application_storage"] ==
                pressure_value["host"]["application_storage"] and
            storage_before["pressure_scratch"] ==
                pressure_value["host"]["pressure_scratch"] and
            storage_before["recipe_storage"] == pressure_value["storage"] and
            storage_after["pressure_cleanup"] == "verified" and
            storage_after["pressure_driver_source_sha256"] ==
                audit["recipe"]["pressure"]["driver"]["sha256"],
            "Source5 Soak origin storage facts changed their raw pressure recipe")
    app_after = exact_object(storage_after["application_process"], {
        "pid", "start_ticks", "tmpdir_path", "cpu_affinity",
        "network_namespace_inode",
    }, "Source5 Soak original application storage identity")
    require(app_after["tmpdir_path"] == origin["application_tmpdir_path"] ==
            audit["launch_descriptor"]["environment"].get("TMPDIR") and
            type(app_after["pid"]) is int and app_after["pid"] > 0 and
            type(app_after["start_ticks"]) is int and app_after["start_ticks"] > 0,
            "Source5 Soak original TMPDIR/PID-start storage binding differs")
    pressure_artifacts = exact_object(storage_after["pressure_artifacts"], {
        "directory", "pins", "proof", "ready_sha256", "driver",
        "worker_sessions", "driver_logs",
    }, "Source5 Soak closed pressure artifact descriptor")
    pressure_dir = artifact_dir / "pressure"
    require(pressure_artifacts["directory"] == str(pressure_dir) and
            pressure_artifacts["proof"]["path"] ==
                str(artifact_dir / "pressure-readback.json") and
            type(storage_after["pressure_readback_sha256"]) is str and
            re.fullmatch(r"[0-9a-f]{64}",
                         storage_after["pressure_readback_sha256"]) is not None and
            pressure_artifacts["driver_logs"]["stdout"]["path"] ==
                str(artifact_dir / "pressure-driver.stdout.log") and
            pressure_artifacts["driver_logs"]["stderr"]["path"] ==
                str(artifact_dir / "pressure-driver.stderr.log"),
            "Source5 Soak pressure output paths differ from the strict origin receipt")
    result = verifier(
        recipe_pin, pressure_artifacts,
        offline_context["host_verification_pin"],
        evidence_path_map=offline_context["evidence_path_map"],
        source_root=Path(audit["source_root"]),
    )
    require(type(result) is dict and
            result.get("readback_sha256") ==
                storage_after["pressure_readback_sha256"],
            "captured pressure reader returned no matching single-APP replay")
    minimum_samples = uint(
        condition["readiness_thresholds"]["minimum_ready_samples"],
        "SourceV5 offline pressure minimum ready samples", positive=True,
    )
    minimum_overlap = uint(
        condition["readiness_thresholds"]["minimum_overlap_seconds"],
        "SourceV5 offline pressure minimum overlap seconds", positive=True,
    )
    require(uint(result.get("sample_count"),
                 "SourceV5 offline pressure sample count") >= minimum_samples and
            uint(result.get("application_overlap_nanoseconds"),
                 "SourceV5 offline pressure overlap") >=
            minimum_overlap * 1_000_000_000,
            "SourceV5 offline pressure replay is below frozen readiness thresholds")
    proof_raw, proof_sha = read_stable_bytes(
        artifact_dir / "pressure-readback.json",
        "SourceV5 saved pressure readback proof", MAX_RECEIPT_BYTES,
    )
    proof = _read_json_raw(proof_raw, "SourceV5 saved pressure readback proof")
    require(pressure_artifacts["proof"]["raw_sha256"] == proof_sha and
            proof == result and proof_raw == canonical_bytes(result),
            "SourceV5 saved pressure proof differs from full offline pressure replay")
    return result


def _validate_artifacts_offline(
    artifact_dir: Path, audit: dict[str, Any], offline_context: dict[str, Any],
) -> dict[str, Any]:
    """Replay all Soak streams offline; never launch, inspect peers, or accept summaries."""
    exact_object(offline_context, {
        "schema", "evidence_path_map", "construction_probe_capture",
        "host_verification_pin", "application_environment",
        "pressure_origin",
    }, "Source5 Soak offline replay context")
    require(offline_context["schema"] in {
                SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA,
                SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA_V2,
            } and audit["recipe"]["schema"] == RECIPE_SCHEMA_V2 and
            ((audit["mode"] == "qualified" and
              audit["duration_seconds"] == QUALIFIED_SECONDS) or
             (offline_context["schema"] ==
                  SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA_V2 and
              audit["mode"] == "functional" and
              0 < audit["duration_seconds"] < QUALIFIED_SECONDS)),
            "Source5 offline replay is not a bounded qualified or functional Soak")
    launch_receipt, _launch_sha = _verify_launch_receipt(
        artifact_dir, audit, audit["preflight"], require_success=True,
    )
    audit["launch_receipt"] = launch_receipt
    receipt_path = _artifact_from_receipt(
        artifact_dir, "soak-receipt.json", "runtime-soak.v2 receipt",
        MAX_RECEIPT_BYTES,
    )
    receipt, receipt_sha, _raw = _validate_receipt_json(
        receipt_path, artifact_dir, audit,
    )
    terminal_path = _artifact_from_receipt(
        artifact_dir, receipt["terminal_stream_relative_path"],
        "terminal stream", audit["recipe"]["runtime"]["terminal_budget_bytes"],
    )
    sample_path = _artifact_from_receipt(
        artifact_dir, receipt["resource_samples_relative_path"],
        "resource sample stream", audit["recipe"]["runtime"]["sample_budget_bytes"],
    )
    terminal_sha, terminal_count = _parse_terminal_stream(
        terminal_path, receipt, audit["ring"],
        audit["recipe"]["runtime"]["terminal_budget_bytes"],
    )
    samples = _parse_samples(
        sample_path, receipt, audit,
        audit["recipe"]["runtime"]["sample_budget_bytes"],
    )
    phases = _validate_phase_and_receipt_v2(
        receipt, audit, terminal_count, samples,
    )
    require(receipt["mode"] == "soak" and
            receipt["comparison_family"] == "external_pressure" and
            samples["count"] == QUALIFIED_SECONDS * 1000 // SAMPLE_INTERVAL_MS + 1 and
            samples["exact_rss_windows"] and samples["rss_growth_passed"],
            "SourceV5 offline Soak lost its exact original horizon or RSS gates")
    require(audit["launch_enabled"] is True,
            "SourceV5 Soak offline replay requires the separately authorized Soak overlay")
    _validate_pressure_proof_offline(artifact_dir, audit, offline_context)
    return {
        "schema": RESULT_SCHEMA_V2,
        "validated": True,
        "passed": True,
        "qualification_eligible": phases["qualification_eligible"],
        "mode": audit["mode"],
        "identity": audit["identity"],
        "source_manifest_sha256": audit["source"]["source_manifest_sha256"],
        "source_tree_sha256": audit["source"]["source_tree_sha256"],
        "build_sha256": audit["source"]["build_sha256"],
        "candidate_binary_sha256": audit["source"]["candidate_binary_sha256"],
        "resource_ceiling_sha256": audit["identity"]["resource_ceiling_sha256"],
        "fixed_global_control_baseline": audit["source"]["fixed_global_control_baseline"],
        "receipt_sha256": receipt_sha,
        "validator_sha256": audit["execution"]["reader_sha256"],
        "monotonic_endpoints": phases["monotonic_endpoints"],
    }


def _check_private_output_directory(path: Path) -> Path:
    try:
        require(not stat.S_ISLNK(path.lstat().st_mode), "soak output directory may not be a symlink")
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise SoakReadbackError(f"soak output directory is unavailable: {error}") from error
    require(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o077 == 0, "soak output directory must be private mode 0700")
    return resolved


def command_preflight(
    args: argparse.Namespace, *,
    source5_probe_capture: dict[str, Any] | None = None,
) -> int:
    recipe_expected_sha = digest(args.recipe_sha256, "expected recipe SHA-256")
    expected_identity = {
        "campaign_id": args.campaign_id,
        "host_id": args.host_id,
        "run_id": args.run_id,
        "allocator": args.allocator,
        "executor": args.executor,
        "profile": args.profile,
        "source_sha256": args.source_sha256,
        "binary_sha256": args.binary_sha256,
        "resource_ceiling_sha256": args.resource_ceiling_sha256,
    }
    audit = _audit_inputs(
        args.recipe,
        recipe_expected_sha,
        expected_identity,
        args.binary,
        args.mode,
        args.duration_seconds,
        args.runner_path,
        require_executing_reader_path=True,
        source5_probe_capture=source5_probe_capture,
    )
    output_dir = _check_private_output_directory(args.output_dir)
    audit["launch_descriptor"] = _make_launch_descriptor(audit, output_dir, args.cpu_set)
    filesystem = os.statvfs(output_dir)
    available_bytes = filesystem.f_bavail * filesystem.f_frsize
    required_bytes = (
        audit["recipe"]["runtime"]["terminal_budget_bytes"]
        + audit["recipe"]["runtime"]["sample_budget_bytes"]
        + 512 * 1024 * 1024
    )
    require(available_bytes >= required_bytes, "soak output filesystem lacks the preflighted terminal/sample artifact capacity")
    output = output_dir / "soak-preflight.json"
    report = _preflight_report(audit)
    output_sha = _write_exclusive_json(output, report)
    launch_config = {
        "preflight_sha256": report["preflight_sha256"],
        "reference_ring_path": audit["ring"]["path"],
        "reference_ring_sha256": audit["ring"]["sha256"],
        "duration_seconds": audit["duration_seconds"],
        "sample_interval_ms": audit["sample_interval_ms"],
        "mode": audit["mode"],
        "nonce": audit["identity"]["nonce"],
        "preflight_output_sha256": output_sha,
    }
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        launch_config.update({
            "comparison_family": audit["identity"]["comparison_family"],
            "launch_enabled": audit["launch_enabled"],
            "pressure_condition_sha256": audit["recipe"]["pressure"]["condition_sha256"],
            "application_wall_timeout_seconds": audit["source"]["application_supervision"]["application_wall_timeout_seconds"],
            "pressure_duration_seconds": audit["source"]["application_supervision"]["pressure_duration_seconds"],
        })
    print(json.dumps(launch_config, sort_keys=True, separators=(",", ":")))
    return 0


def _current_audit(
    args: argparse.Namespace, *,
    source5_probe_capture: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    recipe_expected_sha = digest(args.recipe_sha256, "expected recipe SHA-256")
    # The preflight identity was written by this same recipe. Reconstruct CLI
    # pins from it only after checking the preflight file's digest below.
    recipe, _checksum, raw = read_json(args.recipe, "parent soak recipe", MAX_RECIPE_BYTES)
    require(raw == canonical_bytes(recipe), "parent soak recipe is not canonical JSON")
    require(hashlib.sha256(raw).hexdigest() == recipe_expected_sha, "parent soak recipe SHA changed")
    _, identity = _validate_recipe(recipe, recipe_expected_sha)
    cli_identity = {name: identity[name] for name in (
        "campaign_id", "host_id", "run_id", "allocator", "executor", "profile", "source_sha256", "binary_sha256", "resource_ceiling_sha256"
    )}
    audit = _audit_inputs(
        args.recipe,
        recipe_expected_sha,
        cli_identity,
        args.binary,
        None,
        None,
        args.runner_path,
        require_executing_reader_path=True,
        source5_probe_capture=source5_probe_capture,
    )
    output_dir = _check_private_output_directory(args.output_dir)
    audit["launch_descriptor"] = _make_launch_descriptor(audit, output_dir, args.cpu_set)
    preflight = _verify_preflight(output_dir / "soak-preflight.json", audit)
    audit["preflight"] = preflight
    return audit, preflight


def command_verify_inputs(
    args: argparse.Namespace, *,
    source5_probe_capture: dict[str, Any] | None = None,
) -> int:
    audit, preflight = _current_audit(
        args, source5_probe_capture=source5_probe_capture,
    )
    launch_receipt, launch_receipt_sha = _verify_launch_receipt(
        _check_private_output_directory(args.output_dir),
        audit,
        preflight,
        require_success=False,
    )
    audit["launch_receipt"] = launch_receipt
    checksum, postflight = _write_verify_inputs_postflight(
        audit, preflight, _check_private_output_directory(args.output_dir),
        launch_receipt_sha,
    )
    print(json.dumps({"inputs_unchanged": True,
                      "postflight_sha256": postflight["postflight_sha256"],
                      "file_sha256": checksum}, sort_keys=True))
    return 0


def _write_verify_inputs_postflight(
    audit: dict[str, Any], preflight: dict[str, Any], output_dir: Path,
    launch_receipt_sha: str,
) -> tuple[str, dict[str, Any]]:
    """Write the legacy input-stability role from a caller's frozen audit."""
    postflight = {
        "schema": POSTFLIGHT_SCHEMA,
        "preflight_sha256": preflight["preflight_sha256"],
        "recipe_sha256": audit["recipe_sha256"],
        "source_manifest_sha256": audit["source"]["source_manifest_sha256"],
        "source_tree_sha256": audit["source"]["source_tree_sha256"],
        "build_sha256": audit["source"]["build_sha256"],
        "candidate_binary_sha256": audit["source"]["candidate_binary_sha256"],
        "oracle_producer_binary_sha256": audit["source"]["oracle_producer_binary_sha256"],
        "reference_ring_sha256": audit["ring"]["sha256"],
        "launch_receipt_sha256": launch_receipt_sha,
        "inputs_unchanged": True,
    }
    postflight["postflight_sha256"] = hashlib.sha256(canonical_bytes(postflight)).hexdigest()
    checksum = _write_exclusive_json(output_dir / "soak-postflight.json", postflight)
    return checksum, postflight


def _verify_verify_inputs_postflight(
    audit: dict[str, Any], preflight: dict[str, Any], output_dir: Path,
    launch_receipt_sha: str,
) -> dict[str, Any]:
    """Replay the exact legacy postflight role under the selected overlay."""
    path = output_dir / "soak-postflight.json"
    postflight, checksum, raw = read_json(
        path, "Soak input-stability postflight", MAX_RECEIPT_BYTES,
    )
    expected = {
        "schema": POSTFLIGHT_SCHEMA,
        "preflight_sha256": preflight["preflight_sha256"],
        "recipe_sha256": audit["recipe_sha256"],
        "source_manifest_sha256": audit["source"]["source_manifest_sha256"],
        "source_tree_sha256": audit["source"]["source_tree_sha256"],
        "build_sha256": audit["source"]["build_sha256"],
        "candidate_binary_sha256": audit["source"]["candidate_binary_sha256"],
        "oracle_producer_binary_sha256":
            audit["source"]["oracle_producer_binary_sha256"],
        "reference_ring_sha256": audit["ring"]["sha256"],
        "launch_receipt_sha256": launch_receipt_sha,
        "inputs_unchanged": True,
    }
    expected["postflight_sha256"] = hashlib.sha256(
        canonical_bytes(expected),
    ).hexdigest()
    require(raw == canonical_bytes(postflight) and postflight == expected,
            "Soak input-stability postflight differs from the original overlay")
    return {"path": str(path), "raw_sha256": checksum,
            "postflight_sha256": postflight["postflight_sha256"]}


def command_validate(args: argparse.Namespace) -> int:
    audit, preflight = _current_audit(args)
    launch_receipt, launch_receipt_sha = _verify_launch_receipt(
        _check_private_output_directory(args.output_dir),
        audit,
        preflight,
        require_success=True,
    )
    audit["launch_receipt"] = launch_receipt
    postflight_path = _check_private_output_directory(args.output_dir) / "soak-postflight.json"
    postflight = _readback_json(postflight_path, "postflight receipt")
    expected_keys = {
        "schema", "preflight_sha256", "recipe_sha256", "source_manifest_sha256", "source_tree_sha256",
        "build_sha256", "candidate_binary_sha256", "oracle_producer_binary_sha256", "reference_ring_sha256",
        "launch_receipt_sha256", "inputs_unchanged", "postflight_sha256",
    }
    exact_object(postflight, expected_keys, "postflight receipt")
    require(postflight["schema"] == POSTFLIGHT_SCHEMA and postflight["inputs_unchanged"] is True, "postflight receipt is not a passing stable-input check")
    postflight_material = dict(postflight)
    postflight_digest = postflight_material.pop("postflight_sha256")
    require(digest(postflight_digest, "postflight digest") == hashlib.sha256(canonical_bytes(postflight_material)).hexdigest(), "postflight receipt digest is invalid")
    require(postflight["preflight_sha256"] == preflight["preflight_sha256"], "postflight does not refer to the pre-run recipe")
    require(postflight["launch_receipt_sha256"] == launch_receipt_sha, "postflight does not bind the parent launch receipt")
    result = _validate_artifacts(_check_private_output_directory(args.output_dir), audit)
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        exact_object(result, {
            "schema", "validated", "passed", "qualification_eligible", "mode", "identity",
            "source_manifest_sha256", "source_tree_sha256", "build_sha256", "candidate_binary_sha256",
            "resource_ceiling_sha256", "fixed_global_control_baseline", "receipt_sha256", "validator_sha256",
            "monotonic_endpoints",
        }, "SourceV5 soak-readback v2 composite")
    else:
        result["postflight_sha256"] = postflight["postflight_sha256"]
    output_path = _check_private_output_directory(args.output_dir) / "soak-readback.json"
    checksum = _write_exclusive_json(output_path, result)
    print(json.dumps({"validated": True, "qualification_eligible": result["qualification_eligible"], "readback_sha256": checksum}, sort_keys=True))
    return 0


def _hash_open_executable(fd: int, path: Path, label: str) -> tuple[str, os.stat_result]:
    before = os.fstat(fd)
    path_before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(path_before.st_mode), f"{label} is not a regular non-symlink file")
    require((before.st_dev, before.st_ino) == (path_before.st_dev, path_before.st_ino), f"{label} path differs from its open descriptor")
    require(before.st_mode & 0o111 != 0, f"{label} is not executable")
    os.lseek(fd, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    count = 0
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        count += len(block)
        require(count <= MAX_EXECUTABLE_BYTES, f"{label} exceeds its finite byte bound")
        hasher.update(block)
    after = os.fstat(fd)
    path_after = path.lstat()
    require(_fingerprint(before) == _fingerprint(after) == _fingerprint(path_after), f"{label} changed while being hashed")
    require(count == before.st_size, f"{label} was truncated while being hashed")
    return hasher.hexdigest(), before


def launch_process(
    command: list[str],
    cpu_set: str,
    stdout_path: Path,
    stderr_path: Path,
    timing_path: Path,
    timeout_seconds: float,
    term_grace_seconds: float = 1.5,
    monitored_files: tuple[tuple[Path, int], ...] = (),
    *,
    environment: dict[str, str] | None = None,
    cwd: Path | None = None,
    expected_executable_sha256: str | None = None,
    return_details: bool = False,
    on_started: Any | None = None,
    monitor: Any | None = None,
    on_signal: Any | None = None,
    on_cleanup: Any | None = None,
    timeout_from_before_popen: bool = False,
    timeout_includes_cleanup: bool = False,
    resource_budget_monitor: Any | None = None,
) -> int | dict[str, Any]:
    """Run one child in a separate process group and reap it on timeout/signal."""
    require(command and all(type(arg) is str for arg in command), "launch command is malformed")
    require(resource_budget_monitor is None or callable(resource_budget_monitor),
            "Source5 resource-budget monitor callback is malformed")
    if resource_budget_monitor is not None:
        try:
            initial_budget_stop = bool(resource_budget_monitor())
        except BaseException as error:
            raise SoakReadbackError(
                f"Source5 resource monitor failed before APP Popen: {type(error).__name__}: {error}",
            ) from error
        require(not initial_budget_stop,
                "Source5 resource monitor refused before APP Popen")
    cpu_ids = _parse_cpu_set(cpu_set)
    require(0 < timeout_seconds <= 14_400 and 0 < term_grace_seconds <= 60, "launch timeout is outside its finite bounds")
    cleanup_scan_reserve = 3 * OWNED_GROUP_SCAN_MAX_SECONDS
    require(
        not timeout_includes_cleanup
        or (timeout_from_before_popen and timeout_seconds >= term_grace_seconds + 0.75 + cleanup_scan_reserve),
        "whole-process timeout needs a pre-Popen clock and room for bounded TERM/KILL, group scans, and reap",
    )
    _require_waitid_ownership_support()
    for path in (stdout_path, stderr_path, timing_path):
        require(not path.exists() and not path.is_symlink(), f"refusing to replace launch output {path}")
    output_fds: list[int] = []
    executable_fd: int | None = None
    inherited_executable_fd: int | None = None
    process: subprocess.Popen[bytes] | None = None
    owner: _OwnedProcessGroup | None = None
    received_signal: list[int] = []
    signal_intents: list[tuple[int, float, bool]] = []
    external_signal_intents: list[tuple[int, float]] = []
    cleanup_result_ref: dict[str, Any] | None = None
    old_handlers: dict[int, Any] = {}
    stop_started: float | None = None
    timed_out = False
    limit_exceeded = False
    resource_budget_exceeded = False
    resource_monitor_error: str | None = None
    term_sent = False
    term_sent_at: float | None = None
    kill_sent = False
    kill_sent_at: float | None = None
    cleanup_failure: str | None = None
    hard_cleanup_attempted = False
    signal_callback_delivered = False
    launched_at_ns: int | None = None
    ended_at_ns: int | None = None
    kill_reap_seconds = 0.75
    timeout_wall_deadline: float | None = None
    executable_path = Path(command[0]).resolve(strict=True)
    result_value: int | dict[str, Any] | None = None

    def request_stop(signum: int, _frame: Any) -> None:
        # Signal handlers record intent only. The main loop performs every
        # process-group operation while the direct child is still unreaped.
        when = time.monotonic()
        external = _frame is not None
        if external and not external_signal_intents:
            external_signal_intents.append((signum, when))
            received_signal.append(signum)
            if cleanup_result_ref is not None:
                cleanup_result_ref["received_signal"] = signum
        if not signal_intents:
            signal_intents.append((signum, when, external))

    def consume_signal_intent() -> None:
        nonlocal stop_started, signal_callback_delivered
        if not signal_intents:
            return
        _signum, when, _external = signal_intents[0]
        if stop_started is None:
            stop_started = when
        if external_signal_intents and on_signal is not None and not signal_callback_delivered:
            signal_callback_delivered = True
            on_signal(external_signal_intents[0][0])

    def signal_owned_group(signum: int) -> tuple[list[dict[str, Any]] | None, list[dict[str, Any]] | None]:
        nonlocal cleanup_failure
        assert owner is not None
        active, escaped, scan_error = owner.signal_group(signum)
        if scan_error is not None and cleanup_failure is None:
            cleanup_failure = f"soak launch cleanup could not verify its process group: {scan_error}"
        if escaped and cleanup_failure is None:
            cleanup_failure = "soak launch cleanup found live same-session processes outside its owned process group"
        return active, escaped

    def note_reap_result(
        return_code: int | None, active: list[dict[str, Any]] | None,
        escaped: list[dict[str, Any]] | None, scan_error: str | None,
    ) -> None:
        nonlocal cleanup_failure
        if active:
            cleanup_failure = cleanup_failure or "soak launch cleanup failed: process-group members remained live after bounded SIGKILL"
        if escaped:
            cleanup_failure = cleanup_failure or "soak launch cleanup found live same-session processes outside its owned process group"
        if scan_error is not None:
            cleanup_failure = cleanup_failure or f"soak launch cleanup could not verify its process group: {scan_error}"
        if return_code is None and owner is not None and owner.reaped:
            cleanup_failure = cleanup_failure or "soak launch cleanup failed: direct-child status was not captured"

    try:
        for path in (stdout_path, stderr_path, timing_path):
            output_fds.append(
                os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
            )
        stdout_fd, stderr_fd, timing_fd = output_fds
        executable_fd = os.open(
            executable_path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        executable_sha256, executable_info = _hash_open_executable(executable_fd, executable_path, "launched soak binary")
        if expected_executable_sha256 is not None:
            require(executable_sha256 == expected_executable_sha256, "launched binary descriptor differs from the source-manifest SHA")
        inherited_executable_fd = fcntl.fcntl(executable_fd, fcntl.F_DUPFD, 200)
        os.set_inheritable(inherited_executable_fd, True)
        executable_reference = f"/proc/self/fd/{inherited_executable_fd}"
        executed_argv = list(command)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, request_stop)
        def set_child_affinity() -> None:
            os.sched_setaffinity(0, cpu_ids)

        launched_at_ns = time.monotonic_ns()
        if timeout_from_before_popen:
            timeout_wall_deadline = time.monotonic() + timeout_seconds
        process = subprocess.Popen(
            executed_argv,
            executable=executable_reference,
            cwd=cwd,
            env=environment,
            preexec_fn=set_child_affinity,
            stdin=subprocess.DEVNULL,
            stdout=stdout_fd,
            stderr=stderr_fd,
            close_fds=True,
            pass_fds=(inherited_executable_fd,),
            start_new_session=True,
        )
        owner = _OwnedProcessGroup(process, "soak launch")
        process._allocatbelt_executable_binding = {
            "fd_reference": executable_reference,
            "device": executable_info.st_dev,
            "inode": executable_info.st_ino,
            "size": executable_info.st_size,
            "sha256": executable_sha256,
        }
        if on_started is not None:
            on_started(process, executable_path, executable_sha256, executable_info, cpu_ids, cwd, environment)
        if timeout_wall_deadline is None:
            deadline = time.monotonic() + timeout_seconds
        elif timeout_includes_cleanup:
            deadline = timeout_wall_deadline - term_grace_seconds - kill_reap_seconds - cleanup_scan_reserve
        else:
            deadline = timeout_wall_deadline
        while True:
            consume_signal_intent()
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0 and not signal_intents:
                timed_out = True
                request_stop(signal.SIGTERM, None)
            for monitored_path, maximum in monitored_files:
                try:
                    info = monitored_path.lstat()
                except FileNotFoundError:
                    continue
                require(stat.S_ISREG(info.st_mode), f"monitored output is not a regular file: {monitored_path.name}")
                if info.st_size > maximum:
                    limit_exceeded = True
                    if not signal_intents:
                        request_stop(signal.SIGTERM, None)
            if monitor is not None:
                monitor(process)
            if resource_budget_monitor is not None and not resource_budget_exceeded:
                try:
                    resource_budget_exceeded = bool(resource_budget_monitor())
                except BaseException as error:
                    resource_budget_exceeded = True
                    resource_monitor_error = f"{type(error).__name__}: {error}"
                if resource_budget_exceeded:
                    limit_exceeded = True
                    if not signal_intents:
                        request_stop(signal.SIGTERM, None)
            consume_signal_intent()
            child_status = owner.observe()
            now = time.monotonic()
            if stop_started is None and child_status is not None:
                return_code, active, escaped, scan_error = owner.reap_if_ready()
                if return_code is not None:
                    break
                if scan_error is not None or active or escaped:
                    if scan_error is not None:
                        cleanup_failure = f"soak launch cleanup could not verify its process group: {scan_error}"
                    elif escaped:
                        cleanup_failure = "soak launch cleanup found live same-session processes outside its owned process group"
                    stop_started = now
            if stop_started is not None:
                if not term_sent:
                    signal_owned_group(signal.SIGTERM)
                    term_sent = True
                    term_sent_at = time.monotonic()
                escalation_at = (term_sent_at if term_sent_at is not None else stop_started) + term_grace_seconds
                if not kill_sent and now >= escalation_at:
                    signal_owned_group(signal.SIGKILL)
                    kill_sent = True
                    kill_sent_at = time.monotonic()
                hard_cleanup_deadline = (
                    kill_sent_at + kill_reap_seconds - OWNED_GROUP_SCAN_MAX_SECONDS
                    if kill_sent_at is not None
                    else escalation_at + kill_reap_seconds + 2 * OWNED_GROUP_SCAN_MAX_SECONDS
                )
                child_status = owner.observe()
                if child_status is not None:
                    return_code, active, escaped, scan_error = owner.reap_if_ready()
                    if return_code is not None:
                        note_reap_result(return_code, active, escaped, scan_error)
                        break
                    if scan_error is not None:
                        cleanup_failure = cleanup_failure or f"soak launch cleanup could not verify its process group: {scan_error}"
                    elif escaped and not active:
                        return_code, active, escaped, scan_error = owner.reap_if_ready(allow_unverified_group=True)
                        note_reap_result(return_code, active, escaped, scan_error)
                        if return_code is not None:
                            break
                    if active and not kill_sent and now >= escalation_at:
                        signal_owned_group(signal.SIGKILL)
                        kill_sent = True
                if now >= hard_cleanup_deadline:
                    if not kill_sent:
                        signal_owned_group(signal.SIGKILL)
                        kill_sent = True
                        kill_sent_at = time.monotonic()
                    hard_cleanup_attempted = True
                    return_code, active, escaped, scan_error = owner.reap_if_ready(allow_unverified_group=True)
                    note_reap_result(return_code, active, escaped, scan_error)
                    if return_code is None:
                        cleanup_failure = cleanup_failure or "soak launch cleanup failed: child was not reaped by its hard SIGKILL deadline"
                    break
            remaining = deadline - now
            if stop_started is not None:
                cleanup_deadline = (
                    kill_sent_at + kill_reap_seconds - OWNED_GROUP_SCAN_MAX_SECONDS
                    if kill_sent_at is not None
                    else (term_sent_at if term_sent_at is not None else stop_started) + term_grace_seconds + kill_reap_seconds + 2 * OWNED_GROUP_SCAN_MAX_SECONDS
                )
                remaining = min(remaining, max(0.0, cleanup_deadline - now))
            time.sleep(min(0.05, max(0.005, remaining)))
        require(owner.reaped and owner.return_code is not None, "soak launch did not obtain a verified owned child status")
        return_code = owner.return_code
        os.fsync(stdout_fd)
        os.fsync(stderr_fd)
        timing_record = {
            "schema": "allocatbelt.application-soak-launch-time.v1",
            "time_source": "monotonic_wrapper",
            "exit_code": return_code,
            "elapsed_ns": max(0, time.monotonic_ns() - (launched_at_ns or time.monotonic_ns())),
            "timed_out": timed_out,
            "artifact_budget_exceeded": limit_exceeded,
        }
        os.write(timing_fd, canonical_bytes(timing_record))
        os.fsync(timing_fd)
        ended_at_ns = time.monotonic_ns()
        final_executable_sha256, final_executable_info = _hash_open_executable(
            executable_fd, executable_path, "launched soak binary after execution"
        )
        consume_signal_intent()
        require(final_executable_sha256 == executable_sha256, "launched binary bytes changed while the child ran")
        require(_fingerprint(final_executable_info) == _fingerprint(executable_info), "launched binary descriptor identity changed while the child ran")
        if return_details:
            launch_environment = dict(os.environ) if environment is None else dict(environment)
            result_value = {
                "status": None,
                "child_return_code": return_code,
                "timed_out": timed_out,
                "artifact_budget_exceeded": limit_exceeded,
                "received_signal": received_signal[0] if received_signal else None,
                "started_monotonic_ns": launched_at_ns,
                "ended_monotonic_ns": ended_at_ns,
                "binary_path": str(executable_path),
                "binary_sha256": executable_sha256,
                "binary_device": executable_info.st_dev,
                "binary_inode": executable_info.st_ino,
                "binary_size": executable_info.st_size,
                "requested_argv": command,
                "requested_argv_sha256": hashlib.sha256(canonical_bytes(command)).hexdigest(),
                "executed_argv": executed_argv,
                "executed_file_descriptor": executable_reference,
                "environment": launch_environment,
                "environment_sha256": hashlib.sha256(canonical_bytes(launch_environment)).hexdigest(),
                "cwd": str(cwd.resolve(strict=True)) if cwd is not None else str(Path.cwd()),
                "cpu_set": cpu_set,
            }
            if resource_budget_monitor is not None:
                result_value["resource_budget_exceeded"] = resource_budget_exceeded
                result_value["resource_monitor_error"] = resource_monitor_error
        else:
            result_value = return_code
    except SoakReadbackError:
        raise
    except OSError as error:
        raise SoakReadbackError(f"cannot launch soak process: {error}") from error
    finally:
        active_exception = sys.exc_info()[1]
        final_cleanup_failure: str | None = cleanup_failure
        if process is not None and owner is not None and not owner.reaped and not hard_cleanup_attempted:
            try:
                # This path handles callback, scan, and I/O exceptions. The
                # direct child stays unreaped while the known session receives
                # bounded TERM/KILL attempts. Lost wait ownership stops here.
                _active, escaped, scan_error = owner.signal_group(signal.SIGTERM)
                if scan_error is not None:
                    final_cleanup_failure = final_cleanup_failure or f"soak launch cleanup could not verify its process group: {scan_error}"
                if escaped:
                    final_cleanup_failure = final_cleanup_failure or "soak launch cleanup found live same-session processes outside its owned process group"
                emergency_deadline = time.monotonic() + min(term_grace_seconds, 0.2)
                while time.monotonic() < emergency_deadline and owner.observe() is None:
                    time.sleep(0.01)
                _active, escaped, scan_error = owner.signal_group(signal.SIGKILL)
                if scan_error is not None:
                    final_cleanup_failure = final_cleanup_failure or f"soak launch cleanup could not verify its process group: {scan_error}"
                if escaped:
                    final_cleanup_failure = final_cleanup_failure or "soak launch cleanup found live same-session processes outside its owned process group"
                reap_deadline = time.monotonic() + kill_reap_seconds
                while time.monotonic() < reap_deadline and owner.observe() is None:
                    time.sleep(0.01)
                return_code, active, escaped, scan_error = owner.reap_if_ready(allow_unverified_group=True)
                if return_code is None:
                    final_cleanup_failure = final_cleanup_failure or "soak launch cleanup failed: child remains unreaped after bounded SIGKILL"
                if active:
                    final_cleanup_failure = final_cleanup_failure or "soak launch cleanup failed: process-group members remained live after bounded SIGKILL"
                if escaped:
                    final_cleanup_failure = final_cleanup_failure or "soak launch cleanup found live same-session processes outside its owned process group"
                if scan_error is not None:
                    final_cleanup_failure = final_cleanup_failure or f"soak launch cleanup could not verify its process group: {scan_error}"
            except SoakReadbackError as error:
                final_cleanup_failure = f"soak launch cleanup failed: {error}"
        elif process is not None and owner is not None and not owner.reaped and hard_cleanup_attempted:
            final_cleanup_failure = final_cleanup_failure or "soak launch cleanup failed: child remains unreaped after hard SIGKILL deadline"
        elif process is not None and owner is None:
            final_cleanup_failure = final_cleanup_failure or "soak launch cleanup failed: direct-child ownership was not established"
        cleanup_result: dict[str, Any] | None = None
        if process is not None:
            if on_cleanup is not None:
                cleanup_result = {
                    "schema": "allocatbelt.application-soak-process-cleanup.v1",
                    "status": "failed" if final_cleanup_failure is not None or owner is None or not owner.reaped else "verified",
                    "pid": process.pid,
                    "return_code": process.returncode,
                    "received_signal": received_signal[0] if received_signal else None,
                    "cleanup_error": final_cleanup_failure,
                }
                cleanup_result_ref = cleanup_result
                try:
                    on_cleanup(cleanup_result)
                except BaseException as error:
                    final_cleanup_failure = final_cleanup_failure or f"soak launch cleanup-result callback failed: {error}"
        try:
            consume_signal_intent()
        except BaseException as error:
            final_cleanup_failure = final_cleanup_failure or f"soak launch signal callback failed: {error}"
        if cleanup_result is not None:
            cleanup_result["received_signal"] = received_signal[0] if received_signal else None
        for signum, old_handler in old_handlers.items():
            try:
                signal.signal(signum, old_handler)
            except (OSError, ValueError) as error:
                final_cleanup_failure = f"{final_cleanup_failure}; signal handler restore failed: {error}" if final_cleanup_failure else f"signal handler restore failed: {error}"
        for fd in output_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        for fd in (inherited_executable_fd, executable_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        try:
            consume_signal_intent()
        except BaseException as error:
            final_cleanup_failure = final_cleanup_failure or f"soak launch signal callback failed: {error}"
        if cleanup_result is not None:
            cleanup_result["received_signal"] = received_signal[0] if received_signal else None
        if final_cleanup_failure is not None:
            if active_exception is None:
                raise SoakReadbackError(final_cleanup_failure)
            raise SoakReadbackError(f"{active_exception}; {final_cleanup_failure}") from active_exception

    require(result_value is not None, "soak launch completed without a return value")
    final_signal = received_signal[0] if received_signal else None
    if timed_out:
        final_status = 124
    elif limit_exceeded:
        final_status = 125
    elif final_signal is not None:
        final_status = 128 + final_signal
    elif return_code < 0:
        final_status = 128 + (-return_code)
    else:
        final_status = return_code
    if return_details:
        assert isinstance(result_value, dict)
        result_value["status"] = final_status
        result_value["received_signal"] = final_signal
        return result_value
    return final_status


def command_launch(args: argparse.Namespace) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    require(command, "launch requires a binary command after --")
    output_dir = _check_private_output_directory(args.output_dir)
    audit, preflight = _current_audit(args)
    require(args.preflight.resolve(strict=True).parent == output_dir, "launch preflight must be inside its private output directory")
    require(args.preflight.resolve(strict=True) == output_dir / "soak-preflight.json", "launch preflight path differs from the canonical private output")
    descriptor = audit["launch_descriptor"]
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        require(audit["launch_enabled"] is True and descriptor["launch_enabled"] is True, "SourceV5 external-pressure soak remains launch-disabled because required capacity chronology or feedback composition has not been independently validated")
        return command_launch_v2(args, audit, preflight, output_dir)
    require(command == descriptor["argv"], "actual candidate command/argv differs from the preflighted launch descriptor")
    terminal_path = args.terminal_path or output_dir / "terminal-records.tsv"
    samples_path = args.samples_path or output_dir / "resource-samples.tsv"
    require(terminal_path.resolve(strict=False) == Path(descriptor["terminal_path"]), "actual terminal path differs from the preflighted launch descriptor")
    require(samples_path.resolve(strict=False) == Path(descriptor["samples_path"]), "actual samples path differs from the preflighted launch descriptor")
    for path, label in ((terminal_path, "terminal stream"), (samples_path, "sample stream")):
        require(path.resolve(strict=False).parent == output_dir, f"launch {label} path must be inside the private output directory")
        require(not path.exists() and not path.is_symlink(), f"launch refuses to replace an existing {label}")
    details = launch_process(
        command,
        args.cpu_set,
        output_dir / "stdout.log",
        output_dir / "stderr.log",
        output_dir / "time.txt",
        args.timeout_seconds,
        args.term_grace_seconds,
        tuple(
            (path, maximum)
            for path, maximum in (
                (terminal_path, preflight["terminal_budget_bytes"]),
                (samples_path, preflight["sample_budget_bytes"]),
            )
            if path is not None
        ),
        environment=descriptor["environment"],
        cwd=Path(descriptor["cwd"]),
        expected_executable_sha256=descriptor["binary_sha256"],
        return_details=True,
    )
    require(type(details) is dict, "launch supervisor did not return its parent execution record")
    launch_receipt = _launch_receipt_value(details, audit, preflight)
    launch_receipt_sha = _write_exclusive_json(output_dir / "soak-launch.json", launch_receipt)
    print(json.dumps({"exit_code": details["status"], "launch_receipt_sha256": launch_receipt_sha}, sort_keys=True))
    return details["status"]


def _proc_start_ticks(pid: int) -> int:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        require(len(raw) <= 65536, "application /proc stat exceeds its finite bound")
        text_value = raw.decode("ascii").strip()
    except (OSError, UnicodeError) as error:
        raise SoakReadbackError(f"cannot capture started application process identity: {error}") from error
    closing = text_value.rfind(")")
    require(closing > 0, "application /proc stat has malformed command framing")
    head = text_value[:text_value.find("(")].strip()
    tail = text_value[closing + 1:].strip().split()
    require(head == str(pid) and len(tail) >= 20, "application /proc stat has malformed identity fields")
    return parse_uint(tail[19], "application start ticks", maximum=U64_MAX)


def _atomic_json_publish(path: Path, value: dict[str, Any]) -> str:
    raw = canonical_bytes(value)
    require(not path.exists() and not path.is_symlink(), f"refusing to replace atomic output {path.name}")
    directory = path.parent.resolve(strict=True)
    temporary = directory / f".{path.name}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            require(written > 0, f"short atomic write for {path.name}")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return hashlib.sha256(raw).hexdigest()


def _make_pressure_launch_binding(
    process: subprocess.Popen[bytes], executable_path: Path, executable_sha256: str,
    cpu_ids: set[int], cwd: Path, environment: dict[str, str], pressure_recipe: dict[str, Any],
) -> dict[str, Any]:
    pid = process.pid
    start_ticks = _proc_start_ticks(pid)
    try:
        executable_actual = os.readlink(f"/proc/{pid}/exe")
        cwd_actual = os.readlink(f"/proc/{pid}/cwd")
        affinity = sorted(os.sched_getaffinity(pid))
        netns = os.stat(f"/proc/{pid}/ns/net").st_ino
        environment_raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError as error:
        raise SoakReadbackError(f"cannot capture the application process launch identity: {error}") from error
    require(len(environment_raw) <= MAX_ENVIRONMENT_BYTES, "application environment exceeds its launch-binding bound")
    env_map: dict[str, str] = {}
    for entry in environment_raw.split(b"\0"):
        if not entry:
            continue
        key, sep, value = entry.partition(b"=")
        if sep and key in (b"TMPDIR", b"ALLOCATBELT_APP_PRESSURE_NONCE"):
            try:
                env_map[key.decode("ascii")] = value.decode("utf-8")
            except UnicodeError as error:
                raise SoakReadbackError("application pressure environment is not valid UTF-8") from error
    expected = pressure_recipe
    require(Path(executable_actual) == executable_path and executable_sha256 == expected["files"]["application_binary"]["raw_sha256"], "started application executable differs from frozen pressure bytes")
    require(Path(cwd_actual) == cwd and Path(cwd_actual) in {Path(item) for item in expected["storage"]["application_io_paths"]}, "started application cwd differs from pressure storage binding")
    require(sorted(cpu_ids) == affinity == expected["schedule"]["application_cpu_affinity"], "started application affinity differs from frozen pressure conditions")
    require(env_map.get("ALLOCATBELT_APP_PRESSURE_NONCE") == expected["identity"]["nonce"], "started application lacks the frozen pressure nonce")
    require(env_map.get("TMPDIR") == expected["process"]["application_tmpdir_path"] == environment.get("TMPDIR"), "started application TMPDIR differs from frozen pressure storage")
    require(netns == expected["network"]["network_namespace_inode"], "started application network namespace differs from frozen pressure conditions")
    process_value = {
        "pid": pid,
        "start_ticks": start_ticks,
        "executable_path": str(executable_path),
        "executable_sha256": executable_sha256,
        "cwd": str(cwd),
        "tmpdir_path": env_map["TMPDIR"],
        "cpu_affinity": affinity,
        "network_namespace_inode": netns,
    }
    body = {
        "schema": "allocatbelt.application-pressure-launch-binding.v1",
        "recipe_sha256": expected["recipe_sha256"],
        "nonce": expected["identity"]["nonce"],
        "process": process_value,
    }
    return {**body, "launch_binding_sha256": hashlib.sha256(canonical_bytes(body)).hexdigest()}


def _make_application_launch_attestation(
    process: subprocess.Popen[bytes],
    expected_argv: list[str],
    expected_environment: dict[str, str],
    execution_kind: str,
    process_binding: dict[str, Any],
) -> dict[str, Any]:
    """Seal the direct APP Popen argv, full environment, and executable fd."""
    require(execution_kind in ("normal_app", "timed_soak"), "pressure application descriptor has an unknown execution kind")
    pid = process.pid
    try:
        command_raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        environment_raw = Path(f"/proc/{pid}/environ").read_bytes()
        executable_path = os.readlink(f"/proc/{pid}/exe")
        cwd_path = os.readlink(f"/proc/{pid}/cwd")
    except OSError as error:
        raise SoakReadbackError(f"cannot capture direct application argv/environment identity: {error}") from error
    require(len(command_raw) <= 1024 * 1024, "application command line exceeds its launch attestation bound")
    require(len(environment_raw) <= MAX_ENVIRONMENT_BYTES, "application environment exceeds its launch attestation bound")
    require(command_raw.endswith(b"\0"), "application command line is not NUL terminated")
    try:
        actual_argv = [item.decode("utf-8", "strict") for item in command_raw[:-1].split(b"\0")]
        actual_environment: dict[str, str] = {}
        for entry in environment_raw.split(b"\0"):
            if not entry:
                continue
            key_raw, separator, value_raw = entry.partition(b"=")
            require(bool(separator) and bool(key_raw), "application environment contains a malformed entry")
            key = key_raw.decode("ascii", "strict")
            require(key not in actual_environment, "application environment repeats a variable")
            actual_environment[key] = value_raw.decode("utf-8", "strict")
    except (UnicodeError, SoakReadbackError) as error:
        raise SoakReadbackError(f"application argv/environment is not canonical UTF-8: {error}") from error
    require(actual_argv == expected_argv, "actual APP argv differs from the frozen member descriptor")
    require(actual_environment == expected_environment, "actual APP environment differs from the complete frozen member environment")
    descriptor_identity = getattr(process, "_allocatbelt_executable_binding", None)
    require(type(descriptor_identity) is dict, "direct APP Popen omitted its verified executable fd identity")
    require(
        set(descriptor_identity) == {"fd_reference", "device", "inode", "size", "sha256"}
        and descriptor_identity["sha256"] == process_binding["process"]["executable_sha256"],
        "direct APP executable fd identity differs from the pressure launch record",
    )
    actual_start_ticks = _proc_start_ticks(pid)
    require(actual_start_ticks == process_binding["process"]["start_ticks"], "direct APP PID/start identity changed during launch attestation")
    command_sha = hashlib.sha256(canonical_bytes(actual_argv)).hexdigest()
    environment_sha = hashlib.sha256(canonical_bytes(actual_environment)).hexdigest()
    body = {
        "schema": "allocatbelt.application-pressure-app-launch-attestation.v1",
        "execution_kind": execution_kind,
        "process": {
            "pid": pid,
            "start_ticks": actual_start_ticks,
            "executable_path": executable_path.removesuffix(" (deleted)"),
            "executable_sha256": descriptor_identity["sha256"],
            "executable_device": descriptor_identity["device"],
            "executable_inode": descriptor_identity["inode"],
            "executable_size": descriptor_identity["size"],
            "executable_fd_reference": descriptor_identity["fd_reference"],
            "cwd": cwd_path,
            "argv": actual_argv,
            "argv_sha256": command_sha,
            "cmdline_raw_sha256": hashlib.sha256(command_raw).hexdigest(),
            "environment_sha256": environment_sha,
            "environment_raw_sha256": hashlib.sha256(environment_raw).hexdigest(),
        },
    }
    require(
        body["process"]["executable_path"] == process_binding["process"]["executable_path"]
        and body["process"]["cwd"] == process_binding["process"]["cwd"],
        "direct APP procfs executable or cwd differs from the pressure launch identity",
    )
    return {**body, "attestation_sha256": hashlib.sha256(canonical_bytes(body)).hexdigest()}


def _read_pressure_ready(path: Path, pressure_recipe: dict[str, Any], expected_recipe_sha: str, expected_condition_sha: str) -> tuple[dict[str, Any], str]:
    ready, raw_sha, raw = read_json(path, "measured pressure readiness marker", 64 * 1024)
    exact_object(ready, {
        "schema", "recipe_sha256", "condition_sha256", "nonce", "ownership_protocol",
        "worker_ownership_sha256", "worker_authorization_sha256", "pressure_ready_monotonic_ns",
        "readiness", "ready_sha256",
    }, "pressure readiness marker")
    require(raw == canonical_bytes(ready), "pressure readiness marker is not canonical JSON")
    body = {key: value for key, value in ready.items() if key != "ready_sha256"}
    require(ready["schema"] == "allocatbelt.application-pressure-ready.v1" and ready["recipe_sha256"] == expected_recipe_sha and ready["condition_sha256"] == expected_condition_sha and ready["nonce"] == pressure_recipe["identity"]["nonce"], "pressure readiness marker recipe/condition/nonce differs")
    require(ready["ownership_protocol"] == SOURCE_V5_PRESSURE_OWNERSHIP_PROTOCOL, "pressure readiness marker lacks the required durable worker authorization protocol")
    digest(ready["worker_ownership_sha256"], "pressure readiness ownership journal SHA-256")
    digest(ready["worker_authorization_sha256"], "pressure readiness worker authorization SHA-256")
    require(digest(ready["ready_sha256"], "pressure readiness self digest") == hashlib.sha256(canonical_bytes(body)).hexdigest(), "pressure readiness self digest is invalid")
    readiness = exact_object(ready["readiness"], {
        "cpu_ready", "disk_ready", "loopback_ready", "all_ready", "cpu_busy_basis_points", "disk_write_bytes_per_second",
        "disk_queue_or_stall_microseconds", "loopback_requests_per_second", "loopback_latency_p99_upper_nanoseconds",
        "loopback_tx_bytes_per_second", "loopback_rx_bytes_per_second",
    }, "measured readiness metrics")
    require(all(readiness[key] is True for key in ("cpu_ready", "disk_ready", "loopback_ready", "all_ready")), "pressure driver readiness marker does not attest every required pressure source")
    threshold = pressure_recipe["readiness_thresholds"]
    measured_fields = {
        "cpu_busy_basis_points": "cpu_busy_min_basis_points",
        "disk_write_bytes_per_second": "disk_write_min_bytes_per_second",
        "disk_queue_or_stall_microseconds": "disk_queue_or_stall_min_microseconds",
        "loopback_requests_per_second": "loopback_requests_min_per_second",
        "loopback_tx_bytes_per_second": "loopback_tx_min_bytes_per_second",
        "loopback_rx_bytes_per_second": "loopback_rx_min_bytes_per_second",
    }
    for measured, frozen in measured_fields.items():
        value = uint(readiness[measured], f"pressure readiness {measured}")
        require(value >= threshold[frozen], f"measured pressure readiness is below frozen {frozen}")
    latency = uint(readiness["loopback_latency_p99_upper_nanoseconds"], "pressure readiness loopback latency", positive=True)
    require(latency <= threshold["loopback_latency_p99_max_nanoseconds"], "measured loopback latency exceeds the frozen readiness threshold")
    ready_at = uint(ready["pressure_ready_monotonic_ns"], "pressure ready monotonic timestamp", positive=True, maximum=U128_MAX)
    require(ready_at <= time.monotonic_ns(), "pressure readiness marker is timestamped in the future")
    return ready, raw_sha


def _pressure_output_hashes(path: Path) -> dict[str, str]:
    required = {
        "run": "run.json", "events": "events.jsonl", "launch": "launch-record.json",
        "process_binding": "process-binding.json", "ready": "pressure-ready.json",
    }
    result: dict[str, str] = {}
    for key, name in required.items():
        candidate = path / name
        maximum = MAX_RECEIPT_BYTES if key == "run" else MAX_TERMINAL_BYTES if key == "events" else 256 * 1024
        result[key] = sha256_file(candidate, f"pressure {name}", maximum)
    return result


def _require_source_v5_pressure_prefix(
    pressure_dir: Path, pressure_info: dict[str, Any], expected_ready_sha256: str,
) -> tuple[dict[str, Any], str]:
    """Require SourceV5's durable worker protocol independently of the generic pressure reader."""
    recipe = pressure_info["value"]
    expected_recipe_sha = pressure_info["recipe_sha256"]
    expected_condition_sha = pressure_info["condition_sha256"]
    ready, ready_sha = _read_pressure_ready(
        pressure_dir / "pressure-ready.json", recipe, expected_recipe_sha, expected_condition_sha,
    )
    require(ready_sha == expected_ready_sha256, "SourceV5 pressure readiness raw digest differs from the frozen artifact pin")
    require(
        ready.get("ownership_protocol") == SOURCE_V5_PRESSURE_OWNERSHIP_PROTOCOL
        and ready.get("worker_ownership_sha256")
        and ready.get("worker_authorization_sha256"),
        "SourceV5 pressure proof requires the durable worker ownership protocol",
    )

    events_path = pressure_dir / "events.jsonl"
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(events_path, flags)
    except OSError as error:
        raise SoakReadbackError(f"cannot open SourceV5 pressure event prefix: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_TERMINAL_BYTES, "SourceV5 pressure events are not a bounded regular file")
        records: list[dict[str, Any]] = []
        prefix_raw = bytearray()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for index in range(3):
                raw_line = stream.readline(2 * 1024 * 1024 + 1)
                require(raw_line and raw_line.endswith(b"\n") and len(raw_line) <= 2 * 1024 * 1024, f"SourceV5 pressure event prefix line {index} is missing or oversized")
                prefix_raw.extend(raw_line)
                value = _read_json_raw(raw_line, f"SourceV5 pressure event prefix line {index}")
                require(raw_line == canonical_bytes(value), f"SourceV5 pressure event prefix line {index} is not canonical")
                records.append(value)
        prefix_again = os.pread(descriptor, len(prefix_raw), 0)
        after = os.fstat(descriptor)
        after_path = events_path.lstat()
        identity = lambda item: (item.st_dev, item.st_ino, stat.S_IFMT(item.st_mode))
        require(
            identity(before) == identity(after) == identity(after_path)
            and after.st_size >= before.st_size >= len(prefix_raw)
            and after.st_size <= MAX_TERMINAL_BYTES
            and prefix_again == bytes(prefix_raw),
            "SourceV5 pressure events changed while checking their durable prefix",
        )
    finally:
        os.close(descriptor)

    ownership, authorization, start = records
    require(
        ownership.get("kind") == "worker_ownership"
        and authorization.get("kind") == "workers_authorized"
        and start.get("kind") == "pressure_start",
        "SourceV5 pressure proof event prefix is not ownership, ACK authorization, then pressure start",
    )
    ownership_digest = digest(ownership.get("ownership_sha256"), "SourceV5 worker ownership event digest")
    ownership_body = {key: value for key, value in ownership.items() if key != "ownership_sha256"}
    require(ownership_digest == hashlib.sha256(canonical_bytes(ownership_body)).hexdigest(), "SourceV5 worker ownership event self digest is invalid")
    authorization_digest = digest(authorization.get("authorization_sha256"), "SourceV5 worker authorization event digest")
    authorization_body = {key: value for key, value in authorization.items() if key != "authorization_sha256"}
    require(authorization_digest == hashlib.sha256(canonical_bytes(authorization_body)).hexdigest(), "SourceV5 worker authorization event self digest is invalid")
    require(
        authorization.get("ownership_sha256") == ownership_digest
        and start.get("ownership_sha256") == ownership_digest
        and start.get("authorization_sha256") == authorization_digest
        and ready["worker_ownership_sha256"] == ownership_digest
        and ready["worker_authorization_sha256"] == authorization_digest,
        "SourceV5 pressure start/readiness marker does not bind the durable ownership and ACK records",
    )
    require(
        ownership.get("recipe_sha256") == expected_recipe_sha
        and authorization.get("recipe_sha256") == expected_recipe_sha
        and start.get("recipe_sha256") == expected_recipe_sha
        and ownership.get("nonce") == recipe["identity"]["nonce"]
        and authorization.get("nonce") == recipe["identity"]["nonce"]
        and start.get("nonce") == recipe["identity"]["nonce"],
        "SourceV5 pressure event prefix recipe/nonce differs from its frozen identity",
    )
    return ready, ready_sha


def validate_pressure_proof_inputs(
    pressure_dir: Path,
    pressure_info: dict[str, Any],
    artifact_pins: dict[str, str],
    readiness_thresholds: dict[str, Any],
    proof_path: Path,
) -> dict[str, Any]:
    """Validate one completed pressure directory using explicit frozen inputs."""
    require(type(pressure_info) is dict, "pressure proof is missing its frozen recipe inputs")
    required = {
        "value", "reader", "recipe_sha256", "raw_sha256", "condition_sha256", "recipe_path",
    }
    require(required <= set(pressure_info), "pressure proof inputs omit a frozen recipe pin or reader")
    pin_keys = {"recipe", "run", "events", "launch", "process_binding", "ready"}
    exact_object(artifact_pins, pin_keys, "pressure proof artifact pins")
    for key, value in artifact_pins.items():
        digest(value, f"pressure proof {key} raw SHA-256")
    require(artifact_pins["recipe"] == pressure_info["recipe_sha256"], "pressure proof recipe pin differs from the validated recipe")
    require(type(readiness_thresholds) is dict, "pressure readiness thresholds are malformed")
    require(pressure_dir.resolve(strict=True) == pressure_dir, "pressure artifact directory is a symlink or alias")
    actual_artifacts = _pressure_output_hashes(pressure_dir)
    require({key: artifact_pins[key] for key in actual_artifacts} == actual_artifacts, "pressure proof raw artifact pins differ from the completed pressure directory")
    expected = {"recipe": pressure_info["recipe_sha256"], **artifact_pins}
    _require_source_v5_pressure_prefix(pressure_dir, pressure_info, artifact_pins["ready"])
    try:
        proof = pressure_info["reader"].verify_pressure(
            Path(pressure_info["recipe_path"]),
            pressure_info["recipe_sha256"], pressure_dir, expected,
        )
    except (OSError, TypeError, ValueError, KeyError) as error:
        raise SoakReadbackError(f"captured pressure readback rejected its raw process-bound artifacts: {error}") from error
    minimum_samples = uint(
        readiness_thresholds.get("minimum_ready_samples"),
        "pressure minimum ready samples", positive=True,
    )
    minimum_overlap_seconds = uint(
        readiness_thresholds.get("minimum_overlap_seconds"),
        "pressure minimum overlap seconds", positive=True,
    )
    require(proof["sample_count"] >= minimum_samples, "pressure proof has fewer measured ready samples than SourceV5 requires")
    require(proof["application_overlap_nanoseconds"] >= minimum_overlap_seconds * 1_000_000_000, "pressure proof overlap is below SourceV5 readiness requirement")
    proof_raw = canonical_bytes(proof)
    if proof_path.exists():
        existing, existing_sha, existing_raw = read_json(proof_path, "external pressure validation proof", MAX_RECEIPT_BYTES)
        require(existing_raw == proof_raw, "saved external pressure proof differs from the captured independent validator")
        return {"proof": existing, "raw_sha256": existing_sha}
    proof_sha = _write_exclusive_json(proof_path, proof)
    return {"proof": proof, "raw_sha256": proof_sha}


def _validate_pressure_proof(artifact_dir: Path, audit: dict[str, Any]) -> dict[str, Any]:
    pressure_info = audit["source"].get("pressure_recipe")
    require(type(pressure_info) is dict, "SourceV5 pressure proof is missing its frozen recipe")
    recipe_pin = audit["recipe"]["pressure"]["recipe"]
    require(type(recipe_pin) is dict, "SourceV5 parent audit is missing its pressure recipe pin")
    require(
        pressure_info.get("raw_sha256") == recipe_pin.get("raw_sha256")
        and pressure_info.get("recipe_sha256") == recipe_pin.get("semantic_sha256"),
        "SourceV5 pressure proof recipe identity differs from its parent pin",
    )
    pressure_info = _legacy_pressure_info_for_postflight(pressure_info, recipe_pin)
    condition = audit["recipe"]["qualification"]["pressure_condition"]
    artifact_pins = {"recipe": pressure_info["recipe_sha256"], **_pressure_output_hashes(artifact_dir / "pressure")}
    return validate_pressure_proof_inputs(
        artifact_dir / "pressure",
        pressure_info,
        artifact_pins,
        condition["readiness_thresholds"],
        artifact_dir / "pressure-readback.json",
    )


def _validate_pressure_proof_monitored(
    artifact_dir: Path, audit: dict[str, Any], resource_monitor: Any,
) -> dict[str, Any]:
    """Keep postflight capacity sampling live during pressure proof replay."""
    if resource_monitor is None:
        return _validate_pressure_proof(artifact_dir, audit)
    stop = threading.Event()
    sampler_error: list[BaseException] = []
    interval_seconds = resource_monitor.interval_ns / 1_000_000_000

    def sample_until_complete() -> None:
        try:
            while not stop.wait(interval_seconds):
                if resource_monitor.sample("postflight"):
                    return
        except BaseException as error:
            sampler_error.append(error)

    thread = threading.Thread(
        target=sample_until_complete,
        name="source5-soak-resource-monitor-pressure-postflight",
        daemon=True,
    )
    thread.start()
    proof: dict[str, Any] | None = None
    proof_error: BaseException | None = None
    try:
        proof = _validate_pressure_proof(artifact_dir, audit)
    except BaseException as error:
        proof_error = error
    finally:
        stop.set()
        thread.join()
        if sampler_error:
            resource_monitor.failure = resource_monitor.failure or (
                f"pressure_proof_monitor_thread:{type(sampler_error[0]).__name__}:"
                f"{sampler_error[0]}"
            )[:4096]
        try:
            resource_monitor.sample("postflight", force=True)
        except BaseException as error:
            resource_monitor.failure = resource_monitor.failure or (
                f"pressure_proof_monitor_final_sample:{type(error).__name__}:{error}"
            )[:4096]
    if proof_error is not None:
        raise proof_error
    require(proof is not None,
            "Source5 monitored pressure proof returned no receipt")
    return proof


def _legacy_pressure_info_for_postflight(
    pressure_info: dict[str, Any], recipe_pin: dict[str, Any],
) -> dict[str, Any]:
    """Adapt the accepted V2 audit summary to the shared explicit proof API."""
    exact_object(recipe_pin, {"path", "raw_sha256", "semantic_sha256"}, "SourceV5 parent pressure recipe pin")
    require(
        pressure_info.get("raw_sha256") == recipe_pin["raw_sha256"]
        and pressure_info.get("recipe_sha256") == recipe_pin["semantic_sha256"],
        "SourceV5 pressure proof recipe identity differs from its parent pin",
    )
    adapted = {**pressure_info, "recipe_path": recipe_pin["path"]}
    return adapted


def _tail_text(path: Path, maximum: int = 8192) -> str:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - maximum))
            raw = stream.read(maximum)
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _require_pressure_live_while_application_runs(
    pressure_process: subprocess.Popen[bytes], app_process: subprocess.Popen[bytes], stderr_path: Path,
) -> None:
    pressure_exit = pressure_process.poll()
    if pressure_exit is not None and _owned_child_exit(app_process) is None:
        raise SoakReadbackError(
            f"pressure driver exited {pressure_exit} while the soak process was live; stderr tail: {_tail_text(stderr_path)}"
        )


def _install_external_supervisor_signal_handlers() -> tuple[dict[int, Any], dict[str, int | None]]:
    """Record TERM/HUP across the complete pressure-first launch lifecycle."""
    previous: dict[int, Any] = {}
    state: dict[str, int | None] = {"received_signal": None}

    def record(signum: int, _frame: Any) -> None:
        if state["received_signal"] is None:
            state["received_signal"] = signum

    try:
        for signum in (signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, record)
    except BaseException:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        raise
    return previous, state


def _restore_external_supervisor_signal_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _write_external_supervisor_interruption(
    output_dir: Path, audit: dict[str, Any], signum: int,
    pressure_process: subprocess.Popen[bytes] | None, pressure_start_ticks: int | None,
    application_cleanup: str, pressure_cleanup: str,
) -> int:
    exit_code = 128 + signum
    require(application_cleanup in ("not_started", "verified", "failed", "unverified"), "application cleanup state is malformed")
    require(pressure_cleanup in ("not_started", "verified", "failed", "unverified"), "pressure cleanup state is malformed")
    cleanup_states_verified = application_cleanup in ("not_started", "verified") and pressure_cleanup in ("not_started", "verified")
    cleanup_state = "verified" if cleanup_states_verified else "failed" if "failed" in (application_cleanup, pressure_cleanup) else "unverified"
    receipt = {
        "schema": "allocatbelt.application-soak-supervisor-interruption.v2",
        "recipe_sha256": audit["recipe_sha256"],
        "campaign_id": audit["identity"]["campaign_id"],
        "host_id": audit["identity"]["host_id"],
        "run_id": audit["identity"]["run_id"],
        "nonce": audit["identity"]["nonce"],
        "signal": signum,
        "exit_code": exit_code,
        "pressure_driver_pid": None if pressure_process is None else pressure_process.pid,
        "pressure_driver_start_ticks": pressure_start_ticks,
        "pressure_driver_return_code": None if pressure_process is None else pressure_process.poll(),
        "application_cleanup": application_cleanup,
        "pressure_cleanup": pressure_cleanup,
        "cleanup": cleanup_state,
    }
    _write_exclusive_json(output_dir / "soak-supervisor-interruption.json", receipt)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return exit_code


def _set_child_subreaper(enabled: bool) -> bool:
    """Set Linux child-subreaper state and return the previous state."""
    global _PRESSURE_SUBREAPER_ACTIVE
    require(type(enabled) is bool, "child subreaper state must be boolean")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
        prctl.restype = ctypes.c_int
        previous = ctypes.c_int(0)
        if prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:  # PR_GET_CHILD_SUBREAPER
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        if prctl(36, ctypes.c_void_p(1 if enabled else 0), 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
    except (AttributeError, OSError) as error:
        raise SoakReadbackError(f"cannot establish parent-owned pressure worker supervision: {error}") from error
    _PRESSURE_SUBREAPER_ACTIVE = enabled
    return previous.value != 0


def _proc_process_identity(pid: int) -> dict[str, Any] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SoakReadbackError(f"cannot inspect pressure child process {pid}: {error}") from error
    require(len(raw) <= 65_536, f"pressure process {pid} stat exceeds its finite bound")
    try:
        text_value = raw.decode("ascii").strip()
    except UnicodeError as error:
        raise SoakReadbackError(f"pressure process {pid} stat is not ASCII") from error
    closing = text_value.rfind(")")
    require(closing > 0, f"pressure process {pid} stat has malformed command framing")
    head = text_value[:text_value.find("(")].strip()
    tail = text_value[closing + 1:].strip().split()
    require(head == str(pid) and len(tail) >= 20, f"pressure process {pid} stat has malformed identity fields")
    try:
        start_ticks, parent_pid, process_group, session_id = (int(tail[index]) for index in (19, 1, 2, 3))
    except ValueError as error:
        raise SoakReadbackError(f"pressure process {pid} stat identity is malformed") from error
    require(start_ticks > 0 and parent_pid >= 0 and process_group > 0 and session_id > 0, f"pressure process {pid} stat identity is outside its bound")
    return {
        "pid": pid, "state": tail[0], "start_ticks": start_ticks,
        "parent_pid": parent_pid, "pgid": process_group, "session_id": session_id,
    }


def _read_pressure_worker_ownership_event(
    path: Path | None, recipe_sha256: str, schedule: dict[str, Any], expected_nonce: str | None,
) -> dict[tuple[str, int | None], dict[str, int | str | None]]:
    """Read the driver's durable first event to authenticate workers after cmdline disappears."""
    if path is None or expected_nonce is None:
        return {}
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return {}
    except OSError as error:
        raise SoakReadbackError(f"cannot open durable pressure ownership journal: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_TERMINAL_BYTES, "durable pressure ownership journal is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw_line = stream.readline(2 * 1024 * 1024 + 1)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        require(
            (before.st_dev, before.st_ino, before.st_mode) == (after.st_dev, after.st_ino, after.st_mode)
            == (path_after.st_dev, path_after.st_ino, path_after.st_mode),
            "durable pressure ownership journal path changed during capture",
        )
    finally:
        os.close(descriptor)
    if not raw_line:
        return {}
    require(raw_line.endswith(b"\n") and len(raw_line) <= 2 * 1024 * 1024, "durable pressure ownership journal first row is incomplete or oversized")
    event = _read_json_raw(raw_line, "durable pressure ownership journal")
    require(raw_line == canonical_bytes(event), "durable pressure ownership journal is not canonical")
    exact_object(event, {
        "schema", "kind", "recipe_sha256", "nonce", "monotonic_ns", "workers", "ownership_sha256",
    }, "durable pressure ownership event")
    require(
        event["schema"] == "allocatbelt.application-pressure-event.v1"
        and event["kind"] == "worker_ownership"
        and event["recipe_sha256"] == recipe_sha256
        and event["nonce"] == expected_nonce,
        "durable pressure ownership journal recipe/nonce differs",
    )
    ownership_sha = digest(event["ownership_sha256"], "durable pressure ownership journal digest")
    body = {key: value for key, value in event.items() if key != "ownership_sha256"}
    require(ownership_sha == hashlib.sha256(canonical_bytes(body)).hexdigest(), "durable pressure ownership journal self digest is invalid")
    rows = event["workers"]
    expected = _expected_pressure_worker_keys(schedule)
    require(type(rows) is list and len(rows) == len(expected), "durable pressure ownership journal is sparse")
    result: dict[tuple[str, int | None], dict[str, int | str | None]] = {}
    seen_pids: set[int] = set()
    for value in rows:
        row = exact_object(value, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id", "nonce"}, "durable pressure worker identity")
        role = text(row["role"], "durable pressure worker role", maximum=16)
        cpu_value = row["cpu"]
        if role == "cpu":
            cpu = uint(cpu_value, "durable pressure worker CPU", maximum=65535)
        else:
            require(cpu_value is None and role in ("disk", "loopback"), "durable pressure worker role is unsupported")
            cpu = None
        key = (role, cpu)
        require(key in expected and key not in result, "durable pressure ownership roles differ from the frozen worker set")
        pid = uint(row["pid"], "durable pressure worker PID", positive=True, maximum=(1 << 31) - 1)
        require(pid not in seen_pids, "durable pressure ownership journal duplicates a worker PID")
        seen_pids.add(pid)
        start_ticks = uint(row["start_ticks"], "durable pressure worker start ticks", positive=True)
        pgid = uint(row["pgid"], "durable pressure worker PGID", positive=True, maximum=(1 << 31) - 1)
        session_id = uint(row["session_id"], "durable pressure worker session", positive=True, maximum=(1 << 31) - 1)
        require(pgid == pid and session_id == pid and row["nonce"] == expected_nonce, "durable pressure worker identity differs from its nonce/isolated session")
        result[key] = {"pid": pid, "start_ticks": start_ticks, "pgid": pgid, "session_id": session_id, "nonce": expected_nonce}
    require(set(result) == expected, "durable pressure ownership set differs from the frozen worker set")
    return result


def _parse_pressure_worker_argv(
    raw_command: bytes, driver_path: Path, recipe_sha256: str, schedule: dict[str, Any],
    expected_nonce: str | None = None, expected_driver_pid: int | None = None,
    expected_driver_start_ticks: int | None = None,
) -> tuple[str, int | None] | None:
    if len(raw_command) > 65_536:
        raise SoakReadbackError("pressure worker command line exceeds its finite bound")
    try:
        argv = raw_command.rstrip(b"\0").decode("utf-8").split("\0")
    except UnicodeError:
        return None
    if len(argv) < 3 or argv[1] != str(driver_path) or argv[2] != "_worker":
        return None
    tail = argv[3:]
    require(len(tail) % 2 == 0, "captured pressure worker command line has incomplete option pairs")
    options: dict[str, str] = {}
    for index in range(0, len(tail), 2):
        key, value = tail[index:index + 2]
        require(key.startswith("--") and key not in options, "captured pressure worker command line has duplicate or malformed options")
        options[key] = value
    common = {
        "--recipe-sha256", "--owner-nonce", "--driver-pid", "--driver-start-ticks",
        "--interval-ms", "--duration-seconds", "--seed", "--kind",
    }
    require(
        options.get("--recipe-sha256") == recipe_sha256
        and options.get("--interval-ms") == str(schedule["sample_interval_ms"])
        and options.get("--duration-seconds") == str(schedule["duration_seconds"])
        and options.get("--seed") == str(schedule["seed"]),
        "captured pressure worker command line differs from the frozen driver recipe",
    )
    require(expected_nonce is not None and re.fullmatch(r"[0-9a-f]{32}", expected_nonce) is not None, "pressure worker capture lacks its frozen nonce")
    require(options.get("--owner-nonce") == expected_nonce, "captured pressure worker nonce differs from the frozen run identity")
    try:
        owner_pid = int(options["--driver-pid"])
        owner_ticks = int(options["--driver-start-ticks"])
    except (KeyError, ValueError) as error:
        raise SoakReadbackError("captured pressure worker omits a valid driver PID/start identity") from error
    require(owner_pid > 0 and owner_ticks > 0, "captured pressure worker driver PID/start identity is outside its bound")
    if expected_driver_pid is not None:
        require(owner_pid == expected_driver_pid, "captured pressure worker driver PID differs from the owned driver")
    if expected_driver_start_ticks is not None:
        require(owner_ticks == expected_driver_start_ticks, "captured pressure worker driver start ticks differ from the owned driver")
    kind = options.get("--kind")
    require(kind in ("cpu", "disk", "loopback"), "captured pressure worker has an unexpected role")
    if kind == "cpu":
        require(set(options) == common | {"--cpu", "--duty-basis-points"}, "captured CPU pressure worker options differ from the pinned worker protocol")
        try:
            cpu = int(options["--cpu"])
            duty = int(options["--duty-basis-points"])
        except ValueError as error:
            raise SoakReadbackError("captured CPU pressure worker has a malformed CPU") from error
        require(cpu in schedule["pressure_cpu_affinity"] and duty == schedule["cpu_duty_basis_points"], "captured CPU pressure worker differs from the frozen affinity/duty")
        return kind, cpu
    if kind == "disk":
        require(set(options) == common | {"--scratch-file", "--scratch-bytes", "--scratch-device", "--scratch-inode", "--disk-rate"}, "captured disk pressure worker options differ from the pinned worker protocol")
        try:
            scratch_bytes = int(options["--scratch-bytes"])
            scratch_device = int(options["--scratch-device"])
            scratch_inode = int(options["--scratch-inode"])
            disk_rate = int(options["--disk-rate"])
        except ValueError as error:
            raise SoakReadbackError("captured disk pressure worker has malformed storage arguments") from error
        require(
            Path(options["--scratch-file"]).is_absolute()
            and Path(options["--scratch-file"]).name == f".allocatbelt-pressure-{expected_nonce}.bin"
            and scratch_bytes == schedule["scratch_file_bytes"] and scratch_device > 0 and scratch_inode > 0
            and disk_rate == schedule["disk_bytes_per_second"],
            "captured disk pressure worker differs from its frozen scratch/rate arguments",
        )
        return kind, None
    require(set(options) == common | {"--requests-per-second", "--payload-bytes"}, "captured loopback pressure worker options differ from the pinned worker protocol")
    try:
        requests = int(options["--requests-per-second"])
        payload = int(options["--payload-bytes"])
    except ValueError as error:
        raise SoakReadbackError("captured loopback pressure worker has malformed network arguments") from error
    require(
        requests == schedule["network_requests_per_second"]
        and payload == schedule["network_payload_bytes"],
        "captured loopback pressure worker differs from its frozen request/payload arguments",
    )
    return kind, None


def _proc_child_pids(parent_pid: int, label: str) -> list[int]:
    try:
        raw_children = Path(f"/proc/{parent_pid}/task/{parent_pid}/children").read_bytes()
    except FileNotFoundError:
        return []
    except OSError as error:
        raise SoakReadbackError(f"cannot inspect {label} child list: {error}") from error
    require(len(raw_children) <= 65_536, f"{label} child list exceeds its finite bound")
    try:
        return [int(item) for item in raw_children.decode("ascii").split()]
    except (UnicodeError, ValueError) as error:
        raise SoakReadbackError(f"{label} child list is malformed") from error


def _reap_adopted_pressure_workers(sessions: dict[tuple[str, int | None], dict[str, Any]]) -> None:
    for record in sessions.values():
        if not record.get("adopted_by_subreaper") or record.get("reaped"):
            continue
        try:
            waited_pid, status = os.waitpid(record["pid"], os.WNOHANG)
        except ChildProcessError:
            record["reaped"] = True
            continue
        except InterruptedError:
            continue
        if waited_pid == record["pid"]:
            record["reaped"] = True
            record["wait_status"] = status


def _capture_pressure_worker_sessions(
    driver_pid: int, driver_start_ticks: int | None, driver_path: Path, recipe_sha256: str,
    schedule: dict[str, Any], sessions: dict[tuple[str, int | None], dict[str, Any]],
    expected_nonce: str | None = None,
    excluded_child_identities: set[tuple[int, int]] | None = None,
    ownership_event_path: Path | None = None,
) -> None:
    excluded = set() if excluded_child_identities is None else excluded_child_identities
    if _PRESSURE_SUBREAPER_ACTIVE:
        for record in sessions.values():
            if record.get("parent_pid") != driver_pid or record.get("reaped"):
                continue
            observed = _proc_process_identity(record["pid"])
            if observed is None:
                continue
            require(
                observed["start_ticks"] == record["start_ticks"]
                and observed["pgid"] == record["pgid"]
                and observed["session_id"] == record["session_id"],
                "pressure worker identity changed while the parent-owned subreaper adopted it",
            )
            if observed["parent_pid"] == os.getpid():
                record["parent_pid"] = os.getpid()
                record["adopted_by_subreaper"] = True
    parent_sources: list[tuple[int, str, bool]] = []
    driver_identity = _proc_process_identity(driver_pid)
    if driver_start_ticks is not None and driver_identity is not None and driver_identity["start_ticks"] == driver_start_ticks:
        require(
            driver_identity["pgid"] == driver_pid and driver_identity["session_id"] == driver_pid,
            "pressure driver process group/session changed after Popen",
        )
        parent_sources.append((driver_pid, "pressure driver", False))
    if _PRESSURE_SUBREAPER_ACTIVE:
        parent_sources.append((os.getpid(), "pressure subreaper", True))
    if parent_sources:
        require(expected_nonce is not None and re.fullmatch(r"[0-9a-f]{32}", expected_nonce) is not None, "pressure worker capture lacks its frozen nonce")
    ownership_rows: dict[tuple[str, int | None], dict[str, int | str | None]] | None = None
    for parent_pid, label, adopted in parent_sources:
        child_pids = _proc_child_pids(parent_pid, label)
        maximum_children = len(schedule["pressure_cpu_affinity"]) + (4 if adopted else 2)
        require(len(child_pids) <= maximum_children, f"{label} has more direct children than its frozen pressure worker allowance")
        for child_pid in child_pids:
            identity = _proc_process_identity(child_pid)
            if identity is None or identity["parent_pid"] != parent_pid:
                continue
            if (child_pid, identity["start_ticks"]) in excluded:
                continue
            try:
                command = Path(f"/proc/{child_pid}/cmdline").read_bytes()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise SoakReadbackError(f"cannot inspect pressure worker {child_pid} command: {error}") from error
            parsed = _parse_pressure_worker_argv(
                command, driver_path, recipe_sha256, schedule, expected_nonce,
                expected_driver_pid=driver_pid,
                expected_driver_start_ticks=driver_start_ticks,
            )
            if parsed is None:
                # A just-orphaned worker can consume SIGTERM and EOF before
                # this first post-death scan; Linux then exposes an empty
                # cmdline for its zombie. Never infer a pressure role from
                # PID/session/timing alone. Match workers to the durable first
                # event; record any other adopted zombie as unknown so it can
                # be reaped without becoming evidence of a complete roster.
                if adopted and identity["state"] == "Z" and child_pid != driver_pid:
                    if ownership_rows is None:
                        try:
                            ownership_rows = _read_pressure_worker_ownership_event(
                                ownership_event_path, recipe_sha256, schedule, expected_nonce,
                            )
                        except SoakReadbackError:
                            # A malformed/incomplete journal cannot authorize
                            # role attribution, but direct-child zombie reaping
                            # remains safe and is retained as unknown evidence.
                            ownership_rows = {}
                    matching = [
                        (key, row) for key, row in ownership_rows.items()
                        if row["pid"] == child_pid
                    ]
                    key: tuple[str, int | None]
                    role: str
                    cpu: int | None
                    authenticated = False
                    if len(matching) == 1:
                        key, row = matching[0]
                        role, cpu = key
                        authenticated = (
                            row["start_ticks"] == identity["start_ticks"]
                            and row["pgid"] == identity["pgid"]
                            and row["session_id"] == identity["session_id"]
                            and driver_start_ticks is not None
                            and identity["start_ticks"] >= driver_start_ticks
                        )
                    else:
                        key = ("unknown_adopted_zombie", child_pid)
                        role, cpu = "unknown_adopted_zombie", None
                    if not matching and not ownership_rows:
                        prior_captures = [
                            (prior_key, prior) for prior_key, prior in sessions.items()
                            if prior_key in _expected_pressure_worker_keys(schedule)
                            and prior.get("pid") == child_pid
                        ]
                        if len(prior_captures) == 1:
                            prior_key, prior = prior_captures[0]
                            prior_role, prior_cpu = prior_key
                            prior_identity_matches = (
                                prior.get("start_ticks") == identity["start_ticks"]
                                and prior.get("pgid") == identity["pgid"]
                                and prior.get("session_id") == identity["session_id"]
                                and prior.get("nonce") == expected_nonce
                                and prior.get("driver_pid") == driver_pid
                                and prior.get("driver_start_ticks") == driver_start_ticks
                                and driver_start_ticks is not None
                                and identity["start_ticks"] >= driver_start_ticks
                            )
                            if prior_identity_matches:
                                key, role, cpu = prior_key, prior_role, prior_cpu
                                authenticated = True
                    if not authenticated:
                        key = ("unknown_adopted_zombie", child_pid)
                        role, cpu = "unknown_adopted_zombie", None
                    zombie_record = {
                        "pid": child_pid, "start_ticks": identity["start_ticks"],
                        "pgid": identity["pgid"], "session_id": identity["session_id"],
                        "parent_pid": parent_pid, "adopted_by_subreaper": True,
                        "reaped": False, "role": role, "cpu": cpu,
                        "nonce": expected_nonce if authenticated else None,
                        "orphan_zombie": True, "unknown_adopted_zombie": not authenticated,
                        "driver_pid": driver_pid, "driver_start_ticks": driver_start_ticks,
                    }
                    _record_adopted_pressure_zombie(sessions, key, zombie_record, driver_pid)
                continue
            role, cpu = parsed
            require(identity["pgid"] == child_pid and identity["session_id"] == child_pid, "pressure worker is not isolated in its own session")
            key = (role, cpu)
            record = {
                "pid": child_pid, "start_ticks": identity["start_ticks"],
                "pgid": identity["pgid"], "session_id": identity["session_id"],
                "parent_pid": parent_pid, "adopted_by_subreaper": adopted,
                "reaped": False, "role": role, "cpu": cpu, "nonce": expected_nonce,
                "driver_pid": driver_pid, "driver_start_ticks": driver_start_ticks,
            }
            previous = sessions.get(key)
            if previous is not None:
                same_process = all(previous.get(name) == record[name] for name in ("pid", "start_ticks", "pgid", "session_id", "role", "cpu", "nonce"))
                parent_transition = previous["parent_pid"] == driver_pid and adopted and parent_pid == os.getpid()
                require(same_process and (previous["parent_pid"] == parent_pid or parent_transition), "pressure worker role was rebound to a different process identity")
                if parent_transition:
                    record["reaped"] = previous.get("reaped", False)
                    sessions[key] = record
            else:
                sessions[key] = record


def _expected_pressure_worker_keys(schedule: dict[str, Any]) -> set[tuple[str, int | None]]:
    return {("cpu", cpu) for cpu in schedule["pressure_cpu_affinity"]} | {("disk", None), ("loopback", None)}


def _pressure_worker_inventory_complete(
    sessions: dict[tuple[str, int | None], dict[str, Any]], schedule: dict[str, Any],
) -> bool:
    expected = _expected_pressure_worker_keys(schedule)
    if any(record.get("unknown_adopted_zombie") for record in sessions.values()):
        return False
    worker_keys = set(sessions)
    return worker_keys == expected


def _record_adopted_pressure_zombie(
    sessions: dict[tuple[str, int | None], dict[str, Any]],
    key: tuple[str, int | None], record: dict[str, Any], driver_pid: int,
) -> None:
    """Record a zombie idempotently while rejecting role/PID rebinding."""
    for other_key, previous in sessions.items():
        if other_key != key and previous.get("pid") == record["pid"]:
            raise SoakReadbackError("adopted pressure zombie PID conflicts with an existing worker role")
    previous = sessions.get(key)
    if previous is None:
        sessions[key] = record
        return
    same_identity = all(
        previous.get(field) == record.get(field)
        for field in (
            "pid", "start_ticks", "pgid", "session_id", "role", "cpu", "nonce",
            "driver_pid", "driver_start_ticks",
        )
    ) and previous.get("unknown_adopted_zombie", False) == record.get("unknown_adopted_zombie", False)
    parent_same = previous.get("parent_pid") == record["parent_pid"]
    parent_transition = previous.get("parent_pid") == driver_pid and record["parent_pid"] == os.getpid()
    require(
        same_identity and (parent_same or parent_transition),
        "adopted pressure zombie identity conflicts with its prior capture",
    )
    record["reaped"] = previous.get("reaped", False)
    sessions[key] = record


def _same_pressure_worker(record: dict[str, Any]) -> dict[str, Any] | None:
    if record.get("reaped"):
        return None
    observed = _proc_process_identity(record["pid"])
    if observed is None or observed["start_ticks"] != record["start_ticks"]:
        return None
    require(observed["pgid"] == record["pgid"] and observed["session_id"] == record["session_id"], "owned pressure worker changed process group/session identity")
    return observed


def _signal_owned_pressure_worker(record: dict[str, Any], signum: int) -> bool:
    observed = _same_pressure_worker(record)
    if observed is None or observed["state"] in ("Z", "X"):
        return False
    require(callable(getattr(os, "pidfd_open", None)) and callable(getattr(signal, "pidfd_send_signal", None)), "safe PID-bound pressure cleanup requires pidfd signal support")
    try:
        pidfd = os.pidfd_open(record["pid"], 0)
    except ProcessLookupError:
        return False
    try:
        rechecked = _same_pressure_worker(record)
        if rechecked is None or rechecked["state"] in ("Z", "X"):
            return False
        signal.pidfd_send_signal(pidfd, signum, None, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError as error:
        raise SoakReadbackError(f"cannot signal authenticated pressure worker {record['pid']}: {error}") from error
    finally:
        os.close(pidfd)


def _wait_pressure_workers_gone(
    sessions: dict[tuple[str, int | None], dict[str, Any]], deadline: float,
    *, resource_monitor: Any | None = None,
) -> bool:
    while time.monotonic() < deadline:
        if resource_monitor is not None:
            resource_monitor.sample("pressure_cleanup")
        _reap_adopted_pressure_workers(sessions)
        if all(_same_pressure_worker(record) is None for record in sessions.values()):
            return True
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    _reap_adopted_pressure_workers(sessions)
    return all(_same_pressure_worker(record) is None for record in sessions.values())


def _cleanup_owned_pressure_workers(
    sessions: dict[tuple[str, int | None], dict[str, Any]], term_seconds: int, kill_seconds: int,
    *, resource_monitor: Any | None = None,
) -> bool:
    if not sessions:
        return True
    for record in sessions.values():
        _signal_owned_pressure_worker(record, signal.SIGTERM)
    term_deadline = time.monotonic() + term_seconds
    if _wait_pressure_workers_gone(
            sessions, term_deadline, resource_monitor=resource_monitor):
        return True
    for record in sessions.values():
        _signal_owned_pressure_worker(record, signal.SIGKILL)
    kill_deadline = time.monotonic() + kill_seconds
    return _wait_pressure_workers_gone(
        sessions, kill_deadline, resource_monitor=resource_monitor,
    )


def _signal_owned_pressure_driver(process: subprocess.Popen[bytes], signum: int, start_ticks: int | None) -> None:
    if process.poll() is not None:
        return
    if start_ticks is not None:
        observed = _proc_process_identity(process.pid)
        require(observed is not None and observed["start_ticks"] == start_ticks, "pressure driver PID/start identity changed before cleanup")
    try:
        process.send_signal(signum)
    except ProcessLookupError:
        pass


def _load_soak_resource_monitor_owner(
    audit: dict[str, Any], budget: dict[str, Any],
) -> Any:
    source_root = Path(audit["source_root"])
    manifest = audit["source"]["manifest"]
    files = manifest["source"]["files"]
    owner_pin = exact_object(budget["binding"]["monitor_owner"], {
        "path", "raw_sha256", "mode", "size",
    }, "Source5 FixedR8 monitor-owner pin")
    require(owner_pin["path"] == "scripts/application-fixed-pair.py",
            "Soak resource monitor owner path differs from FixedR8")
    rows = [row for row in files if type(row) is dict and
            row.get("path") == owner_pin["path"]]
    require(len(rows) == 1,
            "Soak resource monitor owner is absent from the typed SourceV5 inventory")
    row = exact_object(rows[0], {"path", "kind", "mode", "sha256", "size"},
                       "Source5 FixedR8 monitor-owner inventory row")
    path = safe_child(source_root, owner_pin["path"],
                      "captured FixedR8 resource monitor owner")
    raw, actual = read_stable_bytes(path, "captured FixedR8 resource monitor owner",
                                    MAX_SOURCE_FILE_BYTES)
    info = path.lstat()
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(row["kind"] == "file" and row["sha256"] == owner_pin["raw_sha256"] == actual and
            row["mode"] == owner_pin["mode"] == mode and
            row["size"] == owner_pin["size"] == len(raw),
            "FixedR8 resource-monitor owner differs from SourceV5 and its budget pin")
    module = types.ModuleType(f"source5_soak_resource_owner_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise SoakReadbackError(
            f"captured FixedR8 resource-monitor owner cannot be compiled: {error}",
        ) from error
    for name in ("_tmpdir_usage_snapshot", "_open_tmpdir_absolute_directory",
                 "_mount_identity"):
        require(callable(getattr(module, name, None)),
                f"captured FixedR8 resource-monitor owner lacks {name}")
    return module


def _read_soak_resource_budget(
    value: object, audit: dict[str, Any], output_root: Path,
) -> tuple[dict[str, Any], dict[str, str]]:
    pin = exact_object(value, {"path", "raw_sha256", "semantic_sha256"},
                       "Source5 Soak resource-budget pin")
    path = safe_absolute_path(pin["path"], "Source5 Soak resource-budget path")
    digest(pin["raw_sha256"], "Source5 Soak resource-budget raw SHA-256")
    digest(pin["semantic_sha256"], "Source5 Soak resource-budget semantic SHA-256")
    raw, raw_sha = read_stable_bytes(path, "Source5 Soak resource budget",
                                    64 * 1024)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o600 and raw_sha == pin["raw_sha256"],
            "Source5 Soak resource budget mode/owner/raw pin differs")
    source_root = Path(audit["source_root"]).resolve(strict=True)
    require(path.resolve(strict=True) == path and
            path != source_root and source_root not in path.parents and
            path != output_root and output_root not in path.parents,
            "Source5 Soak resource budget is aliased or inside immutable/job output")
    try:
        budget = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise SoakReadbackError(f"Source5 Soak resource budget is invalid JSON: {error}") from error
    budget = exact_object(budget, {
        "schema", "binding", "layout", "schedule", "ceilings",
        "artifact_limits", "resource_budget_sha256",
    }, "Source5 Soak resource budget")
    body = {key: item for key, item in budget.items()
            if key != "resource_budget_sha256"}
    semantic = hashlib.sha256(canonical_bytes(body)).hexdigest()
    require(raw == canonical_bytes(budget) and
            budget["schema"] == SOAK_RESOURCE_BUDGET_SCHEMA and
            budget["resource_budget_sha256"] == pin["semantic_sha256"] == semantic,
            "Source5 Soak resource budget canonical/raw/semantic digest differs")
    binding = exact_object(budget["binding"], {
        "campaign_id", "host_id", "job_sha256", "source_manifest",
        "source_tree_sha256", "parent_recipe", "build_receipt",
        "prepared_host_binding_sha256", "observed_host", "monitor_owner",
        "soak_adapter", "soak_reader",
    }, "Source5 Soak resource budget binding")
    source_ref = audit["source"]
    source_manifest = source_ref["manifest"]
    parent_pin = budget["binding"]["parent_recipe"]
    source_pin = budget["binding"]["source_manifest"]
    pressure_recipe = source_ref["pressure_recipe"]["value"]
    pressure_schedule = source_ref["pressure_recipe"]["pressure_schedule"]
    layout = exact_object(budget["layout"], SOAK_RESOURCE_BUDGET_LAYOUT_FIELDS,
                          "Source5 Soak resource budget layout")
    schedule = exact_object(budget["schedule"],
                            SOAK_RESOURCE_BUDGET_SCHEDULE_FIELDS,
                            "Source5 Soak resource budget schedule")
    for name, value in schedule.items():
        uint(value, f"Source5 Soak resource schedule {name}", positive=True)
    ceilings = exact_object(budget["ceilings"],
                            SOAK_RESOURCE_BUDGET_CEILING_FIELDS,
                            "Source5 Soak resource budget ceilings")
    for name, value in ceilings.items():
        uint(value, f"Source5 Soak resource ceiling {name}", positive=True)
    artifact_limits = exact_object(
        budget["artifact_limits"], SOAK_RESOURCE_BUDGET_ARTIFACT_FIELDS,
        "Source5 Soak resource budget artifact limits",
    )
    for name, value in artifact_limits.items():
        uint(value, f"Source5 Soak artifact limit {name}", positive=True)
    expected_source = {
        "path": audit["recipe"]["source"]["manifest_path"],
        "raw_sha256": source_ref["source_manifest_sha256"],
        "semantic_sha256": source_ref["source_manifest_semantic_sha256"],
    }
    require(binding["campaign_id"] == audit["identity"]["campaign_id"] and
            binding["host_id"] == audit["identity"]["host_id"] and
            binding["source_manifest"] == expected_source and
            binding["source_tree_sha256"] == source_ref["source_tree_sha256"] and
            type(parent_pin) is dict and
            set(parent_pin) == {"path", "raw_sha256"} and
            Path(parent_pin["path"]).is_absolute() and
            parent_pin["raw_sha256"] == audit["recipe_sha256"],
            "Source5 Soak budget source/recipe binding differs from its captured audit")
    require(layout["output_root"] == str(output_root) and
            layout["application_tmpdir"] ==
                pressure_recipe["process"]["application_tmpdir_path"] and
            layout["pressure_scratch"] ==
                pressure_recipe["storage"]["pressure_scratch_path"] and
            layout["probe_tmpdir"] ==
                str(Path(layout["probe_capture_root"]) / "tmp") and
            schedule["production_seconds"] == 10_800 ==
                audit["duration_seconds"] and
            schedule["application_sample_interval_ms"] == SAMPLE_INTERVAL_MS and
            schedule["application_sample_tolerance_ns"] == SAMPLE_TOLERANCE_NS and
            schedule["application_sample_count"] == 108_001 and
            schedule["application_wall_timeout_seconds"] ==
                source_ref["application_supervision"]["application_wall_timeout_seconds"] and
            schedule["pressure_total_deadline_seconds"] ==
                pressure_schedule["total_deadline_seconds"] and
            schedule["authorization_effective_timeout_seconds"] > 0 and
            0 < schedule["probe_timeout_seconds"] <= 30 and
            0 < schedule["resource_monitor_interval_ms"] <=
                MAX_SOAK_RESOURCE_OWNER_POLL_NS // 1_000_000 and
            0 <= schedule["resource_monitor_tolerance_ns"] <=
                MAX_SOAK_RESOURCE_OWNER_POLL_NS and
            (schedule["resource_monitor_interval_ms"] * 1_000_000 +
             schedule["resource_monitor_tolerance_ns"]) <=
                2 * MAX_SOAK_RESOURCE_OWNER_POLL_NS and
            artifact_limits["terminal_stream_bytes"] ==
                audit["recipe"]["runtime"]["terminal_budget_bytes"] and
            artifact_limits["resource_samples_bytes"] ==
                audit["recipe"]["runtime"]["sample_budget_bytes"] and
            artifact_limits["terminal_stream_bytes"] <= MAX_TERMINAL_BYTES and
            artifact_limits["resource_samples_bytes"] <= MAX_SAMPLE_BYTES and
            all(artifact_limits[name] <= MAX_RECEIPT_BYTES for name in (
                "soak_receipt_bytes", "launch_receipt_bytes",
                "preflight_receipt_bytes", "readback_receipt_bytes",
                "pressure_run_receipt_bytes", "pressure_launch_bytes",
                "pressure_binding_bytes", "pressure_ready_bytes",
            )) and
            ceilings["maximum_monitor_stream_bytes"] <=
                MAX_SOAK_RESOURCE_MONITOR_STREAM_BYTES and
            ceilings["maximum_monitor_rows"] <= MAX_SOAK_RESOURCE_MONITOR_ROWS and
            ceilings["maximum_monitor_row_bytes"] <=
                MAX_SOAK_RESOURCE_MONITOR_ROW_BYTES and
            artifact_limits["resource_monitor_stream_bytes"] <=
                ceilings["maximum_monitor_stream_bytes"] and
            artifact_limits["owner_return_receipt_bytes"] <=
                ceilings["durable_receipt_reserve_bytes"],
            "Source5 Soak budget schedule differs from its independently derived audit")
    owner = _load_soak_resource_monitor_owner(audit, budget)
    return budget, dict(pin)


class _SoakResourceMonitor:
    """Append bounded origin samples using the SourceV5-pinned FixedR8 walker."""

    _phases = ("preflight", "probe_capture", "preflight_audit",
               "pressure_startup", "application", "pressure_cleanup",
               "postflight")

    def __init__(
        self, budget: dict[str, Any], budget_pin: dict[str, str],
        owner: Any, output_root: Path, *, resume: bool = False,
    ) -> None:
        self.budget = budget
        self.budget_pin = budget_pin
        self.owner = owner
        self.path = output_root / "source5-soak-resource-monitor.jsonl"
        self.maximum_bytes = budget["ceilings"]["maximum_monitor_stream_bytes"]
        self.maximum_rows = budget["ceilings"]["maximum_monitor_rows"]
        self.maximum_row_bytes = budget["ceilings"]["maximum_monitor_row_bytes"]
        self.interval_ns = budget["schedule"]["resource_monitor_interval_ms"] * 1_000_000
        self.gap_ns = self.interval_ns + budget["schedule"]["resource_monitor_tolerance_ns"]
        self.domains = (
            ("output", "output_root", "maximum_output_bytes", "maximum_output_inodes"),
            ("application_tmpdir", "application_tmpdir", "maximum_application_tmpdir_bytes", "maximum_application_tmpdir_inodes"),
            ("pressure_scratch", "pressure_scratch", "maximum_pressure_scratch_bytes", "maximum_pressure_scratch_inodes"),
            ("probe_capture", "probe_capture_root", "maximum_probe_output_bytes", "maximum_probe_output_inodes"),
            ("probe_tmpdir", "probe_tmpdir", "maximum_probe_tmpdir_bytes", "maximum_probe_tmpdir_inodes"),
        )
        self.identities: dict[str, tuple[int, int]] = {}
        self.expected_devices: dict[str, int] = {}
        self.last_ns: int | None = None
        self.last_phase = "preflight"
        self.row_count = 0
        self.previous_sha256 = "0" * 64
        self.prefix_hasher = hashlib.sha256()
        self.high_water: dict[str, dict[str, int]] = {}
        output_root = Path(budget["layout"]["output_root"])
        pressure_root = output_root / "pressure"
        output_roles = (
            ("stdout.log", "application_stdout_bytes"),
            ("stderr.log", "application_stderr_bytes"),
            ("time.txt", "application_timing_bytes"),
            ("soak-receipt.json", "soak_receipt_bytes"),
            ("soak-launch.json", "launch_receipt_bytes"),
            ("soak-preflight.json", "preflight_receipt_bytes"),
            ("soak-postflight.json", "postflight_receipt_bytes"),
            ("source5-soak-launch-authorization.json", "launch_authorization_bytes"),
            ("source5-soak-postflight.json", "postflight_receipt_bytes"),
            ("soak-readback.json", "readback_receipt_bytes"),
            ("source5-soak-supervisor.json", "source5_supervisor_bytes"),
            ("pressure-readback.json", "pressure_readback_bytes"),
            ("pressure-driver.stdout.log", "pressure_driver_stdout_bytes"),
            ("pressure-driver.stderr.log", "pressure_driver_stderr_bytes"),
            ("source5-soak-resource-monitor.jsonl", "resource_monitor_stream_bytes"),
            ("source5-soak-application-owner-return.json", "owner_return_receipt_bytes"),
            ("source5-soak-pressure-owner-return.json", "owner_return_receipt_bytes"),
            ("source5-soak-component.json", "component_receipt_bytes"),
            ("source5-soak-failure.json", "failure_receipt_bytes"),
            ("terminal-records.tsv", "terminal_stream_bytes"),
            ("resource-samples.tsv", "resource_samples_bytes"),
        )
        self.artifact_caps = [
            (output_root / filename, budget["artifact_limits"][limit])
            for filename, limit in output_roles
        ]
        self.artifact_caps.extend((
            (pressure_root / "run.json",
             budget["artifact_limits"]["pressure_run_receipt_bytes"]),
            (pressure_root / "events.jsonl",
             budget["artifact_limits"]["pressure_events_bytes"]),
            (pressure_root / "launch-record.json",
             budget["artifact_limits"]["pressure_launch_bytes"]),
            (pressure_root / "process-binding.json",
             budget["artifact_limits"]["pressure_binding_bytes"]),
            (pressure_root / "pressure-ready.json",
             budget["artifact_limits"]["pressure_ready_bytes"]),
        ))
        self.last_usage: dict[str, Any] = {"domains": {}, "devices": {}}
        self.failure: str | None = None
        self.fd: int | None = None
        self.final_summary: dict[str, Any] | None = None
        if resume:
            self._resume()
        else:
            self._create()

    def _write_line(self, value: dict[str, Any], *, row: bool = False) -> bool:
        raw = canonical_bytes(value)
        if row and len(raw) > self.maximum_row_bytes:
            self.failure = "resource_monitor_row_byte_bound"
            return False
        if self.path.lstat().st_size + len(raw) > self.maximum_bytes:
            self.failure = "resource_monitor_stream_byte_bound"
            return False
        require(self.fd is not None, "Soak resource monitor stream is closed")
        view = memoryview(raw)
        while view:
            written = os.write(self.fd, view)
            require(written > 0, "Soak resource monitor stream write made no progress")
            view = view[written:]
        self.prefix_hasher.update(raw)
        return True

    def _create(self) -> None:
        require(not self.path.exists() and not self.path.is_symlink(),
                "refusing to replace Source5 Soak resource-monitor stream")
        self.fd = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        owner_pin = self.budget["binding"]["monitor_owner"]
        header_body = {
            "schema": SOAK_RESOURCE_MONITOR_SCHEMA,
            "budget": self.budget_pin,
            "monitor_owner": owner_pin,
            "layout": self.budget["layout"],
            "schedule": self.budget["schedule"],
            "ceilings": self.budget["ceilings"],
            "started_monotonic_ns": time.monotonic_ns(),
        }
        header = {**header_body,
                  "header_sha256": hashlib.sha256(canonical_bytes(header_body)).hexdigest()}
        require(len(canonical_bytes(header)) <= self.maximum_row_bytes,
                "Source5 resource-monitor header exceeds its row bound")
        require(self._write_line(header),
                "Source5 Soak resource-monitor header exceeds its stream budget")
        os.fsync(self.fd)

    def _resume(self) -> None:
        require(self.path.is_file() and not self.path.is_symlink(),
                "Source5 Soak resource-monitor prefix is missing")
        header_seen = False
        previous = "0" * 64
        previous_time: int | None = None
        prior_phase = "preflight"
        row_index = 0
        pending = bytearray()

        def process_line(line: bytes) -> None:
            nonlocal header_seen, previous, previous_time, prior_phase, row_index
            require(len(line) <= self.maximum_row_bytes,
                    f"Source5 resource-monitor prefix line[{row_index}] exceeds its bound")
            try:
                row = json.loads(line)
            except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
                raise SoakReadbackError(
                    f"Source5 resource-monitor prefix line[{row_index}] is invalid: {error}",
                ) from error
            require(type(row) is dict and canonical_bytes(row) == line,
                    f"Source5 resource-monitor prefix line[{row_index}] is not canonical")
            if not header_seen:
                header_body = {key: value for key, value in row.items()
                               if key != "header_sha256"}
                require(row.get("schema") == SOAK_RESOURCE_MONITOR_SCHEMA and
                        row.get("budget") == self.budget_pin and
                        row.get("layout") == self.budget["layout"] and
                        row.get("monitor_owner") == self.budget["binding"]["monitor_owner"] and
                        row.get("header_sha256") == hashlib.sha256(
                            canonical_bytes(header_body)).hexdigest(),
                        "Source5 resource-monitor prefix header differs from its budget")
                header_seen = True
                self.prefix_hasher.update(line)
                return
            body = {key: value for key, value in row.items()
                    if key != "row_sha256"}
            require(row.get("schema") == SOAK_RESOURCE_MONITOR_ROW_SCHEMA and
                    row.get("sequence") == row_index and
                    row.get("previous_sha256") == previous and
                    row.get("row_sha256") == hashlib.sha256(
                        canonical_bytes(body)).hexdigest() and
                    row.get("phase") in self._phases and
                    self._phases.index(row["phase"]) >= self._phases.index(prior_phase),
                    f"Source5 resource-monitor prefix row[{row_index}] chain/order differs")
            monotonic_ns = row.get("monotonic_ns")
            require(type(monotonic_ns) is int and monotonic_ns > 0 and
                    (previous_time is None or
                     0 < monotonic_ns - previous_time <= self.gap_ns),
                    f"Source5 resource-monitor prefix row[{row_index}] timing differs")
            self._accumulate(row.get("domains"))
            for name, item in row["domains"].items():
                if item["inode"] is None:
                    self.expected_devices[name] = item["device"]
                elif name in self.expected_devices:
                    require(item["device"] == self.expected_devices[name],
                            f"Source5 resource-monitor {name} moved to another device")
                    self.expected_devices.pop(name, None)
                    self.identities[name] = (item["device"], item["inode"])
                elif type(item["inode"]) is int:
                    prior = self.identities.get(name)
                    identity = (item["device"], item["inode"])
                    require(prior is None or prior == identity,
                            f"Source5 resource-monitor {name} identity changed in its prefix")
                    self.identities[name] = identity
            self.last_usage = {"domains": row.get("domains", {}),
                               "devices": row.get("devices", {})}
            previous = row["row_sha256"]
            previous_time = monotonic_ns
            prior_phase = row["phase"]
            self.prefix_hasher.update(line)
            row_index += 1

        with StableInput(self.path, "Source5 resource-monitor prefix",
                         self.maximum_bytes) as stream:
            while stream.consumed < stream.size:
                block = stream.read(min(64 * 1024,
                                        stream.size - stream.consumed))
                require(bool(block),
                        "Source5 resource-monitor prefix was truncated")
                for byte in block:
                    pending.append(byte)
                    if byte == 10:
                        process_line(bytes(pending))
                        pending.clear()
                    else:
                        require(len(pending) <= self.maximum_row_bytes,
                                "Source5 resource-monitor prefix row exceeds its cap")
            require(not pending and header_seen,
                    "Source5 resource-monitor prefix has a partial or missing header")
            stream.finish()
        self.row_count = row_index
        self.previous_sha256 = previous
        self.last_ns = previous_time
        self.last_phase = prior_phase
        self.fd = os.open(self.path, os.O_WRONLY | os.O_APPEND |
                          getattr(os, "O_CLOEXEC", 0) |
                          getattr(os, "O_NOFOLLOW", 0))

    def _accumulate(self, domains: object) -> None:
        require(type(domains) is dict and
                set(domains) == {row[0] for row in self.domains},
                "Source5 resource-monitor domain map is incomplete")
        for name, value in domains.items():
            require(type(value) is dict and
                    set(value) == {"path", "device", "inode", "bytes_used",
                                   "inode_count", "available_bytes",
                                   "available_inodes", "bytes_limit", "inode_limit"},
                    f"Source5 resource-monitor {name} row is malformed")
            high = self.high_water.setdefault(name, {"bytes": 0, "inodes": 0})
            high["bytes"] = max(high["bytes"], value["bytes_used"])
            high["inodes"] = max(high["inodes"], value["inode_count"])

    def _sample_domains(self) -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
        layout = self.budget["layout"]
        ceilings = self.budget["ceilings"]
        measured: dict[str, Any] = {}
        devices: dict[int, dict[str, Any]] = {}
        for name, path_field, byte_field, inode_field in self.domains:
            path = Path(layout[path_field])
            byte_limit = ceilings[byte_field]
            inode_limit = ceilings[inode_field]
            try:
                named_root = path.lstat()
            except FileNotFoundError:
                named_root = None
            absent_probe = (name in {"probe_capture", "probe_tmpdir"} and
                            named_root is None)
            if absent_probe and name in self.identities:
                raise SoakReadbackError(
                    f"Source5 resource-monitor {name} root disappeared or was replaced",
                )
            if named_root is not None:
                require(stat.S_ISDIR(named_root.st_mode) and
                        not stat.S_ISLNK(named_root.st_mode),
                        f"Source5 resource-monitor {name} root is linked or not a directory")
            stat_path = path
            if absent_probe:
                stat_path = path.parent
                while not stat_path.exists() and stat_path.parent != stat_path:
                    stat_path = stat_path.parent
                fd = self.owner._open_tmpdir_absolute_directory(stat_path)
                root_info = os.fstat(fd)
                root_identity = (root_info.st_dev, root_info.st_ino)
                usage = {"bytes_used": 0, "inode_count": 0}
                placeholder = True
                expected_device = self.expected_devices.get(name)
                if expected_device is not None and root_info.st_dev != expected_device:
                    os.close(fd)
                    raise SoakReadbackError(
                        f"Source5 resource-monitor {name} placeholder changed device",
                    )
            else:
                fd = self.owner._open_tmpdir_absolute_directory(path)
                root_info = os.fstat(fd)
                if ((named_root.st_dev, named_root.st_ino,
                     named_root.st_uid, named_root.st_mode) !=
                    (root_info.st_dev, root_info.st_ino,
                     root_info.st_uid, root_info.st_mode)):
                    os.close(fd)
                    raise SoakReadbackError(
                        f"Source5 resource-monitor {name} root changed between stat and open",
                    )
                root_identity = (root_info.st_dev, root_info.st_ino)
                placeholder = False
                expected_device = self.expected_devices.get(name)
                if expected_device is not None and root_info.st_dev != expected_device:
                    os.close(fd)
                    raise SoakReadbackError(
                        f"Source5 resource-monitor {name} capture root changed device",
                    )
                self.expected_devices.pop(name, None)
                previous = self.identities.get(name)
                if previous is not None and previous != root_identity:
                    os.close(fd)
                    raise SoakReadbackError(
                        f"Source5 resource-monitor {name} root identity changed",
                    )
                self.identities[name] = root_identity
                try:
                    usage = self.owner._tmpdir_usage_snapshot(
                        path, byte_limit, inode_limit, root_identity,
                        allow_descendant_enoent=True,
                    )
                except BaseException:
                    os.close(fd)
                    raise
            try:
                mount = self.owner._mount_identity(stat_path if placeholder else path)
                fs = os.fstatvfs(fd)
                available_bytes = fs.f_bavail * fs.f_frsize
                available_inodes = fs.f_favail
                require(mount["device"] == root_info.st_dev,
                        f"Source5 resource-monitor {name} device changed")
                if not placeholder:
                    expected_identity = self.identities.get(name)
                    if expected_identity is not None and expected_identity != root_identity:
                        raise SoakReadbackError(
                            f"Source5 resource-monitor {name} root identity changed",
                        )
                    self.identities[name] = root_identity
                else:
                    self.expected_devices[name] = root_info.st_dev
                item = {
                    "path": str(path), "device": root_info.st_dev,
                    "inode": None if placeholder else root_info.st_ino,
                    "bytes_used": usage["bytes_used"],
                    "inode_count": usage["inode_count"],
                    "available_bytes": available_bytes,
                    "available_inodes": available_inodes,
                    "bytes_limit": byte_limit, "inode_limit": inode_limit,
                }
                require(item["bytes_used"] <= byte_limit and
                        item["inode_count"] <= inode_limit,
                        f"Source5 resource-monitor {name} ceiling exceeded")
                measured[name] = item
                device = devices.setdefault(root_info.st_dev, {
                    "available_bytes": available_bytes,
                    "available_inodes": available_inodes,
                    "roots": [],
                })
                device["available_bytes"] = min(device["available_bytes"],
                                                available_bytes)
                device["available_inodes"] = min(device["available_inodes"],
                                                 available_inodes)
                device["roots"].append(name)
            finally:
                os.close(fd)
        allowance_by_device: dict[int, dict[str, int]] = {}
        for device, device_row in devices.items():
            roots = [next(spec for spec in self.domains if spec[0] == name)
                     for name in device_row["roots"]]
            roots.sort(key=lambda spec: (len(Path(layout[spec[1]]).parts),
                                         layout[spec[1]]))
            top_level: list[Path] = []
            allowance_bytes = 0
            allowance_inodes = 0
            for name, path_field, byte_field, inode_field in roots:
                path = Path(layout[path_field])
                if any(path == parent or parent in path.parents
                       for parent in top_level):
                    continue
                top_level.append(path)
                allowance_bytes += max(
                    0, ceilings[byte_field] - measured[name]["bytes_used"],
                )
                allowance_inodes += max(
                    0, ceilings[inode_field] - measured[name]["inode_count"],
                )
            required_bytes = (ceilings["minimum_free_bytes"] +
                              allowance_bytes +
                              ceilings["durable_receipt_reserve_bytes"])
            required_inodes = (ceilings["minimum_free_inodes"] +
                               allowance_inodes +
                               ceilings["durable_receipt_reserve_inodes"])
            require(device_row["available_bytes"] >= required_bytes and
                    device_row["available_inodes"] >= required_inodes,
                    f"Source5 resource-monitor device {device} fell below its frozen free-space/reserve floor")
            allowance_by_device[device] = {
                "remaining_bytes": allowance_bytes,
                "remaining_inodes": allowance_inodes,
                "required_bytes": required_bytes,
                "required_inodes": required_inodes,
            }
        device_projection = {
            str(device): {
                "available_bytes": row["available_bytes"],
                "available_inodes": row["available_inodes"],
                **allowance_by_device[device],
            }
            for device, row in devices.items()
        }
        return measured, device_projection

    def _check_declared_artifact_caps(self) -> None:
        """Enforce the caller's closed writable-role limits during live ownership."""
        for path, maximum in self.artifact_caps:
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise SoakReadbackError(
                    f"cannot inspect bounded Soak artifact {path.name}: {error}",
                ) from error
            require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                    info.st_nlink == 1 and info.st_uid == os.getuid() and
                    0 <= info.st_size <= maximum,
                    f"Source5 bounded Soak artifact role exceeded its frozen limit: {path.name}")

    def sample(self, phase: str, *, force: bool = False) -> bool:
        require(phase in self._phases,
                "Source5 resource-monitor phase is outside the frozen schedule")
        phase_index = self._phases.index(phase)
        require(phase_index >= self._phases.index(self.last_phase),
                "Source5 resource-monitor phase order moved backwards")
        now = time.monotonic_ns()
        if self.last_ns is not None and not force and now - self.last_ns < self.interval_ns:
            return self.failure is not None
        if self.last_ns is not None and now - self.last_ns > self.gap_ns:
            self.failure = self.failure or "resource_monitor_gap_exceeded"
        try:
            domains, devices = self._sample_domains()
            self._check_declared_artifact_caps()
        except BaseException as error:
            domains, devices = {}, {}
            self.failure = self.failure or (
                f"resource_monitor_scan:{type(error).__name__}:{error}"
            )[:4096]
        self.last_usage = {"domains": domains, "devices": devices}
        row_body = {
            "schema": SOAK_RESOURCE_MONITOR_ROW_SCHEMA,
            "sequence": self.row_count,
            "phase": phase,
            "monotonic_ns": now,
            "previous_sha256": self.previous_sha256,
            "domains": domains,
            "devices": devices,
            "failure": self.failure,
        }
        row = {**row_body,
               "row_sha256": hashlib.sha256(canonical_bytes(row_body)).hexdigest()}
        if self.row_count >= self.maximum_rows or not self._write_line(row, row=True):
            self.failure = self.failure or "resource_monitor_row_or_stream_bound"
            return True
        self.row_count += 1
        self.previous_sha256 = row["row_sha256"]
        self.last_ns = now
        self.last_phase = phase
        self._accumulate(domains)
        if self.fd is not None:
            os.fsync(self.fd)
        return self.failure is not None

    def close_pending(self) -> None:
        if self.fd is not None:
            os.fsync(self.fd)
            os.close(self.fd)
            self.fd = None

    def pending_summary(self) -> dict[str, Any]:
        return {
            "schema": "allocatbelt.application-source5-soak-resource-monitor-prefix.v1",
            "path": str(self.path),
            "budget": self.budget_pin,
            "row_count": self.row_count,
            "prefix_sha256": self.prefix_hasher.hexdigest(),
            "last_row_sha256": self.previous_sha256,
            "high_water": self.high_water,
            "failure": self.failure,
        }

    def finish(self, final_usage: dict[str, Any]) -> dict[str, Any]:
        require(self.fd is not None,
                "Source5 resource-monitor stream is already finalized")
        prefix_sha = self.prefix_hasher.hexdigest()
        footer_body = {
            "schema": SOAK_RESOURCE_MONITOR_FOOTER_SCHEMA,
            "budget": self.budget_pin,
            "row_count": self.row_count,
            "previous_sha256": self.previous_sha256,
            "prefix_sha256": prefix_sha,
            "high_water": self.high_water,
            "final_usage": final_usage,
            "failure": self.failure,
            "ended_monotonic_ns": time.monotonic_ns(),
        }
        footer = {**footer_body,
                  "footer_sha256": hashlib.sha256(canonical_bytes(footer_body)).hexdigest()}
        require(len(canonical_bytes(footer)) <= self.maximum_row_bytes,
                "Source5 resource-monitor footer exceeds its row bound")
        require(self._write_line(footer),
                "Source5 resource-monitor footer exceeds its stream budget")
        os.fsync(self.fd)
        os.close(self.fd)
        self.fd = None
        self.final_summary = {
            "schema": "allocatbelt.application-source5-soak-resource-monitor-summary.v1",
            "budget": self.budget_pin,
            "stream": {
                "path": str(self.path),
                "raw_sha256": sha256_file(
                    self.path, "Source5 resource-monitor stream",
                    self.maximum_bytes,
                ),
            },
            "row_count": self.row_count,
            "high_water": self.high_water,
            "final_usage": final_usage,
            "failure": self.failure,
            "prefix_sha256": prefix_sha,
        }
        return self.final_summary


def _stop_pressure_session(
    process: subprocess.Popen[bytes], driver_start_ticks: int | None, driver_path: Path,
    recipe_sha256: str, schedule: dict[str, Any], sessions: dict[tuple[str, int | None], dict[str, Any]],
    expected_nonce: str | None = None,
    excluded_child_identities: set[tuple[int, int]] | None = None,
    ownership_event_path: Path | None = None,
    resource_monitor: Any | None = None,
) -> None:
    _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
    if process.poll() is not None:
        require(
            _cleanup_owned_pressure_workers(
                sessions, schedule["term_deadline_seconds"],
                schedule["kill_deadline_seconds"],
                resource_monitor=resource_monitor,
            ),
            "authenticated pressure workers remained alive after the pressure driver exited",
        )
        if _PRESSURE_SUBREAPER_ACTIVE:
            require(
                _pressure_worker_inventory_complete(sessions, schedule),
                "parent-owned pressure supervision cannot establish a complete worker inventory after driver exit",
            )
        return
    _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
    _signal_owned_pressure_driver(process, signal.SIGTERM, driver_start_ticks)
    cleanup_deadline = time.monotonic() + schedule["term_deadline_seconds"] + schedule["kill_deadline_seconds"] + 5
    while process.poll() is None and time.monotonic() < cleanup_deadline:
        if resource_monitor is not None:
            resource_monitor.sample("pressure_cleanup")
        _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
        try:
            process.wait(timeout=min(0.1, max(0.01, cleanup_deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
    if process.poll() is None:
        if resource_monitor is not None:
            resource_monitor.sample("pressure_cleanup", force=True)
        _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
        cleaned = _cleanup_owned_pressure_workers(
            sessions, schedule["term_deadline_seconds"],
            schedule["kill_deadline_seconds"],
            resource_monitor=resource_monitor,
        )
        _signal_owned_pressure_driver(process, signal.SIGKILL, driver_start_ticks)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as error:
            raise SoakReadbackError("pressure driver remained alive after its frozen cleanup budgets") from error
        require(cleaned, "authenticated pressure workers remained alive after their frozen TERM/KILL budgets")
    else:
        if resource_monitor is not None:
            resource_monitor.sample("pressure_cleanup", force=True)
        _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
        require(
            _cleanup_owned_pressure_workers(
                sessions, schedule["term_deadline_seconds"],
                schedule["kill_deadline_seconds"],
                resource_monitor=resource_monitor,
            ),
            "authenticated pressure workers remained alive after the driver exited",
        )
        if _PRESSURE_SUBREAPER_ACTIVE:
            require(
                _pressure_worker_inventory_complete(sessions, schedule),
                "parent-owned pressure supervision cannot establish a complete worker inventory after driver exit",
            )


def _wait_pressure_ready(
    process: subprocess.Popen[bytes], ready_path: Path, pressure_recipe: dict[str, Any],
    expected_recipe_sha: str, expected_condition_sha: str,
    capture_workers: Any | None = None, stderr_path: Path | None = None,
    interrupt_check: Any | None = None,
    resource_monitor: Any | None = None,
) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + pressure_recipe["schedule"]["startup_deadline_seconds"]
    last_error: BaseException | None = None
    diagnostic_stderr = stderr_path or ready_path.parent / "pressure-stderr.log"
    while time.monotonic() < deadline:
        if resource_monitor is not None and resource_monitor.sample("pressure_startup"):
            raise SoakReadbackError(
                "Source5 resource monitor exceeded its bound during pressure startup",
            )
        if interrupt_check is not None:
            interrupt_check()
        if capture_workers is not None:
            capture_workers()
        if process.poll() is not None:
            raise SoakReadbackError(f"pressure driver exited {process.returncode} before readiness; stderr tail: {_tail_text(diagnostic_stderr)}")
        if ready_path.exists():
            try:
                checked = _read_pressure_ready(ready_path, pressure_recipe, expected_recipe_sha, expected_condition_sha)
                if capture_workers is not None:
                    capture_workers()
                return checked
            except (OSError, SoakReadbackError, ValueError, TypeError) as error:
                if ready_path.is_symlink() or ready_path.is_dir():
                    raise
                last_error = error
        time.sleep(0.02)
    reason = f"; last marker error: {last_error}" if last_error is not None else ""
    raise SoakReadbackError(f"pressure did not produce an independently measured, recipe-pinned readiness marker before its startup deadline{reason}; stderr tail: {_tail_text(diagnostic_stderr)}")


def _run_pressure_supervisor_impl(
    args: argparse.Namespace, audit: dict[str, Any], preflight: dict[str, Any],
    output_dir: Path, *, resource_monitor: _SoakResourceMonitor | None = None,
) -> int:
    descriptor = audit["launch_descriptor"]
    require(descriptor.get("execution_kind") in ("normal_app", "timed_soak"), "pressure supervisor requires an explicit normal_app or timed_soak descriptor")
    supervision_state = descriptor.setdefault("_supervision_state", {})
    supervision_state.update({
        "status": None,
        "interrupted": False,
        "pressure_cleanup": "not_started",
        "application_cleanup": "not_started",
        "application_binding": None,
        "application_attestation": None,
        "pressure_ready_sha256": None,
        "pressure_proof": None,
        "details": None,
    })
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    require(command == descriptor["argv"], "actual external-pressure candidate command/argv differs from the preflighted launch descriptor")
    require(descriptor["launch_enabled"] is True, "external-pressure launch descriptor is disabled")
    expected_app_timeout = audit["source"]["application_supervision"]["application_wall_timeout_seconds"]
    require(args.timeout_seconds == expected_app_timeout == descriptor["application_wall_timeout_seconds"], "external-pressure app timeout differs from the independently derived complete wall bound")
    require(args.term_grace_seconds == descriptor["term_grace_seconds"], "pressure APP TERM grace differs from its explicit descriptor")
    pressure_info = audit["source"]["pressure_recipe"]
    pressure_recipe = pressure_info["value"]
    pressure_recipe_path = Path(descriptor["pressure_recipe_path"])
    pressure_recipe_value, pressure_recipe_raw_sha, pressure_recipe_raw = read_json(pressure_recipe_path, "frozen pressure recipe", MAX_RECIPE_BYTES)
    require(pressure_recipe_raw == canonical_bytes(pressure_recipe_value) and pressure_recipe_raw_sha == audit["recipe"]["pressure"]["recipe"]["raw_sha256"], "frozen pressure recipe raw bytes changed after parent preflight")
    require(pressure_recipe_value == pressure_recipe and pressure_recipe_value["recipe_sha256"] == descriptor["pressure_recipe_sha256"], "pressure recipe content differs from its full captured-validator result")
    driver_path = Path(descriptor["pressure_driver_path"])
    require(sha256_file(driver_path, "SourceV5 pressure driver", MAX_SOURCE_FILE_BYTES) == descriptor["pressure_driver_sha256"], "SourceV5 pressure driver changed after preflight")
    pressure_dir = Path(descriptor["pressure_output_dir"])
    pressure_dir.mkdir(mode=0o700)
    os.chmod(pressure_dir, 0o700)
    pressure_stdout = Path(descriptor["pressure_stdout_path"])
    pressure_stderr = Path(descriptor["pressure_stderr_path"])
    signal_handlers, supervisor_signal = _install_external_supervisor_signal_handlers()
    pressure_out_fd = -1
    pressure_err_fd = -1
    pressure_process: subprocess.Popen[bytes] | None = None
    pressure_start_ticks: int | None = None
    pressure_started_at: float | None = None
    pressure_started_monotonic_ns: int | None = None
    pressure_returned_monotonic_ns: int | None = None
    pressure_cleanup_ended_monotonic_ns: int | None = None
    application_identity: tuple[int, int] | None = None
    pressure_workers: dict[tuple[str, int | None], dict[str, Any]] = {}
    pressure_stopped = False
    application_cleanup = "not_started"
    pressure_cleanup = "not_started"
    subreaper_previous: bool | None = None
    try:
        pressure_out_fd = os.open(pressure_stdout, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
        pressure_err_fd = os.open(pressure_stderr, os.O_WRONLY | os.O_CREAT | getattr(os, "O_EXCL", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)

        def check_supervisor_interruption() -> None:
            signum = supervisor_signal["received_signal"]
            if signum is not None:
                raise SoakReadbackError(f"external-pressure soak supervisor received signal {signum}")

        def record_inner_signal(signum: int) -> None:
            if supervisor_signal["received_signal"] is None:
                supervisor_signal["received_signal"] = signum

        def record_application_cleanup(result: dict[str, Any]) -> None:
            nonlocal application_cleanup
            exact_object(result, {
                "schema", "status", "pid", "return_code", "received_signal", "cleanup_error",
            }, "application cleanup result")
            require(result["schema"] == "allocatbelt.application-soak-process-cleanup.v1", "application cleanup result schema differs")
            require(result["status"] in ("verified", "failed"), "application cleanup result status differs")
            application_cleanup = result["status"]
            supervision_state["application_cleanup"] = result
            callback = descriptor.get("_on_cleanup")
            if callback is not None:
                callback(result)

        def record_pressure_owner_return() -> None:
            nonlocal pressure_returned_monotonic_ns
            if resource_monitor is None or pressure_process is None:
                return
            return_code = pressure_process.poll()
            if return_code is None or supervision_state.get("pressure_owner_result_pin"):
                return
            pressure_returned_monotonic_ns = pressure_returned_monotonic_ns or \
                time.monotonic_ns()
            owner_return = {
                "schema": "allocatbelt.application-source5-soak-pressure-owner-return.v2",
                "pid": pressure_process.pid,
                "start_ticks": pressure_start_ticks,
                "return_code": return_code,
                "started_monotonic_ns": pressure_started_monotonic_ns,
                "returned_monotonic_ns": pressure_returned_monotonic_ns,
            }
            supervision_state["pressure_owner_result_pin"] = _write_exclusive_json(
                output_dir / "source5-soak-pressure-owner-return.json",
                owner_return,
            )

        def finish_external_interruption(signum: int) -> int:
            callback = descriptor.get("_on_interrupted")
            if callback is None:
                status = _write_external_supervisor_interruption(
                    output_dir, audit, signum, pressure_process, pressure_start_ticks,
                    application_cleanup, pressure_cleanup,
                )
            else:
                status = callback({
                    "signal": signum,
                    "pressure_pid": None if pressure_process is None else pressure_process.pid,
                    "pressure_start_ticks": pressure_start_ticks,
                    "pressure_return_code": None if pressure_process is None else pressure_process.poll(),
                    "application_cleanup": application_cleanup,
                    "pressure_cleanup": pressure_cleanup,
                    "workers": list(pressure_workers.values()),
                })
            supervision_state.update({
                "status": status,
                "interrupted": True,
                "pressure_cleanup": pressure_cleanup,
                "application_cleanup_status": application_cleanup,
                "received_signal": signum,
            })
            if application_cleanup not in ("not_started", "verified") or pressure_cleanup not in ("not_started", "verified"):
                raise SoakReadbackError(
                    f"external signal {signum} was recorded, but cleanup is {application_cleanup=} {pressure_cleanup=}"
                )
            return status

        def stop_pressure_session() -> None:
            nonlocal pressure_stopped, pressure_cleanup
            nonlocal pressure_returned_monotonic_ns
            nonlocal pressure_cleanup_ended_monotonic_ns
            if pressure_process is None or pressure_stopped:
                return
            pressure_cleanup = "unverified"
            supervision_state["pressure_cleanup"] = pressure_cleanup
            try:
                if resource_monitor is not None:
                    resource_monitor.sample("pressure_cleanup", force=True)
                stop_kwargs = {
                    "excluded_child_identities": (
                        set() if application_identity is None else
                        {application_identity}
                    ),
                    "ownership_event_path": pressure_dir / "events.jsonl",
                }
                if resource_monitor is not None:
                    stop_kwargs["resource_monitor"] = resource_monitor
                _stop_pressure_session(
                    pressure_process, pressure_start_ticks, driver_path,
                    descriptor["pressure_recipe_sha256"], pressure_recipe["schedule"], pressure_workers,
                    audit["identity"]["nonce"], **stop_kwargs,
                )
            except BaseException:
                pressure_cleanup = "failed"
                supervision_state["pressure_cleanup"] = pressure_cleanup
                if resource_monitor is not None:
                    record_pressure_owner_return()
                pressure_stopped = True
                raise
            finally:
                if resource_monitor is not None:
                    resource_monitor.sample("pressure_cleanup", force=True)
            pressure_returned_monotonic_ns = pressure_returned_monotonic_ns or time.monotonic_ns()
            pressure_cleanup_ended_monotonic_ns = time.monotonic_ns()
            pressure_cleanup = "verified"
            supervision_state["pressure_cleanup"] = pressure_cleanup
            supervision_state["pressure_driver"] = {
                "pid": pressure_process.pid,
                "start_ticks": pressure_start_ticks,
                "return_code": pressure_process.returncode,
            }
            supervision_state["pressure_worker_sessions"] = list(pressure_workers.values())
            if resource_monitor is not None:
                record_pressure_owner_return()
            pressure_stopped = True

        pressure_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"}
        pressure_command = [
            sys.executable, str(driver_path), "run",
            "--recipe", str(pressure_recipe_path),
            "--expected-recipe-sha256", descriptor["pressure_recipe_sha256"],
            "--launch-record", descriptor["pressure_launch_path"],
            "--output-dir", descriptor["pressure_output_dir"],
            "--ready-file", descriptor["pressure_ready_path"],
        ]
        subreaper_previous = _set_child_subreaper(True)
        if resource_monitor is not None and resource_monitor.sample(
                "pressure_startup", force=True):
            raise SoakReadbackError(
                "Source5 resource-budget monitor stopped before pressure driver Popen",
            )
        pressure_process = subprocess.Popen(
            pressure_command,
            cwd=Path(audit["source_root"]),
            env=pressure_env,
            stdin=subprocess.DEVNULL,
            stdout=pressure_out_fd,
            stderr=pressure_err_fd,
            close_fds=True,
            start_new_session=True,
        )
        pressure_cleanup = "unverified"
        pressure_started_at = time.monotonic()
        pressure_started_monotonic_ns = time.monotonic_ns()
        try:
            pressure_start_ticks = _proc_start_ticks(pressure_process.pid)
        except SoakReadbackError as error:
            # The worker command line embeds this exact parent lifetime. Do not
            # treat a Popen child whose PID/start identity was never captured as
            # eligible for the normal readiness/launch path.
            raise SoakReadbackError("pressure driver PID/start identity was not captured immediately after Popen") from error
        check_supervisor_interruption()
        def capture_pressure_workers() -> None:
            if pressure_process is not None and _PRESSURE_SUBREAPER_ACTIVE:
                _capture_pressure_worker_sessions(
                    pressure_process.pid, pressure_start_ticks, driver_path,
                    descriptor["pressure_recipe_sha256"], pressure_recipe["schedule"], pressure_workers,
                    audit["identity"]["nonce"],
                    excluded_child_identities=set() if application_identity is None else {application_identity},
                    ownership_event_path=pressure_dir / "events.jsonl",
                )

        os.close(pressure_out_fd)
        pressure_out_fd = -1
        os.close(pressure_err_fd)
        pressure_err_fd = -1

        readiness_kwargs = {
            "capture_workers": capture_pressure_workers,
            "stderr_path": pressure_stderr,
            "interrupt_check": check_supervisor_interruption,
        }
        if resource_monitor is not None:
            readiness_kwargs["resource_monitor"] = resource_monitor
        _ready, ready_sha = _wait_pressure_ready(
            pressure_process, Path(descriptor["pressure_ready_path"]), pressure_recipe,
            descriptor["pressure_recipe_sha256"], descriptor["pressure_condition_sha256"],
            **readiness_kwargs,
        )
        check_supervisor_interruption()
        if resource_monitor is not None and resource_monitor.sample(
                "pressure_startup", force=True):
            stop_pressure_session()
            raise SoakReadbackError(
                "Source5 resource monitor refused after pressure readiness and before APP Popen",
            )
        _require_source_v5_pressure_prefix(pressure_dir, pressure_info, ready_sha)
        require(set(pressure_workers) == _expected_pressure_worker_keys(pressure_recipe["schedule"]), "pressure readiness arrived before every isolated worker session was captured")

        def bind_started_process(
            process: subprocess.Popen[bytes], executable_path: Path, executable_sha: str,
            _executable_info: os.stat_result, cpu_ids: set[int], cwd: Path | None, environment: dict[str, str] | None,
        ) -> None:
            nonlocal application_identity, application_cleanup
            application_cleanup = "unverified"
            check_supervisor_interruption()
            app_stat = _proc_process_identity(process.pid)
            require(app_stat is not None and app_stat["state"] not in ("Z", "X"), "external soak child exited before its PID/start identity could be bound")
            application_identity = (process.pid, app_stat["start_ticks"])
            require(cwd is not None and environment is not None, "external soak launch omitted its frozen cwd/environment")
            binding = _make_pressure_launch_binding(
                process, executable_path, executable_sha, cpu_ids, cwd, environment, pressure_recipe,
            )
            attestation = _make_application_launch_attestation(
                process, descriptor["argv"], descriptor["environment"],
                descriptor["execution_kind"], binding,
            )
            actual_binding_sha = _atomic_json_publish(Path(descriptor["pressure_launch_path"]), binding)
            require(actual_binding_sha == hashlib.sha256(canonical_bytes(binding)).hexdigest(), "atomically published pressure launch record digest differs")
            supervision_state["application_binding"] = binding
            supervision_state["application_binding_sha256"] = actual_binding_sha
            supervision_state["application_attestation"] = attestation
            if resource_monitor is not None:
                resource_monitor.sample("application", force=True)
            callback = descriptor.get("_on_started")
            if callback is not None:
                callback(attestation)

        def monitor_pressure(app_process: subprocess.Popen[bytes]) -> None:
            check_supervisor_interruption()
            capture_pressure_workers()
            if pressure_process is not None:
                _require_pressure_live_while_application_runs(pressure_process, app_process, pressure_stderr)

        launch_kwargs = {
            "environment": descriptor["environment"],
            "cwd": Path(descriptor["cwd"]),
            "expected_executable_sha256": descriptor["binary_sha256"],
            "return_details": True,
            "on_started": bind_started_process,
            "monitor": monitor_pressure,
            "on_signal": record_inner_signal,
            "on_cleanup": record_application_cleanup,
            "timeout_from_before_popen": True,
            "timeout_includes_cleanup": True,
        }
        if resource_monitor is not None:
            first_owner_gate = [True]

            def monitor_owned_application() -> bool:
                if first_owner_gate[0]:
                    first_owner_gate[0] = False
                    return resource_monitor.sample("pressure_startup", force=True)
                return resource_monitor.sample("application")

            launch_kwargs["resource_budget_monitor"] = monitor_owned_application
        details = launch_process(
            command,
            args.cpu_set,
            Path(descriptor["stdout_path"]),
            Path(descriptor["stderr_path"]),
            Path(descriptor["timing_path"]),
            args.timeout_seconds,
            args.term_grace_seconds,
            tuple((Path(path), maximum) for path, maximum in descriptor["monitored_files"]),
            **launch_kwargs,
        )
        require(type(details) is dict, "external-pressure soak supervisor omitted its parent process receipt")
        if resource_monitor is not None:
            supervision_state["application_owner_result_pin"] = _write_exclusive_json(
                output_dir / "source5-soak-application-owner-return.json", details,
            )
        if resource_monitor is not None and resource_monitor.sample(
                "application", force=True):
            details["resource_budget_exceeded"] = True
            details["resource_monitor_error"] = resource_monitor.failure or \
                "resource monitor refused at APP owner return"
            details["status"] = 125
        if supervisor_signal["received_signal"] is not None:
            signum = supervisor_signal["received_signal"]
            record_inner_signal(signum)
            details["received_signal"] = signum
            if not details["timed_out"] and not details["artifact_budget_exceeded"]:
                details["status"] = 128 + signum
        supervision_state["details"] = details
        supervision_state["status"] = details["status"]
        require(application_cleanup == "verified", "application process cleanup did not complete successfully")
        if descriptor.get("persist_legacy_receipt", True):
            launch_receipt = _launch_receipt_value(details, audit, preflight)
            launch_receipt_sha = _write_exclusive_json(output_dir / "soak-launch.json", launch_receipt)
            supervision_state["legacy_launch_receipt_sha256"] = launch_receipt_sha
        if supervisor_signal["received_signal"] is not None:
            stop_pressure_session()
            return finish_external_interruption(supervisor_signal["received_signal"])
        if details["status"] != 0:
            stop_pressure_session()
            check_supervisor_interruption()
            return details["status"]
        else:
            require(pressure_started_at is not None, "pressure driver start time was not captured")
            pressure_deadline = pressure_started_at + pressure_recipe["schedule"]["startup_deadline_seconds"] + pressure_recipe["schedule"]["total_deadline_seconds"] + 5
            monitor_stopped_after_app = False
            while pressure_process.poll() is None and time.monotonic() < pressure_deadline:
                check_supervisor_interruption()
                if resource_monitor is not None and resource_monitor.sample("application"):
                    monitor_stopped_after_app = True
                    break
                capture_pressure_workers()
                try:
                    pressure_process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
            if pressure_process.poll() is not None:
                pressure_returned_monotonic_ns = time.monotonic_ns()
                record_pressure_owner_return()
            if monitor_stopped_after_app:
                details["resource_budget_exceeded"] = True
                details["resource_monitor_error"] = resource_monitor.failure or \
                    "resource monitor refused during post-APP pressure supervision"
                details["status"] = 125
                supervision_state["details"] = details
                supervision_state["status"] = 125
                stop_pressure_session()
                return 125
            if pressure_process.poll() is None:
                stop_pressure_session()
                raise SoakReadbackError("pressure driver did not finish within its frozen process deadline")
            capture_pressure_workers()
        check_supervisor_interruption()
        if pressure_process.poll() == 0:
            if resource_monitor is not None and resource_monitor.sample(
                    "pressure_cleanup", force=True):
                details["resource_budget_exceeded"] = True
                details["resource_monitor_error"] = resource_monitor.failure or \
                    "resource monitor refused at pressure-owner return"
                details["status"] = 125
                supervision_state["details"] = details
                supervision_state["status"] = 125
                stop_pressure_session()
                return 125
            require(set(pressure_workers) == _expected_pressure_worker_keys(pressure_recipe["schedule"]), "pressure driver exited without every frozen worker session having been captured")
            require(_wait_pressure_workers_gone(
                pressure_workers, time.monotonic() + 1.0,
                resource_monitor=resource_monitor,
            ), "pressure driver exited before captured worker sessions were gone")
            if resource_monitor is not None and resource_monitor.sample(
                    "pressure_cleanup", force=True):
                details["resource_budget_exceeded"] = True
                details["resource_monitor_error"] = resource_monitor.failure or \
                    "resource monitor refused during pressure-worker cleanup"
                details["status"] = 125
                supervision_state["details"] = details
                supervision_state["status"] = 125
                stop_pressure_session()
                return 125
            pressure_cleanup = "verified"
            supervision_state["pressure_cleanup"] = pressure_cleanup
            supervision_state["pressure_driver"] = {
                "pid": pressure_process.pid,
                "start_ticks": pressure_start_ticks,
                "return_code": pressure_process.returncode,
            }
            supervision_state["pressure_worker_sessions"] = list(pressure_workers.values())
            pressure_cleanup_ended_monotonic_ns = time.monotonic_ns()
            if resource_monitor is not None and not \
                    supervision_state.get("pressure_owner_result_pin"):
                record_pressure_owner_return()
            pressure_stopped = True
        if resource_monitor is not None and resource_monitor.failure is not None:
            details["resource_budget_exceeded"] = True
            details["resource_monitor_error"] = resource_monitor.failure
            details["status"] = 125
            supervision_state["status"] = 125
            if not pressure_stopped:
                stop_pressure_session()
            supervision_state["details"] = details
            return 125
        if pressure_process.poll() != 0:
            raise SoakReadbackError(f"pressure driver exited {pressure_process.returncode}; stderr tail: {_tail_text(pressure_stderr)}")
        supervision_state["pressure_ready_sha256"] = ready_sha
        supervision_state["pressure_cleanup"] = pressure_cleanup
        proof = _validate_pressure_proof_monitored(
            output_dir, audit, resource_monitor,
        )
        supervision_state["pressure_proof"] = proof
        check_supervisor_interruption()
        if resource_monitor is not None:
            resource_monitor.sample("postflight", force=True)
            if resource_monitor.failure is not None:
                details["resource_budget_exceeded"] = True
                details["resource_monitor_error"] = resource_monitor.failure
                details["status"] = 125
                supervision_state["status"] = 125
        if descriptor.get("emit_result", True):
            print(json.dumps({
                "exit_code": details["status"],
                "launch_receipt_sha256": supervision_state.get("legacy_launch_receipt_sha256"),
                "pressure_readback_path": str(output_dir / "pressure-readback.json"),
                "pressure_readback_sha256": proof["raw_sha256"],
                "pressure_ready_sha256": ready_sha,
                "launch_enabled": True,
            }, sort_keys=True))
        return details["status"]
    except BaseException as primary_error:
        pressure_cleanup_error: BaseException | None = None
        if pressure_process is not None and not pressure_stopped:
            try:
                stop_pressure_session()
            except BaseException as error:
                pressure_cleanup_error = error
        if supervisor_signal["received_signal"] is not None:
            try:
                return finish_external_interruption(supervisor_signal["received_signal"])
            except SoakReadbackError as error:
                if pressure_cleanup_error is not None:
                    raise SoakReadbackError(f"{error}; pressure cleanup also failed: {pressure_cleanup_error}") from pressure_cleanup_error
                raise
        if pressure_cleanup_error is not None:
            raise SoakReadbackError(f"{primary_error}; pressure cleanup failed: {pressure_cleanup_error}") from primary_error
        raise
    finally:
        for fd in (pressure_out_fd, pressure_err_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        try:
            if subreaper_previous is not None:
                _set_child_subreaper(subreaper_previous)
        finally:
            _restore_external_supervisor_signal_handlers(signal_handlers)


def supervise_pressure_application(
    app_descriptor: dict[str, Any],
    pressure_recipe_info: dict[str, Any],
    output_root: Path,
    on_started: Any,
    on_cleanup: Any,
    *, resource_monitor: _SoakResourceMonitor | None = None,
) -> dict[str, Any]:
    """Supervise one direct APP under a fresh SourceV5 pressure session.

    The explicit `execution_kind` distinguishes the existing timed-soak adapter
    from normal SourceV5 applications. The returned receipt keeps the direct
    APP Popen identity, the pressure launch binding, worker cleanup, and the
    closed pressure proof together; callbacks run inside the protected lifetime.
    """
    descriptor_keys = {
        "schema", "execution_kind", "argv", "cpu_set", "cwd", "environment",
        "binary_path", "binary_sha256", "application_wall_timeout_seconds",
        "term_grace_seconds", "stdout_path", "stderr_path", "timing_path",
        "monitored_files",
    }
    require(type(app_descriptor) is dict and set(app_descriptor) in (descriptor_keys, descriptor_keys | {"on_interrupted"}), "pressure application descriptor has an unexpected field set")
    descriptor = app_descriptor
    require(descriptor["schema"] == "allocatbelt.application-pressure-app-descriptor.v1", "unsupported pressure application descriptor")
    require(descriptor["execution_kind"] in ("normal_app", "timed_soak"), "pressure application descriptor must select normal_app or timed_soak")
    require(callable(on_started) and callable(on_cleanup), "pressure application lifecycle callbacks must be callable")
    argv = descriptor["argv"]
    require(type(argv) is list and 1 <= len(argv) <= 96 and all(type(item) is str and item and "\x00" not in item for item in argv), "pressure application argv is malformed")
    binary_path = safe_absolute_path(descriptor["binary_path"], "pressure application binary")
    require(argv[0] == str(binary_path) and binary_path.resolve(strict=True) == binary_path, "pressure APP argv[0] differs from its canonical executable path")
    binary_sha = digest(descriptor["binary_sha256"], "pressure application binary SHA-256")
    cwd = safe_absolute_path(descriptor["cwd"], "pressure application cwd")
    require(str(cwd) == descriptor["cwd"] and cwd.resolve(strict=True) == cwd, "pressure application cwd traverses an alias")
    environment = descriptor["environment"]
    require(type(environment) is dict and environment and all(
        type(key) is str and key and "=" not in key and "\x00" not in key
        and type(value) is str and "\x00" not in value
        for key, value in environment.items()
    ), "pressure application environment is malformed")
    require(len(canonical_bytes(environment)) <= MAX_ENVIRONMENT_BYTES, "pressure application environment exceeds its finite bound")
    cpu_set = descriptor["cpu_set"]
    cpu_ids = _parse_cpu_set(cpu_set)
    recipe = pressure_recipe_info.get("value") if type(pressure_recipe_info) is dict else None
    require(type(recipe) is dict, "pressure application has no validated frozen driver recipe")
    require(
        recipe.get("schema") == "allocatbelt.application-pressure-recipe.v1"
        and recipe.get("identity", {}).get("phase") == "external_pressure",
        "pressure application recipe has the wrong schema or phase",
    )
    recipe_path = safe_absolute_path(pressure_recipe_info.get("recipe_path"), "pressure recipe path")
    recipe_raw_sha = digest(pressure_recipe_info.get("raw_sha256"), "pressure recipe raw SHA-256")
    recipe_sha = digest(pressure_recipe_info.get("recipe_sha256"), "pressure recipe semantic SHA-256")
    condition_sha = digest(pressure_recipe_info.get("condition_sha256"), "pressure condition SHA-256")
    recipe_value, actual_recipe_raw_sha, recipe_raw = read_json(recipe_path, "frozen pressure recipe", MAX_RECIPE_BYTES)
    require(recipe_raw == canonical_bytes(recipe_value) and actual_recipe_raw_sha == recipe_raw_sha, "pressure recipe bytes differ from the frozen raw pin")
    require(recipe_value == recipe and recipe.get("recipe_sha256") == recipe_sha and recipe.get("condition_sha256") == condition_sha, "pressure recipe differs from the independently validated recipe identity")
    require(recipe["files"]["application_binary"]["raw_sha256"] == binary_sha, "pressure recipe application binary differs from the APP descriptor")
    require(recipe["process"]["executable_path"] == str(binary_path), "pressure recipe executable path differs from the APP descriptor")
    require(recipe["process"]["application_tmpdir_path"] == environment.get("TMPDIR"), "pressure APP TMPDIR differs from its frozen driver recipe")
    require(recipe["identity"]["nonce"] == environment.get("ALLOCATBELT_APP_PRESSURE_NONCE"), "pressure APP nonce differs from its frozen driver recipe")
    require(sorted(cpu_ids) == recipe["schedule"]["application_cpu_affinity"], "pressure APP affinity differs from its frozen driver recipe")
    require(str(cwd) in recipe["storage"]["application_io_paths"], "pressure APP cwd is outside its frozen I/O path set")
    require(type(pressure_recipe_info.get("reader")) is types.ModuleType, "pressure recipe has no captured independent reader module")
    thresholds = pressure_recipe_info.get("readiness_thresholds")
    require(type(thresholds) is dict, "pressure proof readiness thresholds are malformed")
    driver_thresholds = pressure_recipe_info.get("driver_readiness_thresholds")
    if driver_thresholds is not None:
        require(type(driver_thresholds) is dict and driver_thresholds == recipe["readiness_thresholds"], "pressure driver readiness thresholds differ from the frozen recipe")

    output_root = safe_absolute_path(str(output_root), "pressure application output root")
    require(output_root.is_dir() and output_root.resolve(strict=True) == output_root, "pressure application output root must be an existing canonical directory")
    require(stat.S_IMODE(output_root.stat().st_mode) & 0o077 == 0, "pressure application output root is not private")
    def reserved_output_path(value: object, label: str, expected_parent: Path) -> Path:
        raw = text(value, label, maximum=4096)
        path = Path(raw)
        require(path.is_absolute() and path.name not in ("", ".", "..") and ".." not in path.parts, f"{label} must be a normalized absolute file path")
        require(path.parent == expected_parent, f"{label} parent differs from its reserved output directory")
        if expected_parent.exists():
            require(expected_parent.resolve(strict=True) == expected_parent, f"{label} parent is a symlink or alias")
        else:
            require(expected_parent == pressure_dir and not expected_parent.is_symlink(), f"{label} parent does not exist as the reserved pressure directory")
        require(not path.exists() and not path.is_symlink(), f"{label} already exists")
        return path

    def monitored_output_path(value: object, label: str) -> Path:
        raw = text(value, label, maximum=4096)
        path = Path(raw)
        require(path.is_absolute() and ".." not in path.parts and path != output_root, f"{label} must be a normalized absolute file below the APP output root")
        try:
            path.relative_to(output_root)
        except ValueError as error:
            raise SoakReadbackError(f"{label} escaped the APP output root") from error
        require(not path.is_relative_to(pressure_dir), f"{label} is inside the closed pressure artifact directory")
        parts = path.relative_to(output_root).parts
        current = output_root
        for component in parts[:-1]:
            current = current / component
            if current.exists():
                info = current.lstat()
                require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), f"{label} parent is not a regular directory")
        require(not path.exists() and not path.is_symlink(), f"{label} already exists")
        return path

    pressure_dir_raw = text(pressure_recipe_info.get("output_dir"), "pressure artifact directory", maximum=4096)
    pressure_dir = Path(pressure_dir_raw)
    require(pressure_dir.is_absolute() and pressure_dir.parent.resolve(strict=True) == output_root and pressure_dir.name == "pressure", "pressure artifacts must use the dedicated pressure subdirectory")
    require(pressure_dir == output_root / "pressure", "pressure artifacts must use the dedicated pressure subdirectory")
    require(not pressure_dir.exists() and not pressure_dir.is_symlink(), "pressure artifact directory already exists")
    driver_path = safe_absolute_path(pressure_recipe_info.get("driver_path"), "SourceV5 pressure driver")
    driver_sha = digest(pressure_recipe_info.get("driver_sha256"), "SourceV5 pressure driver SHA-256")
    require(sha256_file(driver_path, "SourceV5 pressure driver", MAX_SOURCE_FILE_BYTES) == driver_sha, "SourceV5 pressure driver changed before Popen")
    source_root = safe_absolute_path(pressure_recipe_info.get("source_root"), "SourceV5 source root")
    launch_path = reserved_output_path(pressure_recipe_info.get("launch_record_path"), "pressure launch record", pressure_dir)
    ready_path = reserved_output_path(pressure_recipe_info.get("ready_path"), "pressure readiness marker", pressure_dir)
    require(launch_path == pressure_dir / "launch-record.json" and ready_path == pressure_dir / "pressure-ready.json", "pressure launch/readiness paths differ from the canonical private artifact layout")

    timeout = uint(descriptor["application_wall_timeout_seconds"], "pressure APP wall timeout", positive=True, maximum=SOURCE_V5_PRESSURE_MAX_TOTAL_SECONDS)
    term_grace = descriptor["term_grace_seconds"]
    require(type(term_grace) in (int, float) and 0 < term_grace <= 60, "pressure APP TERM grace is outside its finite bound")
    monitored: list[tuple[Path, int]] = []
    require(type(descriptor["monitored_files"]) is list and len(descriptor["monitored_files"]) <= 8, "pressure APP monitored-file list is malformed")
    for index, entry in enumerate(descriptor["monitored_files"]):
        item = exact_object(entry, {"path", "maximum_bytes"}, f"pressure monitored artifact[{index}]")
        path = monitored_output_path(item["path"], f"pressure monitored artifact[{index}] path")
        maximum = uint(item["maximum_bytes"], f"pressure monitored artifact[{index}] budget", positive=True, maximum=MAX_TERMINAL_BYTES)
        monitored.append((path, maximum))
    require(len({path for path, _maximum in monitored}) == len(monitored), "pressure monitored-file list repeats an output path")

    paths = {
        name: reserved_output_path(descriptor[name], f"pressure APP {name}", output_root)
        for name in ("stdout_path", "stderr_path", "timing_path")
    }
    require(all(path.parent == output_root and path != pressure_dir for path in paths.values()), "pressure APP logs must stay outside the pressure artifact directory")
    require(len(set(paths.values())) == len(paths), "pressure APP stdout, stderr and timing paths overlap")
    require(app_descriptor.get("on_interrupted") is None or callable(app_descriptor.get("on_interrupted")), "pressure interruption callback is malformed")

    def record_generic_interruption(record: dict[str, Any]) -> int:
        status = 128 + record["signal"]
        value = {
            "schema": "allocatbelt.application-pressure-supervision-interruption.v1",
            "execution_kind": descriptor["execution_kind"],
            "status": status,
            "signal": record["signal"],
            "pressure_driver": {
                "pid": record["pressure_pid"],
                "start_ticks": record["pressure_start_ticks"],
                "return_code": record["pressure_return_code"],
            },
            "application_cleanup": record["application_cleanup"],
            "pressure_cleanup": record["pressure_cleanup"],
            "pressure_worker_sessions": record["workers"],
        }
        value["interruption_sha256"] = hashlib.sha256(canonical_bytes(value)).hexdigest()
        _write_exclusive_json(output_root / "supervision-interruption.json", value)
        return status

    interruption_callback = app_descriptor.get("on_interrupted", record_generic_interruption)
    execution = {
        **descriptor,
        "launch_enabled": True,
        "application_wall_timeout_seconds": timeout,
        "pressure_recipe_path": str(recipe_path),
        "pressure_recipe_sha256": recipe_sha,
        "pressure_driver_path": str(driver_path),
        "pressure_driver_sha256": driver_sha,
        "pressure_output_dir": str(pressure_dir),
        "pressure_launch_path": str(launch_path),
        "pressure_ready_path": str(ready_path),
        "pressure_condition_sha256": condition_sha,
        "pressure_stdout_path": str(output_root / "pressure-driver.stdout.log"),
        "pressure_stderr_path": str(output_root / "pressure-driver.stderr.log"),
        "stdout_path": str(paths["stdout_path"]),
        "stderr_path": str(paths["stderr_path"]),
        "timing_path": str(paths["timing_path"]),
        "binary_path": str(binary_path),
        "binary_sha256": binary_sha,
        "cwd": str(cwd),
        "environment": environment,
        "monitored_files": monitored,
        "execution_kind": descriptor["execution_kind"],
        "emit_result": False,
        "persist_legacy_receipt": False,
        "_on_started": on_started,
        "_on_cleanup": on_cleanup,
        "_on_interrupted": interruption_callback,
        "_supervision_state": {},
    }
    pressure_info = {
        "value": recipe,
        "reader": pressure_recipe_info["reader"],
        "recipe_sha256": recipe_sha,
        "raw_sha256": recipe_raw_sha,
        "condition_sha256": condition_sha,
        "recipe_path": str(recipe_path),
        "readiness_thresholds": thresholds,
    }
    audit = {
        "launch_descriptor": execution,
        "identity": {"nonce": recipe["identity"]["nonce"], "run_id": recipe["identity"]["run_id"]},
        "source": {
            "pressure_recipe": pressure_info,
            "application_supervision": {"application_wall_timeout_seconds": timeout},
        },
        "source_root": str(source_root),
        "recipe": {
            "pressure": {"recipe": {"path": str(recipe_path), "raw_sha256": recipe_raw_sha}},
            "qualification": {"pressure_condition": {"readiness_thresholds": thresholds}},
        },
    }
    preflight = {
        "terminal_budget_bytes": max((maximum for path, maximum in monitored if path.suffix == ".tsv"), default=MAX_TERMINAL_BYTES),
        "sample_budget_bytes": max((maximum for path, maximum in monitored if path.suffix == ".csv"), default=MAX_SAMPLE_BYTES),
    }
    args = argparse.Namespace(
        command=list(argv), cpu_set=cpu_set, timeout_seconds=timeout,
        term_grace_seconds=float(term_grace),
    )
    if resource_monitor is None:
        status = _run_pressure_supervisor_impl(args, audit, preflight, output_root)
    else:
        status = _run_pressure_supervisor_impl(
            args, audit, preflight, output_root,
            resource_monitor=resource_monitor,
        )
    state = execution["_supervision_state"]
    return {
        "schema": "allocatbelt.application-pressure-supervision.v1",
        "execution_kind": descriptor["execution_kind"],
        "status": status,
        "interrupted": state.get("interrupted", False),
        "received_signal": state.get("received_signal"),
        "application_cleanup": state.get("application_cleanup"),
        "application_binding": state.get("application_binding"),
        "application_binding_sha256": state.get("application_binding_sha256"),
        "application_attestation": state.get("application_attestation"),
        "pressure_ready_sha256": state.get("pressure_ready_sha256"),
        "pressure_proof": state.get("pressure_proof"),
        "pressure_cleanup": state.get("pressure_cleanup"),
        "pressure_driver": state.get("pressure_driver"),
        "pressure_worker_sessions": state.get("pressure_worker_sessions"),
        "details": state.get("details"),
    }


def _adapt_soak_v2_launch(
    args: argparse.Namespace, audit: dict[str, Any], preflight: dict[str, Any],
    *, artifact_limits: dict[str, int] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Restore the immutable V2 CLI contract before building the shared descriptor."""
    descriptor = audit["launch_descriptor"]
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    require(command == descriptor["argv"], "Soak V2 CLI command differs from the frozen launch descriptor")
    require(args.cpu_set == descriptor["cpu_set"], "Soak V2 CLI CPU set differs from the frozen launch descriptor")

    frozen_timeout = uint(
        audit["source"]["application_supervision"]["application_wall_timeout_seconds"],
        "SourceV5 Soak V2 derived application timeout", positive=True,
        maximum=SOURCE_V5_PRESSURE_MAX_TOTAL_SECONDS,
    )
    require(descriptor["application_wall_timeout_seconds"] == frozen_timeout, "Soak V2 launch descriptor timeout differs from the independently derived bound")
    require(args.timeout_seconds == frozen_timeout, "Soak V2 CLI timeout differs from the independently derived bound")
    require(args.term_grace_seconds == 1.5, "Soak V2 CLI TERM grace differs from its frozen 1.5-second contract")

    pressure_info = audit["source"]["pressure_recipe"]
    recipe_pin = audit["recipe"]["pressure"]["recipe"]
    require(type(pressure_info) is dict and type(recipe_pin) is dict, "SourceV5 Soak V2 pressure recipe is missing")
    require(
        pressure_info.get("raw_sha256") == recipe_pin.get("raw_sha256")
        and pressure_info.get("recipe_sha256") == recipe_pin.get("semantic_sha256"),
        "Soak V2 pressure recipe differs from its parent-pinned raw/semantic identities",
    )
    pressure_info = {
        **pressure_info,
        "recipe_path": recipe_pin["path"],
        "raw_sha256": recipe_pin["raw_sha256"],
        "driver_path": descriptor["pressure_driver_path"],
        "driver_sha256": descriptor["pressure_driver_sha256"],
        "output_dir": descriptor["pressure_output_dir"],
        "launch_record_path": descriptor["pressure_launch_path"],
        "ready_path": descriptor["pressure_ready_path"],
        "source_root": audit["source_root"],
        "readiness_thresholds": audit["recipe"]["qualification"]["pressure_condition"]["readiness_thresholds"],
    }
    monitored_files = [
        {"path": str(Path(descriptor["terminal_path"])),
         "maximum_bytes": preflight["terminal_budget_bytes"]},
        {"path": str(Path(descriptor["samples_path"])),
         "maximum_bytes": preflight["sample_budget_bytes"]},
    ]
    if artifact_limits is not None:
        exact_object(artifact_limits, {
            "terminal_stream_bytes", "resource_samples_bytes",
            "application_stdout_bytes", "application_stderr_bytes",
            "application_timing_bytes", "soak_receipt_bytes",
            "launch_receipt_bytes", "launch_authorization_bytes",
            "preflight_receipt_bytes",
            "postflight_receipt_bytes", "readback_receipt_bytes",
            "source5_supervisor_bytes", "pressure_readback_bytes",
            "pressure_events_bytes",
            "pressure_run_receipt_bytes", "pressure_launch_bytes",
            "pressure_binding_bytes", "pressure_ready_bytes",
            "pressure_driver_stdout_bytes", "pressure_driver_stderr_bytes",
            "pressure_worker_stderr_bytes", "probe_stdout_bytes",
            "probe_stderr_bytes", "probe_owner_receipt_bytes",
            "probe_inventory_bytes", "probe_failure_bytes",
            "probe_capture_receipt_bytes", "resource_monitor_stream_bytes",
            "owner_return_receipt_bytes", "host_receipt_bytes",
            "failure_receipt_bytes", "component_receipt_bytes",
        }, "Source5 prospective Soak artifact limits")
        for name in ("application_stdout_bytes", "application_stderr_bytes",
                     "application_timing_bytes"):
            amount = uint(artifact_limits[name],
                          f"Source5 {name} limit", positive=True)
            monitored_files.append({
                "path": str(Path(descriptor[{
                    "application_stdout_bytes": "stdout_path",
                    "application_stderr_bytes": "stderr_path",
                    "application_timing_bytes": "timing_path",
                }[name]])),
                "maximum_bytes": amount,
            })
    app_descriptor = {
        "schema": "allocatbelt.application-pressure-app-descriptor.v1",
        "execution_kind": "timed_soak",
        "argv": command,
        "cpu_set": descriptor["cpu_set"],
        "cwd": descriptor["cwd"],
        "environment": descriptor["environment"],
        "binary_path": descriptor["binary_path"],
        "binary_sha256": descriptor["binary_sha256"],
        "application_wall_timeout_seconds": frozen_timeout,
        "term_grace_seconds": 1.5,
        "stdout_path": str(Path(descriptor["stdout_path"])),
        "stderr_path": str(Path(descriptor["stderr_path"])),
        "timing_path": str(Path(descriptor["timing_path"])),
        "monitored_files": monitored_files,
    }
    return pressure_info, app_descriptor


def launch_soak_v2_application(
    args: argparse.Namespace, audit: dict[str, Any], preflight: dict[str, Any],
    output_dir: Path, on_started: Any, on_cleanup: Any, *,
    resource_budget_pin: object | None = None,
    resource_monitor_context: _SoakResourceMonitor | None = None,
) -> dict[str, Any]:
    """Expose the owned Soak V2 lifetime and its complete supervisor receipt."""
    require(callable(on_started) and callable(on_cleanup), "Soak V2 lifecycle callbacks must be callable")
    descriptor = audit["launch_descriptor"]
    resource_monitor = resource_monitor_context
    resource_budget = None
    externally_owned_monitor = resource_monitor_context is not None
    if resource_budget_pin is not None:
        budget, checked_pin = _read_soak_resource_budget(
            resource_budget_pin, audit, output_dir,
        )
        resource_budget = budget
        require(descriptor.get("resource_budget_pin") == checked_pin and
                descriptor.get("resource_monitor_path") ==
                    str(output_dir / "source5-soak-resource-monitor.jsonl"),
                "Source5 launch descriptor does not bind its prospective resource budget/stream")
        if externally_owned_monitor:
            require(isinstance(resource_monitor, _SoakResourceMonitor) and
                    resource_monitor.budget == budget and
                    resource_monitor.budget_pin == checked_pin and
                    resource_monitor.path == output_dir /
                        "source5-soak-resource-monitor.jsonl" and
                    resource_monitor.fd is not None,
                    "Source5 caller monitor is not the live selected budget owner")
        else:
            owner = _load_soak_resource_monitor_owner(audit, budget)
            resource_monitor = _SoakResourceMonitor(
                budget, checked_pin, owner, output_dir, resume=True,
            )
    else:
        require(descriptor.get("resource_budget_pin") is None and
                descriptor.get("resource_monitor_path") is None and
                resource_monitor_context is None,
                "historical Source5 launch cannot use an unpinned resource monitor")
    def on_interrupted(record: dict[str, Any]) -> int:
        exit_code = 128 + record["signal"]
        cleanup_states_verified = record["application_cleanup"] in ("not_started", "verified") and record["pressure_cleanup"] in ("not_started", "verified")
        cleanup_state = "verified" if cleanup_states_verified else "failed" if "failed" in (record["application_cleanup"], record["pressure_cleanup"]) else "unverified"
        receipt_value = {
            "schema": "allocatbelt.application-soak-supervisor-interruption.v2",
            "recipe_sha256": audit["recipe_sha256"],
            "campaign_id": audit["identity"]["campaign_id"],
            "host_id": audit["identity"]["host_id"],
            "run_id": audit["identity"]["run_id"],
            "nonce": audit["identity"]["nonce"],
            "signal": record["signal"],
            "exit_code": exit_code,
            "pressure_driver_pid": record["pressure_pid"],
            "pressure_driver_start_ticks": record["pressure_start_ticks"],
            "pressure_driver_return_code": record["pressure_return_code"],
            "application_cleanup": record["application_cleanup"],
            "pressure_cleanup": record["pressure_cleanup"],
            "cleanup": cleanup_state,
        }
        _write_exclusive_json(output_dir / "soak-supervisor-interruption.json", receipt_value)
        print(json.dumps(receipt_value, sort_keys=True, separators=(",", ":")))
        return exit_code

    pressure_info, app_descriptor = _adapt_soak_v2_launch(
        args, audit, preflight,
        artifact_limits=(None if resource_budget is None else
                         resource_budget["artifact_limits"]),
    )
    app_descriptor["stdout_path"] = str(output_dir / "stdout.log")
    app_descriptor["stderr_path"] = str(output_dir / "stderr.log")
    app_descriptor["timing_path"] = str(output_dir / "time.txt")
    app_descriptor["on_interrupted"] = on_interrupted
    try:
        if resource_monitor is None:
            receipt = supervise_pressure_application(
                app_descriptor, pressure_info, output_dir,
                on_started=on_started,
                on_cleanup=on_cleanup,
            )
        else:
            receipt = supervise_pressure_application(
                app_descriptor, pressure_info, output_dir,
                on_started=on_started,
                on_cleanup=on_cleanup,
                resource_monitor=resource_monitor,
            )
    except BaseException as error:
        if resource_monitor is not None and resource_monitor.fd is not None:
            resource_monitor.failure = resource_monitor.failure or (
                f"supervisor_failure:{type(error).__name__}:{error}"
            )[:4096]
            try:
                resource_monitor.sample("postflight", force=True)
                if not externally_owned_monitor:
                    resource_monitor.finish(resource_monitor.last_usage)
            except BaseException:
                # Preserve the original supervisor exception; the incomplete
                # stream remains a fail-closed raw failure artifact.
                pass
        raise
    details = receipt["details"]
    if type(details) is dict:
        if resource_monitor is not None:
            resource_monitor.sample("postflight", force=True)
            if externally_owned_monitor:
                descriptor["resource_monitor_prefix"] = \
                    resource_monitor.pending_summary()
            else:
                descriptor["resource_monitor"] = resource_monitor.finish(
                    resource_monitor.last_usage,
                )
            if resource_monitor.failure is not None:
                details["resource_budget_exceeded"] = True
                details["resource_monitor_error"] = resource_monitor.failure
                details["status"] = 125
                receipt["status"] = 125
        launch_receipt = _launch_receipt_value(details, audit, preflight)
        if resource_monitor is not None:
            require(len(canonical_bytes(launch_receipt)) <=
                    resource_monitor.budget["artifact_limits"][
                        "launch_receipt_bytes"],
                    "Source5 bounded Soak launch receipt exceeds its frozen artifact limit")
        launch_receipt_sha = _write_exclusive_json(output_dir / "soak-launch.json", launch_receipt)
        if receipt["status"] == 0 and not receipt["interrupted"]:
            proof = receipt["pressure_proof"]
            require(type(proof) is dict, "shared pressure supervisor omitted the soak proof")
            print(json.dumps({
                "exit_code": receipt["status"],
                "launch_receipt_sha256": launch_receipt_sha,
                "pressure_readback_path": str(output_dir / "pressure-readback.json"),
                "pressure_readback_sha256": proof["raw_sha256"],
                "pressure_ready_sha256": receipt["pressure_ready_sha256"],
                "launch_enabled": True,
            }, sort_keys=True))
    return receipt


def command_launch_v2(args: argparse.Namespace, audit: dict[str, Any], preflight: dict[str, Any], output_dir: Path) -> int:
    """Preserve the established Soak V2 CLI status and receipt outputs."""
    receipt = launch_soak_v2_application(
        args, audit, preflight, output_dir,
        on_started=lambda _attestation: None,
        on_cleanup=lambda _cleanup: None,
    )
    return receipt["status"]


def _add_audit_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--recipe-sha256", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runner-path", type=Path, required=True)
    parser.add_argument("--cpu-set", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command_name", required=True)
    preflight = commands.add_parser("preflight", help="verify frozen source/build/binary/oracle inputs before launch")
    _add_audit_args(preflight)
    for field in ("campaign-id", "host-id", "run-id", "allocator", "executor", "profile", "source-sha256", "binary-sha256", "resource-ceiling-sha256"):
        preflight.add_argument(f"--{field}", required=True)
    preflight.add_argument("--mode", choices=("qualified", "functional"), required=True)
    preflight.add_argument("--duration-seconds", type=int, required=True)
    preflight.set_defaults(func=command_preflight)

    verify = commands.add_parser("verify-inputs", help="rehash frozen inputs after launch, even when the child failed")
    _add_audit_args(verify)
    verify.set_defaults(func=command_verify_inputs)

    validate = commands.add_parser("validate", help="independently validate receipt, terminal IDs, samples and final ledgers")
    _add_audit_args(validate)
    validate.set_defaults(func=command_validate)

    launch = commands.add_parser("launch", help="contain the soak child in a killable process group")
    _add_audit_args(launch)
    launch.add_argument("--preflight", type=Path, required=True)
    launch.add_argument("--timeout-seconds", type=float, required=True)
    launch.add_argument("--term-grace-seconds", type=float, default=1.5)
    launch.add_argument("--terminal-path", type=Path)
    launch.add_argument("--samples-path", type=Path)
    launch.add_argument("command", nargs=argparse.REMAINDER)
    launch.set_defaults(func=command_launch)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, SoakReadbackError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print(f"application soak readback refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
