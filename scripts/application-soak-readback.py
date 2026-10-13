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
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterator


RECIPE_SCHEMA = "allocatbelt.application-soak-parent-recipe.v1"
RECIPE_SCHEMA_V2 = "allocatbelt.application-soak-parent-recipe.v2"
PREFLIGHT_SCHEMA = "allocatbelt.application-soak-preflight.v2"
POSTFLIGHT_SCHEMA = "allocatbelt.application-soak-postflight.v2"
LAUNCH_SCHEMA = "allocatbelt.application-soak-launch.v1"
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
MAX_LINE_BYTES = 8192
_SOURCE_INVENTORY_MODULE_CACHE: dict[str, Any] = {}
_PRESSURE_SUBREAPER_ACTIVE = False

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

    def __init__(self, path: Path, label: str, maximum: int):
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

    def __enter__(self) -> StableInput:
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
        require(self.fd is not None and self.before is not None, f"{self.label} is not open")
        require(self.consumed == self.size, f"{self.label} was not completely read")
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


def read_stable_bytes(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    with StableInput(path, label, maximum) as source:
        blocks = bytearray()
        while source.consumed < source.size:
            blocks.extend(source.read(min(1024 * 1024, source.size - source.consumed)))
        checksum = source.finish()
    return bytes(blocks), checksum


def read_json(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], str, bytes]:
    raw, checksum = read_stable_bytes(path, label, maximum)
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


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _terminate_group(pgid: int, grace_seconds: float = 0.2) -> None:
    if not _group_exists(pgid):
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline and _group_exists(pgid):
        time.sleep(0.02)
    if _group_exists(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _signal_group(pgid: int, signum: int) -> None:
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass


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


def _bounded_reap(process: subprocess.Popen[bytes], label: str) -> str | None:
    """Try to stop and reap a child without ever waiting without a deadline."""
    if process.poll() is not None:
        return None
    _terminate_group(process.pid, 0.1)
    try:
        process.wait(timeout=0.4)
        return None
    except subprocess.TimeoutExpired:
        _signal_group(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=0.5)
        return None
    except subprocess.TimeoutExpired:
        return f"{label} cleanup failed: child was not reaped after bounded SIGKILL"


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
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    old_handlers: dict[int, Any] = {}
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    failure: str | None = None
    cleanup_started: float | None = None
    kill_sent = False
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
            if process is not None:
                _signal_group(process.pid, signal.SIGTERM)

    def interrupted(signum: int, _frame: Any) -> None:
        if not received_signal:
            received_signal.append(signum)

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
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        streams = {"stdout": process.stdout, "stderr": process.stderr}
        for name, stream in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + timeout
        if received_signal:
            begin_cleanup(f"{label} interrupted by signal {received_signal[0]}")
        while selector.get_map() or process.poll() is None:
            if received_signal and failure is None:
                begin_cleanup(f"{label} interrupted by signal {received_signal[0]}")
            if time.monotonic() >= deadline and failure is None:
                begin_cleanup(f"{label} exceeded its {timeout:g}-second deadline")
            now = time.monotonic()
            if process.poll() is not None and cleanup_started is None:
                # The leader may leave descendants that still hold the pipes.
                # Give its process group the same bounded cleanup treatment.
                begin_cleanup()
            if cleanup_started is not None:
                if not kill_sent and now >= cleanup_started + term_grace_seconds:
                    _signal_group(process.pid, signal.SIGKILL)
                    kill_sent = True
                hard_deadline = cleanup_started + term_grace_seconds + kill_reap_seconds
                if now >= hard_deadline:
                    _signal_group(process.pid, signal.SIGKILL)
                    open_streams = list(selector.get_map().values())
                    if open_streams:
                        cleanup_failure = (
                            f"{label} cleanup failed: {len(open_streams)} capture pipe(s) remained open "
                            "at the hard deadline; output is incomplete"
                        )
                    _close_selector_streams(selector)
                    if process.poll() is None:
                        child_failure = f"{label} cleanup failed: child was not reaped by its hard deadline"
                        cleanup_failure = f"{cleanup_failure}; {child_failure}" if cleanup_failure else child_failure
                    break
            select_timeout = 0.05
            if cleanup_started is not None:
                hard_deadline = cleanup_started + term_grace_seconds + kill_reap_seconds
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
        if cleanup_started is None:
            # Also stop descendants that closed their inherited capture pipes.
            _terminate_group(process.pid, term_grace_seconds)
        _signal_group(process.pid, signal.SIGKILL)
        return_code = process.poll()
        if return_code is None:
            _signal_group(process.pid, signal.SIGKILL)
            cleanup_failure = f"{label} cleanup failed: child was not reaped by its hard deadline"
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
        if process is not None:
            if cleanup_failure is not None:
                _signal_group(process.pid, signal.SIGKILL)
                try:
                    process.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    final_cleanup_failure = f"{label} cleanup failed: child remains unreaped after hard deadline"
            else:
                try:
                    final_cleanup_failure = _bounded_reap(process, label)
                except OSError as error:
                    final_cleanup_failure = f"{label} cleanup failed: {error}"
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


def verify_source_tree(root: Path, source: dict[str, Any]) -> str:
    require(root.is_dir() and not root.is_symlink(), "source root must be a real directory")
    commit = text(source["git_commit"], "source git commit", maximum=64)
    live_commit = _run_checked(["git", "rev-parse", "HEAD"], root, "source git identity").decode("ascii").strip()
    require(live_commit == commit, "live source Git commit differs from its frozen manifest")
    inventory_module = source_inventory_module()
    expected_records = inventory_module.validate_records({
        "schema": inventory_module.SCHEMA,
        "entries": source["files"],
    })
    require(expected_records == source["files"], "source inventory records are not canonical")
    try:
        inventory_module.verify_source_tree(root, source["source_tree_sha256"], expected_records)
    except inventory_module.InventoryError as error:
        raise SoakReadbackError(f"live source inventory differs from its manifest: {error}") from error
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


def _audit_manifest_and_binaries(recipe: dict[str, Any]) -> dict[str, Any]:
    if recipe["schema"] == RECIPE_SCHEMA_V2:
        return _audit_manifest_and_binaries_v5(recipe)
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


def _audit_manifest_and_binaries_v5(recipe: dict[str, Any]) -> dict[str, Any]:
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
    live_tree = verify_source_tree(source_root, source)
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
    require(probe_value.get("schema") == "allocatbelt.application-feedback-policy-probe.v1", "unsupported SourceV5 construction probe schema")
    require(probe_value.get("context", {}).get("workload") == "mixed" and probe_value.get("context", {}).get("profile") == identity["profile"], "SourceV5 construction probe context differs from the soak profile")
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
    require(probe_policy["controls"] == contexts[feedback_context_key]["controls"], "constructed feedback controls differ from SourceV5 numeric context")
    require(probe_policy["sample_interval_ns"] == feedback_artifact["policy"]["reader_contract"]["sample_interval_ns"] and probe_policy["minimum_dense_observations"] == contexts[feedback_context_key]["minimum_dense_observations"], "constructed feedback reader policy differs from SourceV5 policy")
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
    source_audit = _audit_manifest_and_binaries(recipe)
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
) -> dict[str, Any]:
    _parse_cpu_set(cpu_set)
    output_dir = _check_private_output_directory(output_dir)
    if audit["recipe"]["schema"] == RECIPE_SCHEMA_V2:
        return _make_launch_descriptor_v2(audit, output_dir, cpu_set, terminal_path, samples_path)
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
    terminal_path: Path | None, samples_path: Path | None,
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
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
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
    exact_object(receipt, expected_keys, "parent launch receipt")
    material = dict(receipt)
    claimed = material.pop("launch_receipt_sha256")
    require(digest(claimed, "launch receipt digest") == hashlib.sha256(canonical_bytes(material)).hexdigest(), "parent launch receipt digest is invalid")
    descriptor = audit["launch_descriptor"]
    static_expected = {
        "schema": LAUNCH_SCHEMA,
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
    require(receipt["received_signal"] is None or type(receipt["received_signal"]) is int, "parent launch receipt signal is malformed")
    if receipt["received_signal"] is not None:
        uint(receipt["received_signal"], "parent launch receipt signal", maximum=64, positive=True)
    if receipt["timed_out"]:
        require(receipt["exit_code"] == 124, "timed launch must use the stable timeout status 124")
    elif receipt["artifact_budget_exceeded"]:
        require(receipt["exit_code"] == 125, "over-budget launch must use the stable refusal status 125")
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
        require(available <= bucket["burst_bytes"] and reserved <= bucket["burst_bytes"], f"sample {index} {direction} byte credits exceed the burst")
        require(available + reserved <= bucket["burst_bytes"], f"sample {index} {direction} available/reserved credit is not conserved")
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
        require(available <= bucket["burst_bytes"] and reserved <= bucket["burst_bytes"], f"sample {index} {direction} credits exceed the hard burst")
        require(available + reserved <= bucket["burst_bytes"], f"sample {index} {direction} credit accounting is not conserved")
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


def _check_private_output_directory(path: Path) -> Path:
    try:
        require(not stat.S_ISLNK(path.lstat().st_mode), "soak output directory may not be a symlink")
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise SoakReadbackError(f"soak output directory is unavailable: {error}") from error
    require(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o077 == 0, "soak output directory must be private mode 0700")
    return resolved


def command_preflight(args: argparse.Namespace) -> int:
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


def _current_audit(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
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
    )
    output_dir = _check_private_output_directory(args.output_dir)
    audit["launch_descriptor"] = _make_launch_descriptor(audit, output_dir, args.cpu_set)
    preflight = _verify_preflight(output_dir / "soak-preflight.json", audit)
    audit["preflight"] = preflight
    return audit, preflight


def command_verify_inputs(args: argparse.Namespace) -> int:
    audit, preflight = _current_audit(args)
    launch_receipt, launch_receipt_sha = _verify_launch_receipt(
        _check_private_output_directory(args.output_dir),
        audit,
        preflight,
        require_success=False,
    )
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
    audit["launch_receipt"] = launch_receipt
    postflight["postflight_sha256"] = hashlib.sha256(canonical_bytes(postflight)).hexdigest()
    checksum = _write_exclusive_json(_check_private_output_directory(args.output_dir) / "soak-postflight.json", postflight)
    print(json.dumps({"inputs_unchanged": True, "postflight_sha256": postflight["postflight_sha256"], "file_sha256": checksum}, sort_keys=True))
    return 0


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
) -> int | dict[str, Any]:
    """Run one child in a separate process group and reap it on timeout/signal."""
    require(command and all(type(arg) is str for arg in command), "launch command is malformed")
    cpu_ids = _parse_cpu_set(cpu_set)
    require(0 < timeout_seconds <= 14_400 and 0 < term_grace_seconds <= 60, "launch timeout is outside its finite bounds")
    require(not timeout_includes_cleanup or (timeout_from_before_popen and timeout_seconds > term_grace_seconds + 0.75), "whole-process timeout needs a pre-Popen clock and room for bounded cleanup")
    for path in (stdout_path, stderr_path, timing_path):
        require(not path.exists() and not path.is_symlink(), f"refusing to replace launch output {path}")
    output_fds: list[int] = []
    executable_fd: int | None = None
    inherited_executable_fd: int | None = None
    process: subprocess.Popen[bytes] | None = None
    received_signal: list[int] = []
    old_handlers: dict[int, Any] = {}
    stop_started: float | None = None
    timed_out = False
    limit_exceeded = False
    launched_at_ns: int | None = None
    ended_at_ns: int | None = None
    kill_sent_at: float | None = None
    kill_reap_seconds = 0.75
    timeout_wall_deadline: float | None = None
    executable_path = Path(command[0]).resolve(strict=True)

    def group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def terminate_group(pgid: int, grace: float) -> None:
        if not group_exists(pgid):
            return
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return
        end = time.monotonic() + grace
        while time.monotonic() < end and group_exists(pgid):
            time.sleep(0.02)
        if group_exists(pgid):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def request_stop(signum: int, _frame: Any) -> None:
        nonlocal stop_started
        if received_signal:
            return
        received_signal.append(signum)
        stop_started = time.monotonic()
        if on_signal is not None and _frame is not None:
            on_signal(signum)
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

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
        if on_started is not None:
            on_started(process, executable_path, executable_sha256, executable_info, cpu_ids, cwd, environment)
        if timeout_wall_deadline is None:
            deadline = time.monotonic() + timeout_seconds
        elif timeout_includes_cleanup:
            deadline = timeout_wall_deadline - term_grace_seconds - kill_reap_seconds
        else:
            deadline = timeout_wall_deadline
        while True:
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0 and not received_signal:
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
                    if not received_signal:
                        request_stop(signal.SIGTERM, None)
            if monitor is not None:
                monitor(process)
            if stop_started is not None:
                escalation_at = stop_started + term_grace_seconds
                if kill_sent_at is None and now >= escalation_at:
                    _signal_group(process.pid, signal.SIGKILL)
                    kill_sent_at = now
                hard_cleanup_deadline = escalation_at + kill_reap_seconds
                if kill_sent_at is not None and now >= hard_cleanup_deadline:
                    raise SoakReadbackError("soak launch cleanup failed: child was not reaped by its hard SIGKILL deadline")
            remaining = deadline - now
            if stop_started is not None:
                remaining = min(remaining, max(0.0, stop_started + term_grace_seconds + kill_reap_seconds - now))
            try:
                return_code = process.wait(timeout=max(0.01, min(max(remaining, 0.0), 0.1)))
                break
            except subprocess.TimeoutExpired:
                continue
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
        require(final_executable_sha256 == executable_sha256, "launched binary bytes changed while the child ran")
        require(_fingerprint(final_executable_info) == _fingerprint(executable_info), "launched binary descriptor identity changed while the child ran")
        if timed_out:
            status = 124
        elif limit_exceeded:
            status = 125
        elif received_signal:
            status = 128 + received_signal[0]
        elif return_code < 0:
            status = 128 + (-return_code)
        else:
            status = return_code
        if return_details:
            launch_environment = dict(os.environ) if environment is None else dict(environment)
            return {
                "status": status,
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
        return status
    except OSError as error:
        raise SoakReadbackError(f"cannot launch soak process: {error}") from error
    finally:
        active_exception = sys.exc_info()[1]
        cleanup_failure: str | None = None
        if process is not None:
            try:
                # Always clean the process group, even if its leader exited
                # while a descendant still holds the original group ID.
                if process.poll() is None and kill_sent_at is not None:
                    _signal_group(process.pid, signal.SIGKILL)
                    try:
                        process.wait(timeout=0)
                    except subprocess.TimeoutExpired:
                        cleanup_failure = "soak launch cleanup failed: child remains unreaped after the hard deadline"
                elif process.poll() is not None:
                    terminate_group(process.pid, min(term_grace_seconds, 0.2))
                else:
                    _terminate_group(process.pid, 0.1)
                    cleanup_failure = _bounded_reap(process, "soak launch")
            except BaseException as error:
                cleanup_failure = cleanup_failure or f"soak launch cleanup failed: {error}"
            if on_cleanup is not None:
                cleanup_result = {
                    "schema": "allocatbelt.application-soak-process-cleanup.v1",
                    "status": "failed" if cleanup_failure is not None else "verified",
                    "pid": process.pid,
                    "return_code": process.returncode,
                    "received_signal": received_signal[0] if received_signal else None,
                    "cleanup_error": cleanup_failure,
                }
                try:
                    on_cleanup(cleanup_result)
                except BaseException as error:
                    if cleanup_failure is None:
                        cleanup_failure = f"soak launch cleanup-result callback failed: {error}"
        for signum, old_handler in old_handlers.items():
            signal.signal(signum, old_handler)
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
        if cleanup_failure is not None:
            if active_exception is None:
                raise SoakReadbackError(cleanup_failure)
            raise SoakReadbackError(f"{active_exception}; {cleanup_failure}") from active_exception


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
    require(len(environment_raw) <= 16 * 1024 * 1024, "application environment exceeds its launch-binding bound")
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
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for index in range(3):
                raw_line = stream.readline(2 * 1024 * 1024 + 1)
                require(raw_line and raw_line.endswith(b"\n") and len(raw_line) <= 2 * 1024 * 1024, f"SourceV5 pressure event prefix line {index} is missing or oversized")
                value = _read_json_raw(raw_line, f"SourceV5 pressure event prefix line {index}")
                require(raw_line == canonical_bytes(value), f"SourceV5 pressure event prefix line {index} is not canonical")
                records.append(value)
        after = os.fstat(descriptor)
        after_path = events_path.lstat()
        fingerprint = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(fingerprint(before) == fingerprint(after) == fingerprint(after_path), "SourceV5 pressure events changed while checking their durable prefix")
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


def _validate_pressure_proof(artifact_dir: Path, audit: dict[str, Any]) -> dict[str, Any]:
    pressure_info = audit["source"].get("pressure_recipe")
    require(type(pressure_info) is dict, "SourceV5 pressure proof is missing its frozen recipe")
    pressure_dir = artifact_dir / "pressure"
    require(pressure_dir.resolve(strict=True) == pressure_dir, "pressure artifact directory is a symlink or alias")
    expected = {"recipe": pressure_info["recipe_sha256"], **_pressure_output_hashes(pressure_dir)}
    _require_source_v5_pressure_prefix(pressure_dir, pressure_info, expected["ready"])
    try:
        proof = pressure_info["reader"].verify_pressure(
            Path(audit["recipe"]["pressure"]["recipe"]["path"]),
            pressure_info["recipe_sha256"], pressure_dir, expected,
        )
    except (OSError, TypeError, ValueError, KeyError) as error:
        raise SoakReadbackError(f"captured pressure readback rejected its raw process-bound artifacts: {error}") from error
    condition = audit["recipe"]["qualification"]["pressure_condition"]
    require(proof["sample_count"] >= condition["readiness_thresholds"]["minimum_ready_samples"], "pressure proof has fewer measured ready samples than SourceV5 requires")
    require(proof["application_overlap_nanoseconds"] >= condition["readiness_thresholds"]["minimum_overlap_seconds"] * 1_000_000_000, "pressure proof overlap is below SourceV5 readiness requirement")
    proof_raw = canonical_bytes(proof)
    proof_path = artifact_dir / "pressure-readback.json"
    if proof_path.exists():
        existing, existing_sha, existing_raw = read_json(proof_path, "external pressure validation proof", MAX_RECEIPT_BYTES)
        require(existing_raw == proof_raw, "saved external pressure proof differs from the captured independent validator")
        return {"proof": existing, "raw_sha256": existing_sha}
    proof_sha = _write_exclusive_json(proof_path, proof)
    return {"proof": proof, "raw_sha256": proof_sha}


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
    if pressure_exit is not None and app_process.poll() is None:
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


def _wait_pressure_workers_gone(sessions: dict[tuple[str, int | None], dict[str, Any]], deadline: float) -> bool:
    while time.monotonic() < deadline:
        _reap_adopted_pressure_workers(sessions)
        if all(_same_pressure_worker(record) is None for record in sessions.values()):
            return True
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    _reap_adopted_pressure_workers(sessions)
    return all(_same_pressure_worker(record) is None for record in sessions.values())


def _cleanup_owned_pressure_workers(
    sessions: dict[tuple[str, int | None], dict[str, Any]], term_seconds: int, kill_seconds: int,
) -> bool:
    if not sessions:
        return True
    for record in sessions.values():
        _signal_owned_pressure_worker(record, signal.SIGTERM)
    term_deadline = time.monotonic() + term_seconds
    if _wait_pressure_workers_gone(sessions, term_deadline):
        return True
    for record in sessions.values():
        _signal_owned_pressure_worker(record, signal.SIGKILL)
    kill_deadline = time.monotonic() + kill_seconds
    return _wait_pressure_workers_gone(sessions, kill_deadline)


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


def _stop_pressure_session(
    process: subprocess.Popen[bytes], driver_start_ticks: int | None, driver_path: Path,
    recipe_sha256: str, schedule: dict[str, Any], sessions: dict[tuple[str, int | None], dict[str, Any]],
    expected_nonce: str | None = None,
    excluded_child_identities: set[tuple[int, int]] | None = None,
    ownership_event_path: Path | None = None,
) -> None:
    _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
    if process.poll() is not None:
        require(
            _cleanup_owned_pressure_workers(sessions, schedule["term_deadline_seconds"], schedule["kill_deadline_seconds"]),
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
        _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
        try:
            process.wait(timeout=min(0.1, max(0.01, cleanup_deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
    if process.poll() is None:
        _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
        cleaned = _cleanup_owned_pressure_workers(sessions, schedule["term_deadline_seconds"], schedule["kill_deadline_seconds"])
        _signal_owned_pressure_driver(process, signal.SIGKILL, driver_start_ticks)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as error:
            raise SoakReadbackError("pressure driver remained alive after its frozen cleanup budgets") from error
        require(cleaned, "authenticated pressure workers remained alive after their frozen TERM/KILL budgets")
    else:
        _capture_pressure_worker_sessions(process.pid, driver_start_ticks, driver_path, recipe_sha256, schedule, sessions, expected_nonce, excluded_child_identities, ownership_event_path)
        require(
            _cleanup_owned_pressure_workers(sessions, schedule["term_deadline_seconds"], schedule["kill_deadline_seconds"]),
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
) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + pressure_recipe["schedule"]["startup_deadline_seconds"]
    last_error: BaseException | None = None
    diagnostic_stderr = stderr_path or ready_path.parent / "pressure-stderr.log"
    while time.monotonic() < deadline:
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


def command_launch_v2(args: argparse.Namespace, audit: dict[str, Any], preflight: dict[str, Any], output_dir: Path) -> int:
    descriptor = audit["launch_descriptor"]
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    require(command == descriptor["argv"], "actual external-pressure candidate command/argv differs from the preflighted launch descriptor")
    require(descriptor["launch_enabled"] is True, "external-pressure launch descriptor is disabled")
    expected_app_timeout = audit["source"]["application_supervision"]["application_wall_timeout_seconds"]
    require(args.timeout_seconds == expected_app_timeout == descriptor["application_wall_timeout_seconds"], "external-pressure app timeout differs from the independently derived complete wall bound")
    require(args.term_grace_seconds == 1.5, "external-pressure runner TERM grace differs from the frozen app wall-bound formula")
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
    pressure_stdout = output_dir / "pressure-driver.stdout.log"
    pressure_stderr = output_dir / "pressure-driver.stderr.log"
    signal_handlers, supervisor_signal = _install_external_supervisor_signal_handlers()
    pressure_out_fd = -1
    pressure_err_fd = -1
    pressure_process: subprocess.Popen[bytes] | None = None
    pressure_start_ticks: int | None = None
    pressure_started_at: float | None = None
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

        def finish_external_interruption(signum: int) -> int:
            status = _write_external_supervisor_interruption(
                output_dir, audit, signum, pressure_process, pressure_start_ticks,
                application_cleanup, pressure_cleanup,
            )
            if application_cleanup not in ("not_started", "verified") or pressure_cleanup not in ("not_started", "verified"):
                raise SoakReadbackError(
                    f"external signal {signum} was recorded, but cleanup is {application_cleanup=} {pressure_cleanup=}"
                )
            return status

        def stop_pressure_session() -> None:
            nonlocal pressure_stopped, pressure_cleanup
            if pressure_process is None or pressure_stopped:
                return
            pressure_cleanup = "unverified"
            try:
                _stop_pressure_session(
                    pressure_process, pressure_start_ticks, driver_path,
                    descriptor["pressure_recipe_sha256"], pressure_recipe["schedule"], pressure_workers,
                    audit["identity"]["nonce"],
                    excluded_child_identities=set() if application_identity is None else {application_identity},
                    ownership_event_path=pressure_dir / "events.jsonl",
                )
            except BaseException:
                pressure_cleanup = "failed"
                pressure_stopped = True
                raise
            pressure_cleanup = "verified"
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

        _ready, ready_sha = _wait_pressure_ready(
            pressure_process, Path(descriptor["pressure_ready_path"]), pressure_recipe,
            descriptor["pressure_recipe_sha256"], descriptor["pressure_condition_sha256"],
            capture_workers=capture_pressure_workers,
            stderr_path=pressure_stderr,
            interrupt_check=check_supervisor_interruption,
        )
        check_supervisor_interruption()
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
            actual_binding_sha = _atomic_json_publish(Path(descriptor["pressure_launch_path"]), binding)
            require(actual_binding_sha == hashlib.sha256(canonical_bytes(binding)).hexdigest(), "atomically published pressure launch record digest differs")

        def monitor_pressure(app_process: subprocess.Popen[bytes]) -> None:
            check_supervisor_interruption()
            capture_pressure_workers()
            if pressure_process is not None:
                _require_pressure_live_while_application_runs(pressure_process, app_process, pressure_stderr)

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
                    (Path(descriptor["terminal_path"]), preflight["terminal_budget_bytes"]),
                    (Path(descriptor["samples_path"]), preflight["sample_budget_bytes"]),
                )
            ),
            environment=descriptor["environment"],
            cwd=Path(descriptor["cwd"]),
            expected_executable_sha256=descriptor["binary_sha256"],
            return_details=True,
            on_started=bind_started_process,
            monitor=monitor_pressure,
            on_signal=record_inner_signal,
            on_cleanup=record_application_cleanup,
            timeout_from_before_popen=True,
            timeout_includes_cleanup=True,
        )
        require(type(details) is dict, "external-pressure soak supervisor omitted its parent process receipt")
        require(application_cleanup == "verified", "application process cleanup did not complete successfully")
        launch_receipt = _launch_receipt_value(details, audit, preflight)
        launch_receipt_sha = _write_exclusive_json(output_dir / "soak-launch.json", launch_receipt)
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
            while pressure_process.poll() is None and time.monotonic() < pressure_deadline:
                check_supervisor_interruption()
                capture_pressure_workers()
                try:
                    pressure_process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
            if pressure_process.poll() is None:
                stop_pressure_session()
                raise SoakReadbackError("pressure driver did not finish within its frozen process deadline")
            capture_pressure_workers()
        check_supervisor_interruption()
        if pressure_process.poll() == 0:
            require(set(pressure_workers) == _expected_pressure_worker_keys(pressure_recipe["schedule"]), "pressure driver exited without every frozen worker session having been captured")
            require(_wait_pressure_workers_gone(pressure_workers, time.monotonic() + 1.0), "pressure driver exited before captured worker sessions were gone")
            pressure_cleanup = "verified"
        if pressure_process.poll() != 0:
            raise SoakReadbackError(f"pressure driver exited {pressure_process.returncode}; stderr tail: {_tail_text(pressure_stderr)}")
        proof = _validate_pressure_proof(output_dir, audit)
        check_supervisor_interruption()
        print(json.dumps({
            "exit_code": details["status"],
            "launch_receipt_sha256": launch_receipt_sha,
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
