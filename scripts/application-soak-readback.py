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
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Iterator


RECIPE_SCHEMA = "allocatbelt.application-soak-parent-recipe.v1"
PREFLIGHT_SCHEMA = "allocatbelt.application-soak-preflight.v2"
POSTFLIGHT_SCHEMA = "allocatbelt.application-soak-postflight.v2"
LAUNCH_SCHEMA = "allocatbelt.application-soak-launch.v1"
RESULT_SCHEMA = "allocatbelt.application-soak-readback.v1"
SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v4"
SOURCE_INVENTORY_SCHEMA = "allocatbelt.application-source-inventory.v1"
SOURCE_INVENTORY_RELATIVE_PATH = "scripts/application-source-inventory.py"
SOURCE_INVENTORY_MODULE_SHA256 = "09557087a64e83bc81e4116f8e8f6b59e42a59beb500108e57d66942bd05f950"
POLICY_SCHEMA = "allocatbelt.application-fixed-policy-artifact.v1"
CALIBRATION_SCHEMA = "allocatbelt.resource-domain-calibration.v1"
RUNTIME_SOAK_SCHEMA = "allocatbelt.runtime-soak.v1"
RING_SCHEMA = "allocatbelt-app-oracle-v2"
TERMINAL_SCHEMA = "allocatbelt.runtime-soak-terminals.v1"

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
    require(type(workers_by_profile) is dict, "fixed policy omits its worker map")
    workers = workers_by_profile.get("oversubscribed" if profile == "oversubscribed" else "ordinary")
    workers = uint(workers, "fixed worker count", positive=True)
    require(workers == (2 if profile == "oversubscribed" else 4), "fixed policy worker count differs from the soak profile contract")
    workloads = policy.get("workloads")
    require(type(workloads) is dict and type(workloads.get("mixed")) is dict, "fixed policy omits mixed workload limits")
    mixed = workloads["mixed"]
    domain = exact_object(mixed.get("domain_ceiling"), set(DOMAINS), "mixed domain ceiling")
    scope = exact_object(mixed.get("scope_limits"), {"managed_memory_limit", "disk_operation_limit", "network_operation_limit"}, "mixed scope limits")
    require(domain == {
        "cpu": workers,
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
    }


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


def _validate_artifacts(
    artifact_dir: Path,
    audit: dict[str, Any],
) -> dict[str, Any]:
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
) -> int | dict[str, Any]:
    """Run one child in a separate process group and reap it on timeout/signal."""
    require(command and all(type(arg) is str for arg in command), "launch command is malformed")
    cpu_ids = _parse_cpu_set(cpu_set)
    require(0 < timeout_seconds <= 14_400 and 0 < term_grace_seconds <= 60, "launch timeout is outside its finite bounds")
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
        deadline = time.monotonic() + timeout_seconds
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
            # Always clean the process group, even if its leader exited while
            # a descendant still holds the original group ID.
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
