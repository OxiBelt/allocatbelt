#!/usr/bin/env python3
"""Run a finite, externally measured CPU, block-I/O, and IPv4 loopback load.

The driver is deliberately standalone. It freezes prospective conditions,
performs a finite contention calibration, or runs one bounded pressure session
against one nonce-bound application process. It does not launch an application
or make a performance decision.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from collections import deque
import hashlib
import json
import mmap
import os
import re
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any


REQUEST_SCHEMA = "allocatbelt.application-pressure-request.v1"
CALIBRATION_SCHEMA = "allocatbelt.application-pressure-contention-calibration.v1"
RECIPE_SCHEMA = "allocatbelt.application-pressure-recipe.v1"
LAUNCH_SCHEMA = "allocatbelt.application-pressure-launch-binding.v1"
PROCESS_BINDING_SCHEMA = "allocatbelt.application-pressure-process-binding.v1"
EVENT_SCHEMA = "allocatbelt.application-pressure-event.v1"
RUN_SCHEMA = "allocatbelt.application-pressure-run.v1"
READY_SCHEMA = "allocatbelt.application-pressure-ready.v1"

DRIVER_PATH = Path(__file__).resolve()
READER_PATH = DRIVER_PATH.with_name("application-pressure-readback.py")
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_CALIBRATION_BYTES = 64 * 1024 * 1024
MAX_RECIPE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_EVENT_LINE_BYTES = 2 * 1024 * 1024
EVENT_TERMINAL_RESERVE_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_FAILURE_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_POLICY_BYTES = 8 * 1024 * 1024
MAX_APP_BINARY_BYTES = 1024 * 1024 * 1024
MAX_SCRATCH_BYTES = 1024 * 1024 * 1024
MAX_DURATION_SECONDS = 12000
MAX_CALIBRATION_SECONDS = 120
MAX_SAMPLES = 120000
MAX_CPU_WORKERS = 64
MAX_PATH_BYTES = 4096
MAX_WORKER_STDERR_RAW_BYTES = 8192
BLOCK_BYTES = 4096
U64_MAX = (1 << 64) - 1
PRESSURE_IO_SCHEMA = "allocatbelt.application-pressure-io-window.v1"
_WORKER_STOP_REQUESTED = False


class PressureError(ValueError):
    """A malformed request, unsupported host, or failed bounded pressure run."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PressureError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise PressureError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_object(value: object) -> str:
    return digest_bytes(canonical_bytes(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PressureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise PressureError(f"non-finite JSON number is forbidden: {value}")


def parse_object(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its {maximum}-byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PressureError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must be a JSON object")
    return value


def exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected shape")
    return value


def string(value: object, label: str, maximum: int = 4096) -> str:
    require(type(value) is str and 0 < len(value) <= maximum, f"{label} must be a bounded string")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), f"{label} contains a control character")
    return value


def token(value: object, label: str, maximum: int = 128) -> str:
    result = string(value, label, maximum)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", result) is not None, f"{label} is malformed")
    return result


def uint(value: object, label: str, *, positive: bool = False, maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} must be a finite unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def sha256(value: object, label: str) -> str:
    result = string(value, label, 64)
    require(re.fullmatch(r"[0-9a-f]{64}", result) is not None, f"{label} must be a lowercase SHA-256 digest")
    return result


def absolute_path(value: object, label: str) -> Path:
    raw = string(value, label, MAX_PATH_BYTES)
    path = Path(raw)
    require(path.is_absolute() and "\x00" not in raw, f"{label} must be an absolute path")
    require(str(path) == raw and ".." not in PurePosixPath(raw).parts, f"{label} must be normalized")
    return path


def _stat_key(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    try:
        require(path.resolve(strict=True) == path, f"{label} path traverses a symlink or alias")
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PressureError(f"cannot safely open {label}: {error}") from error
    try:
        before_fd = os.fstat(descriptor)
        require(stat.S_ISREG(before_fd.st_mode), f"{label} descriptor is not regular")
        require(_stat_key(before_fd) == _stat_key(before_path), f"{label} changed while opening")
        require(0 <= before_fd.st_size <= maximum, f"{label} exceeds its finite byte bound")
        chunks: list[bytes] = []
        count = 0
        while count < before_fd.st_size:
            block = os.read(descriptor, min(1024 * 1024, before_fd.st_size - count))
            require(bool(block), f"{label} was truncated during its stable read")
            chunks.append(block)
            count += len(block)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before_fd) == _stat_key(after_fd) == _stat_key(after_path), f"{label} changed during its stable read")
        require(count == before_fd.st_size, f"{label} size changed during its stable read")
        raw = b"".join(chunks)
        return raw, digest_bytes(raw)
    finally:
        os.close(descriptor)


def hash_stable(path: Path, label: str, maximum: int) -> tuple[int, str]:
    try:
        require(path.resolve(strict=True) == path, f"{label} path traverses a symlink or alias")
        path_info = path.lstat()
        require(stat.S_ISREG(path_info.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise PressureError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(path_info), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its hard byte cap")
        digest = hashlib.sha256()
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(block, f"{label} was truncated during readback")
            digest.update(block)
            count += len(block)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before) == _stat_key(after_fd) == _stat_key(after_path) and count == before.st_size, f"{label} changed during readback")
        return count, digest.hexdigest()
    finally:
        os.close(descriptor)


def verify_canonical_json(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], bytes, str]:
    raw, raw_sha256 = read_stable(path, label, maximum)
    value = parse_object(raw, label, maximum)
    require(raw == canonical_bytes(value), f"{label} is not canonical JSON")
    return value, raw, raw_sha256


def safe_directory(path: Path, label: str, *, create: bool = False) -> Path:
    require(path.is_absolute(), f"{label} must be absolute")
    if create:
        try:
            path.mkdir(mode=0o700, parents=False, exist_ok=False)
        except OSError as error:
            raise PressureError(f"cannot create fresh {label}: {error}") from error
    try:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode), f"{label} must be a real nonsymlink directory")
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise PressureError(f"{label} is unavailable: {error}") from error
    require(resolved == path, f"{label} path traverses a symlink or alias")
    return path


def safe_existing_directory(path: Path, label: str) -> os.stat_result:
    safe_directory(path, label)
    try:
        info = path.stat()
    except OSError as error:
        raise PressureError(f"cannot stat {label}: {error}") from error
    return info


def safe_write_new(path: Path, raw: bytes, label: str, *, maximum: int) -> str:
    require(len(raw) <= maximum, f"{label} exceeds its bounded size")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise PressureError(f"cannot create fresh {label}: {error}") from error
    try:
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            require(count > 0, f"short write while creating {label}")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest_bytes(raw)


def _read_small_text(path: Path, label: str, maximum: int = 1024 * 1024) -> str:
    raw, _ = read_stable(path, label, maximum)
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise PressureError(f"{label} is not UTF-8 text") from error


def _proc_stat(pid: int) -> dict[str, Any]:
    path = Path("/proc") / str(pid) / "stat"
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PressureError(f"cannot read process {pid} stat: {error}") from error
    require(len(raw) <= 65536, f"process {pid} stat is oversized")
    try:
        text = raw.decode("ascii").strip()
    except UnicodeError as error:
        raise PressureError(f"process {pid} stat is not ASCII") from error
    closing = text.rfind(")")
    require(closing > 0, f"process {pid} stat has malformed command framing")
    head = text[:text.find("(")].strip()
    tail = text[closing + 1:].strip().split()
    require(head == str(pid) and len(tail) >= 20, f"process {pid} stat has malformed fields")
    # Fields after comm start at field 3; starttime is field 22.
    start_ticks = uint(int(tail[19]), f"process {pid} start_ticks", positive=True)
    return {"pid": pid, "state": tail[0], "start_ticks": start_ticks}


def _pid_exists(pid: int, start_ticks: int) -> bool:
    try:
        observed = _proc_stat(pid)
    except PressureError:
        return False
    return observed["start_ticks"] == start_ticks and observed["state"] != "Z"


def _proc_link(pid: int, name: str) -> str:
    try:
        result = os.readlink(f"/proc/{pid}/{name}")
    except OSError as error:
        raise PressureError(f"cannot read process {pid} {name}: {error}") from error
    return string(result, f"process {pid} {name}", MAX_PATH_BYTES)


def _proc_net_namespace(pid: int) -> int:
    try:
        info = os.stat(f"/proc/{pid}/ns/net")
    except OSError as error:
        raise PressureError(f"cannot stat process {pid} network namespace: {error}") from error
    return uint(info.st_ino, f"process {pid} network namespace inode", positive=True)


def _affinity(pid: int = 0) -> list[int]:
    try:
        result = sorted(os.sched_getaffinity(pid))
    except (OSError, AttributeError) as error:
        raise PressureError(f"cannot read CPU affinity for pid {pid}: {error}") from error
    require(result and len(result) <= 4096, f"CPU affinity for pid {pid} is empty or exceeds its finite host cap")
    return result


def _validate_cpu_list(value: object, label: str) -> list[int]:
    require(type(value) is list and 1 <= len(value) <= MAX_CPU_WORKERS, f"{label} must contain 1..{MAX_CPU_WORKERS} CPUs")
    result = [uint(item, f"{label} item", maximum=65535) for item in value]
    require(result == sorted(set(result)), f"{label} must be sorted and unique")
    return result


def _mount_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _mount_record(path: Path, st_dev: int) -> dict[str, Any]:
    try:
        raw = Path("/proc/self/mountinfo").read_bytes()
    except OSError as error:
        raise PressureError(f"cannot read mountinfo: {error}") from error
    require(len(raw) <= 16 * 1024 * 1024, "mountinfo exceeds its finite bound")
    device = f"{os.major(st_dev)}:{os.minor(st_dev)}"
    target = str(path)
    candidates: list[dict[str, Any]] = []
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise PressureError("mountinfo is not UTF-8") from error
    for line in lines:
        parts = line.split(" ")
        if "-" not in parts:
            continue
        separator = parts.index("-")
        if separator < 6 or len(parts) < separator + 4:
            continue
        mountpoint = _mount_unescape(parts[4])
        mount_device = parts[2]
        if mount_device != device:
            continue
        if target == mountpoint or target.startswith(mountpoint.rstrip("/") + "/"):
            candidates.append({
                "mount_id": uint(int(parts[0]), "mount id", positive=True),
                "parent_mount_id": uint(int(parts[1]), "parent mount id", positive=True),
                "device": mount_device,
                "root": _mount_unescape(parts[3]),
                "mountpoint": mountpoint,
                "mount_options": parts[5].split(","),
                "filesystem": parts[separator + 1],
                "source": _mount_unescape(parts[separator + 2]),
                "super_options": parts[separator + 3].split(","),
            })
    require(candidates, f"no mountinfo record binds {target} to device {device}")
    candidates.sort(key=lambda item: len(item["mountpoint"]), reverse=True)
    return candidates[0]


def _sysfs_backing_chain(device: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    pending = [device]
    seen: set[str] = set()
    while pending:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)
        node = Path("/sys/dev/block") / current
        try:
            resolved = node.resolve(strict=True)
            dev_text = (resolved / "dev").read_text(encoding="ascii").strip()
            name = resolved.name
        except OSError as error:
            raise PressureError(f"block device {current} has no verifiable sysfs backing chain: {error}") from error
        require(dev_text == current, f"sysfs device identity mismatch for {current}")
        item: dict[str, Any] = {"device": current, "name": name, "sysfs_path": str(resolved)}
        partition_file = resolved / "partition"
        if partition_file.exists():
            try:
                item["partition"] = uint(int(partition_file.read_text(encoding="ascii").strip()), "partition", positive=True)
                parent = resolved.parent
                parent_dev = (parent / "dev").read_text(encoding="ascii").strip()
                if re.fullmatch(r"[0-9]+:[0-9]+", parent_dev):
                    pending.append(parent_dev)
            except (OSError, ValueError) as error:
                raise PressureError(f"cannot follow partition backing device {current}: {error}") from error
        slaves_dir = resolved / "slaves"
        if slaves_dir.is_dir():
            try:
                for slave in sorted(slaves_dir.iterdir(), key=lambda value: value.name):
                    dev_text = (slave.resolve(strict=True) / "dev").read_text(encoding="ascii").strip()
                    require(re.fullmatch(r"[0-9]+:[0-9]+", dev_text) is not None, "malformed block slave device")
                    pending.append(dev_text)
            except OSError as error:
                raise PressureError(f"cannot read block slaves for {current}: {error}") from error
        result.append(item)
        require(len(result) <= 32, "block backing chain exceeds 32 devices")
    return sorted(result, key=lambda item: item["device"])


def _storage_record(path: Path, label: str) -> dict[str, Any]:
    info = safe_existing_directory(path, label)
    device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
    mount = _mount_record(path, info.st_dev)
    require(mount["filesystem"] not in ("tmpfs", "ramfs", "overlay"), f"{label} is on unsupported in-memory/overlay filesystem {mount['filesystem']}")
    chain = _sysfs_backing_chain(device)
    return {
        "path": str(path),
        "device": device,
        "mount": mount,
        "backing_chain": chain,
        "filesystem_type": mount["filesystem"],
        "tmpfs": False,
    }


def _loopback_route() -> dict[str, Any]:
    executable = shutil.which("ip")
    require(executable is not None, "iproute2 `ip` is required to verify the IPv4 loopback route")
    try:
        completed = subprocess.run(
            [executable, "-j", "-4", "route", "get", "127.0.0.1"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=3, check=False, close_fds=True, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PressureError(f"cannot resolve the fixed IPv4 loopback route: {error}") from error
    require(completed.returncode == 0 and len(completed.stdout) <= 65536, "fixed IPv4 loopback route query failed")
    try:
        value = json.loads(completed.stdout.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PressureError("iproute2 returned malformed JSON for IPv4 loopback") from error
    require(type(value) is list and len(value) == 1 and type(value[0]) is dict, "IPv4 loopback route response is not singular")
    route = value[0]
    require(route.get("dst") == "127.0.0.1" and route.get("dev") == "lo", "127.0.0.1 does not resolve through lo")
    source = route.get("prefsrc", route.get("src"))
    require(source == "127.0.0.1", "IPv4 loopback route has a non-loopback source")
    stable_route = {"dst": route["dst"], "dev": route["dev"], "source": source}
    try:
        lo_index = socket.if_nametoindex("lo")
        lo_info = Path("/sys/class/net/lo/ifindex").read_text(encoding="ascii").strip()
    except (OSError, AttributeError) as error:
        raise PressureError(f"cannot verify the shared-kernel lo interface: {error}") from error
    require(int(lo_info) == lo_index and lo_index > 0, "lo interface identity is inconsistent")
    return {
        "address_family": "AF_INET",
        "destination": "127.0.0.1",
        "source": "127.0.0.1",
        "interface": "lo",
        "ifindex": lo_index,
        "route": stable_route,
        "network_namespace_inode": uint(os.stat("/proc/self/ns/net").st_ino, "network namespace inode", positive=True),
        "shared_kernel": True,
        "physical_nic_claimed": False,
        "claim": "ipv4_loopback_shared_kernel_only",
    }


def _host_facts(cpu_affinity: list[int], app_affinity: list[int], storage_paths: list[Path]) -> dict[str, Any]:
    allowed = _affinity(0)
    require(set(cpu_affinity) <= set(allowed), "pressure CPU affinity exceeds the driver's allowed CPU set")
    require(set(app_affinity) <= set(allowed), "application CPU affinity exceeds the driver's allowed CPU set")
    storage = [_storage_record(path, f"application I/O path {index}") for index, path in enumerate(storage_paths)]
    first = storage[0]
    require(all(item["device"] == first["device"] and item["mount"]["mount_id"] == first["mount"]["mount_id"] for item in storage), "application I/O paths do not share one exact backing mount/device")
    return {
        "kernel_release": os.uname().release,
        "boot_id_sha256": digest_bytes(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()),
        "allowed_cpu_affinity": allowed,
        "pressure_cpu_affinity": cpu_affinity,
        "application_cpu_affinity": app_affinity,
        "application_storage": storage,
        "pressure_scratch": None,
        "network": _loopback_route(),
    }


def _file_spec(value: object, label: str) -> dict[str, Any]:
    item = exact_object(value, {"path", "sha256"}, label)
    path = absolute_path(item["path"], f"{label} path")
    expected = sha256(item["sha256"], f"{label} SHA-256")
    maximum = MAX_SOURCE_BYTES if "source" in label else MAX_POLICY_BYTES
    _, actual = read_stable(path, label, maximum)
    require(actual == expected, f"{label} raw SHA-256 differs from the request")
    return {"path": str(path), "raw_sha256": actual}


def _binary_spec(value: object) -> dict[str, Any]:
    item = exact_object(value, {"path", "sha256"}, "application binary")
    path = absolute_path(item["path"], "application binary path")
    expected = sha256(item["sha256"], "application binary SHA-256")
    _, actual = read_stable(path, "application binary", MAX_APP_BINARY_BYTES)
    require(actual == expected, "application binary raw SHA-256 differs from the request")
    try:
        info = path.stat()
    except OSError as error:
        raise PressureError(f"cannot stat application binary: {error}") from error
    require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111), "application binary must be a regular executable file")
    return {"path": str(path), "raw_sha256": actual, "mode": stat.S_IMODE(info.st_mode), "size": info.st_size}


def _schedule(value: object, *, calibration: bool = False) -> dict[str, Any]:
    keys = {
        "seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds",
        "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds",
        "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points",
        "pressure_cpu_affinity", "application_cpu_affinity", "disk_bytes_per_second",
        "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes",
    }
    schedule = exact_object(value, keys, "pressure schedule")
    seed = uint(schedule["seed"], "schedule seed", positive=True, maximum=(1 << 63) - 1)
    duration = uint(schedule["duration_seconds"], "pressure duration", positive=True, maximum=MAX_DURATION_SECONDS)
    interval = uint(schedule["sample_interval_ms"], "sample interval", positive=True, maximum=1000)
    require(interval >= 100 and duration * 1000 % interval == 0, "sample interval must be 100..1000ms and divide the total duration exactly")
    samples = duration * 1000 // interval
    require(samples <= MAX_SAMPLES, "pressure schedule exceeds the finite sample bound")
    startup = uint(schedule["startup_deadline_seconds"], "startup deadline", positive=True, maximum=10)
    total = uint(schedule["total_deadline_seconds"], "total deadline", positive=True, maximum=14400)
    term = uint(schedule["term_deadline_seconds"], "TERM deadline", positive=True, maximum=30)
    kill = uint(schedule["kill_deadline_seconds"], "KILL deadline", positive=True, maximum=15)
    overlap = uint(schedule["minimum_overlap_seconds"], "minimum application overlap", positive=True, maximum=MAX_DURATION_SECONDS)
    ready_windows = uint(schedule["startup_ready_windows"], "startup readiness windows", positive=True, maximum=10)
    require(overlap <= duration and ready_windows * interval <= duration * 1000, "readiness/overlap exceeds the finite pressure horizon")
    require(total >= startup + duration + term + kill, "total deadline does not cover startup, pressure, TERM and KILL deadlines")
    duty = uint(schedule["cpu_duty_basis_points"], "CPU duty", positive=True, maximum=10000)
    require(100 <= duty <= 10000, "CPU duty must be in 1..100 percent")
    pressure_affinity = _validate_cpu_list(schedule["pressure_cpu_affinity"], "pressure CPU affinity")
    app_affinity = _validate_cpu_list(schedule["application_cpu_affinity"], "application CPU affinity")
    disk_rate = uint(schedule["disk_bytes_per_second"], "disk write rate", positive=True, maximum=512 * 1024 * 1024)
    disk_target_per_window = disk_rate * interval // 1000
    require(disk_target_per_window >= BLOCK_BYTES, "disk rate cannot produce one measured block per sample interval")
    disk_actual_per_window = ((disk_target_per_window + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES
    require(disk_actual_per_window * samples <= 64 * 1024**3, "rounded per-window pressure writes exceed the 64 GiB schedule bound")
    scratch_bytes = uint(schedule["scratch_file_bytes"], "scratch file size", positive=True, maximum=MAX_SCRATCH_BYTES)
    require(scratch_bytes >= BLOCK_BYTES and scratch_bytes % BLOCK_BYTES == 0, "scratch file must be block aligned and at least 4 KiB")
    net_rate = uint(schedule["network_requests_per_second"], "loopback request rate", positive=True, maximum=100000)
    require(net_rate * interval >= 1000, "loopback request rate cannot produce one measured request per sample interval")
    payload = uint(schedule["network_payload_bytes"], "loopback payload size", positive=True, maximum=65536)
    require(payload >= 16, "loopback payload must be at least 16 bytes")
    require(net_rate * payload * 2 <= 64 * 1024**2 and net_rate * payload * 2 * duration <= 64 * 1024**3, "cumulative loopback traffic exceeds its finite byte/rate bound")
    normalized = {
        "seed": seed,
        "duration_seconds": duration,
        "sample_interval_ms": interval,
        "startup_deadline_seconds": startup,
        "total_deadline_seconds": total,
        "term_deadline_seconds": term,
        "kill_deadline_seconds": kill,
        "minimum_overlap_seconds": overlap,
        "startup_ready_windows": ready_windows,
        "cpu_duty_basis_points": duty,
        "pressure_cpu_affinity": pressure_affinity,
        "application_cpu_affinity": app_affinity,
        "disk_bytes_per_second": disk_rate,
        "scratch_file_bytes": scratch_bytes,
        "network_requests_per_second": net_rate,
        "network_payload_bytes": payload,
    }
    if calibration:
        require(3 <= duration <= MAX_CALIBRATION_SECONDS, "contention calibration must collect 3..120 seconds")
        require(total <= 200, "contention calibration total deadline must not exceed 200 seconds")
    return normalized


def _artifact_budget(schedule: dict[str, Any], backing_chain: list[dict[str, Any]]) -> dict[str, int]:
    interval_ns = schedule["sample_interval_ms"] * 1_000_000
    minimum_interval_ns = interval_ns - max(1_000_000, interval_ns // 100)
    cpus = schedule["pressure_cpu_affinity"]
    cpu_max = U64_MAX
    maximum_aggregate_cpu = cpu_max * len(cpus)
    maximum_requests = (schedule["network_requests_per_second"] * schedule["sample_interval_ms"] + 999) // 1000 + 2
    maximum_rate = U64_MAX * 1_000_000_000 // minimum_interval_ns
    maximum_disk_rate = U64_MAX * 512 * 1_000_000_000 // minimum_interval_ns
    maximum_loopback_rate = maximum_requests * 1_000_000_000 // minimum_interval_ns
    maximum_disk_window = max(
        BLOCK_BYTES,
        ((schedule["disk_bytes_per_second"] * schedule["sample_interval_ms"] // 1000 + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES,
    )
    cpu_counters = [
        {
            "cpu": cpu,
            "total_ticks": cpu_max,
            "idle_ticks": cpu_max,
            "busy_ticks": cpu_max,
            "busy_basis_points": 10000,
        }
        for cpu in cpus
    ]
    cpu_generators = [
        {
            "cpu": cpu,
            "thread_cpu_time_ns": cpu_max,
            "spin_witness": cpu_max,
            "start_monotonic_ns": cpu_max,
            "end_monotonic_ns": cpu_max,
        }
        for cpu in cpus
    ]
    worker_io = {
        **{f"cpu:{cpu}": {"write_bytes_delta": cpu_max, "syscw_delta": cpu_max} for cpu in cpus},
        "disk": {"write_bytes_delta": cpu_max, "syscw_delta": cpu_max},
        "loopback": {"write_bytes_delta": cpu_max, "syscw_delta": cpu_max},
    }
    sample = {
        "schema": EVENT_SCHEMA,
        "kind": "sample",
        "sequence": MAX_SAMPLES - 1,
        "interval_start_monotonic_ns": cpu_max,
        "interval_end_monotonic_ns": cpu_max,
        "app_active": True,
        "cpu": {
            "per_cpu": cpu_counters,
            "total_ticks": maximum_aggregate_cpu,
            "idle_ticks": maximum_aggregate_cpu,
            "busy_basis_points": 10000,
        },
        "cpu_psi_delta_microseconds": cpu_max,
        "block": {
            "writes_completed": cpu_max,
            "sectors_written": cpu_max,
            "write_milliseconds": cpu_max,
            "io_milliseconds": cpu_max,
            "weighted_io_milliseconds": cpu_max,
            "in_flight": cpu_max,
            "write_bytes": cpu_max * 512,
        },
        "io_psi_delta_microseconds": cpu_max,
        "block_device_chain": backing_chain,
        "loopback_counters": {
            key: cpu_max for key in (
                "rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
                "tx_bytes", "tx_packets", "tx_errors", "tx_dropped",
            )
        },
        "loopback": {
            "schema": PRESSURE_IO_SCHEMA,
            "role": "loopback",
            "recipe_sha256": "f" * 64,
            "sequence": MAX_SAMPLES - 1,
            "start_monotonic_ns": cpu_max,
            "end_monotonic_ns": cpu_max,
            "requests_completed": maximum_requests,
            "bytes_on_wire": maximum_requests * schedule["network_payload_bytes"] * 2,
            "latency_histogram": [maximum_requests] * 64,
            "p99_upper_latency_nanoseconds": 1 << 63,
        },
        "pressure_generators": {
            "cpu": cpu_generators,
            "disk": {
                "write_bytes": maximum_disk_window,
                "write_mode": "o_direct",
                "fdatasync_count": 1,
                "fdatasync_time_nanoseconds": cpu_max,
                "start_monotonic_ns": cpu_max,
                "end_monotonic_ns": cpu_max,
            },
        },
        "worker_process_io": worker_io,
        "readiness": {
            "cpu_ready": True,
            "disk_ready": True,
            "loopback_ready": True,
            "all_ready": True,
            "cpu_busy_basis_points": 10000,
            "disk_write_bytes_per_second": maximum_disk_rate,
            "disk_queue_or_stall_microseconds": cpu_max * 1001,
            "loopback_requests_per_second": maximum_loopback_rate,
            "loopback_latency_p99_upper_nanoseconds": 1 << 63,
            "loopback_tx_bytes_per_second": maximum_rate,
            "loopback_rx_bytes_per_second": maximum_rate,
        },
    }
    maximum_sample_line_bytes = len(canonical_bytes(sample))
    require(maximum_sample_line_bytes <= MAX_EVENT_LINE_BYTES, "frozen sample row exceeds the independent reader line bound")
    sample_count = schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"]
    sample_events_bytes = sample_count * maximum_sample_line_bytes
    maximum_event_bytes = sample_events_bytes + EVENT_TERMINAL_RESERVE_BYTES
    require(maximum_event_bytes <= MAX_ARTIFACT_BYTES, "frozen pressure schedule exceeds the 512 MiB event and terminal-evidence budget")
    return {
        "sample_count": sample_count,
        "maximum_sample_line_bytes": maximum_sample_line_bytes,
        "sample_events_bytes": sample_events_bytes,
        "terminal_reserve_bytes": EVENT_TERMINAL_RESERVE_BYTES,
        "maximum_event_bytes": maximum_event_bytes,
    }


def _identity(value: object, *, calibration: bool = False) -> dict[str, Any]:
    item = exact_object(value, {"host_id", "run_id", "pair_id", "condition_id", "member", "nonce", "allocator", "executor"}, "pressure identity")
    host_id = token(item["host_id"], "host id")
    run_id = token(item["run_id"], "run id")
    pair_id = token(item["pair_id"], "pair id")
    condition_id = token(item["condition_id"], "condition id")
    member = token(item["member"], "pair member")
    nonce = string(item["nonce"], "process nonce", 32)
    require(re.fullmatch(r"[0-9a-f]{32}", nonce) is not None, "process nonce must be 32 lowercase hexadecimal characters")
    allocator = token(item["allocator"], "allocator")
    executor = token(item["executor"], "executor")
    return {
        "host_id": host_id, "run_id": run_id, "pair_id": pair_id,
        "condition_id": condition_id, "member": member, "nonce": nonce,
        "allocator": allocator, "executor": executor,
        "phase": "calibration" if calibration else "external_pressure",
    }


def _request(value: object, *, calibration: bool = False) -> dict[str, Any]:
    common_keys = {"schema", "identity", "files", "process", "storage", "schedule"}
    expected_keys = common_keys if calibration else common_keys | {"pressure_calibration", "readiness_thresholds"}
    request = exact_object(value, expected_keys, "pressure request")
    require(request["schema"] == REQUEST_SCHEMA, "unsupported pressure request schema")
    identity = _identity(request["identity"], calibration=calibration)
    schedule = _schedule(request["schedule"], calibration=calibration)
    process = exact_object(request["process"], {"executable_path", "application_tmpdir_path"}, "expected application process")
    executable_path = absolute_path(process["executable_path"], "expected application executable path")
    application_tmpdir = absolute_path(process["application_tmpdir_path"], "expected application TMPDIR")
    files = exact_object(request["files"], {"source_manifest", "application_binary", "policy", "application_capacity_calibration"}, "raw input files")
    source = _file_spec(files["source_manifest"], "source manifest")
    binary = _binary_spec(files["application_binary"])
    policy = _file_spec(files["policy"], "policy")
    capacity = _file_spec(files["application_capacity_calibration"], "application capacity calibration")
    require(binary["path"] == str(executable_path), "expected process executable path differs from the pinned application binary path")
    storage = exact_object(request["storage"], {"application_io_paths", "pressure_scratch_path", "output_minimum_free_bytes"}, "pressure storage")
    raw_io_paths = storage["application_io_paths"]
    require(type(raw_io_paths) is list and 1 <= len(raw_io_paths) <= 16, "application_io_paths must contain 1..16 exact application I/O directories")
    io_paths = [absolute_path(value, f"application I/O path {index}") for index, value in enumerate(raw_io_paths)]
    require(len({str(path) for path in io_paths}) == len(io_paths), "application I/O paths contain duplicates")
    require(application_tmpdir in io_paths, "application TMPDIR is not in the exact application I/O path set")
    scratch_path = absolute_path(storage["pressure_scratch_path"], "pressure scratch path")
    minimum_free = uint(storage["output_minimum_free_bytes"], "minimum free bytes", positive=True, maximum=1 << 40)
    pressure_calibration: dict[str, Any] | None = None
    thresholds: dict[str, Any] | None = None
    if not calibration:
        pressure_calibration = exact_object(request["pressure_calibration"], {"path", "sha256"}, "pressure contention calibration")
        pressure_path = absolute_path(pressure_calibration["path"], "pressure contention calibration path")
        pressure_sha = sha256(pressure_calibration["sha256"], "pressure contention calibration raw SHA-256")
        pressure_cal, pressure_raw, actual_pressure_sha = verify_canonical_json(pressure_path, "pressure contention calibration", MAX_CALIBRATION_BYTES)
        require(actual_pressure_sha == pressure_sha, "pressure contention calibration raw SHA-256 differs from request")
        _validate_calibration(pressure_cal, schedule, identity, source, policy, capacity)
        pressure_calibration = {"path": str(pressure_path), "raw_sha256": actual_pressure_sha}
        del pressure_raw
        thresholds = _validate_threshold_selection(request["readiness_thresholds"], pressure_cal)
    return {
        "identity": identity,
        "files": {
            "source_manifest": source,
            "application_binary": binary,
            "policy": policy,
            "application_capacity_calibration": capacity,
        },
        "process": {"executable_path": str(executable_path), "application_tmpdir_path": str(application_tmpdir)},
        "storage": {
            "application_io_paths": [str(path) for path in io_paths],
            "pressure_scratch_path": str(scratch_path),
            "output_minimum_free_bytes": minimum_free,
        },
        "schedule": schedule,
        "pressure_calibration": pressure_calibration,
        "readiness_thresholds": thresholds,
    }


def _threshold_keys() -> set[str]:
    return {
        "cpu_busy_min_basis_points",
        "disk_write_min_bytes_per_second",
        "disk_queue_or_stall_min_microseconds",
        "loopback_requests_min_per_second",
        "loopback_latency_p99_max_nanoseconds",
        "loopback_tx_min_bytes_per_second",
        "loopback_rx_min_bytes_per_second",
    }


def _calibration_material(calibration: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in calibration.items() if key != "calibration_sha256"}


def _validate_calibration(
    value: object, schedule: dict[str, Any], identity: dict[str, Any],
    source: dict[str, Any], policy: dict[str, Any], capacity: dict[str, Any],
) -> dict[str, Any]:
    calibration = exact_object(value, {
        "schema", "identity", "schedule_sha256", "raw_inputs", "driver_sha256", "host", "storage",
        "network", "worker_sessions", "samples", "summary", "suggested_readiness_thresholds",
        "worker_cleanup", "scratch_file_removed", "start_monotonic_ns", "finish_monotonic_ns", "deadlines",
        "calibration_sha256",
    }, "pressure contention calibration")
    require(calibration["schema"] == CALIBRATION_SCHEMA, "unsupported pressure contention calibration schema")
    calibration_identity = exact_object(calibration["identity"], {"host_id", "pair_id", "condition_id", "phase"}, "pressure calibration identity")
    require(calibration_identity["phase"] == "calibration" and calibration_identity["condition_id"] == identity["condition_id"] and calibration_identity["host_id"] == identity["host_id"] and calibration_identity["pair_id"] == identity["pair_id"], "pressure contention calibration belongs to a different host/pair/condition")
    require(calibration["schedule_sha256"] == digest_object(_pressure_profile(schedule)), "pressure contention calibration intensity differs from the frozen schedule")
    require(calibration["driver_sha256"] == _hash_script(DRIVER_PATH, "pressure driver"), "pressure calibration was produced by different driver bytes")
    cal_storage = exact_object(calibration["storage"], {"application_device", "mount_id", "backing_chain"}, "calibration storage identity")
    cal_host = exact_object(calibration["host"], {
        "kernel_release", "boot_id_sha256", "allowed_cpu_affinity", "pressure_cpu_affinity",
        "application_cpu_affinity", "application_storage", "pressure_scratch", "network",
    }, "calibration host identity")
    require(cal_host["network"] == calibration["network"], "pressure calibration host/network identity differs")
    require(calibration["raw_inputs"] == {
        "source_manifest_sha256": source["raw_sha256"],
        "policy_sha256": policy["raw_sha256"],
        "application_capacity_calibration_sha256": capacity["raw_sha256"],
    }, "pressure contention calibration raw input hashes differ or app-byte calibration was conflated")
    claimed = sha256(calibration["calibration_sha256"], "calibration self digest")
    require(claimed == digest_object(_calibration_material(calibration)), "pressure contention calibration digest is invalid")
    samples = calibration["samples"]
    require(type(samples) is list and len(samples) >= 3, "pressure contention calibration is sparse")
    for index, sample in enumerate(samples):
        _validate_calibration_sample(sample, schedule, index, cal_storage["backing_chain"])
    sessions = calibration["worker_sessions"]
    cleanup = calibration["worker_cleanup"]
    require(type(sessions) is list and len(sessions) == len(schedule["pressure_cpu_affinity"]) + 2 and type(cleanup) is list and len(cleanup) == len(sessions), "pressure calibration worker cleanup is sparse")
    sessions_by_key: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in sessions:
        worker = exact_object(item, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id"}, "calibration worker session")
        role = token(worker["role"], "calibration worker role", 16)
        cpu = uint(worker["cpu"], "calibration worker CPU", maximum=65535) if role == "cpu" else None
        require(role in ("cpu", "disk", "loopback") and (role != "cpu" or cpu in schedule["pressure_cpu_affinity"]), "calibration worker session has an unexpected role/CPU")
        pid = uint(worker["pid"], "calibration worker PID", positive=True, maximum=(1 << 31) - 1)
        start_ticks = uint(worker["start_ticks"], "calibration worker start ticks", positive=True)
        require(worker["pgid"] == pid and worker["session_id"] == pid and (role, cpu) not in sessions_by_key, "calibration worker session is not isolated or is duplicated")
        sessions_by_key[(role, cpu)] = {**worker, "pid": pid, "start_ticks": start_ticks}
    expected_sessions = {("cpu", cpu) for cpu in schedule["pressure_cpu_affinity"]} | {("disk", None), ("loopback", None)}
    require(set(sessions_by_key) == expected_sessions, "calibration worker sessions differ from frozen pressure resources")
    cleanup_by_key: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in cleanup:
        record = exact_object(item, {
            "role", "cpu", "pid", "start_ticks", "pgid", "session_id", "exit_code",
            "cleanup_started_monotonic_ns", "term_deadline_monotonic_ns", "kill_deadline_monotonic_ns",
            "term_error", "kill_error", "reap_error", "alive_after_cleanup",
            "term_sent_monotonic_ns", "kill_sent_monotonic_ns", "reaped_monotonic_ns", "stderr_output",
            "stderr_raw_base64", "stderr_raw_sha256", "stderr_raw_bytes", "stderr_raw_truncated", "stderr_read_error",
        }, "calibration worker cleanup")
        key = (record["role"], record["cpu"])
        require(key in sessions_by_key and key not in cleanup_by_key, "calibration cleanup repeats or invents a worker")
        session = sessions_by_key[key]
        require(all(record[name] == session[name] for name in ("pid", "start_ticks", "pgid", "session_id")), "calibration cleanup PID/start/session differs")
        raw_stderr = _validate_worker_stderr_capture(record, "calibration worker")
        require(_worker_exit_was_bounded(record) and record["alive_after_cleanup"] is False and all(record[name] is None for name in ("term_error", "kill_error", "reap_error")) and raw_stderr == b"", "calibration worker did not cleanly terminate and reap")
        cleanup_started = uint(record["cleanup_started_monotonic_ns"], "calibration cleanup start", positive=True)
        term_deadline = uint(record["term_deadline_monotonic_ns"], "calibration TERM deadline", positive=True)
        kill_deadline = uint(record["kill_deadline_monotonic_ns"], "calibration KILL deadline", positive=True)
        reaped = uint(record["reaped_monotonic_ns"], "calibration reap time", positive=True)
        require(term_deadline == cleanup_started + schedule["term_deadline_seconds"] * 1_000_000_000, "calibration TERM deadline differs from the frozen profile")
        if record["term_sent_monotonic_ns"] is not None:
            require(cleanup_started <= uint(record["term_sent_monotonic_ns"], "calibration TERM time", positive=True) <= term_deadline, "calibration TERM escalation missed its bound")
        if record["kill_sent_monotonic_ns"] is not None:
            killed = uint(record["kill_sent_monotonic_ns"], "calibration KILL time", positive=True)
            require(term_deadline <= killed <= kill_deadline, "calibration KILL escalation missed its bound")
        require(reaped <= kill_deadline, "calibration worker reap exceeded its KILL deadline")
        require(not _pid_exists(record["pid"], record["start_ticks"]), "calibration pressure worker is still alive")
        cleanup_by_key[key] = record
    require(set(cleanup_by_key) == expected_sessions and calibration["scratch_file_removed"] is True, "calibration omitted worker cleanup or scratch removal")
    start_ns = uint(calibration["start_monotonic_ns"], "calibration start", positive=True)
    finish_ns = uint(calibration["finish_monotonic_ns"], "calibration finish", positive=True)
    deadlines = exact_object(calibration["deadlines"], {"startup_seconds", "total_seconds", "term_seconds", "kill_seconds"}, "calibration deadlines")
    require(deadlines["startup_seconds"] == schedule["startup_deadline_seconds"] and deadlines["term_seconds"] == schedule["term_deadline_seconds"] and deadlines["kill_seconds"] == schedule["kill_deadline_seconds"], "pressure calibration startup/cleanup deadlines differ from the frozen profile")
    cal_duration_ns = len(samples) * schedule["sample_interval_ms"] * 1_000_000
    minimum_calibration_ns = (deadlines["startup_seconds"] + deadlines["term_seconds"] + deadlines["kill_seconds"]) * 1_000_000_000 + cal_duration_ns
    require(uint(deadlines["total_seconds"], "calibration total deadline", positive=True, maximum=200) * 1_000_000_000 >= minimum_calibration_ns, "pressure calibration total deadline omits a finite phase")
    require(finish_ns >= start_ns and finish_ns - start_ns <= deadlines["total_seconds"] * 1_000_000_000, "pressure calibration exceeded its finite total deadline")
    summary = _summarize_samples(samples)
    require(summary == calibration["summary"], "pressure contention calibration summary does not match raw samples")
    suggested = _suggest_thresholds(summary)
    require(suggested == calibration["suggested_readiness_thresholds"], "pressure contention calibration thresholds do not match its measured samples")
    return calibration


def _pressure_profile(schedule: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "seed", "sample_interval_ms", "startup_deadline_seconds", "term_deadline_seconds",
        "kill_deadline_seconds", "cpu_duty_basis_points", "pressure_cpu_affinity",
        "application_cpu_affinity", "disk_bytes_per_second", "scratch_file_bytes",
        "network_requests_per_second", "network_payload_bytes",
    )
    return {key: schedule[key] for key in keys}


def _validate_calibration_sample(
    sample: object, schedule: dict[str, Any], sequence: int,
    backing_chain: list[dict[str, Any]],
) -> None:
    item = exact_object(sample, {
        "schema", "sequence", "interval_start_monotonic_ns", "interval_end_monotonic_ns",
        "app_active", "cpu", "cpu_psi_delta_microseconds", "block", "io_psi_delta_microseconds",
        "block_device_chain", "loopback_counters", "loopback", "pressure_generators", "worker_process_io",
    }, f"calibration sample[{sequence}]")
    require(item["schema"] == EVENT_SCHEMA and item["sequence"] == sequence and item["app_active"] is False, "calibration sample identity or phase is invalid")
    start = uint(item["interval_start_monotonic_ns"], "calibration sample start", positive=True)
    end = uint(item["interval_end_monotonic_ns"], "calibration sample end", positive=True)
    sample_ns = schedule["sample_interval_ms"] * 1_000_000
    cadence_tolerance_ns = max(1_000_000, sample_ns // 100)
    require(sample_ns - cadence_tolerance_ns <= end - start <= sample_ns + max(500_000_000, sample_ns), "calibration sample interval is sparse or outside its clock tolerance")
    uint(item["cpu_psi_delta_microseconds"], "calibration CPU PSI delta")
    uint(item["io_psi_delta_microseconds"], "calibration I/O PSI delta")
    cpu = exact_object(item["cpu"], {"per_cpu", "total_ticks", "idle_ticks", "busy_basis_points"}, "calibration CPU counters")
    require(type(cpu["per_cpu"]) is list and len(cpu["per_cpu"]) == len(schedule["pressure_cpu_affinity"]), "calibration CPU counters are sparse")
    require(cpu["busy_basis_points"] <= 10000 and uint(cpu["total_ticks"], "calibration CPU ticks", positive=True) > uint(cpu["idle_ticks"], "calibration idle ticks"), "calibration CPU load counters are invalid")
    block = exact_object(item["block"], {"writes_completed", "sectors_written", "write_milliseconds", "io_milliseconds", "weighted_io_milliseconds", "in_flight", "write_bytes"}, "calibration block counters")
    require(uint(block["writes_completed"], "calibration writes", positive=True) > 0 and uint(block["write_bytes"], "calibration block bytes", positive=True) == uint(block["sectors_written"], "calibration sectors") * 512, "calibration block counters show no consistent writes")
    require(item["block_device_chain"] == backing_chain, "calibration block backing chain differs from its storage identity")
    net = exact_object(item["loopback_counters"], {"rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"}, "calibration lo counters")
    require(uint(net["rx_bytes"], "calibration lo RX", positive=True) > 0 and uint(net["tx_bytes"], "calibration lo TX", positive=True) > 0, "calibration has no loopback traffic")
    loop = item["loopback"]
    require(type(loop) is dict and loop.get("schema") == PRESSURE_IO_SCHEMA and loop.get("role") == "loopback" and loop.get("sequence") == sequence, "calibration loopback witness is malformed")
    sha256(loop.get("recipe_sha256"), "calibration worker recipe SHA")
    requests = uint(loop.get("requests_completed"), "calibration loopback requests", positive=True)
    require(loop.get("bytes_on_wire") == requests * schedule["network_payload_bytes"] * 2, "calibration loopback bytes do not match the request schedule")
    require(type(loop.get("latency_histogram")) is list and len(loop["latency_histogram"]) == 64 and sum(uint(count, "calibration histogram count") for count in loop["latency_histogram"]) == requests, "calibration loopback latency witness is sparse")
    generators = exact_object(item["pressure_generators"], {"cpu", "disk"}, "calibration pressure generators")
    require(type(generators["cpu"]) is list and len(generators["cpu"]) == len(schedule["pressure_cpu_affinity"]), "calibration CPU generator evidence is sparse")
    for index, generator in enumerate(generators["cpu"]):
        row = exact_object(generator, {"cpu", "thread_cpu_time_ns", "spin_witness", "start_monotonic_ns", "end_monotonic_ns"}, f"calibration CPU worker[{index}]")
        require(row["cpu"] == schedule["pressure_cpu_affinity"][index], "calibration CPU worker differs from requested affinity")
        uint(row["thread_cpu_time_ns"], "calibration CPU worker time", positive=True)
    disk_generator = exact_object(generators["disk"], {"write_bytes", "write_mode", "fdatasync_count", "fdatasync_time_nanoseconds", "start_monotonic_ns", "end_monotonic_ns"}, "calibration disk generator")
    require(uint(disk_generator["write_bytes"], "calibration generator bytes", positive=True) % BLOCK_BYTES == 0 and disk_generator["write_mode"] == "o_direct" and disk_generator["fdatasync_count"] == 1, "calibration disk worker is sparse")


def _validate_threshold_selection(value: object, calibration: dict[str, Any]) -> dict[str, int]:
    thresholds = exact_object(value, _threshold_keys(), "numeric readiness thresholds")
    normalized = {
        key: uint(thresholds[key], f"readiness threshold {key}", positive=True, maximum=U64_MAX)
        for key in sorted(_threshold_keys())
    }
    suggested = calibration["suggested_readiness_thresholds"]
    require(normalized["cpu_busy_min_basis_points"] <= suggested["cpu_busy_min_basis_points"], "selected CPU readiness threshold exceeds the measured calibration proposal")
    require(normalized["disk_write_min_bytes_per_second"] <= suggested["disk_write_min_bytes_per_second"], "selected disk readiness threshold exceeds the measured calibration proposal")
    require(normalized["disk_queue_or_stall_min_microseconds"] <= suggested["disk_queue_or_stall_min_microseconds"], "selected block-stall readiness threshold exceeds the measured calibration proposal")
    require(normalized["loopback_requests_min_per_second"] <= suggested["loopback_requests_min_per_second"], "selected loopback capacity threshold exceeds the measured calibration proposal")
    require(normalized["loopback_latency_p99_max_nanoseconds"] >= suggested["loopback_latency_p99_max_nanoseconds"], "selected loopback latency readiness threshold is stricter than measured calibration")
    require(normalized["loopback_tx_min_bytes_per_second"] <= suggested["loopback_tx_min_bytes_per_second"], "selected loopback TX readiness threshold exceeds the measured calibration proposal")
    require(normalized["loopback_rx_min_bytes_per_second"] <= suggested["loopback_rx_min_bytes_per_second"], "selected loopback RX readiness threshold exceeds the measured calibration proposal")
    return normalized


def freeze_recipe(request_path: Path, output_path: Path) -> dict[str, Any]:
    request, request_raw, _ = verify_canonical_json(request_path, "pressure request", MAX_REQUEST_BYTES)
    require(request_raw == canonical_bytes(request), "pressure request framing is not canonical")
    normalized = _request(request)
    schedule = normalized["schedule"]
    storage_paths = [Path(path) for path in normalized["storage"]["application_io_paths"]]
    host = _host_facts(schedule["pressure_cpu_affinity"], schedule["application_cpu_affinity"], storage_paths)
    scratch_path = Path(normalized["storage"]["pressure_scratch_path"])
    scratch_storage = _storage_record(scratch_path, "pressure scratch path")
    app_storage = host["application_storage"][0]
    require(
        scratch_storage["device"] == app_storage["device"]
        and scratch_storage["mount"]["mount_id"] == app_storage["mount"]["mount_id"]
        and scratch_storage["backing_chain"] == app_storage["backing_chain"],
        "pressure scratch path does not share the application I/O device, mount, and backing chain",
    )
    host["pressure_scratch"] = scratch_storage
    pressure_calibration_path = Path(normalized["pressure_calibration"]["path"])
    pressure_calibration, _, pressure_raw_sha = verify_canonical_json(pressure_calibration_path, "pressure contention calibration", MAX_CALIBRATION_BYTES)
    require(pressure_raw_sha == normalized["pressure_calibration"]["raw_sha256"], "pressure contention calibration changed while freezing")
    calibration_host = pressure_calibration["host"]
    require(
        calibration_host["kernel_release"] == host["kernel_release"]
        and calibration_host["boot_id_sha256"] == host["boot_id_sha256"]
        and calibration_host["allowed_cpu_affinity"] == host["allowed_cpu_affinity"]
        and calibration_host["pressure_cpu_affinity"] == host["pressure_cpu_affinity"]
        and calibration_host["application_cpu_affinity"] == host["application_cpu_affinity"],
        "pressure calibration host/kernel/CPU conditions differ from current recipe",
    )
    require(pressure_calibration["network"] == host["network"], "pressure calibration IPv4 loopback route/network namespace differs")
    require(pressure_calibration["storage"] == {
        "application_device": app_storage["device"],
        "mount_id": app_storage["mount"]["mount_id"],
        "backing_chain": app_storage["backing_chain"],
    }, "pressure calibration block device/mount/backing chain differs")
    artifact_budget = _artifact_budget(schedule, app_storage["backing_chain"])
    free_bytes = shutil.disk_usage(scratch_path).free
    required_free = schedule["scratch_file_bytes"] + normalized["storage"]["output_minimum_free_bytes"]
    require(free_bytes >= required_free, "application device lacks the frozen scratch file plus free-space reserve")
    driver_sha = _hash_script(DRIVER_PATH, "pressure driver")
    reader_sha = _hash_script(READER_PATH, "pressure reader")
    require(os.geteuid() == os.stat(DRIVER_PATH).st_uid or os.access(DRIVER_PATH, os.R_OK), "pressure driver file is not readable by this process")
    recipe_body = {
        "schema": RECIPE_SCHEMA,
        "identity": normalized["identity"],
        "files": normalized["files"],
        "process": normalized["process"],
        "host": host,
        "storage": {
            **normalized["storage"],
            "application_device": app_storage["device"],
            "application_mount_id": app_storage["mount"]["mount_id"],
            "backing_chain": app_storage["backing_chain"],
            "non_tmpfs": True,
        },
        "network": {
            **host["network"],
            "claim": "ipv4_loopback_shared_kernel_only",
            "physical_nic_claimed": False,
        },
        "schedule": normalized["schedule"],
        "artifact_budget": artifact_budget,
        "pressure_calibration": normalized["pressure_calibration"],
        "readiness_thresholds": normalized["readiness_thresholds"],
        "script_hashes": {"driver_sha256": driver_sha, "reader_sha256": reader_sha},
        "condition_sha256": digest_object({
            "host_id": normalized["identity"]["host_id"],
            "condition_id": normalized["identity"]["condition_id"],
            "source_manifest_sha256": normalized["files"]["source_manifest"]["raw_sha256"],
            "policy_sha256": normalized["files"]["policy"]["raw_sha256"],
            "application_capacity_calibration_sha256": normalized["files"]["application_capacity_calibration"]["raw_sha256"],
            "host": {
                "kernel_release": host["kernel_release"],
                "boot_id_sha256": host["boot_id_sha256"],
                "allowed_cpu_affinity": host["allowed_cpu_affinity"],
                "pressure_cpu_affinity": host["pressure_cpu_affinity"],
                "application_cpu_affinity": host["application_cpu_affinity"],
            },
            "storage": {
                "device": app_storage["device"],
                "mount_id": app_storage["mount"]["mount_id"],
                "backing_chain": app_storage["backing_chain"],
            },
            "network": host["network"],
            "schedule": normalized["schedule"],
            "pressure_calibration_sha256": normalized["pressure_calibration"]["raw_sha256"],
            "readiness_thresholds": normalized["readiness_thresholds"],
        }),
    }
    recipe = {**recipe_body, "recipe_sha256": digest_object(recipe_body)}
    raw = canonical_bytes(recipe)
    output_parent = output_path.parent
    safe_directory(output_parent, "recipe output directory")
    recipe_raw_sha = safe_write_new(output_path, raw, "frozen pressure recipe", maximum=MAX_RECIPE_BYTES)
    return {"recipe_sha256": recipe["recipe_sha256"], "recipe_raw_sha256": recipe_raw_sha, "condition_sha256": recipe["condition_sha256"], "path": str(output_path)}


def _hash_script(path: Path, label: str) -> str:
    _, actual = read_stable(path, label, 4 * 1024 * 1024)
    return actual


def _validate_recipe(value: object, expected_sha256: str | None = None) -> dict[str, Any]:
    recipe = exact_object(value, {
        "schema", "identity", "files", "process", "host", "storage", "network",
        "schedule", "artifact_budget", "pressure_calibration", "readiness_thresholds", "script_hashes",
        "condition_sha256", "recipe_sha256",
    }, "frozen pressure recipe")
    require(recipe["schema"] == RECIPE_SCHEMA, "unsupported frozen pressure recipe schema")
    body = {key: value for key, value in recipe.items() if key != "recipe_sha256"}
    actual_sha = digest_object(body)
    claimed = sha256(recipe["recipe_sha256"], "recipe digest")
    require(actual_sha == claimed and (expected_sha256 is None or actual_sha == expected_sha256), "frozen pressure recipe digest differs from the independently supplied expected hash")
    recipe_identity = exact_object(recipe["identity"], {
        "host_id", "run_id", "pair_id", "condition_id", "member", "nonce",
        "allocator", "executor", "phase",
    }, "frozen pressure identity")
    require(recipe_identity["phase"] == "external_pressure", "frozen pressure recipe has the wrong phase")
    identity = _identity({key: value for key, value in recipe_identity.items() if key != "phase"})
    schedule = _schedule(recipe["schedule"])
    storage = exact_object(recipe["storage"], {
        "application_io_paths", "pressure_scratch_path", "output_minimum_free_bytes",
        "application_device", "application_mount_id", "backing_chain", "non_tmpfs",
    }, "recipe storage")
    require(type(storage["backing_chain"]) is list and 1 <= len(storage["backing_chain"]) <= 32, "recipe block backing chain is sparse or oversized")
    artifact_budget = exact_object(recipe["artifact_budget"], {
        "sample_count", "maximum_sample_line_bytes", "sample_events_bytes",
        "terminal_reserve_bytes", "maximum_event_bytes",
    }, "recipe event artifact budget")
    require(artifact_budget == _artifact_budget(schedule, storage["backing_chain"]), "frozen event artifact budget does not match the independent schedule bounds")
    hashes = exact_object(recipe["script_hashes"], {"driver_sha256", "reader_sha256"}, "pressure script hashes")
    sha256(hashes["driver_sha256"], "driver SHA-256")
    sha256(hashes["reader_sha256"], "reader SHA-256")
    thresholds = exact_object(recipe["readiness_thresholds"], _threshold_keys(), "readiness thresholds")
    for key in _threshold_keys():
        uint(thresholds[key], f"readiness threshold {key}", positive=True)
    require(recipe["network"].get("claim") == "ipv4_loopback_shared_kernel_only" and recipe["network"].get("physical_nic_claimed") is False, "network recipe makes an unsupported physical NIC claim")
    require(recipe["network"].get("interface") == "lo" and recipe["network"].get("destination") == "127.0.0.1", "network recipe does not bind IPv4 loopback")
    require(recipe["storage"].get("non_tmpfs") is True and recipe["storage"].get("application_device") == recipe["host"]["application_storage"][0]["device"], "storage recipe is not bound to the non-tmpfs application device")
    require(identity["nonce"] == recipe["identity"]["nonce"], "process nonce changed during recipe validation")
    return recipe


def _verify_recipe_inputs(recipe: dict[str, Any]) -> None:
    for label, record in recipe["files"].items():
        maximum = MAX_APP_BINARY_BYTES if label == "application_binary" else MAX_SOURCE_BYTES if label == "source_manifest" else MAX_POLICY_BYTES
        _, actual = read_stable(Path(record["path"]), f"frozen input {label}", maximum)
        require(actual == record["raw_sha256"], f"frozen input {label} changed after recipe construction")
    calibration = recipe["pressure_calibration"]
    _, raw_sha = read_stable(Path(calibration["path"]), "frozen pressure contention calibration", MAX_CALIBRATION_BYTES)
    require(raw_sha == calibration["raw_sha256"], "pressure contention calibration changed after recipe construction")


def _verify_live_environment(recipe: dict[str, Any]) -> None:
    host = recipe["host"]
    require(os.uname().release == host["kernel_release"], "kernel release changed after recipe freeze")
    require(digest_bytes(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()) == host["boot_id_sha256"], "host boot identity changed after recipe freeze")
    require(set(recipe["schedule"]["pressure_cpu_affinity"]) <= set(_affinity(0)), "live driver affinity no longer permits its frozen pressure CPUs")
    current_network = _loopback_route()
    for key in ("address_family", "destination", "source", "interface", "ifindex", "network_namespace_inode", "shared_kernel", "physical_nic_claimed", "claim"):
        require(current_network[key] == host["network"][key], f"live IPv4 loopback condition {key} differs from frozen recipe")
    require(current_network["route"] == host["network"]["route"], "live IPv4 loopback route differs from frozen recipe")
    for index, expected in enumerate(host["application_storage"]):
        observed = _storage_record(Path(expected["path"]), f"live application storage path {index}")
        require(observed == expected, f"live application storage path {index} differs from frozen mount/device/backing chain")
    scratch = _storage_record(Path(host["pressure_scratch"]["path"]), "live pressure scratch path")
    require(scratch == host["pressure_scratch"], "live pressure scratch mount/device/backing chain differs from frozen recipe")


def _parse_pressure(raw: bytes, label: str) -> dict[str, int]:
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise PressureError(f"{label} is not ASCII") from error
    result: dict[str, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        kind = fields[0]
        if kind not in ("some", "full"):
            continue
        values: dict[str, int] = {}
        for field in fields[1:]:
            key, sep, value = field.partition("=")
            if sep and value.isdigit():
                values[key] = int(value)
        if "total" in values:
            result[kind] = values["total"]
    require("some" in result, f"{label} lacks a finite PSI some total")
    return result


def _cpu_stats() -> dict[int, tuple[int, int]]:
    try:
        raw = Path("/proc/stat").read_bytes()
    except OSError as error:
        raise PressureError(f"cannot read /proc/stat: {error}") from error
    require(len(raw) <= 4 * 1024 * 1024, "/proc/stat exceeds its finite bound")
    result: dict[int, tuple[int, int]] = {}
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise PressureError("/proc/stat is not ASCII") from error
    for line in lines:
        fields = line.split()
        if not fields or not re.fullmatch(r"cpu[0-9]+", fields[0]):
            continue
        cpu_id = int(fields[0][3:])
        counters = [uint(int(value), f"CPU {cpu_id} counter") for value in fields[1:]]
        require(len(counters) >= 8, f"CPU {cpu_id} counters are sparse")
        # guest and guest_nice are already included in user/nice by Linux.
        total = sum(counters[:8])
        idle = counters[3] + counters[4]
        result[cpu_id] = (total, idle)
    require(result, "/proc/stat contains no per-CPU counters")
    return result


def _cpu_window(before: dict[int, tuple[int, int]], after: dict[int, tuple[int, int]], cpus: list[int]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    total_delta = 0
    idle_delta = 0
    per_cpu: list[dict[str, int]] = []
    for cpu_id in cpus:
        require(cpu_id in before and cpu_id in after, f"CPU {cpu_id} counters are missing")
        total = after[cpu_id][0] - before[cpu_id][0]
        idle = after[cpu_id][1] - before[cpu_id][1]
        require(total > 0 and 0 <= idle <= total, f"CPU {cpu_id} counter interval is sparse or invalid")
        busy = total - idle
        per_cpu.append({"cpu": cpu_id, "total_ticks": total, "idle_ticks": idle, "busy_ticks": busy, "busy_basis_points": busy * 10000 // total})
        total_delta += total
        idle_delta += idle
    result["per_cpu"] = per_cpu
    result["total_ticks"] = total_delta
    result["idle_ticks"] = idle_delta
    result["busy_basis_points"] = (total_delta - idle_delta) * 10000 // total_delta
    return result


def _disk_stats() -> dict[str, dict[str, int]]:
    try:
        raw = Path("/proc/diskstats").read_bytes()
    except OSError as error:
        raise PressureError(f"cannot read /proc/diskstats: {error}") from error
    require(len(raw) <= 8 * 1024 * 1024, "/proc/diskstats exceeds its finite bound")
    result: dict[str, dict[str, int]] = {}
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise PressureError("/proc/diskstats is not ASCII") from error
    for line in lines:
        fields = line.split()
        if len(fields) < 14:
            continue
        device = f"{fields[0]}:{fields[1]}"
        numbers = [uint(int(value), f"diskstats {device} counter") for value in fields[3:14]]
        result[device] = {
            "reads_completed": numbers[0],
            "reads_merged": numbers[1],
            "sectors_read": numbers[2],
            "read_milliseconds": numbers[3],
            "writes_completed": numbers[4],
            "writes_merged": numbers[5],
            "sectors_written": numbers[6],
            "write_milliseconds": numbers[7],
            "in_flight": numbers[8],
            "io_milliseconds": numbers[9],
            "weighted_io_milliseconds": numbers[10],
        }
    return result


def _net_stats() -> dict[str, int]:
    result: dict[str, int] = {}
    # Read the fixed Linux interface counters by their exact sysfs names.
    for name in ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"):
        path = Path("/sys/class/net/lo/statistics") / name
        try:
            text = path.read_text(encoding="ascii").strip()
            require(re.fullmatch(r"[0-9]+", text) is not None, f"lo {name} counter is malformed")
            result[name] = uint(int(text), f"lo {name}")
        except OSError as error:
            raise PressureError(f"cannot read lo {name} counter: {error}") from error
    return result


def _read_psi(path: Path, label: str) -> dict[str, int]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PressureError(f"cannot read {label}: {error}") from error
    require(len(raw) <= 65536, f"{label} exceeds its finite bound")
    return _parse_pressure(raw, label)


def _counter_delta(before: dict[str, int], after: dict[str, int], keys: tuple[str, ...], label: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for key in keys:
        require(key in before and key in after and after[key] >= before[key], f"{label} {key} counter is missing or regressed")
        result[key] = after[key] - before[key]
    return result


def _disk_window(before: dict[str, dict[str, int]], after: dict[str, dict[str, int]], device: str) -> dict[str, Any]:
    require(device in before and device in after, f"application block device {device} has no diskstats counters")
    prior = before[device]
    current = after[device]
    delta = {key: current[key] - prior[key] for key in (
        "writes_completed", "sectors_written", "write_milliseconds", "io_milliseconds", "weighted_io_milliseconds",
    )}
    require(all(value >= 0 for value in delta.values()), "application block device counters regressed")
    delta["in_flight"] = current["in_flight"]
    delta["write_bytes"] = delta["sectors_written"] * 512
    return delta


def _proc_io(pid: int) -> dict[str, int]:
    try:
        raw = Path(f"/proc/{pid}/io").read_bytes()
    except OSError as error:
        raise PressureError(f"cannot read worker {pid} I/O counters: {error}") from error
    require(len(raw) <= 65536, f"worker {pid} I/O counters are oversized")
    result: dict[str, int] = {}
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise PressureError(f"worker {pid} I/O counters are not ASCII") from error
    for line in lines:
        key, sep, value = line.partition(":")
        if sep and value.strip().isdigit():
            result[key] = int(value.strip())
    require("write_bytes" in result and "syscw" in result, f"worker {pid} I/O counters are sparse")
    return result


def _readiness_from_sample(sample: dict[str, Any], thresholds: dict[str, int]) -> dict[str, Any]:
    interval_ns = sample["interval_end_monotonic_ns"] - sample["interval_start_monotonic_ns"]
    require(interval_ns > 0, "sample interval is empty")
    cpu_busy = sample["cpu"]["busy_basis_points"] >= thresholds["cpu_busy_min_basis_points"]
    disk_bps = sample["block"]["write_bytes"] * 1_000_000_000 // interval_ns
    disk_stall_us = sample["block"]["weighted_io_milliseconds"] * 1000 + sample["io_psi_delta_microseconds"]
    disk_evidence = sample["block"]["in_flight"] > 0 or disk_stall_us >= thresholds["disk_queue_or_stall_min_microseconds"]
    disk_ready = disk_bps >= thresholds["disk_write_min_bytes_per_second"] and sample["block"]["writes_completed"] > 0 and disk_evidence
    net_ops = sample["loopback"]["requests_completed"]
    net_rps = net_ops * 1_000_000_000 // interval_ns
    tx_bps = sample["loopback_counters"]["tx_bytes"] * 1_000_000_000 // interval_ns
    rx_bps = sample["loopback_counters"]["rx_bytes"] * 1_000_000_000 // interval_ns
    net_ready = (
        net_rps >= thresholds["loopback_requests_min_per_second"]
        and sample["loopback"]["p99_upper_latency_nanoseconds"] <= thresholds["loopback_latency_p99_max_nanoseconds"]
        and tx_bps >= thresholds["loopback_tx_min_bytes_per_second"]
        and rx_bps >= thresholds["loopback_rx_min_bytes_per_second"]
        and sample["loopback_counters"]["rx_errors"] == 0
        and sample["loopback_counters"]["tx_errors"] == 0
        and sample["loopback_counters"]["rx_dropped"] == 0
        and sample["loopback_counters"]["tx_dropped"] == 0
    )
    return {
        "cpu_ready": cpu_busy,
        "disk_ready": disk_ready,
        "loopback_ready": net_ready,
        "all_ready": cpu_busy and disk_ready and net_ready,
        "cpu_busy_basis_points": sample["cpu"]["busy_basis_points"],
        "disk_write_bytes_per_second": disk_bps,
        "disk_queue_or_stall_microseconds": disk_stall_us,
        "loopback_requests_per_second": net_rps,
        "loopback_latency_p99_upper_nanoseconds": sample["loopback"]["p99_upper_latency_nanoseconds"],
        "loopback_tx_bytes_per_second": tx_bps,
        "loopback_rx_bytes_per_second": rx_bps,
    }


def _median(values: list[int], label: str) -> int:
    require(values, f"cannot calculate measured {label} threshold from an empty sample set")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) // 2


def _summarize_samples(samples: list[dict[str, Any]]) -> dict[str, int]:
    require(type(samples) is list and len(samples) >= 3, "readiness samples are sparse")
    cpu_values = [uint(item["cpu"]["busy_basis_points"], "sample CPU busy") for item in samples]
    disk_values: list[int] = []
    stall_values: list[int] = []
    rps_values: list[int] = []
    p99_values: list[int] = []
    tx_values: list[int] = []
    rx_values: list[int] = []
    for item in samples:
        result = _readiness_from_sample(item, {
            "cpu_busy_min_basis_points": 1,
            "disk_write_min_bytes_per_second": 1,
            "disk_queue_or_stall_min_microseconds": 1,
            "loopback_requests_min_per_second": 1,
            "loopback_latency_p99_max_nanoseconds": U64_MAX,
            "loopback_tx_min_bytes_per_second": 1,
            "loopback_rx_min_bytes_per_second": 1,
        })
        disk_values.append(result["disk_write_bytes_per_second"])
        stall_values.append(result["disk_queue_or_stall_microseconds"])
        rps_values.append(result["loopback_requests_per_second"])
        p99_values.append(result["loopback_latency_p99_upper_nanoseconds"])
        tx_values.append(result["loopback_tx_bytes_per_second"])
        rx_values.append(result["loopback_rx_bytes_per_second"])
    return {
        "sample_count": len(samples),
        "cpu_busy_basis_points_median": _median(cpu_values, "CPU busy"),
        "disk_write_bytes_per_second_median": _median(disk_values, "block write"),
        "disk_queue_or_stall_microseconds_median": _median(stall_values, "block queue/stall"),
        "loopback_requests_per_second_median": _median(rps_values, "loopback capacity"),
        "loopback_latency_p99_upper_nanoseconds_median": _median(p99_values, "loopback latency"),
        "loopback_tx_bytes_per_second_median": _median(tx_values, "loopback transmit"),
        "loopback_rx_bytes_per_second_median": _median(rx_values, "loopback receive"),
    }


def _suggest_thresholds(summary: dict[str, int]) -> dict[str, int]:
    # These are readiness thresholds derived only from finite pressure
    # contention measurements. They are not application performance gates.
    values = {
        "cpu_busy_min_basis_points": summary["cpu_busy_basis_points_median"] * 8000 // 10000,
        "disk_write_min_bytes_per_second": summary["disk_write_bytes_per_second_median"] * 8000 // 10000,
        "disk_queue_or_stall_min_microseconds": max(1, summary["disk_queue_or_stall_microseconds_median"] * 5000 // 10000),
        "loopback_requests_min_per_second": summary["loopback_requests_per_second_median"] * 8000 // 10000,
        "loopback_latency_p99_max_nanoseconds": summary["loopback_latency_p99_upper_nanoseconds_median"] * 20000 // 10000,
        "loopback_tx_min_bytes_per_second": summary["loopback_tx_bytes_per_second_median"] * 8000 // 10000,
        "loopback_rx_min_bytes_per_second": summary["loopback_rx_bytes_per_second_median"] * 8000 // 10000,
    }
    require(all(type(value) is int and value > 0 for value in values.values()), "finite calibration did not produce positive readiness thresholds for every pressure witness")
    return values


def _histogram_p99_upper(histogram: list[int]) -> int:
    require(type(histogram) is list and len(histogram) == 64, "loopback latency histogram is malformed")
    counts = [uint(item, "latency bucket count") for item in histogram]
    total = sum(counts)
    require(total > 0, "loopback latency witness has no completed requests")
    wanted = (total * 99 + 99) // 100
    cumulative = 0
    for index, count in enumerate(counts):
        cumulative += count
        if cumulative >= wanted:
            return 1 << index
    raise PressureError("loopback latency histogram is sparse")


def _storage_reserve(
    recipe: dict[str, Any], output_dir: Path, *, scratch_reserved: bool = False,
    reserve_event_budget: bool = False,
) -> None:
    floor = recipe["storage"]["output_minimum_free_bytes"]
    scratch_path = Path(recipe["storage"]["pressure_scratch_path"])
    disk_free = shutil.disk_usage(scratch_path).free
    output_free = shutil.disk_usage(output_dir).free
    scratch_allowance = 0 if scratch_reserved else recipe["schedule"]["scratch_file_bytes"]
    budget = recipe.get("artifact_budget")
    event_allowance = budget["maximum_event_bytes"] if reserve_event_budget and type(budget) is dict else 0
    receipt_allowance = MAX_MANIFEST_BYTES if type(budget) is dict else 0
    try:
        scratch_info = scratch_path.stat()
        output_info = output_dir.stat()
        outputvfs = os.statvfs(output_dir)
    except OSError as error:
        raise PressureError(f"cannot inspect artifact free-space watchdog: {error}") from error
    available = outputvfs.f_bavail * outputvfs.f_frsize
    shared_device = scratch_info.st_dev == output_info.st_dev
    if shared_device:
        required = floor + scratch_allowance + event_allowance + receipt_allowance
        require(disk_free >= required, "shared application/artifact device fell below its bounded scratch/event/receipt reserve")
    else:
        require(disk_free >= floor + scratch_allowance, "application block device fell below its scratch/free-space reserve")
        require(output_free >= floor + event_allowance + receipt_allowance, "artifact device fell below its frozen event/receipt reserve")
    require(stat.S_ISDIR(output_info.st_mode) and available >= floor + event_allowance + receipt_allowance, "artifact storage free-space watchdog failed")


class WorkerSet:
    def __init__(self, recipe: dict[str, Any]):
        self.recipe = recipe
        self.children: list[dict[str, Any]] = []
        self.selector = selectors.DefaultSelector()
        self.lines: dict[int, dict[int, dict[str, Any]]] = {}
        self.buffers: dict[int, bytes] = {}
        self.scratch_file: Path | None = None
        self.scratch_removed = False
        self.scratch_identity: tuple[int, int] | None = None
        self._spawned = False

    def spawn(self) -> None:
        require(os.getsid(0) == os.getpid(), "driver must start in a fresh dedicated session")
        recipe = self.recipe
        script = str(DRIVER_PATH)
        schedule = recipe["schedule"]
        common = [
            sys.executable, script, "_worker",
            "--recipe-sha256", recipe["recipe_sha256"],
            "--interval-ms", str(schedule["sample_interval_ms"]),
            "--duration-seconds", str(schedule["duration_seconds"]),
            "--seed", str(schedule["seed"]),
        ]
        try:
            for cpu_id in schedule["pressure_cpu_affinity"]:
                process = subprocess.Popen(
                    common + ["--kind", "cpu", "--cpu", str(cpu_id), "--duty-basis-points", str(schedule["cpu_duty_basis_points"])],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    close_fds=True, start_new_session=True, bufsize=0,
                    cwd="/", env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONUNBUFFERED": "1"},
                )
                self._add_child(process, "cpu", cpu_id)
            scratch = Path(recipe["storage"]["pressure_scratch_path"]) / f".allocatbelt-pressure-{recipe['identity']['nonce']}.bin"
            self.scratch_file = scratch
            require(not scratch.exists() and not scratch.is_symlink(), "pressure scratch name already exists")
            scratch_fd = os.open(
                scratch,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                info = os.fstat(scratch_fd)
                require(stat.S_ISREG(info.st_mode), "pressure scratch file is not regular")
                expected_device = recipe["storage"]["application_device"]
                observed_device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
                require(observed_device == expected_device, "pressure scratch file escaped the frozen application device")
                self.scratch_identity = (info.st_dev, info.st_ino)
                os.posix_fallocate(scratch_fd, 0, schedule["scratch_file_bytes"])
                os.fsync(scratch_fd)
            finally:
                os.close(scratch_fd)
            process = subprocess.Popen(
                common + [
                    "--kind", "disk", "--scratch-file", str(scratch),
                    "--scratch-bytes", str(schedule["scratch_file_bytes"]),
                    "--scratch-device", str(self.scratch_identity[0]),
                    "--scratch-inode", str(self.scratch_identity[1]),
                    "--disk-rate", str(schedule["disk_bytes_per_second"]),
                ],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, start_new_session=True, bufsize=0,
                cwd="/", env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONUNBUFFERED": "1"},
            )
            self._add_child(process, "disk", None)
            process = subprocess.Popen(
                common + [
                    "--kind", "loopback", "--requests-per-second", str(schedule["network_requests_per_second"]),
                    "--payload-bytes", str(schedule["network_payload_bytes"]),
                ],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, start_new_session=True, bufsize=0,
                cwd="/", env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONUNBUFFERED": "1"},
            )
            self._add_child(process, "loopback", None)
            self._spawned = True
        except BaseException:
            self.cleanup(0, 0)
            raise

    def _add_child(self, process: subprocess.Popen[bytes], role: str, cpu: int | None) -> None:
        require(process.stdout is not None and process.stdin is not None, "pressure worker pipes were not created")
        record = {
            "role": role,
            "cpu": cpu,
            "pid": process.pid,
            "pgid": process.pid,
            "session_id": process.pid,
            "process": process,
            "start_ticks": None,
            "ready": False,
            "stderr": process.stderr,
            "stderr_raw_capture": bytearray(),
            "stderr_raw_truncated": False,
            "stderr_read_error": None,
            "stderr_capture_complete": False,
        }
        self.children.append(record)
        self.lines[process.pid] = {}
        self.buffers[process.pid] = b""
        os.set_blocking(process.stdout.fileno(), False)
        self.selector.register(process.stdout, selectors.EVENT_READ, record)

    def await_ready(self, deadline_ns: int) -> None:
        while not all(child["ready"] for child in self.children):
            now = time.monotonic_ns()
            require(now < deadline_ns, "pressure worker startup/readiness deadline expired")
            for key, _ in self.selector.select(min(0.1, (deadline_ns - now) / 1_000_000_000)):
                self._consume(key.fileobj, key.data)
            for child in self.children:
                process = child["process"]
                if process.poll() is not None and not child["ready"]:
                    detail = self._stderr_excerpt(child)
                    raise PressureError(f"{child['role']} worker exited before startup readiness: {detail}")
        for child in self.children:
            child["start_ticks"] = _proc_stat(child["pid"])["start_ticks"]
            child["affinity"] = _affinity(child["pid"])
            require(child["affinity"] == ([child["cpu"]] if child["cpu"] is not None else child["affinity"]), "pressure CPU worker affinity differs from its frozen CPU")
            child["pgid_observed"] = os.getpgid(child["pid"])
            child["sid_observed"] = os.getsid(child["pid"])
            require(child["pgid_observed"] == child["pid"] and child["sid_observed"] == child["pid"], "pressure worker is not isolated in its own process group and session")

    def begin(self, start_ns: int) -> None:
        line = canonical_bytes({"start_monotonic_ns": start_ns})
        for child in self.children:
            stream = child["process"].stdin
            require(stream is not None, "pressure worker stdin disappeared")
            stream.write(line)
            stream.flush()
            stream.close()

    def wait_sample(self, seq: int, deadline_ns: int) -> dict[str, Any]:
        target = {child["pid"] for child in self.children}
        while True:
            ready = {pid for pid in target if seq in self.lines[pid]}
            if ready == target:
                break
            now = time.monotonic_ns()
            require(now < deadline_ns, f"pressure workers produced a sparse/missing sample at sequence {seq}")
            for key, _ in self.selector.select(min(0.05, (deadline_ns - now) / 1_000_000_000)):
                self._consume(key.fileobj, key.data)
            for child in self.children:
                process = child["process"]
                if process.poll() is not None and seq not in self.lines[child["pid"]]:
                    detail = self._stderr_excerpt(child)
                    raise PressureError(f"{child['role']} pressure worker exited during sample {seq}: {detail}")
        records = {child["role"] if child["cpu"] is None else f"cpu:{child['cpu']}": self.lines[child["pid"]].pop(seq) for child in self.children}
        return records
    def _consume(self, stream: Any, child: dict[str, Any]) -> None:
        try:
            chunk = os.read(stream.fileno(), 65536)
        except BlockingIOError:
            return
        except OSError as error:
            raise PressureError(f"cannot read {child['role']} worker telemetry: {error}") from error
        if not chunk:
            return
        pid = child["pid"]
        pending = self.buffers[pid] + chunk
        require(len(pending) <= 1024 * 1024, f"{child['role']} worker telemetry line exceeds its bound")
        pieces = pending.split(b"\n")
        self.buffers[pid] = pieces.pop()
        for raw_line in pieces:
            require(len(raw_line) <= 65536, f"{child['role']} worker telemetry line is oversized")
            item = parse_object(raw_line, f"{child['role']} worker telemetry", 65536)
            require(raw_line + b"\n" == canonical_bytes(item), f"{child['role']} worker telemetry is not canonical")
            if item.get("event") == "ready":
                require(not child["ready"] and item.get("recipe_sha256") == self.recipe["recipe_sha256"] and item.get("role") == child["role"], "worker startup record is duplicated or mismatched")
                if child["cpu"] is not None:
                    require(item.get("cpu") == child["cpu"], "CPU worker started on the wrong logical CPU")
                elif child["role"] == "loopback":
                    require(item.get("address", [None])[0] == "127.0.0.1", "loopback worker did not bind IPv4 loopback")
                    require(item.get("network_namespace_inode") == self.recipe["network"]["network_namespace_inode"], "loopback worker entered a different network namespace")
                    child["loopback_address"] = item["address"]
                child["ready"] = True
                continue
            seq = uint(item.get("sequence"), "worker sample sequence")
            require(seq not in self.lines[pid], f"{child['role']} worker repeated sample {seq}")
            self.lines[pid][seq] = item

    def _stderr_capture(self, child: dict[str, Any]) -> tuple[bytes, bool, str | None]:
        stream = child["stderr"]
        if stream is None:
            return b"", False, "worker stderr pipe is unavailable"
        if child["stderr_capture_complete"]:
            return bytes(child["stderr_raw_capture"]), child["stderr_raw_truncated"], child["stderr_read_error"]
        try:
            os.set_blocking(stream.fileno(), False)
            while True:
                try:
                    raw = os.read(stream.fileno(), 4096)
                except BlockingIOError:
                    break
                if not raw:
                    child["stderr_capture_complete"] = True
                    break
                captured = child["stderr_raw_capture"]
                remaining = MAX_WORKER_STDERR_RAW_BYTES - len(captured)
                if remaining > 0:
                    captured.extend(raw[:remaining])
                if len(raw) > remaining:
                    child["stderr_raw_truncated"] = True
                if child["stderr_raw_truncated"]:
                    # Drain a bounded amount on each call while retaining only
                    # the exact prefix. This keeps a noisy worker from filling
                    # its pipe without allowing unbounded evidence growth.
                    break
        except OSError as error:
            child["stderr_read_error"] = f"{type(error).__name__}: {error}"
        if child["process"].poll() is not None:
            child["stderr_capture_complete"] = True
        return bytes(child["stderr_raw_capture"]), child["stderr_raw_truncated"], child["stderr_read_error"]

    def _stderr_excerpt(self, child: dict[str, Any]) -> str:
        raw, _, read_error = self._stderr_capture(child)
        if read_error is not None:
            return f"worker stderr unavailable: {read_error}"
        return raw.decode("utf-8", errors="replace")[:4096].strip() or "no worker stderr"

    def process_io(self) -> dict[str, dict[str, int]]:
        return {child["role"] if child["cpu"] is None else f"cpu:{child['cpu']}": _proc_io(child["pid"]) for child in self.children}

    def cleanup(self, term_seconds: int, kill_seconds: int) -> list[dict[str, Any]]:
        if not self._spawned and not self.children:
            return []
        cleanup_start = time.monotonic_ns()
        term_deadline = cleanup_start + max(0, term_seconds) * 1_000_000_000
        for child in self.children:
            process = child["process"]
            if process.poll() is None:
                try:
                    os.killpg(child["pgid"], signal.SIGTERM)
                    child["term_sent_monotonic_ns"] = time.monotonic_ns()
                except ProcessLookupError:
                    pass
                except OSError as error:
                    child["term_error"] = str(error)
        for child in self.children:
            process = child["process"]
            if process.poll() is None:
                remaining = max(0.0, (term_deadline - time.monotonic_ns()) / 1_000_000_000)
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    pass
        kill_started = time.monotonic_ns()
        kill_deadline = kill_started + max(0, kill_seconds) * 1_000_000_000
        for child in self.children:
            process = child["process"]
            if process.poll() is None:
                try:
                    os.killpg(child["pgid"], signal.SIGKILL)
                    child["kill_sent_monotonic_ns"] = time.monotonic_ns()
                except ProcessLookupError:
                    pass
                except OSError as error:
                    child["kill_error"] = str(error)
        records: list[dict[str, Any]] = []
        for child in self.children:
            process = child["process"]
            if process.poll() is None:
                remaining = max(0.0, (kill_deadline - time.monotonic_ns()) / 1_000_000_000)
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    child["reap_error"] = "worker survived the KILL deadline"
            returncode = process.poll()
            reaped_ns = time.monotonic_ns() if returncode is not None else None
            remains = _pid_exists(child["pid"], child.get("start_ticks") or 0)
            stderr_raw, stderr_truncated, stderr_read_error = self._stderr_capture(child)
            stderr_text = stderr_raw.decode("utf-8", errors="replace")[:4096].strip()
            if stderr_text == "no worker stderr":
                stderr_text = ""
            record = {
                "role": child["role"], "cpu": child["cpu"], "pid": child["pid"],
                "start_ticks": child.get("start_ticks"), "pgid": child["pgid"],
                "session_id": child["session_id"], "exit_code": returncode,
                "cleanup_started_monotonic_ns": cleanup_start,
                "term_deadline_monotonic_ns": term_deadline,
                "kill_deadline_monotonic_ns": kill_deadline,
                "term_error": child.get("term_error"), "kill_error": child.get("kill_error"),
                "reap_error": child.get("reap_error"), "alive_after_cleanup": remains,
                "stderr_output": stderr_text,
                "stderr_raw_base64": base64.b64encode(stderr_raw).decode("ascii"),
                "stderr_raw_sha256": digest_bytes(stderr_raw),
                "stderr_raw_bytes": len(stderr_raw),
                "stderr_raw_truncated": stderr_truncated,
                "stderr_read_error": stderr_read_error,
                "term_sent_monotonic_ns": child.get("term_sent_monotonic_ns"),
                "kill_sent_monotonic_ns": child.get("kill_sent_monotonic_ns"),
                "reaped_monotonic_ns": reaped_ns,
            }
            if process.stdout is not None:
                try:
                    self.selector.unregister(process.stdout)
                except Exception:
                    pass
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            records.append(record)
        self.selector.close()
        if self.scratch_file is not None:
            try:
                if self.scratch_file.exists() or self.scratch_file.is_symlink():
                    info = self.scratch_file.lstat()
                    require(self.scratch_identity == (info.st_dev, info.st_ino), "pressure scratch path identity changed before cleanup")
                    self.scratch_file.unlink()
                self.scratch_removed = not self.scratch_file.exists() and not self.scratch_file.is_symlink()
            except FileNotFoundError:
                self.scratch_removed = True
            except OSError as error:
                records.append({"role": "scratch_cleanup", "error": str(error), "alive_after_cleanup": True})
        return records


def _worker_exit_was_bounded(record: dict[str, Any]) -> bool:
    code = record.get("exit_code")
    if code == 0:
        return True
    if code == -signal.SIGTERM:
        return record.get("term_sent_monotonic_ns") is not None and record.get("kill_sent_monotonic_ns") is None
    if code == -signal.SIGKILL:
        return record.get("kill_sent_monotonic_ns") is not None
    return False


def _validate_worker_stderr_capture(record: dict[str, Any], label: str) -> bytes:
    encoded = record["stderr_raw_base64"]
    require(type(encoded) is str and len(encoded) <= ((MAX_WORKER_STDERR_RAW_BYTES + 2) // 3) * 4, f"{label} raw stderr capture exceeds its bound")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PressureError(f"{label} raw stderr capture is not canonical base64: {error}") from error
    require(len(raw) == uint(record["stderr_raw_bytes"], f"{label} stderr byte count", maximum=MAX_WORKER_STDERR_RAW_BYTES), f"{label} raw stderr byte count differs")
    require(digest_bytes(raw) == sha256(record["stderr_raw_sha256"], f"{label} stderr SHA-256"), f"{label} raw stderr digest differs")
    require(type(record["stderr_raw_truncated"]) is bool and record["stderr_raw_truncated"] is False, f"{label} raw stderr capture was truncated")
    require(record["stderr_read_error"] is None, f"{label} raw stderr could not be completely read")
    excerpt = raw.decode("utf-8", errors="replace")[:4096].strip()
    require(record["stderr_output"] == excerpt, f"{label} stderr excerpt differs from its raw capture")
    return raw


def _worker_emit(value: dict[str, Any]) -> None:
    raw = canonical_bytes(value)
    written = os.write(sys.stdout.fileno(), raw)
    require(written == len(raw), "short worker telemetry write")


def _worker_read_start() -> int:
    raw = sys.stdin.buffer.readline(65537)
    require(raw and len(raw) <= 65536 and raw.endswith(b"\n"), "worker did not receive its bounded start barrier")
    value = parse_object(raw[:-1], "worker start barrier", 65536)
    require(raw == canonical_bytes(value), "worker start barrier is not canonical")
    exact_object(value, {"start_monotonic_ns"}, "worker start barrier")
    return uint(value["start_monotonic_ns"], "worker start time", positive=True)


def _sleep_until(
    target_ns: int,
    *,
    deadline_ns: int | None = None,
    maximum_sleep_ns: int = 10_000_000,
    label: str = "monotonic wait",
) -> None:
    uint(target_ns, f"{label} target", positive=True)
    uint(maximum_sleep_ns, f"{label} maximum sleep", positive=True)
    if deadline_ns is not None:
        uint(deadline_ns, f"{label} deadline", positive=True)
        require(target_ns <= deadline_ns, f"{label} target exceeds its finite deadline")
    while True:
        now = time.monotonic_ns()
        if deadline_ns is not None:
            require(now <= deadline_ns, f"{label} exceeded its finite deadline")
        if now >= target_ns:
            return
        sleep_ns = min(target_ns - now, maximum_sleep_ns)
        if deadline_ns is not None:
            sleep_ns = min(sleep_ns, deadline_ns - now)
        if sleep_ns > 0:
            time.sleep(sleep_ns / 1_000_000_000)


def _worker_wait_until(target_ns: int) -> None:
    _sleep_until(target_ns, maximum_sleep_ns=10_000_000, label="worker start barrier")


def _worker_cpu(args: argparse.Namespace) -> None:
    os.sched_setaffinity(0, {args.cpu})
    if os.sched_getaffinity(0) != {args.cpu}:
        raise PressureError("CPU worker could not pin itself to the frozen CPU")
    _worker_emit({"event": "ready", "role": "cpu", "cpu": args.cpu, "recipe_sha256": args.recipe_sha256})
    start_ns = _worker_read_start()
    _worker_wait_until(start_ns)
    interval_ns = args.interval_ms * 1_000_000
    duty_ns = interval_ns * args.duty_basis_points // 10000
    end_ns = start_ns + args.duration_seconds * 1_000_000_000
    sequence = 0
    while sequence * interval_ns < end_ns - start_ns and not _WORKER_STOP_REQUESTED:
        target_end = start_ns + (sequence + 1) * interval_ns
        interval_start = time.monotonic_ns()
        busy_end = min(target_end, interval_start + duty_ns)
        spins = 0
        while time.monotonic_ns() < busy_end:
            spins = (spins * 33 + 1) & 0xFFFFFFFF
        now = time.monotonic_ns()
        if now < target_end:
            time.sleep((target_end - now) / 1_000_000_000)
        actual_end = time.monotonic_ns()
        _worker_emit({
            "schema": PRESSURE_IO_SCHEMA, "role": "cpu", "cpu": args.cpu,
            "recipe_sha256": args.recipe_sha256, "sequence": sequence,
            "start_monotonic_ns": interval_start, "end_monotonic_ns": actual_end,
            "thread_cpu_time_ns": time.thread_time_ns(), "spin_witness": spins,
        })
        sequence += 1


def _worker_disk(args: argparse.Namespace) -> None:
    scratch = Path(args.scratch_file)
    direct_flag = getattr(os, "O_DIRECT", None)
    require(type(direct_flag) is int and direct_flag > 0, "Python/Linux does not expose O_DIRECT for independent block-I/O pressure")
    flags = os.O_RDWR | direct_flag | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(scratch, flags, 0o600)
    payload_map: mmap.mmap | None = None
    payload_view: memoryview | None = None
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_size == args.scratch_bytes, "pressure scratch file does not match its frozen size")
        require(info.st_dev == args.scratch_device and info.st_ino == args.scratch_inode, "pressure scratch file identity changed before worker startup")
        _worker_emit({"event": "ready", "role": "disk", "recipe_sha256": args.recipe_sha256})
        start_ns = _worker_read_start()
        _worker_wait_until(start_ns)
        interval_ns = args.interval_ms * 1_000_000
        end_ns = start_ns + args.duration_seconds * 1_000_000_000
        sequence = 0
        offset = 0
        seed_bytes = hashlib.sha256(str(args.seed).encode("ascii")).digest()
        payload = (seed_bytes * ((BLOCK_BYTES + len(seed_bytes) - 1) // len(seed_bytes)))[:BLOCK_BYTES]
        payload_map = mmap.mmap(-1, BLOCK_BYTES)
        payload_map[:] = payload
        payload_view = memoryview(payload_map)
        while sequence * interval_ns < end_ns - start_ns and not _WORKER_STOP_REQUESTED:
            target_end = start_ns + (sequence + 1) * interval_ns
            interval_start = time.monotonic_ns()
            target_bytes = max(BLOCK_BYTES, args.disk_rate * args.interval_ms // 1000)
            writes = 0
            sync_ns = 0
            while writes < target_bytes and not _WORKER_STOP_REQUESTED:
                if offset + BLOCK_BYTES > args.scratch_bytes:
                    offset = 0
                count = os.pwrite(descriptor, payload_view, offset)
                require(count == BLOCK_BYTES, "short pressure block write")
                offset += count
                writes += count
            sync_start = time.monotonic_ns()
            os.fdatasync(descriptor)
            sync_ns += time.monotonic_ns() - sync_start
            now = time.monotonic_ns()
            if now < target_end:
                time.sleep((target_end - now) / 1_000_000_000)
            actual_end = time.monotonic_ns()
            _worker_emit({
                "schema": PRESSURE_IO_SCHEMA, "role": "disk", "recipe_sha256": args.recipe_sha256,
                "sequence": sequence, "start_monotonic_ns": interval_start,
                "end_monotonic_ns": actual_end, "write_bytes": writes,
                "write_mode": "o_direct", "fdatasync_count": 1, "fdatasync_time_nanoseconds": sync_ns,
            })
            sequence += 1
    finally:
        if payload_view is not None:
            payload_view.release()
        if payload_map is not None:
            payload_map.close()
        os.close(descriptor)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        block = sock.recv(remaining)
        require(block, "loopback echo peer closed early")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def _recv_echo_frame(sock: socket.socket, size: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = size
    while remaining and not _WORKER_STOP_REQUESTED:
        try:
            block = sock.recv(remaining)
        except TimeoutError:
            continue
        if not block:
            if _WORKER_STOP_REQUESTED:
                return None
            raise PressureError("loopback echo peer closed early")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks) if remaining == 0 else None


def _worker_loopback(args: argparse.Namespace) -> None:
    global _WORKER_STOP_REQUESTED
    require(hasattr(socket, "AF_INET"), "host has no IPv4 socket support")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.05)
    address = listener.getsockname()
    server_ready = threading.Event()
    server_errors: list[str] = []

    def serve_echo() -> None:
        connection: socket.socket | None = None
        try:
            while not _WORKER_STOP_REQUESTED:
                try:
                    connection, peer = listener.accept()
                    require(peer[0] == "127.0.0.1", "loopback server accepted a non-loopback peer")
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    connection.settimeout(0.1)
                    server_ready.set()
                    break
                except TimeoutError:
                    continue
            while connection is not None and not _WORKER_STOP_REQUESTED:
                request = _recv_echo_frame(connection, args.payload_bytes)
                if request is None:
                    continue
                connection.sendall(request)
        except (OSError, PressureError) as error:
            if not _WORKER_STOP_REQUESTED:
                server_errors.append(f"{type(error).__name__}: {error}")
            server_ready.set()
        finally:
            if connection is not None:
                connection.close()
            listener.close()

    server_thread = threading.Thread(target=serve_echo, name="pressure-loopback-echo", daemon=False)
    server_thread.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    client.settimeout(2.0)
    client.connect(address)
    require(server_ready.wait(2.0) and not server_errors, "loopback echo server did not become ready")
    _worker_emit({
        "event": "ready", "role": "loopback", "recipe_sha256": args.recipe_sha256,
        "address": ["127.0.0.1", address[1]], "network_namespace_inode": os.stat("/proc/self/ns/net").st_ino,
    })
    start_ns = _worker_read_start()
    _worker_wait_until(start_ns)
    interval_ns = args.interval_ms * 1_000_000
    end_ns = start_ns + args.duration_seconds * 1_000_000_000
    payload_size = args.payload_bytes
    payload = hashlib.sha256(str(args.seed).encode("ascii")).digest()
    body = (payload * ((payload_size - 8 + len(payload) - 1) // len(payload)))[:payload_size - 8]
    sequence = 0
    next_request = 0
    request_id = 0
    try:
        while sequence * interval_ns < end_ns - start_ns and not _WORKER_STOP_REQUESTED:
            target_end = start_ns + (sequence + 1) * interval_ns
            interval_start = time.monotonic_ns()
            histogram = [0] * 64
            requests = 0
            bytes_on_wire = 0
            rate_interval_ns = max(1, 1_000_000_000 // args.requests_per_second)
            while time.monotonic_ns() < target_end and not _WORKER_STOP_REQUESTED:
                now = time.monotonic_ns()
                if now < next_request:
                    time.sleep(min((next_request - now) / 1_000_000_000, max(0.00005, (target_end - now) / 1_000_000_000)))
                    continue
                request_id += 1
                payload_bytes = struct.pack("!Q", request_id) + body
                sent = time.monotonic_ns()
                try:
                    client.sendall(payload_bytes)
                    echoed = _recv_exact(client, payload_size)
                except (OSError, PressureError):
                    if _WORKER_STOP_REQUESTED:
                        break
                    raise
                received = time.monotonic_ns()
                require(echoed == payload_bytes, "loopback echo payload differs from the seeded request")
                latency = max(1, received - sent)
                bucket = min(63, latency.bit_length())
                histogram[bucket] += 1
                requests += 1
                bytes_on_wire += payload_size * 2
                next_request = sent + rate_interval_ns
            now = time.monotonic_ns()
            if now < target_end:
                time.sleep((target_end - now) / 1_000_000_000)
            actual_end = time.monotonic_ns()
            if requests == 0 and _WORKER_STOP_REQUESTED:
                break
            _worker_emit({
                "schema": PRESSURE_IO_SCHEMA, "role": "loopback", "recipe_sha256": args.recipe_sha256,
                "sequence": sequence, "start_monotonic_ns": interval_start,
                "end_monotonic_ns": actual_end, "requests_completed": requests,
                "bytes_on_wire": bytes_on_wire, "latency_histogram": histogram,
                "p99_upper_latency_nanoseconds": _histogram_p99_upper(histogram),
            })
            sequence += 1
    finally:
        _WORKER_STOP_REQUESTED = True
        client.close()
        server_thread.join(timeout=1.0)
        require(not server_thread.is_alive(), "loopback echo server did not stop")
        require(not server_errors, "loopback echo server failed: " + "; ".join(server_errors))


def worker_main(args: argparse.Namespace) -> int:
    require(re.fullmatch(r"[0-9a-f]{64}", args.recipe_sha256) is not None, "worker recipe SHA is malformed")
    def stop_worker(_signum: int, _frame: Any) -> None:
        global _WORKER_STOP_REQUESTED
        _WORKER_STOP_REQUESTED = True
    signal.signal(signal.SIGTERM, stop_worker)
    if args.kind == "cpu":
        _worker_cpu(args)
    elif args.kind == "disk":
        _worker_disk(args)
    elif args.kind == "loopback":
        _worker_loopback(args)
    else:
        raise PressureError("unknown private worker kind")
    return 0


def _validate_worker_record(value: dict[str, Any], child: dict[str, Any], seq: int, recipe_sha: str) -> dict[str, Any]:
    require(value.get("schema") == PRESSURE_IO_SCHEMA and value.get("sequence") == seq and value.get("recipe_sha256") == recipe_sha, "worker telemetry schema, sequence, or recipe binding differs")
    expected_role = child["role"]
    require(value.get("role") == expected_role, "worker telemetry role differs")
    if child["cpu"] is not None:
        require(value.get("cpu") == child["cpu"], "CPU worker telemetry reports the wrong CPU")
        exact_object(value, {"schema", "role", "cpu", "recipe_sha256", "sequence", "start_monotonic_ns", "end_monotonic_ns", "thread_cpu_time_ns", "spin_witness"}, "CPU worker telemetry")
        uint(value["thread_cpu_time_ns"], "CPU worker time")
        uint(value["spin_witness"], "CPU spin witness")
    elif expected_role == "disk":
        exact_object(value, {"schema", "role", "recipe_sha256", "sequence", "start_monotonic_ns", "end_monotonic_ns", "write_bytes", "write_mode", "fdatasync_count", "fdatasync_time_nanoseconds"}, "disk worker telemetry")
        require(uint(value["write_bytes"], "worker written bytes", positive=True) % BLOCK_BYTES == 0, "disk worker writes are sparse or unaligned")
        require(value["write_mode"] == "o_direct", "disk worker did not use direct block I/O")
        require(value["fdatasync_count"] == 1, "disk worker omitted its bounded per-window synchronization")
        uint(value["fdatasync_time_nanoseconds"], "fdatasync time")
    else:
        exact_object(value, {"schema", "role", "recipe_sha256", "sequence", "start_monotonic_ns", "end_monotonic_ns", "requests_completed", "bytes_on_wire", "latency_histogram", "p99_upper_latency_nanoseconds"}, "loopback worker telemetry")
        uint(value["requests_completed"], "loopback requests", positive=True)
        uint(value["bytes_on_wire"], "loopback bytes", positive=True)
        require(value["bytes_on_wire"] == value["requests_completed"] * recipe_schedule_payload(recipe_sha), "loopback byte/request count differs")
        require(type(value["latency_histogram"]) is list and len(value["latency_histogram"]) == 64, "loopback histogram is malformed")
        require(sum(uint(item, "loopback latency bucket") for item in value["latency_histogram"]) == value["requests_completed"], "loopback latency histogram count differs from requests")
        require(value["p99_upper_latency_nanoseconds"] == _histogram_p99_upper(value["latency_histogram"]), "loopback p99 does not match its histogram")
    start = uint(value["start_monotonic_ns"], "worker window start", positive=True)
    end = uint(value["end_monotonic_ns"], "worker window end", positive=True)
    require(end > start, "worker interval is empty")
    return value


_WORKER_PAYLOAD_BY_RECIPE: dict[str, int] = {}


def recipe_schedule_payload(recipe_sha: str) -> int:
    try:
        return _WORKER_PAYLOAD_BY_RECIPE[recipe_sha]
    except KeyError as error:
        raise PressureError("loopback payload is not bound to the active recipe") from error


def _counter_snapshot(device_chain: list[dict[str, Any]]) -> dict[str, Any]:
    devices = _disk_stats()
    result: dict[str, Any] = {}
    for item in device_chain:
        device = item["device"]
        require(device in devices, f"backing block device {device} has no independent diskstats")
        result[device] = devices[device]
    return {"cpu": _cpu_stats(), "cpu_psi": _read_psi(Path("/proc/pressure/cpu"), "CPU PSI"),
            "io_psi": _read_psi(Path("/proc/pressure/io"), "I/O PSI"),
            "disk": result, "loopback": _net_stats()}


def _build_sample(
    recipe: dict[str, Any], seq: int, start_ns: int, end_ns: int,
    before: dict[str, Any], after: dict[str, Any], worker_records: dict[str, Any],
    worker_io_before: dict[str, dict[str, int]], worker_io_after: dict[str, dict[str, int]],
    app_active: bool,
) -> dict[str, Any]:
    app_storage = recipe["storage"]["backing_chain"]
    device = recipe["storage"]["application_device"]
    cpu = _cpu_window(before["cpu"], after["cpu"], recipe["schedule"]["pressure_cpu_affinity"])
    cpu_psi_delta = after["cpu_psi"]["some"] - before["cpu_psi"]["some"]
    io_psi_delta = after["io_psi"]["some"] - before["io_psi"]["some"]
    require(cpu_psi_delta >= 0 and io_psi_delta >= 0, "PSI counters regressed")
    block = _disk_window(before["disk"], after["disk"], device)
    lo = _counter_delta(before["loopback"], after["loopback"], (
        "rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped",
    ), "lo")
    loopback_workers = worker_records["loopback"]
    sample = {
        "schema": EVENT_SCHEMA,
        "sequence": seq,
        "interval_start_monotonic_ns": start_ns,
        "interval_end_monotonic_ns": end_ns,
        "app_active": app_active,
        "cpu": cpu,
        "cpu_psi_delta_microseconds": cpu_psi_delta,
        "block": block,
        "io_psi_delta_microseconds": io_psi_delta,
        "block_device_chain": app_storage,
        "loopback_counters": lo,
        "loopback": loopback_workers,
        "pressure_generators": {
            "cpu": [
                {
                    "cpu": item["cpu"],
                    "thread_cpu_time_ns": item["thread_cpu_time_ns"],
                    "spin_witness": item["spin_witness"],
                    "start_monotonic_ns": item["start_monotonic_ns"],
                    "end_monotonic_ns": item["end_monotonic_ns"],
                }
                for item in sorted(worker_records["cpu"], key=lambda value: value["cpu"])
            ],
            "disk": {
                "write_bytes": worker_records["disk"]["write_bytes"],
                "write_mode": worker_records["disk"]["write_mode"],
                "fdatasync_count": worker_records["disk"]["fdatasync_count"],
                "fdatasync_time_nanoseconds": worker_records["disk"]["fdatasync_time_nanoseconds"],
                "start_monotonic_ns": worker_records["disk"]["start_monotonic_ns"],
                "end_monotonic_ns": worker_records["disk"]["end_monotonic_ns"],
            },
        },
        "worker_process_io": {
            key: {
                "write_bytes_delta": max(0, worker_io_after[key]["write_bytes"] - worker_io_before[key]["write_bytes"]),
                "syscw_delta": max(0, worker_io_after[key]["syscw"] - worker_io_before[key]["syscw"]),
            }
            for key in worker_io_before
        },
    }
    thresholds = recipe.get("readiness_thresholds")
    if type(thresholds) is dict:
        sample["readiness"] = _readiness_from_sample(sample, thresholds)
    return sample


def _calibration_sample_observations(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for sample in samples:
        block = sample["block"]
        disk = sample["pressure_generators"]["disk"]
        observations.append({
            "sequence": sample["sequence"],
            "interval_start_monotonic_ns": sample["interval_start_monotonic_ns"],
            "interval_end_monotonic_ns": sample["interval_end_monotonic_ns"],
            "block": {
                key: block[key] for key in (
                    "writes_completed", "sectors_written", "write_bytes", "write_milliseconds",
                    "io_milliseconds", "weighted_io_milliseconds", "in_flight",
                )
            },
            "io_psi_delta_microseconds": sample["io_psi_delta_microseconds"],
            "disk_generator": disk,
            "disk_worker_process_io": sample["worker_process_io"]["disk"],
        })
    return observations


def _launch_binding(path: Path, recipe: dict[str, Any]) -> tuple[dict[str, Any], bytes, str]:
    value, raw, raw_sha = verify_canonical_json(path, "application launch binding", 256 * 1024)
    binding = exact_object(value, {"schema", "recipe_sha256", "nonce", "process", "launch_binding_sha256"}, "application launch binding")
    require(binding["schema"] == LAUNCH_SCHEMA, "unsupported application launch binding schema")
    require(binding["recipe_sha256"] == recipe["recipe_sha256"] and binding["nonce"] == recipe["identity"]["nonce"], "application launch binding belongs to a different frozen recipe/nonce")
    process = exact_object(binding["process"], {"pid", "start_ticks", "executable_path", "executable_sha256", "cwd", "tmpdir_path", "cpu_affinity", "network_namespace_inode"}, "application process identity")
    pid = uint(process["pid"], "application PID", positive=True, maximum=(1 << 31) - 1)
    start_ticks = uint(process["start_ticks"], "application process start ticks", positive=True)
    executable_path = string(process["executable_path"], "application executable path", MAX_PATH_BYTES)
    executable_sha = sha256(process["executable_sha256"], "application executable SHA-256")
    cwd = string(process["cwd"], "application cwd", MAX_PATH_BYTES)
    tmpdir_path = string(process["tmpdir_path"], "application TMPDIR", MAX_PATH_BYTES)
    affinity = _validate_cpu_list(process["cpu_affinity"], "application CPU affinity")
    netns = uint(process["network_namespace_inode"], "application network namespace inode", positive=True)
    claimed = sha256(binding["launch_binding_sha256"], "launch binding digest")
    body = {key: value for key, value in binding.items() if key != "launch_binding_sha256"}
    require(claimed == digest_object(body), "application launch binding digest is invalid")
    require(executable_path == recipe["process"]["executable_path"], "application launch executable path differs from the frozen binary")
    require(executable_sha == recipe["files"]["application_binary"]["raw_sha256"], "application launch binary hash differs from the frozen binary")
    require(affinity == recipe["schedule"]["application_cpu_affinity"], "application launch CPU affinity differs from frozen conditions")
    require(netns == recipe["network"]["network_namespace_inode"], "application launch network namespace differs from frozen conditions")
    require(cwd in recipe["storage"]["application_io_paths"], "application launch cwd is not among its frozen I/O paths")
    require(tmpdir_path == recipe["process"]["application_tmpdir_path"] and tmpdir_path in recipe["storage"]["application_io_paths"], "application launch TMPDIR differs from the frozen I/O path")
    current = _proc_stat(pid)
    require(current["start_ticks"] == start_ticks and current["state"] not in ("Z", "X"), "application PID was reused, exited, or start identity changed")
    require(_proc_link(pid, "exe") == executable_path, "live application executable path differs from its launch binding")
    require(_proc_link(pid, "cwd") == cwd, "live application cwd differs from its launch binding")
    require(_proc_net_namespace(pid) == netns, "live application network namespace differs from its launch binding")
    require(_affinity(pid) == affinity, "live application CPU affinity differs from its launch binding")
    environ = _read_proc_environ(pid)
    require(environ.get("ALLOCATBELT_APP_PRESSURE_NONCE") == recipe["identity"]["nonce"], "live application lacks the frozen pressure nonce")
    require(environ.get("TMPDIR") == tmpdir_path, "live application TMPDIR differs from frozen storage path")
    binary_raw, actual_binary_sha = read_stable(Path(executable_path), "live application binary", MAX_APP_BINARY_BYTES)
    del binary_raw
    require(actual_binary_sha == executable_sha, "live application binary bytes differ from its frozen hash")
    final_stat = _proc_stat(pid)
    require(final_stat["start_ticks"] == start_ticks and final_stat["state"] not in ("Z", "X"), "application PID/start identity changed during launch authentication")
    return binding, raw, raw_sha


def _read_proc_environ(pid: int) -> dict[str, str]:
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError as error:
        raise PressureError(f"cannot read application environment for PID {pid}: {error}") from error
    require(len(raw) <= 16 * 1024 * 1024, "application environment exceeds its finite bound")
    result: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        key, sep, value = item.partition(b"=")
        if sep:
            try:
                name = key.decode("utf-8")
                text = value.decode("utf-8")
            except UnicodeError as error:
                raise PressureError("application environment is not UTF-8") from error
            if name in ("ALLOCATBELT_APP_PRESSURE_NONCE", "TMPDIR"):
                result[name] = text
    return result


def _write_event_raw(stream: Any, raw: bytes, *, maximum_bytes: int = MAX_ARTIFACT_BYTES) -> bytes:
    require(len(raw) <= MAX_EVENT_LINE_BYTES and raw.endswith(b"\n"), "pressure event line exceeds its frozen line bound")
    require(stream.tell() + len(raw) <= maximum_bytes, "pressure event stream exceeded its frozen byte budget")
    written = stream.write(raw)
    require(written == len(raw), "short pressure event write")
    stream.flush()
    return raw


def _write_event(stream: Any, event: dict[str, Any], *, maximum_bytes: int = MAX_ARTIFACT_BYTES) -> bytes:
    return _write_event_raw(stream, canonical_bytes(event), maximum_bytes=maximum_bytes)


def _write_ready_marker(path: Path, recipe: dict[str, Any], ready_sample: dict[str, Any]) -> str:
    body = {
        "schema": READY_SCHEMA,
        "recipe_sha256": recipe["recipe_sha256"],
        "condition_sha256": recipe["condition_sha256"],
        "nonce": recipe["identity"]["nonce"],
        "pressure_ready_monotonic_ns": ready_sample["interval_end_monotonic_ns"],
        "readiness": ready_sample["readiness"],
    }
    value = {**body, "ready_sha256": digest_object(body)}
    return safe_write_new(path, canonical_bytes(value), "pressure readiness marker", maximum=64 * 1024)


def _wait_for_launch(path: Path, recipe: dict[str, Any], deadline_ns: int) -> tuple[dict[str, Any], bytes, str, int]:
    while time.monotonic_ns() < deadline_ns:
        if path.exists():
            try:
                binding, raw, sha = _launch_binding(path, recipe)
                return binding, raw, sha, time.monotonic_ns()
            except PressureError:
                # A launcher may create its private file just before completing
                # the canonical atomic publication. Retry only until deadline.
                if path.is_symlink() or path.is_dir():
                    raise
        time.sleep(0.02)
    raise PressureError("authenticated application launch binding did not arrive before the startup deadline")


def _proc_identity_still_same(binding: dict[str, Any]) -> bool:
    process = binding.get("process", binding.get("identity"))
    require(type(process) is dict, "application process identity is missing")
    try:
        return _pid_exists(process["pid"], process["start_ticks"])
    except PressureError:
        return False


def run_pressure(recipe_path: Path, expected_sha: str, launch_path: Path, output_path: Path, ready_path: Path) -> dict[str, Any]:
    recipe_value, _, _recipe_raw_sha = verify_canonical_json(recipe_path, "frozen pressure recipe", MAX_RECIPE_BYTES)
    recipe = _validate_recipe(recipe_value, expected_sha)
    actual_recipe_sha = recipe["recipe_sha256"]
    _verify_recipe_inputs(recipe)
    _verify_live_environment(recipe)
    require(_hash_script(DRIVER_PATH, "pressure driver") == recipe["script_hashes"]["driver_sha256"], "pressure driver changed after recipe freeze")
    require(_hash_script(READER_PATH, "pressure reader") == recipe["script_hashes"]["reader_sha256"], "pressure reader changed after recipe freeze")
    require(output_path.is_absolute() and ready_path.is_absolute(), "run artifact paths must be absolute")
    output_dir = safe_directory(output_path, "pressure run output directory", create=True)
    require(ready_path == output_dir / "pressure-ready.json", "pressure ready marker path must be the canonical run artifact")
    require(launch_path == output_dir / "launch-record.json", "application launch record path must be the canonical run artifact")
    require(not ready_path.exists() and not launch_path.exists() and not launch_path.is_symlink(), "pressure ready marker or launch binding already exists")
    launch_path.parent.resolve(strict=True)
    require(launch_path.parent == output_dir or launch_path.parent.is_dir(), "launch binding parent is unavailable")
    require(os.getsid(0) == os.getpid(), "pressure driver must be launched as a fresh session leader")
    _storage_reserve(recipe, output_dir, reserve_event_budget=True)

    events_path = output_dir / "events.jsonl"
    process_binding_path = output_dir / "process-binding.json"
    result_path = output_dir / "run.json"
    for path in (events_path, process_binding_path, result_path):
        require(not path.exists() and not path.is_symlink(), f"pressure artifact already exists: {path.name}")

    schedule = recipe["schedule"]
    _WORKER_PAYLOAD_BY_RECIPE[recipe["recipe_sha256"]] = schedule["network_payload_bytes"] * 2
    children = WorkerSet(recipe)
    events_hash = hashlib.sha256()
    event_count = 0
    sample_count = 0
    sample_event_bytes = 0
    event_max_bytes = recipe["artifact_budget"]["maximum_event_bytes"]
    startup_readiness: deque[bool] = deque(maxlen=schedule["startup_ready_windows"])
    active_readiness_windows = 0
    active_readiness_ok = True
    process_binding: dict[str, Any] | None = None
    process_binding_raw_sha: str | None = None
    launch_raw_sha: str | None = None
    run_start_ns = time.monotonic_ns()
    failure: str | None = None
    cleanup_records: list[dict[str, Any]] = []
    readiness_marker_sha: str | None = None
    app_started_ns: int | None = None
    app_exit_ns: int | None = None
    app_last_alive_ns: int | None = None
    app_last_alive_sequence: int | None = None
    final_status = "failed"
    events_stream = events_path.open("xb", buffering=0)
    hard_deadline_ns = run_start_ns + schedule["total_deadline_seconds"] * 1_000_000_000
    startup_deadline_ns = run_start_ns + schedule["startup_deadline_seconds"] * 1_000_000_000
    try:
        _storage_reserve(recipe, output_dir, reserve_event_budget=True)
        children.spawn()
        _storage_reserve(recipe, output_dir, scratch_reserved=True, reserve_event_budget=True)
        children.await_ready(startup_deadline_ns)
        start_ns = time.monotonic_ns() + 250_000_000
        children.begin(start_ns)
        start_event = {
            "schema": EVENT_SCHEMA, "kind": "pressure_start", "sequence": -1,
            "recipe_sha256": actual_recipe_sha, "monotonic_ns": start_ns,
            "workers": [{"role": child["role"], "cpu": child["cpu"], "pid": child["pid"], "start_ticks": child["start_ticks"], "pgid": child["pgid"], "session_id": child["session_id"]} for child in children.children],
            "storage_device": recipe["storage"]["application_device"],
            "network_namespace_inode": recipe["network"]["network_namespace_inode"],
        }
        raw_start = _write_event(events_stream, start_event, maximum_bytes=event_max_bytes)
        events_hash.update(raw_start)
        event_count += 1
        # Wait for the first exact sample before opening the application gate.
        selector_start = start_ns
        interval_ns = schedule["sample_interval_ms"] * 1_000_000
        counters_before: dict[str, Any] | None = None
        worker_io_before: dict[str, dict[str, int]] | None = None
        for seq in range(schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"]):
            require(time.monotonic_ns() < hard_deadline_ns, "pressure run total deadline expired")
            target_start = start_ns + seq * interval_ns
            target_end = target_start + interval_ns
            _sleep_until(target_start, deadline_ns=hard_deadline_ns, maximum_sleep_ns=10_000_000, label="pressure sample start")
            before = _counter_snapshot(recipe["storage"]["backing_chain"])
            before_mono = time.monotonic_ns()
            if counters_before is not None:
                before = counters_before
                before_mono = selector_start
            worker_before = children.process_io()
            if worker_io_before is not None:
                worker_before = worker_io_before
            ready_deadline = target_end + max(500_000_000, interval_ns // 2)
            raw_worker_records = children.wait_sample(seq, ready_deadline)
            worker_records = _normalize_worker_records(raw_worker_records, children.children, seq, schedule, actual_recipe_sha)
            _sleep_until(target_end, deadline_ns=hard_deadline_ns, maximum_sleep_ns=5_000_000, label="pressure sample end")
            after = _counter_snapshot(recipe["storage"]["backing_chain"])
            observed_end = time.monotonic_ns()
            worker_after = children.process_io()
            app_active = False
            if process_binding is not None:
                app_active = _proc_identity_still_same(process_binding)
                if app_active:
                    app_last_alive_ns = observed_end
                    app_last_alive_sequence = seq
                else:
                    app_exit_ns = app_last_alive_ns
            # First pressure sample is a complete independent window. Publish
            # readiness before accepting a launch binding from the controller.
            sample = _build_sample(
                recipe, seq, before_mono, observed_end, before, after,
                worker_records, worker_before, worker_after, app_active,
            )
            require(observed_end - before_mono <= interval_ns + max(500_000_000, interval_ns), "pressure telemetry sample is sparse")
            sample_count += 1
            if process_binding is None:
                startup_readiness.append(sample["readiness"]["all_ready"])
            elif app_active and app_started_ns is not None and sample["interval_start_monotonic_ns"] >= app_started_ns:
                active_readiness_windows += 1
                active_readiness_ok = active_readiness_ok and sample["readiness"]["all_ready"]
            sample_event = {"schema": EVENT_SCHEMA, "kind": "sample", **sample}
            raw_sample = canonical_bytes(sample_event)
            require(len(raw_sample) <= recipe["artifact_budget"]["maximum_sample_line_bytes"], "pressure sample exceeds its frozen conservative row bound")
            require(sample_event_bytes + len(raw_sample) <= recipe["artifact_budget"]["sample_events_bytes"], "pressure samples exceed their frozen aggregate row budget")
            raw_sample = _write_event_raw(events_stream, raw_sample, maximum_bytes=event_max_bytes)
            sample_event_bytes += len(raw_sample)
            events_hash.update(raw_sample)
            event_count += 1
            if process_binding is None and seq + 1 >= schedule["startup_ready_windows"]:
                require(len(startup_readiness) == schedule["startup_ready_windows"] and all(startup_readiness), "measured pressure readiness did not pass the frozen startup windows")
                readiness_marker_sha = _write_ready_marker(ready_path, recipe, sample)
                binding, launch_raw, launch_raw_sha, observed_launch_ns = _wait_for_launch(
                    launch_path, recipe, startup_deadline_ns,
                )
                process_binding = {
                    "schema": PROCESS_BINDING_SCHEMA,
                    "recipe_sha256": actual_recipe_sha,
                    "launch_record_sha256": launch_raw_sha,
                    "identity": {
                        "pid": binding["process"]["pid"],
                        "start_ticks": binding["process"]["start_ticks"],
                        "nonce": recipe["identity"]["nonce"],
                        "executable_sha256": binding["process"]["executable_sha256"],
                        "tmpdir_path": binding["process"]["tmpdir_path"],
                        "cpu_affinity": binding["process"]["cpu_affinity"],
                        "network_namespace_inode": binding["process"]["network_namespace_inode"],
                    },
                    "observed_monotonic_ns": observed_launch_ns,
                    "pressure_ready_monotonic_ns": sample["interval_end_monotonic_ns"],
                    "readiness_snapshot": sample["readiness"],
                    "application_capacity_calibration_sha256": recipe["files"]["application_capacity_calibration"]["raw_sha256"],
                    "pressure_contention_calibration_sha256": recipe["pressure_calibration"]["raw_sha256"],
                }
                process_binding["process_binding_sha256"] = digest_object(process_binding)
                process_binding_raw_sha = safe_write_new(process_binding_path, canonical_bytes(process_binding), "bound application process identity", maximum=256 * 1024)
                app_started_ns = observed_launch_ns
                event = {
                    "schema": EVENT_SCHEMA, "kind": "application_start", "sequence": seq,
                    "monotonic_ns": observed_launch_ns,
                    "pid": binding["process"]["pid"], "start_ticks": binding["process"]["start_ticks"],
                    "launch_record_sha256": launch_raw_sha,
                }
                raw_app = _write_event(events_stream, event, maximum_bytes=event_max_bytes)
                events_hash.update(raw_app)
                event_count += 1
                copied_launch = output_dir / "launch-record.json"
                require(launch_path == copied_launch and copied_launch.exists(), "launch record was not published at its canonical artifact path")
                reread_binding, reread_raw, reread_sha = verify_canonical_json(copied_launch, "copied application launch binding", 256 * 1024)
                require(reread_raw == launch_raw and reread_sha == launch_raw_sha and reread_binding == binding, "application launch record changed after process binding")
                # The launch binding file is reread after creation; no mutable
                # caller buffer is treated as the authenticated process proof.
                del launch_raw
            if process_binding is not None and not _proc_identity_still_same(process_binding):
                # The exact PID/start pair is also checked in the launch record
                # below; if the process ended, the final interval closes here.
                app_exit_ns = app_last_alive_ns
                require(app_exit_ns is not None and app_last_alive_sequence is not None, "application exited before an independent live sample was recorded")
                exit_event = {
                    "schema": EVENT_SCHEMA, "kind": "application_exit", "sequence": app_last_alive_sequence,
                    "monotonic_ns": app_exit_ns, "pid": binding["process"]["pid"],
                    "start_ticks": binding["process"]["start_ticks"], "exit_observed": True,
                }
                raw_exit = _write_event(events_stream, exit_event, maximum_bytes=event_max_bytes)
                events_hash.update(raw_exit)
                event_count += 1
                if seq + 1 < schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"]:
                    # Its own lifetime determines the pressure stop; minimum
                    # overlap and readiness are checked after cleanup.
                    break
            if seq % max(1, 1000 // schedule["sample_interval_ms"]) == 0:
                _storage_reserve(recipe, output_dir, scratch_reserved=True)
            # Reduce sample memory to the bounded numeric fields needed for
            # measured readiness and the independent reader recomputes raw
            # events directly from disk.
            selector_start = observed_end
            counters_before = after
            worker_io_before = worker_after
        require(process_binding is not None, "application launch binding was not observed")
        if app_exit_ns is None:
            process = process_binding["identity"]
            if _pid_exists(process["pid"], process["start_ticks"]):
                raise PressureError("application did not exit within the frozen pressure schedule")
            app_exit_ns = app_last_alive_ns
            require(app_exit_ns is not None and app_last_alive_sequence is not None, "application exited before an independent live sample was recorded")
            exit_event = {
                "schema": EVENT_SCHEMA, "kind": "application_exit",
                "sequence": app_last_alive_sequence, "monotonic_ns": app_exit_ns,
                "pid": process["pid"], "start_ticks": process["start_ticks"],
                "exit_observed": True,
            }
            raw_exit = _write_event(events_stream, exit_event, maximum_bytes=event_max_bytes)
            events_hash.update(raw_exit)
            event_count += 1
        require(app_started_ns is not None and app_exit_ns is not None, "application overlap bounds are missing")
        overlap_ns = app_exit_ns - app_started_ns
        require(overlap_ns >= schedule["minimum_overlap_seconds"] * 1_000_000_000, "application/pressure overlap is shorter than the frozen minimum")
        require(active_readiness_windows > 0 and active_readiness_ok, "measured readiness failed during the application pressure overlap")
        final_status = "complete"
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
        final_status = "failed"
        try:
            failure_event = {"schema": EVENT_SCHEMA, "kind": "pressure_failure", "sequence": sample_count, "monotonic_ns": time.monotonic_ns(), "failure": failure}
            raw_failure = _write_event(events_stream, failure_event, maximum_bytes=event_max_bytes)
            events_hash.update(raw_failure)
            event_count += 1
        except BaseException:
            failure = failure or "failed to preserve bounded pressure failure event"
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        term_seconds = schedule["term_deadline_seconds"]
        kill_seconds = schedule["kill_deadline_seconds"]
        try:
            cleanup_records = children.cleanup(term_seconds, kill_seconds)
        except BaseException as cleanup_error:
            cleanup_records = [{"role": "cleanup", "error": f"{type(cleanup_error).__name__}: {cleanup_error}", "alive_after_cleanup": True}]
            failure = failure or f"cleanup failed: {cleanup_error}"
            final_status = "failed"
        try:
            cleanup_ok_partial = bool(cleanup_records) and all(
                _worker_exit_was_bounded(item) and item.get("alive_after_cleanup") is False
                and item.get("term_error") is None and item.get("kill_error") is None and item.get("reap_error") is None and item.get("stderr_output") == ""
                and item.get("stderr_raw_bytes") == 0 and item.get("stderr_raw_truncated") is False and item.get("stderr_read_error") is None
                for item in cleanup_records if item.get("role") != "scratch_cleanup"
            ) and not any(item.get("role") == "scratch_cleanup" and item.get("error") for item in cleanup_records)
            cleanup_event = {
                "schema": EVENT_SCHEMA,
                "kind": "pressure_cleanup",
                "monotonic_ns": time.monotonic_ns(),
                "workers": cleanup_records,
                "scratch_file_removed": children.scratch_removed,
                "cleanup_ok": cleanup_ok_partial,
            }
            raw_cleanup = _write_event(events_stream, cleanup_event, maximum_bytes=event_max_bytes)
            events_hash.update(raw_cleanup)
            event_count += 1
        except BaseException as error:
            failure = failure or f"terminal cleanup event could not be preserved: {type(error).__name__}: {error}"
            final_status = "failed"
        try:
            if not events_stream.closed:
                events_stream.flush()
                os.fsync(events_stream.fileno())
        except BaseException as error:
            failure = failure or f"event stream close failed: {type(error).__name__}: {error}"
            final_status = "failed"
        finally:
            if not events_stream.closed:
                try:
                    events_stream.close()
                except BaseException as error:
                    failure = failure or f"event stream close failed: {type(error).__name__}: {error}"
                    final_status = "failed"

    cleanup_ok = bool(cleanup_records) and all(
        _worker_exit_was_bounded(item) and item.get("alive_after_cleanup") is False
        and item.get("term_error") is None and item.get("kill_error") is None and item.get("reap_error") is None and item.get("stderr_output") == ""
        and item.get("stderr_raw_bytes") == 0 and item.get("stderr_raw_truncated") is False and item.get("stderr_read_error") is None
        for item in cleanup_records if item.get("role") != "scratch_cleanup"
    ) and not any(item.get("role") == "scratch_cleanup" and item.get("error") for item in cleanup_records)
    if not cleanup_ok:
        failure = failure or "pressure worker process/session cleanup or reaping failed"
        final_status = "failed"
    try:
        events_bytes, events_sha = hash_stable(events_path, "pressure event stream", event_max_bytes)
        require(events_sha == events_hash.hexdigest(), "live event digest differs from the bounded event file")
    except BaseException as error:
        failure = failure or f"bounded event verification failed after cleanup: {type(error).__name__}: {error}"
        final_status = "failed"
        events_sha = events_hash.hexdigest()
        try:
            events_bytes = events_path.stat().st_size
        except OSError:
            events_bytes = 0
    try:
        if process_binding is None:
            process_binding = {
                "schema": PROCESS_BINDING_SCHEMA, "recipe_sha256": actual_recipe_sha,
                "launch_record_sha256": None, "identity": None,
                "observed_monotonic_ns": None, "pressure_ready_monotonic_ns": None,
                "readiness_snapshot": None,
                "application_capacity_calibration_sha256": recipe["files"]["application_capacity_calibration"]["raw_sha256"],
                "pressure_contention_calibration_sha256": recipe["pressure_calibration"]["raw_sha256"],
            }
            process_binding["process_binding_sha256"] = digest_object(process_binding)
            if not process_binding_path.exists():
                process_binding_raw_sha = safe_write_new(process_binding_path, canonical_bytes(process_binding), "failed process binding", maximum=256 * 1024)
        if launch_raw_sha is not None and process_binding["launch_record_sha256"] != launch_raw_sha:
            raise PressureError("process binding launch record hash differs")
        if process_binding_path.exists():
            _, _, saved_sha = verify_canonical_json(process_binding_path, "bound process identity", 256 * 1024)
            if saved_sha != digest_bytes(canonical_bytes(process_binding)):
                raise PressureError("saved process binding changed during pressure run")
            process_binding_raw_sha = saved_sha
    except BaseException as error:
        failure = failure or f"process binding preservation failed after cleanup: {type(error).__name__}: {error}"
        final_status = "failed"
    if time.monotonic_ns() > hard_deadline_ns:
        failure = failure or "pressure run exceeded the frozen total deadline during cleanup"
        final_status = "failed"
    result_body = {
        "schema": RUN_SCHEMA,
        "status": final_status,
        "failure": failure,
        "recipe_sha256": actual_recipe_sha,
        "condition_sha256": recipe["condition_sha256"],
        "events_sha256": events_sha,
        "events_bytes": events_bytes,
        "event_count": event_count,
        "sample_count": sample_count,
        "process_binding_sha256": process_binding_raw_sha,
        "launch_record_sha256": launch_raw_sha,
        "readiness_marker_sha256": readiness_marker_sha,
        "application_overlap_nanoseconds": max(0, (app_exit_ns or 0) - (app_started_ns or 0)),
        "worker_cleanup": cleanup_records,
        "cleanup_ok": cleanup_ok,
        "scratch_file_removed": children.scratch_removed,
        "start_monotonic_ns": run_start_ns,
        "finish_monotonic_ns": time.monotonic_ns(),
        "deadlines": {
            "startup_seconds": schedule["startup_deadline_seconds"],
            "total_seconds": schedule["total_deadline_seconds"],
            "term_seconds": schedule["term_deadline_seconds"],
            "kill_seconds": schedule["kill_deadline_seconds"],
        },
    }
    result = {**result_body, "run_sha256": digest_object(result_body)}
    try:
        run_raw_sha = safe_write_new(result_path, canonical_bytes(result), "pressure run receipt", maximum=MAX_MANIFEST_BYTES)
    except BaseException as error:
        raise PressureError(f"failed to preserve the post-cleanup run receipt: {type(error).__name__}: {error}") from error
    require(final_status == "complete", failure or "bounded pressure run failed")
    return {"status": final_status, "recipe_sha256": actual_recipe_sha, "events_sha256": events_sha,
            "launch_record_sha256": launch_raw_sha,
            "process_binding_sha256": process_binding_raw_sha,
            "readiness_marker_sha256": readiness_marker_sha,
            "run_sha256": run_raw_sha, "run_receipt_sha256": result["run_sha256"],
            "path": str(output_dir)}


def calibrate(request_path: Path, output_path: Path) -> dict[str, Any]:
    request, request_raw, _ = verify_canonical_json(request_path, "pressure calibration request", MAX_REQUEST_BYTES)
    require(request_raw == canonical_bytes(request), "pressure calibration request is not canonical")
    normalized = _request(request, calibration=True)
    schedule = normalized["schedule"]
    storage_paths = [Path(path) for path in normalized["storage"]["application_io_paths"]]
    host = _host_facts(schedule["pressure_cpu_affinity"], schedule["application_cpu_affinity"], storage_paths)
    scratch_path = Path(normalized["storage"]["pressure_scratch_path"])
    scratch = _storage_record(scratch_path, "pressure calibration scratch path")
    app_storage = host["application_storage"][0]
    require(scratch["device"] == app_storage["device"] and scratch["mount"]["mount_id"] == app_storage["mount"]["mount_id"] and scratch["backing_chain"] == app_storage["backing_chain"], "calibration scratch path differs from the application backing device")
    host["pressure_scratch"] = scratch
    free = shutil.disk_usage(scratch_path).free
    reserve = schedule["scratch_file_bytes"] + normalized["storage"]["output_minimum_free_bytes"]
    require(free >= reserve, "calibration scratch device lacks the frozen free-space reserve")
    safe_directory(output_path.parent, "calibration output directory")
    require(not output_path.exists() and not output_path.is_symlink(), "pressure calibration output already exists")
    run_dir = output_path.parent / f".pressure-calibration-{normalized['identity']['nonce']}"
    safe_directory(run_dir, "temporary calibration output", create=True)
    fake_recipe_body = {
        "schema": RECIPE_SCHEMA,
        "identity": normalized["identity"],
        "files": normalized["files"],
        "process": normalized["process"],
        "host": host,
        "storage": {**normalized["storage"], "application_device": app_storage["device"], "application_mount_id": app_storage["mount"]["mount_id"], "backing_chain": app_storage["backing_chain"], "non_tmpfs": True},
        "network": {**host["network"], "claim": "ipv4_loopback_shared_kernel_only", "physical_nic_claimed": False},
        "schedule": schedule,
        "pressure_calibration": None,
        "readiness_thresholds": None,
        "script_hashes": {"driver_sha256": _hash_script(DRIVER_PATH, "pressure driver"), "reader_sha256": _hash_script(READER_PATH, "pressure reader")},
        "condition_sha256": digest_object({
            "host_id": normalized["identity"]["host_id"],
            "condition_id": normalized["identity"]["condition_id"],
            "source_manifest_sha256": normalized["files"]["source_manifest"]["raw_sha256"],
            "policy_sha256": normalized["files"]["policy"]["raw_sha256"],
            "application_capacity_calibration_sha256": normalized["files"]["application_capacity_calibration"]["raw_sha256"],
            "host": {
                "kernel_release": host["kernel_release"],
                "boot_id_sha256": host["boot_id_sha256"],
                "allowed_cpu_affinity": host["allowed_cpu_affinity"],
                "pressure_cpu_affinity": host["pressure_cpu_affinity"],
                "application_cpu_affinity": host["application_cpu_affinity"],
            },
            "storage": {"device": app_storage["device"], "mount_id": app_storage["mount"]["mount_id"], "backing_chain": app_storage["backing_chain"]},
            "network": host["network"],
            "schedule": schedule,
        }),
    }
    fake_recipe = {**fake_recipe_body, "recipe_sha256": digest_object(fake_recipe_body)}
    _WORKER_PAYLOAD_BY_RECIPE[fake_recipe["recipe_sha256"]] = schedule["network_payload_bytes"] * 2
    workers = WorkerSet(fake_recipe)
    samples: list[dict[str, Any]] = []
    failure: str | None = None
    cleanup: list[dict[str, Any]] = []
    calibration_start_ns = time.monotonic_ns()
    calibration_deadline_ns = calibration_start_ns + schedule["total_deadline_seconds"] * 1_000_000_000
    try:
        _storage_reserve(fake_recipe, run_dir)
        workers.spawn()
        _storage_reserve(fake_recipe, run_dir, scratch_reserved=True)
        start_deadline = calibration_start_ns + schedule["startup_deadline_seconds"] * 1_000_000_000
        workers.await_ready(start_deadline)
        start_ns = time.monotonic_ns() + 250_000_000
        workers.begin(start_ns)
        interval_ns = schedule["sample_interval_ms"] * 1_000_000
        counters_before: dict[str, Any] | None = None
        io_before: dict[str, dict[str, int]] | None = None
        previous_end = start_ns
        for seq in range(schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"]):
            target_start = start_ns + seq * interval_ns
            target_end = target_start + interval_ns
            _sleep_until(target_start, deadline_ns=calibration_deadline_ns, maximum_sleep_ns=10_000_000, label="calibration sample start")
            before = counters_before if counters_before is not None else _counter_snapshot(app_storage["backing_chain"])
            worker_before = io_before if io_before is not None else workers.process_io()
            worker_records_raw = workers.wait_sample(seq, target_end + max(500_000_000, interval_ns // 2))
            worker_records = _normalize_worker_records(worker_records_raw, workers.children, seq, schedule, fake_recipe["recipe_sha256"])
            _sleep_until(target_end, deadline_ns=calibration_deadline_ns, maximum_sleep_ns=5_000_000, label="calibration sample end")
            after = _counter_snapshot(app_storage["backing_chain"])
            worker_after = workers.process_io()
            sample = _build_sample(fake_recipe, seq, previous_end, time.monotonic_ns(), before, after, worker_records, worker_before, worker_after, False)
            samples.append(sample)
            if seq % max(1, 1000 // schedule["sample_interval_ms"]) == 0:
                _storage_reserve(fake_recipe, run_dir, scratch_reserved=True)
            counters_before = after
            io_before = worker_after
            previous_end = sample["interval_end_monotonic_ns"]
        require(all(item["block"]["writes_completed"] > 0 and item["block"]["write_bytes"] > 0 for item in samples), "pressure calibration did not observe writes on the application block device")
        require(any(item["block"]["in_flight"] > 0 or item["block"]["weighted_io_milliseconds"] > 0 or item["io_psi_delta_microseconds"] > 0 for item in samples), "pressure calibration has no independent block queue/stall evidence")
        require(all(
            item["loopback_counters"]["tx_bytes"] > 0 and item["loopback_counters"]["rx_bytes"] > 0
            and all(item["loopback_counters"][key] == 0 for key in ("rx_errors", "rx_dropped", "tx_errors", "tx_dropped"))
            for item in samples
        ), "pressure calibration did not observe clean real IPv4 loopback traffic")
        require(time.monotonic_ns() <= calibration_deadline_ns, "pressure calibration exceeded its frozen total deadline")
    except BaseException as error:
        failure = f"{type(error).__name__}: {error}"
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup = workers.cleanup(schedule["term_deadline_seconds"], schedule["kill_deadline_seconds"])
    cleanup_ok = bool(cleanup) and all(
        _worker_exit_was_bounded(item) and item.get("alive_after_cleanup") is False
        and item.get("term_error") is None and item.get("kill_error") is None and item.get("reap_error") is None and item.get("stderr_output") == ""
        and item.get("stderr_raw_bytes") == 0 and item.get("stderr_raw_truncated") is False and item.get("stderr_read_error") is None
        for item in cleanup if item.get("role") != "scratch_cleanup"
    ) and not any(item.get("role") == "scratch_cleanup" and item.get("error") for item in cleanup)
    if failure is not None or not cleanup_ok or not workers.scratch_removed:
        failure_body = {
            "schema": "allocatbelt.application-pressure-calibration-failure.v1",
            "failure": failure or "calibration process cleanup or scratch removal failed",
            "sample_count": len(samples),
            "device_write_sample_count": sum(
                1 for item in samples if item["block"]["writes_completed"] > 0 and item["block"]["write_bytes"] > 0
            ),
            "sample_observations": _calibration_sample_observations(samples),
            "worker_cleanup": cleanup,
            "scratch_file_removed": workers.scratch_removed,
            "finish_monotonic_ns": time.monotonic_ns(),
        }
        try:
            safe_write_new(run_dir / "failure.json", canonical_bytes(failure_body), "pressure calibration failure evidence", maximum=MAX_FAILURE_BYTES)
        except (OSError, PressureError):
            pass
        raise PressureError(failure_body["failure"])
    summary = _summarize_samples(samples)
    require(len(samples) == schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"], "pressure calibration sample count differs from its frozen schedule")
    suggested = _suggest_thresholds(summary)
    body = {
        "schema": CALIBRATION_SCHEMA,
        "identity": {
            "host_id": normalized["identity"]["host_id"],
            "pair_id": normalized["identity"]["pair_id"],
            "condition_id": normalized["identity"]["condition_id"],
            "phase": "calibration",
        },
        "schedule_sha256": digest_object(_pressure_profile(schedule)),
        "raw_inputs": {
            "source_manifest_sha256": normalized["files"]["source_manifest"]["raw_sha256"],
            "policy_sha256": normalized["files"]["policy"]["raw_sha256"],
            "application_capacity_calibration_sha256": normalized["files"]["application_capacity_calibration"]["raw_sha256"],
        },
        "driver_sha256": _hash_script(DRIVER_PATH, "pressure driver"),
        "host": host,
        "storage": {"application_device": app_storage["device"], "mount_id": app_storage["mount"]["mount_id"], "backing_chain": app_storage["backing_chain"]},
        "network": host["network"],
        "worker_sessions": [
            {"role": child["role"], "cpu": child["cpu"], "pid": child["pid"], "start_ticks": child["start_ticks"], "pgid": child["pgid"], "session_id": child["session_id"]}
            for child in workers.children
        ],
        "samples": samples,
        "summary": summary,
        "suggested_readiness_thresholds": suggested,
        "worker_cleanup": cleanup,
        "scratch_file_removed": workers.scratch_removed,
        "start_monotonic_ns": calibration_start_ns,
        "finish_monotonic_ns": time.monotonic_ns(),
        "deadlines": {
            "startup_seconds": schedule["startup_deadline_seconds"],
            "total_seconds": schedule["total_deadline_seconds"],
            "term_seconds": schedule["term_deadline_seconds"],
            "kill_seconds": schedule["kill_deadline_seconds"],
        },
    }
    calibration = {**body, "calibration_sha256": digest_object(body)}
    raw = canonical_bytes(calibration)
    safe_write_new(output_path, raw, "pressure contention calibration", maximum=MAX_CALIBRATION_BYTES)
    try:
        run_dir.rmdir()
    except OSError:
        # Keep calibration failure artifacts rather than deleting diagnostics.
        pass
    return {"calibration_sha256": calibration["calibration_sha256"], "calibration_raw_sha256": digest_bytes(raw), "sample_count": len(samples), "suggested_readiness_thresholds": suggested, "path": str(output_path)}


def _normalize_worker_records(
    raw: dict[str, Any], children: list[dict[str, Any]], seq: int,
    schedule: dict[str, Any], recipe_sha: str,
) -> dict[str, Any]:
    normalized: dict[str, Any] = {"cpu": [], "disk": None, "loopback": None}
    by_label = {child["role"] if child["cpu"] is None else f"cpu:{child['cpu']}": child for child in children}
    for key, child in by_label.items():
        value = _validate_worker_record(raw[key], child, seq, recipe_sha)
        if child["role"] == "cpu":
            normalized["cpu"].append(value)
        elif child["role"] == "disk":
            normalized["disk"] = value
        else:
            normalized["loopback"] = value
    require(len(normalized["cpu"]) == len(schedule["pressure_cpu_affinity"]) and normalized["disk"] is not None and normalized["loopback"] is not None, "worker telemetry is missing a pressure resource")
    return normalized


def _load_cli_recipe(path: Path, expected_sha: str | None) -> tuple[dict[str, Any], str]:
    value, _, actual = verify_canonical_json(path, "frozen pressure recipe", MAX_RECIPE_BYTES)
    recipe = _validate_recipe(value, expected_sha)
    return recipe, actual


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze", help="freeze a canonical pressure recipe; does not start load")
    freeze.add_argument("--request", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    calibrate_parser = sub.add_parser("calibrate", help="run one finite contention calibration; no application performance thresholds")
    calibrate_parser.add_argument("--request", type=Path, required=True)
    calibrate_parser.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("run", help="run one bounded pressure session for one authenticated application process")
    run.add_argument("--recipe", type=Path, required=True)
    run.add_argument("--expected-recipe-sha256", required=True)
    run.add_argument("--launch-record", type=Path, required=True)
    run.add_argument("--output-dir", type=Path, required=True)
    run.add_argument("--ready-file", type=Path, required=True)
    worker = sub.add_parser("_worker", help=argparse.SUPPRESS)
    worker.add_argument("--kind", choices=("cpu", "disk", "loopback"), required=True)
    worker.add_argument("--recipe-sha256", required=True)
    worker.add_argument("--interval-ms", type=int, required=True)
    worker.add_argument("--duration-seconds", type=int, required=True)
    worker.add_argument("--seed", type=int, required=True)
    worker.add_argument("--cpu", type=int)
    worker.add_argument("--duty-basis-points", type=int, default=0)
    worker.add_argument("--scratch-file")
    worker.add_argument("--scratch-bytes", type=int, default=0)
    worker.add_argument("--scratch-device", type=int, default=0)
    worker.add_argument("--scratch-inode", type=int, default=0)
    worker.add_argument("--disk-rate", type=int, default=0)
    worker.add_argument("--requests-per-second", type=int, default=0)
    worker.add_argument("--payload-bytes", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "_worker":
        def stop_driver(signum: int, _frame: Any) -> None:
            raise PressureError(f"pressure driver received signal {signum}")
        signal.signal(signal.SIGTERM, stop_driver)
        signal.signal(signal.SIGINT, stop_driver)
    try:
        if args.command == "freeze":
            result = freeze_recipe(args.request, args.output)
        elif args.command == "calibrate":
            result = calibrate(args.request, args.output)
        elif args.command == "run":
            expected = sha256(args.expected_recipe_sha256, "expected recipe SHA-256")
            result = run_pressure(args.recipe, expected, args.launch_record, args.output_dir, args.ready_file)
        elif args.command == "_worker":
            return worker_main(args)
        else:
            raise PressureError("unknown command")
    except (PressureError, OSError, subprocess.SubprocessError) as error:
        print(f"application-pressure-driver: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
