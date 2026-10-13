#!/usr/bin/env python3
"""Independently validate one bounded external-application pressure session.

This reader does not accept the driver's claimed pass as evidence. The caller
supplies the frozen recipe digest and expected artifact digests separately;
the reader then rechecks canonical bytes, samples, readiness, overlap and live
process cleanup from the raw event stream.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import signal
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterator


RECIPE_SCHEMA = "allocatbelt.application-pressure-recipe.v1"
LAUNCH_SCHEMA = "allocatbelt.application-pressure-launch-binding.v1"
PROCESS_BINDING_SCHEMA = "allocatbelt.application-pressure-process-binding.v1"
EVENT_SCHEMA = "allocatbelt.application-pressure-event.v1"
RUN_SCHEMA = "allocatbelt.application-pressure-run.v1"
READBACK_SCHEMA = "allocatbelt.application-pressure-readback.v1"
PRESSURE_IO_SCHEMA = "allocatbelt.application-pressure-io-window.v1"
MAX_RECIPE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_LAUNCH_BYTES = 256 * 1024
MAX_EVENTS_BYTES = 512 * 1024 * 1024
MAX_EVENT_LINE_BYTES = 2 * 1024 * 1024
EVENT_TERMINAL_RESERVE_BYTES = 2 * 1024 * 1024
MAX_DURATION_SECONDS = 12000
MAX_SAMPLE_COUNT = 120000
MAX_EVENT_COUNT = 120004
MAX_WORKER_STDERR_RAW_BYTES = 8192
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_POLICY_BYTES = 8 * 1024 * 1024
U64_MAX = (1 << 64) - 1
BLOCK_BYTES = 4096


class ReadbackError(ValueError):
    """A recipe or pressure artifact fails independent validation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReadbackError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ReadbackError(f"value cannot be canonically encoded: {error}") from error
    return (text + "\n").encode("ascii")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_object(value: object) -> str:
    return sha256_bytes(canonical_bytes(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadbackError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReadbackError(f"non-finite JSON constant is forbidden: {value}")


def parse_object(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its finite byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReadbackError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must be one JSON object")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected shape")
    return value


def uint(value: object, label: str, *, positive: bool = False, maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} must be a finite unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def text(value: object, label: str, maximum: int = 4096) -> str:
    require(type(value) is str and 0 < len(value) <= maximum, f"{label} must be a bounded string")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), f"{label} contains a control character")
    return value


def sha256(value: object, label: str) -> str:
    result = text(value, label, 64)
    require(re.fullmatch(r"[0-9a-f]{64}", result) is not None, f"{label} is not lowercase SHA-256")
    return result


def absolute_path(value: object, label: str) -> Path:
    raw = text(value, label)
    path = Path(raw)
    require(path.is_absolute() and str(path) == raw and ".." not in PurePosixPath(raw).parts, f"{label} must be a normalized absolute path")
    return path


def _stat_key(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    try:
        require(path.resolve(strict=True) == path, f"{label} path traverses a symlink or alias")
        path_info = path.lstat()
        require(stat.S_ISREG(path_info.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise ReadbackError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(path_info), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its hard byte cap")
        parts: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(block, f"{label} was truncated during readback")
            parts.append(block)
            count += len(block)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before) == _stat_key(after_fd) == _stat_key(after_path) and count == before.st_size, f"{label} changed during readback")
        raw = b"".join(parts)
        return raw, sha256_bytes(raw)
    finally:
        os.close(descriptor)


def read_canonical(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], bytes, str]:
    raw, digest = read_stable(path, label, maximum)
    value = parse_object(raw, label, maximum)
    require(raw == canonical_bytes(value), f"{label} is not canonical JSON")
    return value, raw, digest


def _validate_recipe(value: object, expected_sha: str) -> dict[str, Any]:
    recipe = exact(value, {
        "schema", "identity", "files", "process", "host", "storage", "network",
        "schedule", "artifact_budget", "pressure_calibration", "readiness_thresholds", "script_hashes",
        "condition_sha256", "recipe_sha256",
    }, "frozen pressure recipe")
    require(recipe["schema"] == RECIPE_SCHEMA, "unsupported pressure recipe schema")
    body = {key: value for key, value in recipe.items() if key != "recipe_sha256"}
    calculated = digest_object(body)
    require(sha256(recipe["recipe_sha256"], "recipe SHA-256") == calculated == expected_sha, "recipe differs from the separately supplied frozen SHA-256")
    identity = exact(recipe["identity"], {"host_id", "run_id", "pair_id", "condition_id", "member", "nonce", "allocator", "executor", "phase"}, "recipe identity")
    require(identity["phase"] == "external_pressure" and re.fullmatch(r"[0-9a-f]{32}", text(identity["nonce"], "recipe nonce", 32)) is not None, "recipe is not bound to one external-pressure process")
    files = exact(recipe["files"], {"source_manifest", "application_binary", "policy", "application_capacity_calibration"}, "recipe raw input files")
    for label, record in files.items():
        record = exact(record, {"path", "raw_sha256"} | ({"mode", "size"} if label == "application_binary" else set()), f"recipe input {label}")
        absolute_path(record["path"], f"recipe {label} path")
        sha256(record["raw_sha256"], f"recipe {label} raw SHA-256")
    require(files["application_capacity_calibration"]["raw_sha256"] != recipe["pressure_calibration"]["raw_sha256"], "app-byte calibration and pressure-contention calibration hashes were conflated")
    process = exact(recipe["process"], {"executable_path", "application_tmpdir_path"}, "expected application process")
    require(process["executable_path"] == files["application_binary"]["path"], "application executable path differs from pinned binary")
    app_tmpdir = str(absolute_path(process["application_tmpdir_path"], "application TMPDIR path"))
    schedule = exact(recipe["schedule"], {
        "seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds",
        "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds",
        "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points",
        "pressure_cpu_affinity", "application_cpu_affinity", "disk_bytes_per_second",
        "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes",
    }, "recipe schedule")
    duration = uint(schedule["duration_seconds"], "pressure duration", positive=True, maximum=MAX_DURATION_SECONDS)
    interval_ms = uint(schedule["sample_interval_ms"], "sample interval", positive=True, maximum=1000)
    require(interval_ms >= 100 and duration * 1000 % interval_ms == 0, "recipe sample schedule is invalid")
    count = duration * 1000 // interval_ms
    require(count <= MAX_SAMPLE_COUNT, "recipe sample schedule exceeds the reader cap")
    uint(schedule["total_deadline_seconds"], "total deadline", positive=True, maximum=14400)
    uint(schedule["startup_deadline_seconds"], "startup deadline", positive=True, maximum=10)
    uint(schedule["term_deadline_seconds"], "TERM deadline", positive=True, maximum=30)
    uint(schedule["kill_deadline_seconds"], "KILL deadline", positive=True, maximum=15)
    uint(schedule["minimum_overlap_seconds"], "minimum overlap", positive=True, maximum=duration)
    uint(schedule["startup_ready_windows"], "startup ready windows", positive=True, maximum=10)
    require(schedule["total_deadline_seconds"] >= schedule["startup_deadline_seconds"] + duration + schedule["term_deadline_seconds"] + schedule["kill_deadline_seconds"], "recipe total deadline omits a bounded phase")
    for key in ("cpu_duty_basis_points", "disk_bytes_per_second", "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes", "seed"):
        uint(schedule[key], f"schedule {key}", positive=True)
    require(schedule["cpu_duty_basis_points"] <= 10000 and schedule["scratch_file_bytes"] <= 1024 * 1024 * 1024, "recipe pressure intensity exceeds its bound")
    require(schedule["scratch_file_bytes"] >= BLOCK_BYTES and schedule["scratch_file_bytes"] % BLOCK_BYTES == 0, "recipe scratch size is not block aligned")
    require(schedule["disk_bytes_per_second"] <= 512 * 1024 * 1024, "recipe disk pressure exceeds its per-second bound")
    disk_target_per_window = schedule["disk_bytes_per_second"] * interval_ms // 1000
    require(disk_target_per_window >= BLOCK_BYTES, "recipe disk rate is too sparse for its sample cadence")
    disk_actual_per_window = ((disk_target_per_window + BLOCK_BYTES - 1) // BLOCK_BYTES) * BLOCK_BYTES
    require(disk_actual_per_window * count <= 64 * 1024**3, "rounded per-window pressure writes exceed the 64 GiB schedule bound")
    require(schedule["network_requests_per_second"] <= 100000 and schedule["network_payload_bytes"] <= 65536 and schedule["network_payload_bytes"] >= 16, "recipe loopback intensity exceeds its per-request bound")
    require(schedule["network_requests_per_second"] * interval_ms >= 1000, "recipe loopback request rate is too sparse for its sample cadence")
    require(schedule["network_requests_per_second"] * schedule["network_payload_bytes"] * 2 <= 64 * 1024**2 and schedule["network_requests_per_second"] * schedule["network_payload_bytes"] * 2 * duration <= 64 * 1024**3, "recipe loopback traffic exceeds its cumulative bound")
    cpu_pressure = _cpu_list(schedule["pressure_cpu_affinity"], "pressure CPU affinity")
    cpu_application = _cpu_list(schedule["application_cpu_affinity"], "application CPU affinity")
    host = exact(recipe["host"], {
        "kernel_release", "boot_id_sha256", "allowed_cpu_affinity", "pressure_cpu_affinity",
        "application_cpu_affinity", "application_storage", "pressure_scratch", "network",
    }, "host binding")
    text(host["kernel_release"], "frozen kernel release", 256)
    sha256(host["boot_id_sha256"], "frozen boot identity hash")
    allowed = host["allowed_cpu_affinity"]
    require(type(allowed) is list and 1 <= len(allowed) <= 4096, "captured host CPU affinity is empty or oversized")
    allowed = [uint(cpu, "captured host CPU", maximum=65535) for cpu in allowed]
    require(allowed == sorted(set(allowed)), "captured host CPU affinity is not canonical")
    require(host["allowed_cpu_affinity"] == allowed, "captured host CPU affinity is malformed")
    require(host["pressure_cpu_affinity"] == cpu_pressure and host["application_cpu_affinity"] == cpu_application, "host CPU affinity differs from the frozen schedule")
    require(set(cpu_pressure) <= set(allowed) and set(cpu_application) <= set(allowed), "frozen CPU sets exceed captured host affinity")
    storage = exact(recipe["storage"], {
        "application_io_paths", "pressure_scratch_path", "output_minimum_free_bytes",
        "application_device", "application_mount_id", "backing_chain", "non_tmpfs",
    }, "storage binding")
    require(storage["non_tmpfs"] is True and storage["application_device"] != "0:0", "application disk pressure is not bound to a real non-tmpfs device")
    app_paths = storage["application_io_paths"]
    require(type(app_paths) is list and 1 <= len(app_paths) <= 16, "frozen application I/O path set is sparse or oversized")
    app_paths = [str(absolute_path(value, "frozen application I/O path")) for value in app_paths]
    require(len(set(app_paths)) == len(app_paths), "frozen application I/O paths repeat")
    require(app_tmpdir in app_paths, "frozen application TMPDIR is absent from application storage paths")
    scratch_path = str(absolute_path(storage["pressure_scratch_path"], "frozen pressure scratch path"))
    require(uint(storage["output_minimum_free_bytes"], "frozen free-space floor", positive=True) > 0, "frozen free-space floor is invalid")
    chain = _device_chain(storage["backing_chain"], storage["application_device"])
    artifact_budget = exact(recipe["artifact_budget"], {
        "sample_count", "maximum_sample_line_bytes", "sample_events_bytes",
        "terminal_reserve_bytes", "maximum_event_bytes",
    }, "recipe event artifact budget")
    require(artifact_budget == _artifact_budget(schedule, chain), "frozen event artifact budget differs from independently recomputed bounds")
    require(type(host["application_storage"]) is list and len(host["application_storage"]) == len(app_paths), "application storage inventory is sparse")
    for index, item in enumerate(host["application_storage"]):
        _validate_storage_record(item, app_paths[index], storage["application_device"], storage["application_mount_id"], chain, f"application storage[{index}]")
    scratch_record = _validate_storage_record(host["pressure_scratch"], scratch_path, storage["application_device"], storage["application_mount_id"], chain, "pressure scratch storage")
    require(scratch_record["filesystem_type"] not in ("tmpfs", "ramfs", "overlay"), "pressure scratch is on an in-memory/overlay filesystem")
    network = exact(recipe["network"], {
        "address_family", "destination", "source", "interface", "ifindex", "route",
        "network_namespace_inode", "shared_kernel", "physical_nic_claimed", "claim",
    }, "network binding")
    require(network["address_family"] == "AF_INET" and network["destination"] == "127.0.0.1" and network["source"] == "127.0.0.1" and network["interface"] == "lo", "network witness is not IPv4 loopback")
    require(network["shared_kernel"] is True and network["physical_nic_claimed"] is False and network["claim"] == "ipv4_loopback_shared_kernel_only", "network recipe claims physical NIC pressure")
    require(network["network_namespace_inode"] == host["network"]["network_namespace_inode"], "host and network namespace identities differ")
    require(network == host["network"], "host and process network route evidence differs")
    route = network["route"]
    exact(route, {"dst", "dev", "source"}, "IPv4 loopback route")
    require(route.get("dst") == "127.0.0.1" and route.get("dev") == "lo" and route.get("source") == "127.0.0.1", "frozen route does not target IPv4 loopback on lo")
    uint(network["ifindex"], "loopback ifindex", positive=True)
    uint(network["network_namespace_inode"], "network namespace inode", positive=True)
    calibration = exact(recipe["pressure_calibration"], {"path", "raw_sha256"}, "pressure-contention calibration binding")
    absolute_path(calibration["path"], "pressure-contention calibration path")
    calibration_sha = sha256(calibration["raw_sha256"], "pressure-contention calibration raw SHA-256")
    thresholds = exact(recipe["readiness_thresholds"], {
        "cpu_busy_min_basis_points", "disk_write_min_bytes_per_second",
        "disk_queue_or_stall_min_microseconds", "loopback_requests_min_per_second",
        "loopback_latency_p99_max_nanoseconds", "loopback_tx_min_bytes_per_second",
        "loopback_rx_min_bytes_per_second",
    }, "numeric readiness thresholds")
    for key, value in thresholds.items():
        uint(value, f"readiness threshold {key}", positive=True)
    require(thresholds["cpu_busy_min_basis_points"] <= 10000, "CPU busy threshold exceeds 100 percent")
    hashes = exact(recipe["script_hashes"], {"driver_sha256", "reader_sha256"}, "script hashes")
    sha256(hashes["driver_sha256"], "driver SHA-256")
    sha256(hashes["reader_sha256"], "reader SHA-256")
    condition_material = {
        "host_id": identity["host_id"],
        "condition_id": identity["condition_id"],
        "source_manifest_sha256": files["source_manifest"]["raw_sha256"],
        "policy_sha256": files["policy"]["raw_sha256"],
        "application_capacity_calibration_sha256": files["application_capacity_calibration"]["raw_sha256"],
        "host": {
            "kernel_release": host["kernel_release"],
            "boot_id_sha256": host["boot_id_sha256"],
            "allowed_cpu_affinity": host["allowed_cpu_affinity"],
            "pressure_cpu_affinity": host["pressure_cpu_affinity"],
            "application_cpu_affinity": host["application_cpu_affinity"],
        },
        "storage": {
            "device": storage["application_device"],
            "mount_id": storage["application_mount_id"],
            "backing_chain": chain,
        },
        "network": host["network"],
        "schedule": schedule,
        "pressure_calibration_sha256": calibration_sha,
        "readiness_thresholds": thresholds,
    }
    condition = sha256(recipe["condition_sha256"], "condition SHA-256")
    require(condition == digest_object(condition_material), "condition digest does not bind the immutable schedule and host/storage/network controls")
    return {"identity": identity, "schedule": schedule, "storage": storage, "network": network, "thresholds": thresholds, "artifact_budget": artifact_budget, "files": files, "calibration_sha256": calibration_sha, "condition_sha256": condition, "script_hashes": hashes}


def _cpu_list(value: object, label: str) -> list[int]:
    require(type(value) is list and 1 <= len(value) <= 64, f"{label} is empty or exceeds its bound")
    result = [uint(item, label, maximum=65535) for item in value]
    require(result == sorted(set(result)), f"{label} is not sorted and unique")
    return result


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
        "sequence": MAX_SAMPLE_COUNT - 1,
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
            "sequence": MAX_SAMPLE_COUNT - 1,
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
    require(maximum_sample_line_bytes <= MAX_EVENT_LINE_BYTES, "sample row exceeds the reader's event-line bound")
    sample_count = schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"]
    sample_events_bytes = sample_count * maximum_sample_line_bytes
    maximum_event_bytes = sample_events_bytes + EVENT_TERMINAL_RESERVE_BYTES
    require(maximum_event_bytes <= MAX_EVENTS_BYTES, "frozen pressure schedule exceeds the 512 MiB event and terminal-evidence budget")
    return {
        "sample_count": sample_count,
        "maximum_sample_line_bytes": maximum_sample_line_bytes,
        "sample_events_bytes": sample_events_bytes,
        "terminal_reserve_bytes": EVENT_TERMINAL_RESERVE_BYTES,
        "maximum_event_bytes": maximum_event_bytes,
    }


def _validate_storage_record(
    value: object, expected_path: str, expected_device: str,
    expected_mount_id: int, expected_chain: list[dict[str, Any]], label: str,
) -> dict[str, Any]:
    record = exact(value, {"path", "device", "mount", "backing_chain", "filesystem_type", "tmpfs"}, label)
    path = str(absolute_path(record["path"], f"{label} path"))
    require(path == expected_path, f"{label} path differs from the frozen I/O path")
    require(record["device"] == expected_device and record["backing_chain"] == expected_chain, f"{label} device/backing chain differs")
    require(record["tmpfs"] is False and record["filesystem_type"] not in ("tmpfs", "ramfs", "overlay"), f"{label} is on an in-memory/overlay filesystem")
    mount = exact(record["mount"], {
        "mount_id", "parent_mount_id", "device", "root", "mountpoint", "mount_options",
        "filesystem", "source", "super_options",
    }, f"{label} mount record")
    require(uint(mount["mount_id"], f"{label} mount id", positive=True) == expected_mount_id, f"{label} mount id differs from frozen storage")
    uint(mount["parent_mount_id"], f"{label} parent mount id", positive=True)
    require(mount["device"] == expected_device and mount["filesystem"] == record["filesystem_type"], f"{label} mount device/filesystem differs")
    mountpoint = str(absolute_path(mount["mountpoint"], f"{label} mountpoint"))
    require(path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/"), f"{label} path is outside its frozen mountpoint")
    text(mount["root"], f"{label} mount root", 4096)
    text(mount["source"], f"{label} mount source", 4096)
    for key in ("mount_options", "super_options"):
        options = mount[key]
        require(type(options) is list and options and all(type(item) is str and item for item in options), f"{label} {key} are malformed")
    return record


def _device_chain(value: object, device: str) -> list[dict[str, Any]]:
    require(type(value) is list and 1 <= len(value) <= 32, "block backing chain is sparse or oversized")
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        require(type(item) is dict, f"block chain[{index}] must be an object")
        record = exact(item, {"device", "name", "sysfs_path", "partition"} if "partition" in item else {"device", "name", "sysfs_path"}, f"block chain[{index}]")
        current = text(record["device"], "block device identity", 32)
        require(re.fullmatch(r"[0-9]+:[0-9]+", current) is not None and current not in seen, "block backing chain repeats or malforms a device")
        seen.add(current)
        text(record["name"], "block kernel name", 256)
        path = text(record["sysfs_path"], "block sysfs path", 4096)
        require(path.startswith("/sys/devices/"), "block sysfs path is outside /sys/devices")
        if "partition" in record:
            uint(record["partition"], "block partition number", positive=True)
        result.append(record)
    require(device in seen, "application block device is absent from its backing chain")
    require(result == sorted(result, key=lambda item: item["device"]), "block backing chain is not canonical")
    return result


def _validate_calibration(recipe: dict[str, Any]) -> None:
    binding = recipe["pressure_calibration"]
    path = Path(binding["path"])
    value, _, raw_sha = read_canonical(path, "pressure contention calibration", 64 * 1024 * 1024)
    require(raw_sha == binding["raw_sha256"], "pressure contention calibration raw digest differs from frozen recipe")
    exact(value, {
        "schema", "identity", "schedule_sha256", "raw_inputs", "driver_sha256", "host", "storage",
        "network", "worker_sessions", "samples", "summary", "suggested_readiness_thresholds",
        "worker_cleanup", "scratch_file_removed", "start_monotonic_ns", "finish_monotonic_ns", "deadlines",
        "calibration_sha256",
    }, "pressure contention calibration")
    require(value["schema"] == "allocatbelt.application-pressure-contention-calibration.v1", "unsupported pressure calibration schema")
    calibration_body = {key: item for key, item in value.items() if key != "calibration_sha256"}
    require(sha256(value["calibration_sha256"], "calibration digest") == digest_object(calibration_body), "pressure calibration internal digest is invalid")
    require(value["identity"]["host_id"] == recipe["identity"]["host_id"] and value["identity"]["condition_id"] == recipe["identity"]["condition_id"], "pressure calibration host/condition differs from recipe")
    identity = exact(value["identity"], {"host_id", "pair_id", "condition_id", "phase"}, "pressure calibration identity")
    require(identity["phase"] == "calibration" and identity["pair_id"] == recipe["identity"]["pair_id"], "pressure calibration pair identity differs from recipe")
    require(sha256(value["driver_sha256"], "calibration driver hash") == recipe["script_hashes"]["driver_sha256"], "pressure calibration came from different driver bytes")
    profile_keys = (
        "seed", "sample_interval_ms", "startup_deadline_seconds", "term_deadline_seconds",
        "kill_deadline_seconds", "cpu_duty_basis_points", "pressure_cpu_affinity",
        "application_cpu_affinity", "disk_bytes_per_second", "scratch_file_bytes",
        "network_requests_per_second", "network_payload_bytes",
    )
    profile = {key: recipe["schedule"][key] for key in profile_keys}
    require(value["schedule_sha256"] == digest_object(profile), "pressure calibration intensity differs from frozen recipe")
    files = recipe["files"]
    require(value["raw_inputs"] == {
        "source_manifest_sha256": files["source_manifest"]["raw_sha256"],
        "policy_sha256": files["policy"]["raw_sha256"],
        "application_capacity_calibration_sha256": files["application_capacity_calibration"]["raw_sha256"],
    }, "pressure calibration raw inputs differ or app-byte calibration was conflated")
    host = value["host"]
    expected_host = recipe["host"]
    require(
        host["kernel_release"] == expected_host["kernel_release"]
        and host["boot_id_sha256"] == expected_host["boot_id_sha256"]
        and host["allowed_cpu_affinity"] == expected_host["allowed_cpu_affinity"]
        and host["pressure_cpu_affinity"] == expected_host["pressure_cpu_affinity"]
        and host["application_cpu_affinity"] == expected_host["application_cpu_affinity"],
        "pressure calibration was measured on a different host/kernel/CPU set",
    )
    require(value["network"] == expected_host["network"], "pressure calibration loopback route/namespace differs from frozen recipe")
    require(value["storage"] == {
        "application_device": recipe["storage"]["application_device"],
        "mount_id": recipe["storage"]["application_mount_id"],
        "backing_chain": recipe["storage"]["backing_chain"],
    }, "pressure calibration application block device differs from frozen recipe")
    _validate_calibration_samples(value["samples"], recipe, value)
    sessions = value["worker_sessions"]
    cleanup = value["worker_cleanup"]
    require(type(sessions) is list and len(sessions) == len(recipe["schedule"]["pressure_cpu_affinity"]) + 2 and type(cleanup) is list and len(cleanup) == len(sessions), "pressure calibration worker cleanup is sparse")
    session_by_key: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in sessions:
        worker = exact(item, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id"}, "calibration worker session")
        role = text(worker["role"], "calibration worker role", 16)
        cpu = uint(worker["cpu"], "calibration worker CPU", maximum=65535) if role == "cpu" else None
        require(role in ("cpu", "disk", "loopback") and (role != "cpu" or cpu in recipe["schedule"]["pressure_cpu_affinity"]), "calibration worker session role/CPU differs")
        pid = uint(worker["pid"], "calibration worker PID", positive=True, maximum=(1 << 31) - 1)
        ticks = uint(worker["start_ticks"], "calibration worker start ticks", positive=True)
        require(worker["pgid"] == pid and worker["session_id"] == pid, "calibration worker was not isolated in its own session")
        key = (role, cpu)
        require(key not in session_by_key, "calibration repeats a worker session")
        session_by_key[key] = {**worker, "pid": pid, "start_ticks": ticks}
    expected_sessions = {("cpu", cpu) for cpu in recipe["schedule"]["pressure_cpu_affinity"]} | {("disk", None), ("loopback", None)}
    require(set(session_by_key) == expected_sessions, "calibration worker set differs from frozen pressure resources")
    cleanup_by_key: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in cleanup:
        record = exact(item, {
            "role", "cpu", "pid", "start_ticks", "pgid", "session_id", "exit_code",
            "cleanup_started_monotonic_ns", "term_deadline_monotonic_ns", "kill_deadline_monotonic_ns",
            "term_error", "kill_error", "reap_error", "alive_after_cleanup",
            "term_sent_monotonic_ns", "kill_sent_monotonic_ns", "reaped_monotonic_ns", "stderr_output",
            "stderr_raw_base64", "stderr_raw_sha256", "stderr_raw_bytes", "stderr_raw_truncated", "stderr_read_error",
        }, "calibration worker cleanup")
        key = (record["role"], record["cpu"])
        require(key in session_by_key and key not in cleanup_by_key, "calibration cleanup invents or duplicates a worker")
        session = session_by_key[key]
        require(all(record[field] == session[field] for field in ("pid", "start_ticks", "pgid", "session_id")), "calibration cleanup PID/start identity differs")
        raw_stderr = _validate_worker_stderr_capture(record, "calibration worker")
        require(_worker_exit_status_valid(record) and record["alive_after_cleanup"] is False and all(record[field] is None for field in ("term_error", "kill_error", "reap_error")) and raw_stderr == b"", "calibration worker cleanup failed")
        cleanup_started = uint(record["cleanup_started_monotonic_ns"], "calibration cleanup start", positive=True)
        term_deadline = uint(record["term_deadline_monotonic_ns"], "calibration TERM deadline", positive=True)
        kill_deadline = uint(record["kill_deadline_monotonic_ns"], "calibration KILL deadline", positive=True)
        reaped = uint(record["reaped_monotonic_ns"], "calibration reap time", positive=True)
        require(term_deadline == cleanup_started + recipe["schedule"]["term_deadline_seconds"] * 1_000_000_000, "calibration TERM deadline differs from recipe")
        if record["term_sent_monotonic_ns"] is not None:
            require(uint(record["term_sent_monotonic_ns"], "calibration TERM send time", positive=True) <= term_deadline, "calibration TERM deadline was exceeded")
        if record["kill_sent_monotonic_ns"] is not None:
            killed = uint(record["kill_sent_monotonic_ns"], "calibration KILL send time", positive=True)
            require(killed >= term_deadline and killed <= kill_deadline, "calibration KILL escalation deadline is invalid")
        require(reaped <= kill_deadline, "calibration worker reap exceeded its cleanup deadline")
        _require_pid_reaped(record["pid"], record["start_ticks"], "calibration worker")
        cleanup_by_key[key] = record
    require(set(cleanup_by_key) == expected_sessions and value["scratch_file_removed"] is True, "pressure calibration omitted worker cleanup or scratch removal")
    calibration_start = uint(value["start_monotonic_ns"], "calibration start", positive=True)
    calibration_end = uint(value["finish_monotonic_ns"], "calibration finish", positive=True)
    deadlines = exact(value["deadlines"], {"startup_seconds", "total_seconds", "term_seconds", "kill_seconds"}, "pressure calibration deadlines")
    require(deadlines["startup_seconds"] == recipe["schedule"]["startup_deadline_seconds"] and deadlines["term_seconds"] == recipe["schedule"]["term_deadline_seconds"] and deadlines["kill_seconds"] == recipe["schedule"]["kill_deadline_seconds"], "pressure calibration startup/cleanup deadlines differ from frozen profile")
    calibration_duration = len(value["samples"]) * recipe["schedule"]["sample_interval_ms"] * 1_000_000
    require(3_000_000_000 <= calibration_duration <= 120_000_000_000, "pressure calibration is outside the finite 3..120 second window")
    require(uint(deadlines["total_seconds"], "calibration total deadline", positive=True, maximum=200) * 1_000_000_000 >= calibration_duration + (deadlines["startup_seconds"] + deadlines["term_seconds"] + deadlines["kill_seconds"]) * 1_000_000_000, "pressure calibration total deadline omits a bounded phase")
    require(calibration_end >= calibration_start and calibration_end - calibration_start <= deadlines["total_seconds"] * 1_000_000_000, "pressure calibration exceeded its finite total deadline")
    # Recompute the threshold proposal from every raw measurement. The
    # selected recipe thresholds are numeric readiness limits only.
    summary = _measurement_summary(value["samples"])
    require(summary == value["summary"], "pressure calibration summary differs from raw measured windows")
    proposed = _propose(summary)
    require(proposed == value["suggested_readiness_thresholds"], "pressure calibration threshold proposal differs from its measured windows")
    chosen = recipe["readiness_thresholds"]
    for lower_key in (
        "cpu_busy_min_basis_points", "disk_write_min_bytes_per_second",
        "disk_queue_or_stall_min_microseconds", "loopback_requests_min_per_second",
        "loopback_tx_min_bytes_per_second", "loopback_rx_min_bytes_per_second",
    ):
        require(chosen[lower_key] <= proposed[lower_key], f"selected readiness threshold {lower_key} exceeds measured calibration")
    require(chosen["loopback_latency_p99_max_nanoseconds"] >= proposed["loopback_latency_p99_max_nanoseconds"], "selected loopback readiness threshold is stricter than calibration")


def _median(values: list[int]) -> int:
    require(values, "cannot summarize an empty measured series")
    values = sorted(values)
    middle = len(values) // 2
    return values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) // 2


def _derive_readiness(sample: dict[str, Any], thresholds: dict[str, int]) -> dict[str, Any]:
    start = uint(sample["interval_start_monotonic_ns"], "sample start", positive=True)
    end = uint(sample["interval_end_monotonic_ns"], "sample end", positive=True)
    interval = end - start
    require(interval > 0, "pressure sample interval is empty")
    cpu = sample["cpu"]
    busy = cpu["busy_basis_points"]
    cpu_ready = busy >= thresholds["cpu_busy_min_basis_points"]
    block = sample["block"]
    disk_bps = block["write_bytes"] * 1_000_000_000 // interval
    disk_stall_us = block["weighted_io_milliseconds"] * 1000 + sample["io_psi_delta_microseconds"]
    disk_evidence = block["in_flight"] > 0 or disk_stall_us >= thresholds["disk_queue_or_stall_min_microseconds"]
    disk_ready = disk_bps >= thresholds["disk_write_min_bytes_per_second"] and block["writes_completed"] > 0 and disk_evidence
    loop = sample["loopback"]
    reqs = loop["requests_completed"]
    rps = reqs * 1_000_000_000 // interval
    tx = sample["loopback_counters"]["tx_bytes"] * 1_000_000_000 // interval
    rx = sample["loopback_counters"]["rx_bytes"] * 1_000_000_000 // interval
    net_ready = (
        rps >= thresholds["loopback_requests_min_per_second"]
        and loop["p99_upper_latency_nanoseconds"] <= thresholds["loopback_latency_p99_max_nanoseconds"]
        and tx >= thresholds["loopback_tx_min_bytes_per_second"]
        and rx >= thresholds["loopback_rx_min_bytes_per_second"]
        and sample["loopback_counters"]["rx_errors"] == 0
        and sample["loopback_counters"]["tx_errors"] == 0
        and sample["loopback_counters"]["rx_dropped"] == 0
        and sample["loopback_counters"]["tx_dropped"] == 0
    )
    return {
        "cpu_ready": cpu_ready, "disk_ready": disk_ready, "loopback_ready": net_ready,
        "all_ready": cpu_ready and disk_ready and net_ready,
        "cpu_busy_basis_points": busy,
        "disk_write_bytes_per_second": disk_bps,
        "disk_queue_or_stall_microseconds": disk_stall_us,
        "loopback_requests_per_second": rps,
        "loopback_latency_p99_upper_nanoseconds": loop["p99_upper_latency_nanoseconds"],
        "loopback_tx_bytes_per_second": tx,
        "loopback_rx_bytes_per_second": rx,
    }


def _validate_sample(sample: dict[str, Any], recipe: dict[str, Any], sequence: int) -> dict[str, Any]:
    exact(sample, {
        "schema", "kind", "sequence", "interval_start_monotonic_ns", "interval_end_monotonic_ns",
        "app_active", "cpu", "cpu_psi_delta_microseconds", "block", "io_psi_delta_microseconds",
        "block_device_chain", "loopback_counters", "loopback", "pressure_generators",
        "worker_process_io", "readiness",
    }, f"sample[{sequence}]")
    require(sample["schema"] == EVENT_SCHEMA and sample["kind"] == "sample" and sample["sequence"] == sequence, "sample schema/kind/sequence differs")
    start = uint(sample["interval_start_monotonic_ns"], "sample start", positive=True)
    end = uint(sample["interval_end_monotonic_ns"], "sample end", positive=True)
    require(end > start, "sample interval is empty")
    require(type(sample["app_active"]) is bool, "sample application activity is not boolean")
    cpu = exact(sample["cpu"], {"per_cpu", "total_ticks", "idle_ticks", "busy_basis_points"}, "CPU sample")
    per_cpu = cpu["per_cpu"]
    require(type(per_cpu) is list and len(per_cpu) == len(recipe["schedule"]["pressure_cpu_affinity"]), "CPU counter sample is sparse")
    cpu_total = 0
    cpu_idle = 0
    for index, item in enumerate(per_cpu):
        row = exact(item, {"cpu", "total_ticks", "idle_ticks", "busy_ticks", "busy_basis_points"}, f"CPU counter[{index}]")
        require(row["cpu"] == recipe["schedule"]["pressure_cpu_affinity"][index], "CPU counter affinity/order differs from recipe")
        total = uint(row["total_ticks"], "CPU total ticks", positive=True)
        idle = uint(row["idle_ticks"], "CPU idle ticks")
        busy_ticks = uint(row["busy_ticks"], "CPU busy ticks")
        require(idle <= total and busy_ticks == total - idle and row["busy_basis_points"] == busy_ticks * 10000 // total, "CPU counter arithmetic is inconsistent")
        cpu_total += total
        cpu_idle += idle
    require(cpu["total_ticks"] == cpu_total and cpu["idle_ticks"] == cpu_idle and cpu["busy_basis_points"] == (cpu_total - cpu_idle) * 10000 // cpu_total, "aggregate CPU counters are inconsistent")
    uint(sample["cpu_psi_delta_microseconds"], "CPU PSI delta")
    uint(sample["io_psi_delta_microseconds"], "I/O PSI delta")
    block = exact(sample["block"], {
        "writes_completed", "sectors_written", "write_milliseconds", "io_milliseconds",
        "weighted_io_milliseconds", "in_flight", "write_bytes",
    }, "block device counters")
    for key in block:
        uint(block[key], f"block counter {key}")
    require(block["write_bytes"] == block["sectors_written"] * 512, "block bytes differ from the kernel sectors counter")
    require(block["writes_completed"] > 0 and block["write_bytes"] > 0, "application block device made no write progress")
    require(sample["block_device_chain"] == recipe["storage"]["backing_chain"], "sample block backing chain differs from frozen recipe")
    loop_counters = exact(sample["loopback_counters"], {"rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"}, "loopback interface counters")
    for key in loop_counters:
        uint(loop_counters[key], f"loopback counter {key}")
    require(loop_counters["rx_bytes"] > 0 and loop_counters["tx_bytes"] > 0, "lo counters show no IPv4 loopback traffic")
    loop = exact(sample["loopback"], {
        "schema", "role", "recipe_sha256", "sequence", "start_monotonic_ns", "end_monotonic_ns",
        "requests_completed", "bytes_on_wire", "latency_histogram", "p99_upper_latency_nanoseconds",
    }, "loopback pressure witness")
    require(loop["schema"] == PRESSURE_IO_SCHEMA and loop["role"] == "loopback" and loop["sequence"] == sequence, "loopback worker witness identity differs")
    require(loop["recipe_sha256"] == recipe["recipe_sha256"], "loopback generator witness belongs to another recipe")
    uint(loop["start_monotonic_ns"], "loopback worker start", positive=True)
    uint(loop["end_monotonic_ns"], "loopback worker end", positive=True)
    requests = uint(loop["requests_completed"], "loopback completed requests", positive=True)
    maximum_requests = (recipe["schedule"]["network_requests_per_second"] * recipe["schedule"]["sample_interval_ms"] + 999) // 1000 + 2
    require(requests <= maximum_requests, "loopback request count exceeds the frozen per-window intensity bound")
    payload_bytes = recipe["schedule"]["network_payload_bytes"] * 2
    require(loop["bytes_on_wire"] == requests * payload_bytes, "loopback bytes do not match the frozen payload/count")
    histogram = loop["latency_histogram"]
    require(type(histogram) is list and len(histogram) == 64 and sum(uint(item, "latency bucket") for item in histogram) == requests, "loopback latency histogram differs from successful requests")
    wanted = (requests * 99 + 99) // 100
    cumulative = 0
    p99 = None
    for index, count in enumerate(histogram):
        cumulative += count
        if cumulative >= wanted:
            p99 = 1 << index
            break
    require(p99 is not None and loop["p99_upper_latency_nanoseconds"] == p99, "loopback p99 latency is not supported by the histogram")
    generators = exact(sample["pressure_generators"], {"cpu", "disk"}, "pressure generator evidence")
    cpu_generators = generators["cpu"]
    require(type(cpu_generators) is list and len(cpu_generators) == len(recipe["schedule"]["pressure_cpu_affinity"]), "CPU generator witnesses are sparse")
    for index, item in enumerate(cpu_generators):
        cpu_event = exact(item, {"cpu", "thread_cpu_time_ns", "spin_witness", "start_monotonic_ns", "end_monotonic_ns"}, f"CPU generator[{index}]")
        require(cpu_event["cpu"] == recipe["schedule"]["pressure_cpu_affinity"][index], "CPU generator affinity differs from frozen set")
        uint(cpu_event["thread_cpu_time_ns"], "CPU generator time", positive=True)
        uint(cpu_event["spin_witness"], "CPU generator spin witness")
        worker_start = uint(cpu_event["start_monotonic_ns"], "CPU generator sample start", positive=True)
        worker_end = uint(cpu_event["end_monotonic_ns"], "CPU generator sample end", positive=True)
        require(worker_end > worker_start and worker_start <= end and worker_end >= start, "CPU generator interval does not overlap its independent CPU sample")
    disk_generator = exact(generators["disk"], {
        "write_bytes", "write_mode", "fdatasync_count", "fdatasync_time_nanoseconds", "start_monotonic_ns", "end_monotonic_ns",
    }, "disk generator evidence")
    disk_generated = uint(disk_generator["write_bytes"], "disk generator bytes", positive=True)
    require(disk_generated % BLOCK_BYTES == 0 and disk_generator["write_mode"] == "o_direct" and disk_generator["fdatasync_count"] == 1, "disk generator did not issue one directly synchronized bounded window")
    uint(disk_generator["fdatasync_time_nanoseconds"], "disk generator sync time")
    disk_start = uint(disk_generator["start_monotonic_ns"], "disk generator sample start", positive=True)
    disk_end = uint(disk_generator["end_monotonic_ns"], "disk generator sample end", positive=True)
    require(disk_end > disk_start and disk_start <= end and disk_end >= start, "disk generator interval does not overlap its independent block sample")
    expected_worker_labels = {*(f"cpu:{cpu_id}" for cpu_id in recipe["schedule"]["pressure_cpu_affinity"]), "disk", "loopback"}
    worker_io = exact(sample["worker_process_io"], expected_worker_labels, "independent worker /proc I/O counters")
    disk_io = exact(worker_io["disk"], {"write_bytes_delta", "syscw_delta"}, "disk worker I/O counter")
    require(uint(disk_io["write_bytes_delta"], "disk worker write bytes", positive=True) > 0 and uint(disk_io["syscw_delta"], "disk worker write syscalls", positive=True) > 0, "disk worker /proc counters show no write progress")
    for label, item in worker_io.items():
        exact(item, {"write_bytes_delta", "syscw_delta"}, f"{label} worker I/O counters")
        uint(item["write_bytes_delta"], f"{label} write bytes")
        uint(item["syscw_delta"], f"{label} write syscalls")
    recomputed = _derive_readiness(sample, recipe["readiness_thresholds"])
    require(recomputed == sample["readiness"], "driver readiness claim differs from independent numeric recomputation")
    return {"start": start, "end": end, "app_active": sample["app_active"], "readiness": recomputed}


def _validate_calibration_samples(samples: object, recipe: dict[str, Any], calibration: dict[str, Any]) -> None:
    require(type(samples) is list and len(samples) >= 3, "pressure calibration measurements are sparse")
    cpus = recipe["schedule"]["pressure_cpu_affinity"]
    expected_worker_io = {*(f"cpu:{cpu_id}" for cpu_id in cpus), "disk", "loopback"}
    sample_ns = recipe["schedule"]["sample_interval_ms"] * 1_000_000
    prior_end: int | None = None
    prior_cpu_time: dict[int, int] = {}
    saw_block_pressure = False
    for sequence, sample in enumerate(samples):
        exact(sample, {
            "schema", "sequence", "interval_start_monotonic_ns", "interval_end_monotonic_ns",
            "app_active", "cpu", "cpu_psi_delta_microseconds", "block", "io_psi_delta_microseconds",
            "block_device_chain", "loopback_counters", "loopback", "pressure_generators", "worker_process_io",
        }, f"calibration sample[{sequence}]")
        require(sample["schema"] == EVENT_SCHEMA and sample["sequence"] == sequence and sample["app_active"] is False, "calibration sample identity/phase differs")
        start = uint(sample["interval_start_monotonic_ns"], "calibration sample start", positive=True)
        end = uint(sample["interval_end_monotonic_ns"], "calibration sample end", positive=True)
        cadence_tolerance_ns = max(1_000_000, sample_ns // 100)
        require(sample_ns - cadence_tolerance_ns <= end - start <= sample_ns + max(500_000_000, sample_ns), "calibration sample cadence is sparse")
        require(prior_end is None or start == prior_end, "calibration samples have a gap or overlap")
        prior_end = end
        io_psi = uint(sample["io_psi_delta_microseconds"], "calibration I/O PSI delta")
        uint(sample["cpu_psi_delta_microseconds"], "calibration CPU PSI delta")
        cpu = exact(sample["cpu"], {"per_cpu", "total_ticks", "idle_ticks", "busy_basis_points"}, "calibration CPU counters")
        require(type(cpu["per_cpu"]) is list and len(cpu["per_cpu"]) == len(cpus), "calibration CPU counters are sparse")
        total_ticks = 0
        idle_ticks = 0
        for index, row in enumerate(cpu["per_cpu"]):
            counter = exact(row, {"cpu", "total_ticks", "idle_ticks", "busy_ticks", "busy_basis_points"}, f"calibration CPU counter[{index}]")
            require(counter["cpu"] == cpus[index], "calibration CPU counter affinity differs")
            total = uint(counter["total_ticks"], "calibration CPU ticks", positive=True)
            idle = uint(counter["idle_ticks"], "calibration CPU idle ticks")
            busy = uint(counter["busy_ticks"], "calibration CPU busy ticks")
            require(idle <= total and busy == total - idle and counter["busy_basis_points"] == busy * 10000 // total, "calibration CPU counter arithmetic differs")
            total_ticks += total
            idle_ticks += idle
        require(cpu["total_ticks"] == total_ticks and cpu["idle_ticks"] == idle_ticks and cpu["busy_basis_points"] == (total_ticks - idle_ticks) * 10000 // total_ticks, "calibration CPU aggregate differs")
        block = exact(sample["block"], {"writes_completed", "sectors_written", "write_milliseconds", "io_milliseconds", "weighted_io_milliseconds", "in_flight", "write_bytes"}, "calibration block counters")
        for key, value in block.items():
            uint(value, f"calibration block {key}")
        require(block["write_bytes"] == block["sectors_written"] * 512 and block["write_bytes"] > 0 and block["writes_completed"] > 0, "calibration block counters show no writes")
        saw_block_pressure = saw_block_pressure or block["in_flight"] > 0 or block["weighted_io_milliseconds"] > 0 or io_psi > 0
        require(sample["block_device_chain"] == calibration["storage"]["backing_chain"], "calibration sample block chain differs")
        counters = exact(sample["loopback_counters"], {"rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"}, "calibration lo counters")
        for key, value in counters.items():
            uint(value, f"calibration lo {key}")
        require(counters["rx_bytes"] > 0 and counters["tx_bytes"] > 0 and all(counters[key] == 0 for key in ("rx_errors", "rx_dropped", "tx_errors", "tx_dropped")), "calibration loopback counters show no clean traffic")
        loop = exact(sample["loopback"], {"schema", "role", "recipe_sha256", "sequence", "start_monotonic_ns", "end_monotonic_ns", "requests_completed", "bytes_on_wire", "latency_histogram", "p99_upper_latency_nanoseconds"}, "calibration loopback witness")
        require(loop["schema"] == PRESSURE_IO_SCHEMA and loop["role"] == "loopback" and loop["sequence"] == sequence, "calibration loopback witness identity differs")
        sha256(loop["recipe_sha256"], "calibration worker recipe SHA")
        requests = uint(loop["requests_completed"], "calibration loopback requests", positive=True)
        require(loop["bytes_on_wire"] == requests * recipe["schedule"]["network_payload_bytes"] * 2, "calibration loopback byte count differs")
        histogram = loop["latency_histogram"]
        require(type(histogram) is list and len(histogram) == 64 and sum(uint(item, "calibration latency bucket") for item in histogram) == requests, "calibration latency histogram is incomplete")
        wanted = (requests * 99 + 99) // 100
        cumulative = 0
        p99 = None
        for index, count in enumerate(histogram):
            cumulative += count
            if cumulative >= wanted:
                p99 = 1 << index
                break
        require(p99 == loop["p99_upper_latency_nanoseconds"], "calibration p99 differs from its histogram")
        generators = exact(sample["pressure_generators"], {"cpu", "disk"}, "calibration generators")
        require(type(generators["cpu"]) is list and len(generators["cpu"]) == len(cpus), "calibration CPU worker evidence is sparse")
        for index, item in enumerate(generators["cpu"]):
            worker = exact(item, {"cpu", "thread_cpu_time_ns", "spin_witness", "start_monotonic_ns", "end_monotonic_ns"}, f"calibration CPU generator[{index}]")
            require(worker["cpu"] == cpus[index], "calibration CPU worker used an unexpected CPU")
            cpu_time = uint(worker["thread_cpu_time_ns"], "calibration worker CPU time", positive=True)
            require(cpu_time > prior_cpu_time.get(cpus[index], 0), "calibration CPU worker made no progress")
            prior_cpu_time[cpus[index]] = cpu_time
            uint(worker["spin_witness"], "calibration CPU spin witness")
        disk_worker = exact(generators["disk"], {"write_bytes", "write_mode", "fdatasync_count", "fdatasync_time_nanoseconds", "start_monotonic_ns", "end_monotonic_ns"}, "calibration disk generator")
        require(uint(disk_worker["write_bytes"], "calibration disk generator bytes", positive=True) % BLOCK_BYTES == 0 and disk_worker["write_mode"] == "o_direct" and disk_worker["fdatasync_count"] == 1, "calibration disk generator is incomplete")
        uint(disk_worker["fdatasync_time_nanoseconds"], "calibration disk sync time")
        worker_io = exact(sample["worker_process_io"], expected_worker_io, "calibration worker /proc I/O")
        for label, item in worker_io.items():
            counters = exact(item, {"write_bytes_delta", "syscw_delta"}, f"calibration {label} I/O")
            uint(counters["write_bytes_delta"], f"calibration {label} bytes")
            uint(counters["syscw_delta"], f"calibration {label} syscalls")
        require(worker_io["disk"]["write_bytes_delta"] > 0 and worker_io["disk"]["syscw_delta"] > 0, "calibration disk process counters show no writes")
    require(saw_block_pressure, "calibration contains no independent block queue/stall witness")


def _measurement_summary(samples: object) -> dict[str, int]:
    require(type(samples) is list and len(samples) >= 3, "calibration windows are sparse")
    cpu: list[int] = []
    disk: list[int] = []
    stall: list[int] = []
    requests: list[int] = []
    latency: list[int] = []
    tx: list[int] = []
    rx: list[int] = []
    for item in samples:
        block = item["block"]
        interval = item["interval_end_monotonic_ns"] - item["interval_start_monotonic_ns"]
        require(interval > 0, "pressure calibration interval is empty")
        cpu.append(item["cpu"]["busy_basis_points"])
        disk.append(block["write_bytes"] * 1_000_000_000 // interval)
        stall.append(block["weighted_io_milliseconds"] * 1000 + item["io_psi_delta_microseconds"])
        requests.append(item["loopback"]["requests_completed"] * 1_000_000_000 // interval)
        latency.append(item["loopback"]["p99_upper_latency_nanoseconds"])
        tx.append(item["loopback_counters"]["tx_bytes"] * 1_000_000_000 // interval)
        rx.append(item["loopback_counters"]["rx_bytes"] * 1_000_000_000 // interval)
    return {
        "sample_count": len(samples),
        "cpu_busy_basis_points_median": _median(cpu),
        "disk_write_bytes_per_second_median": _median(disk),
        "disk_queue_or_stall_microseconds_median": _median(stall),
        "loopback_requests_per_second_median": _median(requests),
        "loopback_latency_p99_upper_nanoseconds_median": _median(latency),
        "loopback_tx_bytes_per_second_median": _median(tx),
        "loopback_rx_bytes_per_second_median": _median(rx),
    }


def _propose(summary: dict[str, int]) -> dict[str, int]:
    result = {
        "cpu_busy_min_basis_points": summary["cpu_busy_basis_points_median"] * 8000 // 10000,
        "disk_write_min_bytes_per_second": summary["disk_write_bytes_per_second_median"] * 8000 // 10000,
        "disk_queue_or_stall_min_microseconds": max(1, summary["disk_queue_or_stall_microseconds_median"] * 5000 // 10000),
        "loopback_requests_min_per_second": summary["loopback_requests_per_second_median"] * 8000 // 10000,
        "loopback_latency_p99_max_nanoseconds": summary["loopback_latency_p99_upper_nanoseconds_median"] * 20000 // 10000,
        "loopback_tx_min_bytes_per_second": summary["loopback_tx_bytes_per_second_median"] * 8000 // 10000,
        "loopback_rx_min_bytes_per_second": summary["loopback_rx_bytes_per_second_median"] * 8000 // 10000,
    }
    require(all(type(item) is int and item > 0 for item in result.values()), "pressure calibration did not produce positive numeric readiness values")
    return result


def _iter_events(
    path: Path, expected_sha: str, expected_bytes: int, maximum_bytes: int,
    state: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    try:
        require(path.resolve(strict=True) == path, "pressure events path traverses a symlink or alias")
        path_info = path.lstat()
        require(stat.S_ISREG(path_info.st_mode), "pressure events must be a regular nonsymlink file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise ReadbackError(f"cannot safely open pressure events: {error}") from error
    stream = os.fdopen(descriptor, "rb", buffering=0)
    try:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(path_info), "pressure events changed while opening")
        require(0 <= before.st_size <= maximum_bytes and before.st_size == expected_bytes, "pressure event size differs from its frozen budget/receipt")
        digest = hashlib.sha256()
        total = 0
        event_count = 0
        while True:
            line = stream.readline(MAX_EVENT_LINE_BYTES + 1)
            if not line:
                break
            require(len(line) <= MAX_EVENT_LINE_BYTES and line.endswith(b"\n"), f"pressure event line {event_count} is sparse or oversized")
            require(b"\r" not in line and b"\0" not in line, f"pressure event line {event_count} has invalid framing")
            total += len(line)
            require(total <= maximum_bytes and total <= expected_bytes, "pressure event stream exceeded its frozen byte budget")
            digest.update(line)
            value = parse_object(line[:-1], f"pressure event[{event_count}]", MAX_EVENT_LINE_BYTES)
            require(line == canonical_bytes(value), f"pressure event line {event_count} is not canonical")
            event_count += 1
            require(event_count <= MAX_EVENT_COUNT, "pressure event count exceeds its hard bound")
            state["event_count"] = event_count
            yield value
        after_fd = os.fstat(stream.fileno())
        after_path = path.lstat()
        require(_stat_key(before) == _stat_key(after_fd) == _stat_key(after_path) and total == before.st_size == expected_bytes, "pressure event file changed during streaming verification")
        actual = digest.hexdigest()
        require(actual == expected_sha, "pressure events differ from separately supplied raw digest")
        require(1 <= event_count <= MAX_EVENT_COUNT, "pressure event count is outside its hard bound")
        state["events_sha256"] = actual
        state["events_bytes"] = total
    finally:
        stream.close()


def _validate_worker_start(value: object, recipe: dict[str, Any]) -> dict[tuple[str, int | None], dict[str, Any]]:
    start = exact(value, {
        "schema", "kind", "sequence", "recipe_sha256", "monotonic_ns", "workers",
        "storage_device", "network_namespace_inode",
    }, "pressure start event")
    require(start["schema"] == EVENT_SCHEMA and start["kind"] == "pressure_start" and start["sequence"] == -1, "pressure start event identity differs")
    require(start["recipe_sha256"] == recipe["recipe_sha256"], "pressure start event belongs to another recipe")
    uint(start["monotonic_ns"], "pressure start time", positive=True)
    require(start["storage_device"] == recipe["storage"]["application_device"], "pressure start device differs from recipe")
    require(start["network_namespace_inode"] == recipe["network"]["network_namespace_inode"], "pressure start network namespace differs")
    workers = start["workers"]
    require(type(workers) is list and len(workers) == len(recipe["schedule"]["pressure_cpu_affinity"]) + 2, "pressure start worker set is sparse")
    output: dict[tuple[str, int | None], dict[str, Any]] = {}
    for item in workers:
        worker = exact(item, {"role", "cpu", "pid", "start_ticks", "pgid", "session_id"}, "pressure worker identity")
        role = text(worker["role"], "worker role", 16)
        cpu = worker["cpu"]
        if role == "cpu":
            cpu = uint(cpu, "worker CPU", maximum=65535)
            require(cpu in recipe["schedule"]["pressure_cpu_affinity"], "worker CPU is outside frozen pressure affinity")
        else:
            require(cpu is None and role in ("disk", "loopback"), "unknown pressure worker role")
        pid = uint(worker["pid"], "worker PID", positive=True, maximum=(1 << 31) - 1)
        ticks = uint(worker["start_ticks"], "worker start ticks", positive=True)
        pgid = uint(worker["pgid"], "worker process group", positive=True, maximum=(1 << 31) - 1)
        sid = uint(worker["session_id"], "worker session", positive=True, maximum=(1 << 31) - 1)
        require(pgid == pid and sid == pid, "pressure worker was not isolated in its own session")
        key = (role, cpu)
        require(key not in output, "pressure worker set contains a duplicate role")
        output[key] = {**worker, "pid": pid, "start_ticks": ticks}
    expected = {("cpu", cpu) for cpu in recipe["schedule"]["pressure_cpu_affinity"]} | {("disk", None), ("loopback", None)}
    require(set(output) == expected, "pressure worker set differs from frozen resource schedule")
    return output


def _validate_launch(value: object, recipe: dict[str, Any], expected_sha: str) -> dict[str, Any]:
    launch = exact(value, {"schema", "recipe_sha256", "nonce", "process", "launch_binding_sha256"}, "application launch binding")
    require(launch["schema"] == LAUNCH_SCHEMA and launch["recipe_sha256"] == recipe["recipe_sha256"] and launch["nonce"] == recipe["identity"]["nonce"], "application launch binding identity differs")
    body = {key: value for key, value in launch.items() if key != "launch_binding_sha256"}
    require(sha256(launch["launch_binding_sha256"], "launch binding digest") == digest_object(body), "application launch binding self digest is invalid")
    process = exact(launch["process"], {"pid", "start_ticks", "executable_path", "executable_sha256", "cwd", "tmpdir_path", "cpu_affinity", "network_namespace_inode"}, "application process identity")
    uint(process["pid"], "application PID", positive=True, maximum=(1 << 31) - 1)
    uint(process["start_ticks"], "application process start ticks", positive=True)
    require(process["executable_path"] == recipe["process"]["executable_path"] and process["executable_sha256"] == recipe["files"]["application_binary"]["raw_sha256"], "application process binary differs from frozen recipe")
    require(process["cwd"] in recipe["storage"]["application_io_paths"], "application cwd differs from frozen I/O path set")
    require(process["tmpdir_path"] == recipe["process"]["application_tmpdir_path"] and process["tmpdir_path"] in recipe["storage"]["application_io_paths"], "application TMPDIR differs from frozen I/O path set")
    require(process["cpu_affinity"] == recipe["schedule"]["application_cpu_affinity"], "application CPU affinity differs from frozen recipe")
    require(process["network_namespace_inode"] == recipe["network"]["network_namespace_inode"], "application network namespace differs from frozen recipe")
    return process


def _validate_run(value: object, expected: dict[str, str]) -> dict[str, Any]:
    run = exact(value, {
        "schema", "status", "failure", "recipe_sha256", "condition_sha256", "events_sha256",
        "events_bytes", "event_count", "sample_count", "process_binding_sha256",
        "launch_record_sha256", "readiness_marker_sha256", "application_overlap_nanoseconds",
        "worker_cleanup", "cleanup_ok", "start_monotonic_ns", "finish_monotonic_ns",
        "deadlines", "scratch_file_removed", "run_sha256",
    }, "pressure run receipt")
    require(run["schema"] == RUN_SCHEMA and run["status"] == "complete" and run["failure"] is None, "pressure driver did not report a complete run")
    body = {key: value for key, value in run.items() if key != "run_sha256"}
    require(sha256(run["run_sha256"], "run receipt digest") == digest_object(body), "run receipt self digest is invalid")
    require(run["recipe_sha256"] == expected["recipe"] and run["events_sha256"] == expected["events"], "run receipt is not bound to supplied recipe/events digests")
    require(run["process_binding_sha256"] == expected["process_binding"] and run["launch_record_sha256"] == expected["launch"], "run receipt process binding differs from supplied artifacts")
    require(run["readiness_marker_sha256"] == expected["ready"], "run receipt readiness marker differs from supplied artifact digest")
    require(run["cleanup_ok"] is True and run["scratch_file_removed"] is True, "pressure cleanup or scratch removal is incomplete")
    uint(run["events_bytes"], "event bytes", positive=True, maximum=MAX_EVENTS_BYTES)
    uint(run["event_count"], "event count", positive=True, maximum=MAX_EVENT_COUNT)
    uint(run["sample_count"], "sample count", positive=True, maximum=MAX_SAMPLE_COUNT)
    uint(run["start_monotonic_ns"], "run start", positive=True)
    uint(run["finish_monotonic_ns"], "run finish", positive=True)
    require(run["finish_monotonic_ns"] >= run["start_monotonic_ns"], "run end precedes its start")
    deadlines = exact(run["deadlines"], {"startup_seconds", "total_seconds", "term_seconds", "kill_seconds"}, "run deadlines")
    for key, value in deadlines.items():
        uint(value, f"run deadline {key}", positive=True)
    require(run["finish_monotonic_ns"] - run["start_monotonic_ns"] <= deadlines["total_seconds"] * 1_000_000_000, "pressure run exceeded its frozen total deadline")
    uint(run["application_overlap_nanoseconds"], "application overlap", positive=True)
    return run


def _pid_same(pid: int, start_ticks: int) -> bool:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
        text_value = raw.decode("ascii").strip()
        closing = text_value.rfind(")")
        fields = text_value[closing + 1:].strip().split()
        return len(fields) >= 20 and int(fields[19]) == start_ticks and fields[0] != "Z"
    except (OSError, UnicodeError, ValueError):
        return False


def _worker_exit_status_valid(record: dict[str, Any]) -> bool:
    code = record.get("exit_code")
    if code == 0:
        return True
    if code == -signal.SIGTERM:
        return record.get("term_sent_monotonic_ns") is not None and record.get("kill_sent_monotonic_ns") is None
    if code == -signal.SIGKILL:
        return record.get("kill_sent_monotonic_ns") is not None
    return False


def _require_pid_reaped(pid: int, start_ticks: int, label: str) -> None:
    pid = uint(pid, f"{label} PID", positive=True, maximum=(1 << 31) - 1)
    start_ticks = uint(start_ticks, f"{label} start ticks", positive=True)
    require(not _pid_same(pid, start_ticks), f"{label} PID/start identity is still alive after cleanup")


def _validate_worker_stderr_capture(record: dict[str, Any], label: str) -> bytes:
    encoded = record["stderr_raw_base64"]
    require(type(encoded) is str and len(encoded) <= ((MAX_WORKER_STDERR_RAW_BYTES + 2) // 3) * 4, f"{label} raw stderr capture exceeds its bound")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ReadbackError(f"{label} raw stderr capture is not canonical base64: {error}") from error
    require(len(raw) == uint(record["stderr_raw_bytes"], f"{label} stderr byte count", maximum=MAX_WORKER_STDERR_RAW_BYTES), f"{label} raw stderr byte count differs")
    require(sha256_bytes(raw) == sha256(record["stderr_raw_sha256"], f"{label} stderr SHA-256"), f"{label} raw stderr digest differs")
    require(type(record["stderr_raw_truncated"]) is bool and record["stderr_raw_truncated"] is False, f"{label} raw stderr capture was truncated")
    require(record["stderr_read_error"] is None, f"{label} raw stderr could not be completely read")
    excerpt = raw.decode("utf-8", errors="replace")[:4096].strip()
    require(record["stderr_output"] == excerpt, f"{label} stderr excerpt differs from its raw capture")
    return raw


def _validate_cleanup(run: dict[str, Any], workers: dict[tuple[str, int | None], dict[str, Any]], recipe: dict[str, Any]) -> None:
    records = run["worker_cleanup"]
    require(type(records) is list and len(records) == len(workers), "worker cleanup report is sparse")
    seen: set[tuple[str, int | None]] = set()
    for item in records:
        record = exact(item, {
            "role", "cpu", "pid", "start_ticks", "pgid", "session_id", "exit_code",
            "cleanup_started_monotonic_ns", "term_deadline_monotonic_ns", "kill_deadline_monotonic_ns",
            "term_error", "kill_error", "reap_error", "alive_after_cleanup",
            "term_sent_monotonic_ns", "kill_sent_monotonic_ns", "reaped_monotonic_ns", "stderr_output",
            "stderr_raw_base64", "stderr_raw_sha256", "stderr_raw_bytes", "stderr_raw_truncated", "stderr_read_error",
        }, "worker cleanup record")
        key = (record["role"], record["cpu"])
        require(key in workers and key not in seen, "worker cleanup identity is duplicated or unrecognized")
        seen.add(key)
        expected = workers[key]
        for field in ("pid", "start_ticks", "pgid", "session_id"):
            require(record[field] == expected[field], f"worker cleanup {field} differs from pressure start")
        require(_worker_exit_status_valid(record) and record["alive_after_cleanup"] is False, "pressure worker did not exit cleanly and get reaped")
        raw_stderr = _validate_worker_stderr_capture(record, "pressure worker")
        require(record["term_error"] is None and record["kill_error"] is None and record["reap_error"] is None and raw_stderr == b"", "pressure worker cleanup reported an error")
        cleanup_started = uint(record["cleanup_started_monotonic_ns"], "worker cleanup start", positive=True)
        term_deadline = uint(record["term_deadline_monotonic_ns"], "worker TERM deadline", positive=True)
        kill_deadline = uint(record["kill_deadline_monotonic_ns"], "worker KILL deadline", positive=True)
        require(term_deadline == cleanup_started + recipe["schedule"]["term_deadline_seconds"] * 1_000_000_000, "worker TERM deadline differs from frozen schedule")
        reaped = uint(record["reaped_monotonic_ns"], "worker reap time", positive=True)
        if record["term_sent_monotonic_ns"] is not None:
            sent = uint(record["term_sent_monotonic_ns"], "TERM time", positive=True)
            require(cleanup_started <= sent <= term_deadline, "TERM time is outside its finite deadline")
        if record["kill_sent_monotonic_ns"] is not None:
            sent = uint(record["kill_sent_monotonic_ns"], "KILL time", positive=True)
            require(term_deadline <= sent <= kill_deadline, "KILL escalation is outside its finite deadline")
        require(reaped <= kill_deadline and reaped <= run["finish_monotonic_ns"], "pressure worker was not reaped by its KILL deadline")
        _require_pid_reaped(record["pid"], record["start_ticks"], "pressure worker")
    require(seen == set(workers), "worker cleanup report omitted a session")


def _verify_script_hashes(recipe_info: dict[str, Any]) -> None:
    script_dir = Path(__file__).resolve().parent
    driver = script_dir / "application-pressure-driver.py"
    reader = Path(__file__).resolve()
    for label, path, expected in (
        ("pressure driver", driver, recipe_info["script_hashes"]["driver_sha256"]),
        ("pressure reader", reader, recipe_info["script_hashes"]["reader_sha256"]),
    ):
        _, actual = read_stable(path, label, 4 * 1024 * 1024)
        require(actual == expected, f"{label} bytes differ from the frozen recipe")


def _verify_raw_inputs(recipe_info: dict[str, Any]) -> None:
    for label, spec in recipe_info["files"].items():
        maximum = MAX_BINARY_BYTES if label == "application_binary" else MAX_SOURCE_BYTES if label == "source_manifest" else MAX_POLICY_BYTES
        _, actual = read_stable(Path(spec["path"]), f"raw input {label}", maximum)
        require(actual == spec["raw_sha256"], f"raw input {label} changed since recipe freeze")


def verify_pressure(
    recipe_path: Path, expected_recipe_sha: str, artifacts: Path,
    expected: dict[str, str],
) -> dict[str, Any]:
    recipe_value, _, recipe_raw_sha = read_canonical(recipe_path, "frozen pressure recipe", MAX_RECIPE_BYTES)
    recipe_info = _validate_recipe(recipe_value, expected_recipe_sha)
    recipe = recipe_value
    _verify_script_hashes(recipe_info)
    _verify_raw_inputs(recipe_info)
    _validate_calibration(recipe)
    try:
        dir_info = artifacts.lstat()
        require(stat.S_ISDIR(dir_info.st_mode) and artifacts.resolve(strict=True) == artifacts, "artifact directory is a symlink or alias")
    except OSError as error:
        raise ReadbackError(f"artifact directory is unavailable: {error}") from error
    required = {"events.jsonl", "process-binding.json", "launch-record.json", "run.json", "pressure-ready.json"}
    names = {path.name for path in artifacts.iterdir()}
    require(names == required, "pressure artifact directory has missing or unexpected files")
    launch, _, launch_sha = read_canonical(artifacts / "launch-record.json", "launch record", MAX_LAUNCH_BYTES)
    require(launch_sha == expected["launch"], "launch record raw digest differs from the separately supplied expected hash")
    process = _validate_launch(launch, recipe, expected["launch"])
    process_binding, _, process_binding_sha = read_canonical(artifacts / "process-binding.json", "process binding", MAX_LAUNCH_BYTES)
    require(process_binding_sha == expected["process_binding"], "process binding raw digest differs from the separately supplied expected hash")
    binding = exact(process_binding, {
        "schema", "recipe_sha256", "launch_record_sha256", "identity", "observed_monotonic_ns",
        "pressure_ready_monotonic_ns", "readiness_snapshot", "application_capacity_calibration_sha256",
        "pressure_contention_calibration_sha256", "process_binding_sha256",
    }, "pressure process binding")
    require(binding["schema"] == PROCESS_BINDING_SCHEMA and binding["recipe_sha256"] == expected_recipe_sha, "process binding recipe identity differs")
    binding_body = {key: value for key, value in binding.items() if key != "process_binding_sha256"}
    require(sha256(binding["process_binding_sha256"], "process binding self digest") == digest_object(binding_body), "process binding self digest is invalid")
    require(binding["launch_record_sha256"] == launch_sha, "process binding does not bind the copied launch record")
    require(binding["application_capacity_calibration_sha256"] == recipe_info["files"]["application_capacity_calibration"]["raw_sha256"], "app-byte capacity calibration hash was changed")
    require(binding["pressure_contention_calibration_sha256"] == recipe_info["calibration_sha256"], "pressure-contention calibration hash was changed")
    observed_process = exact(binding["identity"], {
        "pid", "start_ticks", "nonce", "executable_sha256", "tmpdir_path", "cpu_affinity", "network_namespace_inode",
    }, "bound process identity")
    require(observed_process["pid"] == process["pid"] and observed_process["start_ticks"] == process["start_ticks"] and observed_process["nonce"] == recipe_info["identity"]["nonce"], "bound PID/start/nonce differ from launch record")
    require(observed_process["executable_sha256"] == recipe_info["files"]["application_binary"]["raw_sha256"] and observed_process["tmpdir_path"] == recipe["process"]["application_tmpdir_path"] and observed_process["cpu_affinity"] == recipe_info["schedule"]["application_cpu_affinity"] and observed_process["network_namespace_inode"] == recipe_info["network"]["network_namespace_inode"], "bound process executable/TMPDIR/affinity/network identity differs")
    uint(binding["observed_monotonic_ns"], "application observation time", positive=True)
    ready_at = uint(binding["pressure_ready_monotonic_ns"], "pressure ready time", positive=True)
    require(ready_at <= binding["observed_monotonic_ns"], "application was observed before measured readiness")
    ready, _, ready_sha = read_canonical(artifacts / "pressure-ready.json", "pressure ready marker", 64 * 1024)
    require(ready_sha == expected["ready"], "pressure ready marker raw digest differs from separately supplied expected hash")
    ready = exact(ready, {
        "schema", "recipe_sha256", "condition_sha256", "nonce", "pressure_ready_monotonic_ns", "readiness", "ready_sha256",
    }, "pressure ready marker")
    ready_body = {key: value for key, value in ready.items() if key != "ready_sha256"}
    require(ready["schema"] == "allocatbelt.application-pressure-ready.v1" and ready["recipe_sha256"] == expected_recipe_sha and ready["condition_sha256"] == recipe_info["condition_sha256"] and ready["nonce"] == recipe_info["identity"]["nonce"], "pressure ready marker identity differs")
    require(sha256(ready["ready_sha256"], "pressure ready digest") == digest_object(ready_body), "pressure ready marker self digest is invalid")
    require(ready["pressure_ready_monotonic_ns"] == ready_at and ready["readiness"] == binding["readiness_snapshot"], "pressure ready marker differs from the process binding")
    run_value, _, run_sha = read_canonical(artifacts / "run.json", "pressure run receipt", MAX_MANIFEST_BYTES)
    require(run_sha == expected["run"], "run receipt raw digest differs from separately supplied expected hash")
    run = _validate_run(run_value, {**expected, "recipe": expected_recipe_sha})
    require(run["condition_sha256"] == recipe_info["condition_sha256"], "run receipt condition differs from frozen recipe")
    event_state: dict[str, Any] = {"event_count": 0}
    events = _iter_events(
        artifacts / "events.jsonl", expected["events"], run["events_bytes"],
        recipe_info["artifact_budget"]["maximum_event_bytes"], event_state,
    )
    start_event = next(events, None)
    require(type(start_event) is dict and start_event.get("kind") == "pressure_start", "event stream does not start with pressure worker identities")
    workers = _validate_worker_start(start_event, recipe)
    require(all(item["pid"] != process["pid"] for item in workers.values()), "application PID is also listed as a pressure worker")
    _validate_cleanup(run, workers, recipe)
    timeline = _validate_event_timeline(events, start_event, recipe, process, binding, run, workers)
    require(event_state.get("event_count") == run["event_count"] and event_state.get("events_sha256") == run["events_sha256"] == expected["events"] and event_state.get("events_bytes") == run["events_bytes"], "run receipt event count/digest differs from streamed raw event file")
    scratch_path = Path(recipe["storage"]["pressure_scratch_path"]) / f".allocatbelt-pressure-{recipe_info['identity']['nonce']}.bin"
    require(not scratch_path.exists() and not scratch_path.is_symlink(), "bounded block-I/O scratch file remains after pressure cleanup")
    run_ns = run["finish_monotonic_ns"] - run["start_monotonic_ns"]
    require(run_ns <= recipe_info["schedule"]["total_deadline_seconds"] * 1_000_000_000, "pressure run exceeded its total deadline")
    result_body = {
        "schema": READBACK_SCHEMA,
        "status": "valid",
        "recipe_sha256": expected_recipe_sha,
        "recipe_raw_sha256": recipe_raw_sha,
        "validator_sha256": recipe_info["script_hashes"]["reader_sha256"],
        "condition_sha256": recipe_info["condition_sha256"],
        "identity": {
            key: recipe_info["identity"][key]
            for key in ("host_id", "run_id", "pair_id", "condition_id", "member", "nonce", "allocator", "executor", "phase")
        },
        "run_sha256": expected["run"],
        "events_sha256": expected["events"],
        "launch_record_sha256": expected["launch"],
        "process_binding_sha256": expected["process_binding"],
        "readiness_marker_sha256": expected["ready"],
        "sample_count": run["sample_count"],
        "application_overlap_nanoseconds": run["application_overlap_nanoseconds"],
        "application_process": {
            "pid": process["pid"],
            "start_ticks": process["start_ticks"],
            "nonce": observed_process["nonce"],
            "executable_sha256": observed_process["executable_sha256"],
        },
        "application_window": timeline["application_window"],
        "continuous_ready_window": timeline["continuous_ready_window"],
        "readiness_windows_passed": True,
        "cleanup_rechecked": True,
        "physical_nic_claimed": False,
    }
    return {**result_body, "readback_sha256": digest_object(result_body)}


def _advance_app_sample_continuity(
    *, app_started: bool, live_seen: bool, terminal_inactive_seen: bool,
    app_active: bool, readiness_ok: bool, complete_overlap_window: bool,
) -> tuple[bool, bool]:
    if not app_started:
        require(not app_active, "application was live before its authenticated start event")
        return live_seen, terminal_inactive_seen
    require(not terminal_inactive_seen, "application pressure trace has an inactive hole or process revival")
    if app_active:
        if complete_overlap_window:
            require(readiness_ok, "readiness failed inside a complete application-overlap window")
        return True, False
    return live_seen, True


def _validate_event_timeline(
    events: Iterator[dict[str, Any]], start_event: dict[str, Any], recipe: dict[str, Any], process: dict[str, Any],
    binding: dict[str, Any], run: dict[str, Any], workers: dict[tuple[str, int | None], dict[str, Any]],
) -> dict[str, dict[str, int]]:
    start_ns = uint(start_event["monotonic_ns"], "pressure start time", positive=True)
    interval_ns = recipe["schedule"]["sample_interval_ms"] * 1_000_000
    previous_end: int | None = None
    sample_count = 0
    last_sample: dict[str, Any] | None = None
    first_live_sequence: int | None = None
    last_live_sample: dict[str, Any] | None = None
    live_seen = False
    terminal_inactive_seen = False
    startup_ready: list[bool] = []
    active_readiness_windows = 0
    active_readiness_ok = True
    app_start_ns: int | None = None
    app_exit_ns: int | None = None
    cleanup_seen = False
    cleanup_count = 0
    app_start_count = 0
    app_exit_count = 0
    continuous_ready_start_ns: int | None = None
    continuous_ready_end_ns: int | None = None
    continuous_ready_broken = False
    for event in events:
        require(event.get("schema") == EVENT_SCHEMA, "pressure event has unknown schema")
        kind = event.get("kind")
        if kind == "sample":
            require(app_exit_ns is None and not cleanup_seen, "pressure samples continue after application exit or cleanup")
            sequence = sample_count
            result = _validate_sample(event, recipe, sequence)
            start = result["start"]
            end = result["end"]
            cadence_tolerance_ns = max(1_000_000, interval_ns // 100)
            require(interval_ns - cadence_tolerance_ns <= end - start <= interval_ns + max(500_000_000, interval_ns), "sample interval is shorter/sparser than frozen cadence")
            if previous_end is not None:
                require(start == previous_end, "pressure sample intervals have a gap or overlap")
            previous_end = end
            live_seen, terminal_inactive_seen = _advance_app_sample_continuity(
                app_started=app_start_ns is not None,
                live_seen=live_seen,
                terminal_inactive_seen=terminal_inactive_seen,
                app_active=result["app_active"],
                readiness_ok=result["readiness"]["all_ready"],
                complete_overlap_window=app_start_ns is not None and start >= app_start_ns,
            )
            if app_start_ns is None:
                startup_ready.append(result["readiness"]["all_ready"])
                del startup_ready[:-recipe["schedule"]["startup_ready_windows"]]
            else:
                ready_barrier_ns = binding["pressure_ready_monotonic_ns"]
                require(start >= ready_barrier_ns, "pressure sample precedes the authenticated readiness barrier")
                sample_ready = result["readiness"]["all_ready"]
                if sample_ready:
                    if continuous_ready_start_ns is None:
                        continuous_ready_start_ns = start
                        require(
                            continuous_ready_start_ns >= ready_barrier_ns,
                            "continuous ready pressure interval precedes its readiness barrier",
                        )
                    if not continuous_ready_broken:
                        continuous_ready_end_ns = end
                elif continuous_ready_start_ns is not None:
                    continuous_ready_broken = True
            if result["app_active"]:
                require(app_start_ns is not None, "application was live before its authenticated start event")
                active_readiness_windows += 1
                active_readiness_ok = active_readiness_ok and result["readiness"]["all_ready"]
                require(result["readiness"]["all_ready"], "pressure window overlapping the live application is unready")
                if first_live_sequence is None:
                    first_live_sequence = sequence
                last_live_sample = {
                    "sequence": sequence,
                    "start": start,
                    "end": end,
                    "readiness": result["readiness"],
                }
            last_sample = {
                "sequence": sequence,
                "start": start,
                "end": end,
                "app_active": result["app_active"],
                "readiness": result["readiness"],
            }
            sample_count += 1
        elif kind == "application_start":
            app_start_count += 1
            require(app_start_count == 1 and app_exit_count == 0 and cleanup_count == 0, "pressure event stream repeats or reorders application start")
            require(last_sample is not None, "application start appears before a complete readiness sample")
            start_exact = exact(event, {"schema", "kind", "sequence", "monotonic_ns", "pid", "start_ticks", "launch_record_sha256"}, "application start event")
            require(start_exact["sequence"] == last_sample["sequence"] and start_exact["pid"] == process["pid"] and start_exact["start_ticks"] == process["start_ticks"] and start_exact["launch_record_sha256"] == binding["launch_record_sha256"], "application start event differs from launch binding")
            app_start_ns = uint(start_exact["monotonic_ns"], "application start observation", positive=True)
            require(app_start_ns == binding["observed_monotonic_ns"] and last_sample["end"] <= app_start_ns, "application start does not follow its measured readiness window")
            require(app_start_ns >= start_ns, "application start precedes pressure worker startup")
            ready_count = recipe["schedule"]["startup_ready_windows"]
            require(len(startup_ready) >= ready_count and all(startup_ready[-ready_count:]), "measured startup readiness windows are missing or failed")
            require(last_sample["end"] == binding["pressure_ready_monotonic_ns"] and last_sample["readiness"] == binding["readiness_snapshot"], "ready marker does not match the last complete startup sample")
        elif kind == "application_exit":
            app_exit_count += 1
            require(app_exit_count == 1 and app_start_ns is not None and cleanup_count == 0, "pressure event stream repeats or reorders application exit")
            exit_exact = exact(event, {"schema", "kind", "sequence", "monotonic_ns", "pid", "start_ticks", "exit_observed"}, "application exit event")
            require(exit_exact["pid"] == process["pid"] and exit_exact["start_ticks"] == process["start_ticks"] and exit_exact["exit_observed"] is True, "application exit event does not match launch PID/start")
            require(last_live_sample is not None and exit_exact["sequence"] == last_live_sample["sequence"], "application exit does not name its last independently live sample")
            app_exit_ns = uint(exit_exact["monotonic_ns"], "application exit observation", positive=True)
            require(app_exit_ns == last_live_sample["end"] and app_exit_ns > app_start_ns, "application exit is not bounded by its final live sample")
            if terminal_inactive_seen:
                require(last_sample is not None and not last_sample["app_active"] and last_sample["sequence"] + 1 == sample_count, "inactive observation is not the single trailing death window")
            else:
                require(last_sample is not None and last_sample["sequence"] == last_live_sample["sequence"], "application live window was followed by an unrecorded sample")
        elif kind == "pressure_cleanup":
            cleanup_count += 1
            require(cleanup_count == 1 and app_exit_ns is not None, "pressure cleanup is duplicated or precedes application exit")
            cleanup = exact(event, {"schema", "kind", "monotonic_ns", "workers", "scratch_file_removed", "cleanup_ok"}, "pressure cleanup event")
            cleanup_ns = uint(cleanup["monotonic_ns"], "pressure cleanup time", positive=True)
            require(cleanup["cleanup_ok"] is True and cleanup["scratch_file_removed"] is True and cleanup_ns <= run["finish_monotonic_ns"], "pressure cleanup event is incomplete")
            require(cleanup["workers"] == run["worker_cleanup"] and len(workers) == len(run["worker_cleanup"]), "cleanup event differs from worker start identities or run receipt")
            require(app_exit_ns <= cleanup_ns, "pressure workers were cleaned before the application exited")
            cleanup_seen = True
        elif kind == "pressure_failure":
            raise ReadbackError("pressure event stream contains a failure record")
        else:
            raise ReadbackError(f"unknown pressure event kind: {kind}")
    require(sample_count == run["sample_count"] and last_sample is not None, "sample event count differs from run receipt")
    require(app_start_count == 1 and app_exit_count == 1 and cleanup_count == 1, "pressure event stream omits its application interval or cleanup")
    require(first_live_sequence is not None and last_live_sample is not None, "pressure trace contains no independently live application window")
    overlap = app_exit_ns - app_start_ns
    require(overlap >= recipe["schedule"]["minimum_overlap_seconds"] * 1_000_000_000 and overlap == run["application_overlap_nanoseconds"], "application overlap differs from the frozen minimum or receipt")
    require(active_readiness_windows > 0 and active_readiness_ok, "readiness failed or application was not live through a complete pressure window")
    _require_pid_reaped(process["pid"], process["start_ticks"], "application")
    require(
        continuous_ready_start_ns is not None
        and continuous_ready_end_ns is not None
        and app_start_ns is not None
        and app_exit_ns is not None
        and continuous_ready_end_ns > continuous_ready_start_ns,
        "pressure trace has no complete continuous-ready application window",
    )
    return {
        "application_window": {
            "observed_start_monotonic_ns": app_start_ns,
            "observed_exit_monotonic_ns": app_exit_ns,
        },
        "continuous_ready_window": {
            "start_monotonic_ns": continuous_ready_start_ns,
            "end_monotonic_ns": continuous_ready_end_ns,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    verify = command.add_parser("verify", help="independently recompute a bounded pressure run")
    verify.add_argument("--recipe", type=Path, required=True)
    verify.add_argument("--expected-recipe-sha256", required=True)
    verify.add_argument("--artifacts", type=Path, required=True)
    verify.add_argument("--expected-run-sha256", required=True)
    verify.add_argument("--expected-events-sha256", required=True)
    verify.add_argument("--expected-launch-sha256", required=True)
    verify.add_argument("--expected-process-binding-sha256", required=True)
    verify.add_argument("--expected-ready-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        expected_recipe = sha256(args.expected_recipe_sha256, "expected recipe SHA-256")
        expected = {
            "recipe": expected_recipe,
            "run": sha256(args.expected_run_sha256, "expected run SHA-256"),
            "events": sha256(args.expected_events_sha256, "expected event SHA-256"),
            "launch": sha256(args.expected_launch_sha256, "expected launch SHA-256"),
            "process_binding": sha256(args.expected_process_binding_sha256, "expected process binding SHA-256"),
            "ready": sha256(args.expected_ready_sha256, "expected readiness marker SHA-256"),
        }
        result = verify_pressure(args.recipe, expected_recipe, args.artifacts, expected)
    except (ReadbackError, OSError, ValueError) as error:
        print(f"application-pressure-readback: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
